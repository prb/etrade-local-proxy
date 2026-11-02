//! Keep-alive task tests against a LOCAL `wiremock` upstream (no live calls).
//! A few-millisecond interval drives the loop in real time.
mod common;
use std::time::Duration;

use common::test_config;
use etrade_local_proxy::core::keepalive::KeepAliveAction;
use etrade_local_proxy::core::newtypes::{AccessToken, TokenSecret};
use etrade_local_proxy::core::status::{Authorized, Unauthorized};
use etrade_local_proxy::shell::clock_nonce::{CounterNonceSource, FixedClock, Signer};
use etrade_local_proxy::shell::error::{KeepAliveError, ProbeError, ProxyError};
use etrade_local_proxy::shell::http::http_client_with;
use etrade_local_proxy::shell::keepalive;
use etrade_local_proxy::shell::probe;
use reqwest::Client;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TICK: Duration = Duration::from_millis(20);

fn authorized() -> Authorized {
    Unauthorized.authorize(AccessToken::new("acctok"), TokenSecret::new("accsec"))
}

async fn mount(server: &MockServer, status: u16) {
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(status))
        .mount(server)
        .await;
}

fn auth_header(req: &wiremock::Request) -> String {
    req.headers
        .get("authorization")
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .unwrap_or_default()
}

#[tokio::test]
async fn repeats_signed_calls_with_distinct_nonces() {
    let server = MockServer::start().await;
    mount(&server, 200).await;
    let (client, config, authed) = (Client::new(), test_config(), authorized());
    let clock = FixedClock::new(1_700_000_000);
    let nonces = CounterNonceSource::new();
    let base = server.uri();
    // The loop never ends on success; bound it with a timeout.
    let ended = tokio::time::timeout(
        Duration::from_millis(300),
        keepalive::run(
            &client,
            &config,
            &authed,
            Some(&base),
            Signer::new(&clock, &nonces),
            TICK,
        ),
    )
    .await;
    assert!(ended.is_err(), "keep-alive must keep running on success");
    let reqs = server.received_requests().await.expect("recorded");
    assert!(
        reqs.len() >= 3,
        "expected repeated calls, got {}",
        reqs.len()
    );
    let headers: Vec<String> = reqs.iter().map(auth_header).collect();
    assert!(headers.iter().all(|h| h.contains("oauth_signature=")));
    let mut unique = headers.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        headers.len(),
        "each call must sign with a fresh nonce"
    );
}

#[tokio::test]
async fn first_call_waits_one_interval() {
    let server = MockServer::start().await;
    mount(&server, 200).await;
    let (client, config, authed) = (Client::new(), test_config(), authorized());
    let (clock, nonces) = (FixedClock::new(1_700_000_000), CounterNonceSource::new());
    let base = server.uri();
    let _ = tokio::time::timeout(
        Duration::from_millis(100),
        keepalive::run(
            &client,
            &config,
            &authed,
            Some(&base),
            Signer::new(&clock, &nonces),
            Duration::from_secs(60),
        ),
    )
    .await;
    assert!(server
        .received_requests()
        .await
        .expect("recorded")
        .is_empty());
}

#[tokio::test]
async fn unauthorized_is_fatal() {
    for code in [401u16, 403] {
        let server = MockServer::start().await;
        mount(&server, code).await;
        let (client, config, authed) = (Client::new(), test_config(), authorized());
        let (clock, nonces) = (FixedClock::new(1_700_000_000), CounterNonceSource::new());
        let base = server.uri();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            keepalive::run(
                &client,
                &config,
                &authed,
                Some(&base),
                Signer::new(&clock, &nonces),
                TICK,
            ),
        )
        .await
        .expect("fatal outcome ends the task");
        assert!(
            matches!(result, KeepAliveError::TokenRejected { code: c } if c == code),
            "unexpected result: {result:?}"
        );
        assert_eq!(server.received_requests().await.expect("recorded").len(), 1);
    }
}

#[tokio::test]
async fn server_error_is_transient_and_retried() {
    let server = MockServer::start().await;
    mount(&server, 500).await;
    let (client, config, authed) = (Client::new(), test_config(), authorized());
    let (clock, nonces) = (FixedClock::new(1_700_000_000), CounterNonceSource::new());
    let base = server.uri();
    let signer = Signer::new(&clock, &nonces);
    assert_eq!(
        keepalive::tick(&client, &config, &authed, Some(&base), signer).await,
        KeepAliveAction::Transient { status: Some(500) }
    );
    let ended = tokio::time::timeout(
        Duration::from_millis(300),
        keepalive::run(&client, &config, &authed, Some(&base), signer, TICK),
    )
    .await;
    assert!(ended.is_err(), "5xx must not end the task");
    assert!(server.received_requests().await.expect("recorded").len() >= 3);
}

#[tokio::test]
async fn dropped_connection_is_transient() {
    // Bind then drop a listener so connections are refused.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    let (client, config, authed) = (Client::new(), test_config(), authorized());
    let (clock, nonces) = (FixedClock::new(1_700_000_000), CounterNonceSource::new());
    let signer = Signer::new(&clock, &nonces);
    assert_eq!(
        keepalive::tick(&client, &config, &authed, Some(&base), signer).await,
        KeepAliveAction::Transient { status: None }
    );
    let ended = tokio::time::timeout(
        Duration::from_millis(150),
        keepalive::run(&client, &config, &authed, Some(&base), signer, TICK),
    )
    .await;
    assert!(ended.is_err(), "transport failure must not end the task");
}

fn short_timeout_client() -> Client {
    http_client_with(Duration::from_millis(100), Duration::from_millis(150)).expect("client")
}

#[tokio::test]
async fn probe_times_out_on_hung_upstream() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let (config, authed) = (test_config(), authorized());
    let (clock, nonces) = (FixedClock::new(1_700_000_000), CounterNonceSource::new());
    let base = server.uri();
    let result = probe::validate(
        &short_timeout_client(),
        &config,
        &authed,
        Some(&base),
        Signer::new(&clock, &nonces),
    )
    .await;
    assert!(
        matches!(&result, Err(ProbeError::Transport(ProxyError::Upstream(e))) if e.is_timeout()),
        "expected timeout, got {result:?}"
    );
}

#[tokio::test]
async fn timed_out_tick_is_transient_and_loop_recovers() {
    let server = MockServer::start().await;
    // The first call hangs past the client timeout; later calls answer fast.
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount(&server, 200).await;
    let (client, config, authed) = (short_timeout_client(), test_config(), authorized());
    let (clock, nonces) = (FixedClock::new(1_700_000_000), CounterNonceSource::new());
    let base = server.uri();
    let signer = Signer::new(&clock, &nonces);
    assert_eq!(
        keepalive::tick(&client, &config, &authed, Some(&base), signer).await,
        KeepAliveAction::Transient { status: None }
    );
    // The loop keeps calling after the timeout (later calls hit the fast mock).
    let ended = tokio::time::timeout(
        Duration::from_millis(400),
        keepalive::run(&client, &config, &authed, Some(&base), signer, TICK),
    )
    .await;
    assert!(ended.is_err(), "a timeout must not end the task");
    assert!(server.received_requests().await.expect("recorded").len() >= 3);
}

// ---- log content ----------------------------------------------------------

use std::sync::{Arc, Mutex};

/// Run the loop with a captured log sink for `window`, returning the lines.
async fn captured(
    client: &Client,
    base: &str,
    interval: Duration,
    window: Duration,
) -> (Vec<String>, Option<KeepAliveError>) {
    let (config, authed) = (test_config(), authorized());
    let (clock, nonces) = (FixedClock::new(1_700_000_000), CounterNonceSource::new());
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let result = tokio::time::timeout(
        window,
        keepalive::run_with_log(
            client,
            &config,
            &authed,
            Some(base),
            Signer::new(&clock, &nonces),
            interval,
            move |l| sink.lock().expect("lock").push(l.to_owned()),
        ),
    )
    .await
    .ok();
    let out = lines.lock().expect("lock").clone();
    (out, result)
}

#[tokio::test]
async fn startup_schedule_line_precedes_first_wait() {
    let server = MockServer::start().await;
    mount(&server, 200).await;
    let (lines, _) = captured(
        &Client::new(),
        &server.uri(),
        Duration::from_secs(1800),
        Duration::from_millis(100),
    )
    .await;
    assert_eq!(
        lines,
        vec![
            "info: 2023-11-14T22:13:20Z keep-alive scheduled: GET /v1/accounts/list \
             every 30m, first run at 2023-11-14T22:43:20Z"
                .to_owned()
        ]
    );
}

#[tokio::test]
async fn success_lines_have_status_and_timing() {
    let server = MockServer::start().await;
    mount(&server, 200).await;
    let (lines, _) = captured(
        &Client::new(),
        &server.uri(),
        TICK,
        Duration::from_millis(200),
    )
    .await;
    let ok = lines
        .iter()
        .find(|l| l.contains("keep-alive OK"))
        .expect("ok line");
    assert!(ok
        .starts_with("info: 2023-11-14T22:13:20Z keep-alive OK GET /v1/accounts/list (HTTP 200, "));
    assert!(ok.ends_with("ms)"));
}

#[tokio::test]
async fn http_500_and_timeout_report_distinct_causes_with_counter() {
    let server = MockServer::start().await;
    mount(&server, 500).await;
    let (lines, _) = captured(
        &Client::new(),
        &server.uri(),
        TICK,
        Duration::from_millis(250),
    )
    .await;
    let warns: Vec<_> = lines.iter().filter(|l| l.starts_with("warn:")).collect();
    assert!(warns.len() >= 2);
    assert!(warns[0].contains("got HTTP 500") && warns[0].contains("failure 1 in a row"));
    assert!(warns[1].contains("failure 2 in a row; will retry in 20ms"));

    let slow = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&slow)
        .await;
    let (lines, _) = captured(
        &short_timeout_client(),
        &slow.uri(),
        TICK,
        Duration::from_millis(500),
    )
    .await;
    let warn = lines.iter().find(|l| l.starts_with("warn:")).expect("warn");
    assert!(warn.contains("failed: timeout"), "{warn}");
    assert!(!warn.contains("HTTP"), "{warn}");
    assert!(!warn.contains("http://"), "no URL in logs: {warn}");
}

#[tokio::test]
async fn failure_counter_resets_after_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(200))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;
    let (lines, _) = captured(
        &Client::new(),
        &server.uri(),
        TICK,
        Duration::from_millis(400),
    )
    .await;
    let tags: Vec<String> = lines
        .iter()
        .skip(1)
        .take(4)
        .map(|l| {
            l.split_once("(failure ")
                .map_or("ok".to_owned(), |(_, r)| r.chars().take(1).collect())
        })
        .collect();
    assert_eq!(tags, ["1", "2", "ok", "1"], "{lines:?}");
}

#[tokio::test]
async fn fatal_logs_summary_and_still_returns_token_rejected() {
    for code in [401u16, 403] {
        let server = MockServer::start().await;
        mount(&server, code).await;
        let (lines, result) =
            captured(&Client::new(), &server.uri(), TICK, Duration::from_secs(5)).await;
        assert!(matches!(result, Some(KeepAliveError::TokenRejected { code: c }) if c == code));
        let last = lines.last().expect("fatal line");
        assert!(last.starts_with("error: 2023-11-14T22:13:20Z "));
        assert!(last.contains(&format!("HTTP {code}")));
        assert!(last.contains("none since startup"));
        assert!(last.contains("restart the proxy to re-authorize"));
    }
}
