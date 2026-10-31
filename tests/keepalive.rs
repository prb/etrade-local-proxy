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
use etrade_local_proxy::shell::probe;
use etrade_local_proxy::shell::keepalive;
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
