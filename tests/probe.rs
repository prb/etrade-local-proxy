//! Integration tests for the startup authorization-validation probe, against a
//! LOCAL `wiremock` upstream (AC-13 — no live calls).
//!
//! Drives `probe::validate` directly with the wiremock `base_url_override`, the
//! deterministic clock/nonce fakes, and asserts:
//!   * SUCCESS — a 200 `AccountListResponse` with a known N yields `Ok(Some(N))`
//!     and the probe sends a signed `GET /v1/accounts/list`;
//!   * FAIL-FAST — a 401 yields `Err(ProbeError::NonSuccessStatus { code: 401 })`
//!     so startup would abort;
//!   * 2xx-UNPARSEABLE — a 200 with an unexpected body yields `Ok(None)`
//!     (authorization validated, count unknown, no error).

mod common;

use common::test_config;

use etrade_local_proxy::core::newtypes::{AccessToken, TokenSecret};
use etrade_local_proxy::core::status::Unauthorized;
use etrade_local_proxy::shell::clock_nonce::{CounterNonceSource, FixedClock};
use etrade_local_proxy::shell::error::ProbeError;
use etrade_local_proxy::shell::probe;

use reqwest::Client;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn authorized() -> etrade_local_proxy::core::status::Authorized {
    Unauthorized.authorize(AccessToken::new("acctok"), TokenSecret::new("accsec"))
}

#[tokio::test]
async fn success_counts_accounts_and_signs_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"AccountListResponse":{"Accounts":{"Account":[{"accountId":"1"},{"accountId":"2"}]}}}"#,
        ))
        .mount(&server)
        .await;

    let client = Client::new();
    let config = test_config();
    let authed = authorized();
    let clock = FixedClock::new(1_700_000_000);
    let nonces = CounterNonceSource::new();

    let count = probe::validate(
        &client,
        &config,
        &authed,
        Some(&server.uri()),
        &clock,
        &nonces,
    )
    .await
    .expect("probe succeeds");
    assert_eq!(count, Some(2));

    // The probe sent exactly one signed GET to the probe path.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "exactly one upstream hit");
    let probe_req = &requests[0];
    assert_eq!(probe_req.method.as_str(), "GET");
    assert_eq!(probe_req.url.path(), "/v1/accounts/list");
    let auth = probe_req
        .headers
        .get("authorization")
        .expect("signed Authorization header present")
        .to_str()
        .unwrap();
    assert!(auth.starts_with("OAuth "));
}

#[tokio::test]
async fn non_success_status_fails_fast() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&server)
        .await;

    let client = Client::new();
    let config = test_config();
    let authed = authorized();
    let clock = FixedClock::new(1_700_000_000);
    let nonces = CounterNonceSource::new();

    let result = probe::validate(
        &client,
        &config,
        &authed,
        Some(&server.uri()),
        &clock,
        &nonces,
    )
    .await;

    assert!(
        matches!(result, Err(ProbeError::NonSuccessStatus { code: 401 })),
        "a non-2xx probe response must fail fast with the status code, got {result:?}"
    );
}

#[tokio::test]
async fn success_with_unparseable_body_is_unknown_count() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"unexpected":true}"#))
        .mount(&server)
        .await;

    let client = Client::new();
    let config = test_config();
    let authed = authorized();
    let clock = FixedClock::new(1_700_000_000);
    let nonces = CounterNonceSource::new();

    let count = probe::validate(
        &client,
        &config,
        &authed,
        Some(&server.uri()),
        &clock,
        &nonces,
    )
    .await
    .expect("a 2xx with an unexpected body is still a validated token");
    assert_eq!(count, None, "unparseable 2xx body yields an unknown count");
}
