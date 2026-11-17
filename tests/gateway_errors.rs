//! Gateway/readiness error replies (`502`/`503`/`504`) carry a fixed-shape JSON
//! body naming the reason. Each row of the contract table is driven against a
//! local stub upstream (hang, refuse, reset, oversized body, no token).
//!
//! The URL carries a recognizable account key and the request a recognizable
//! header value; neither may appear in any error body.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::test_config;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};

use etrade_local_proxy::core::newtypes::{AccessToken, TokenSecret};
use etrade_local_proxy::core::status::Unauthorized;
use etrade_local_proxy::shell::clock_nonce::{Clock, CounterNonceSource, FixedClock, NonceSource};
use etrade_local_proxy::shell::http::http_client_with;
use etrade_local_proxy::shell::server::{app_state, router};
use etrade_local_proxy::shell::state::{self, SharedState};
use etrade_local_proxy::shell::upstream::UPSTREAM_BODY_CAP;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tower::ServiceExt;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ACCOUNT_KEY: &str = "AcctKeyZ9q81";
const HEADER_VALUE: &str = "secret-header-value-7731";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

fn app(upstream_base: String, auth: SharedState, request_timeout: Duration) -> axum::Router {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FixedClock::new(1_700_000_000));
    let nonces: Arc<dyn NonceSource + Send + Sync> = Arc::new(CounterNonceSource::new());
    let client =
        http_client_with(Duration::from_millis(500), request_timeout).expect("build client");
    router(app_state(
        Arc::new(test_config()),
        auth,
        clock,
        nonces,
        client,
        Some(upstream_base),
        request_timeout,
    ))
}

fn ready() -> SharedState {
    state::ready(Unauthorized.authorize(AccessToken::new("acctok"), TokenSecret::new("accsec")))
}

/// Send a GET (with a sensitive-looking header) and return status, content
/// type, and body text.
async fn get(app: axum::Router) -> (StatusCode, Option<String>, String) {
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/etrade-api/v1/accounts/{ACCOUNT_KEY}/transactions.json"))
                .header("x-secret", HEADER_VALUE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, content_type, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Assert the status, JSON content type, exact body, and that nothing sensitive
/// leaked into it.
fn assert_error(
    (status, content_type, body): (StatusCode, Option<String>, String),
    expected_status: StatusCode,
    expected_body: serde_json::Value,
) {
    assert_eq!(status, expected_status);
    assert_eq!(content_type.as_deref(), Some("application/json"));
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("body is JSON");
    assert_eq!(parsed, expected_body);
    for secret in [
        ACCOUNT_KEY,
        HEADER_VALUE,
        "transactions",
        "/etrade-api",
        "127.0.0.1",
        "acctok",
        "accsec",
        "ckey",
        "csec",
    ] {
        assert!(!body.contains(secret), "body leaked {secret:?}: {body}");
    }
}

#[tokio::test]
async fn hanging_upstream_is_504_upstream_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let result = get(app(server.uri(), ready(), REQUEST_TIMEOUT)).await;
    assert_error(
        result,
        StatusCode::GATEWAY_TIMEOUT,
        serde_json::json!({"error": "upstream_timeout", "timeout_seconds": 1}),
    );
}

#[tokio::test]
async fn refused_connection_is_502_upstream_error() {
    // Bind then drop to obtain a port nothing is listening on.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let result = get(app(base, ready(), REQUEST_TIMEOUT)).await;
    assert_error(
        result,
        StatusCode::BAD_GATEWAY,
        serde_json::json!({"error": "upstream_error"}),
    );
}

#[tokio::test]
async fn reset_connection_is_502_upstream_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    // Accept, read the start of the request, then drop the socket mid-exchange.
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 16];
            let _ = socket.read(&mut buf).await;
            drop(socket);
        }
    });
    let result = get(app(base, ready(), REQUEST_TIMEOUT)).await;
    assert_error(
        result,
        StatusCode::BAD_GATEWAY,
        serde_json::json!({"error": "upstream_error"}),
    );
}

#[tokio::test]
async fn oversized_upstream_body_is_502_upstream_too_large() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; UPSTREAM_BODY_CAP + 1]))
        .mount(&server)
        .await;
    // Generous timeout: the 8 MiB transfer over loopback must not trip it.
    let result = get(app(server.uri(), ready(), Duration::from_secs(20))).await;
    assert_error(
        result,
        StatusCode::BAD_GATEWAY,
        serde_json::json!({"error": "upstream_too_large"}),
    );
}

#[tokio::test]
async fn missing_token_is_503_not_ready() {
    let result = get(app("http://127.0.0.1:1".into(), state::pending(), REQUEST_TIMEOUT)).await;
    assert_error(
        result,
        StatusCode::SERVICE_UNAVAILABLE,
        serde_json::json!({"error": "not_ready"}),
    );
}

#[tokio::test]
async fn upstream_error_statuses_pass_through_unchanged() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream says no"))
        .mount(&server)
        .await;
    let (status, _, body) = get(app(server.uri(), ready(), REQUEST_TIMEOUT)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "upstream says no");
}
