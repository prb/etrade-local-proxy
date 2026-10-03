//! Integration test for the proxy forward path, end to end, against a LOCAL
//! `wiremock` upstream (AC-13 — no live calls).
//!
//! The router is driven in-process via `tower`'s `oneshot` so the full
//! `admit` → sign → forward → relay pipeline runs. Asserts:
//!   * `GET /etrade-api/v1/accounts/list?x=1` reaches the fake as
//!     `GET /v1/accounts/list?x=1`, query preserved, with a signed header;
//!   * a `POST` under the prefix returns `405` and the mock records ZERO
//!     upstream hits (structural GET-only, end to end);
//!   * an out-of-prefix `GET` returns `404`;
//!   * two sequential proxied `GET`s carry DISTINCT `oauth_nonce` values
//!     (freshness contract) via a counter-backed `NonceSource`.

mod common;

use std::sync::Arc;

use common::{oauth_param, test_config};

use axum::body::Body;
use axum::http::{Request, StatusCode};

use etrade_local_proxy::core::newtypes::{AccessToken, TokenSecret};
use etrade_local_proxy::core::status::Unauthorized;
use etrade_local_proxy::shell::clock_nonce::{Clock, CounterNonceSource, FixedClock, NonceSource};
use etrade_local_proxy::shell::server::{app_state, router};
use etrade_local_proxy::shell::state;

use tower::ServiceExt; // for `oneshot`
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build an in-process router whose auth state is Ready and whose upstream is
/// pointed at the given local fake, with the supplied generators injected.
fn ready_router(
    upstream_base: String,
    clock: Arc<dyn Clock + Send + Sync>,
    nonces: Arc<dyn NonceSource + Send + Sync>,
) -> axum::Router {
    let config = Arc::new(test_config());
    let authorized =
        Unauthorized.authorize(AccessToken::new("acctok"), TokenSecret::new("accsec"));
    let auth = state::ready(authorized);
    let app_state = app_state(config, auth, clock, nonces, Some(upstream_base));
    router(app_state)
}

#[tokio::test]
async fn get_forwards_with_query_preserved_and_signed_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .and(query_param("x", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"ok":true}"#),
        )
        .mount(&server)
        .await;

    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FixedClock::new(1_700_000_000));
    let nonces: Arc<dyn NonceSource + Send + Sync> = Arc::new(CounterNonceSource::new());
    let app = ready_router(server.uri(), clock, nonces);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/etrade-api/v1/accounts/list?x=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], br#"{"ok":true}"#);

    // The fake received exactly the mapped path+query with a signed header.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "exactly one upstream hit");
    let upstream = &requests[0];
    assert_eq!(upstream.url.path(), "/v1/accounts/list");
    assert_eq!(upstream.url.query(), Some("x=1"));
    let auth = upstream
        .headers
        .get("authorization")
        .expect("signed Authorization header forwarded upstream")
        .to_str()
        .unwrap();
    assert!(auth.starts_with("OAuth "));
    // The signed query parameter participated in the signature.
    assert_eq!(oauth_param(auth, "oauth_token").as_deref(), Some("acctok"));
}

#[tokio::test]
async fn post_under_prefix_is_405_and_never_forwarded() {
    let server = MockServer::start().await;
    // Mount a catch-all that would record a hit if anything were forwarded.
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FixedClock::new(1_700_000_000));
    let nonces: Arc<dyn NonceSource + Send + Sync> = Arc::new(CounterNonceSource::new());
    let app = ready_router(server.uri(), clock, nonces);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/etrade-api/v1/accounts/ABC123/orders")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Structural GET-only guarantee: ZERO upstream hits.
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests.is_empty(),
        "a non-GET must never reach the upstream, got {} hit(s)",
        requests.len()
    );
}

#[tokio::test]
async fn out_of_prefix_get_is_404() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FixedClock::new(1_700_000_000));
    let nonces: Arc<dyn NonceSource + Send + Sync> = Arc::new(CounterNonceSource::new());
    let app = ready_router(server.uri(), clock, nonces);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/not/the/prefix")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn sequential_gets_carry_distinct_nonces() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/accounts/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;

    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FixedClock::new(1_700_000_000));
    // A counter-backed NonceSource shared across both requests via the router's
    // app state, so sequential requests draw "nonce-0" then "nonce-1".
    let nonces: Arc<dyn NonceSource + Send + Sync> = Arc::new(CounterNonceSource::new());
    let app = ready_router(server.uri(), clock, nonces);

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/etrade-api/v1/accounts/list")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2, "two upstream hits recorded");

    let nonce_of = |i: usize| {
        let auth = requests[i]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        oauth_param(auth, "oauth_nonce").expect("oauth_nonce present")
    };
    assert_ne!(
        nonce_of(0),
        nonce_of(1),
        "two sequential proxied requests must carry distinct oauth_nonce values"
    );
}
