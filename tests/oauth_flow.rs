//! Integration test for the OAuth 1.0a three-leg startup flow against a LOCAL
//! `wiremock` fake standing in for `api.etrade.com` (AC-13 — no live calls).
//!
//! Asserts an `Authorized` is produced, that the recorded request-token call's
//! signed parameter set carries `oauth_callback=oob`, that the access-token
//! call's carries `oauth_verifier=<code>`, and that the two legs carry DISTINCT
//! `oauth_nonce` values (the per-leg freshness contract). Because the pure core
//! builds the base string and the `Authorization` header from the same
//! `OauthParams::as_pairs()`, asserting on the recorded header is equivalent to
//! asserting on the signature base string.

mod common;

use common::{oauth_param, test_config};

use etrade_local_proxy::core::newtypes::Verifier;
use etrade_local_proxy::shell::clock_nonce::{CounterNonceSource, FixedClock};
use etrade_local_proxy::shell::error::OauthFlowError;
use etrade_local_proxy::shell::oauth_flow::run;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The authorization header reqwest recorded for the request at `req_path`.
async fn recorded_authorization(server: &MockServer, req_path: &str) -> String {
    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled");
    let req = requests
        .iter()
        .find(|r| r.url.path() == req_path)
        .unwrap_or_else(|| panic!("a request to {req_path} was recorded"));
    req.headers
        .get("authorization")
        .expect("Authorization header present")
        .to_str()
        .expect("Authorization header is valid ASCII")
        .to_string()
}

#[tokio::test]
async fn three_leg_flow_signs_each_leg_with_distinct_nonces() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oauth/request_token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "oauth_token=reqtok&oauth_token_secret=reqsec&oauth_callback_confirmed=true",
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/oauth/access_token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("oauth_token=acctok&oauth_token_secret=accsec"),
        )
        .mount(&server)
        .await;

    let config = test_config();
    let clock = FixedClock::new(1_700_000_000);
    // Counter-backed nonces: leg 1 draws "nonce-0", leg 2 draws "nonce-1".
    let nonces = CounterNonceSource::new();

    let authorized = run(
        &config,
        Some(&server.uri()),
        &clock,
        &nonces,
        |_url| Ok(Verifier::new("verifier-code")),
    )
    .await
    .expect("the three-leg flow produces an Authorized token");

    // An Authorized value was produced carrying the access token from leg 2.
    assert_eq!(authorized.access_token().as_str(), "acctok");

    // --- Leg 1 (request token): signed set carries oauth_callback=oob ---
    let leg1_auth = recorded_authorization(&server, "/oauth/request_token").await;
    assert_eq!(
        oauth_param(&leg1_auth, "oauth_callback").as_deref(),
        Some("oob"),
        "request-token base string must sign oauth_callback=oob"
    );
    // Leg 1 carries no token (never emitted empty).
    assert!(
        oauth_param(&leg1_auth, "oauth_token").is_none(),
        "request-token leg must not emit oauth_token"
    );

    // --- Leg 2 (access token): signed set carries oauth_verifier=<code> ---
    let leg2_auth = recorded_authorization(&server, "/oauth/access_token").await;
    assert_eq!(
        oauth_param(&leg2_auth, "oauth_verifier").as_deref(),
        Some("verifier-code"),
        "access-token base string must sign oauth_verifier"
    );
    // Leg 2 carries the request token as oauth_token.
    assert_eq!(
        oauth_param(&leg2_auth, "oauth_token").as_deref(),
        Some("reqtok"),
        "access-token leg signs with the request token"
    );

    // --- The two legs carry DISTINCT oauth_nonce values (freshness) ---
    let nonce1 = oauth_param(&leg1_auth, "oauth_nonce").expect("leg 1 nonce");
    let nonce2 = oauth_param(&leg2_auth, "oauth_nonce").expect("leg 2 nonce");
    assert_ne!(
        nonce1, nonce2,
        "each OAuth leg must draw a fresh, distinct oauth_nonce"
    );
}

#[tokio::test]
async fn empty_verifier_aborts_without_calling_access_token_leg() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth/request_token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "oauth_token=reqtok&oauth_token_secret=reqsec&oauth_callback_confirmed=true",
        ))
        .mount(&server)
        .await;
    // No access-token mock mounted: if the flow reached leg 2 it would fail
    // with a 404-driven UnexpectedStatus instead of EmptyVerifier.

    let config = test_config();
    let clock = FixedClock::new(1_700_000_000);
    let nonces = CounterNonceSource::new();

    let result = run(
        &config,
        Some(&server.uri()),
        &clock,
        &nonces,
        |_url| Err(OauthFlowError::EmptyVerifier),
    )
    .await;

    assert!(matches!(result, Err(OauthFlowError::EmptyVerifier)));
}
