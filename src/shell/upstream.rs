//! Outbound resource-leg forwarding: sign the proxied `GET` via the pure core,
//! send it with `reqwest`, and buffer the response with a hard size cap.
//!
//! The body is **fully buffered (bounded)** before any status/headers are
//! written to the local client, so an upstream read error or an over-cap body
//! maps cleanly to `502` with no mid-stream window. Only whitelisted headers
//! are copied; `Content-Length` and hop-by-hop headers are dropped.

use reqwest::Client;

use crate::core::config::Config;
use crate::core::env::UpstreamHost;
use crate::core::newtypes::ResourcePath;
use crate::core::oauth::base_string::upstream_base_url;
use crate::core::oauth::params::SigningInput;
use crate::core::oauth::sign::sign_leg;
use crate::core::oauth::{split_query, wire_query};
use crate::core::relay::relay_header_allowed;
use crate::core::status::Authorized;
use crate::shell::clock_nonce::Signer;
use crate::shell::error::ProxyError;

/// Hard cap on the upstream response body (8 MiB). A misbehaving or compromised
/// upstream cannot drive unbounded allocation; exceeding the cap is an upstream
/// fault mapped to `502`.
pub const UPSTREAM_BODY_CAP: usize = 8 * 1024 * 1024;

/// A buffered upstream response ready to relay to the local client.
pub struct RelayedResponse {
    pub status: u16,
    /// Whitelisted `(name, value)` headers only.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Forward one admitted `GET` request upstream and buffer the response.
///
/// Thin delegator over [`signed_get`]: the proxy handler's forward path and the
/// startup probe share the exact same signing/send/relay machinery. `admit`
/// produces `mapped_path` (e.g. `/v1/accounts/list?x=1`). `accept` carries the
/// client's `Accept` header through to the upstream (e.g.
/// `application/json`) so callers can select ETrade's JSON representation;
/// `None` sends no `Accept` and ETrade returns its default (XML).
pub async fn forward(
    client: &Client,
    config: &Config,
    authorized: &Authorized,
    mapped_path: &str,
    accept: Option<&str>,
    base_url_override: Option<&str>,
    signer: Signer<'_>,
) -> Result<RelayedResponse, ProxyError> {
    signed_get(
        client,
        config,
        authorized,
        mapped_path,
        accept,
        base_url_override,
        signer,
    )
    .await
}

/// Sign and send one resource-leg `GET` for a given mapped path, buffering the
/// response with a hard size cap.
///
/// This is the shared signed-GET machinery used by BOTH the per-request proxy
/// handler ([`forward`]) and the startup authorization probe
/// ([`crate::shell::probe`]), so there is exactly one place that signs a
/// resource request. `mapped_path` is the upstream path+query (e.g.
/// `/v1/accounts/list?x=1`). `accept`, when present, is forwarded verbatim as
/// the upstream `Accept` header so a client can request ETrade's JSON
/// representation; `None` omits it. The `Accept` header is not part of the
/// OAuth 1.0a signature base string, so forwarding it does not affect signing.
/// `base_url_override` points the request at a local fake in tests (replacing
/// the `https://api.etrade.com` host); production passes `None`. A fresh
/// `(nonce, timestamp)` is drawn here, immediately before signing, so every
/// call signs with a distinct nonce.
pub async fn signed_get(
    client: &Client,
    config: &Config,
    authorized: &Authorized,
    mapped_path: &str,
    accept: Option<&str>,
    base_url_override: Option<&str>,
    signer: Signer<'_>,
) -> Result<RelayedResponse, ProxyError> {
    // Split the query off the mapped path; the pure core decodes and filters.
    let (path, query_params) = split_query(mapped_path);
    let resource_path = ResourcePath::new(path.clone());

    // The selected environment's upstream host, threaded as data so the signed
    // base URI matches the sent URL exactly.
    let host = config.environment().host();

    // Fresh nonce/timestamp immediately before signing.
    let (ts, nonce) = signer.fresh();
    let signed = sign_leg(
        &host,
        &SigningInput::Resource {
            consumer_key: config.consumer_key(),
            access_token: authorized.access_token(),
            access_token_secret: authorized.token_secret(),
            path: &resource_path,
        },
        config.consumer_secret(),
        &query_params,
        &nonce,
        &ts,
    );

    // Build the wire URL from the SAME signed pairs (never the raw client query)
    // so the signed set and sent set are byte-identical.
    let wire = wire_query(&query_params);
    let url = build_url(&host, base_url_override, &path, &wire);

    let mut request = client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, &signed.authorization_header);
    // Forward the client's Accept verbatim so it can select ETrade's JSON
    // representation. Not part of the OAuth signature base string.
    if let Some(accept) = accept {
        request = request.header(reqwest::header::ACCEPT, accept);
    }
    let response = request.send().await?;

    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter(|(name, _)| relay_header_allowed(name.as_str()))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect();

    let body = read_bounded(response).await?;

    Ok(RelayedResponse {
        status,
        headers,
        body,
    })
}

/// Build the outbound URL. Uses `upstream_base_url` for the selected `host` so
/// the sent host matches the signed base URI exactly; a test override replaces
/// the host while preserving the path and query.
fn build_url(host: &UpstreamHost, base_url_override: Option<&str>, path: &str, wire: &str) -> String {
    let base = match base_url_override {
        Some(base) => format!("{}{}", base.trim_end_matches('/'), path),
        None => upstream_base_url(host, path),
    };
    if wire.is_empty() {
        base
    } else {
        format!("{base}?{wire}")
    }
}

/// Read the response body with a hard cap, chunk by chunk. Exceeding
/// [`UPSTREAM_BODY_CAP`] maps to [`ProxyError::UpstreamTooLarge`].
async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, ProxyError> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if buf.len() + chunk.len() > UPSTREAM_BODY_CAP {
            return Err(ProxyError::UpstreamTooLarge {
                cap: UPSTREAM_BODY_CAP,
            });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::{build_config, EnvSnapshot};
    use crate::core::env::Environment;
    use crate::core::newtypes::{AccessToken, ListenPort, TokenSecret};
    use crate::core::status::Unauthorized;
    use crate::shell::clock_nonce::{CounterNonceSource, FixedClock};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config() -> Config {
        let env = EnvSnapshot {
            consumer_key: Some("ckey".into()),
            consumer_secret: Some("csec".into()),
        };
        build_config(&env, ListenPort::new(8443), Environment::Live).unwrap()
    }

    fn authorized() -> Authorized {
        Unauthorized.authorize(AccessToken::new("acctok"), TokenSecret::new("accsec"))
    }

    #[test]
    fn build_url_preserves_path_and_query() {
        let live = Environment::Live.host();
        assert_eq!(
            build_url(&live, Some("http://127.0.0.1:9000"), "/v1/accounts/list", "x=1"),
            "http://127.0.0.1:9000/v1/accounts/list?x=1"
        );
        assert_eq!(
            build_url(&live, Some("http://127.0.0.1:9000"), "/v1/accounts/list", ""),
            "http://127.0.0.1:9000/v1/accounts/list"
        );
        assert_eq!(
            build_url(&live, None, "/v1/accounts/list", ""),
            "https://api.etrade.com/v1/accounts/list"
        );
    }

    #[test]
    fn build_url_none_uses_sandbox_host() {
        let sandbox = Environment::Sandbox.host();
        assert_eq!(
            build_url(&sandbox, None, "/v1/accounts/list", ""),
            "https://apisb.etrade.com/v1/accounts/list"
        );
    }

    #[tokio::test]
    async fn forwards_with_query_and_filters_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/accounts/list"))
            .and(query_param("x", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .insert_header("x-custom", "drop-me")
                    .set_body_string(r#"{"ok":true}"#),
            )
            .mount(&server)
            .await;

        let client = Client::new();
        let config = config();
        let authed = authorized();
        let clock = FixedClock::new(1_700_000_000);
        let nonces = CounterNonceSource::new();
        let relayed = forward(
            &client,
            &config,
            &authed,
            "/v1/accounts/list?x=1",
            None,
            Some(&server.uri()),
            Signer::new(&clock, &nonces),
        )
        .await
        .expect("forward succeeds");

        assert_eq!(relayed.status, 200);
        assert_eq!(relayed.body, br#"{"ok":true}"#);
        // Whitelisted header kept, custom header dropped, content-length dropped.
        assert!(relayed
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("content-type")));
        assert!(!relayed
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("x-custom")));
        assert!(!relayed
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("content-length")));
    }

    #[tokio::test]
    async fn over_cap_body_maps_to_too_large() {
        let server = MockServer::start().await;
        let big = vec![b'a'; UPSTREAM_BODY_CAP + 1];
        Mock::given(method("GET"))
            .and(path("/v1/accounts/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(big))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = config();
        let authed = authorized();
        let clock = FixedClock::new(1_700_000_000);
        let nonces = CounterNonceSource::new();
        let result = forward(
            &client,
            &config,
            &authed,
            "/v1/accounts/big",
            None,
            Some(&server.uri()),
            Signer::new(&clock, &nonces),
        )
        .await;
        assert!(matches!(
            result,
            Err(ProxyError::UpstreamTooLarge { cap }) if cap == UPSTREAM_BODY_CAP
        ));
    }

    #[tokio::test]
    async fn accept_header_is_forwarded_upstream() {
        use wiremock::matchers::header as match_header;

        let server = MockServer::start().await;
        // The mock only matches when the upstream request carries the Accept
        // header the client sent, proving passthrough.
        Mock::given(method("GET"))
            .and(path("/v1/accounts/list"))
            .and(match_header("accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = config();
        let authed = authorized();
        let clock = FixedClock::new(1_700_000_000);
        let nonces = CounterNonceSource::new();
        let relayed = forward(
            &client,
            &config,
            &authed,
            "/v1/accounts/list",
            Some("application/json"),
            Some(&server.uri()),
            Signer::new(&clock, &nonces),
        )
        .await
        .expect("forward with Accept succeeds");
        assert_eq!(relayed.status, 200);
    }

    #[tokio::test]
    async fn no_accept_header_sends_none() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/accounts/list"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<xml/>"))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = config();
        let authed = authorized();
        let clock = FixedClock::new(1_700_000_000);
        let nonces = CounterNonceSource::new();
        let relayed = forward(
            &client,
            &config,
            &authed,
            "/v1/accounts/list",
            None,
            Some(&server.uri()),
            Signer::new(&clock, &nonces),
        )
        .await
        .expect("forward without Accept succeeds");
        assert_eq!(relayed.status, 200);

        // With `accept = None` the proxy does not forward a client-chosen
        // Accept. (reqwest still sets its own default `*/*`; what matters is we
        // did not inject `application/json`.)
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let sent_accept = requests[0]
            .headers
            .get("accept")
            .map(|v| v.to_str().unwrap().to_string());
        assert_ne!(
            sent_accept.as_deref(),
            Some("application/json"),
            "no client Accept should be forwarded when accept is None"
        );
    }
}
