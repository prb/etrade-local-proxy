//! The OAuth 1.0a three-leg startup flow.
//!
//! Each leg draws a **fresh** `(nonce, timestamp)` from the injected generators
//! immediately before signing, so no value is reused across legs. The signing
//! itself is pure (`core::oauth::sign::sign_leg`); only the two GETs and the
//! stdin prompt are effects. The leg-1 parser logs `oauth_callback_confirmed`
//! (informational) so the `oauth_callback=oob` assumption is actively confirmed
//! on the first live run.

use reqwest::Client;

use crate::core::authorize_url::authorize_url;
use crate::core::config::Config;
use crate::core::error::{parse_oauth_token_response, OauthTokenResponse};
use crate::core::env::UpstreamHost;
use crate::core::newtypes::{AccessToken, RequestToken, TokenSecret, Verifier};
use crate::core::oauth::endpoints::{oauth_endpoint_url, ACCESS_TOKEN_PATH, REQUEST_TOKEN_PATH};
use crate::core::oauth::params::SigningInput;
use crate::core::oauth::sign::sign_leg;
use crate::core::status::{Authorized, Unauthorized};
use crate::shell::clock_nonce::{Clock, NonceSource};
use crate::shell::error::OauthFlowError;

/// The callback token sent on the request-token leg (out-of-band: no redirect).
const CALLBACK_OOB: &str = "oob";

/// Human-readable endpoint labels used in diagnostics.
const REQUEST_TOKEN_LABEL: &str = "REQUEST_TOKEN_PATH (/oauth/request_token)";
const ACCESS_TOKEN_LABEL: &str = "ACCESS_TOKEN_PATH (/oauth/access_token)";

/// Run the three-leg flow against ETrade (or a local fake), returning the
/// [`Authorized`] token on success.
///
/// `verifier_prompt` reads the verifier from the console given the authorize
/// URL; it is injected so integration tests can drive the flow without stdin.
/// Production callers pass [`crate::shell::prompt::read_verifier`].
pub async fn run(
    config: &Config,
    base_url_override: Option<&str>,
    clock: &dyn Clock,
    nonces: &dyn NonceSource,
    verifier_prompt: impl FnOnce(&str) -> Result<Verifier, OauthFlowError>,
) -> Result<Authorized, OauthFlowError> {
    let client = Client::new();

    // The selected environment's upstream host, threaded as data into both
    // signing and URL construction so signing matches sending.
    let host = config.environment().host();

    // --- Leg 1: request token (fresh nonce/ts) ---
    let ts = clock.now_unix();
    let nonce = nonces.next();
    let leg1 = sign_leg(
        &host,
        &SigningInput::RequestToken {
            consumer_key: config.consumer_key(),
            callback: CALLBACK_OOB,
        },
        config.consumer_secret(),
        &[],
        &nonce,
        &ts,
    );

    let request_token_url = endpoint_url(&host, base_url_override, REQUEST_TOKEN_PATH);
    let body = fetch_leg(
        &client,
        &request_token_url,
        &leg1.authorization_header,
        REQUEST_TOKEN_LABEL,
        OauthFlowError::CALLBACK_HINT,
    )
    .await?;
    let request_token: OauthTokenResponse = parse_leg(&body, REQUEST_TOKEN_LABEL)?;

    // Informational: confirm the oauth_callback=oob assumption on first run.
    match request_token.callback_confirmed {
        Some(true) => eprintln!("info: oauth_callback_confirmed=true (oob accepted)"),
        Some(false) => {
            eprintln!("warn: oauth_callback_confirmed=false; verify oauth_callback=oob is accepted")
        }
        None => {
            eprintln!("info: oauth_callback_confirmed absent in request-token response (non-fatal)")
        }
    }

    let rt = RequestToken::new(request_token.oauth_token);
    let rt_secret = TokenSecret::new(request_token.oauth_token_secret);

    // --- Console: print authorize URL, read verifier ---
    let url = authorize_url(config.consumer_key(), &rt);
    let verifier = verifier_prompt(&url)?;

    // --- Leg 2: access token (fresh nonce/ts) ---
    let ts = clock.now_unix();
    let nonce = nonces.next();
    let leg2 = sign_leg(
        &host,
        &SigningInput::AccessToken {
            consumer_key: config.consumer_key(),
            request_token: &rt,
            request_token_secret: &rt_secret,
            verifier: &verifier,
        },
        config.consumer_secret(),
        &[],
        &nonce,
        &ts,
    );

    let access_token_url = endpoint_url(&host, base_url_override, ACCESS_TOKEN_PATH);
    let body = fetch_leg(
        &client,
        &access_token_url,
        &leg2.authorization_header,
        ACCESS_TOKEN_LABEL,
        OauthFlowError::NO_HINT,
    )
    .await?;
    let access_token: OauthTokenResponse = parse_leg(&body, ACCESS_TOKEN_LABEL)?;

    Ok(Unauthorized.authorize(
        AccessToken::new(access_token.oauth_token),
        TokenSecret::new(access_token.oauth_token_secret),
    ))
}

/// Build a leg URL, honoring a test base-URL override (so the flow can be
/// pointed at a local wiremock server). The override replaces the
/// `https://{host}` host; the leg path is preserved.
fn endpoint_url(host: &UpstreamHost, base_url_override: Option<&str>, path: &str) -> String {
    match base_url_override {
        Some(base) => format!("{}{}", base.trim_end_matches('/'), path),
        None => oauth_endpoint_url(host, path),
    }
}

/// GET one leg with the signed `Authorization` header and return the response
/// body text. The ETrade OAuth token legs are GET requests (all OAuth
/// parameters ride in the `Authorization` header; there is no body), which is
/// also what the signature base string is computed over (`HttpMethod::Get`).
/// A non-2xx status maps to [`OauthFlowError::UnexpectedStatus`].
async fn fetch_leg(
    client: &Client,
    url: &str,
    authorization: &str,
    endpoint: &'static str,
    callback_hint: &'static str,
) -> Result<String, OauthFlowError> {
    let response = client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(OauthFlowError::UnexpectedStatus {
            endpoint,
            code: status.as_u16(),
            callback_hint,
        });
    }
    Ok(body)
}

/// Parse a leg's form body, mapping a parse error to [`OauthFlowError::Parse`].
fn parse_leg(body: &str, endpoint: &'static str) -> Result<OauthTokenResponse, OauthFlowError> {
    parse_oauth_token_response(body).map_err(|source| OauthFlowError::Parse { endpoint, source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::{build_config, EnvSnapshot};
    use crate::core::env::Environment;
    use crate::core::newtypes::ListenPort;
    use crate::shell::clock_nonce::{CounterNonceSource, FixedClock};

    fn test_config() -> Config {
        let env = EnvSnapshot {
            consumer_key: Some("ckey".into()),
            consumer_secret: Some("csec".into()),
        };
        build_config(&env, ListenPort::new(8443), Environment::Live).unwrap()
    }

    #[test]
    fn endpoint_url_uses_override_host() {
        let live = Environment::Live.host();
        assert_eq!(
            endpoint_url(&live, Some("http://127.0.0.1:9000"), "/oauth/request_token"),
            "http://127.0.0.1:9000/oauth/request_token"
        );
        assert_eq!(
            endpoint_url(&live, Some("http://127.0.0.1:9000/"), "/oauth/request_token"),
            "http://127.0.0.1:9000/oauth/request_token"
        );
        assert_eq!(
            endpoint_url(&live, None, "/oauth/request_token"),
            "https://api.etrade.com/oauth/request_token"
        );
    }

    #[test]
    fn endpoint_url_none_uses_sandbox_host() {
        let sandbox = Environment::Sandbox.host();
        assert_eq!(
            endpoint_url(&sandbox, None, "/oauth/request_token"),
            "https://apisb.etrade.com/oauth/request_token"
        );
    }

    #[tokio::test]
    async fn empty_verifier_aborts_flow_after_leg1() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth/request_token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "oauth_token=reqtok&oauth_token_secret=reqsec&oauth_callback_confirmed=true",
            ))
            .mount(&server)
            .await;

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

    #[tokio::test]
    async fn full_flow_produces_authorized() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let nonces = CounterNonceSource::new();
        let authorized = run(
            &config,
            Some(&server.uri()),
            &clock,
            &nonces,
            |_url| Ok(Verifier::new("verifier-code")),
        )
        .await
        .expect("flow succeeds");
        assert_eq!(authorized.access_token().as_str(), "acctok");
    }

    #[tokio::test]
    async fn non_2xx_maps_to_unexpected_status() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth/request_token"))
            .respond_with(ResponseTemplate::new(401).set_body_string("nope"))
            .mount(&server)
            .await;

        let config = test_config();
        let clock = FixedClock::new(1_700_000_000);
        let nonces = CounterNonceSource::new();
        let result = run(
            &config,
            Some(&server.uri()),
            &clock,
            &nonces,
            |_url| Ok(Verifier::new("v")),
        )
        .await;
        match result {
            Err(OauthFlowError::UnexpectedStatus { code, callback_hint, .. }) => {
                assert_eq!(code, 401);
                assert!(!callback_hint.is_empty());
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }
}
