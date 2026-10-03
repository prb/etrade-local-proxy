//! Shell error enums (typed, per-module `thiserror`, `#[non_exhaustive]`, with
//! `#[from]` for clean `?`). `anyhow` is reserved for `main`.

use thiserror::Error;

use crate::core::error::OauthParseError;

/// TLS setup errors. Fatal at startup.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TlsError {
    /// `rcgen` failed to generate the self-signed certificate/key.
    #[error("failed to generate self-signed certificate")]
    CertGeneration(#[from] rcgen::Error),
    /// `rustls` rejected the generated cert/key when building the server config.
    #[error("failed to build rustls server config")]
    RustlsConfig(#[source] rustls::Error),
}

/// OAuth three-leg startup flow errors. Fatal at startup; the user sees a clear
/// message and re-runs. No token material appears in any message.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OauthFlowError {
    /// The outbound HTTP request to ETrade failed at the transport layer.
    #[error("OAuth HTTP request failed")]
    Http(#[from] reqwest::Error),
    /// A leg returned a non-2xx status. The message names the endpoint
    /// constant; the request-token leg additionally flags `oauth_callback=oob`
    /// as an unverified assumption to check on a 401.
    #[error(
        "OAuth leg {endpoint} returned HTTP {code} \u{2014} verify this path \
         against the current ETrade authorization docs (an unverified \
         assumption, see core::oauth::endpoints){callback_hint}"
    )]
    UnexpectedStatus {
        endpoint: &'static str,
        code: u16,
        /// Extra hint appended for the request-token leg about the `oob`
        /// callback assumption; empty for other legs.
        callback_hint: &'static str,
    },
    /// A leg's form body could not be parsed.
    #[error(
        "OAuth leg {endpoint} response could not be parsed \u{2014} verify this \
         path against the current ETrade authorization docs (see \
         core::oauth::endpoints)"
    )]
    Parse {
        endpoint: &'static str,
        #[source]
        source: OauthParseError,
    },
    /// Reading the verifier from stdin failed.
    #[error("failed to read the verifier from stdin")]
    Prompt(#[from] std::io::Error),
    /// The verifier was empty after trimming (single prompt, no re-prompt).
    #[error("no verifier entered; re-run the proxy and paste the verifier code")]
    EmptyVerifier,
}

impl OauthFlowError {
    /// The hint appended to [`OauthFlowError::UnexpectedStatus`] for the
    /// request-token leg (the only leg where `oauth_callback=oob` is in play).
    pub const CALLBACK_HINT: &'static str =
        "; if this is a 401, also verify oauth_callback=oob is accepted";
    /// No extra hint for the non-request-token legs.
    pub const NO_HINT: &'static str = "";
}

/// Per-request proxy errors, each mapped to a single HTTP status by the handler
/// (`Upstream`/`UpstreamTooLarge` → 502, `NotReady` → 503). Recoverable: the
/// process keeps running.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// The outbound request to ETrade failed (send or read). Maps to 502.
    #[error("upstream request failed")]
    Upstream(#[from] reqwest::Error),
    /// The upstream body exceeded the hard cap. Maps to 502.
    #[error("upstream response body exceeded the {cap}-byte cap")]
    UpstreamTooLarge { cap: usize },
    /// The proxy has not completed authorization yet. Maps to 503.
    #[error("proxy is not ready: authorization has not completed")]
    NotReady,
}

/// Server bind/TLS errors. Fatal at startup.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServerError {
    /// Binding the loopback listener failed.
    #[error("failed to bind the loopback listener")]
    Bind(#[from] std::io::Error),
    /// TLS setup failed.
    #[error("TLS setup failed")]
    Tls(#[from] TlsError),
}
