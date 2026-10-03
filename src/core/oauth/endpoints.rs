//! Single source of truth for every ETrade host and path literal, so the
//! proxied host cannot drift between the resource leg and the OAuth flow.
//!
//! # First-run verification (documented assumptions)
//!
//! The three values below are drawn from the ETrade authorization docs linked
//! in `CONCEPT.md` and could not be byte-verified against the live service in
//! this environment. They are **not** blockers: no automated test makes a live
//! call (AC-13), so the suite passes regardless. On the first live run with
//! real credentials, confirm and record the date beside each constant:
//!
//! 1. the two OAuth leg paths ([`REQUEST_TOKEN_PATH`], [`ACCESS_TOKEN_PATH`])
//!    resolve (leg 1 and leg 2 return 2xx, not 404);
//! 2. the authorize URL ([`AUTHORIZE_URL_BASE`]) opens ETrade's authorization
//!    page;
//! 3. `oauth_callback=oob` is accepted — the request-token response body
//!    contains `oauth_callback_confirmed=true`.
//!
//! Each is isolated here as a named constant / single call site, so a
//! correction is a one-line change.

/// Host for proxied read calls AND the two OAuth token legs. Fixed by FR-5.
/// Live ETrade API host (see <https://developer.etrade.com/documentation>).
pub const UPSTREAM_HOST: &str = "api.etrade.com";

/// OAuth 1.0a request-token leg path.
///
/// Documented assumption — confirm on first live run (see module docs).
pub const REQUEST_TOKEN_PATH: &str = "/oauth/request_token";

/// OAuth 1.0a access-token leg path.
///
/// Documented assumption — confirm on first live run (see module docs).
pub const ACCESS_TOKEN_PATH: &str = "/oauth/access_token";

/// Browser-facing authorize URL base (host + path). Fixed by AC-12.
///
/// Documented assumption — confirm on first live run (see module docs).
pub const AUTHORIZE_URL_BASE: &str = "https://us.etrade.com/e/t/etws/authorize";

/// Full `https` URL for an OAuth leg on [`UPSTREAM_HOST`].
///
/// Builds `https://{UPSTREAM_HOST}{path}`, so [`UPSTREAM_HOST`] is the only
/// source of the host and no literal is duplicated.
pub fn oauth_endpoint_url(path: &str) -> String {
    format!("https://{UPSTREAM_HOST}{path}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_url_uses_single_host_constant() {
        assert_eq!(
            oauth_endpoint_url(REQUEST_TOKEN_PATH),
            "https://api.etrade.com/oauth/request_token"
        );
        assert_eq!(
            oauth_endpoint_url(ACCESS_TOKEN_PATH),
            "https://api.etrade.com/oauth/access_token"
        );
    }

    #[test]
    fn constants_are_stable() {
        assert_eq!(UPSTREAM_HOST, "api.etrade.com");
        assert_eq!(AUTHORIZE_URL_BASE, "https://us.etrade.com/e/t/etws/authorize");
    }
}
