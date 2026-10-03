//! Signature base string construction per RFC 5849 §3.4.1 (pure).

use super::{oauth_encode, HttpMethod};
use crate::core::env::UpstreamHost;

/// Build the normalized base URI per RFC 5849 §3.4.1.2 for a mapped upstream
/// path: lowercase scheme `https`, lowercase `host`, default port 443 omitted,
/// path only, no query, no fragment.
///
/// This is the single construction site for the signed base URI, so the
/// normalization rule cannot drift. The host arrives as data (the selected
/// [`UpstreamHost`]) and is already lowercase and port-free; callers must route
/// all base-URI construction through here so signing matches sending.
pub fn upstream_base_url(host: &UpstreamHost, path: &str) -> String {
    format!("https://{}{}", host.as_str(), path)
}

/// Build the signature base string.
///
/// `base_url` MUST already be normalized (built via [`upstream_base_url`]); this
/// function does not re-normalize it. `base_params` is
/// `OauthParams::as_pairs()` unioned with the query params (no
/// `oauth_signature`). Steps, in order:
///
/// 1. percent-encode every parameter name and value with [`oauth_encode`];
/// 2. stable-sort a **copy** of the already-encoded pairs by encoded name, then
///    encoded value (RFC 5849 §3.4.1.3.2);
/// 3. join as `name=value` with `&`;
/// 4. return `METHOD & oauth_encode(base_url) & oauth_encode(joined)`.
pub fn signature_base_string(
    method: &HttpMethod,
    base_url: &str,
    base_params: &[(String, String)],
) -> String {
    let mut encoded: Vec<(String, String)> = base_params
        .iter()
        .map(|(name, value)| (oauth_encode(name), oauth_encode(value)))
        .collect();
    // Stable sort over the full multiset so duplicate names are kept and
    // ordered by (encoded) value.
    encoded.sort();

    let joined = encoded
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");

    format!(
        "{}&{}&{}",
        method.as_str(),
        oauth_encode(base_url),
        oauth_encode(&joined)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::env::Environment;
    use proptest::prelude::*;

    #[test]
    fn upstream_base_url_normalized() {
        assert_eq!(
            upstream_base_url(&Environment::Live.host(), "/v1/accounts/list"),
            "https://api.etrade.com/v1/accounts/list"
        );
    }

    #[test]
    fn upstream_base_url_sandbox_host() {
        assert_eq!(
            upstream_base_url(&Environment::Sandbox.host(), "/v1/accounts/list"),
            "https://apisb.etrade.com/v1/accounts/list"
        );
    }

    #[test]
    fn base_string_rfc5849_shape() {
        let params = vec![
            ("oauth_consumer_key".to_string(), "key".to_string()),
            ("oauth_nonce".to_string(), "abc".to_string()),
            ("a".to_string(), "1".to_string()),
        ];
        let bs = signature_base_string(
            &HttpMethod::Get,
            "https://api.etrade.com/v1/accounts/list",
            &params,
        );
        assert!(bs.starts_with("GET&"));
        // The base URL is percent-encoded.
        assert!(bs.contains("https%3A%2F%2Fapi.etrade.com%2Fv1%2Faccounts%2Flist"));
        // Params are sorted (a before oauth_*) and joined with encoded &.
        assert!(bs.contains("a%3D1%26oauth_consumer_key%3Dkey"));
        // Never contains an unencoded oauth_signature.
        assert!(!bs.contains("oauth_signature"));
    }

    #[test]
    fn base_string_sorts_duplicate_names_by_value() {
        let params = vec![
            ("symbol".to_string(), "B".to_string()),
            ("symbol".to_string(), "A".to_string()),
        ];
        let bs = signature_base_string(&HttpMethod::Get, "https://api.etrade.com/p", &params);
        // After sorting, symbol=A precedes symbol=B.
        let a_pos = bs.find("symbol%3DA").unwrap();
        let b_pos = bs.find("symbol%3DB").unwrap();
        assert!(a_pos < b_pos);
    }

    proptest! {
        // Determinism: identical inputs always yield an identical base string.
        #[test]
        fn base_string_deterministic(
            params in proptest::collection::vec(
                ("[a-z]{1,5}", "[a-zA-Z0-9]{0,6}"),
                0..6,
            )
        ) {
            let a = signature_base_string(&HttpMethod::Get, "https://api.etrade.com/p", &params);
            let b = signature_base_string(&HttpMethod::Get, "https://api.etrade.com/p", &params);
            prop_assert_eq!(a, b);
        }

        // Never panics over arbitrary parameter sets.
        #[test]
        fn base_string_total(
            params in proptest::collection::vec((".*", ".*"), 0..8)
        ) {
            let _ = signature_base_string(&HttpMethod::Get, "https://api.etrade.com/p", &params);
        }

        // Base string never contains the oauth_signature key.
        #[test]
        fn base_string_excludes_signature(
            params in proptest::collection::vec(("[a-z]{1,5}", "[a-z0-9]{0,6}"), 0..6)
        ) {
            let bs = signature_base_string(&HttpMethod::Get, "https://api.etrade.com/p", &params);
            prop_assert!(!bs.contains("oauth_signature"));
        }
    }
}
