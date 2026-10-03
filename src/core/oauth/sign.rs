//! HMAC-SHA1 signing + `Authorization` header construction (pure).
//!
//! [`sign_leg`] is the single enforcing call site for the per-leg token/secret
//! pairing: it matches the [`SigningInput`] variant to pick the leg's token
//! secret and pairs it with the leg's public token, builds the base string,
//! signs it, and renders the header. The lower-level functions remain public so
//! property tests can exercise each stage in isolation.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha1::Sha1;

use super::base_string::signature_base_string;
use super::params::{oauth_params, OauthParams, SigningInput};
use super::{oauth_encode, HttpMethod};
use crate::core::env::UpstreamHost;
use crate::core::newtypes::{ConsumerSecret, Nonce, Timestamp, TokenSecret};

type HmacSha1 = Hmac<Sha1>;

/// The HMAC key: `oauth_encode(consumer_secret) & oauth_encode(token_secret)`,
/// where an absent token secret contributes the empty string.
///
/// This is the **one and only source-level `expose_secret()` call site**. The
/// exposed `&str` is folded into the returned key `String` and never escapes
/// this function.
pub fn signing_key(consumer_secret: &ConsumerSecret, token_secret: Option<&TokenSecret>) -> String {
    let consumer = oauth_encode(consumer_secret.secret().expose_secret());
    let token = token_secret
        .map(|t| oauth_encode(t.secret().expose_secret()))
        .unwrap_or_default();
    format!("{consumer}&{token}")
}

/// HMAC-SHA1 over the base string, base64-encoded with the standard alphabet
/// (with padding). Uses base64 `0.22`'s engine API.
pub fn sign_hmac_sha1(base_string: &str, signing_key: &str) -> String {
    // Hmac accepts a key of any length, so this construction cannot fail; the
    // `expect` documents that invariant.
    let mut mac = HmacSha1::new_from_slice(signing_key.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(base_string.as_bytes());
    let bytes = mac.finalize().into_bytes();
    STANDARD.encode(bytes)
}

/// Render the full `Authorization` header value.
///
/// Renders **exactly** the pairs in `params.as_pairs()` plus the injected
/// `oauth_signature` — each value run through the shared [`oauth_encode`] and
/// double-quoted, pairs sorted by name, comma-space separated, scheme literal
/// `OAuth ` (no realm). Because the base string is built from the same
/// `as_pairs()`, the header and base-string parameter sets are identical by
/// construction.
pub fn authorization_header(params: &OauthParams, signature: &str) -> String {
    let mut pairs = params.as_pairs();
    pairs.push(("oauth_signature".to_string(), signature.to_string()));
    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    let rendered = pairs
        .iter()
        .map(|(name, value)| format!("{}=\"{}\"", name, oauth_encode(value)))
        .collect::<Vec<_>>()
        .join(", ");

    format!("OAuth {rendered}")
}

/// The output of signing one leg: the ready-to-send `Authorization` header
/// value and the [`OauthParams`] it was built from (exposed for test
/// assertions). No secret escapes in either field.
pub struct SignedLeg {
    pub authorization_header: String,
    pub oauth_params: OauthParams,
}

/// The one and only per-leg signing entry point.
///
/// Matches `input` to pull the leg's token secret (empty for `RequestToken`,
/// the request-token secret for `AccessToken`, the access-token secret for
/// `Resource`) and pairs it with the leg's public token — so the token/secret
/// pairing is the single expressible option. For the resource leg the caller
/// passes the already-split `query_params`; the two OAuth token legs pass an
/// empty slice. The upstream `host` arrives as data (from the selected
/// [`UpstreamHost`]) so the base string is signed against the same host the
/// request is sent to. Nonce and timestamp are injected.
pub fn sign_leg(
    host: &UpstreamHost,
    input: &SigningInput<'_>,
    consumer_secret: &ConsumerSecret,
    query_params: &[(String, String)],
    nonce: &Nonce,
    timestamp: &Timestamp,
) -> SignedLeg {
    let oauth_params = oauth_params(input, nonce, timestamp);

    // The token secret travels with the leg; this match is the single place the
    // per-leg pairing is chosen.
    let token_secret: Option<&TokenSecret> = match input {
        SigningInput::RequestToken { .. } => None,
        SigningInput::AccessToken {
            request_token_secret,
            ..
        } => Some(request_token_secret),
        SigningInput::Resource {
            access_token_secret,
            ..
        } => Some(access_token_secret),
    };

    let key = signing_key(consumer_secret, token_secret);

    let mut base_params = oauth_params.as_pairs();
    base_params.extend(query_params.iter().cloned());

    let base_url = base_url_for(host, input);
    let base = signature_base_string(&HttpMethod::Get, &base_url, &base_params);
    let signature = sign_hmac_sha1(&base, &key);
    let header = authorization_header(&oauth_params, &signature);

    SignedLeg {
        authorization_header: header,
        oauth_params,
    }
}

/// The normalized base URL each leg signs over. The two OAuth token legs sign
/// over their fixed endpoint URLs; the resource leg signs over the mapped
/// upstream path it carries in its `SigningInput`, built via
/// [`upstream_base_url`]. Because every leg's base URL is derived from the one
/// `SigningInput` value, `sign_leg` is total over all three legs and is the
/// single enforcing call site for production signing.
///
/// [`upstream_base_url`]: super::base_string::upstream_base_url
fn base_url_for(host: &UpstreamHost, input: &SigningInput<'_>) -> String {
    use super::endpoints;
    match input {
        SigningInput::RequestToken { .. } => {
            endpoints::oauth_endpoint_url(host, endpoints::REQUEST_TOKEN_PATH)
        }
        SigningInput::AccessToken { .. } => {
            endpoints::oauth_endpoint_url(host, endpoints::ACCESS_TOKEN_PATH)
        }
        SigningInput::Resource { path, .. } => {
            super::base_string::upstream_base_url(host, path.as_str())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::env::Environment;
    use crate::core::newtypes::{AccessToken, ConsumerKey, RequestToken, ResourcePath, Verifier};
    use crate::core::oauth::base_string;
    use proptest::prelude::*;

    /// The live host, used by the default-path assertions below.
    fn live_host() -> UpstreamHost {
        Environment::Live.host()
    }

    fn nonce() -> Nonce {
        Nonce::new("nonce-xyz")
    }
    fn ts() -> Timestamp {
        Timestamp::new(1_700_000_000)
    }

    /// Parse the `(name, value)` pairs back out of a rendered header, decoding
    /// the percent-encoded, double-quoted values.
    fn parse_header_pairs(header: &str) -> Vec<(String, String)> {
        let body = header.strip_prefix("OAuth ").expect("OAuth scheme prefix");
        body.split(", ")
            .map(|kv| {
                let (name, quoted) = kv.split_once('=').expect("name=value");
                let value = quoted.trim_matches('"');
                let decoded = percent_encoding::percent_decode(value.as_bytes())
                    .decode_utf8()
                    .expect("header values are valid utf8")
                    .into_owned();
                (name.to_string(), decoded)
            })
            .collect()
    }

    #[test]
    fn signing_key_folds_secrets() {
        let cs = ConsumerSecret::new("cons+sec");
        let ts = TokenSecret::new("tok/sec");
        assert_eq!(signing_key(&cs, Some(&ts)), "cons%2Bsec&tok%2Fsec");
        assert_eq!(signing_key(&cs, None), "cons%2Bsec&");
    }

    #[test]
    fn hmac_sha1_is_deterministic_and_base64() {
        let a = sign_hmac_sha1("base", "key&");
        let b = sign_hmac_sha1("base", "key&");
        assert_eq!(a, b);
        // Base64 standard output decodes to the 20-byte SHA-1 MAC.
        let decoded = STANDARD.decode(&a).unwrap();
        assert_eq!(decoded.len(), 20);
    }

    #[test]
    fn hmac_sha1_known_vector() {
        // RFC 2202 test case 2: key="Jefe", data="what do ya want for nothing?"
        let sig = sign_hmac_sha1("what do ya want for nothing?", "Jefe");
        let decoded = STANDARD.decode(&sig).unwrap();
        let hex: String = decoded.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    #[test]
    fn header_percent_encodes_signature() {
        let key = ConsumerKey::new("ckey");
        let params = oauth_params(
            &SigningInput::RequestToken {
                consumer_key: &key,
                callback: "oob",
            },
            &nonce(),
            &ts(),
        );
        let header = authorization_header(&params, "ab+cd/ef=");
        assert!(header.contains("oauth_signature=\"ab%2Bcd%2Fef%3D\""));
        assert!(header.starts_with("OAuth "));
        assert!(!header.contains("realm"));
    }

    #[test]
    fn request_token_leg_emits_no_token() {
        let key = ConsumerKey::new("ckey");
        let cs = ConsumerSecret::new("csec");
        let signed = sign_leg(
            &live_host(),
            &SigningInput::RequestToken {
                consumer_key: &key,
                callback: "oob",
            },
            &cs,
            &[],
            &nonce(),
            &ts(),
        );
        assert!(!signed.authorization_header.contains("oauth_token="));
        assert!(signed.authorization_header.contains("oauth_callback=\"oob\""));
    }

    #[test]
    fn header_multiset_matches_as_pairs_all_legs() {
        let key = ConsumerKey::new("ckey");
        let cs = ConsumerSecret::new("csec");
        let rt = RequestToken::new("reqtok");
        let rts = TokenSecret::new("reqsec");
        let verifier = Verifier::new("verif");
        let at = AccessToken::new("acctok");
        let ats = TokenSecret::new("accsec");
        let path = ResourcePath::new("/v1/accounts/list");

        let inputs = [
            SigningInput::RequestToken {
                consumer_key: &key,
                callback: "oob",
            },
            SigningInput::AccessToken {
                consumer_key: &key,
                request_token: &rt,
                request_token_secret: &rts,
                verifier: &verifier,
            },
            SigningInput::Resource {
                consumer_key: &key,
                access_token: &at,
                access_token_secret: &ats,
                path: &path,
            },
        ];

        for input in &inputs {
            let signed = sign_leg(&live_host(), input, &cs, &[], &nonce(), &ts());
            let mut from_header: Vec<(String, String)> =
                parse_header_pairs(&signed.authorization_header)
                    .into_iter()
                    .filter(|(n, _)| n != "oauth_signature")
                    .collect();
            let mut from_params = signed.oauth_params.as_pairs();
            from_header.sort();
            from_params.sort();
            assert_eq!(from_header, from_params);
        }
    }

    #[test]
    fn resource_leg_base_string_reflects_mapped_path() {
        // The resource leg must sign over the exact mapped upstream path it
        // carries, so the signed base URL changes with the path and matches
        // upstream_base_url(path).
        let key = ConsumerKey::new("ckey");
        let cs = ConsumerSecret::new("csec");
        let at = AccessToken::new("acctok");
        let ats = TokenSecret::new("accsec");
        let nonce = Nonce::new("nonce-xyz");
        let ts = Timestamp::new(1_700_000_000);

        let path_a = ResourcePath::new("/v1/accounts/list");
        let path_b = ResourcePath::new("/v1/accounts/BALANCE/balance");

        let sign_with = |path: &ResourcePath| {
            let input = SigningInput::Resource {
                consumer_key: &key,
                access_token: &at,
                access_token_secret: &ats,
                path,
            };
            // Reproduce sign_leg's base-string input to assert the base URL.
            let params = oauth_params(&input, &nonce, &ts);
            let base_url = base_string::upstream_base_url(&live_host(), path.as_str());
            let base = signature_base_string(&HttpMethod::Get, &base_url, &params.as_pairs());
            let full = sign_leg(&live_host(), &input, &cs, &[], &nonce, &ts);
            (base, full.authorization_header)
        };

        let (base_a, header_a) = sign_with(&path_a);
        let (base_b, header_b) = sign_with(&path_b);

        // The base string embeds the percent-encoded mapped path.
        assert!(base_a.contains(&oauth_encode(
            "https://api.etrade.com/v1/accounts/list"
        )));
        assert!(base_b.contains(&oauth_encode(
            "https://api.etrade.com/v1/accounts/BALANCE/balance"
        )));
        // Different mapped paths therefore produce different signatures.
        assert_ne!(base_a, base_b);
        assert_ne!(header_a, header_b);
    }

    #[test]
    fn resource_leg_base_string_uses_sandbox_host() {
        // Signing matches sending: a Resource leg signed with the sandbox host
        // must compute its base string against apisb.etrade.com, never the live
        // host.
        let key = ConsumerKey::new("ckey");
        let cs = ConsumerSecret::new("csec");
        let at = AccessToken::new("acctok");
        let ats = TokenSecret::new("accsec");
        let path = ResourcePath::new("/v1/accounts/list");
        let sandbox = Environment::Sandbox.host();

        let input = SigningInput::Resource {
            consumer_key: &key,
            access_token: &at,
            access_token_secret: &ats,
            path: &path,
        };

        // Reproduce sign_leg's base-string input under the sandbox host.
        let params = oauth_params(&input, &nonce(), &ts());
        let base_url = base_string::upstream_base_url(&sandbox, path.as_str());
        let base = signature_base_string(&HttpMethod::Get, &base_url, &params.as_pairs());

        assert!(base.contains(&oauth_encode("https://apisb.etrade.com/v1/accounts/list")));
        assert!(!base.contains(&oauth_encode("https://api.etrade.com/v1/accounts/list")));

        // sign_leg itself signs over the same sandbox base URL without panicking.
        let _ = sign_leg(&sandbox, &input, &cs, &[], &nonce(), &ts());
    }

    proptest! {
        // The resource leg's signed base URL always reflects the mapped path it
        // carries (upstream_base_url(path)), for arbitrary account subpaths.
        #[test]
        fn resource_base_url_tracks_path(sub in "(/[a-zA-Z0-9]{1,6}){0,4}") {
            let key = ConsumerKey::new("ckey");
            let cs = ConsumerSecret::new("csec");
            let at = AccessToken::new("acctok");
            let ats = TokenSecret::new("accsec");
            let nonce = Nonce::new("nonce-xyz");
            let ts = Timestamp::new(1_700_000_000);
            let mapped = format!("/v1/accounts{sub}");
            let path = ResourcePath::new(mapped.clone());
            let input = SigningInput::Resource {
                consumer_key: &key,
                access_token: &at,
                access_token_secret: &ats,
                path: &path,
            };
            let params = oauth_params(&input, &nonce, &ts);
            let base_url = base_string::upstream_base_url(&live_host(), &mapped);
            let base = signature_base_string(&HttpMethod::Get, &base_url, &params.as_pairs());
            // sign_leg uses exactly this base URL internally; confirm the
            // encoded upstream URL is present in the base string.
            let encoded_url = oauth_encode(&format!("https://api.etrade.com{mapped}"));
            prop_assert!(base.contains(&encoded_url));
            // sign_leg produces a header for the same input without panicking.
            let _ = sign_leg(&live_host(), &input, &cs, &[], &nonce, &ts);
        }

        // AC-4: fixed nonce/timestamp => identical header; distinct ones differ
        // for at least some parameter sets. Here we check determinism directly.
        #[test]
        fn resource_leg_deterministic(
            ckey in "[a-zA-Z0-9]{1,8}",
            atok in "[a-zA-Z0-9]{1,8}",
            asec in "[a-zA-Z0-9]{1,8}",
            n in "[a-zA-Z0-9]{1,8}",
            t in 1u64..2_000_000_000,
        ) {
            let key = ConsumerKey::new(ckey);
            let cs = ConsumerSecret::new("csec");
            let at = AccessToken::new(atok);
            let ats = TokenSecret::new(asec);
            let path = ResourcePath::new("/v1/accounts/list");
            let nonce = Nonce::new(n);
            let ts = Timestamp::new(t);
            let input = SigningInput::Resource {
                consumer_key: &key,
                access_token: &at,
                access_token_secret: &ats,
                path: &path,
            };
            let a = sign_leg(&live_host(), &input, &cs, &[], &nonce, &ts);
            let b = sign_leg(&live_host(), &input, &cs, &[], &nonce, &ts);
            prop_assert_eq!(a.authorization_header, b.authorization_header);
        }

        // Varying the nonce changes the signature.
        #[test]
        fn varying_nonce_changes_signature(
            n1 in "[a-zA-Z0-9]{4,10}",
            n2 in "[a-zA-Z0-9]{4,10}",
        ) {
            prop_assume!(n1 != n2);
            let key = ConsumerKey::new("ckey");
            let cs = ConsumerSecret::new("csec");
            let at = AccessToken::new("acctok");
            let ats = TokenSecret::new("accsec");
            let path = ResourcePath::new("/v1/accounts/list");
            let ts = Timestamp::new(1_700_000_000);
            let input = SigningInput::Resource {
                consumer_key: &key,
                access_token: &at,
                access_token_secret: &ats,
                path: &path,
            };
            let a = sign_leg(&live_host(), &input, &cs, &[], &Nonce::new(n1), &ts);
            let b = sign_leg(&live_host(), &input, &cs, &[], &Nonce::new(n2), &ts);
            prop_assert_ne!(a.authorization_header, b.authorization_header);
        }

        // Header/base-string agreement across all three legs over arbitrary
        // values: parsed-back header multiset == as_pairs().
        #[test]
        fn header_agrees_with_as_pairs(
            ckey in "[a-zA-Z0-9]{1,8}",
            tok in "[a-zA-Z0-9]{1,8}",
            cb in "[a-zA-Z0-9]{1,8}",
            n in "[a-zA-Z0-9]{1,8}",
            t in 1u64..2_000_000_000,
            which in 0u8..3,
        ) {
            let key = ConsumerKey::new(ckey);
            let cs = ConsumerSecret::new("csec");
            let rt = RequestToken::new(tok.clone());
            let rts = TokenSecret::new("reqsec");
            let verifier = Verifier::new(cb.clone());
            let at = AccessToken::new(tok.clone());
            let ats = TokenSecret::new("accsec");
            let path = ResourcePath::new("/v1/accounts/list");
            let nonce = Nonce::new(n);
            let ts = Timestamp::new(t);

            let input = match which {
                0 => SigningInput::RequestToken { consumer_key: &key, callback: &cb },
                1 => SigningInput::AccessToken {
                    consumer_key: &key,
                    request_token: &rt,
                    request_token_secret: &rts,
                    verifier: &verifier,
                },
                _ => SigningInput::Resource {
                    consumer_key: &key,
                    access_token: &at,
                    access_token_secret: &ats,
                    path: &path,
                },
            };

            let signed = sign_leg(&live_host(), &input, &cs, &[], &nonce, &ts);
            let mut from_header: Vec<(String, String)> =
                parse_header_pairs(&signed.authorization_header)
                    .into_iter()
                    .filter(|(nm, _)| nm != "oauth_signature")
                    .collect();
            let mut from_params = signed.oauth_params.as_pairs();
            from_header.sort();
            from_params.sort();
            prop_assert_eq!(&from_header, &from_params);

            // RequestToken leg emits no oauth_token; the other two emit one.
            let token_count = from_params.iter().filter(|(nm, _)| nm == "oauth_token").count();
            match which {
                0 => prop_assert_eq!(token_count, 0),
                _ => prop_assert_eq!(token_count, 1),
            }
        }
    }
}
