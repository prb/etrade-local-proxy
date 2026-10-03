//! OAuth 1.0a signing — pure, with injected nonce/timestamp.
//!
//! This module hosts the shared percent-encoder ([`oauth_encode`]), the query
//! splitter ([`split_query`]) and re-serializer ([`wire_query`]) used on the
//! resource leg, and the core [`HttpMethod`] enum. The signing pipeline itself
//! lives in the submodules: [`params`] (the three-leg `SigningInput` domain and
//! `OauthParams`), [`base_string`], and [`sign`].

pub mod base_string;
pub mod endpoints;
pub mod params;
pub mod sign;

use percent_encoding::{percent_decode, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

/// RFC 3986 / RFC 5849 encoding set: everything is encoded **except** the
/// unreserved set `A-Z a-z 0-9 - . _ ~`. We start from [`NON_ALPHANUMERIC`]
/// (which encodes every non-alphanumeric byte, i.e. the strictest set) and
/// *remove* the four unreserved punctuation characters.
const OAUTH_UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encode a string per RFC 5849 §3.6 (OAuth parameter encoding), the
/// single encoder shared by the base string, the `Authorization` header, and
/// [`wire_query`] so those outputs cannot diverge.
pub fn oauth_encode(s: &str) -> String {
    utf8_percent_encode(s, OAUTH_UNRESERVED).to_string()
}

/// The HTTP method, as a small core enum free of framework types. The shell
/// maps `axum`/`hyper`'s method into this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Trace,
    Connect,
    /// Any method the proxy does not model explicitly. Carries the uppercase
    /// token so the base string can still render it faithfully if ever needed.
    Other,
}

impl HttpMethod {
    /// The uppercase method token used in the signature base string.
    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Trace => "TRACE",
            HttpMethod::Connect => "CONNECT",
            HttpMethod::Other => "OTHER",
        }
    }

    /// Whether this is the single admitted verb (`GET`).
    pub fn is_get(&self) -> bool {
        matches!(self, HttpMethod::Get)
    }
}

/// Percent-decode a single query token (name or value).
///
/// On a valid-UTF-8 decode the decoded string is returned (so the caller can
/// re-encode it uniformly with [`oauth_encode`] — decode-then-encode). On a
/// non-UTF-8 decode the **raw substring is returned verbatim**, never U+FFFD;
/// re-encoding it with [`oauth_encode`] then yields a byte-identical result on
/// both the signed side and the wire side.
fn decode_token(raw: &str) -> String {
    match percent_decode(raw.as_bytes()).decode_utf8() {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => raw.to_string(),
    }
}

/// Split a path+query into its path and an **ordered** list of query pairs.
///
/// - Total; never panics (uses only `split_once`/`split`, no indexing).
/// - Each name and value is percent-**decoded** per RFC 5849 §3.4.1.3.1
///   (non-UTF-8 escapes are kept raw — see [`decode_token`]).
/// - Duplicates are **preserved** as an ordered multiset — never collected into
///   a map, never de-duplicated — so `?symbol=A&symbol=B` yields the two pairs
///   in client order.
/// - Any pair whose decoded name begins with `oauth_` is **dropped**, so client
///   input can neither inject nor shadow a protocol parameter in the signed set.
/// - A bare `/path` yields `(path, [])`; a trailing `?` or a pair with no `=`
///   is handled totally (empty value, or empty name/value).
pub fn split_query(path_and_query: &str) -> (String, Vec<(String, String)>) {
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_string(), q),
        None => (path_and_query.to_string(), ""),
    };

    let pairs = query
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| match segment.split_once('=') {
            Some((name, value)) => (decode_token(name), decode_token(value)),
            None => (decode_token(segment), String::new()),
        })
        .filter(|(name, _)| !name.starts_with("oauth_"))
        .collect();

    (path, pairs)
}

/// Re-serialize signed query pairs into a wire query string using the **same**
/// [`oauth_encode`] as the base string.
///
/// Operates on the pairs *as given*: it preserves client order and preserves
/// duplicates (no map, no de-dup, no sort). The signed set (a sorted copy of
/// these pairs) and the wire set (these pairs in client order) are therefore
/// the same multiset, differing only in order. Empty input yields `""`.
pub fn wire_query(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", oauth_encode(name), oauth_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn encode_leaves_unreserved_untouched() {
        assert_eq!(
            oauth_encode("AZaz09-._~"),
            "AZaz09-._~",
            "unreserved set must pass through unchanged"
        );
    }

    #[test]
    fn encode_escapes_reserved_and_base64_chars() {
        assert_eq!(oauth_encode("+"), "%2B");
        assert_eq!(oauth_encode("/"), "%2F");
        assert_eq!(oauth_encode("="), "%3D");
        assert_eq!(oauth_encode(" "), "%20");
        assert_eq!(oauth_encode("&"), "%26");
    }

    #[test]
    fn split_query_basic() {
        let (path, pairs) = split_query("/v1/accounts/list?a=1&b=2");
        assert_eq!(path, "/v1/accounts/list");
        assert_eq!(
            pairs,
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
    }

    #[test]
    fn split_query_no_query() {
        let (path, pairs) = split_query("/v1/accounts");
        assert_eq!(path, "/v1/accounts");
        assert!(pairs.is_empty());
    }

    #[test]
    fn split_query_preserves_duplicates_in_order() {
        let (_, pairs) = split_query("/p?symbol=A&symbol=B&symbol=A");
        assert_eq!(
            pairs,
            vec![
                ("symbol".into(), "A".into()),
                ("symbol".into(), "B".into()),
                ("symbol".into(), "A".into()),
            ]
        );
    }

    #[test]
    fn split_query_drops_oauth_params() {
        let (_, pairs) = split_query("/p?oauth_token=inject&x=1&oauth_signature=bad");
        assert_eq!(pairs, vec![("x".into(), "1".into())]);
    }

    #[test]
    fn split_query_decodes_percent_escapes() {
        let (_, pairs) = split_query("/p?name=a%20b&other=%7E");
        assert_eq!(
            pairs,
            vec![("name".into(), "a b".into()), ("other".into(), "~".into())]
        );
    }

    #[test]
    fn split_query_trailing_question_and_bare_name() {
        let (path, pairs) = split_query("/p?");
        assert_eq!(path, "/p");
        assert!(pairs.is_empty());

        let (_, pairs) = split_query("/p?flag");
        assert_eq!(pairs, vec![("flag".into(), String::new())]);
    }

    #[test]
    fn split_query_non_utf8_escape_kept_raw() {
        // %FF is not valid UTF-8; the raw substring is kept verbatim.
        let (_, pairs) = split_query("/p?v=%FF");
        assert_eq!(pairs, vec![("v".into(), "%FF".into())]);
        // And it re-encodes to %25FF on the wire (double-encoded, by design).
        assert_eq!(wire_query(&pairs), "v=%25FF");
    }

    #[test]
    fn wire_query_round_trip_order() {
        let pairs = vec![("a".to_string(), "1".to_string()), ("b".into(), "x y".into())];
        assert_eq!(wire_query(&pairs), "a=1&b=x%20y");
    }

    #[test]
    fn wire_query_empty() {
        assert_eq!(wire_query(&[]), "");
    }

    proptest! {
        // split_query is total: it must never panic on arbitrary input.
        #[test]
        fn split_query_is_total(input in ".*") {
            let _ = split_query(&input);
        }

        // Never emits an oauth_ parameter, whatever the input.
        #[test]
        fn split_query_never_emits_oauth(input in ".*") {
            let (_, pairs) = split_query(&input);
            for (name, _) in pairs {
                prop_assert!(!name.starts_with("oauth_"));
            }
        }

        // For arbitrary decoded pairs, the signed set (sorted) equals the wire
        // set (re-parsed) as a multiset — including non-UTF-8 raw passthrough,
        // which is injected via the raw-escape class below.
        #[test]
        fn signed_set_equals_wire_set(
            pairs in proptest::collection::vec(
                ("[a-z]{1,6}", "[a-zA-Z0-9 %/+=~]{0,8}"),
                0..6,
            )
        ) {
            // Build a query string, split it, re-serialize, split again, and
            // confirm the multiset is identical.
            let query: String = pairs
                .iter()
                .map(|(n, v)| format!("{}={}", oauth_encode(n), oauth_encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            let path_and_query = format!("/p?{query}");
            let (_, signed) = split_query(&path_and_query);

            let wire = wire_query(&signed);
            let (_, reparsed) = split_query(&format!("/p?{wire}"));

            let mut a = signed.clone();
            let mut b = reparsed;
            a.sort();
            b.sort();
            prop_assert_eq!(a, b);
        }

        // Non-UTF-8 percent escapes: still total, and signed == wire multiset.
        #[test]
        fn non_utf8_escapes_total_and_consistent(
            raw in proptest::collection::vec("(%FF|%C0%80|%80|[a-z])", 0..6)
        ) {
            let query: String = raw
                .iter()
                .enumerate()
                .map(|(i, tok)| format!("k{i}={tok}"))
                .collect::<Vec<_>>()
                .join("&");
            let (_, signed) = split_query(&format!("/p?{query}"));
            let wire = wire_query(&signed);
            let (_, reparsed) = split_query(&format!("/p?{wire}"));
            let mut a = signed.clone();
            let mut b = reparsed;
            a.sort();
            b.sort();
            prop_assert_eq!(a, b);
        }
    }
}
