//! The central request-admission decision and path mapping.
//!
//! [`admit`] is a **total** pure function over `(method, path+query)`: it never
//! panics and returns an [`Admission`] for every input. It is the single source
//! of truth for the GET-only rule (checked verb-first) and the
//! `/etrade-api/v1/accounts` prefix rule.

use super::oauth::HttpMethod;

/// The local prefix under which the ETrade read surface is exposed.
const PROXY_PREFIX: &str = "/etrade-api";
/// The admitted upstream prefix (after mapping away `/etrade-api`).
const ACCOUNTS_PREFIX: &str = "/v1/accounts";
/// The status endpoint path.
const STATUS_PATH: &str = "/internal/status";

/// The outcome of admitting a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    /// A `GET` under `/etrade-api/v1/accounts`, mapped to the upstream path.
    Forward(UpstreamPath),
    /// A `GET /internal/status`.
    Status,
    /// Anything else, with the reason.
    Reject(RejectReason),
}

/// Why a request was rejected. One reason maps to exactly one HTTP status in
/// the shell (`MethodNotGet → 405`, `OutOfPrefix → 404`).
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    /// Any method other than `GET`, regardless of path.
    MethodNotGet,
    /// A `GET` that is neither `/internal/status` nor under the proxy prefix.
    OutOfPrefix,
}

/// The upstream path+query produced by mapping an admitted local request,
/// e.g. `/v1/accounts/list?x=1`. Carries the query verbatim; the shell splits
/// it with `core::oauth::split_query` immediately before signing.
#[derive(Debug, PartialEq, Eq)]
pub struct UpstreamPath(String);

impl UpstreamPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Admit a request. Total; never panics.
///
/// Enforcement is verb-first: any non-`GET` yields `Reject(MethodNotGet)`
/// regardless of path. Then:
/// - `GET /internal/status` → `Status`;
/// - `GET` whose path (before `?`) starts with `/etrade-api/v1/accounts` and
///   whose next character is `/`, `?`, or end-of-string → `Forward`, mapping
///   `/etrade-api` + rest → `/v1/accounts/...` with the query preserved;
/// - every other `GET` → `Reject(OutOfPrefix)`.
pub fn admit(method: &HttpMethod, path_and_query: &str) -> Admission {
    if !method.is_get() {
        return Admission::Reject(RejectReason::MethodNotGet);
    }

    // Split off the query (if any) using only total string ops.
    let path = match path_and_query.split_once('?') {
        Some((p, _)) => p,
        None => path_and_query,
    };

    if path == STATUS_PATH {
        return Admission::Status;
    }

    // Does the path lie under the proxied accounts prefix, respecting segment
    // boundaries so `/etrade-api/v1/accountsX` does not match?
    match path.strip_prefix(PROXY_PREFIX) {
        Some(rest) if is_under_accounts(rest) => {
            // Map "/etrade-api" + rest -> "/v1/accounts..."; preserve the query
            // verbatim from the original input.
            let query = path_and_query
                .split_once('?')
                .map(|(_, q)| q)
                .unwrap_or("");
            let mapped = if query.is_empty() {
                rest.to_string()
            } else {
                format!("{rest}?{query}")
            };
            Admission::Forward(UpstreamPath(mapped))
        }
        _ => Admission::Reject(RejectReason::OutOfPrefix),
    }
}

/// Whether the remainder (after stripping `/etrade-api`) is the accounts prefix
/// at a segment boundary.
fn is_under_accounts(rest: &str) -> bool {
    match rest.strip_prefix(ACCOUNTS_PREFIX) {
        // Exactly `/v1/accounts`, or followed by a path/query boundary.
        Some(after) => after.is_empty() || after.starts_with('/') || after.starts_with('?'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn status_get_is_status() {
        assert_eq!(admit(&HttpMethod::Get, "/internal/status"), Admission::Status);
    }

    #[test]
    fn in_prefix_get_forwards_and_maps() {
        match admit(&HttpMethod::Get, "/etrade-api/v1/accounts/list?x=1") {
            Admission::Forward(p) => assert_eq!(p.as_str(), "/v1/accounts/list?x=1"),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn in_prefix_get_without_query_maps() {
        match admit(&HttpMethod::Get, "/etrade-api/v1/accounts") {
            Admission::Forward(p) => assert_eq!(p.as_str(), "/v1/accounts"),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn non_get_rejected_method_even_under_prefix() {
        for m in [HttpMethod::Post, HttpMethod::Put, HttpMethod::Delete] {
            assert_eq!(
                admit(&m, "/etrade-api/v1/accounts/ABC/orders"),
                Admission::Reject(RejectReason::MethodNotGet)
            );
        }
    }

    #[test]
    fn out_of_prefix_get_rejected() {
        assert_eq!(
            admit(&HttpMethod::Get, "/v1/accounts/list"),
            Admission::Reject(RejectReason::OutOfPrefix)
        );
        assert_eq!(
            admit(&HttpMethod::Get, "/etrade-api/v1/market/quote"),
            Admission::Reject(RejectReason::OutOfPrefix)
        );
    }

    #[test]
    fn partial_segment_does_not_match() {
        assert_eq!(
            admit(&HttpMethod::Get, "/etrade-api/v1/accountsX"),
            Admission::Reject(RejectReason::OutOfPrefix)
        );
    }

    fn method_strategy() -> impl Strategy<Value = HttpMethod> {
        prop_oneof![
            Just(HttpMethod::Get),
            Just(HttpMethod::Post),
            Just(HttpMethod::Put),
            Just(HttpMethod::Delete),
            Just(HttpMethod::Patch),
            Just(HttpMethod::Head),
            Just(HttpMethod::Options),
            Just(HttpMethod::Other),
        ]
    }

    proptest! {
        // AC-8: admit is total over arbitrary method+path; never panics.
        #[test]
        fn admit_is_total(m in method_strategy(), p in ".*") {
            let _ = admit(&m, &p);
        }

        // AC-5: a non-GET is never Forward, over arbitrary paths.
        #[test]
        fn non_get_never_forwards(p in ".*") {
            for m in [HttpMethod::Post, HttpMethod::Put, HttpMethod::Delete,
                      HttpMethod::Patch, HttpMethod::Head, HttpMethod::Options,
                      HttpMethod::Other] {
                prop_assert!(!matches!(admit(&m, &p), Admission::Forward(_)));
                prop_assert_eq!(admit(&m, &p), Admission::Reject(RejectReason::MethodNotGet));
            }
        }

        // AC-6: an out-of-prefix GET is never Forward. /internal/status is
        // excluded from this arm (it is covered by the dedicated Status test).
        #[test]
        fn out_of_prefix_get_never_forwards(
            p in "(/[a-z0-9]{1,6}){0,4}"
        ) {
            prop_assume!(!p.starts_with("/etrade-api/v1/accounts"));
            prop_assume!(p != "/internal/status");
            prop_assert!(!matches!(admit(&HttpMethod::Get, &p), Admission::Forward(_)));
            prop_assert_eq!(
                admit(&HttpMethod::Get, &p),
                Admission::Reject(RejectReason::OutOfPrefix)
            );
        }

        // AC-7: an in-prefix GET is admitted and mapped with the query preserved.
        #[test]
        fn in_prefix_get_mapped(
            sub in "(/[a-z0-9]{1,6}){0,3}",
            q in "([a-z]{1,4}=[a-z0-9]{0,4})?",
        ) {
            let path = format!("/etrade-api/v1/accounts{sub}");
            let full = if q.is_empty() { path.clone() } else { format!("{path}?{q}") };
            match admit(&HttpMethod::Get, &full) {
                Admission::Forward(up) => {
                    let expected = if q.is_empty() {
                        format!("/v1/accounts{sub}")
                    } else {
                        format!("/v1/accounts{sub}?{q}")
                    };
                    prop_assert_eq!(up.as_str(), expected);
                }
                other => prop_assert!(false, "expected Forward, got {:?}", other),
            }
        }
    }
}
