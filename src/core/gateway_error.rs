//! Pure description of the errors the proxy itself generates (`502`, `503`,
//! `504`) and the JSON body clients receive for them.
//!
//! The body is built only from this closed enum plus one number, so it cannot
//! carry the request URL, account key, headers, token material, or the
//! upstream body.

use serde::Serialize;

/// Why the proxy, not E*TRADE, produced an error reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayFailure {
    /// The upstream call exceeded the overall request timeout (`504`).
    UpstreamTimeout,
    /// Any other upstream failure: connect error, reset, bad TLS (`502`).
    UpstreamError,
    /// The upstream body exceeded the size cap (`502`).
    UpstreamTooLarge,
    /// No token yet (`503`).
    NotReady,
}

impl GatewayFailure {
    /// The HTTP status code for this failure.
    pub fn status(self) -> u16 {
        match self {
            Self::UpstreamTimeout => 504,
            Self::UpstreamError | Self::UpstreamTooLarge => 502,
            Self::NotReady => 503,
        }
    }

    /// The machine-readable `error` code; always matches
    /// `^[a-z][a-z0-9_]{0,39}$`.
    pub fn code(self) -> &'static str {
        match self {
            Self::UpstreamTimeout => "upstream_timeout",
            Self::UpstreamError => "upstream_error",
            Self::UpstreamTooLarge => "upstream_too_large",
            Self::NotReady => "not_ready",
        }
    }

    /// The JSON body. `timeout_seconds` is the overall request timeout in
    /// effect and is included for [`GatewayFailure::UpstreamTimeout`] only.
    pub fn body(self, timeout_seconds: u64) -> GatewayErrorBody {
        GatewayErrorBody {
            error: self.code(),
            timeout_seconds: matches!(self, Self::UpstreamTimeout).then_some(timeout_seconds),
        }
    }
}

/// Serialized shape: `{"error": "...", "timeout_seconds": 30}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayErrorBody {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ALL: [GatewayFailure; 4] = [
        GatewayFailure::UpstreamTimeout,
        GatewayFailure::UpstreamError,
        GatewayFailure::UpstreamTooLarge,
        GatewayFailure::NotReady,
    ];

    fn is_valid_code(s: &str) -> bool {
        let mut chars = s.chars();
        s.len() <= 40
            && chars.next().is_some_and(|c| c.is_ascii_lowercase())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }

    #[test]
    fn table_rows() {
        let rows = [
            (GatewayFailure::UpstreamTimeout, 504, "upstream_timeout"),
            (GatewayFailure::UpstreamError, 502, "upstream_error"),
            (GatewayFailure::UpstreamTooLarge, 502, "upstream_too_large"),
            (GatewayFailure::NotReady, 503, "not_ready"),
        ];
        for (failure, status, code) in rows {
            assert_eq!((failure.status(), failure.code()), (status, code));
        }
    }

    #[test]
    fn codes_match_the_contract_pattern() {
        assert!(ALL.iter().all(|f| is_valid_code(f.code())));
    }

    #[test]
    fn timeout_body_example() {
        let json = serde_json::to_string(&GatewayFailure::UpstreamTimeout.body(30)).unwrap();
        assert_eq!(json, r#"{"error":"upstream_timeout","timeout_seconds":30}"#);
    }

    #[test]
    fn non_timeout_body_has_no_timeout_seconds() {
        let json = serde_json::to_string(&GatewayFailure::NotReady.body(30)).unwrap();
        assert_eq!(json, r#"{"error":"not_ready"}"#);
    }

    proptest! {
        #[test]
        fn timeout_seconds_only_for_timeout(secs in any::<u64>(), idx in 0usize..4) {
            let failure = ALL[idx];
            let body = failure.body(secs);
            prop_assert_eq!(
                body.timeout_seconds,
                (failure == GatewayFailure::UpstreamTimeout).then_some(secs)
            );
        }
    }
}
