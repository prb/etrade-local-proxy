//! Pure response-header relay policy (whitelist predicate).
//!
//! The proxy relays only a small whitelist of upstream response headers and
//! drops `Content-Length` (the framework sets its own) and all hop-by-hop
//! headers. Header names are compared case-insensitively per RFC 9110.

/// Headers forwarded verbatim from the upstream response.
const ALLOWED: &[&str] = &[
    "content-type",
    "date",
    "etag",
    "cache-control",
    "expires",
    "last-modified",
    "age",
    "vary",
];

/// Whether an upstream response header may be relayed to the local client.
///
/// Returns `true` only for whitelisted headers. `Content-Length` and all
/// hop-by-hop headers (`Connection`, `Transfer-Encoding`, `Keep-Alive`,
/// `Upgrade`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`)
/// return `false`.
pub fn relay_header_allowed(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ALLOWED.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelisted_headers_allowed() {
        for h in ["Content-Type", "content-type", "Date", "ETag", "Cache-Control", "Expires"] {
            assert!(relay_header_allowed(h), "{h} should be allowed");
        }
    }

    #[test]
    fn content_length_rejected() {
        assert!(!relay_header_allowed("Content-Length"));
        assert!(!relay_header_allowed("content-length"));
    }

    #[test]
    fn hop_by_hop_rejected() {
        for h in [
            "Connection",
            "Transfer-Encoding",
            "Keep-Alive",
            "Upgrade",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailer",
        ] {
            assert!(!relay_header_allowed(h), "{h} should be rejected");
        }
    }

    #[test]
    fn unknown_header_rejected() {
        assert!(!relay_header_allowed("X-Custom-Thing"));
        assert!(!relay_header_allowed("Set-Cookie"));
    }
}
