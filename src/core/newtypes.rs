//! Domain newtypes over primitives so values that must not be interchangeable
//! cannot be (NFR-1). Secret-bearing values wrap [`secrecy::SecretString`],
//! which redacts in `Debug`, does not implement `Display`, and zeroizes on
//! drop (NFR-2). Non-secret token values keep a plain `String` but carry a
//! hand-written `Debug` that redacts the material so it cannot leak into a log
//! line by accident.

use secrecy::SecretString;

/// Truncating/redacting formatter for non-secret token-like strings.
///
/// Shows the first few characters so a value is still *recognizable* in a log
/// without disclosing the whole token. Short values are fully redacted.
fn fmt_redacted(label: &str, value: &str, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    const PREFIX: usize = 3;
    // Use char boundaries so arbitrary UTF-8 never panics the formatter.
    let shown: String = value.chars().take(PREFIX).collect();
    if value.chars().count() <= PREFIX {
        write!(f, "{label}(\"[REDACTED]\")")
    } else {
        write!(f, "{label}(\"{shown}…[REDACTED]\")")
    }
}

/// ETrade OAuth consumer key (public identifier; not secret).
#[derive(Clone, PartialEq, Eq)]
pub struct ConsumerKey(String);

impl ConsumerKey {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ConsumerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The consumer key is a public identifier, but we still truncate it to
        // keep debug output tidy and avoid pasting whole credentials in logs.
        fmt_redacted("ConsumerKey", &self.0, f)
    }
}

/// ETrade OAuth consumer secret (secret; wrapped so it cannot leak).
#[derive(Clone)]
pub struct ConsumerSecret(SecretString);

impl ConsumerSecret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::from(value.into()))
    }

    /// The underlying secret handle. Callers obtain the raw bytes only through
    /// [`secrecy::ExposeSecret`]; the one source-level `expose_secret()` site
    /// is `core::oauth::sign::signing_key`.
    pub fn secret(&self) -> &SecretString {
        &self.0
    }
}

impl std::fmt::Debug for ConsumerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConsumerSecret([REDACTED])")
    }
}

/// A temporary OAuth request token (public value; carried in base string).
#[derive(Clone, PartialEq, Eq)]
pub struct RequestToken(String);

impl RequestToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for RequestToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_redacted("RequestToken", &self.0, f)
    }
}

/// A token secret (secret; wrapped). Used for both the request-token secret and
/// the access-token secret; it is a distinct type from the public token value.
#[derive(Clone)]
pub struct TokenSecret(SecretString);

impl TokenSecret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::from(value.into()))
    }

    pub fn secret(&self) -> &SecretString {
        &self.0
    }
}

impl std::fmt::Debug for TokenSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenSecret([REDACTED])")
    }
}

/// An OAuth access token (public value; carried in base string on leg 3).
#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken(String);

impl AccessToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_redacted("AccessToken", &self.0, f)
    }
}

/// The OAuth verifier pasted by the user (opaque; redacted in debug output).
#[derive(Clone, PartialEq, Eq)]
pub struct Verifier(String);

impl Verifier {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_redacted("Verifier", &self.0, f)
    }
}

/// An OAuth nonce. **Injected** into the core by the shell's RNG (one fresh
/// value per leg/request); never generated inside the core.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nonce(String);

impl Nonce {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An OAuth timestamp in unix seconds. **Injected** into the core by the
/// shell's clock; never read from the system clock inside the core.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn new(secs: u64) -> Self {
        Self(secs)
    }

    pub fn as_secs(&self) -> u64 {
        self.0
    }
}

/// The mapped upstream **path** for a proxied resource request, with the query
/// already split off (e.g. `/v1/accounts/list`). This is the signing input the
/// resource leg needs to compute its RFC-5849 base URI, so it travels inside
/// `SigningInput::Resource`. The shell produces it by `split_query`-ing the
/// `UpstreamPath` that `admit` returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourcePath(String);

impl ResourcePath {
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The TCP port the loopback listener binds. The address itself is a code
/// constant (`127.0.0.1`); only the port is configurable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenPort(u16);

impl ListenPort {
    pub fn new(port: u16) -> Self {
        Self(port)
    }

    pub fn get(&self) -> u16 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = ConsumerSecret::new("super-secret-value");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("super-secret-value"));
        assert!(rendered.contains("REDACTED"));

        let token_secret = TokenSecret::new("another-secret");
        let rendered = format!("{token_secret:?}");
        assert!(!rendered.contains("another-secret"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn secret_round_trips_through_expose() {
        let secret = ConsumerSecret::new("abc123");
        assert_eq!(secret.secret().expose_secret(), "abc123");
    }

    #[test]
    fn token_debug_truncates_long_values() {
        let token = AccessToken::new("abcdefghijklmnop");
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("abcdefghijklmnop"));
        assert!(rendered.contains("abc"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn token_debug_fully_redacts_short_values() {
        let token = RequestToken::new("ab");
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("\"ab"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn debug_handles_multibyte_without_panic() {
        // Boundary safety: a multibyte prefix must not split a char boundary.
        let token = Verifier::new("héllo-wörld-verifier");
        let _ = format!("{token:?}");
    }

    #[test]
    fn accessors_round_trip() {
        assert_eq!(ConsumerKey::new("k").as_str(), "k");
        assert_eq!(RequestToken::new("r").as_str(), "r");
        assert_eq!(AccessToken::new("a").as_str(), "a");
        assert_eq!(Verifier::new("v").as_str(), "v");
        assert_eq!(Nonce::new("n").as_str(), "n");
        assert_eq!(Timestamp::new(42).as_secs(), 42);
        assert_eq!(ListenPort::new(8443).get(), 8443);
    }
}
