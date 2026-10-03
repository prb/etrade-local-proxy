//! Browser-facing authorize URL construction (pure).
//!
//! This URL is handed to the user to open in a browser, not a signature base
//! string, so it uses ordinary `application/x-www-form-urlencoded` query
//! encoding — **not** `oauth_encode`. Reusing the OAuth encoder would turn a
//! request token's `+`/`/`/`=` into `%2B`/`%2F`/`%3D`, producing a URL that
//! does not match what ETrade's authorize endpoint expects.

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

use super::oauth::endpoints;
use crate::core::newtypes::{ConsumerKey, RequestToken};

/// `application/x-www-form-urlencoded` query-component set. Like the OAuth set
/// it leaves the unreserved characters alone, but it is used here under the
/// form-urlencoding contract (a browser-facing query), kept separate from
/// `oauth_encode` so the two intents cannot be conflated.
const FORM_QUERY: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn form_encode(s: &str) -> String {
    utf8_percent_encode(s, FORM_QUERY).to_string()
}

/// Build the authorize URL:
/// `https://us.etrade.com/e/t/etws/authorize?key={key}&token={token}`.
pub fn authorize_url(key: &ConsumerKey, token: &RequestToken) -> String {
    format!(
        "{}?key={}&token={}",
        endpoints::AUTHORIZE_URL_BASE,
        form_encode(key.as_str()),
        form_encode(token.as_str())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_neutral_literal_ac12() {
        // AC-12: encode-neutral fixture (unreserved chars) => exact literal.
        let key = ConsumerKey::new("abc-DEF_123.key~");
        let token = RequestToken::new("tok-456_XYZ.0~");
        assert_eq!(
            authorize_url(&key, &token),
            "https://us.etrade.com/e/t/etws/authorize?key=abc-DEF_123.key~&token=tok-456_XYZ.0~"
        );
    }

    #[test]
    fn form_encoding_escapes_special_chars() {
        let key = ConsumerKey::new("a+b/c=d");
        let token = RequestToken::new("x+y/z=");
        let url = authorize_url(&key, &token);
        assert!(url.contains("key=a%2Bb%2Fc%3Dd"));
        assert!(url.contains("token=x%2By%2Fz%3D"));
    }
}
