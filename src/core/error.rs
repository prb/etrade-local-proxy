//! Core error enums (typed, per-module `thiserror`) and the pure
//! `application/x-www-form-urlencoded` OAuth-response parser.

use percent_encoding::percent_decode;
use thiserror::Error;

/// Configuration validation errors. Messages name the variable, never the
/// value. Fatal at startup (surfaced through `main` before any bind).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("ETRADE_CONSUMER_KEY is not set")]
    MissingConsumerKey,
    #[error("ETRADE_CONSUMER_SECRET is not set")]
    MissingConsumerSecret,
    #[error("ETRADE_CONSUMER_KEY is set but empty")]
    EmptyConsumerKey,
    #[error("ETRADE_CONSUMER_SECRET is set but empty")]
    EmptyConsumerSecret,
}

/// Errors from parsing an OAuth form-encoded response body.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum OauthParseError {
    #[error("OAuth response is missing the `{field}` field")]
    MissingField { field: &'static str },
    #[error("OAuth response body is not valid application/x-www-form-urlencoded")]
    MalformedForm,
}

/// The parsed fields of an OAuth token response. `callback_confirmed` is only
/// present on the request-token leg (`oauth_callback_confirmed`), informational.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OauthTokenResponse {
    pub oauth_token: String,
    pub oauth_token_secret: String,
    pub callback_confirmed: Option<bool>,
}

/// Parse an `application/x-www-form-urlencoded` OAuth response body, extracting
/// `oauth_token`, `oauth_token_secret`, and (if present)
/// `oauth_callback_confirmed`. Pure; total over arbitrary input (never panics).
pub fn parse_oauth_token_response(body: &str) -> Result<OauthTokenResponse, OauthParseError> {
    let pairs = parse_form(body)?;

    let find = |key: &str| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());

    let oauth_token = find("oauth_token").ok_or(OauthParseError::MissingField {
        field: "oauth_token",
    })?;
    let oauth_token_secret = find("oauth_token_secret").ok_or(OauthParseError::MissingField {
        field: "oauth_token_secret",
    })?;
    let callback_confirmed = find("oauth_callback_confirmed").map(|v| v == "true");

    Ok(OauthTokenResponse {
        oauth_token,
        oauth_token_secret,
        callback_confirmed,
    })
}

/// Parse a form body into decoded `(name, value)` pairs. An empty body is a
/// malformed form (no fields); a segment without `=` is treated as a malformed
/// form rather than a bare flag, since OAuth responses are always `k=v`.
fn parse_form(body: &str) -> Result<Vec<(String, String)>, OauthParseError> {
    if body.trim().is_empty() {
        return Err(OauthParseError::MalformedForm);
    }

    body.split('&')
        .map(|segment| {
            segment
                .split_once('=')
                .map(|(k, v)| (form_decode(k), form_decode(v)))
                .ok_or(OauthParseError::MalformedForm)
        })
        .collect()
}

/// Percent-decode a form token, treating `+` as a space per the
/// form-urlencoded convention. Non-UTF-8 escapes fall back to the raw token.
fn form_decode(s: &str) -> String {
    let spaces = s.replace('+', " ");
    match percent_decode(spaces.as_bytes()).decode_utf8() {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => spaces,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_token_response() {
        let body = "oauth_token=tok&oauth_token_secret=sec&oauth_callback_confirmed=true";
        let parsed = parse_oauth_token_response(body).unwrap();
        assert_eq!(parsed.oauth_token, "tok");
        assert_eq!(parsed.oauth_token_secret, "sec");
        assert_eq!(parsed.callback_confirmed, Some(true));
    }

    #[test]
    fn parses_access_token_response_without_callback() {
        let body = "oauth_token=atok&oauth_token_secret=asec";
        let parsed = parse_oauth_token_response(body).unwrap();
        assert_eq!(parsed.oauth_token, "atok");
        assert_eq!(parsed.oauth_token_secret, "asec");
        assert_eq!(parsed.callback_confirmed, None);
    }

    #[test]
    fn decodes_percent_escapes_and_plus() {
        let body = "oauth_token=a%2Bb&oauth_token_secret=c+d";
        let parsed = parse_oauth_token_response(body).unwrap();
        assert_eq!(parsed.oauth_token, "a+b");
        assert_eq!(parsed.oauth_token_secret, "c d");
    }

    #[test]
    fn missing_token_is_typed_error() {
        let body = "oauth_token_secret=sec";
        assert_eq!(
            parse_oauth_token_response(body).unwrap_err(),
            OauthParseError::MissingField {
                field: "oauth_token"
            }
        );
    }

    #[test]
    fn missing_secret_is_typed_error() {
        let body = "oauth_token=tok";
        assert_eq!(
            parse_oauth_token_response(body).unwrap_err(),
            OauthParseError::MissingField {
                field: "oauth_token_secret"
            }
        );
    }

    #[test]
    fn malformed_body_is_typed_error() {
        assert_eq!(
            parse_oauth_token_response("").unwrap_err(),
            OauthParseError::MalformedForm
        );
        assert_eq!(
            parse_oauth_token_response("not-a-form").unwrap_err(),
            OauthParseError::MalformedForm
        );
    }

    #[test]
    fn callback_confirmed_false() {
        let body = "oauth_token=t&oauth_token_secret=s&oauth_callback_confirmed=false";
        let parsed = parse_oauth_token_response(body).unwrap();
        assert_eq!(parsed.callback_confirmed, Some(false));
    }
}
