//! The three OAuth 1.0a legs as distinct typed signing inputs, and the protocol
//! parameters assembled from them.
//!
//! The signing domain is modeled around the **work performed**, not the URL.
//! Each [`SigningInput`] variant carries exactly the fields its leg admits, so
//! illegal states — a request-token leg carrying a token, a resource leg
//! carrying a callback — are unrepresentable. [`OauthParams`] has **no**
//! `oauth_signature` field (the signature is computed last and only ever
//! rendered into the header) and makes `oauth_token` simply *absent* on the
//! request-token leg (never an empty string), which both base string and header
//! derive from the same [`OauthParams::as_pairs`].

use crate::core::newtypes::{
    AccessToken, ConsumerKey, Nonce, RequestToken, ResourcePath, Timestamp, TokenSecret,
};

pub(crate) const SIGNATURE_METHOD: &str = "HMAC-SHA1";
pub(crate) const OAUTH_VERSION: &str = "1.0";

/// The three OAuth 1.0a legs as distinct signing inputs. Each variant carries
/// exactly the fields its leg requires — no optional token, no empty-string
/// placeholder. The signing key material (the token secret) travels *with* the
/// leg, so pairing the wrong secret with a leg is unrepresentable.
pub enum SigningInput<'a> {
    /// Leg 1 — get request token. Consumer key only, carries `oauth_callback`.
    /// No token field and no token secret, so `oauth_token` can never be
    /// emitted on this leg. Signs with the consumer secret and an empty token
    /// secret (supplied by `sign_leg`).
    RequestToken {
        consumer_key: &'a ConsumerKey,
        callback: &'a str,
    },
    /// Leg 2 — exchange verifier for access token. Consumer key + the request
    /// token (public value) + the request token's secret (signs this leg) +
    /// `oauth_verifier`.
    AccessToken {
        consumer_key: &'a ConsumerKey,
        request_token: &'a RequestToken,
        request_token_secret: &'a TokenSecret,
        verifier: &'a crate::core::newtypes::Verifier,
    },
    /// Leg 3 — sign a proxied read. Consumer key + the access token (public
    /// value) + the access token's secret (signs this leg) + the **mapped
    /// upstream path** (no query) this leg is being signed over. The path is
    /// part of this leg's signing input by definition — it is what the resource
    /// leg needs to compute its RFC-5849 base URI — so it travels inside the
    /// variant and `sign_leg` builds the base URL from it. No callback or
    /// verifier.
    Resource {
        consumer_key: &'a ConsumerKey,
        access_token: &'a AccessToken,
        access_token_secret: &'a TokenSecret,
        path: &'a ResourcePath,
    },
}

/// The protocol parameters for one leg. **No `oauth_signature` field** by
/// construction. `token` is `Some` only for the access-token and resource legs;
/// `None` for the request-token leg, so a literal `oauth_token=""` is
/// structurally impossible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OauthParams {
    consumer_key: String,
    nonce: String,
    timestamp: String,
    signature_method: &'static str,
    version: &'static str,
    /// Present only on the access-token (request token) and resource (access
    /// token) legs.
    token: Option<String>,
    /// `oauth_callback` (leg 1) or `oauth_verifier` (leg 2); empty on leg 3.
    extra: Vec<(String, String)>,
}

impl OauthParams {
    /// The protocol params rendered as `(name, value)` pairs, **excluding**
    /// `oauth_signature`. The single source for both the base-string parameter
    /// set and the rendered header, so the two cannot diverge. Emits
    /// `oauth_token` only when the leg carried a token, and emits every `extra`
    /// entry so those protocol parameters enter both the base string and the
    /// header.
    pub fn as_pairs(&self) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = Vec::with_capacity(6 + self.extra.len());
        pairs.push(("oauth_consumer_key".to_string(), self.consumer_key.clone()));
        pairs.push(("oauth_nonce".to_string(), self.nonce.clone()));
        pairs.push((
            "oauth_signature_method".to_string(),
            self.signature_method.to_string(),
        ));
        pairs.push(("oauth_timestamp".to_string(), self.timestamp.clone()));
        if let Some(token) = &self.token {
            pairs.push(("oauth_token".to_string(), token.clone()));
        }
        pairs.push(("oauth_version".to_string(), self.version.to_string()));
        pairs.extend(self.extra.iter().cloned());
        pairs
    }
}

/// Assemble [`OauthParams`] from a [`SigningInput`] plus the **injected**
/// nonce/timestamp. Total over the three domains: each variant maps to exactly
/// the fields that leg admits.
pub fn oauth_params(
    input: &SigningInput<'_>,
    nonce: &Nonce,
    timestamp: &Timestamp,
) -> OauthParams {
    let (consumer_key, token, extra) = match input {
        SigningInput::RequestToken {
            consumer_key,
            callback,
        } => (
            consumer_key.as_str().to_string(),
            None,
            vec![("oauth_callback".to_string(), (*callback).to_string())],
        ),
        SigningInput::AccessToken {
            consumer_key,
            request_token,
            verifier,
            ..
        } => (
            consumer_key.as_str().to_string(),
            Some(request_token.as_str().to_string()),
            vec![("oauth_verifier".to_string(), verifier.as_str().to_string())],
        ),
        SigningInput::Resource {
            consumer_key,
            access_token,
            ..
        } => (
            consumer_key.as_str().to_string(),
            Some(access_token.as_str().to_string()),
            Vec::new(),
        ),
    };

    OauthParams {
        consumer_key,
        nonce: nonce.as_str().to_string(),
        timestamp: timestamp.as_secs().to_string(),
        signature_method: SIGNATURE_METHOD,
        version: OAUTH_VERSION,
        token,
        extra,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::newtypes::Verifier;

    fn nonce() -> Nonce {
        Nonce::new("nonce123")
    }

    fn ts() -> Timestamp {
        Timestamp::new(1_700_000_000)
    }

    #[test]
    fn request_token_leg_has_no_token_but_has_callback() {
        let key = ConsumerKey::new("ckey");
        let input = SigningInput::RequestToken {
            consumer_key: &key,
            callback: "oob",
        };
        let params = oauth_params(&input, &nonce(), &ts());
        let pairs = params.as_pairs();
        assert!(pairs.iter().all(|(n, _)| n != "oauth_token"));
        assert!(pairs
            .iter()
            .any(|(n, v)| n == "oauth_callback" && v == "oob"));
    }

    #[test]
    fn access_token_leg_has_request_token_and_verifier() {
        let key = ConsumerKey::new("ckey");
        let rt = RequestToken::new("reqtok");
        let secret = TokenSecret::new("reqsec");
        let verifier = Verifier::new("verif");
        let input = SigningInput::AccessToken {
            consumer_key: &key,
            request_token: &rt,
            request_token_secret: &secret,
            verifier: &verifier,
        };
        let pairs = oauth_params(&input, &nonce(), &ts()).as_pairs();
        assert!(pairs
            .iter()
            .any(|(n, v)| n == "oauth_token" && v == "reqtok"));
        assert!(pairs
            .iter()
            .any(|(n, v)| n == "oauth_verifier" && v == "verif"));
    }

    #[test]
    fn resource_leg_has_access_token_and_no_extra() {
        let key = ConsumerKey::new("ckey");
        let at = AccessToken::new("acctok");
        let secret = TokenSecret::new("accsec");
        let path = ResourcePath::new("/v1/accounts/list");
        let input = SigningInput::Resource {
            consumer_key: &key,
            access_token: &at,
            access_token_secret: &secret,
            path: &path,
        };
        let pairs = oauth_params(&input, &nonce(), &ts()).as_pairs();
        assert!(pairs
            .iter()
            .any(|(n, v)| n == "oauth_token" && v == "acctok"));
        assert!(pairs
            .iter()
            .all(|(n, _)| n != "oauth_callback" && n != "oauth_verifier"));
    }

    #[test]
    fn common_params_present_on_every_leg() {
        let key = ConsumerKey::new("ckey");
        let input = SigningInput::RequestToken {
            consumer_key: &key,
            callback: "oob",
        };
        let pairs = oauth_params(&input, &nonce(), &ts()).as_pairs();
        for required in [
            "oauth_consumer_key",
            "oauth_nonce",
            "oauth_signature_method",
            "oauth_timestamp",
            "oauth_version",
        ] {
            assert!(pairs.iter().any(|(n, _)| n == required), "missing {required}");
        }
        assert!(pairs
            .iter()
            .any(|(n, v)| n == "oauth_signature_method" && v == "HMAC-SHA1"));
        assert!(pairs.iter().any(|(n, v)| n == "oauth_version" && v == "1.0"));
        // Never carries a signature.
        assert!(pairs.iter().all(|(n, _)| n != "oauth_signature"));
    }
}
