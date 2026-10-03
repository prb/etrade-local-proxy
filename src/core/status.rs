//! Authorization lifecycle as a consuming typestate, plus status
//! serialization. "Authorized" is derived from *which type the runtime holds*,
//! not a boolean flag or a nullable token.

use crate::core::newtypes::{AccessToken, TokenSecret};

/// The start state: no token held.
#[derive(Debug)]
pub struct Unauthorized;

/// The authorized state: owns the access token and its secret. The access
/// token exists only inside a value of this type.
#[derive(Debug)]
pub struct Authorized {
    access_token: AccessToken,
    token_secret: TokenSecret,
}

impl Unauthorized {
    /// Consume the unauthorized state to produce the authorized one. Supplying
    /// a token is the only way to reach [`Authorized`].
    pub fn authorize(self, access_token: AccessToken, token_secret: TokenSecret) -> Authorized {
        Authorized {
            access_token,
            token_secret,
        }
    }
}

impl Authorized {
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    pub fn token_secret(&self) -> &TokenSecret {
        &self.token_secret
    }
}

/// The `/internal/status` response body.
#[derive(Debug, serde::Serialize)]
pub struct StatusBody {
    authorized: bool,
}

/// `{"authorized":false}`.
pub fn status_body_unauthorized() -> StatusBody {
    StatusBody { authorized: false }
}

/// `{"authorized":true}`. Takes `&Authorized` but never reads the token bytes.
pub fn status_body_authorized(_: &Authorized) -> StatusBody {
    StatusBody { authorized: true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_serializes_false() {
        let json = serde_json::to_string(&status_body_unauthorized()).unwrap();
        insta::assert_snapshot!("status_unauthorized", json);
    }

    #[test]
    fn authorized_serializes_true() {
        let authed = Unauthorized.authorize(
            AccessToken::new("acctok"),
            TokenSecret::new("accsec"),
        );
        let json = serde_json::to_string(&status_body_authorized(&authed)).unwrap();
        insta::assert_snapshot!("status_authorized", json);
    }

    #[test]
    fn typestate_round_trip() {
        let authed = Unauthorized.authorize(AccessToken::new("a"), TokenSecret::new("s"));
        assert_eq!(authed.access_token().as_str(), "a");
    }
}
