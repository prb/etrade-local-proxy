//! Startup authorization-validation probe.
//!
//! After the OAuth flow yields the `Authorized` access token and before the
//! proxy begins serving, this makes ONE signed lightweight read call
//! (`GET /v1/accounts/list`) through the shared signed-GET machinery in
//! [`crate::shell::upstream`] to confirm the token actually works.
//!
//! A 2xx status validates the token — that is the entire authorization signal,
//! so the response body is not inspected (ETrade returns XML here, and the
//! probe needs nothing from it). A non-2xx status or a transport error is a
//! fail-fast startup error (no `panic!`/`unwrap`): the caller propagates it and
//! the server never comes up.

use reqwest::Client;

use crate::core::config::Config;
use crate::core::status::Authorized;
use crate::shell::clock_nonce::Signer;
use crate::shell::error::ProbeError;
use crate::shell::upstream::signed_get;

/// The lightweight read used to validate authorization.
const PROBE_PATH: &str = "/v1/accounts/list";

/// Validate the access token with one signed `GET /v1/accounts/list`.
///
/// `base_url_override` is passed straight through to [`signed_get`] so the
/// probe targets the SAME host the proxy uses (the wiremock override in tests,
/// the selected `--sandbox`/live host in production). A fresh nonce/timestamp
/// is drawn inside `signed_get` for this call.
///
/// Returns `Ok(())` when the token is validated (a 2xx response). Returns
/// `Err` on a non-2xx status or a transport failure — the caller fails fast
/// and does not serve.
pub async fn validate(
    client: &Client,
    config: &Config,
    authorized: &Authorized,
    base_url_override: Option<&str>,
    signer: Signer<'_>,
) -> Result<(), ProbeError> {
    // The probe sends no client `Accept`; ETrade's default (XML) is fine, since
    // the probe keys only on the 2xx status, not the body.
    let relayed = signed_get(
        client,
        config,
        authorized,
        PROBE_PATH,
        None,
        base_url_override,
        signer,
    )
    .await?;

    if !(200..300).contains(&relayed.status) {
        return Err(ProbeError::NonSuccessStatus {
            code: relayed.status,
        });
    }

    Ok(())
}
