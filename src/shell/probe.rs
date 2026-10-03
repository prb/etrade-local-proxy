//! Startup authorization-validation probe.
//!
//! After the OAuth flow yields the `Authorized` access token and before the
//! proxy begins serving, this makes ONE signed lightweight read call
//! (`GET /v1/accounts/list`) through the shared signed-GET machinery in
//! [`crate::shell::upstream`] to confirm the token actually works.
//!
//! On a 2xx the token is validated: the body is parsed just enough to COUNT
//! accounts (never logging account data), and an unexpected/unparseable 2xx
//! body is still a success with the count reported as unknown — the 2xx proves
//! the token works regardless of the body shape. A non-2xx status or a
//! transport error is a fail-fast startup error (no `panic!`/`unwrap`): the
//! caller propagates it and the server never comes up.

use reqwest::Client;
use serde::Deserialize;

use crate::core::config::Config;
use crate::core::status::Authorized;
use crate::shell::clock_nonce::{Clock, NonceSource};
use crate::shell::error::ProbeError;
use crate::shell::upstream::signed_get;

/// The lightweight read used to validate authorization.
const PROBE_PATH: &str = "/v1/accounts/list";

/// Minimal, all-optional view of ETrade's `accounts/list` body for counting.
/// The wire shape is `{"AccountListResponse":{"Accounts":{"Account":[...]}}}`.
/// Every field is `Option` so an unexpected 2xx shape parses to `None` (count
/// unknown) rather than erroring — authorization is validated by the 2xx, not
/// the body.
#[derive(Debug, Deserialize)]
struct AccountListBody {
    #[serde(rename = "AccountListResponse")]
    account_list_response: Option<AccountListResponse>,
}

#[derive(Debug, Deserialize)]
struct AccountListResponse {
    #[serde(rename = "Accounts")]
    accounts: Option<Accounts>,
}

#[derive(Debug, Deserialize)]
struct Accounts {
    #[serde(rename = "Account")]
    account: Option<Vec<serde_json::Value>>,
}

/// Count the accounts in a 2xx `accounts/list` body. Total over arbitrary JSON:
/// a body that does not match the expected shape yields `None` (unknown count),
/// never a panic or error.
fn count_accounts(body: &[u8]) -> Option<usize> {
    serde_json::from_slice::<AccountListBody>(body)
        .ok()
        .and_then(|body| body.account_list_response)
        .and_then(|resp| resp.accounts)
        .and_then(|accounts| accounts.account)
        .map(|list| list.len())
}

/// Validate the access token with one signed `GET /v1/accounts/list`.
///
/// `base_url_override` is passed straight through to [`signed_get`] so the
/// probe targets the SAME host the proxy uses (the wiremock override in tests,
/// the selected `--sandbox`/live host in production). A fresh nonce/timestamp
/// is drawn inside `signed_get` for this call.
///
/// Returns `Ok(Some(n))` (token validated, `n` accounts) or `Ok(None)` (token
/// validated, count unknown because the 2xx body did not match the expected
/// shape). Returns `Err` on a non-2xx status or a transport failure — the
/// caller fails fast and does not serve.
pub async fn validate(
    client: &Client,
    config: &Config,
    authorized: &Authorized,
    base_url_override: Option<&str>,
    clock: &(dyn Clock + Send + Sync),
    nonces: &(dyn NonceSource + Send + Sync),
) -> Result<Option<usize>, ProbeError> {
    let relayed = signed_get(
        client,
        config,
        authorized,
        PROBE_PATH,
        base_url_override,
        clock,
        nonces,
    )
    .await?;

    if !(200..300).contains(&relayed.status) {
        return Err(ProbeError::NonSuccessStatus {
            code: relayed.status,
        });
    }

    Ok(count_accounts(&relayed.body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_accounts_from_expected_shape() {
        let body = br#"{"AccountListResponse":{"Accounts":{"Account":[{"a":1},{"b":2},{"c":3}]}}}"#;
        assert_eq!(count_accounts(body), Some(3));
    }

    #[test]
    fn empty_account_list_counts_zero() {
        let body = br#"{"AccountListResponse":{"Accounts":{"Account":[]}}}"#;
        assert_eq!(count_accounts(body), Some(0));
    }

    #[test]
    fn unexpected_shape_is_unknown_not_error() {
        assert_eq!(count_accounts(br#"{"unexpected":true}"#), None);
        assert_eq!(count_accounts(br#""not-an-object""#), None);
        assert_eq!(count_accounts(b"not json at all"), None);
    }
}
