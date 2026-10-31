//! Background keep-alive task.
//!
//! ETrade access tokens go inactive after ~2 hours idle; a periodic signed
//! `GET /v1/accounts/list` resets that timer. It cannot (and does not try to)
//! extend the midnight US Eastern hard expiry.
//!
//! Each tick reuses [`probe::validate`] (and thus the shared `signed_get`), so
//! every call draws its own fresh nonce/timestamp via the [`Signer`]. The pure
//! core ([`classify`]) decides the action; this module only performs effects.
//!
//! Termination: [`run`] loops forever and returns only a [`KeepAliveError`]
//! on a fatal (401/403) outcome. `main` selects on this
//! future alongside the server, so a fatal keep-alive propagates through
//! `anyhow` to a non-zero exit with no `process::exit` in the shell.
//! The first call fires one interval after start (the startup probe just ran).
//! Only status codes are logged, never response bodies or account data.
use std::time::Duration;

use reqwest::Client;

use crate::core::config::Config;
use crate::core::keepalive::{classify, KeepAliveAction, KeepAliveOutcome};
use crate::core::status::Authorized;
use crate::shell::clock_nonce::Signer;
use crate::shell::error::{KeepAliveError, ProbeError};
use crate::shell::probe;

/// Default keep-alive period: well inside ETrade's ~2h idle window.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Reduce a probe result to the plain outcome the pure core classifies.
fn outcome_of(result: &Result<(), ProbeError>) -> KeepAliveOutcome {
    match result {
        Ok(()) => KeepAliveOutcome::Status(200),
        Err(ProbeError::NonSuccessStatus { code }) => KeepAliveOutcome::Status(*code),
        Err(_) => KeepAliveOutcome::TransportFailure,
    }
}

/// Make one signed keep-alive call and classify the result.
pub async fn tick(
    client: &Client,
    config: &Config,
    authorized: &Authorized,
    base_url_override: Option<&str>,
    signer: Signer<'_>,
) -> KeepAliveAction {
    let result = probe::validate(client, config, authorized, base_url_override, signer).await;
    // A bare `Ok(())` carries no status; the probe accepts any 2xx, and the
    // log line reports 200 as the representative success code.
    classify(outcome_of(&result))
}

/// Run the keep-alive loop forever, returning only the fatal error.
pub async fn run(
    client: &Client,
    config: &Config,
    authorized: &Authorized,
    base_url_override: Option<&str>,
    signer: Signer<'_>,
    interval: Duration,
) -> KeepAliveError {
    // `interval_at` delays the first tick by one full period.
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match tick(client, config, authorized, base_url_override, signer).await {
            KeepAliveAction::Healthy { status } => {
                eprintln!("info: keep-alive OK (HTTP {status})");
            }
            KeepAliveAction::Fatal { status } => {
                return KeepAliveError::TokenRejected { code: status };
            }
            KeepAliveAction::Transient { status: Some(code) } => {
                eprintln!("warn: keep-alive got HTTP {code}; will retry next interval");
            }
            KeepAliveAction::Transient { status: None } => {
                eprintln!("warn: keep-alive request failed; will retry next interval");
            }
        }
    }
}
