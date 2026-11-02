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
//! Logging (stderr, UTC-timestamped, rendered by `core::keepalive_log`): a
//! schedule line at start, then one line per run with status and elapsed ms,
//! failure causes with a consecutive-failure count, and a fatal summary.
//! Only status codes, timings and transport-error text are logged, never
//! tokens, URLs, response bodies or account data.
use std::time::{Duration, Instant};

use reqwest::Client;

use crate::core::config::Config;
use crate::core::keepalive::{classify, KeepAliveAction, KeepAliveOutcome};
use crate::core::keepalive_log::{
    advance, schedule_line, FailureKind, LoopState, Observation, TransportCause,
};
use crate::core::status::Authorized;
use crate::shell::clock_nonce::Signer;
use crate::shell::error::{KeepAliveError, ProbeError, ProxyError};
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

/// Join an error's `source()` chain (excluding the error itself, whose
/// `reqwest` Display embeds the request URL) into `a: b: c`.
fn source_chain(err: &(dyn std::error::Error + 'static)) -> String {
    std::iter::successors(err.source(), |e| e.source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

/// Convert a probe failure into the plain cause the core renders.
/// `None` when the failure was an HTTP status (no transport cause).
fn cause_of(result: &Result<(), ProbeError>) -> Option<TransportCause> {
    match result {
        Ok(()) | Err(ProbeError::NonSuccessStatus { .. }) => None,
        Err(ProbeError::Transport(ProxyError::Upstream(e))) => Some(TransportCause {
            kind: if e.is_timeout() {
                FailureKind::Timeout
            } else if e.is_connect() {
                FailureKind::Connect
            } else {
                FailureKind::Other
            },
            detail: source_chain(e),
        }),
        Err(ProbeError::Transport(other)) => Some(TransportCause {
            kind: FailureKind::Other,
            detail: other.to_string(),
        }),
    }
}

/// Make one signed keep-alive call, timing it, and report what happened.
pub async fn attempt(
    client: &Client,
    config: &Config,
    authorized: &Authorized,
    base_url_override: Option<&str>,
    signer: Signer<'_>,
) -> Observation {
    let started = Instant::now();
    let result = probe::validate(client, config, authorized, base_url_override, signer).await;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    // A bare `Ok(())` carries no status; the probe accepts any 2xx, and the
    // log line reports 200 as the representative success code.
    Observation {
        action: classify(outcome_of(&result)),
        elapsed_ms,
        cause: cause_of(&result),
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
    attempt(client, config, authorized, base_url_override, signer)
        .await
        .action
}

/// Run the keep-alive loop forever, logging to stderr; returns only the fatal
/// error.
pub async fn run(
    client: &Client,
    config: &Config,
    authorized: &Authorized,
    base_url_override: Option<&str>,
    signer: Signer<'_>,
    interval: Duration,
) -> KeepAliveError {
    run_with_log(
        client,
        config,
        authorized,
        base_url_override,
        signer,
        interval,
        |line| eprintln!("{line}"),
    )
    .await
}

/// [`run`] with the log sink injected, so tests can capture the lines.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_log(
    client: &Client,
    config: &Config,
    authorized: &Authorized,
    base_url_override: Option<&str>,
    signer: Signer<'_>,
    interval: Duration,
    mut log: impl FnMut(&str),
) -> KeepAliveError {
    log(&schedule_line(signer.clock.now_unix().as_secs(), interval));
    // `interval_at` delays the first tick by one full period.
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut state = LoopState::default();
    loop {
        ticker.tick().await;
        let obs = attempt(client, config, authorized, base_url_override, signer).await;
        let (next, line) = advance(state, signer.clock.now_unix().as_secs(), interval, &obs);
        log(&line);
        state = next;
        if let KeepAliveAction::Fatal { status } = obs.action {
            return KeepAliveError::TokenRejected { code: status };
        }
    }
}
