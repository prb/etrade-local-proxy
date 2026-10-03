//! Imperative shell entrypoint. Wires the startup sequence:
//! parse `--port` → snapshot env → validate config → generate TLS → run the
//! OAuth three-leg flow → serve the loopback HTTPS proxy. `anyhow` aggregates
//! errors here (the only place it is used), with `.context` at the boundaries
//! that aid diagnosis. Any error maps to a non-zero exit.

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;

use etrade_local_proxy::core::config::build_config;
use etrade_local_proxy::core::env::Environment;
use etrade_local_proxy::core::newtypes::ListenPort;
use etrade_local_proxy::shell::clock_nonce::{Clock, NonceSource, RandomNonceSource, SystemClock};
use etrade_local_proxy::shell::{env, oauth_flow, probe, prompt, server, state, tls};

/// Local HTTPS read-only reverse proxy for the ETrade API.
#[derive(Debug, Parser)]
#[command(name = "etrade-local-proxy", version, about)]
struct Cli {
    /// Loopback TCP port to listen on.
    #[arg(long, default_value_t = 8443)]
    port: u16,

    /// Target the ETrade sandbox (apisb.etrade.com) instead of the live
    /// environment. Absent = live (api.etrade.com).
    #[arg(long, default_value_t = false)]
    sandbox: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // `{:#}` renders the full anyhow context chain; no token material
            // reaches here (errors reference variable names, not values).
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let port = ListenPort::new(cli.port);
    // The `--sandbox` flag is the only interface for host selection (no env
    // var); absent = live, present = sandbox.
    let environment = if cli.sandbox {
        Environment::Sandbox
    } else {
        Environment::Live
    };

    // Validate config BEFORE binding any socket, so a missing credential exits
    // non-zero with a message naming the variable.
    let snapshot = env::snapshot();
    let config =
        build_config(&snapshot, port, environment).context("invalid configuration")?;
    let config = Arc::new(config);

    // Ephemeral TLS; prints the fingerprint to stdout.
    let tls = tls::generate().context("TLS setup failed")?;

    // Generator seams for the OAuth flow and the per-request signing.
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SystemClock);
    let nonces: Arc<dyn NonceSource + Send + Sync> = Arc::new(RandomNonceSource);

    // Three-leg OAuth flow (console authorize URL + stdin verifier).
    let authorized = oauth_flow::run(
        &config,
        None,
        clock.as_ref(),
        nonces.as_ref(),
        prompt::read_verifier,
    )
    .await
    .context("OAuth authorization flow failed")?;

    // Validate the freshly minted token with one signed lightweight read before
    // serving. On any non-2xx or transport error this returns an error that
    // `?`/`.context` propagate to `main`, which exits non-zero WITHOUT serving.
    let client = reqwest::Client::new();
    let account_count = probe::validate(
        &client,
        &config,
        &authorized,
        None,
        clock.as_ref(),
        nonces.as_ref(),
    )
    .await
    .context("authorization validation failed")?;
    match account_count {
        Some(n) => {
            eprintln!("info: authorization validated via GET /v1/accounts/list \u{2014} {n} accounts");
        }
        None => {
            eprintln!(
                "info: authorization validated via GET /v1/accounts/list \u{2014} account count unknown"
            );
        }
    }

    // Store the token and serve.
    let auth = state::ready(authorized);

    server::serve(port, tls.server_config, config, auth, clock, nonces)
        .await
        .context("server failed")?;

    Ok(())
}
