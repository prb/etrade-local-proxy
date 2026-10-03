//! Loopback bind helper and the axum server wiring.
//!
//! The bind address is a **code constant** (`127.0.0.1`) — only the port is
//! configurable, so there is no code path to a non-loopback address (AC-9). The
//! router is a single fallback handler routed through `admit`, keeping the
//! verb-first admission the single source of truth.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use reqwest::Client;
use rustls::ServerConfig;

use crate::core::config::Config;
use crate::core::newtypes::ListenPort;
use crate::shell::clock_nonce::{Clock, NonceSource};
use crate::shell::error::ServerError;
use crate::shell::handlers::{self, AppState};
use crate::shell::state::SharedState;

/// The loopback socket address for a given port. The IP is the hard-coded
/// constant `127.0.0.1`; nothing derives it from input, config, or env.
pub fn bind_addr(port: ListenPort) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port.get())
}

/// Build the axum router with the fallback handler and app state.
pub fn router(state: AppState) -> Router {
    Router::new()
        .fallback(handlers::handle)
        .with_state(state)
}

/// Assemble the [`AppState`] shared by every request.
#[allow(clippy::too_many_arguments)]
pub fn app_state(
    config: Arc<Config>,
    auth: SharedState,
    clock: Arc<dyn Clock + Send + Sync>,
    nonces: Arc<dyn NonceSource + Send + Sync>,
    upstream_base: Option<String>,
) -> AppState {
    AppState {
        config,
        auth,
        clock,
        nonces,
        client: Client::new(),
        upstream_base,
    }
}

/// Bind the loopback TLS listener and serve until shutdown.
///
/// This is the serve seam: it takes the shared state and the generator seams as
/// parameters so an integration test can drive a server with a `Pending` state
/// and a counter-backed `NonceSource` (see FEAT-003).
pub async fn serve(
    port: ListenPort,
    server_config: Arc<ServerConfig>,
    config: Arc<Config>,
    auth: SharedState,
    clock: Arc<dyn Clock + Send + Sync>,
    nonces: Arc<dyn NonceSource + Send + Sync>,
) -> Result<(), ServerError> {
    let addr = bind_addr(port);
    let tls = RustlsConfig::from_config(server_config);
    let state = app_state(config, auth, clock, nonces, None);
    let app = router(state);

    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await
        .map_err(ServerError::Bind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn bind_addr_is_loopback_example() {
        let addr = bind_addr(ListenPort::new(8443));
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addr.port(), 8443);
    }

    proptest! {
        // AC-9: for EVERY port the bind IP is loopback; there is no path to any
        // other address.
        #[test]
        fn bind_addr_always_loopback(port in any::<u16>()) {
            let addr = bind_addr(ListenPort::new(port));
            prop_assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            prop_assert!(addr.ip().is_loopback());
            prop_assert_eq!(addr.port(), port);
        }
    }
}
