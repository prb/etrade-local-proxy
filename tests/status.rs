//! Integration test for `/internal/status` served over the REAL `rustls`
//! stack, in both auth phases, plus the proxy handler's `503`/`NotReady`
//! branch while Pending.
//!
//! The server is driven through the `serve` seam (`shell::server::serve`),
//! which binds a loopback TLS listener via `axum-server`. A `reqwest` client
//! configured to accept the ephemeral self-signed cert talks to it. No live
//! ETrade call is made (AC-13): the Pending proxy request is rejected `503`
//! before any upstream call, and the Ready status request touches no upstream.

mod common;

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use common::test_config;

use etrade_local_proxy::core::newtypes::{AccessToken, ListenPort, TokenSecret};
use etrade_local_proxy::core::status::Unauthorized;
use etrade_local_proxy::shell::clock_nonce::{Clock, NonceSource, RandomNonceSource, SystemClock};
use etrade_local_proxy::shell::server::serve;
use etrade_local_proxy::shell::state::{self, SharedState};
use etrade_local_proxy::shell::tls;

/// Grab a currently-free loopback port by binding to port 0 and releasing it.
/// There is a small race window before `serve` rebinds, acceptable for a test.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener
        .local_addr()
        .expect("listener has a local address")
        .port()
}

/// A reqwest client that trusts the loopback self-signed cert (the fingerprint
/// is how a real client bootstraps trust; the test accepts it directly).
fn tls_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build test client")
}

/// Spin up `serve` with the given shared state on a free port and return the
/// chosen port plus the task handle. The caller aborts the task when done.
async fn spawn_server(auth: SharedState) -> (u16, tokio::task::JoinHandle<()>) {
    let tls = tls::generate().expect("tls generation succeeds");
    let config = Arc::new(test_config());
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SystemClock);
    let nonces: Arc<dyn NonceSource + Send + Sync> = Arc::new(RandomNonceSource);

    let port = free_port();
    let server_config = tls.server_config.clone();
    let handle = tokio::spawn(async move {
        // The serve future runs until the task is aborted.
        let _ = serve(
            ListenPort::new(port),
            server_config,
            config,
            auth,
            clock,
            nonces,
        )
        .await;
    });

    // Give the listener a moment to come up before the first request.
    wait_until_listening(port).await;
    (port, handle)
}

/// Poll the port until a TLS request succeeds (or time out).
async fn wait_until_listening(port: u16) {
    let client = tls_client();
    let url = format!("https://127.0.0.1:{port}/internal/status");
    for _ in 0..50 {
        if client.get(&url).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server on port {port} did not start listening");
}

#[tokio::test]
async fn status_reports_false_while_pending_and_proxy_returns_503() {
    let auth = state::pending();
    let (port, handle) = spawn_server(auth).await;
    let client = tls_client();

    // /internal/status => {"authorized":false}
    let status_body = client
        .get(format!("https://127.0.0.1:{port}/internal/status"))
        .send()
        .await
        .expect("status request succeeds")
        .text()
        .await
        .expect("status body readable");
    assert_eq!(status_body, r#"{"authorized":false}"#);

    // A proxied GET while Pending => 503 (ProxyError::NotReady), with no
    // upstream call attempted.
    let proxy = client
        .get(format!(
            "https://127.0.0.1:{port}/etrade-api/v1/accounts/list"
        ))
        .send()
        .await
        .expect("proxy request completes");
    assert_eq!(proxy.status().as_u16(), 503);

    handle.abort();
}

#[tokio::test]
async fn status_reports_true_while_ready() {
    let authorized =
        Unauthorized.authorize(AccessToken::new("acctok"), TokenSecret::new("accsec"));
    let auth = state::ready(authorized);
    let (port, handle) = spawn_server(auth).await;
    let client = tls_client();

    let body = client
        .get(format!("https://127.0.0.1:{port}/internal/status"))
        .send()
        .await
        .expect("status request succeeds")
        .text()
        .await
        .expect("status body readable");
    assert_eq!(body, r#"{"authorized":true}"#);

    handle.abort();
}
