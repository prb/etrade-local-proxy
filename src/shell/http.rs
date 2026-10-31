//! The single constructor for every outbound `reqwest::Client`.
//!
//! No production client may be built with `Client::new()` (which has no
//! timeouts): a hung or half-open connection would block forever, and a hung
//! keep-alive request would stall the loop until the token went idle. All
//! outbound calls (OAuth flow, startup probe, keep-alive, proxy forward) use a
//! client from [`http_client`].

use std::time::Duration;

use reqwest::Client;

/// Maximum time to establish the TCP/TLS connection to the upstream.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum total time for one request. In `reqwest` this covers connect, send,
/// and reading the full response body.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a client with the production timeouts ([`CONNECT_TIMEOUT`],
/// [`REQUEST_TIMEOUT`]).
pub fn http_client() -> Result<Client, reqwest::Error> {
    http_client_with(CONNECT_TIMEOUT, REQUEST_TIMEOUT)
}

/// Build a client with explicit timeouts (lets tests use short durations).
pub fn http_client_with(connect: Duration, request: Duration) -> Result<Client, reqwest::Error> {
    Client::builder()
        .connect_timeout(connect)
        .timeout(request)
        .build()
}
