//! Imperative shell: owns all effects (async runtime, TLS, HTTP server/client,
//! stdin/stdout prompts, environment reads, system clock and RNG).
//!
//! These modules are implemented in FEAT-002. For FEAT-001 they are doc stubs
//! so the crate compiles while the pure core is built and tested.

pub mod clock_nonce;
pub mod env;
pub mod error;
pub mod handlers;
pub mod oauth_flow;
pub mod prompt;
pub mod server;
pub mod state;
pub mod tls;
pub mod upstream;
