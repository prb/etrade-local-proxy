//! Imperative shell: owns all effects (async runtime, TLS, HTTP server/client,
//! stdin/stdout prompts, environment reads, system clock and RNG). Every
//! decision is delegated to the pure core; this layer only performs effects.

pub mod clock_nonce;
pub mod env;
pub mod error;
pub mod handlers;
pub mod oauth_flow;
pub mod probe;
pub mod prompt;
pub mod server;
pub mod state;
pub mod tls;
pub mod upstream;
