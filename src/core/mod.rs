//! Pure functional core.
//!
//! Every item here is a plain-value transformation: data in, data out, with no
//! IO, no async runtime, and no references to `tokio`, `axum`, `reqwest`,
//! `rustls`, `std::env`, or `std::io`. Sources of non-determinism (clock,
//! nonce) are *injected* as parameters by the shell so the core stays
//! deterministic and unit- and property-testable with plain values.

pub mod admission;
pub mod authorize_url;
pub mod config;
pub mod error;
pub mod newtypes;
pub mod oauth;
pub mod relay;
pub mod status;
pub mod tls_fingerprint;
