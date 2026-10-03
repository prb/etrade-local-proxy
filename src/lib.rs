//! ETrade local read-only proxy.
//!
//! The crate is split into a **pure functional core** (`core`) and a **thin
//! imperative shell** (`shell`), per `.kiro/steering/rust-functional-style.md`.
//! The `core` tree performs no IO and references no async runtime, HTTP, TLS,
//! `std::env`, or `std::io`; it is unit- and property-testable with plain
//! values. The `shell` tree owns all effects and calls into the core.

pub mod core;
pub mod shell;
