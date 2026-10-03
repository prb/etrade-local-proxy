//! Reads the two credential environment variables into an [`EnvSnapshot`] —
//! the only `std::env` reads in the crate. This is the single environment seam;
//! the pure core validates the resulting snapshot (`core::config::build_config`).

use crate::core::config::EnvSnapshot;

/// Environment variable holding the ETrade OAuth consumer key.
pub const CONSUMER_KEY_VAR: &str = "ETRADE_CONSUMER_KEY";
/// Environment variable holding the ETrade OAuth consumer secret.
pub const CONSUMER_SECRET_VAR: &str = "ETRADE_CONSUMER_SECRET";

/// Capture a snapshot of the two credential variables. An unset variable maps
/// to `None`; a set-but-blank variable is kept as `Some("")` so the pure
/// validator can distinguish "missing" from "empty" and name the right error.
pub fn snapshot() -> EnvSnapshot {
    EnvSnapshot {
        consumer_key: std::env::var(CONSUMER_KEY_VAR).ok(),
        consumer_secret: std::env::var(CONSUMER_SECRET_VAR).ok(),
    }
}
