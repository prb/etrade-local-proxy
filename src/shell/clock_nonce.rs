//! The clock and nonce generator seams.
//!
//! The pure core takes plain `&Nonce`/`&Timestamp` values so property tests can
//! pin them. The shell feeds those values through two *generator* traits so a
//! fresh `(nonce, timestamp)` is drawn immediately before signing **each OAuth
//! leg and each proxied request** — no value is ever reused across legs or
//! requests. The real implementations wrap the system clock and a CSPRNG; the
//! deterministic fakes ([`FixedClock`], [`CounterNonceSource`]) let tests pin
//! inputs and are reused by the FEAT-003 integration suite.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;

use crate::core::newtypes::{Nonce, Timestamp};

/// Supplies the current wall-clock time in unix seconds.
pub trait Clock {
    /// The current time as unix seconds.
    fn now_unix(&self) -> Timestamp;
}

/// Supplies a fresh OAuth nonce per call.
pub trait NonceSource {
    /// A fresh, unique nonce. Each call must return a distinct value.
    fn next(&self) -> Nonce;
}

/// The two injected non-determinism sources that always travel together when
/// signing: a clock and a nonce source. Bundling them keeps the "draw a fresh
/// `(nonce, timestamp)` immediately before signing" contract in one borrowed
/// value instead of threading two parameters through every signing call.
#[derive(Clone, Copy)]
pub struct Signer<'a> {
    pub clock: &'a (dyn Clock + Send + Sync),
    pub nonces: &'a (dyn NonceSource + Send + Sync),
}

impl<'a> Signer<'a> {
    /// Bundle a clock and a nonce source for one signing call site.
    pub fn new(
        clock: &'a (dyn Clock + Send + Sync),
        nonces: &'a (dyn NonceSource + Send + Sync),
    ) -> Self {
        Self { clock, nonces }
    }

    /// Draw a fresh `(timestamp, nonce)` pair, immediately before signing.
    pub fn fresh(&self) -> (Timestamp, Nonce) {
        (self.clock.now_unix(), self.nonces.next())
    }
}

/// The real system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> Timestamp {
        // `duration_since` fails only if the system clock is before 1970, an
        // unrecoverable, nonsensical startup condition — a documented expect
        // site sanctioned by the steering doc.
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before UNIX_EPOCH")
            .as_secs();
        Timestamp::new(secs)
    }
}

/// A CSPRNG-backed nonce source producing a fresh 160-bit random hex nonce per
/// call. OAuth 1.0a requires `oauth_nonce` to be unique per `(timestamp,
/// token)`; 160 bits of entropy makes a collision negligible.
#[derive(Debug, Default, Clone, Copy)]
pub struct RandomNonceSource;

impl NonceSource for RandomNonceSource {
    fn next(&self) -> Nonce {
        let mut bytes = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut bytes);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Nonce::new(hex)
    }
}

/// A fixed clock for deterministic tests.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    secs: u64,
}

impl FixedClock {
    pub fn new(secs: u64) -> Self {
        Self { secs }
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> Timestamp {
        Timestamp::new(self.secs)
    }
}

/// A counter-backed nonce source for deterministic tests: it returns
/// `"nonce-0"`, `"nonce-1"`, ... so successive calls are distinct and
/// reproducible, letting a test assert the freshness contract.
#[derive(Debug, Default)]
pub struct CounterNonceSource {
    counter: AtomicU64,
}

impl CounterNonceSource {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl NonceSource for CounterNonceSource {
    fn next(&self) -> Nonce {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        Nonce::new(format!("nonce-{n}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_after_epoch() {
        // A sanity check: the real clock returns a plausibly recent timestamp.
        assert!(SystemClock.now_unix().as_secs() > 1_600_000_000);
    }

    #[test]
    fn random_nonce_is_distinct_and_hex() {
        let src = RandomNonceSource;
        let a = src.next();
        let b = src.next();
        assert_ne!(a.as_str(), b.as_str());
        assert_eq!(a.as_str().len(), 40);
        assert!(a.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fixed_clock_is_constant() {
        let clock = FixedClock::new(1_700_000_000);
        assert_eq!(clock.now_unix().as_secs(), 1_700_000_000);
        assert_eq!(clock.now_unix().as_secs(), 1_700_000_000);
    }

    #[test]
    fn counter_nonce_is_sequential_and_distinct() {
        let src = CounterNonceSource::new();
        assert_eq!(src.next().as_str(), "nonce-0");
        assert_eq!(src.next().as_str(), "nonce-1");
        assert_eq!(src.next().as_str(), "nonce-2");
    }
}
