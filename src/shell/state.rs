//! Shared runtime auth state.
//!
//! The write happens exactly once at startup (Pending → Ready); every read is
//! synchronous and the guard is **never held across an `.await`** — handlers
//! clone the `Arc<Authorized>` out and drop the guard before any async call.
//! This is `std::sync::RwLock` (not tokio's) deliberately, matching the
//! write-once / read-many pattern on the `current_thread` runtime.

use std::sync::{Arc, RwLock};

use crate::core::status::{status_body_authorized, status_body_unauthorized, Authorized, StatusBody};

/// Whether authorization has completed. The access token lives only inside the
/// `Authorized` typestate within `Ready`.
#[derive(Debug)]
pub enum AuthPhase {
    /// Authorization has not completed; no token held.
    Pending,
    /// Authorized; holds the token behind an `Arc` so a handler can clone it
    /// out under a short read guard and sign without holding the lock across an
    /// `.await`.
    Ready(Arc<Authorized>),
}

/// The shared handle to the auth phase.
pub type SharedState = Arc<RwLock<AuthPhase>>;

/// Create a shared state in the `Pending` phase.
pub fn pending() -> SharedState {
    Arc::new(RwLock::new(AuthPhase::Pending))
}

/// Create a shared state already in the `Ready` phase (used after the OAuth
/// flow completes, and by tests).
pub fn ready(authorized: Authorized) -> SharedState {
    Arc::new(RwLock::new(AuthPhase::Ready(Arc::new(authorized))))
}

/// Flip the phase to `Ready`, storing the authorized token. A poisoned lock at
/// startup is unrecoverable (documented expect site).
pub fn set_ready(state: &SharedState, authorized: Authorized) {
    let mut guard = state.write().expect("auth-state lock poisoned");
    *guard = AuthPhase::Ready(Arc::new(authorized));
}

/// Clone the `Arc<Authorized>` out if ready, dropping the read guard before
/// returning. Returns `None` while `Pending`. A poisoned lock is a documented
/// expect site.
pub fn authorized_handle(state: &SharedState) -> Option<Arc<Authorized>> {
    let guard = state.read().expect("auth-state lock poisoned");
    match &*guard {
        AuthPhase::Pending => None,
        AuthPhase::Ready(a) => Some(Arc::clone(a)),
    }
}

/// Build the `/internal/status` body from the current phase, reading under a
/// guard that is dropped before serialization. A poisoned lock is a documented
/// expect site.
pub fn status_body(state: &SharedState) -> StatusBody {
    let guard = state.read().expect("auth-state lock poisoned");
    match &*guard {
        AuthPhase::Pending => status_body_unauthorized(),
        AuthPhase::Ready(a) => status_body_authorized(a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::newtypes::{AccessToken, TokenSecret};
    use crate::core::status::Unauthorized;

    fn authed() -> Authorized {
        Unauthorized.authorize(AccessToken::new("acctok"), TokenSecret::new("accsec"))
    }

    #[test]
    fn pending_has_no_handle_and_unauthorized_status() {
        let state = pending();
        assert!(authorized_handle(&state).is_none());
        let json = serde_json::to_string(&status_body(&state)).unwrap();
        assert_eq!(json, r#"{"authorized":false}"#);
    }

    #[test]
    fn set_ready_exposes_handle_and_authorized_status() {
        let state = pending();
        set_ready(&state, authed());
        assert!(authorized_handle(&state).is_some());
        let json = serde_json::to_string(&status_body(&state)).unwrap();
        assert_eq!(json, r#"{"authorized":true}"#);
    }

    #[test]
    fn ready_constructor_is_authorized() {
        let state = ready(authed());
        assert!(authorized_handle(&state).is_some());
    }
}
