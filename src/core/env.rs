//! The target ETrade environment, modeled as a sum type (pure).
//!
//! The proxy targets the live ETrade environment by default; a `--sandbox` CLI
//! flag selects the sandbox. This module encapsulates the only consequence of
//! that choice — the upstream host — so no caller handles the `apisb`-vs-`api`
//! distinction directly (CONCEPT.md). The host is modeled as a newtype over the
//! host literal rather than a bare `&str`, so the two environments are the only
//! representable upstream hosts and the literals live in exactly one place
//! ([`crate::core::oauth::endpoints`]).

use crate::core::oauth::endpoints;

/// The ETrade environment the proxy signs and forwards against. `Live` is the
/// default; `Sandbox` is selected by the `--sandbox` flag. The authorize URL is
/// identical in both environments (see [`endpoints::AUTHORIZE_URL_BASE`]); the
/// only difference carried here is the upstream host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Environment {
    /// The live ETrade environment (`api.etrade.com`).
    #[default]
    Live,
    /// The ETrade sandbox environment (`apisb.etrade.com`).
    Sandbox,
}

/// The upstream host for the API read calls AND both OAuth token legs. A
/// newtype over the host literal so a host value cannot be confused with any
/// other string and the two environment hosts are the only ones representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamHost(&'static str);

impl UpstreamHost {
    /// The host as a plain string, for base-URL construction.
    pub fn as_str(&self) -> &str {
        self.0
    }
}

impl Environment {
    /// The single mapping from environment to upstream host:
    /// `Live -> api.etrade.com`, `Sandbox -> apisb.etrade.com`. Both literals
    /// come from [`endpoints`], the one source of truth for host strings.
    pub fn host(self) -> UpstreamHost {
        match self {
            Environment::Live => UpstreamHost(endpoints::UPSTREAM_HOST),
            Environment::Sandbox => UpstreamHost(endpoints::SANDBOX_UPSTREAM_HOST),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_maps_to_live_host() {
        assert_eq!(Environment::Live.host().as_str(), "api.etrade.com");
    }

    #[test]
    fn sandbox_maps_to_sandbox_host() {
        assert_eq!(Environment::Sandbox.host().as_str(), "apisb.etrade.com");
    }

    #[test]
    fn default_environment_is_live() {
        assert_eq!(Environment::default(), Environment::Live);
    }
}
