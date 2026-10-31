//! Pure keep-alive outcome classifier.
//!
//! The shell periodically makes a signed `GET /v1/accounts/list` to reset
//! ETrade's ~2h idle timer. This module maps the plain-value outcome of one
//! such call to the action the shell must take. No IO, no async: the shell
//! performs the logging and decides how to terminate.

/// What one keep-alive call produced, reduced to plain data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepAliveOutcome {
    /// The upstream answered with this HTTP status.
    Status(u16),
    /// No usable response (transport error, timeout, oversized body).
    TransportFailure,
}

/// The action the shell takes for a classified outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepAliveAction {
    /// 2xx: the idle timer was reset. Log and continue.
    Healthy { status: u16 },
    /// 401/403: the token is no longer valid (e.g. midnight ET expiry or
    /// revocation). Retrying is pointless; the proxy must stop.
    Fatal { status: u16 },
    /// Anything else: log a warning and retry at the next interval.
    /// `status` is `None` for a transport failure.
    Transient { status: Option<u16> },
}

/// Classify a keep-alive outcome. Total over every input.
pub fn classify(outcome: KeepAliveOutcome) -> KeepAliveAction {
    match outcome {
        KeepAliveOutcome::Status(s) if (200..300).contains(&s) => {
            KeepAliveAction::Healthy { status: s }
        }
        KeepAliveOutcome::Status(s @ (401 | 403)) => KeepAliveAction::Fatal { status: s },
        KeepAliveOutcome::Status(s) => KeepAliveAction::Transient { status: Some(s) },
        KeepAliveOutcome::TransportFailure => KeepAliveAction::Transient { status: None },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn success_is_healthy() {
        assert_eq!(
            classify(KeepAliveOutcome::Status(200)),
            KeepAliveAction::Healthy { status: 200 }
        );
    }

    #[test]
    fn auth_failures_are_fatal() {
        for s in [401, 403] {
            assert_eq!(
                classify(KeepAliveOutcome::Status(s)),
                KeepAliveAction::Fatal { status: s }
            );
        }
    }

    #[test]
    fn other_failures_are_transient() {
        for s in [199, 300, 400, 404, 429, 500, 503] {
            assert_eq!(
                classify(KeepAliveOutcome::Status(s)),
                KeepAliveAction::Transient { status: Some(s) }
            );
        }
        assert_eq!(
            classify(KeepAliveOutcome::TransportFailure),
            KeepAliveAction::Transient { status: None }
        );
    }

    proptest! {
        // Totality + partition: every status maps to exactly the expected class.
        #[test]
        fn classification_partitions_all_statuses(s in any::<u16>()) {
            let action = classify(KeepAliveOutcome::Status(s));
            match s {
                200..=299 => prop_assert_eq!(action, KeepAliveAction::Healthy { status: s }),
                401 | 403 => prop_assert_eq!(action, KeepAliveAction::Fatal { status: s }),
                _ => prop_assert_eq!(action, KeepAliveAction::Transient { status: Some(s) }),
            }
        }

        #[test]
        fn success_never_fatal(s in 200u16..300) {
            let fatal = matches!(classify(KeepAliveOutcome::Status(s)), KeepAliveAction::Fatal { .. });
            prop_assert!(!fatal);
        }
    }
}
