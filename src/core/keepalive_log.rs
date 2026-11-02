//! Pure keep-alive log rendering and bookkeeping.
//!
//! Everything here is plain data in, `String`/plain data out. The shell
//! supplies the current time (from its injected clock), the measured elapsed
//! milliseconds, and a plain-data failure cause; it prints the returned lines.
//! Lines never contain tokens, headers, URLs, response bodies or account data:
//! only the fixed request label, HTTP status codes, timings and a short
//! transport-failure description supplied by the shell.

use std::time::Duration;

use crate::core::keepalive::KeepAliveAction;

/// The request the keep-alive task makes, as shown in log lines.
pub const REQUEST_LABEL: &str = "GET /v1/accounts/list";

/// Largest unix time rendered (9999-12-31T23:59:59Z); larger inputs clamp so
/// the output is always exactly 20 characters.
const MAX_SECS: u64 = 253_402_300_799;

/// Render unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC), total over all `u64`.
///
/// Uses the civil-from-days algorithm (proleptic Gregorian calendar).
pub fn iso8601_utc(unix_secs: u64) -> String {
    let secs = unix_secs.min(MAX_SECS);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Render an interval compactly: `30m`, `2h`, `45s`, `20ms`, `1500ms`.
pub fn interval_text(interval: Duration) -> String {
    let ms = interval.as_millis();
    if !ms.is_multiple_of(1000) {
        return format!("{ms}ms");
    }
    let secs = ms / 1000;
    match secs {
        0 => "0s".to_owned(),
        s if s.is_multiple_of(3600) => format!("{}h", s / 3600),
        s if s.is_multiple_of(60) => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// Short classification of a transport failure (no HTTP response).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The request exceeded a client timeout.
    Timeout,
    /// The connection could not be established.
    Connect,
    /// Any other transport error (TLS, reset, oversized body, ...).
    Other,
}

impl FailureKind {
    fn label(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect failure",
            Self::Other => "transport error",
        }
    }
}

/// A transport failure reduced to plain data by the shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportCause {
    pub kind: FailureKind,
    /// Source-chain text of the underlying error (no URL); may be empty.
    pub detail: String,
}

/// What one keep-alive attempt produced, as plain data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub action: KeepAliveAction,
    pub elapsed_ms: u64,
    /// Present when the attempt had no HTTP response.
    pub cause: Option<TransportCause>,
}

/// Progress carried between ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoopState {
    /// Consecutive transient failures so far (0 after a success).
    pub failures: u32,
    /// Unix seconds of the last successful keep-alive.
    pub last_ok: Option<u64>,
}

/// The startup line, printed before the first interval wait.
pub fn schedule_line(now: u64, interval: Duration) -> String {
    format!(
        "info: {} keep-alive scheduled: {REQUEST_LABEL} every {}, first run at {}",
        iso8601_utc(now),
        interval_text(interval),
        iso8601_utc(now.saturating_add(interval.as_secs())),
    )
}

/// Fold one observation into the state and render its log line.
/// A fatal observation leaves the state unchanged; its line is the summary.
pub fn advance(
    state: LoopState,
    now: u64,
    interval: Duration,
    obs: &Observation,
) -> (LoopState, String) {
    let ts = iso8601_utc(now);
    let retry = |failures: u32| {
        format!(
            "failure {failures} in a row; will retry in {}",
            interval_text(interval)
        )
    };
    match obs.action {
        KeepAliveAction::Healthy { status } => (
            LoopState {
                failures: 0,
                last_ok: Some(now),
            },
            format!(
                "info: {ts} keep-alive OK {REQUEST_LABEL} (HTTP {status}, {}ms)",
                obs.elapsed_ms
            ),
        ),
        KeepAliveAction::Fatal { status } => (
            state,
            format!(
                "error: {ts} keep-alive {REQUEST_LABEL} got HTTP {status}; \
                 last successful keep-alive: {}; the ETrade access token \
                 expired, went inactive, or was revoked; restart the proxy \
                 to re-authorize",
                state
                    .last_ok
                    .map_or_else(|| "none since startup".to_owned(), iso8601_utc),
            ),
        ),
        KeepAliveAction::Transient { status } => {
            let failures = state.failures.saturating_add(1);
            let next = LoopState { failures, ..state };
            let what = match (status, &obs.cause) {
                (Some(code), _) => format!("got HTTP {code}"),
                (None, Some(c)) if c.detail.is_empty() => format!("failed: {}", c.kind.label()),
                (None, Some(c)) => format!("failed: {} ({})", c.kind.label(), c.detail),
                (None, None) => "failed: transport error".to_owned(),
            };
            (
                next,
                format!(
                    "warn: {ts} keep-alive {REQUEST_LABEL} {what} after {}ms ({})",
                    obs.elapsed_ms,
                    retry(failures)
                ),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const IV: Duration = Duration::from_secs(30 * 60);

    #[test]
    fn known_vectors() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        // Leap-year day after Feb 29 and year-end boundaries.
        assert_eq!(iso8601_utc(951_868_800), "2000-03-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_704_067_199), "2023-12-31T23:59:59Z");
        assert_eq!(iso8601_utc(1_704_067_200), "2024-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(iso8601_utc(MAX_SECS), "9999-12-31T23:59:59Z");
        assert_eq!(iso8601_utc(u64::MAX), "9999-12-31T23:59:59Z");
    }

    #[test]
    fn interval_texts() {
        assert_eq!(interval_text(IV), "30m");
        assert_eq!(interval_text(Duration::from_secs(7200)), "2h");
        assert_eq!(interval_text(Duration::from_secs(45)), "45s");
        assert_eq!(interval_text(Duration::from_millis(20)), "20ms");
        assert_eq!(interval_text(Duration::from_millis(1500)), "1500ms");
    }

    #[test]
    fn schedule_line_format() {
        assert_eq!(
            schedule_line(1_700_000_000, IV),
            "info: 2023-11-14T22:13:20Z keep-alive scheduled: GET /v1/accounts/list \
             every 30m, first run at 2023-11-14T22:43:20Z"
        );
    }

    fn obs(action: KeepAliveAction, cause: Option<TransportCause>) -> Observation {
        Observation {
            action,
            elapsed_ms: 412,
            cause,
        }
    }

    #[test]
    fn ok_line_and_state() {
        let (st, line) = advance(
            LoopState {
                failures: 3,
                last_ok: None,
            },
            1_700_000_000,
            IV,
            &obs(KeepAliveAction::Healthy { status: 200 }, None),
        );
        assert_eq!(
            line,
            "info: 2023-11-14T22:13:20Z keep-alive OK GET /v1/accounts/list (HTTP 200, 412ms)"
        );
        assert_eq!(
            st,
            LoopState {
                failures: 0,
                last_ok: Some(1_700_000_000)
            }
        );
    }

    #[test]
    fn http_failure_counts_up_and_keeps_last_ok() {
        let o = obs(KeepAliveAction::Transient { status: Some(500) }, None);
        let s0 = LoopState {
            failures: 0,
            last_ok: Some(5),
        };
        let (s1, l1) = advance(s0, 1_700_000_000, IV, &o);
        let (s2, l2) = advance(s1, 1_700_000_000, IV, &o);
        assert_eq!(
            s2,
            LoopState {
                failures: 2,
                last_ok: Some(5)
            }
        );
        assert!(l1.contains("got HTTP 500 after 412ms (failure 1 in a row; will retry in 30m)"));
        assert!(l2.contains("failure 2 in a row"));
        assert!(l1.starts_with("warn: 2023-11-14T22:13:20Z "));
    }

    #[test]
    fn transport_causes_render_distinctly() {
        let mk = |kind, detail: &str| {
            advance(
                LoopState::default(),
                0,
                IV,
                &obs(
                    KeepAliveAction::Transient { status: None },
                    Some(TransportCause {
                        kind,
                        detail: detail.to_owned(),
                    }),
                ),
            )
            .1
        };
        assert!(mk(FailureKind::Timeout, "operation timed out")
            .contains("failed: timeout (operation timed out) after 412ms"));
        assert!(mk(FailureKind::Connect, "refused").contains("failed: connect failure (refused)"));
        assert!(mk(FailureKind::Other, "").contains("failed: transport error after"));
    }

    #[test]
    fn fatal_line_reports_last_success() {
        let o = obs(KeepAliveAction::Fatal { status: 401 }, None);
        let (_, none) = advance(LoopState::default(), 1_700_000_000, IV, &o);
        assert!(none.starts_with("error: 2023-11-14T22:13:20Z "));
        assert!(none.contains("got HTTP 401"));
        assert!(none.contains("last successful keep-alive: none since startup"));
        assert!(none.contains("restart the proxy to re-authorize"));
        let (_, some) = advance(
            LoopState {
                failures: 0,
                last_ok: Some(0),
            },
            1_700_000_000,
            IV,
            &o,
        );
        assert!(some.contains("last successful keep-alive: 1970-01-01T00:00:00Z"));
    }

    proptest! {
        #[test]
        fn iso_is_well_formed(s in any::<u64>()) {
            let t = iso8601_utc(s);
            prop_assert_eq!(t.len(), 20);
            let b = t.as_bytes();
            for (i, c) in b.iter().enumerate() {
                match i {
                    4 | 7 => prop_assert_eq!(*c, b'-'),
                    10 => prop_assert_eq!(*c, b'T'),
                    13 | 16 => prop_assert_eq!(*c, b':'),
                    19 => prop_assert_eq!(*c, b'Z'),
                    _ => prop_assert!(c.is_ascii_digit()),
                }
            }
        }

        // Fixed-width ISO strings sort lexicographically in time order.
        #[test]
        fn iso_preserves_order(a in 0u64..=MAX_SECS, b in 0u64..=MAX_SECS) {
            prop_assert_eq!(a.cmp(&b), iso8601_utc(a).cmp(&iso8601_utc(b)));
        }

        #[test]
        fn iso_fields_in_range(s in 0u64..=MAX_SECS) {
            let t = iso8601_utc(s);
            let n = |r: std::ops::Range<usize>| t[r].parse::<u32>().unwrap_or(u32::MAX);
            prop_assert!((1..=12).contains(&n(5..7)));
            prop_assert!((1..=31).contains(&n(8..10)));
            prop_assert!(n(11..13) < 24 && n(14..16) < 60 && n(17..19) < 60);
        }

        #[test]
        fn failures_reset_on_success(f in 0u32..1000, ms in 0u64..100_000) {
            let o = Observation {
                action: KeepAliveAction::Healthy { status: 200 },
                elapsed_ms: ms,
                cause: None,
            };
            let (st, _) = advance(LoopState { failures: f, last_ok: None }, 10, IV, &o);
            prop_assert_eq!(st.failures, 0);
        }
    }
}
