//! List refresh policy (part P3b): the per-list refresh state machine and the schedule.
//!
//! This module is pure. It reads no clock: each event carries `now`, a [`MonoTime`] from the
//! monotonic clock of the shell. Wall-clock times (Unix seconds) come in as inputs too.
//!
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Idle
//!     Idle --> Due: Tick (now >= next_due)
//!     Idle --> Due: UpdateNow
//!     Backoff --> Due: Tick (now >= retry_at)
//!     Backoff --> Due: UpdateNow
//!     Due --> Fetching: Start
//!     Fetching --> Idle: Updated / NotModified
//!     Fetching --> Backoff: Failed (backoff x 2, capped)
//!     Fetching --> Due: outcome after an UpdateNow during the fetch
//!     Idle --> Idle: invalid event (logged at ERROR)
//! ```
//!
//! - `Updated`, `NotModified` and `Failed` are the outcomes of one fetch. After an outcome
//!   the machine waits again (`Idle`), or retries later (`Backoff`).
//! - A manual "update now" moves `Idle` and `Backoff` to `Due`. In `Due` it changes nothing.
//!   In `Fetching` it sets a flag: when the fetch ends, the machine goes to `Due` again, so a
//!   fetch always starts after the request (the URL can have changed during the fetch).
//! - An invalid event (an outcome with no fetch, a `Start` when the list is not due, time
//!   that goes back) is logged at ERROR with the full state and event. The machine then goes
//!   to `Idle` with the next scheduled time, the safe state: no fetch runs.
//! - The machine has no loop. Each event is one transition. From any state, at most
//!   [`MAX_STEPS_TO_FETCH`] events (`UpdateNow`, then `Start`) start a fetch; see
//!   [`steps_to_fetch`].
//!
//! The schedule: a list is due `refresh_interval_hours` after its last success, plus a small
//! jitter. The jitter comes from the list id ([`jitter`]), so tests are stable and the lists
//! do not all start at the same second. `refresh_interval_hours = 0` turns the schedule off:
//! [`next_due`] gives no time, "update now" still works, a list with no copy on disk is still
//! fetched once at start, and a failed fetch still retries with backoff (cap
//! [`MANUAL_BACKOFF_CAP`]) until one fetch works.

pub mod meta;
#[cfg(test)]
mod tests;

use std::time::Duration;

pub use crate::blocking_state::MonoTime;
pub use meta::{BodyFacts, EntryCounts, ListMeta, MetaError, Validators, parse_meta, render_meta};

/// First retry delay after a failed fetch.
pub const DEFAULT_BASE_BACKOFF: Duration = Duration::from_secs(60);
/// Highest retry delay when the automatic refresh is off (`refresh_interval_hours = 0`).
pub const MANUAL_BACKOFF_CAP: Duration = Duration::from_hours(6);
/// Highest jitter that the schedule adds to the interval.
pub const MAX_JITTER: Duration = Duration::from_mins(10);
/// Highest refresh interval that the schedule accepts (the API allows 1 to 168 hours).
pub const MAX_INTERVAL: Duration = Duration::from_hours(366 * 24);
/// Events that start a fetch from any state, at most: `UpdateNow`, then `Start`.
pub const MAX_STEPS_TO_FETCH: usize = 2;

/// Settings of the refresh policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshPolicy {
    /// Time between two refreshes of one list. `None`: no automatic refresh.
    pub interval: Option<Duration>,
    /// First retry delay after a failed fetch. Each next failure doubles it, up to
    /// [`RefreshPolicy::backoff_cap`].
    pub base_backoff: Duration,
}

impl RefreshPolicy {
    /// The policy for `lists.refresh_interval_hours` of the config. 0 turns the automatic
    /// refresh off.
    pub fn from_hours(hours: u32) -> Self {
        let interval =
            (hours > 0).then(|| Duration::from_hours(u64::from(hours)).min(MAX_INTERVAL));
        Self {
            interval,
            base_backoff: DEFAULT_BASE_BACKOFF,
        }
    }

    /// The highest retry delay: the refresh interval, or [`MANUAL_BACKOFF_CAP`] with no
    /// interval. At least one second.
    pub fn backoff_cap(&self) -> Duration {
        self.interval
            .unwrap_or(MANUAL_BACKOFF_CAP)
            .max(Duration::from_secs(1))
    }

    /// The retry delay after `failures` consecutive failures (at least 1):
    /// `base * 2^(failures - 1)`, at most [`RefreshPolicy::backoff_cap`].
    pub fn backoff(&self, failures: u32) -> Duration {
        let cap = self.backoff_cap();
        let base = self.base_backoff.max(Duration::from_secs(1)).min(cap);
        let shift = failures.saturating_sub(1).min(31);
        base.saturating_mul(1u32 << shift).min(cap)
    }
}

/// A deterministic mix of the list id (`splitmix64`). Pure, the same on each platform.
fn mix(id: u32) -> u64 {
    let mut z = u64::from(id).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The highest jitter for an interval: a tenth of the interval, at most [`MAX_JITTER`].
pub fn max_jitter(interval: Duration) -> Duration {
    (interval / 10).min(MAX_JITTER)
}

/// The jitter of one list, in whole seconds in `0..=max_jitter(interval)`. It depends only
/// on the list id and the interval.
pub fn jitter(list_id: u32, interval: Duration) -> Duration {
    let span = max_jitter(interval).as_secs().saturating_add(1);
    Duration::from_secs(mix(list_id) % span)
}

/// `t + d`, at most the last point of the clock.
fn add(t: MonoTime, d: Duration) -> MonoTime {
    t.checked_add(d)
        .unwrap_or(MonoTime::from_duration(Duration::MAX))
}

/// The next due time of a list after a success at `now`: `now + interval + jitter`.
/// `None` when the automatic refresh is off.
pub fn next_due(policy: &RefreshPolicy, list_id: u32, now: MonoTime) -> Option<MonoTime> {
    let interval = policy.interval?;
    Some(add(add(now, interval), jitter(list_id, interval)))
}

/// The first due time of a list at start.
///
/// - No copy on disk (`last_success_unix` is `None`): due at `now`, also with no automatic
///   refresh, so each list gets a first copy.
/// - A copy and no automatic refresh: no due time.
/// - A copy: due `interval + jitter` after the last success. The wall clock can be wrong
///   after boot (a Pi has no real-time clock), so the wait is in `0..=interval + jitter`: a
///   clock that is behind does not delay the refresh by more than one interval, and a clock
///   that is ahead only makes the list due now.
pub fn initial_due(
    policy: &RefreshPolicy,
    list_id: u32,
    now: MonoTime,
    wall_now_unix: i64,
    last_success_unix: Option<i64>,
) -> Option<MonoTime> {
    let Some(last) = last_success_unix else {
        return Some(now);
    };
    let interval = policy.interval?;
    let full = interval.saturating_add(jitter(list_id, interval));
    let elapsed_secs = wall_now_unix.saturating_sub(last);
    let wait = if elapsed_secs <= 0 {
        full
    } else {
        full.saturating_sub(Duration::from_secs(elapsed_secs.unsigned_abs()))
    };
    Some(add(now, wait))
}

/// The state of the refresh of one list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshState {
    /// Waiting. With `next_due`, the list is due at that time. With `None`, only an
    /// "update now" makes it due.
    Idle { next_due: Option<MonoTime> },
    /// A fetch is needed. The shell starts it when a fetch slot is free.
    Due { since: MonoTime },
    /// A fetch runs. `again`: an "update now" came during the fetch, so the list is due
    /// again when the fetch ends.
    Fetching { started: MonoTime, again: bool },
    /// The last fetch failed. The list is due again at `retry_at`.
    Backoff { retry_at: MonoTime },
}

/// An event for the refresh machine of one list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshEvent {
    /// The time is `now`. A due time at or before `now` makes the list due.
    Tick(MonoTime),
    /// The user asked for an update.
    UpdateNow(MonoTime),
    /// The shell starts a fetch. Valid only in `Due`.
    Start(MonoTime),
    /// The fetch got a new body. Valid only in `Fetching`.
    Updated(MonoTime),
    /// The server said "not modified", or the body did not change. Valid only in `Fetching`.
    NotModified(MonoTime),
    /// The fetch failed. Valid only in `Fetching`.
    Failed(MonoTime),
}

impl RefreshEvent {
    /// The time of the event.
    pub fn now(&self) -> MonoTime {
        match *self {
            Self::Tick(t)
            | Self::UpdateNow(t)
            | Self::Start(t)
            | Self::Updated(t)
            | Self::NotModified(t)
            | Self::Failed(t) => t,
        }
    }
}

/// Why an event is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidRefresh {
    #[error("time went back from {last:?} to {now:?}")]
    TimeWentBack { last: MonoTime, now: MonoTime },
    #[error("the event is not expected in this state")]
    Unexpected,
}

/// The refresh machine of one list: the state, the count of consecutive failures and the
/// last time that an event gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListRefresh {
    list_id: u32,
    state: RefreshState,
    failures: u32,
    last_now: Option<MonoTime>,
}

impl ListRefresh {
    /// A machine in `Idle` with the first due time (see [`initial_due`]).
    pub fn new(list_id: u32, first_due: Option<MonoTime>) -> Self {
        Self {
            list_id,
            state: RefreshState::Idle {
                next_due: first_due,
            },
            failures: 0,
            last_now: None,
        }
    }

    /// The list id.
    pub fn list_id(&self) -> u32 {
        self.list_id
    }

    /// The current state.
    pub fn state(&self) -> RefreshState {
        self.state
    }

    /// Consecutive failed fetches. A success sets it to 0.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// True when the shell must start a fetch.
    pub fn wants_fetch(&self) -> bool {
        matches!(self.state, RefreshState::Due { .. })
    }

    /// True while a fetch runs.
    pub fn is_fetching(&self) -> bool {
        matches!(self.state, RefreshState::Fetching { .. })
    }

    /// The time at which a `Tick` changes the state, if the state waits for a time.
    pub fn wake_at(&self) -> Option<MonoTime> {
        match self.state {
            RefreshState::Idle { next_due } => next_due,
            RefreshState::Backoff { retry_at } => Some(retry_at),
            RefreshState::Due { .. } | RefreshState::Fetching { .. } => None,
        }
    }

    /// Applies one event. An invalid event is logged at ERROR, the machine goes to `Idle`
    /// (the safe state), and the function returns the error.
    pub fn step(
        &mut self,
        policy: &RefreshPolicy,
        event: RefreshEvent,
    ) -> Result<(), InvalidRefresh> {
        let before = *self;
        let (next, result) = transition(policy, *self, event);
        *self = next;
        if let Err(e) = result {
            tracing::error!(
                state = ?before,
                event = ?event,
                next = ?next,
                error = %e,
                "invalid list refresh event; the list goes to idle"
            );
        }
        result
    }

    /// True when the machine obeys its invariants: `Backoff` follows at least one failure,
    /// and no stored start time is later than the last time seen.
    pub fn is_valid(&self) -> bool {
        let not_after_last = |t: MonoTime| self.last_now.is_none_or(|l| t <= l);
        match self.state {
            RefreshState::Idle { .. } => true,
            RefreshState::Due { since } => not_after_last(since),
            RefreshState::Fetching { started, .. } => not_after_last(started),
            RefreshState::Backoff { .. } => self.failures >= 1,
        }
    }
}

/// The pure transition function. It returns the next machine and the result. On an invalid
/// event, the next state is `Idle` with the next scheduled time after the latest time seen.
pub fn transition(
    policy: &RefreshPolicy,
    m: ListRefresh,
    event: RefreshEvent,
) -> (ListRefresh, Result<(), InvalidRefresh>) {
    use RefreshEvent::{Failed, NotModified, Start, Tick, UpdateNow, Updated};
    use RefreshState::{Backoff, Due, Fetching, Idle};

    let now = event.now();
    let latest = m.last_now.map_or(now, |l| l.max(now));
    let safe = |e| {
        (
            ListRefresh {
                state: Idle {
                    next_due: next_due(policy, m.list_id, latest),
                },
                last_now: Some(latest),
                ..m
            },
            Err(e),
        )
    };
    if let Some(last) = m.last_now
        && now < last
    {
        return safe(InvalidRefresh::TimeWentBack { last, now });
    }
    let ok = |state, failures| {
        (
            ListRefresh {
                state,
                failures,
                last_now: Some(now),
                ..m
            },
            Ok(()),
        )
    };
    let f = m.failures;
    match (m.state, event) {
        (Idle { next_due: Some(t) }, Tick(_)) if now >= t => ok(Due { since: now }, f),
        (Backoff { retry_at }, Tick(_)) if now >= retry_at => ok(Due { since: now }, f),
        (state, Tick(_)) => ok(state, f),
        (Idle { .. } | Backoff { .. }, UpdateNow(_)) => ok(Due { since: now }, f),
        (Due { since }, UpdateNow(_)) => ok(Due { since }, f),
        (Fetching { started, .. }, UpdateNow(_)) => ok(
            Fetching {
                started,
                again: true,
            },
            f,
        ),
        (Due { .. }, Start(_)) => ok(
            Fetching {
                started: now,
                again: false,
            },
            f,
        ),
        (Fetching { again, .. }, Updated(_) | NotModified(_)) => {
            let state = if again {
                Due { since: now }
            } else {
                Idle {
                    next_due: next_due(policy, m.list_id, now),
                }
            };
            ok(state, 0)
        }
        (Fetching { again, .. }, Failed(_)) => {
            let failures = f.saturating_add(1);
            let state = if again {
                Due { since: now }
            } else {
                Backoff {
                    retry_at: add(now, policy.backoff(failures)),
                }
            };
            ok(state, failures)
        }
        (_, Start(_) | Updated(_) | NotModified(_) | Failed(_)) => safe(InvalidRefresh::Unexpected),
    }
}

/// The rank function of the step bound: the number of events that start a fetch from
/// `state` (`UpdateNow` if needed, then `Start`). Each of these events lowers the rank by
/// one, and the rank is at most [`MAX_STEPS_TO_FETCH`].
pub fn steps_to_fetch(state: RefreshState) -> usize {
    match state {
        RefreshState::Idle { .. } | RefreshState::Backoff { .. } => 2,
        RefreshState::Due { .. } => 1,
        RefreshState::Fetching { .. } => 0,
    }
}

/// The event that moves `state` one step closer to a fetch, or `None` in `Fetching`.
pub fn next_fetch_event(state: RefreshState, now: MonoTime) -> Option<RefreshEvent> {
    match state {
        RefreshState::Idle { .. } | RefreshState::Backoff { .. } => {
            Some(RefreshEvent::UpdateNow(now))
        }
        RefreshState::Due { .. } => Some(RefreshEvent::Start(now)),
        RefreshState::Fetching { .. } => None,
    }
}

/// Drives the machine to `Fetching` with at most [`MAX_STEPS_TO_FETCH`] events at `now`
/// (or at the last time seen, when that is later). Returns the number of events. Reaching
/// the bound without a fetch logs an ERROR and returns `None` (it cannot happen; a test
/// proves it).
pub fn drive_to_fetch(policy: &RefreshPolicy, m: &mut ListRefresh, now: MonoTime) -> Option<usize> {
    let now = m.last_now.map_or(now, |l| l.max(now));
    for steps in 0..=MAX_STEPS_TO_FETCH {
        let Some(event) = next_fetch_event(m.state(), now) else {
            return Some(steps);
        };
        if steps == MAX_STEPS_TO_FETCH {
            break;
        }
        // An invalid event logs at ERROR inside `step`.
        let _ = m.step(policy, event);
    }
    tracing::error!(machine = ?m, "list refresh did not reach a fetch within the step bound");
    None
}
