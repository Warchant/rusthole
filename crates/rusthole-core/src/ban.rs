//! The login ban state machine (decision D10, amendment A7). Pure: `now` is an input.
//!
//! Each client address has an entry. Failed password, TOTP and API-token checks count.
//! After `threshold` failures the address is locked. Each new lock is twice as long as the
//! one before, up to `max_lockout`. A success, or a quiet time with no failure, removes the
//! entry. The table has a size limit (LRU).
//!
//! An attempt has two steps: [`BanTable::begin`] before the check, and
//! [`BanTable::finish`] after it. `begin` reserves the attempt (`pending`), so parallel
//! attempts cannot pass the threshold: `failures + pending` never goes above it.
//!
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Open: begin (new address)
//!     Open --> Open: begin / cancel / failure below the threshold
//!     Open --> Locked: failure at the threshold
//!     Locked --> Open: begin after the lock time
//!     Open --> [*]: success, or quiet time
//!     Open --> Locked: invalid event (ERROR, safe state)
//!     Locked --> Locked: invalid event (ERROR, safe state)
//! ```
//!
//! An invalid event (a `finish` with no reserved attempt) is logged at ERROR with the full
//! state and event. Then the entry goes to the safe state: locked.

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::time::Duration;

use lru::LruCache;

use crate::blocking_state::MonoTime;

/// The rules of the ban.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanPolicy {
    /// Failures before a lock. At least 1.
    pub threshold: u32,
    /// The first lock time. Each next lock is twice as long.
    pub base_lockout: Duration,
    /// The longest lock time.
    pub max_lockout: Duration,
    /// After this time with no failure (and no lock), the entry is removed. It must be at
    /// least `base_lockout`, so that the attempt bound holds.
    pub quiet: Duration,
    /// The largest number of entries. The least recently used entry goes out first.
    pub max_entries: usize,
}

impl Default for BanPolicy {
    fn default() -> Self {
        Self {
            threshold: 5,
            base_lockout: Duration::from_secs(60),
            max_lockout: Duration::from_secs(3600),
            quiet: Duration::from_mins(15),
            max_entries: 4096,
        }
    }
}

impl BanPolicy {
    /// The lock time for lock number `level` (0 is the first lock).
    pub fn lockout(&self, level: u32) -> Duration {
        let factor = 1u32.checked_shl(level.min(31)).unwrap_or(u32::MAX);
        self.base_lockout
            .checked_mul(factor)
            .unwrap_or(self.max_lockout)
            .min(self.max_lockout)
    }

    fn threshold(&self) -> u32 {
        self.threshold.max(1)
    }
}

/// The state of one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Attempts can start.
    Open {
        /// Failures since the last lock, success or quiet time.
        failures: u32,
        /// Attempts that started and did not finish.
        pending: u32,
        /// The number of locks before (the next lock time doubles with each).
        level: u32,
        /// The time of the last event.
        last_event: MonoTime,
    },
    /// No attempt can start until `until`.
    Locked {
        /// The end of the lock.
        until: MonoTime,
        /// The number of locks, including this one.
        level: u32,
        /// Attempts that started before the lock and did not finish.
        pending: u32,
    },
}

/// An event for one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanEvent {
    /// An attempt wants to start.
    Begin,
    /// The attempt failed (a wrong password, TOTP code or token, or an attempt that stopped
    /// before its end).
    Failure,
    /// The attempt worked.
    Success,
    /// The attempt ended with no check (for example `totp_required`). It does not count.
    Cancel,
}

/// What a transition gives to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanOutcome {
    /// `Begin`: the attempt can run.
    Allowed,
    /// `Begin`: the address is locked, or the parallel attempts use all tries. Try again
    /// after `retry_after`.
    Banned {
        /// The wait time.
        retry_after: Duration,
    },
    /// `Failure`: the failure counted. `locked` is the new lock time when this failure
    /// locked the address.
    Counted {
        /// The new lock time, if any.
        locked: Option<Duration>,
    },
    /// `Success` or `Cancel`: done.
    Done,
    /// `Success` while the address is locked (other attempts failed in parallel). The
    /// caller must refuse the login.
    Rejected {
        /// The wait time.
        retry_after: Duration,
    },
    /// The event was not valid in the state. It was logged at ERROR, and the address is
    /// locked now.
    Invalid {
        /// The wait time.
        retry_after: Duration,
    },
}

/// The time left until `until`, at least one second (a `Retry-After` of 0 makes no sense).
fn wait(until: MonoTime, now: MonoTime) -> Duration {
    until.saturating_since(now).max(Duration::from_secs(1))
}

/// The safe state after an invalid event: locked for the next lock time.
fn safe_state(policy: &BanPolicy, level: u32, pending: u32, now: MonoTime) -> EntryState {
    let until = now
        .checked_add(policy.lockout(level))
        .unwrap_or(MonoTime::from_duration(Duration::MAX));
    EntryState::Locked {
        until,
        level: level.saturating_add(1),
        pending,
    }
}

/// The transition function. `None` is "no entry" (a clean address).
///
/// Returns the next state (`None` removes the entry) and the outcome.
// One match arm for each (state, event) pair: the table reads best in one place.
#[allow(clippy::too_many_lines)]
pub fn transition(
    policy: &BanPolicy,
    state: Option<EntryState>,
    event: BanEvent,
    now: MonoTime,
) -> (Option<EntryState>, BanOutcome) {
    let invalid = |level: u32, pending: u32| {
        tracing::error!(
            ?state,
            ?event,
            ?now,
            "invalid ban event; the address is locked"
        );
        let next = safe_state(policy, level, pending, now);
        let retry_after = match next {
            EntryState::Locked { until, .. } => wait(until, now),
            EntryState::Open { .. } => Duration::from_secs(1),
        };
        (Some(next), BanOutcome::Invalid { retry_after })
    };
    // A quiet entry is forgotten before the event (decay).
    let state = match state {
        Some(EntryState::Open {
            pending: 0,
            last_event,
            ..
        }) if now.saturating_since(last_event) >= policy.quiet => None,
        Some(EntryState::Locked {
            until, pending: 0, ..
        }) if now >= until && now.saturating_since(until) >= policy.quiet => None,
        other => other,
    };
    match (state, event) {
        (None, BanEvent::Begin) => (
            Some(EntryState::Open {
                failures: 0,
                pending: 1,
                level: 0,
                last_event: now,
            }),
            BanOutcome::Allowed,
        ),
        (None, BanEvent::Failure | BanEvent::Success | BanEvent::Cancel) => invalid(0, 0),
        (
            Some(EntryState::Open {
                failures,
                pending,
                level,
                last_event,
            }),
            BanEvent::Begin,
        ) => {
            if failures.saturating_add(pending) >= policy.threshold() {
                // The parallel attempts use all tries. Wait a little for them to end.
                (
                    state,
                    BanOutcome::Banned {
                        retry_after: Duration::from_secs(1),
                    },
                )
            } else {
                (
                    Some(EntryState::Open {
                        failures,
                        pending: pending + 1,
                        level,
                        last_event: last_event.max(now),
                    }),
                    BanOutcome::Allowed,
                )
            }
        }
        (
            Some(EntryState::Open {
                level, pending: 0, ..
            }),
            _,
        ) => invalid(level, 0),
        (
            Some(EntryState::Open {
                failures,
                pending,
                level,
                last_event,
            }),
            BanEvent::Failure,
        ) => {
            let failures = failures.saturating_add(1);
            let pending = pending - 1;
            if failures >= policy.threshold() {
                let lock = policy.lockout(level);
                let until = now
                    .checked_add(lock)
                    .unwrap_or(MonoTime::from_duration(Duration::MAX));
                (
                    Some(EntryState::Locked {
                        until,
                        level: level.saturating_add(1),
                        pending,
                    }),
                    BanOutcome::Counted { locked: Some(lock) },
                )
            } else {
                (
                    Some(EntryState::Open {
                        failures,
                        pending,
                        level,
                        last_event: last_event.max(now),
                    }),
                    BanOutcome::Counted { locked: None },
                )
            }
        }
        (Some(EntryState::Open { pending, .. }), BanEvent::Success) => {
            let pending = pending - 1;
            let next = (pending > 0).then_some(EntryState::Open {
                failures: 0,
                pending,
                level: 0,
                last_event: now,
            });
            (next, BanOutcome::Done)
        }
        (
            Some(EntryState::Open {
                failures,
                pending,
                level,
                last_event,
            }),
            BanEvent::Cancel,
        ) => (
            Some(EntryState::Open {
                failures,
                pending: pending - 1,
                level,
                last_event,
            }),
            BanOutcome::Done,
        ),
        (
            Some(EntryState::Locked {
                until,
                level,
                pending,
            }),
            BanEvent::Begin,
        ) => {
            if now >= until {
                (
                    Some(EntryState::Open {
                        failures: 0,
                        pending: pending.saturating_add(1),
                        level,
                        last_event: now,
                    }),
                    BanOutcome::Allowed,
                )
            } else {
                (
                    state,
                    BanOutcome::Banned {
                        retry_after: wait(until, now),
                    },
                )
            }
        }
        (
            Some(EntryState::Locked {
                level, pending: 0, ..
            }),
            _,
        ) => invalid(level, 0),
        (
            Some(EntryState::Locked {
                until,
                level,
                pending,
            }),
            BanEvent::Failure | BanEvent::Cancel,
        ) => (
            Some(EntryState::Locked {
                until,
                level,
                pending: pending - 1,
            }),
            if event == BanEvent::Failure {
                BanOutcome::Counted { locked: None }
            } else {
                BanOutcome::Done
            },
        ),
        (
            Some(EntryState::Locked {
                until,
                level,
                pending,
            }),
            BanEvent::Success,
        ) => (
            Some(EntryState::Locked {
                until,
                level,
                pending: pending - 1,
            }),
            BanOutcome::Rejected {
                retry_after: wait(until, now),
            },
        ),
    }
}

/// The ban key of an address: an IPv4 address as it is; an IPv6 address by its /64
/// network (decision D10; v1 uses IPv4 only, amendment A11).
pub fn ban_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                let [a, b, c, d, ..] = v6.segments();
                IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
            }
        }
    }
}

/// The ban entries of all addresses, with a size limit.
#[derive(Debug)]
pub struct BanTable {
    policy: BanPolicy,
    map: LruCache<IpAddr, EntryState>,
}

impl BanTable {
    /// An empty table.
    pub fn new(policy: BanPolicy) -> Self {
        let cap = NonZeroUsize::new(policy.max_entries.max(1)).unwrap_or(NonZeroUsize::MIN);
        Self {
            policy,
            map: LruCache::new(cap),
        }
    }

    /// The policy.
    pub fn policy(&self) -> &BanPolicy {
        &self.policy
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True with no entry.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The state of an address (no LRU update).
    pub fn state(&self, ip: IpAddr) -> Option<EntryState> {
        self.map.peek(&ban_key(ip)).copied()
    }

    /// Applies `event` for `ip` at `now`.
    pub fn step(&mut self, ip: IpAddr, event: BanEvent, now: MonoTime) -> BanOutcome {
        let key = ban_key(ip);
        let state = self.map.get(&key).copied();
        let (next, outcome) = transition(&self.policy, state, event, now);
        match next {
            Some(s) => {
                self.map.put(key, s);
            }
            None => {
                self.map.pop(&key);
            }
        }
        outcome
    }

    /// Starts an attempt. See [`BanEvent::Begin`].
    pub fn begin(&mut self, ip: IpAddr, now: MonoTime) -> BanOutcome {
        self.step(ip, BanEvent::Begin, now)
    }

    /// Removes the entries that are quiet or whose lock ended long ago. The loop has one
    /// step for each entry, so it is bounded by `max_entries`. Returns the number removed.
    pub fn purge(&mut self, now: MonoTime) -> usize {
        let quiet = self.policy.quiet;
        let old: Vec<IpAddr> = self
            .map
            .iter()
            .filter(|(_, s)| match s {
                EntryState::Open {
                    pending: 0,
                    last_event,
                    ..
                } => now.saturating_since(*last_event) >= quiet,
                EntryState::Locked {
                    until, pending: 0, ..
                } => now >= *until && now.saturating_since(*until) >= quiet,
                _ => false,
            })
            .map(|(k, _)| *k)
            .collect();
        for k in &old {
            self.map.pop(k);
        }
        old.len()
    }
}

#[cfg(test)]
mod tests;
