//! Blocking toggle with a timer (amendment A9).
//!
//! A pure state machine. It reads no clock: each event that needs the time carries `now`, a
//! [`MonoTime`] from the monotonic clock of the shell.
//!
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Enabled
//!     Enabled --> Disabled: Disable(for)
//!     Disabled --> Disabled: Disable(for) (new timer)
//!     Disabled --> Enabled: Enable
//!     Disabled --> Enabled: Tick(now >= until)
//!     Enabled --> Enabled: Enable, Tick
//!     Disabled --> Enabled: invalid event (logged at ERROR)
//!     Enabled --> Enabled: invalid event (logged at ERROR)
//! ```
//!
//! An invalid event (time that goes back, a zero or too long duration, a deadline that
//! overflows) is logged at ERROR with the full state and event. The machine then goes to
//! `Enabled`, the safe state: blocking is on.
//!
//! The machine has no loop. Each event is one transition. A timer needs at most one `Tick`
//! at or after its deadline to end, and [`BlockingToggle::is_blocking`] is correct with no
//! `Tick` at all.

use std::time::Duration;

/// A point on a monotonic clock, as the time since an origin that the shell selects
/// (for example the start of the process).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MonoTime(Duration);

impl MonoTime {
    /// The origin.
    pub const ZERO: Self = Self(Duration::ZERO);

    /// The point `since_origin` after the origin.
    pub const fn from_duration(since_origin: Duration) -> Self {
        Self(since_origin)
    }

    /// The time since the origin.
    pub const fn as_duration(self) -> Duration {
        self.0
    }

    /// `self + d`, or `None` on overflow.
    pub fn checked_add(self, d: Duration) -> Option<Self> {
        self.0.checked_add(d).map(Self)
    }

    /// `self - earlier`, or zero when `earlier` is later.
    pub fn saturating_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

/// Longest allowed timed disable. For a longer time, disable with no timer.
pub const MAX_DISABLE: Duration = Duration::from_hours(366 * 24);

/// The state of the toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToggleState {
    /// Blocking is on.
    Enabled,
    /// Blocking is off. With `until`, blocking comes on again at that time.
    Disabled { until: Option<MonoTime> },
}

/// An event for the toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToggleEvent {
    /// Turn blocking off. With a duration, only for that time. A new `Disable` replaces the
    /// timer.
    Disable {
        duration: Option<Duration>,
        now: MonoTime,
    },
    /// Turn blocking on. A second `Enable` changes nothing.
    Enable,
    /// The time is `now`. A timer that ends at or before `now` ends.
    Tick(MonoTime),
}

/// Why an event is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidEvent {
    #[error("time went back from {last:?} to {now:?}")]
    TimeWentBack { last: MonoTime, now: MonoTime },
    #[error("the disable duration is zero")]
    ZeroDuration,
    #[error("the disable duration is longer than the maximum")]
    DurationTooLong,
    #[error("the deadline overflows the clock")]
    DeadlineOverflow,
}

/// The blocking toggle: the state and the last time that an event gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockingToggle {
    state: ToggleState,
    last_now: Option<MonoTime>,
}

impl Default for BlockingToggle {
    fn default() -> Self {
        Self::new(true)
    }
}

impl BlockingToggle {
    /// A new toggle. Use `blocking.enabled` of the config: `false` gives a disable with no
    /// timer.
    pub fn new(enabled: bool) -> Self {
        Self {
            state: if enabled {
                ToggleState::Enabled
            } else {
                ToggleState::Disabled { until: None }
            },
            last_now: None,
        }
    }

    /// The current state.
    pub fn state(&self) -> ToggleState {
        self.state
    }

    /// Applies one event. An invalid event is logged at ERROR, the toggle goes to `Enabled`,
    /// and the function returns the error.
    pub fn step(&mut self, event: ToggleEvent) -> Result<(), InvalidEvent> {
        let before = *self;
        let (next, result) = transition(*self, event);
        *self = next;
        if let Err(e) = result {
            tracing::error!(
                state = ?before,
                event = ?event,
                error = %e,
                "invalid blocking toggle event; blocking is on again"
            );
        }
        result
    }

    /// True when blocking is on at `now`. A timer that ends at or before `now` counts as
    /// ended, also with no `Tick`.
    pub fn is_blocking(&self, now: MonoTime) -> bool {
        match self.state {
            ToggleState::Enabled => true,
            ToggleState::Disabled { until: None } => false,
            ToggleState::Disabled { until: Some(t) } => now >= t,
        }
    }

    /// The time until blocking comes on again, when a timer runs at `now`.
    pub fn remaining(&self, now: MonoTime) -> Option<Duration> {
        match self.state {
            ToggleState::Disabled { until: Some(t) } if now < t => Some(t.saturating_since(now)),
            _ => None,
        }
    }

    /// True when the state obeys the invariant: a timer ends after the last time seen.
    pub fn is_valid(&self) -> bool {
        match self.state {
            ToggleState::Enabled | ToggleState::Disabled { until: None } => true,
            ToggleState::Disabled { until: Some(t) } => self.last_now.is_some_and(|l| l < t),
        }
    }
}

/// The pure transition function. It returns the next toggle and the result. On an invalid
/// event, the next state is `Enabled` (the safe state) and the last time does not change.
pub fn transition(
    toggle: BlockingToggle,
    event: ToggleEvent,
) -> (BlockingToggle, Result<(), InvalidEvent>) {
    let safe = |e| {
        (
            BlockingToggle {
                state: ToggleState::Enabled,
                last_now: toggle.last_now,
            },
            Err(e),
        )
    };
    let now = match event {
        ToggleEvent::Disable { now, .. } | ToggleEvent::Tick(now) => Some(now),
        ToggleEvent::Enable => None,
    };
    if let (Some(now), Some(last)) = (now, toggle.last_now)
        && now < last
    {
        return safe(InvalidEvent::TimeWentBack { last, now });
    }
    let last_now = now.or(toggle.last_now);
    let state = match (toggle.state, event) {
        (_, ToggleEvent::Enable) => ToggleState::Enabled,
        (_, ToggleEvent::Disable { duration: None, .. }) => ToggleState::Disabled { until: None },
        (
            _,
            ToggleEvent::Disable {
                duration: Some(d),
                now,
            },
        ) => {
            if d.is_zero() {
                return safe(InvalidEvent::ZeroDuration);
            }
            if d > MAX_DISABLE {
                return safe(InvalidEvent::DurationTooLong);
            }
            match now.checked_add(d) {
                Some(until) => ToggleState::Disabled { until: Some(until) },
                None => return safe(InvalidEvent::DeadlineOverflow),
            }
        }
        (ToggleState::Disabled { until: Some(t) }, ToggleEvent::Tick(now)) if now >= t => {
            ToggleState::Enabled
        }
        (state, ToggleEvent::Tick(_)) => state,
    };
    (BlockingToggle { state, last_now }, Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn t(ms: u64) -> MonoTime {
        MonoTime::from_duration(Duration::from_millis(ms))
    }

    #[test]
    fn timer_ends_exactly_at_deadline() {
        let mut b = BlockingToggle::new(true);
        assert!(b.is_blocking(t(0)));
        b.step(ToggleEvent::Disable {
            duration: Some(Duration::from_secs(5)),
            now: t(1000),
        })
        .unwrap();
        assert!(!b.is_blocking(t(5999)));
        assert_eq!(b.remaining(t(5999)), Some(Duration::from_millis(1)));
        assert!(b.is_blocking(t(6000)));
        assert_eq!(b.remaining(t(6000)), None);
        b.step(ToggleEvent::Tick(t(5999))).unwrap();
        assert_eq!(
            b.state(),
            ToggleState::Disabled {
                until: Some(t(6000))
            }
        );
        b.step(ToggleEvent::Tick(t(6000))).unwrap();
        assert_eq!(b.state(), ToggleState::Enabled);
    }

    #[test]
    fn disable_without_timer_and_enable() {
        let mut b = BlockingToggle::new(false);
        assert!(!b.is_blocking(t(10)));
        assert_eq!(b.remaining(t(10)), None);
        b.step(ToggleEvent::Tick(t(1_000_000))).unwrap();
        assert!(!b.is_blocking(t(1_000_000)));
        b.step(ToggleEvent::Enable).unwrap();
        b.step(ToggleEvent::Enable).unwrap();
        assert_eq!(b.state(), ToggleState::Enabled);
        assert_eq!(BlockingToggle::default(), BlockingToggle::new(true));
    }

    #[test]
    fn new_disable_replaces_timer() {
        let mut b = BlockingToggle::new(true);
        b.step(ToggleEvent::Disable {
            duration: Some(Duration::from_secs(60)),
            now: t(0),
        })
        .unwrap();
        b.step(ToggleEvent::Disable {
            duration: Some(Duration::from_secs(1)),
            now: t(10),
        })
        .unwrap();
        assert!(b.is_blocking(t(1010)));
        b.step(ToggleEvent::Disable {
            duration: None,
            now: t(20),
        })
        .unwrap();
        assert!(!b.is_blocking(t(10_000_000)));
    }

    #[test]
    fn invalid_events_go_to_enabled() {
        let disabled = |now| {
            let mut b = BlockingToggle::new(true);
            b.step(ToggleEvent::Disable {
                duration: None,
                now,
            })
            .unwrap();
            b
        };
        let mut b = disabled(t(100));
        assert_eq!(
            b.step(ToggleEvent::Tick(t(99))),
            Err(InvalidEvent::TimeWentBack {
                last: t(100),
                now: t(99)
            })
        );
        assert_eq!(b.state(), ToggleState::Enabled);

        let mut b = disabled(t(100));
        assert_eq!(
            b.step(ToggleEvent::Disable {
                duration: Some(Duration::ZERO),
                now: t(200)
            }),
            Err(InvalidEvent::ZeroDuration)
        );
        assert_eq!(b.state(), ToggleState::Enabled);

        let mut b = disabled(t(100));
        assert_eq!(
            b.step(ToggleEvent::Disable {
                duration: Some(MAX_DISABLE + Duration::from_nanos(1)),
                now: t(200)
            }),
            Err(InvalidEvent::DurationTooLong)
        );
        assert_eq!(b.state(), ToggleState::Enabled);

        let mut b = BlockingToggle::new(true);
        assert_eq!(
            b.step(ToggleEvent::Disable {
                duration: Some(Duration::from_secs(1)),
                now: MonoTime::from_duration(Duration::MAX)
            }),
            Err(InvalidEvent::DeadlineOverflow)
        );
        assert_eq!(b.state(), ToggleState::Enabled);
    }

    #[test]
    fn mono_time_helpers() {
        assert_eq!(MonoTime::ZERO.as_duration(), Duration::ZERO);
        assert_eq!(t(5).saturating_since(t(7)), Duration::ZERO);
        assert_eq!(t(7).saturating_since(t(5)), Duration::from_millis(2));
    }

    fn event() -> impl Strategy<Value = ToggleEvent> {
        prop_oneof![
            (proptest::option::of(0u64..5000), 0u64..10_000).prop_map(|(d, now)| {
                ToggleEvent::Disable {
                    duration: d.map(Duration::from_millis),
                    now: t(now),
                }
            }),
            Just(ToggleEvent::Enable),
            (0u64..10_000).prop_map(|now| ToggleEvent::Tick(t(now))),
        ]
    }

    proptest! {
        /// Any event sequence keeps a valid state. Each event is exactly one transition, so a
        /// run of N events takes N steps (the bound). An invalid event leaves `Enabled`.
        #[test]
        fn any_sequence_keeps_valid_state(events in prop::collection::vec(event(), 0..64)) {
            let mut b = BlockingToggle::new(true);
            let mut steps = 0usize;
            for e in &events {
                let r = b.step(*e);
                steps += 1;
                prop_assert!(b.is_valid(), "state {:?} after {:?}", b, e);
                if r.is_err() {
                    prop_assert_eq!(b.state(), ToggleState::Enabled);
                }
            }
            prop_assert_eq!(steps, events.len());
        }

        /// A timer ends exactly at its deadline: one nanosecond before, blocking is off; at
        /// the deadline, blocking is on, and one Tick at the deadline gives Enabled.
        #[test]
        fn timer_expires_exactly(start in 0u64..1_000_000, ms in 1u64..1_000_000) {
            let mut b = BlockingToggle::new(true);
            let now = t(start);
            let d = Duration::from_millis(ms);
            b.step(ToggleEvent::Disable { duration: Some(d), now }).unwrap();
            let deadline = now.checked_add(d).unwrap();
            let before = MonoTime::from_duration(deadline.as_duration().checked_sub(Duration::from_nanos(1)).unwrap());
            prop_assert!(!b.is_blocking(before));
            prop_assert_eq!(b.remaining(before), Some(Duration::from_nanos(1)));
            prop_assert!(b.is_blocking(deadline));
            b.step(ToggleEvent::Tick(before)).unwrap();
            prop_assert!(!b.is_blocking(before));
            b.step(ToggleEvent::Tick(deadline)).unwrap();
            prop_assert_eq!(b.state(), ToggleState::Enabled);
        }

        /// `is_blocking` does not depend on Ticks: with or without the Ticks, the answer at
        /// each time is the same.
        #[test]
        fn ticks_do_not_change_answer(events in prop::collection::vec(event(), 0..32), probe in 0u64..20_000) {
            let mut with = BlockingToggle::new(true);
            let mut without = BlockingToggle::new(true);
            let mut last = 0;
            for e in &events {
                if with.step(*e).is_err() {
                    // An invalid event resets `with` only; the comparison ends here.
                    return Ok(());
                }
                if !matches!(e, ToggleEvent::Tick(_)) {
                    // `without` saw fewer times, so an event valid for `with` is valid here.
                    prop_assert!(without.step(*e).is_ok());
                }
                if let ToggleEvent::Disable { now, .. } | ToggleEvent::Tick(now) = e {
                    last = last.max(now.as_duration().as_millis());
                }
            }
            let probe = t(probe.max(u64::try_from(last).unwrap()));
            prop_assert_eq!(with.is_blocking(probe), without.is_blocking(probe));
        }
    }
}
