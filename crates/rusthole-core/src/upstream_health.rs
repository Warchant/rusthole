//! Upstream health state machine and upstream choice (amendment A5).
//!
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Healthy
//!     Healthy --> Suspect: Failure
//!     Suspect --> Healthy: Success
//!     Suspect --> Suspect: Failure (count < down_after)
//!     Suspect --> Down: Failure (count = down_after)
//!     Down --> Probing: ProbeStart (probe is due)
//!     Down --> Healthy: Success
//!     Probing --> Healthy: Success
//!     Probing --> Down: Failure (backoff x 2, capped)
//! ```
//!
//! Only a timeout or an I/O error is a `Failure`. A SERVFAIL answer is not: a validating
//! upstream answers SERVFAIL for a bogus domain, so one client could mark every upstream
//! down. A SERVFAIL only makes the query go to the next upstream.
//!
//! `Success` and `Failure` are valid in each state, because parallel queries can report late.
//! `ProbeStart` is valid only in `Down` when the probe is due. An invalid event gives an
//! [`InvalidTransition`] (the caller logs it at ERROR) and the machine goes to the safe state:
//! `Down` with the base backoff. A `Down` upstream is still used as the last choice, so the
//! safe state never stops DNS.
//!
//! The machine takes exactly one step for each event, so it has no loop. This module is
//! pure: each event carries `now_ms`, a monotonic time in milliseconds.

/// Settings of the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthConfig {
    /// Consecutive failures that make an upstream `Down`. At least 1.
    pub down_after: u32,
    /// First probe delay after the upstream goes `Down`, in milliseconds.
    pub base_backoff_ms: u64,
    /// Highest probe delay, in milliseconds.
    pub max_backoff_ms: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            down_after: 3,
            base_backoff_ms: 1_000,
            max_backoff_ms: 300_000,
        }
    }
}

impl HealthConfig {
    fn base(&self) -> u64 {
        self.base_backoff_ms.max(1).min(self.max())
    }

    fn max(&self) -> u64 {
        self.max_backoff_ms.max(1)
    }

    fn down(&self, backoff_ms: u64, now_ms: u64) -> HealthState {
        let backoff_ms = backoff_ms.clamp(self.base(), self.max());
        HealthState::Down {
            backoff_ms,
            next_probe_ms: now_ms.saturating_add(backoff_ms),
        }
    }
}

/// The health of one upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HealthState {
    /// The last query worked.
    #[default]
    Healthy,
    /// `failures` consecutive queries failed (`1..down_after`).
    Suspect {
        /// Consecutive failures.
        failures: u32,
    },
    /// The upstream failed `down_after` times. A probe is due at `next_probe_ms`.
    Down {
        /// The current probe delay.
        backoff_ms: u64,
        /// When the next probe is due.
        next_probe_ms: u64,
    },
    /// A probe query is in flight.
    Probing {
        /// The probe delay that was used. A failed probe doubles it.
        backoff_ms: u64,
        /// When the probe started.
        started_ms: u64,
    },
}

/// An input to the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthEvent {
    /// A query got a valid answer (any response code).
    Success {
        /// The time of the event.
        now_ms: u64,
    },
    /// A query timed out or had an I/O error.
    Failure {
        /// The time of the event.
        now_ms: u64,
    },
    /// The caller starts a probe query. Valid only when [`probe_due`] is true.
    ProbeStart {
        /// The time of the event.
        now_ms: u64,
    },
}

/// An event that the state does not expect. The caller logs it at ERROR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTransition {
    /// The state before the event.
    pub state: HealthState,
    /// The event.
    pub event: HealthEvent,
}

/// The result of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    /// The next state.
    pub state: HealthState,
    /// Set when the event was not valid in the old state.
    pub invalid: Option<InvalidTransition>,
}

/// Applies `event` to `state`.
pub fn step(cfg: &HealthConfig, state: HealthState, event: HealthEvent) -> Step {
    use HealthEvent::{Failure, ProbeStart, Success};
    use HealthState::{Down, Healthy, Probing, Suspect};
    let ok = |s| Step {
        state: s,
        invalid: None,
    };
    let down_after = cfg.down_after.max(1);
    match (state, event) {
        (_, Success { .. }) => ok(Healthy),
        (Healthy, Failure { now_ms }) => {
            if down_after <= 1 {
                ok(cfg.down(cfg.base(), now_ms))
            } else {
                ok(Suspect { failures: 1 })
            }
        }
        (Suspect { failures }, Failure { now_ms }) => {
            let failures = failures.saturating_add(1);
            if failures >= down_after {
                ok(cfg.down(cfg.base(), now_ms))
            } else {
                ok(Suspect { failures })
            }
        }
        // A late failure of a last-choice query: the upstream stays down.
        (Down { .. }, Failure { .. }) => ok(state),
        (Probing { backoff_ms, .. }, Failure { now_ms }) => {
            ok(cfg.down(backoff_ms.saturating_mul(2), now_ms))
        }
        (
            Down {
                backoff_ms,
                next_probe_ms,
            },
            ProbeStart { now_ms },
        ) if now_ms >= next_probe_ms => ok(Probing {
            backoff_ms,
            started_ms: now_ms,
        }),
        (Healthy | Suspect { .. } | Down { .. } | Probing { .. }, ProbeStart { now_ms }) => Step {
            state: cfg.down(cfg.base(), now_ms),
            invalid: Some(InvalidTransition { state, event }),
        },
    }
}

/// True when the state is `Down` and its probe is due at `now_ms`.
pub fn probe_due(state: &HealthState, now_ms: u64) -> bool {
    matches!(state, HealthState::Down { next_probe_ms, .. } if now_ms >= *next_probe_ms)
}

/// True when the state obeys the limits of `cfg`. Each state that [`step`] returns is valid.
pub fn is_valid(cfg: &HealthConfig, state: &HealthState) -> bool {
    match *state {
        HealthState::Healthy => true,
        HealthState::Suspect { failures } => failures >= 1 && failures < cfg.down_after.max(1),
        HealthState::Down { backoff_ms, .. } | HealthState::Probing { backoff_ms, .. } => {
            backoff_ms >= cfg.base() && backoff_ms <= cfg.max()
        }
    }
}

/// The rank of a state for the upstream choice: lower is better.
fn rank(state: &HealthState) -> u8 {
    match state {
        HealthState::Healthy => 0,
        HealthState::Suspect { .. } => 1,
        HealthState::Probing { .. } => 2,
        HealthState::Down { .. } => 3,
    }
}

/// The order in which to try the upstreams: by health, then by config order. The list has
/// at most `max_attempts` entries.
///
/// The list is never empty when `states` is not empty and `max_attempts > 0`: when all
/// upstreams are down, rusthole still tries them, so DNS does not stop.
pub fn plan(states: &[HealthState], max_attempts: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..states.len()).collect();
    // A stable sort keeps the config order inside each rank.
    order.sort_by_key(|&i| states.get(i).map_or(u8::MAX, rank));
    order.truncate(max_attempts);
    order
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const CFG: HealthConfig = HealthConfig {
        down_after: 3,
        base_backoff_ms: 1_000,
        max_backoff_ms: 8_000,
    };

    fn run(state: HealthState, event: HealthEvent) -> HealthState {
        let s = step(&CFG, state, event);
        assert!(s.invalid.is_none(), "{state:?} {event:?}");
        s.state
    }

    #[test]
    fn healthy_to_down_and_back() {
        let mut s = HealthState::Healthy;
        s = run(s, HealthEvent::Failure { now_ms: 0 });
        assert_eq!(s, HealthState::Suspect { failures: 1 });
        s = run(s, HealthEvent::Failure { now_ms: 1 });
        assert_eq!(s, HealthState::Suspect { failures: 2 });
        s = run(s, HealthEvent::Failure { now_ms: 2 });
        assert_eq!(
            s,
            HealthState::Down {
                backoff_ms: 1_000,
                next_probe_ms: 1_002
            }
        );
        assert!(!probe_due(&s, 1_001));
        assert!(probe_due(&s, 1_002));
        s = run(s, HealthEvent::ProbeStart { now_ms: 1_002 });
        assert_eq!(
            s,
            HealthState::Probing {
                backoff_ms: 1_000,
                started_ms: 1_002
            }
        );
        s = run(s, HealthEvent::Success { now_ms: 1_050 });
        assert_eq!(s, HealthState::Healthy);
    }

    #[test]
    fn suspect_recovers_on_success() {
        let s = run(
            HealthState::Suspect { failures: 2 },
            HealthEvent::Success { now_ms: 5 },
        );
        assert_eq!(s, HealthState::Healthy);
    }

    #[test]
    fn failed_probes_double_backoff_up_to_max() {
        let mut s = HealthState::Down {
            backoff_ms: 1_000,
            next_probe_ms: 0,
        };
        let mut now = 0;
        let mut seen = Vec::new();
        for _ in 0..6 {
            s = run(s, HealthEvent::ProbeStart { now_ms: now });
            now += 10;
            s = run(s, HealthEvent::Failure { now_ms: now });
            let HealthState::Down {
                backoff_ms,
                next_probe_ms,
            } = s
            else {
                panic!("{s:?}");
            };
            assert_eq!(next_probe_ms, now + backoff_ms);
            seen.push(backoff_ms);
            now = next_probe_ms;
        }
        assert_eq!(seen, vec![2_000, 4_000, 8_000, 8_000, 8_000, 8_000]);
    }

    #[test]
    fn late_events_are_valid() {
        let down = HealthState::Down {
            backoff_ms: 1_000,
            next_probe_ms: 50,
        };
        assert_eq!(run(down, HealthEvent::Failure { now_ms: 10 }), down);
        assert_eq!(
            run(down, HealthEvent::Success { now_ms: 10 }),
            HealthState::Healthy
        );
    }

    #[test]
    fn invalid_probe_start_goes_to_safe_state() {
        for state in [
            HealthState::Healthy,
            HealthState::Suspect { failures: 1 },
            HealthState::Probing {
                backoff_ms: 2_000,
                started_ms: 0,
            },
            HealthState::Down {
                backoff_ms: 4_000,
                next_probe_ms: 100,
            },
        ] {
            let event = HealthEvent::ProbeStart { now_ms: 50 };
            let s = step(&CFG, state, event);
            assert_eq!(s.invalid, Some(InvalidTransition { state, event }));
            assert_eq!(
                s.state,
                HealthState::Down {
                    backoff_ms: 1_000,
                    next_probe_ms: 1_050
                }
            );
        }
    }

    #[test]
    fn down_after_one() {
        let cfg = HealthConfig {
            down_after: 0,
            ..CFG
        };
        let s = step(
            &cfg,
            HealthState::Healthy,
            HealthEvent::Failure { now_ms: 0 },
        );
        assert!(matches!(s.state, HealthState::Down { .. }));
    }

    #[test]
    fn plan_orders_by_health_then_config() {
        let states = [
            HealthState::Down {
                backoff_ms: 1_000,
                next_probe_ms: 0,
            },
            HealthState::Suspect { failures: 1 },
            HealthState::Healthy,
            HealthState::Probing {
                backoff_ms: 1_000,
                started_ms: 0,
            },
            HealthState::Healthy,
        ];
        assert_eq!(plan(&states, 10), vec![2, 4, 1, 3, 0]);
        assert_eq!(plan(&states, 2), vec![2, 4]);
        assert_eq!(plan(&states, 0), Vec::<usize>::new());
        assert_eq!(plan(&[], 3), Vec::<usize>::new());
    }

    #[test]
    fn plan_never_empty_when_all_down() {
        let down = HealthState::Down {
            backoff_ms: 1_000,
            next_probe_ms: 9,
        };
        assert_eq!(plan(&[down, down], 4), vec![0, 1]);
    }

    fn event() -> impl Strategy<Value = (u8, u64)> {
        (0u8..3, 0u64..20_000)
    }

    proptest! {
        /// Any event sequence keeps a valid state. Each event is one step. An invalid event
        /// always goes to the safe state. Time can also go back.
        #[test]
        fn any_sequence_keeps_valid_state(
            down_after in 0u32..5,
            base in 0u64..5_000,
            max in 0u64..50_000,
            events in proptest::collection::vec(event(), 0..300),
        ) {
            let cfg = HealthConfig { down_after, base_backoff_ms: base, max_backoff_ms: max };
            let mut s = HealthState::Healthy;
            for (kind, now_ms) in events {
                let ev = match kind {
                    0 => HealthEvent::Success { now_ms },
                    1 => HealthEvent::Failure { now_ms },
                    _ => HealthEvent::ProbeStart { now_ms },
                };
                let out = step(&cfg, s, ev);
                prop_assert!(is_valid(&cfg, &out.state), "{:?} -> {:?}", s, out.state);
                if out.invalid.is_some() {
                    let safe = matches!(out.state, HealthState::Down { .. });
                    prop_assert!(safe);
                    prop_assert!(!probe_due(&s, now_ms));
                }
                s = out.state;
            }
        }

        /// A probe loop (probe, fail, wait) reaches the highest backoff in a bounded number
        /// of steps: the rank `log2(max / backoff)` goes down on each failed probe.
        #[test]
        fn probe_backoff_reaches_max_in_bounded_steps(base in 1u64..10_000, max in 1u64..1_000_000) {
            let cfg = HealthConfig { down_after: 1, base_backoff_ms: base, max_backoff_ms: max };
            let mut s = step(&cfg, HealthState::Healthy, HealthEvent::Failure { now_ms: 0 }).state;
            let bound = 64; // A u64 doubles at most 64 times.
            let mut reached = false;
            for _ in 0..=bound {
                let HealthState::Down { backoff_ms, next_probe_ms } = s else {
                    return Err(TestCaseError::fail(format!("{s:?}")));
                };
                if backoff_ms == cfg.max_backoff_ms.max(1) {
                    reached = true;
                    break;
                }
                let now = next_probe_ms;
                s = step(&cfg, s, HealthEvent::ProbeStart { now_ms: now }).state;
                s = step(&cfg, s, HealthEvent::Failure { now_ms: now }).state;
            }
            prop_assert!(reached);
        }

        /// The plan holds each upstream at most once and never more than `max_attempts`.
        #[test]
        fn plan_is_a_bounded_permutation(
            kinds in proptest::collection::vec(0u8..4, 0..10),
            max_attempts in 0usize..12,
        ) {
            let states: Vec<HealthState> = kinds.iter().map(|k| match k {
                0 => HealthState::Healthy,
                1 => HealthState::Suspect { failures: 1 },
                2 => HealthState::Probing { backoff_ms: 1, started_ms: 0 },
                _ => HealthState::Down { backoff_ms: 1, next_probe_ms: 0 },
            }).collect();
            let p = plan(&states, max_attempts);
            prop_assert_eq!(p.len(), states.len().min(max_attempts));
            let mut seen = p.clone();
            seen.sort_unstable();
            seen.dedup();
            prop_assert_eq!(seen.len(), p.len());
            for w in p.windows(2) {
                prop_assert!(rank(&states[w[0]]) <= rank(&states[w[1]]));
            }
        }
    }
}
