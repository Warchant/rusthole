use std::net::Ipv4Addr;

use proptest::prelude::*;

use super::*;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

fn t(secs: u64) -> MonoTime {
    MonoTime::from_duration(Duration::from_secs(secs))
}

fn fail_once(table: &mut BanTable, now: MonoTime) -> BanOutcome {
    assert_eq!(table.begin(IP, now), BanOutcome::Allowed);
    table.step(IP, BanEvent::Failure, now)
}

#[test]
fn five_failures_lock_for_one_minute() {
    let mut table = BanTable::new(BanPolicy::default());
    for _ in 0..4 {
        assert_eq!(
            fail_once(&mut table, t(10)),
            BanOutcome::Counted { locked: None }
        );
    }
    assert_eq!(
        fail_once(&mut table, t(10)),
        BanOutcome::Counted {
            locked: Some(Duration::from_secs(60))
        }
    );
    assert_eq!(
        table.begin(IP, t(30)),
        BanOutcome::Banned {
            retry_after: Duration::from_secs(40)
        }
    );
    // The lock ends at 70 s.
    assert_eq!(table.begin(IP, t(70)), BanOutcome::Allowed);
}

#[test]
fn locks_double_up_to_the_cap() {
    let p = BanPolicy::default();
    let got: Vec<u64> = (0..9).map(|l| p.lockout(l).as_secs()).collect();
    assert_eq!(got, [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]);
    assert_eq!(p.lockout(u32::MAX), p.max_lockout);

    let mut table = BanTable::new(p);
    let mut now = 0;
    for want in [60, 120, 240] {
        for _ in 0..4 {
            fail_once(&mut table, t(now));
        }
        assert_eq!(
            fail_once(&mut table, t(now)),
            BanOutcome::Counted {
                locked: Some(Duration::from_secs(want))
            }
        );
        now += want;
    }
}

#[test]
fn success_and_quiet_time_reset_the_entry() {
    let mut table = BanTable::new(BanPolicy::default());
    for _ in 0..4 {
        fail_once(&mut table, t(0));
    }
    assert_eq!(table.begin(IP, t(1)), BanOutcome::Allowed);
    assert_eq!(table.step(IP, BanEvent::Success, t(1)), BanOutcome::Done);
    assert!(table.is_empty());

    for _ in 0..4 {
        fail_once(&mut table, t(0));
    }
    // 15 minutes later the failures are forgotten: 4 more failures do not lock.
    for _ in 0..4 {
        assert_eq!(
            fail_once(&mut table, t(900)),
            BanOutcome::Counted { locked: None }
        );
    }
    assert_eq!(table.purge(t(900 + 899)), 0);
    assert_eq!(table.purge(t(1800)), 1);
}

#[test]
fn parallel_attempts_cannot_pass_the_threshold() {
    let mut table = BanTable::new(BanPolicy::default());
    for _ in 0..5 {
        assert_eq!(table.begin(IP, t(0)), BanOutcome::Allowed);
    }
    assert!(matches!(table.begin(IP, t(0)), BanOutcome::Banned { .. }));
    // A cancel gives a try back; it does not count as a failure.
    assert_eq!(table.step(IP, BanEvent::Cancel, t(0)), BanOutcome::Done);
    assert_eq!(table.begin(IP, t(0)), BanOutcome::Allowed);
    for _ in 0..4 {
        table.step(IP, BanEvent::Failure, t(1));
    }
    assert_eq!(
        table.step(IP, BanEvent::Failure, t(1)),
        BanOutcome::Counted {
            locked: Some(Duration::from_secs(60))
        }
    );
}

#[test]
fn a_finish_with_no_started_attempt_is_invalid() {
    let mut table = BanTable::new(BanPolicy::default());
    for _ in 0..5 {
        fail_once(&mut table, t(0));
    }
    // No attempt is pending, so a success is not valid. The address stays locked.
    assert!(matches!(
        table.step(IP, BanEvent::Success, t(1)),
        BanOutcome::Invalid { .. }
    ));
    assert!(matches!(table.state(IP), Some(EntryState::Locked { .. })));
}

#[test]
fn success_of_a_parallel_attempt_during_a_lock_is_rejected() {
    let p = BanPolicy::default();
    // One attempt was pending when parallel failures locked the address.
    let s = Some(EntryState::Locked {
        until: t(60),
        level: 1,
        pending: 1,
    });
    let (next, out) = transition(&p, s, BanEvent::Success, t(5));
    assert_eq!(
        out,
        BanOutcome::Rejected {
            retry_after: Duration::from_secs(55)
        }
    );
    assert_eq!(
        next,
        Some(EntryState::Locked {
            until: t(60),
            level: 1,
            pending: 0
        })
    );
}

#[test]
fn invalid_events_lock_the_address() {
    let p = BanPolicy::default();
    for event in [BanEvent::Failure, BanEvent::Success, BanEvent::Cancel] {
        let (next, out) = transition(&p, None, event, t(10));
        assert_eq!(
            out,
            BanOutcome::Invalid {
                retry_after: Duration::from_secs(60)
            }
        );
        assert_eq!(
            next,
            Some(EntryState::Locked {
                until: t(70),
                level: 1,
                pending: 0
            })
        );
    }
}

#[test]
fn ipv6_uses_the_64_network() {
    let a: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
    let b: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();
    assert_eq!(ban_key(a), ban_key(b));
    let mapped: IpAddr = "::ffff:192.0.2.10".parse().unwrap();
    assert_eq!(ban_key(mapped), IP);
}

#[test]
fn the_table_has_a_size_limit() {
    let mut table = BanTable::new(BanPolicy {
        max_entries: 8,
        ..BanPolicy::default()
    });
    for i in 0..100u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, i));
        table.begin(ip, t(0));
        assert!(table.len() <= 8);
    }
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Begin,
    Failure,
    Cancel,
    Success,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => Just(Op::Begin),
        3 => Just(Op::Failure),
        1 => Just(Op::Cancel),
        1 => Just(Op::Success),
    ]
}

fn event(op: Op) -> BanEvent {
    match op {
        Op::Begin => BanEvent::Begin,
        Op::Failure => BanEvent::Failure,
        Op::Cancel => BanEvent::Cancel,
        Op::Success => BanEvent::Success,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// With no success and no cancel, no event sequence lets more than `threshold` attempts
    /// start in any window of `base_lockout` (half-open). Invalid events are in the
    /// sequences too: they only lock.
    #[test]
    fn at_most_threshold_attempts_in_a_window(
        steps in prop::collection::vec((0u64..90_000, prop_oneof![3 => Just(Op::Begin), 2 => Just(Op::Failure)]), 1..300),
        threshold in 1u32..8,
    ) {
        let p = BanPolicy { threshold, ..BanPolicy::default() };
        let mut table = BanTable::new(p);
        let mut now_ms = 0u64;
        let mut allowed: Vec<u64> = Vec::new();
        for (dt, o) in steps {
            now_ms += dt;
            let now = MonoTime::from_duration(Duration::from_millis(now_ms));
            if table.step(IP, event(o), now) == BanOutcome::Allowed {
                allowed.push(now_ms);
            }
        }
        let window = u64::try_from(p.base_lockout.as_millis()).unwrap();
        for (i, start) in allowed.iter().enumerate() {
            let inside = allowed[i..].iter().take_while(|&&x| x < start + window).count();
            prop_assert!(inside <= threshold as usize, "{inside} attempts in one window: {allowed:?}");
        }
    }

    /// The invariants hold for any event sequence: in an open entry, failures plus pending
    /// attempts never pass the threshold; an invalid event always leaves the entry locked;
    /// each step is one transition.
    #[test]
    fn invariants_hold(
        steps in prop::collection::vec((0u64..120_000, op()), 1..300),
    ) {
        let p = BanPolicy::default();
        let mut state = None;
        let mut now_ms = 0u64;
        for (dt, o) in steps {
            now_ms += dt;
            let now = MonoTime::from_duration(Duration::from_millis(now_ms));
            let (next, out) = transition(&p, state, event(o), now);
            if let Some(EntryState::Open { failures, pending, .. }) = next {
                prop_assert!(failures + pending <= p.threshold);
            }
            if matches!(out, BanOutcome::Invalid { .. }) {
                prop_assert!(matches!(next, Some(EntryState::Locked { .. })), "{next:?}");
            }
            if let BanOutcome::Banned { retry_after } | BanOutcome::Rejected { retry_after } | BanOutcome::Invalid { retry_after } = out {
                prop_assert!(retry_after >= Duration::from_secs(1));
                prop_assert!(retry_after <= p.max_lockout.max(Duration::from_secs(1)));
            }
            state = next;
        }
    }
}
