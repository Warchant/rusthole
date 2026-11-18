use std::time::Duration;

use proptest::prelude::*;

use super::meta::{HASH_HEX_LEN, MAX_ERROR_LEN, MAX_META_BYTES, META_VERSION, bound_error};
use super::*;

fn t(secs: u64) -> MonoTime {
    MonoTime::from_duration(Duration::from_secs(secs))
}

fn daily() -> RefreshPolicy {
    RefreshPolicy::from_hours(24)
}

fn due_now(id: u32, now: MonoTime) -> ListRefresh {
    ListRefresh::new(id, Some(now))
}

#[test]
fn full_cycle_success() {
    let p = daily();
    let mut m = due_now(7, t(0));
    m.step(&p, RefreshEvent::Tick(t(0))).unwrap();
    assert_eq!(m.state(), RefreshState::Due { since: t(0) });
    assert!(m.wants_fetch());
    m.step(&p, RefreshEvent::Start(t(1))).unwrap();
    assert!(m.is_fetching());
    m.step(&p, RefreshEvent::Updated(t(5))).unwrap();
    let next = next_due(&p, 7, t(5)).unwrap();
    assert_eq!(
        m.state(),
        RefreshState::Idle {
            next_due: Some(next)
        }
    );
    assert_eq!(m.wake_at(), Some(next));
    // Not due before the time, due at the time.
    m.step(&p, RefreshEvent::Tick(t(6))).unwrap();
    assert!(!m.wants_fetch());
    m.step(&p, RefreshEvent::Tick(next)).unwrap();
    assert!(m.wants_fetch());
}

#[test]
fn not_modified_is_a_success() {
    let p = daily();
    let mut m = due_now(1, t(0));
    m.step(&p, RefreshEvent::UpdateNow(t(0))).unwrap();
    m.step(&p, RefreshEvent::Start(t(0))).unwrap();
    m.step(&p, RefreshEvent::Failed(t(1))).unwrap();
    assert_eq!(m.failures(), 1);
    m.step(&p, RefreshEvent::UpdateNow(t(2))).unwrap();
    m.step(&p, RefreshEvent::Start(t(2))).unwrap();
    m.step(&p, RefreshEvent::NotModified(t(3))).unwrap();
    assert_eq!(m.failures(), 0);
    assert!(matches!(
        m.state(),
        RefreshState::Idle { next_due: Some(_) }
    ));
}

#[test]
fn failures_back_off_and_cap_at_the_interval() {
    let p = RefreshPolicy::from_hours(1);
    let mut m = due_now(3, t(0));
    let mut now = 0;
    let mut delays = Vec::new();
    for _ in 0..10 {
        m.step(&p, RefreshEvent::Tick(t(now))).unwrap();
        m.step(&p, RefreshEvent::Start(t(now))).unwrap();
        m.step(&p, RefreshEvent::Failed(t(now))).unwrap();
        let RefreshState::Backoff { retry_at } = m.state() else {
            panic!("backoff expected: {m:?}");
        };
        delays.push(retry_at.saturating_since(t(now)).as_secs());
        now = retry_at.as_duration().as_secs();
    }
    assert_eq!(
        delays,
        [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600, 3600]
    );
    assert_eq!(m.failures(), 10);
}

#[test]
fn update_now_moves_idle_and_backoff_to_due() {
    let p = daily();
    let mut m = ListRefresh::new(1, None);
    // No schedule: a tick never makes the list due.
    m.step(&p, RefreshEvent::Tick(t(1_000_000))).unwrap();
    assert!(!m.wants_fetch());
    m.step(&p, RefreshEvent::UpdateNow(t(1_000_001))).unwrap();
    assert!(m.wants_fetch());
    // A second update now changes nothing.
    m.step(&p, RefreshEvent::UpdateNow(t(1_000_002))).unwrap();
    assert_eq!(
        m.state(),
        RefreshState::Due {
            since: t(1_000_001)
        }
    );

    m.step(&p, RefreshEvent::Start(t(1_000_003))).unwrap();
    m.step(&p, RefreshEvent::Failed(t(1_000_004))).unwrap();
    assert!(matches!(m.state(), RefreshState::Backoff { .. }));
    m.step(&p, RefreshEvent::UpdateNow(t(1_000_005))).unwrap();
    assert_eq!(
        m.state(),
        RefreshState::Due {
            since: t(1_000_005)
        }
    );
}

#[test]
fn update_now_during_a_fetch_fetches_again() {
    let p = daily();
    let mut m = due_now(1, t(0));
    m.step(&p, RefreshEvent::Tick(t(0))).unwrap();
    m.step(&p, RefreshEvent::Start(t(1))).unwrap();
    m.step(&p, RefreshEvent::UpdateNow(t(2))).unwrap();
    assert_eq!(
        m.state(),
        RefreshState::Fetching {
            started: t(1),
            again: true
        }
    );
    m.step(&p, RefreshEvent::Updated(t(3))).unwrap();
    assert_eq!(m.state(), RefreshState::Due { since: t(3) });
}

#[test]
fn invalid_events_go_to_idle() {
    let p = daily();
    let cases = [
        RefreshEvent::Start(t(10)),
        RefreshEvent::Updated(t(10)),
        RefreshEvent::NotModified(t(10)),
        RefreshEvent::Failed(t(10)),
    ];
    for event in cases {
        let mut m = ListRefresh::new(1, None);
        let err = m.step(&p, event).unwrap_err();
        assert_eq!(err, InvalidRefresh::Unexpected);
        assert_eq!(
            m.state(),
            RefreshState::Idle {
                next_due: next_due(&p, 1, t(10))
            }
        );
    }
    // A fetch outcome in `Due` (no fetch runs) is invalid.
    let mut m = due_now(1, t(0));
    m.step(&p, RefreshEvent::Tick(t(0))).unwrap();
    assert!(m.step(&p, RefreshEvent::Updated(t(1))).is_err());
    assert!(matches!(m.state(), RefreshState::Idle { .. }));
    // A `Start` during a fetch is invalid.
    let mut m = due_now(1, t(0));
    m.step(&p, RefreshEvent::Tick(t(0))).unwrap();
    m.step(&p, RefreshEvent::Start(t(0))).unwrap();
    assert!(m.step(&p, RefreshEvent::Start(t(1))).is_err());
    assert!(matches!(m.state(), RefreshState::Idle { .. }));
}

#[test]
fn time_that_goes_back_is_invalid() {
    let p = daily();
    let mut m = due_now(1, t(0));
    m.step(&p, RefreshEvent::Tick(t(100))).unwrap();
    m.step(&p, RefreshEvent::Start(t(100))).unwrap();
    let err = m.step(&p, RefreshEvent::Updated(t(50))).unwrap_err();
    assert_eq!(
        err,
        InvalidRefresh::TimeWentBack {
            last: t(100),
            now: t(50)
        }
    );
    // The safe state uses the latest time seen.
    assert_eq!(
        m.state(),
        RefreshState::Idle {
            next_due: next_due(&p, 1, t(100))
        }
    );
}

#[test]
fn manual_mode_has_no_schedule() {
    let p = RefreshPolicy::from_hours(0);
    assert_eq!(p.interval, None);
    assert_eq!(next_due(&p, 1, t(0)), None);
    // A list with no copy is fetched once at start.
    assert_eq!(initial_due(&p, 1, t(5), 1_000, None), Some(t(5)));
    assert_eq!(initial_due(&p, 1, t(5), 1_000, Some(900)), None);
    // A failure retries with backoff, capped by the manual cap.
    assert_eq!(p.backoff_cap(), MANUAL_BACKOFF_CAP);
    assert_eq!(p.backoff(100), MANUAL_BACKOFF_CAP);
}

#[test]
fn jitter_is_stable_and_small() {
    let day = Duration::from_hours(24);
    assert_eq!(jitter(1, day), jitter(1, day));
    assert!(jitter(1, day) <= MAX_JITTER);
    // Different ids spread out.
    let mut values: Vec<u64> = (0..50).map(|id| jitter(id, day).as_secs()).collect();
    values.sort_unstable();
    values.dedup();
    assert!(values.len() > 40, "{values:?}");
    // A short interval has a short jitter.
    assert!(jitter(9, Duration::from_hours(1)) <= Duration::from_mins(6));
}

#[test]
fn initial_due_follows_the_last_success() {
    let p = daily();
    let day: i64 = 24 * 3600;
    let day_u = 24 * 3600u64;
    let j = jitter(4, Duration::from_hours(24));
    let now = t(1000);
    // Success one hour ago: due in 23 hours plus the jitter.
    let due = initial_due(&p, 4, now, 10 * day, Some(10 * day - 3600)).unwrap();
    assert_eq!(due, t(1000 + day_u - 3600 + j.as_secs()));
    // Success long ago: due now.
    assert_eq!(initial_due(&p, 4, now, 10 * day, Some(day)), Some(now));
    // The wall clock is behind the last success: wait at most one interval plus jitter.
    let due = initial_due(&p, 4, now, 0, Some(10 * day)).unwrap();
    assert_eq!(due, t(1000 + day_u + j.as_secs()));
}

#[test]
fn drive_to_fetch_is_bounded() {
    let p = daily();
    let mut m = ListRefresh::new(1, None);
    assert_eq!(drive_to_fetch(&p, &mut m, t(1)), Some(2));
    assert!(m.is_fetching());
    assert_eq!(drive_to_fetch(&p, &mut m, t(2)), Some(0));
}

#[test]
fn meta_round_trip_and_rules() {
    let mut m = ListMeta::new("https://lists.example/a.txt");
    assert!(!m.has_body_for("https://lists.example/a.txt"));
    let body = BodyFacts {
        hash: "a".repeat(HASH_HEX_LEN),
        size_bytes: 10,
        entries: EntryCounts {
            valid: 3,
            invalid: 1,
            skipped: 0,
        },
    };
    let v = Validators {
        etag: Some("\"v1\"".into()),
        last_modified: Some("Tue, 17 Nov 2026 03:00:00 GMT".into()),
    };
    m = m.after_body("https://lists.example/a.txt", 100, v.clone(), body.clone());
    assert!(m.has_body_for("https://lists.example/a.txt"));
    assert!(!m.has_body_for("https://lists.example/b.txt"));
    assert_eq!(m.changed_at, Some(100));
    assert_eq!(parse_meta(&render_meta(&m)).unwrap(), m);

    // The same body later: `changed_at` stays.
    let later = m.after_body("https://lists.example/a.txt", 200, v.clone(), body);
    assert_eq!(later.changed_at, Some(100));
    assert_eq!(later.last_success, Some(200));

    // "Not modified" at the same time and with the same validators changes nothing.
    assert_eq!(m.after_not_modified(100, Validators::default()), m);
    assert_eq!(m.after_not_modified(100, v), m);
    // Later: only the times change.
    let nm = m.after_not_modified(300, Validators::default());
    assert_eq!(nm.last_success, Some(300));
    assert_eq!(nm.etag, m.etag);

    // A failure keeps the body facts and stores a bounded error.
    let failed = m.after_failure(400, &"x".repeat(1000));
    assert_eq!(failed.body_hash, m.body_hash);
    assert_eq!(failed.last_error.as_ref().unwrap().len(), MAX_ERROR_LEN);
    assert_eq!(failed.last_success, Some(100));
    assert_eq!(parse_meta(&render_meta(&failed)).unwrap(), failed);
    // The same failure at the same time changes nothing.
    assert_eq!(failed.after_failure(400, &"x".repeat(1000)), failed);
}

#[test]
fn bad_validators_are_not_kept() {
    let v = Validators {
        etag: Some("a\r\nX-Evil: 1".into()),
        last_modified: Some("x".repeat(10_000)),
    }
    .bounded();
    assert_eq!(v, Validators::default());
}

#[test]
fn bound_error_keeps_char_boundaries() {
    let text = "é".repeat(400);
    let cut = bound_error(&text);
    assert!(cut.len() <= MAX_ERROR_LEN);
    assert!(cut.chars().all(|c| c == 'é'));
}

#[test]
fn parse_meta_rejects_bad_files() {
    assert!(matches!(parse_meta(b""), Err(MetaError::Json(_))));
    assert!(matches!(parse_meta(b"{not json"), Err(MetaError::Json(_))));
    assert!(matches!(
        parse_meta(&vec![b' '; MAX_META_BYTES + 1]),
        Err(MetaError::TooLarge { .. })
    ));
    let mut m = ListMeta::new("http://lists.example/x");
    m.version = 2;
    assert_eq!(
        parse_meta(&render_meta(&m)),
        Err(MetaError::Version { found: 2 })
    );
    m.version = META_VERSION;
    m.body_hash = Some("XYZ".into());
    assert_eq!(
        parse_meta(&render_meta(&m)),
        Err(MetaError::BadField { field: "body_hash" })
    );
    m.body_hash = None;
    m.url = String::new();
    assert_eq!(
        parse_meta(&render_meta(&m)),
        Err(MetaError::BadField { field: "url" })
    );
    // An unknown field is an error.
    let text = br#"{"version":1,"url":"http://a.example/","etag":null,"last_modified":null,
        "body_hash":null,"size_bytes":0,"entries":{"valid":0,"invalid":0,"skipped":0},
        "last_success":null,"last_attempt":null,"changed_at":null,"last_error":null,"x":1}"#;
    assert!(matches!(parse_meta(text), Err(MetaError::Json(_))));
}

fn event() -> impl Strategy<Value = (u8, u64)> {
    (0u8..6, 0u64..5_000)
}

fn to_event(kind: u8, now: MonoTime) -> RefreshEvent {
    match kind {
        0 => RefreshEvent::Tick(now),
        1 => RefreshEvent::UpdateNow(now),
        2 => RefreshEvent::Start(now),
        3 => RefreshEvent::Updated(now),
        4 => RefreshEvent::NotModified(now),
        _ => RefreshEvent::Failed(now),
    }
}

fn policy() -> impl Strategy<Value = RefreshPolicy> {
    (0u32..200, 1u64..4000).prop_map(|(h, base)| RefreshPolicy {
        base_backoff: Duration::from_secs(base),
        ..RefreshPolicy::from_hours(h)
    })
}

/// A machine after a random event sequence. Times mostly go forward; some go back.
fn run(p: &RefreshPolicy, id: u32, events: &[(u8, u64)]) -> ListRefresh {
    let mut m = ListRefresh::new(id, Some(t(0)));
    let mut now = 0u64;
    for &(kind, dt) in events {
        // One event in eight goes back in time.
        now = if dt % 8 == 0 {
            now.saturating_sub(dt)
        } else {
            now + dt
        };
        let _ = m.step(p, to_event(kind, t(now)));
    }
    m
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).map_or(512, |env: u32| env.max(512))
    ))]

    /// Any event sequence keeps a valid state. An invalid event always gives `Idle`.
    #[test]
    fn any_sequence_keeps_valid_state(
        p in policy(),
        id in any::<u32>(),
        events in prop::collection::vec(event(), 0..64),
    ) {
        let mut m = ListRefresh::new(id, Some(t(0)));
        let mut now = 0u64;
        for (kind, dt) in events {
            now = if dt % 8 == 0 { now.saturating_sub(dt) } else { now + dt };
            let result = m.step(&p, to_event(kind, t(now)));
            prop_assert!(m.is_valid(), "{m:?}");
            if result.is_err() {
                let is_idle = matches!(m.state(), RefreshState::Idle { .. });
                prop_assert!(is_idle, "{m:?}");
            }
        }
    }

    /// The backoff never shrinks with more failures and never passes the cap.
    #[test]
    fn backoff_grows_and_caps(p in policy(), failures in 1u32..200) {
        let a = p.backoff(failures);
        let b = p.backoff(failures + 1);
        prop_assert!(a <= b);
        prop_assert!(b <= p.backoff_cap());
        prop_assert!(p.backoff(1) <= p.base_backoff.max(Duration::from_secs(1)));
        prop_assert!(a >= Duration::from_secs(1));
        // Enough failures always reach the cap.
        prop_assert_eq!(p.backoff(64), p.backoff_cap());
    }

    /// After an "update now", a fetch starts that begins at or after the request: at once
    /// (`Start`) or after the running fetch ends.
    #[test]
    fn update_now_always_leads_to_a_fetch(
        p in policy(),
        id in any::<u32>(),
        events in prop::collection::vec(event(), 0..32),
        outcome in 3u8..6,
        dt in 0u64..100,
    ) {
        let mut m = run(&p, id, &events);
        let at = m.last_now.unwrap_or(t(0));
        m.step(&p, RefreshEvent::UpdateNow(at)).unwrap();
        if m.is_fetching() {
            // The running fetch ends. The list is then due again.
            m.step(&p, to_event(outcome, t(at.as_duration().as_secs() + dt))).unwrap();
        }
        prop_assert!(m.wants_fetch(), "{m:?}");
        let start = t(at.as_duration().as_secs() + dt);
        m.step(&p, RefreshEvent::Start(start)).unwrap();
        let RefreshState::Fetching { started, .. } = m.state() else {
            return Err(TestCaseError::fail(format!("not fetching: {m:?}")));
        };
        prop_assert!(started >= at);
    }

    /// From any state, at most `MAX_STEPS_TO_FETCH` events start a fetch, and each event
    /// lowers the rank by one.
    #[test]
    fn steps_to_fetch_are_bounded(
        p in policy(),
        id in any::<u32>(),
        events in prop::collection::vec(event(), 0..48),
    ) {
        let mut m = run(&p, id, &events);
        let now = m.last_now.unwrap_or(t(0));
        let mut rank = steps_to_fetch(m.state());
        prop_assert!(rank <= MAX_STEPS_TO_FETCH);
        let mut steps = 0;
        while let Some(e) = next_fetch_event(m.state(), now) {
            prop_assert!(steps < MAX_STEPS_TO_FETCH, "{m:?}");
            m.step(&p, e).unwrap();
            let next = steps_to_fetch(m.state());
            prop_assert_eq!(next + 1, rank);
            rank = next;
            steps += 1;
        }
        prop_assert!(m.is_fetching());
        let mut again = run(&p, id, &events);
        let n = drive_to_fetch(&p, &mut again, now);
        prop_assert_eq!(n, Some(steps));
    }

    /// The next due time is in the future and within the interval plus the jitter.
    #[test]
    fn next_due_is_in_the_future(
        hours in 1u32..=168,
        id in any::<u32>(),
        now in 0u64..10_000_000_000,
    ) {
        let p = RefreshPolicy::from_hours(hours);
        let interval = p.interval.unwrap();
        let due = next_due(&p, id, t(now)).unwrap();
        prop_assert!(due > t(now));
        prop_assert!(due >= t(now).checked_add(interval).unwrap());
        prop_assert!(due <= t(now).checked_add(interval + max_jitter(interval)).unwrap());
    }

    /// The first due time is never in the past and never later than one interval plus the
    /// jitter, for any wall clock.
    #[test]
    fn initial_due_is_bounded(
        hours in 0u32..=168,
        id in any::<u32>(),
        now in 0u64..1_000_000_000,
        wall in any::<i64>(),
        last in proptest::option::of(any::<i64>()),
    ) {
        let p = RefreshPolicy::from_hours(hours);
        match initial_due(&p, id, t(now), wall, last) {
            None => prop_assert!(p.interval.is_none() && last.is_some()),
            Some(due) => {
                prop_assert!(due >= t(now));
                let span = p.interval.map_or(Duration::ZERO, |i| i + max_jitter(i));
                prop_assert!(due <= t(now).checked_add(span).unwrap());
            }
        }
    }

    /// `parse_meta` never panics, and a valid file round-trips.
    #[test]
    fn parse_meta_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_meta(&bytes);
    }

    #[test]
    fn meta_round_trips(
        url in "https?://[a-z]{1,10}\\.example/[a-z]{0,10}",
        etag in proptest::option::of("\"[a-zA-Z0-9]{1,20}\""),
        size in any::<u64>(),
        valid in any::<u64>(),
        times in proptest::option::of(any::<i64>()),
        err in proptest::option::of("[ -~]{0,300}"),
    ) {
        let m = ListMeta {
            version: META_VERSION,
            url,
            etag,
            last_modified: None,
            body_hash: Some("0".repeat(HASH_HEX_LEN)),
            size_bytes: size,
            entries: EntryCounts { valid, invalid: 0, skipped: 0 },
            last_success: times,
            last_attempt: times,
            changed_at: times,
            last_error: err,
        };
        prop_assert_eq!(parse_meta(&render_meta(&m)), Ok(m));
    }
}
