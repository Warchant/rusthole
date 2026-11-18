//! Clock fallback for DoT and DoH upstreams (amendment A6).
//!
//! A TLS certificate check needs a correct wall clock. A Raspberry Pi has no real-time
//! clock, so after a boot its clock can be in 1970 until NTP sets it. While the clock is not
//! plausible ([`rusthole_tls::clock_plausible`]), the pool skips the DoT and DoH upstreams and
//! uses the plain `upstreams.fallback_plain` servers.
//!
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Encrypted: clock plausible
//!     [*] --> Fallback: clock not plausible, fallback set
//!     [*] --> EncryptedUnverified: clock not plausible, no fallback
//!     Encrypted --> Fallback: clock not plausible, fallback set (WARN)
//!     Encrypted --> EncryptedUnverified: clock not plausible, no fallback (ERROR)
//!     Fallback --> Encrypted: clock plausible (WARN)
//!     EncryptedUnverified --> Encrypted: clock plausible (WARN)
//! ```
//!
//! Each event (a clock check) is valid in each state, so the machine has no invalid
//! transition. [`clock_step`] is pure: the wall clock is an input.

use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::time::Duration;

/// How often the server checks the wall clock.
pub const CLOCK_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Which upstreams the pool uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamMode {
    /// The clock is plausible: all upstreams in `upstreams.servers`.
    Encrypted,
    /// The clock is not plausible: the plain upstreams in `upstreams.servers` and the
    /// `upstreams.fallback_plain` servers. DoT and DoH upstreams are skipped.
    Fallback,
    /// The clock is not plausible and no fallback is set: all upstreams in
    /// `upstreams.servers`. The DoT and DoH certificate checks can fail.
    EncryptedUnverified,
}

/// What to log after a clock check. Only a change of mode gives a notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockNotice {
    /// The clock is not plausible; the fallback servers are in use. WARN.
    UseFallback,
    /// The clock is not plausible and no fallback is set. ERROR.
    NoFallback,
    /// The clock is plausible again; the encrypted upstreams are in use. WARN.
    ClockValid,
}

/// The result of one clock check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockStep {
    /// The new mode.
    pub mode: UpstreamMode,
    /// What to log, if the mode changed.
    pub notice: Option<ClockNotice>,
}

/// One clock check. `prev` is `None` at the first check.
///
/// - Plausible clock: [`UpstreamMode::Encrypted`].
/// - Clock not plausible: [`UpstreamMode::Fallback`] when a fallback is set, else
///   [`UpstreamMode::EncryptedUnverified`].
///
/// A notice comes only when the mode changes. The first check gives no notice for
/// [`UpstreamMode::Encrypted`].
pub fn clock_step(
    prev: Option<UpstreamMode>,
    now_unix: i64,
    build_time_unix: i64,
    has_fallback: bool,
) -> ClockStep {
    let mode = if rusthole_tls::clock_plausible(now_unix, build_time_unix) {
        UpstreamMode::Encrypted
    } else if has_fallback {
        UpstreamMode::Fallback
    } else {
        UpstreamMode::EncryptedUnverified
    };
    let notice = if prev == Some(mode) {
        None
    } else {
        match mode {
            UpstreamMode::Encrypted => prev.map(|_| ClockNotice::ClockValid),
            UpstreamMode::Fallback => Some(ClockNotice::UseFallback),
            UpstreamMode::EncryptedUnverified => Some(ClockNotice::NoFallback),
        }
    };
    ClockStep { mode, notice }
}

/// Logs a notice at its level.
pub fn log_notice(notice: ClockNotice, now_unix: i64, build_time_unix: i64) {
    match notice {
        ClockNotice::UseFallback => tracing::warn!(
            now_unix,
            build_time_unix,
            "the system clock is before the build time of rusthole; TLS certificate checks \
             cannot work, so the DoT and DoH upstreams are skipped and upstreams.fallback_plain \
             is used until the clock is valid (for example after NTP sets it)"
        ),
        ClockNotice::NoFallback => tracing::error!(
            now_unix,
            build_time_unix,
            "the system clock is before the build time of rusthole and upstreams.fallback_plain \
             is empty; TLS certificate checks of the DoT and DoH upstreams can fail, so DNS can \
             stop working until NTP sets the clock. Set upstreams.fallback_plain to a plain DNS \
             server to keep DNS working after a boot without a real-time clock"
        ),
        ClockNotice::ClockValid => tracing::warn!(
            now_unix,
            "the system clock is valid again; the DoT and DoH upstreams are in use"
        ),
    }
}

/// The role of a server in the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRole {
    /// A plain upstream in `upstreams.servers`.
    Plain,
    /// A DoT or DoH upstream in `upstreams.servers`.
    Encrypted,
    /// A server in `upstreams.fallback_plain`.
    Fallback,
}

/// The servers that the pool can use in `mode`, as indexes into `roles`, in order.
///
/// - [`UpstreamMode::Encrypted`] and [`UpstreamMode::EncryptedUnverified`]: each server in
///   `upstreams.servers`; no fallback server.
/// - [`UpstreamMode::Fallback`]: the plain servers in `upstreams.servers`, then the
///   fallback servers; no DoT or DoH server.
pub fn eligible(roles: &[ServerRole], mode: UpstreamMode) -> Vec<usize> {
    roles
        .iter()
        .enumerate()
        .filter(|(_, r)| match mode {
            UpstreamMode::Encrypted | UpstreamMode::EncryptedUnverified => {
                **r != ServerRole::Fallback
            }
            UpstreamMode::Fallback => **r != ServerRole::Encrypted,
        })
        .map(|(i, _)| i)
        .collect()
}

/// The current mode, shared by the pool and the clock task.
#[derive(Debug)]
pub(crate) struct ModeCell(AtomicU8);

impl ModeCell {
    pub(crate) fn new(mode: UpstreamMode) -> Self {
        Self(AtomicU8::new(Self::encode(mode)))
    }

    fn encode(mode: UpstreamMode) -> u8 {
        match mode {
            UpstreamMode::Encrypted => 0,
            UpstreamMode::Fallback => 1,
            UpstreamMode::EncryptedUnverified => 2,
        }
    }

    pub(crate) fn get(&self) -> UpstreamMode {
        match self.0.load(Ordering::Acquire) {
            0 => UpstreamMode::Encrypted,
            1 => UpstreamMode::Fallback,
            _ => UpstreamMode::EncryptedUnverified,
        }
    }

    pub(crate) fn set(&self, mode: UpstreamMode) {
        self.0.store(Self::encode(mode), Ordering::Release);
    }
}

/// The wall clock in Unix seconds. Tests use a fake.
pub trait WallClock: Send + Sync + fmt::Debug {
    /// Now, in Unix seconds.
    fn now_unix(&self) -> i64;
}

/// The system wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now_unix(&self) -> i64 {
        rusthole_tls::now_unix()
    }
}

/// A wall clock that gives a set value. For tests.
#[derive(Debug, Default)]
pub struct FixedWallClock(AtomicI64);

impl FixedWallClock {
    /// A clock at `now_unix`.
    pub fn new(now_unix: i64) -> Self {
        Self(AtomicI64::new(now_unix))
    }

    /// Sets the time.
    pub fn set(&self, now_unix: i64) {
        self.0.store(now_unix, Ordering::Release);
    }
}

impl WallClock for FixedWallClock {
    fn now_unix(&self) -> i64 {
        self.0.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rusthole_tls::policy::CLOCK_MARGIN;

    const BUILD: i64 = 1_800_000_000;
    const GOOD: i64 = BUILD + 10;
    const BAD: i64 = 0;

    #[test]
    fn first_check() {
        let s = clock_step(None, GOOD, BUILD, true);
        assert_eq!(s.mode, UpstreamMode::Encrypted);
        assert_eq!(s.notice, None);
        let s = clock_step(None, BAD, BUILD, true);
        assert_eq!(s.mode, UpstreamMode::Fallback);
        assert_eq!(s.notice, Some(ClockNotice::UseFallback));
        let s = clock_step(None, BAD, BUILD, false);
        assert_eq!(s.mode, UpstreamMode::EncryptedUnverified);
        assert_eq!(s.notice, Some(ClockNotice::NoFallback));
    }

    #[test]
    fn transitions_log_once_per_change() {
        use UpstreamMode::{Encrypted, EncryptedUnverified, Fallback};
        let mut mode = None;
        let mut notices = Vec::new();
        for now in [BAD, BAD, BAD, GOOD, GOOD, BAD, GOOD] {
            let s = clock_step(mode, now, BUILD, true);
            mode = Some(s.mode);
            notices.push(s.notice);
        }
        assert_eq!(
            notices,
            vec![
                Some(ClockNotice::UseFallback),
                None,
                None,
                Some(ClockNotice::ClockValid),
                None,
                Some(ClockNotice::UseFallback),
                Some(ClockNotice::ClockValid),
            ]
        );
        assert_eq!(
            clock_step(Some(Encrypted), BAD, BUILD, false).notice,
            Some(ClockNotice::NoFallback)
        );
        assert_eq!(
            clock_step(Some(EncryptedUnverified), BAD, BUILD, false).notice,
            None
        );
        assert_eq!(
            clock_step(Some(EncryptedUnverified), GOOD, BUILD, false),
            ClockStep {
                mode: Encrypted,
                notice: Some(ClockNotice::ClockValid)
            }
        );
        assert_eq!(clock_step(Some(Fallback), BAD, BUILD, true).notice, None);
    }

    #[test]
    fn margin_edge() {
        let edge = BUILD - CLOCK_MARGIN;
        assert_eq!(
            clock_step(None, edge, BUILD, true).mode,
            UpstreamMode::Encrypted
        );
        assert_eq!(
            clock_step(None, edge - 1, BUILD, true).mode,
            UpstreamMode::Fallback
        );
    }

    #[test]
    fn eligible_servers() {
        use ServerRole::{Encrypted as E, Fallback as F, Plain as P};
        let roles = [E, P, E, F, F];
        assert_eq!(eligible(&roles, UpstreamMode::Encrypted), vec![0, 1, 2]);
        assert_eq!(
            eligible(&roles, UpstreamMode::EncryptedUnverified),
            vec![0, 1, 2]
        );
        assert_eq!(eligible(&roles, UpstreamMode::Fallback), vec![1, 3, 4]);
    }

    /// Records the level and the message of each event.
    #[derive(Default, Clone)]
    struct Capture(std::sync::Arc<parking_lot::Mutex<Vec<(tracing::Level, String)>>>);

    struct MessageVisitor(String);

    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut v = MessageVisitor(String::new());
            event.record(&mut v);
            self.0.lock().push((*event.metadata().level(), v.0));
        }
    }

    fn logged(notice: ClockNotice) -> Vec<(tracing::Level, String)> {
        use tracing_subscriber::layer::SubscriberExt;
        let cap = Capture::default();
        let sub = tracing_subscriber::registry().with(cap.clone());
        tracing::subscriber::with_default(sub, || log_notice(notice, BAD, BUILD));
        cap.0.lock().clone()
    }

    /// No fallback: one ERROR that names the missing setting. The other notices are WARN.
    #[test]
    fn notice_levels() {
        let e = logged(ClockNotice::NoFallback);
        assert_eq!(e.len(), 1, "{e:?}");
        assert_eq!(e[0].0, tracing::Level::ERROR);
        assert!(e[0].1.contains("upstreams.fallback_plain"), "{e:?}");
        for n in [ClockNotice::UseFallback, ClockNotice::ClockValid] {
            let e = logged(n);
            assert_eq!(e.len(), 1, "{e:?}");
            assert_eq!(e[0].0, tracing::Level::WARN, "{n:?}");
        }
        assert!(
            logged(ClockNotice::UseFallback)[0]
                .1
                .contains("fallback_plain")
        );
    }

    #[test]
    fn mode_cell_round_trip() {
        let c = ModeCell::new(UpstreamMode::Encrypted);
        for m in [
            UpstreamMode::Fallback,
            UpstreamMode::EncryptedUnverified,
            UpstreamMode::Encrypted,
        ] {
            c.set(m);
            assert_eq!(c.get(), m);
        }
    }

    fn role() -> impl Strategy<Value = ServerRole> {
        prop_oneof![
            Just(ServerRole::Plain),
            Just(ServerRole::Encrypted),
            Just(ServerRole::Fallback)
        ]
    }

    proptest! {
        /// The mode depends only on the clock and the fallback; a notice comes if and only
        /// if the mode changed (and the first Encrypted gives none).
        #[test]
        fn step_invariants(prev in proptest::option::of(prop_oneof![
                Just(UpstreamMode::Encrypted),
                Just(UpstreamMode::Fallback),
                Just(UpstreamMode::EncryptedUnverified)]),
            now in any::<i64>(), build in any::<i64>(), fb in any::<bool>()) {
            let s = clock_step(prev, now, build, fb);
            let plausible = rusthole_tls::clock_plausible(now, build);
            prop_assert_eq!(s.mode == UpstreamMode::Encrypted, plausible);
            if !plausible {
                prop_assert_eq!(s.mode == UpstreamMode::Fallback, fb);
            }
            let changed = prev != Some(s.mode);
            let expect_notice = changed && !(prev.is_none() && s.mode == UpstreamMode::Encrypted);
            prop_assert_eq!(s.notice.is_some(), expect_notice);
        }

        /// No encrypted server in fallback mode, no fallback server in the other modes, and
        /// the order stays.
        #[test]
        fn eligible_invariants(roles in proptest::collection::vec(role(), 0..20)) {
            for mode in [UpstreamMode::Encrypted, UpstreamMode::Fallback, UpstreamMode::EncryptedUnverified] {
                let e = eligible(&roles, mode);
                prop_assert!(e.windows(2).all(|w| w[0] < w[1]));
                for &i in &e {
                    let r = roles[i];
                    if mode == UpstreamMode::Fallback {
                        prop_assert_ne!(r, ServerRole::Encrypted);
                    } else {
                        prop_assert_ne!(r, ServerRole::Fallback);
                    }
                }
                prop_assert!(roles.iter().filter(|r| **r == ServerRole::Plain).count()
                    <= e.len());
            }
        }
    }
}
