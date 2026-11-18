//! Clocks of the web shell. The policy (sessions, ban, TOTP) gets the time as an input, so
//! tests can use a [`ManualClock`].

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rusthole_core::blocking_state::MonoTime;

/// A source of the time.
pub trait Clock: Send + Sync + fmt::Debug {
    /// The monotonic time, for durations (sessions, ban, timers).
    fn mono(&self) -> MonoTime;
    /// The wall clock in Unix seconds, for time stamps that people read and for TOTP.
    fn wall(&self) -> i64;
}

/// The system clocks: [`Instant`] since the start, and the system wall clock.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock with the origin now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn mono(&self) -> MonoTime {
        MonoTime::from_duration(self.origin.elapsed())
    }

    fn wall(&self) -> i64 {
        rusthole_store::wall_now()
    }
}

/// A clock that moves only when a test moves it.
#[derive(Debug, Default)]
pub struct ManualClock {
    mono_ms: AtomicU64,
    wall: AtomicI64,
}

impl ManualClock {
    /// A clock at monotonic time 0 and wall time `wall`.
    pub fn new(wall: i64) -> Arc<Self> {
        Arc::new(Self {
            mono_ms: AtomicU64::new(0),
            wall: AtomicI64::new(wall),
        })
    }

    /// Moves both clocks forward by `d`.
    pub fn advance(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        self.mono_ms.fetch_add(ms, Ordering::SeqCst);
        let s = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
        self.wall.fetch_add(s, Ordering::SeqCst);
    }

    /// Sets the wall clock.
    pub fn set_wall(&self, wall: i64) {
        self.wall.store(wall, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn mono(&self) -> MonoTime {
        MonoTime::from_duration(Duration::from_millis(self.mono_ms.load(Ordering::SeqCst)))
    }

    fn wall(&self) -> i64 {
        self.wall.load(Ordering::SeqCst)
    }
}
