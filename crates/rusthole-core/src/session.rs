//! Admin session policy (decision D10). Pure: `now` is an input.
//!
//! A session ends at the first of two limits:
//!
//! - idle: `idle` after the last request;
//! - absolute: `absolute` after the login.
//!
//! [`SessionTable`] keeps the sessions in memory with a size limit. The key is a 32-byte
//! value; the web shell uses the SHA-256 hash of the session id, so a map lookup does not
//! compare the secret id itself.

use std::collections::HashMap;
use std::time::Duration;

use crate::blocking_state::MonoTime;

/// The rules of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    /// The session ends this long after the last request.
    pub idle: Duration,
    /// The session ends this long after the login.
    pub absolute: Duration,
    /// The largest number of sessions. A new session pushes out the expired sessions, then
    /// the session with the oldest last request.
    pub max_sessions: usize,
}

impl SessionPolicy {
    /// The policy for `admin.session_ttl_seconds`: the absolute limit is the setting, and
    /// the idle limit is one hour (or the setting, when it is shorter).
    pub fn from_ttl_seconds(ttl: u32) -> Self {
        let absolute = Duration::from_secs(u64::from(ttl.max(1)));
        Self {
            idle: absolute.min(DEFAULT_IDLE),
            absolute,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }

    /// The end of a session.
    pub fn deadline(&self, t: &SessionTimes) -> MonoTime {
        let far = MonoTime::from_duration(Duration::MAX);
        let idle = t.last_seen.checked_add(self.idle).unwrap_or(far);
        let absolute = t.created.checked_add(self.absolute).unwrap_or(far);
        idle.min(absolute)
    }

    /// True when the session is valid at `now`.
    pub fn is_live(&self, t: &SessionTimes, now: MonoTime) -> bool {
        now < self.deadline(t)
    }
}

/// The idle limit of a session.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(3600);
/// The largest number of sessions (one admin, a few browsers).
pub const DEFAULT_MAX_SESSIONS: usize = 64;

/// The times of one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTimes {
    /// The login.
    pub created: MonoTime,
    /// The last request.
    pub last_seen: MonoTime,
}

/// The sessions in memory, with a size limit.
#[derive(Debug, Clone)]
pub struct SessionTable<V> {
    policy: SessionPolicy,
    map: HashMap<[u8; 32], (SessionTimes, V)>,
}

impl<V> SessionTable<V> {
    /// An empty table.
    pub fn new(policy: SessionPolicy) -> Self {
        Self {
            policy,
            map: HashMap::new(),
        }
    }

    /// The policy.
    pub fn policy(&self) -> &SessionPolicy {
        &self.policy
    }

    /// Uses a new policy (for example a new `session_ttl_seconds`). Sessions that the new
    /// policy ends go out at the next touch or purge.
    pub fn set_policy(&mut self, policy: SessionPolicy) {
        self.policy = policy;
    }

    /// The number of sessions (live or not purged yet).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True with no session.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Adds a session. First the expired sessions go out; then, when the table is full, the
    /// session with the oldest last request goes out.
    pub fn insert(&mut self, key: [u8; 32], value: V, now: MonoTime) {
        self.purge(now);
        let max = self.policy.max_sessions.max(1);
        // Each step removes one session, so the loop has at most `len` steps.
        for _ in 0..=self.map.len() {
            if self.map.len() < max {
                break;
            }
            let oldest = self
                .map
                .iter()
                .min_by_key(|(_, (t, _))| t.last_seen)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    self.map.remove(&k);
                }
                None => break,
            }
        }
        self.map.insert(
            key,
            (
                SessionTimes {
                    created: now,
                    last_seen: now,
                },
                value,
            ),
        );
    }

    /// Uses a session: when it is live, its last request becomes `now`, and the function
    /// gives the value and the new deadline. An expired session is removed.
    pub fn touch(&mut self, key: &[u8; 32], now: MonoTime) -> Option<(&V, MonoTime)> {
        let policy = self.policy;
        let live = self
            .map
            .get(key)
            .is_some_and(|(t, _)| policy.is_live(t, now));
        if !live {
            self.map.remove(key);
            return None;
        }
        let (t, v) = self.map.get_mut(key)?;
        t.last_seen = t.last_seen.max(now);
        let deadline = policy.deadline(t);
        Some((v, deadline))
    }

    /// Removes a session. True when it was there.
    pub fn remove(&mut self, key: &[u8; 32]) -> bool {
        self.map.remove(key).is_some()
    }

    /// Removes all sessions.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Removes the expired sessions. Returns the number removed.
    pub fn purge(&mut self, now: MonoTime) -> usize {
        let policy = self.policy;
        let before = self.map.len();
        self.map.retain(|_, (t, _)| policy.is_live(t, now));
        before - self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn t(secs: u64) -> MonoTime {
        MonoTime::from_duration(Duration::from_secs(secs))
    }

    fn policy() -> SessionPolicy {
        SessionPolicy {
            idle: Duration::from_secs(100),
            absolute: Duration::from_secs(1000),
            max_sessions: 3,
        }
    }

    #[test]
    fn idle_and_absolute_limits() {
        let mut table = SessionTable::new(policy());
        table.insert([1; 32], "a", t(0));
        assert_eq!(table.touch(&[1; 32], t(99)).map(|(v, _)| *v), Some("a"));
        // Each request moves the idle limit, until the absolute limit.
        for s in (190..1000).step_by(90) {
            assert!(table.touch(&[1; 32], t(s)).is_some(), "at {s}");
        }
        assert!(table.touch(&[1; 32], t(1000)).is_none());
        assert!(table.is_empty());

        table.insert([2; 32], "b", t(0));
        assert!(table.touch(&[2; 32], t(100)).is_none());
    }

    #[test]
    fn ttl_policy() {
        let p = SessionPolicy::from_ttl_seconds(28_800);
        assert_eq!(p.absolute, Duration::from_secs(28_800));
        assert_eq!(p.idle, DEFAULT_IDLE);
        let short = SessionPolicy::from_ttl_seconds(60);
        assert_eq!(short.idle, Duration::from_secs(60));
    }

    #[test]
    fn full_table_drops_the_oldest() {
        let mut table = SessionTable::new(policy());
        table.insert([1; 32], 1, t(0));
        table.insert([2; 32], 2, t(1));
        table.insert([3; 32], 3, t(2));
        table.touch(&[1; 32], t(3));
        table.insert([4; 32], 4, t(4));
        assert_eq!(table.len(), 3);
        assert!(table.touch(&[2; 32], t(5)).is_none());
        assert!(table.touch(&[1; 32], t(5)).is_some());
        assert!(table.remove(&[4; 32]));
        assert!(!table.remove(&[4; 32]));
    }

    proptest! {
        /// A session is live exactly when the last request is less than `idle` ago and the
        /// login is less than `absolute` ago. The table never has more than the limit.
        #[test]
        fn expiry_matches_the_model(
            touches in prop::collection::vec((0u64..150, any::<bool>()), 1..60),
            idle in 1u64..200,
            absolute in 1u64..2000,
        ) {
            let p = SessionPolicy {
                idle: Duration::from_secs(idle),
                absolute: Duration::from_secs(absolute),
                max_sessions: 4,
            };
            let mut table = SessionTable::new(p);
            table.insert([7; 32], (), t(0));
            let mut now = 0u64;
            let mut last = 0u64;
            let mut alive = true;
            for (dt, other) in touches {
                now += dt;
                if other {
                    // Other sessions fill the table; ours is pushed out only when it is the
                    // oldest, so keep it fresh in the model by touching first.
                    continue;
                }
                let model = alive && now - last < idle && now < absolute;
                let got = table.touch(&[7; 32], t(now)).is_some();
                prop_assert_eq!(got, model, "now {} last {}", now, last);
                if got {
                    last = now;
                } else {
                    alive = false;
                }
                prop_assert!(table.len() <= 4);
            }
        }
    }
}
