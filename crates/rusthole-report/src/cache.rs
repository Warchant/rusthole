//! The RAM cache of section results (docs/PLAN.md R-D11). Pure: the caller gives the
//! monotonic time.

use std::collections::HashMap;
use std::time::Duration;

use rusthole_core::blocking_state::MonoTime;

use crate::model::{Section, SectionReport, Status};

/// The most entries in the cache.
pub const MAX_ENTRIES: usize = 1024;
/// How long an `ok` or `unavailable` result stays.
pub const OK_TTL: Duration = Duration::from_hours(1);
/// How long a `failed` result stays, so a click does not ask a slow source again at once.
pub const FAILED_TTL: Duration = Duration::from_mins(5);

/// The key of an entry: the section and the name.
pub type Key = (Section, String);

/// How long a result with `status` stays in the cache. `None`: do not keep it.
pub const fn ttl(_section: Section, status: Status) -> Option<Duration> {
    match status {
        Status::Ok | Status::Unavailable => Some(OK_TTL),
        Status::Failed => Some(FAILED_TTL),
        // `off` depends on the setting, not on the name.
        Status::Off => None,
    }
}

#[derive(Debug, Clone)]
struct Entry {
    report: SectionReport,
    expires: MonoTime,
}

/// A bounded cache with a time to live for each entry.
#[derive(Debug, Default)]
pub struct Cache {
    map: HashMap<Key, Entry>,
}

impl Cache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of entries (live or expired).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when the cache has no entry.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The result for `key` when it is not expired at `now`.
    pub fn get(&self, key: &Key, now: MonoTime) -> Option<SectionReport> {
        self.map
            .get(key)
            .filter(|e| e.expires > now)
            .map(|e| e.report.clone())
    }

    /// Keeps `report` from `now` for its time to live. When the cache is full, it removes
    /// the expired entries first, then the entry that expires first.
    pub fn put(&mut self, key: Key, report: SectionReport, now: MonoTime) {
        let Some(ttl) = ttl(report.section, report.outcome.status) else {
            self.map.remove(&key);
            return;
        };
        let Some(expires) = now.checked_add(ttl) else {
            return;
        };
        if !self.map.contains_key(&key) && self.map.len() >= MAX_ENTRIES {
            self.map.retain(|_, e| e.expires > now);
            if self.map.len() >= MAX_ENTRIES
                && let Some(oldest) = self
                    .map
                    .iter()
                    .min_by_key(|(_, e)| e.expires)
                    .map(|(k, _)| k.clone())
            {
                self.map.remove(&oldest);
            }
        }
        self.map.insert(key, Entry { report, expires });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests: a failure is a test failure.
mod tests {
    use proptest::prelude::*;
    use serde_json::Value;

    use super::*;
    use crate::model::Outcome;

    fn report(name: &str, status: Status) -> SectionReport {
        SectionReport {
            section: Section::Dns,
            name: name.to_owned(),
            outcome: Outcome {
                status,
                data: Value::Null,
                error: None,
            },
            cached: false,
            fetched_at: 0,
        }
    }

    fn at(secs: u64) -> MonoTime {
        MonoTime::from_duration(Duration::from_secs(secs))
    }

    fn key(name: &str) -> Key {
        (Section::Dns, name.to_owned())
    }

    #[test]
    fn ok_lives_one_hour_and_failed_five_minutes() {
        let mut c = Cache::new();
        c.put(key("a.test"), report("a.test", Status::Ok), at(100));
        c.put(key("b.test"), report("b.test", Status::Failed), at(100));
        assert!(c.get(&key("a.test"), at(100 + 3599)).is_some());
        assert!(c.get(&key("a.test"), at(100 + 3600)).is_none());
        assert!(c.get(&key("b.test"), at(100 + 299)).is_some());
        assert!(c.get(&key("b.test"), at(100 + 300)).is_none());
    }

    #[test]
    fn off_is_never_kept_and_removes_the_old_entry() {
        let mut c = Cache::new();
        c.put(key("a.test"), report("a.test", Status::Ok), at(0));
        c.put(key("a.test"), report("a.test", Status::Off), at(1));
        assert!(c.get(&key("a.test"), at(2)).is_none());
        assert!(c.is_empty());
    }

    #[test]
    fn a_full_cache_drops_the_entry_that_expires_first() {
        let mut c = Cache::new();
        // The first entry is a failure: it expires first.
        c.put(
            key("first.test"),
            report("first.test", Status::Failed),
            at(0),
        );
        for i in 1..MAX_ENTRIES {
            c.put(key(&format!("n{i}.test")), report("x", Status::Ok), at(0));
        }
        assert_eq!(c.len(), MAX_ENTRIES);
        c.put(key("new.test"), report("new.test", Status::Ok), at(1));
        assert_eq!(c.len(), MAX_ENTRIES);
        assert!(c.get(&key("first.test"), at(1)).is_none());
        assert!(c.get(&key("new.test"), at(1)).is_some());
        assert!(c.get(&key("n1.test"), at(1)).is_some());
    }

    proptest! {
        /// The cache never holds more than MAX_ENTRIES, and the last put of a kept status
        /// is always readable at the same time.
        #[test]
        fn bounded_and_last_put_readable(
            ops in proptest::collection::vec((0u16..3000, 0u8..3, 0u64..20_000), 1..3000)
        ) {
            let mut c = Cache::new();
            let mut now = 0u64;
            for (n, s, dt) in ops {
                now += dt;
                let status = match s { 0 => Status::Ok, 1 => Status::Failed, _ => Status::Unavailable };
                let k = key(&format!("n{n}.test"));
                c.put(k.clone(), report("x", status), at(now));
                prop_assert!(c.len() <= MAX_ENTRIES);
                prop_assert!(c.get(&k, at(now)).is_some());
            }
        }
    }
}
