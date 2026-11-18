//! Statistics store of rusthole (part P4): RAM aggregates, the SQLite flush, recent
//! queries and the audit log.
//!
//! ```mermaid
//! flowchart LR
//!     DNS[DNS path] -->|try_send, never blocks| CH[(bounded channel)]
//!     CH --> W[worker thread]
//!     W -->|apply| RAM[Aggregator + recent ring]
//!     W -->|every flush interval:<br/>one transaction| DB[(stats.db, WAL)]
//!     API[admin API, P5] -->|query| S[Stats]
//!     S --> RAM
//!     S --> DB
//! ```
//!
//! - [`service`]: the worker thread, the [`Recorder`] for the DNS path, and the shutdown.
//! - [`stats`]: the [`Stats`] handle with the query functions for the admin API.
//! - [`db`]: the SQLite schema, the flush, the retention and the reads.
//! - [`audit`]: the audit log.
//!
//! The policy (aggregation, bounds, grouping, paging, flush timing) is pure code in
//! `rusthole_core::stats`. docs/STATS.md describes the schema and the write rules.

pub mod audit;
pub mod db;
pub mod service;
pub mod stats;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use audit::{AuditEntry, AuditParams, NewAudit};
pub use service::{Recorder, ShutdownReport, StatsService};
pub use stats::{ClientDetail, DomainDetailHours, HoursFilter, Stats, StoreCounters};

/// The file name of the database in the data directory.
pub const DB_FILE: &str = "stats.db";
/// The default size of the event channel between the DNS path and the worker.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 65_536;

/// An error of the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// An SQLite error.
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A file system error.
    #[error("cannot use the data directory: {0}")]
    Io(#[from] std::io::Error),
    /// The file has a schema from a newer rusthole version.
    #[error("the database has schema version {found}; this version supports up to {supported}")]
    NewerSchema {
        /// The version in the file.
        found: i64,
        /// The version of this code.
        supported: i64,
    },
    /// A lock was not free in its time limit (a flush or a long query runs).
    #[error("the statistics store is busy; try again")]
    Busy,
    /// A read needs more rows than the store takes into RAM (see
    /// [`db::MAX_QUERY_PAIRS`]). Use a shorter range or a filter.
    #[error("the statistics query needs more than {limit} rows; use a shorter range or a filter")]
    TooLarge {
        /// The row cap.
        limit: usize,
    },
    /// The cursor is not valid.
    #[error(transparent)]
    Cursor(#[from] rusthole_core::stats::page::CursorError),
    /// The worker thread could not start.
    #[error("cannot start the statistics thread: {0}")]
    Thread(String),
}

/// What other parts know about a client address (MAC from the neighbor table, a name from
/// the config, conditional forwarding or local records).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// The MAC address (lower case, colon form).
    pub mac: Option<String>,
    /// The name.
    pub name: Option<String>,
}

/// Settings of the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsSettings {
    /// The database file. `None` keeps all data in RAM only (the store never opens a file).
    pub db_path: Option<PathBuf>,
    /// The time between two flushes.
    pub flush_interval: Duration,
    /// Days of history.
    pub retention_days: u32,
    /// The size of the recent-query ring.
    pub recent_queries: usize,
    /// The bound on the keys in RAM between two flushes.
    pub max_keys: usize,
    /// The size of the event channel.
    pub channel_capacity: usize,
}

impl StatsSettings {
    /// Settings from the `[stats]` section and the data directory. A flush interval of 0
    /// gives RAM-only mode.
    pub fn from_config(stats: &rusthole_core::config::Stats, data_dir: &Path) -> Self {
        let ram_only = stats.flush_interval_seconds == 0;
        Self {
            db_path: (!ram_only).then(|| data_dir.join(DB_FILE)),
            flush_interval: Duration::from_secs(u64::from(stats.flush_interval_seconds)),
            retention_days: stats.retention_days,
            recent_queries: usize::try_from(stats.recent_queries).unwrap_or(usize::MAX),
            max_keys: rusthole_core::stats::agg::DEFAULT_MAX_KEYS,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }

    /// RAM-only settings with defaults (for tests and tools).
    pub fn ram_only() -> Self {
        Self::from_config(
            &rusthole_core::config::Stats {
                flush_interval_seconds: 0,
                ..rusthole_core::config::Stats::default()
            },
            Path::new("."),
        )
    }
}

/// The wall-clock time in Unix seconds. Only for timestamps that people read (the hour
/// buckets); durations use a monotonic clock.
pub fn wall_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    }
}
