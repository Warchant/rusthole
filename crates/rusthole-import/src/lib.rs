//! Pi-hole v6 Teleporter import.
//!
//! The import has two layers:
//!
//! - An I/O layer reads the zip ([`archive`]) and the SQLite database ([`gravity`]) into plain
//!   structs. It has limits on sizes and row counts, so a hostile file cannot use all memory.
//! - A pure layer ([`map_gravity`], [`map_pihole_toml`], [`map_hosts`]) changes these structs
//!   into a rusthole [`Config`] and an [`ImportReport`]. Property tests cover it.
//!
//! The import never copies or prints a password hash, a TOTP secret or an app password.
//!
//! ```mermaid
//! flowchart LR
//!     zip[Teleporter zip] --> archive
//!     archive -->|gravity.db bytes| gravity
//!     archive -->|pihole.toml text| ptoml[map_pihole_toml]
//!     archive -->|etc/hosts text| hosts[map_hosts]
//!     gravity -->|Gravity| mapg[map_gravity]
//!     mapg --> cfg[Config + ImportReport]
//!     ptoml --> cfg
//!     hosts --> cfg
//! ```

pub mod archive;
pub mod gravity;
mod map_gravity;
mod map_hosts;
mod map_pihole_toml;
mod report;

#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use gravity::Gravity;
pub use map_gravity::{map_gravity, sanitize_group_name};
pub use map_hosts::map_hosts;
pub use map_pihole_toml::map_pihole_toml;
pub use report::ImportReport;
use rusthole_core::Config;

/// Limits for one import. They stop a zip bomb or a very large database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of entries in the zip.
    pub max_entries: usize,
    /// Maximum uncompressed size of one entry that the import reads, in bytes.
    pub max_entry_size: u64,
    /// Maximum uncompressed size of all entries that the import reads, in bytes.
    pub max_total_size: u64,
    /// Maximum number of rows that the import reads from one table.
    pub max_rows: usize,
    /// Maximum number of SQLite virtual machine steps for all reads of `gravity.db`,
    /// in thousands. It gives each read a fixed bound, also for a hostile file.
    pub max_sqlite_ksteps: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 1000,
            max_entry_size: 256 * 1024 * 1024,
            max_total_size: 512 * 1024 * 1024,
            max_rows: 100_000,
            // A full read of 100 000 rows in each table takes far less than this.
            max_sqlite_ksteps: 2_000_000,
        }
    }
}

/// Why an import failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    #[error("the file is not a valid zip archive: {0}")]
    Zip(String),
    #[error("the zip has more than {limit} entries")]
    TooManyEntries { limit: usize },
    #[error("zip entry {name:?} is larger than {limit} bytes when uncompressed")]
    EntryTooLarge { name: String, limit: u64 },
    #[error("the zip entries are larger than {limit} bytes in total when uncompressed")]
    TotalTooLarge { limit: u64 },
    #[error("zip entry {0:?} occurs more than once")]
    DuplicateEntry(String),
    #[error("the zip has no {0:?}; is this a Pi-hole v6 Teleporter export?")]
    MissingEntry(&'static str),
    #[error("zip entry {0:?} is not UTF-8 text")]
    NotUtf8(&'static str),
    #[error("gravity.db cannot be read: {0}")]
    Sqlite(String),
    #[error("gravity.db has no table {0:?}; is this a Pi-hole v6 export?")]
    MissingTable(&'static str),
    #[error("gravity.db table {table:?} has more than {limit} rows")]
    TooManyRows { table: &'static str, limit: usize },
    #[error("gravity.db table {table:?} is not a plain table: {why}")]
    UnsafeTable {
        table: &'static str,
        why: &'static str,
    },
    #[error("reading gravity.db took more than {limit} thousand SQLite steps")]
    SqliteBudget { limit: u64 },
    #[error("pihole.toml is not valid TOML: {0}")]
    PiholeToml(String),
}

/// The result of an import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    /// The new config.
    pub config: Config,
    /// What the import did with each item.
    pub report: ImportReport,
}

/// Reads a Teleporter zip and returns a rusthole config and a report.
///
/// The function starts from [`Config::default`]. It applies `pihole.toml`, then `gravity.db`,
/// then `etc/hosts`.
pub fn import_teleporter(zip_bytes: &[u8], limits: &Limits) -> Result<Imported, ImportError> {
    let files = archive::read_teleporter(zip_bytes, limits)?;
    let mut config = Config::default();
    let mut report = ImportReport::default();
    for name in &files.skipped {
        report.ignore(format!("zip entry {name}: not used by rusthole"));
    }
    match &files.pihole_toml {
        Some(text) => map_pihole_toml(text, &mut config, &mut report)?,
        None => report.report(format!(
            "zip has no {}: settings keep the rusthole defaults",
            archive::PIHOLE_TOML
        )),
    }
    let gravity_bytes = files
        .gravity_db
        .as_deref()
        .ok_or(ImportError::MissingEntry(archive::GRAVITY_DB))?;
    let gravity = gravity::read_gravity(gravity_bytes, limits)?;
    map_gravity(&gravity, &mut config, &mut report);
    if let Some(text) = &files.hosts {
        map_hosts(text, &mut config, &mut report);
    }
    Ok(Imported { config, report })
}

#[cfg(test)]
mod tests;
