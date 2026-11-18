//! The SQLite database of the statistics: schema, migrations, flush, retention, reads and
//! the audit log.
//!
//! See docs/STATS.md for the schema and the write rules. Only the flush transaction and
//! the audit log write to the file. Each committed write transaction increments
//! [`Db::writes`], so a test can prove that nothing writes between two flushes.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params, params_from_iter};
use rusthole_core::stats::agg::Snapshot;
use rusthole_core::stats::policy::{day_of, retention_cutoff_hour, retention_due};
use rusthole_core::stats::query::{
    ClientMeta, Filter, HourMap, NameFilter, PairMap, ReasonMap, TimelineMap, TypeMap, UpstreamMap,
};
use rusthole_core::stats::{Counts, PairKey, Tally, UpstreamTally};

use crate::audit::{AuditEntry, NewAudit};
use crate::{Identity, StoreError};

/// The schema version that this code writes (`PRAGMA user_version`).
pub const SCHEMA_VERSION: i64 = 1;

/// Time that SQLite waits for a lock of another connection.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest number of client addresses in one SQL statement. A filter with more
/// addresses runs one statement for each chunk, and the results are added up.
pub(crate) const MAX_FILTER_CLIENTS: usize = 256;

/// The largest number of (client, name) rows that one read takes from the database.
///
/// The `domains` table gets one row for each new name, and clients send the names. A client
/// that sends random names can add up to 1.44 million names a day with the default rate
/// limit. Without this cap, a 30-day read could put tens of millions of pairs into RAM. A read
/// above the cap gives [`StoreError::TooLarge`]. A home network has far fewer pairs: the
/// size test (20 clients, 2,000 names) gives 40,000.
pub const MAX_QUERY_PAIRS: usize = 250_000;

/// The migrations. Item `i` changes the schema from version `i` to version `i + 1`.
const MIGRATIONS: [&str; 1] = [r"
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE clients (
    id         INTEGER PRIMARY KEY,
    ip         TEXT NOT NULL UNIQUE,
    mac        TEXT,
    name       TEXT,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);

CREATE TABLE domains (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    first_seen INTEGER NOT NULL
);

CREATE TABLE hourly (
    hour_utc   INTEGER NOT NULL,
    client_id  INTEGER NOT NULL,
    domain_id  INTEGER NOT NULL,
    total      INTEGER NOT NULL,
    blocked    INTEGER NOT NULL,
    cached     INTEGER NOT NULL,
    forwarded  INTEGER NOT NULL,
    local      INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (hour_utc, client_id, domain_id)
) WITHOUT ROWID;

CREATE TABLE hourly_types (
    hour_utc INTEGER NOT NULL,
    qtype    INTEGER NOT NULL,
    count    INTEGER NOT NULL,
    PRIMARY KEY (hour_utc, qtype)
) WITHOUT ROWID;

CREATE TABLE hourly_upstreams (
    hour_utc INTEGER NOT NULL,
    upstream TEXT NOT NULL,
    count    INTEGER NOT NULL,
    sum_us   INTEGER NOT NULL,
    PRIMARY KEY (hour_utc, upstream)
) WITHOUT ROWID;

CREATE TABLE hourly_reasons (
    hour_utc INTEGER NOT NULL,
    reason   TEXT NOT NULL,
    count    INTEGER NOT NULL,
    PRIMARY KEY (hour_utc, reason)
) WITHOUT ROWID;

CREATE TABLE timeline (
    bucket    INTEGER PRIMARY KEY,
    total     INTEGER NOT NULL,
    blocked   INTEGER NOT NULL,
    cached    INTEGER NOT NULL,
    forwarded INTEGER NOT NULL,
    local     INTEGER NOT NULL
);

CREATE TABLE audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    actor     TEXT NOT NULL,
    client_ip TEXT,
    ok        INTEGER NOT NULL,
    detail    TEXT
);
CREATE INDEX audit_at ON audit (at);
"];

/// What one flush wrote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlushReport {
    /// Rows written to `hourly`.
    pub hourly_rows: usize,
    /// True when the retention ran in this flush.
    pub retention_ran: bool,
    /// Rows that the retention deleted.
    pub deleted_rows: usize,
}

/// The statistics database.
#[derive(Debug)]
pub struct Db {
    conn: Connection,
    writes: u64,
    last_retention_day: Option<i64>,
}

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// Escapes `%`, `_` and `\` for a `LIKE ... ESCAPE '\'` pattern.
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The mode of a new database file (Unix). SQLite gives the `-wal` and `-shm` files the mode
/// of the main file.
#[cfg(unix)]
pub(crate) const DB_FILE_MODE: u32 = 0o600;

/// Makes the database file with mode 0600 when it is missing, so other local users cannot
/// read the per-client history. Logs a WARN when an existing file can be read by the group
/// or by others (the store does not change the mode of a file that the owner made).
#[cfg(unix)]
fn prepare_private_file(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(DB_FILE_MODE)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let mode = std::fs::metadata(path)?.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "the statistics database can be read by other users; use chmod 600"
                );
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Other OSes: SQLite makes the file with the default access rights.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // The same signature as the Unix function.
fn prepare_private_file(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

impl Db {
    /// Opens (or makes) the database at `path`: WAL mode, `synchronous=NORMAL`, and the
    /// schema migrations.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        prepare_private_file(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            tracing::warn!(mode, "SQLite did not change to WAL mode");
        }
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let mut db = Self {
            conn,
            writes: 0,
            last_retention_day: None,
        };
        db.migrate()?;
        db.last_retention_day = db
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'last_retention_day'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(db)
    }

    /// Runs the migrations from the version in the file to [`SCHEMA_VERSION`]. A file from
    /// a newer version is an error.
    fn migrate(&mut self) -> Result<(), StoreError> {
        let version: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::NewerSchema {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        let start = usize::try_from(version).map_err(|_| StoreError::NewerSchema {
            found: version,
            supported: SCHEMA_VERSION,
        })?;
        if start >= MIGRATIONS.len() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        // One step for each migration: the loop is bounded by MIGRATIONS.len().
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(start) {
            tx.execute_batch(sql)?;
            let next = i64::try_from(i + 1).unwrap_or(SCHEMA_VERSION);
            tx.pragma_update(None, "user_version", next)?;
        }
        tx.commit()?;
        self.writes += 1;
        Ok(())
    }

    /// The number of committed write transactions since the open (migrations, flushes and
    /// audit lines).
    pub fn writes(&self) -> u64 {
        self.writes
    }

    /// The UTC day of the last retention run, or `None` when it never ran.
    pub fn last_retention_day(&self) -> Option<i64> {
        self.last_retention_day
    }

    /// The number of rows that this connection changed (from SQLite).
    pub fn total_changes(&self) -> u64 {
        self.conn.total_changes()
    }

    /// The schema version in the file.
    pub fn schema_version(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?)
    }

    /// Writes a snapshot in one transaction (decision D5). The counts are added to the rows
    /// that are already there. When `retention_due` says so, the same transaction deletes
    /// the rows older than `retention_days`.
    pub fn flush(
        &mut self,
        snap: &Snapshot,
        identities: &HashMap<IpAddr, Identity>,
        now: i64,
        retention_days: u32,
    ) -> Result<FlushReport, StoreError> {
        let mut report = FlushReport::default();
        let run_retention = retention_due(self.last_retention_day, now);
        let tx = self.conn.transaction()?;
        let client_ids = upsert_clients(&tx, snap, identities)?;
        report.hourly_rows = write_hours(&tx, snap, &client_ids)?;
        write_timeline(&tx, snap)?;
        if run_retention {
            report.deleted_rows = delete_old(&tx, now, retention_days)?;
            report.retention_ran = true;
            tx.execute(
                "INSERT INTO meta (key, value) VALUES ('last_retention_day', ?1) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                [day_of(now)],
            )?;
        }
        tx.commit()?;
        self.writes += 1;
        if run_retention {
            self.last_retention_day = Some(day_of(now));
        }
        Ok(report)
    }

    /// Writes one audit line at once, in its own transaction. Returns its id.
    pub fn append_audit(&mut self, a: &NewAudit) -> Result<i64, StoreError> {
        let a = a.clamped();
        self.conn.execute(
            "INSERT INTO audit (at, action, target, actor, client_ip, ok, detail) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                a.at,
                a.action,
                a.target,
                a.actor,
                a.client_ip.map(|ip| ip.to_string()),
                a.ok,
                a.detail
            ],
        )?;
        self.writes += 1;
        Ok(self.conn.last_insert_rowid())
    }

    /// Audit lines, newest first: ids below `before` (when given), actions that start with
    /// `prefix` (when given), at most `limit` lines.
    pub fn audit(
        &self,
        before: Option<i64>,
        prefix: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, at, action, target, actor, client_ip, ok, detail FROM audit \
             WHERE (?1 IS NULL OR id < ?1) \
             AND (?2 IS NULL OR substr(action, 1, length(?2)) = ?2) \
             ORDER BY id DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![before, prefix, to_i64(limit as u64)], |r| {
            let ip: Option<String> = r.get(5)?;
            Ok(AuditEntry {
                id: r.get(0)?,
                at: r.get(1)?,
                action: r.get(2)?,
                target: r.get(3)?,
                actor: r.get(4)?,
                client_ip: ip.and_then(|s| s.parse().ok()),
                ok: r.get(6)?,
                detail: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// All clients in the database.
    pub fn clients(&self) -> Result<Vec<ClientMeta>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT ip, mac, name, first_seen, last_seen FROM clients")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (ip, mac, name, first_seen, last_seen) = row?;
            if let Ok(ip) = ip.parse() {
                out.push(ClientMeta {
                    ip,
                    mac,
                    name,
                    first_seen,
                    last_seen,
                });
            }
        }
        Ok(out)
    }

    /// The SQL texts and the parameters of a filter on clients and names: one statement for
    /// each chunk of [`MAX_FILTER_CLIENTS`] client addresses. The chunks have no common
    /// address, so the caller adds up the results. Gives no statement when the filter can
    /// match no row.
    fn filter_sqls(f: &Filter) -> Vec<(String, Vec<rusqlite::types::Value>)> {
        match &f.clients {
            None => vec![Self::filter_sql(f, None)],
            Some(clients) => {
                let all: Vec<IpAddr> = clients.iter().copied().collect();
                all.chunks(MAX_FILTER_CLIENTS)
                    .map(|chunk| Self::filter_sql(f, Some(chunk)))
                    .collect()
            }
        }
    }

    /// The SQL text and the parameters of a filter, with the client addresses of one chunk
    /// (`None`: all clients).
    fn filter_sql(f: &Filter, clients: Option<&[IpAddr]>) -> (String, Vec<rusqlite::types::Value>) {
        use rusqlite::types::Value;
        let mut sql = String::from("h.hour_utc BETWEEN ?1 AND ?2");
        let mut args = vec![Value::Integer(f.from_hour), Value::Integer(f.to_hour)];
        if let Some(clients) = clients {
            sql.push_str(" AND c.ip IN (");
            for (i, ip) in clients.iter().enumerate() {
                if i > 0 {
                    sql.push_str(", ");
                }
                args.push(Value::Text(ip.to_string()));
                let _ = write!(sql, "?{}", args.len());
            }
            sql.push(')');
        }
        match &f.name {
            None => {}
            Some(NameFilter::Exact(n)) => {
                args.push(Value::Text(n.clone()));
                let _ = write!(sql, " AND d.name = ?{}", args.len());
            }
            Some(NameFilter::Base(b)) => {
                // A pre-filter in SQL; the caller checks the registrable domain in Rust.
                args.push(Value::Text(b.clone()));
                let exact = args.len();
                args.push(Value::Text(format!("%.{}", like_escape(b))));
                let like = args.len();
                let _ = write!(
                    sql,
                    " AND (d.name = ?{exact} OR d.name LIKE ?{like} ESCAPE '\\')"
                );
            }
        }
        (sql, args)
    }

    /// The pairs in the filter, added up over the hours. A read of more than
    /// [`MAX_QUERY_PAIRS`] rows gives [`StoreError::TooLarge`].
    pub fn pairs(&self, f: &Filter) -> Result<PairMap, StoreError> {
        self.pairs_capped(f, MAX_QUERY_PAIRS)
    }

    /// [`Db::pairs`] with a given cap on the rows (tests use a small cap).
    ///
    /// The cap bounds the rows that come into RAM. SQLite still groups all rows of the range
    /// (in its own page cache and temp files) before it gives the first row, so the time of
    /// a read still grows with the rows in the range.
    pub(crate) fn pairs_capped(&self, f: &Filter, cap: usize) -> Result<PairMap, StoreError> {
        let mut out = PairMap::new();
        let mut read: usize = 0;
        for (where_sql, args) in Self::filter_sqls(f) {
            // One row more than the rest of the cap shows that the cap is passed.
            let limit = cap.saturating_sub(read).saturating_add(1);
            let sql = format!(
                "SELECT c.ip, d.name, SUM(h.total), SUM(h.blocked), SUM(h.cached), \
                 SUM(h.forwarded), SUM(h.local), MIN(h.first_seen), MAX(h.last_seen) \
                 FROM hourly h JOIN clients c ON c.id = h.client_id \
                 JOIN domains d ON d.id = h.domain_id \
                 WHERE {where_sql} GROUP BY h.client_id, h.domain_id LIMIT {limit}"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let mut rows = stmt.query(params_from_iter(args))?;
            while let Some(r) = rows.next()? {
                read = read.saturating_add(1);
                if read > cap {
                    return Err(StoreError::TooLarge { limit: cap });
                }
                let ip: String = r.get(0)?;
                let name: String = r.get(1)?;
                let Ok(client) = ip.parse::<IpAddr>() else {
                    continue;
                };
                if !f.matches_name(&name) {
                    continue;
                }
                let t = Tally {
                    counts: Counts {
                        total: to_u64(r.get(2)?),
                        blocked: to_u64(r.get(3)?),
                        cached: to_u64(r.get(4)?),
                        forwarded: to_u64(r.get(5)?),
                        local: to_u64(r.get(6)?),
                    },
                    first_seen: r.get(7)?,
                    last_seen: r.get(8)?,
                };
                let key = PairKey {
                    client,
                    name: name.into_boxed_str(),
                };
                out.entry(key).and_modify(|m| m.add(&t)).or_insert(t);
            }
        }
        Ok(out)
    }

    /// The first query of a name in the stored data (all hours), or `None` when the name
    /// is not in the database.
    pub fn domain_first_seen(&self, name: &str) -> Result<Option<i64>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT first_seen FROM domains WHERE name = ?1",
                [name],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Counts by hour in the filter.
    pub fn hour_counts(&self, f: &Filter) -> Result<HourMap, StoreError> {
        // The map has one item for each hour, so it needs no row cap.
        let mut out = HourMap::new();
        let by_name = matches!(f.name, Some(NameFilter::Base(_)));
        for (where_sql, args) in Self::filter_sqls(f) {
            let sql = format!(
                "SELECT h.hour_utc, {name_col}, SUM(h.total), SUM(h.blocked), SUM(h.cached), \
                 SUM(h.forwarded), SUM(h.local) \
                 FROM hourly h JOIN clients c ON c.id = h.client_id \
                 JOIN domains d ON d.id = h.domain_id \
                 WHERE {where_sql} GROUP BY h.hour_utc{group_name}",
                name_col = if by_name { "d.name" } else { "''" },
                group_name = if by_name { ", h.domain_id" } else { "" },
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let mut rows = stmt.query(params_from_iter(args))?;
            while let Some(r) = rows.next()? {
                if by_name {
                    let name: String = r.get(1)?;
                    if !f.matches_name(&name) {
                        continue;
                    }
                }
                let c = Counts {
                    total: to_u64(r.get(2)?),
                    blocked: to_u64(r.get(3)?),
                    cached: to_u64(r.get(4)?),
                    forwarded: to_u64(r.get(5)?),
                    local: to_u64(r.get(6)?),
                };
                out.entry(r.get(0)?).or_default().add(&c);
            }
        }
        Ok(out)
    }

    /// Query types in the hours `from..=to`.
    pub fn types(&self, from: i64, to: i64) -> Result<TypeMap, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT qtype, SUM(count) FROM hourly_types WHERE hour_utc BETWEEN ?1 AND ?2 \
             GROUP BY qtype",
        )?;
        let rows = stmt.query_map([from, to], |r| Ok((r.get::<_, u16>(0)?, to_u64(r.get(1)?))))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Upstream answers in the hours `from..=to`.
    pub fn upstreams(&self, from: i64, to: i64) -> Result<UpstreamMap, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT upstream, SUM(count), SUM(sum_us) FROM hourly_upstreams \
             WHERE hour_utc BETWEEN ?1 AND ?2 GROUP BY upstream",
        )?;
        let rows = stmt.query_map([from, to], |r| {
            Ok((
                r.get::<_, String>(0)?,
                UpstreamTally {
                    count: to_u64(r.get(1)?),
                    sum_us: to_u64(r.get(2)?),
                },
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Reasons in the hours `from..=to`.
    pub fn reasons(&self, from: i64, to: i64) -> Result<ReasonMap, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT reason, SUM(count) FROM hourly_reasons WHERE hour_utc BETWEEN ?1 AND ?2 \
             GROUP BY reason",
        )?;
        let rows = stmt.query_map([from, to], |r| {
            Ok((r.get::<_, String>(0)?, to_u64(r.get(1)?)))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 10-minute buckets `from..=to`.
    pub fn timeline(&self, from: i64, to: i64) -> Result<TimelineMap, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT bucket, total, blocked, cached, forwarded, local FROM timeline \
             WHERE bucket BETWEEN ?1 AND ?2",
        )?;
        let rows = stmt.query_map([from, to], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                Counts {
                    total: to_u64(r.get(1)?),
                    blocked: to_u64(r.get(2)?),
                    cached: to_u64(r.get(3)?),
                    forwarded: to_u64(r.get(4)?),
                    local: to_u64(r.get(5)?),
                },
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The number of rows in `hourly` (for tests and the size report).
    pub fn hourly_rows(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT count(*) FROM hourly", [], |r| r.get(0))?;
        Ok(to_u64(n))
    }

    /// Runs raw SQL (tests only: to break the schema for a failure test).
    #[cfg(test)]
    pub(crate) fn execute_raw(&self, sql: &str) -> Result<(), StoreError> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    /// Moves the WAL into the main file (for the size report).
    pub fn checkpoint(&self) -> Result<(), StoreError> {
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }
}

/// The ids of all names in a snapshot. Adds the new names. A name gets the first query of
/// the snapshot as `first_seen`; a name that is already there gets a smaller `first_seen`
/// only when the snapshot has an earlier query (this is rare, so the flush seldom rewrites a
/// `domains` row).
fn domain_ids<'a>(
    tx: &Transaction<'_>,
    snap: &'a Snapshot,
) -> Result<HashMap<&'a str, i64>, StoreError> {
    let mut first: HashMap<&'a str, i64> = HashMap::new();
    for bucket in snap.hours.values() {
        for names in bucket.pairs.values() {
            for (name, t) in names {
                first
                    .entry(&**name)
                    .and_modify(|f| *f = (*f).min(t.first_seen))
                    .or_insert(t.first_seen);
            }
        }
    }
    let mut find = tx.prepare("SELECT id, first_seen FROM domains WHERE name = ?1")?;
    let mut add = tx.prepare("INSERT INTO domains (name, first_seen) VALUES (?1, ?2)")?;
    let mut lower = tx.prepare("UPDATE domains SET first_seen = ?2 WHERE id = ?1")?;
    let mut ids = HashMap::with_capacity(first.len());
    for (name, first_seen) in first {
        let found = find
            .query_row([name], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
            .optional()?;
        let id = if let Some((id, stored)) = found {
            if first_seen < stored {
                lower.execute(params![id, first_seen])?;
            }
            id
        } else {
            add.execute(params![name, first_seen])?;
            tx.last_insert_rowid()
        };
        ids.insert(name, id);
    }
    Ok(ids)
}

/// Upserts the hour buckets of a snapshot: the counts are added to the rows that are
/// already there. Returns the number of `hourly` rows written.
fn write_hours(
    tx: &Transaction<'_>,
    snap: &Snapshot,
    client_ids: &HashMap<IpAddr, i64>,
) -> Result<usize, StoreError> {
    let mut rows = 0;
    let domain_ids = domain_ids(tx, snap)?;
    let mut hourly = tx.prepare(
        "INSERT INTO hourly (hour_utc, client_id, domain_id, total, blocked, cached, \
         forwarded, local, first_seen, last_seen) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT (hour_utc, client_id, domain_id) DO UPDATE SET \
         total = total + excluded.total, blocked = blocked + excluded.blocked, \
         cached = cached + excluded.cached, forwarded = forwarded + excluded.forwarded, \
         local = local + excluded.local, \
         first_seen = min(first_seen, excluded.first_seen), \
         last_seen = max(last_seen, excluded.last_seen)",
    )?;
    let mut types = tx.prepare(
        "INSERT INTO hourly_types (hour_utc, qtype, count) VALUES (?1, ?2, ?3) \
         ON CONFLICT (hour_utc, qtype) DO UPDATE SET count = count + excluded.count",
    )?;
    let mut ups = tx.prepare(
        "INSERT INTO hourly_upstreams (hour_utc, upstream, count, sum_us) \
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT (hour_utc, upstream) DO UPDATE SET \
         count = count + excluded.count, sum_us = sum_us + excluded.sum_us",
    )?;
    let mut reasons = tx.prepare(
        "INSERT INTO hourly_reasons (hour_utc, reason, count) VALUES (?1, ?2, ?3) \
         ON CONFLICT (hour_utc, reason) DO UPDATE SET count = count + excluded.count",
    )?;
    for (&hour, bucket) in &snap.hours {
        for (client, names) in &bucket.pairs {
            let Some(&client_id) = client_ids.get(client) else {
                continue;
            };
            for (name, t) in names {
                let Some(&domain_id) = domain_ids.get(&**name) else {
                    continue;
                };
                let c = &t.counts;
                hourly.execute(params![
                    hour,
                    client_id,
                    domain_id,
                    to_i64(c.total),
                    to_i64(c.blocked),
                    to_i64(c.cached),
                    to_i64(c.forwarded),
                    to_i64(c.local),
                    t.first_seen,
                    t.last_seen
                ])?;
                rows += 1;
            }
        }
        for (&qtype, &count) in &bucket.types {
            types.execute(params![hour, qtype, to_i64(count)])?;
        }
        for (up, t) in &bucket.upstreams {
            ups.execute(params![hour, &**up, to_i64(t.count), to_i64(t.sum_us)])?;
        }
        for (reason, &count) in &bucket.reasons {
            reasons.execute(params![hour, &**reason, to_i64(count)])?;
        }
    }
    Ok(rows)
}

/// Upserts the 10-minute buckets of a snapshot.
fn write_timeline(tx: &Transaction<'_>, snap: &Snapshot) -> Result<(), StoreError> {
    let mut timeline = tx.prepare(
        "INSERT INTO timeline (bucket, total, blocked, cached, forwarded, local) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT (bucket) DO UPDATE SET \
         total = total + excluded.total, blocked = blocked + excluded.blocked, \
         cached = cached + excluded.cached, forwarded = forwarded + excluded.forwarded, \
         local = local + excluded.local",
    )?;
    for (&bucket, c) in &snap.timeline {
        timeline.execute(params![
            bucket,
            to_i64(c.total),
            to_i64(c.blocked),
            to_i64(c.cached),
            to_i64(c.forwarded),
            to_i64(c.local)
        ])?;
    }
    Ok(())
}

/// Upserts the clients of a snapshot and the known identities. Returns the id of each
/// client address in the snapshot.
fn upsert_clients(
    tx: &Transaction<'_>,
    snap: &Snapshot,
    identities: &HashMap<IpAddr, Identity>,
) -> Result<HashMap<IpAddr, i64>, StoreError> {
    let mut seen: HashMap<IpAddr, (i64, i64)> = HashMap::new();
    for bucket in snap.hours.values() {
        for (client, names) in &bucket.pairs {
            for t in names.values() {
                seen.entry(*client)
                    .and_modify(|(f, l)| {
                        *f = (*f).min(t.first_seen);
                        *l = (*l).max(t.last_seen);
                    })
                    .or_insert((t.first_seen, t.last_seen));
            }
        }
    }
    let mut ids = HashMap::with_capacity(seen.len());
    let mut upsert = tx.prepare(
        "INSERT INTO clients (ip, mac, name, first_seen, last_seen) VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (ip) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen), \
         last_seen = max(last_seen, excluded.last_seen), \
         mac = coalesce(excluded.mac, mac), name = coalesce(excluded.name, name) \
         RETURNING id",
    )?;
    for (ip, (first, last)) in &seen {
        let id_info = identities.get(ip);
        let id: i64 = upsert.query_row(
            params![
                ip.to_string(),
                id_info.and_then(|i| i.mac.as_deref()),
                id_info.and_then(|i| i.name.as_deref()),
                first,
                last
            ],
            |r| r.get(0),
        )?;
        ids.insert(*ip, id);
    }
    let mut update = tx.prepare(
        "UPDATE clients SET mac = coalesce(?2, mac), name = coalesce(?3, name) WHERE ip = ?1",
    )?;
    for (ip, i) in identities {
        if !seen.contains_key(ip) {
            update.execute(params![ip.to_string(), i.mac.as_deref(), i.name.as_deref()])?;
        }
    }
    Ok(ids)
}

/// Deletes the rows older than the retention. Returns the number of deleted rows.
fn delete_old(tx: &Transaction<'_>, now: i64, retention_days: u32) -> Result<usize, StoreError> {
    let cutoff = retention_cutoff_hour(now, retention_days);
    let cutoff_seconds = cutoff.saturating_mul(rusthole_core::stats::HOUR_SECONDS);
    let mut n = 0;
    for table in [
        "hourly",
        "hourly_types",
        "hourly_upstreams",
        "hourly_reasons",
    ] {
        n += tx.execute(
            &format!("DELETE FROM {table} WHERE hour_utc < ?1"),
            [cutoff],
        )?;
    }
    n += tx.execute(
        "DELETE FROM timeline WHERE bucket < ?1",
        [cutoff_seconds.div_euclid(rusthole_core::stats::TEN_MINUTES)],
    )?;
    n += tx.execute(
        "DELETE FROM domains WHERE id NOT IN (SELECT DISTINCT domain_id FROM hourly)",
        [],
    )?;
    n += tx.execute(
        "DELETE FROM clients WHERE last_seen < ?1 \
         AND id NOT IN (SELECT DISTINCT client_id FROM hourly)",
        [cutoff_seconds],
    )?;
    n += tx.execute("DELETE FROM audit WHERE at < ?1", [cutoff_seconds])?;
    Ok(n)
}
