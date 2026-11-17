//! Reads the Pi-hole v6 `gravity.db` from memory into plain structs.
//!
//! The database is opened from the bytes in memory, read-only. No temp file is written.
//! The file is untrusted, so the reader follows the SQLite advice for such files
//! (<https://sqlite.org/security.html>):
//!
//! - It sets low SQLite limits (value length, SQL length, expression depth, columns) and the
//!   `DEFENSIVE` flag before it reads the schema.
//! - It turns off triggers, views and functions from the schema (`trusted_schema = OFF`).
//! - It accepts each name only when it is a real table: not a view, not a virtual table, and
//!   with no generated or hidden column. A generated column can compute a very large value on
//!   each read.
//! - A progress handler stops all reads after a fixed number of VM steps
//!   ([`Limits::max_sqlite_ksteps`]). So each read has a bound, also for a costly query plan.
//! - It reads at most `max_rows + 1` rows from each table.

use rusqlite::config::DbConfig;
use rusqlite::limits::Limit;
use rusqlite::{Connection, ErrorCode, MAIN_DB, OpenFlags};

use crate::{ImportError, Limits};

/// SQLite limits for an untrusted `gravity.db`. The real Pi-hole schema is far below each one.
const SQLITE_LIMITS: [(Limit, i32); 7] = [
    // Largest string, blob or row: 1 MiB. A domain or a URL is much smaller.
    (Limit::SQLITE_LIMIT_LENGTH, 1 << 20),
    // Largest SQL statement, also in the schema: 100 KiB.
    (Limit::SQLITE_LIMIT_SQL_LENGTH, 100 * 1024),
    (Limit::SQLITE_LIMIT_EXPR_DEPTH, 100),
    (Limit::SQLITE_LIMIT_COLUMN, 100),
    (Limit::SQLITE_LIMIT_COMPOUND_SELECT, 50),
    (Limit::SQLITE_LIMIT_ATTACHED, 0),
    (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 1),
];

/// VM steps between two calls of the progress handler.
const STEPS_PER_TICK: i32 = 1000;

/// One row of table `group`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    /// Pi-hole group ID. ID 0 is the Default group.
    pub id: i64,
    /// True when the group is enabled.
    pub enabled: bool,
    /// Group name.
    pub name: String,
    /// Free text.
    pub description: Option<String>,
}

/// One row of table `adlist`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdlistRow {
    /// Pi-hole list ID.
    pub id: i64,
    /// List URL.
    pub address: String,
    /// True when the list is enabled.
    pub enabled: bool,
    /// Free text.
    pub comment: Option<String>,
    /// 0 = block list, 1 = allow list.
    pub kind: i64,
}

/// One row of table `domainlist`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRow {
    /// Pi-hole rule ID.
    pub id: i64,
    /// 0 = exact allow, 1 = exact deny, 2 = regex allow, 3 = regex deny.
    pub kind: i64,
    /// Domain name or regex.
    pub domain: String,
    /// True when the rule is enabled.
    pub enabled: bool,
    /// Free text.
    pub comment: Option<String>,
}

/// One row of table `client`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRow {
    /// Pi-hole client ID.
    pub id: i64,
    /// IP address, CIDR block, MAC address, host name or `:interface`.
    pub ip: String,
    /// Free text.
    pub comment: Option<String>,
}

/// The content of `gravity.db` that the import uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gravity {
    /// Table `group`.
    pub groups: Vec<GroupRow>,
    /// Table `adlist`.
    pub adlists: Vec<AdlistRow>,
    /// Table `adlist_by_group`: (list ID, group ID).
    pub adlist_by_group: Vec<(i64, i64)>,
    /// Table `domainlist`.
    pub domainlist: Vec<DomainRow>,
    /// Table `domainlist_by_group`: (rule ID, group ID).
    pub domainlist_by_group: Vec<(i64, i64)>,
    /// Table `client`.
    pub clients: Vec<ClientRow>,
    /// Table `client_by_group`: (client ID, group ID).
    pub client_by_group: Vec<(i64, i64)>,
}

fn sql_err(e: &rusqlite::Error, limits: &Limits) -> ImportError {
    if e.sqlite_error_code() == Some(ErrorCode::OperationInterrupted) {
        return ImportError::SqliteBudget {
            limit: limits.max_sqlite_ksteps,
        };
    }
    ImportError::Sqlite(e.to_string())
}

/// Opens an empty in-memory connection with the limits and flags for an untrusted file.
fn hardened_connection(limits: &Limits) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open_in_memory_with_flags(
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    for (limit, value) in SQLITE_LIMITS {
        conn.set_limit(limit, value)?;
    }
    for (flag, on) in [
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false),
    ] {
        conn.set_db_config(flag, on)?;
    }
    // SQLite calls the handler each STEPS_PER_TICK VM steps of one statement. The handler
    // counts the calls of all statements and stops the read when the budget is used up. The
    // reader runs a fixed number of statements, so all reads together take at most
    // (budget + 1 + statements) * STEPS_PER_TICK steps.
    let budget = limits.max_sqlite_ksteps;
    let mut ticks: u64 = 0;
    conn.progress_handler(
        STEPS_PER_TICK,
        Some(move || {
            ticks = ticks.saturating_add(1);
            ticks > budget
        }),
    )?;
    Ok(conn)
}

/// Opens `bytes` as a read-only SQLite database in memory and reads the tables.
pub fn read_gravity(bytes: &[u8], limits: &Limits) -> Result<Gravity, ImportError> {
    if bytes.is_empty() {
        return Err(ImportError::Sqlite("the database file is empty".into()));
    }
    let image = rollback_mode_image(bytes);
    let mut conn = hardened_connection(limits).map_err(|e| sql_err(&e, limits))?;
    conn.deserialize_read_exact(MAIN_DB, image.as_slice(), image.len(), true)
        .map_err(|e| sql_err(&e, limits))?;
    // Refuse each write.
    conn.pragma_update(None, "query_only", true)
        .map_err(|e| sql_err(&e, limits))?;

    let reader = Reader {
        conn: &conn,
        limits,
    };
    Ok(Gravity {
        groups: reader.rows(
            "group",
            r#"SELECT id, enabled, name, description FROM "group" ORDER BY id LIMIT ?1"#,
            |r| {
                Ok(GroupRow {
                    id: r.get(0)?,
                    enabled: r.get(1)?,
                    name: r.get(2)?,
                    description: r.get(3)?,
                })
            },
        )?,
        adlists: reader.rows(
            "adlist",
            "SELECT id, address, enabled, comment, type FROM adlist ORDER BY id LIMIT ?1",
            |r| {
                Ok(AdlistRow {
                    id: r.get(0)?,
                    address: r.get(1)?,
                    enabled: r.get(2)?,
                    comment: r.get(3)?,
                    kind: r.get(4)?,
                })
            },
        )?,
        adlist_by_group: reader.links("adlist_by_group", "adlist_id")?,
        domainlist: reader.rows(
            "domainlist",
            "SELECT id, type, domain, enabled, comment FROM domainlist ORDER BY id LIMIT ?1",
            |r| {
                Ok(DomainRow {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    domain: r.get(2)?,
                    enabled: r.get(3)?,
                    comment: r.get(4)?,
                })
            },
        )?,
        domainlist_by_group: reader.links("domainlist_by_group", "domainlist_id")?,
        clients: reader.rows(
            "client",
            "SELECT id, ip, comment FROM client ORDER BY id LIMIT ?1",
            |r| {
                Ok(ClientRow {
                    id: r.get(0)?,
                    ip: r.get(1)?,
                    comment: r.get(2)?,
                })
            },
        )?,
        client_by_group: reader.links("client_by_group", "client_id")?,
    })
}

/// Offsets of the file format version bytes in the SQLite header (write and read version).
const HEADER_VERSION_BYTES: [usize; 2] = [18, 19];

/// Returns a copy of the database image in rollback-journal mode.
///
/// Pi-hole keeps `gravity.db` in WAL mode, and the version bytes of a WAL file are 2.
/// `sqlite3_deserialize` cannot open a WAL image (`SQLITE_CANTOPEN`). The SQLite docs say to
/// set both bytes to 1. The import opens the copy read-only, so this change is safe.
fn rollback_mode_image(bytes: &[u8]) -> Vec<u8> {
    let mut image = bytes.to_vec();
    let is_wal = HEADER_VERSION_BYTES
        .iter()
        .all(|&i| image.get(i).copied() == Some(2));
    if is_wal {
        for i in HEADER_VERSION_BYTES {
            if let Some(b) = image.get_mut(i) {
                *b = 1;
            }
        }
    }
    image
}

struct Reader<'c> {
    conn: &'c Connection,
    limits: &'c Limits,
}

impl Reader<'_> {
    fn err(&self, e: &rusqlite::Error) -> ImportError {
        sql_err(e, self.limits)
    }

    /// Fails unless `table` is a plain table in the main schema: not a view, not a virtual
    /// table, and with no generated or hidden column.
    fn require_table(&self, table: &'static str) -> Result<(), ImportError> {
        let kind: Option<String> = self
            .conn
            .query_row(
                "SELECT type FROM pragma_table_list WHERE schema = 'main' AND name = ?1",
                [table],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(self.err(&other)),
            })?;
        match kind.as_deref() {
            Some("table") => {}
            Some("virtual") => {
                return Err(ImportError::UnsafeTable {
                    table,
                    why: "it is a virtual table",
                });
            }
            _ => return Err(ImportError::MissingTable(table)),
        }
        let hidden: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM pragma_table_xinfo(?1) WHERE hidden <> 0",
                [table],
                |r| r.get(0),
            )
            .map_err(|e| self.err(&e))?;
        if hidden != 0 {
            return Err(ImportError::UnsafeTable {
                table,
                why: "it has a generated or hidden column",
            });
        }
        Ok(())
    }

    fn rows<T>(
        &self,
        table: &'static str,
        sql: &str,
        map: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Vec<T>, ImportError> {
        self.require_table(table)?;
        let max_rows = self.limits.max_rows;
        let limit = i64::try_from(max_rows.saturating_add(1)).unwrap_or(i64::MAX);
        let mut stmt = self.conn.prepare(sql).map_err(|e| self.err(&e))?;
        let out = stmt
            .query_map([limit], map)
            .map_err(|e| self.err(&e))?
            .collect::<Result<Vec<T>, _>>()
            .map_err(|e| self.err(&e))?;
        if out.len() > max_rows {
            return Err(ImportError::TooManyRows {
                table,
                limit: max_rows,
            });
        }
        Ok(out)
    }

    fn links(
        &self,
        table: &'static str,
        id_column: &'static str,
    ) -> Result<Vec<(i64, i64)>, ImportError> {
        // `table` and `id_column` are constants of this file, never input.
        let sql = format!(
            "SELECT {id_column}, group_id FROM {table} ORDER BY {id_column}, group_id LIMIT ?1"
        );
        self.rows(table, &sql, |r| Ok((r.get(0)?, r.get(1)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{SCHEMA, build_gravity_db, home_gravity};

    #[test]
    fn round_trip_through_sqlite() {
        let g = home_gravity();
        let bytes = build_gravity_db(&g);
        assert_eq!(read_gravity(&bytes, &Limits::default()).unwrap(), g);
    }

    #[test]
    fn opens_a_wal_mode_database() {
        let g = home_gravity();
        let mut bytes = build_gravity_db(&g);
        // A Pi-hole gravity.db is in WAL mode: both version bytes of the header are 2.
        bytes[18] = 2;
        bytes[19] = 2;
        assert_eq!(read_gravity(&bytes, &Limits::default()).unwrap(), g);
    }

    #[test]
    fn row_limit() {
        let g = home_gravity();
        let bytes = build_gravity_db(&g);
        let limits = Limits {
            max_rows: 19,
            ..Limits::default()
        };
        assert!(matches!(
            read_gravity(&bytes, &limits),
            Err(ImportError::TooManyRows { .. })
        ));
    }

    #[test]
    fn step_budget_stops_the_read() {
        // SQLite calls the handler only inside a statement, each STEPS_PER_TICK steps. So the
        // fixture needs a table with many rows: 5000 rules take far more than 2000 steps.
        let mut g = home_gravity();
        for id in 100..5100 {
            g.domainlist.push(crate::gravity::DomainRow {
                id,
                kind: 1,
                domain: format!("d{id}.example"),
                enabled: true,
                comment: None,
            });
        }
        let bytes = build_gravity_db(&g);
        for ksteps in [0, 1] {
            let limits = Limits {
                max_sqlite_ksteps: ksteps,
                ..Limits::default()
            };
            assert_eq!(
                read_gravity(&bytes, &limits),
                Err(ImportError::SqliteBudget { limit: ksteps })
            );
        }
        // The default budget is large enough for this fixture.
        assert_eq!(read_gravity(&bytes, &Limits::default()), Ok(g));
    }

    #[test]
    fn refuses_garbage_and_missing_tables() {
        assert!(matches!(
            read_gravity(b"", &Limits::default()),
            Err(ImportError::Sqlite(_))
        ));
        assert!(matches!(
            read_gravity(b"this is not sqlite at all", &Limits::default()),
            Err(ImportError::Sqlite(_))
        ));
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"CREATE TABLE "group"(id INTEGER, enabled BOOLEAN, name TEXT, description TEXT);"#,
        )
        .unwrap();
        let bytes = conn.serialize(MAIN_DB).unwrap().to_vec();
        assert_eq!(
            read_gravity(&bytes, &Limits::default()),
            Err(ImportError::MissingTable("adlist"))
        );
    }

    #[test]
    fn refuses_a_view_in_place_of_a_table() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"CREATE VIEW "group" AS SELECT 0 AS id, 1 AS enabled, 'x' AS name, NULL AS description;"#,
        )
        .unwrap();
        let mut conn = conn;
        let bytes = conn.serialize(MAIN_DB).unwrap().to_vec();
        assert_eq!(
            read_gravity(&bytes, &Limits::default()),
            Err(ImportError::MissingTable("group"))
        );
    }

    /// Builds a database from the full test schema, with table `domainlist` replaced by
    /// `domainlist_sql`, and runs `fill` on it.
    fn schema_with_domainlist(domainlist_sql: &str, fill: &str) -> Vec<u8> {
        let (before, rest) = SCHEMA.split_once("CREATE TABLE domainlist (").unwrap();
        let (_, after) = rest.split_once(");").unwrap();
        let schema = format!("{before}{domainlist_sql}{after}");
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&schema).unwrap();
        conn.execute_batch(fill).unwrap();
        conn.serialize(MAIN_DB).unwrap().to_vec()
    }

    #[test]
    fn refuses_a_generated_column() {
        // Each read of such a column can compute a very large value from a small file.
        let bytes = schema_with_domainlist(
            "CREATE TABLE domainlist (id INTEGER PRIMARY KEY, type INTEGER, enabled BOOLEAN, \
             comment TEXT, domain TEXT AS (printf('%.*c', 999999999, 'x')) VIRTUAL);",
            "INSERT INTO domainlist(id, type, enabled) VALUES (1, 1, 1);",
        );
        assert_eq!(
            read_gravity(&bytes, &Limits::default()),
            Err(ImportError::UnsafeTable {
                table: "domainlist",
                why: "it has a generated or hidden column",
            })
        );
    }

    #[test]
    fn refuses_a_virtual_table() {
        let bytes = schema_with_domainlist(
            "CREATE VIRTUAL TABLE domainlist USING fts5(id, type, domain, enabled, comment);",
            "INSERT INTO domainlist VALUES (1, 1, 'x.example', 1, NULL);",
        );
        assert_eq!(
            read_gravity(&bytes, &Limits::default()),
            Err(ImportError::UnsafeTable {
                table: "domainlist",
                why: "it is a virtual table",
            })
        );
    }

    #[test]
    fn refuses_a_value_above_the_length_limit() {
        let bytes = schema_with_domainlist(
            "CREATE TABLE domainlist (id INTEGER PRIMARY KEY, type INTEGER, domain TEXT, \
             enabled BOOLEAN, comment TEXT);",
            "INSERT INTO domainlist VALUES (1, 1, printf('%.*c', 2000000, 'x'), 1, NULL);",
        );
        match read_gravity(&bytes, &Limits::default()) {
            Err(ImportError::Sqlite(why)) => assert!(why.contains("too big"), "{why}"),
            other => panic!("expected a SQLite error, got {other:?}"),
        }
    }
}
