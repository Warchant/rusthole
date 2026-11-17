//! Synthetic Teleporter exports for tests, fuzz seeds and the `write_fixture` example.
//!
//! All names and addresses are synthetic: domains under `example`, MAC addresses with the
//! locally administered prefix `02:00:00`, IP addresses from `192.0.2.0/24` and `2001:db8::/32`.
//! The password hash is a fake string with the Pi-hole format.

// Test support code: a failure here is a bug in the test setup, so a panic is the right result.
#![allow(clippy::expect_used, clippy::missing_panics_doc)]

use std::io::{Cursor, Write};

use rusqlite::{Connection, MAIN_DB, params};
use zip::write::SimpleFileOptions;

use crate::gravity::{AdlistRow, ClientRow, DomainRow, Gravity, GroupRow};

/// Pi-hole v6 `gravity.db` schema: the tables and columns that the import reads, plus a few
/// other columns, so that the import does not depend on the column order. It also has a view
/// and a trigger, as a real file has, so the tests prove that the SQLite limits of the import
/// accept such a schema.
pub const SCHEMA: &str = r#"
CREATE TABLE "group" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    name TEXT UNIQUE NOT NULL,
    date_added INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)),
    date_modified INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)),
    description TEXT
);
CREATE TABLE adlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    date_added INTEGER NOT NULL DEFAULT 0,
    date_modified INTEGER NOT NULL DEFAULT 0,
    comment TEXT,
    date_updated INTEGER,
    number INTEGER NOT NULL DEFAULT 0,
    invalid_domains INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 0,
    abp_entries INTEGER NOT NULL DEFAULT 0,
    type INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE adlist_by_group (
    adlist_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (adlist_id, group_id)
);
CREATE TABLE domainlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type INTEGER NOT NULL DEFAULT 0,
    domain TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    date_added INTEGER NOT NULL DEFAULT 0,
    date_modified INTEGER NOT NULL DEFAULT 0,
    comment TEXT
);
CREATE TABLE domainlist_by_group (
    domainlist_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (domainlist_id, group_id)
);
CREATE TABLE client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    date_added INTEGER NOT NULL DEFAULT 0,
    date_modified INTEGER NOT NULL DEFAULT 0,
    comment TEXT
);
CREATE TABLE client_by_group (
    client_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (client_id, group_id)
);
CREATE TABLE gravity (domain TEXT NOT NULL, adlist_id INTEGER NOT NULL);
CREATE VIEW vw_adlist AS SELECT DISTINCT address, adlist.id AS id
    FROM adlist
    LEFT JOIN adlist_by_group ON adlist_by_group.adlist_id = adlist.id
    LEFT JOIN "group" ON "group".id = adlist_by_group.group_id
    WHERE adlist.enabled = 1 AND (adlist_by_group.group_id IS NULL OR "group".enabled = 1)
    ORDER BY adlist.id;
CREATE TRIGGER tr_adlist_update AFTER UPDATE OF address, enabled, comment ON adlist
    BEGIN
      UPDATE adlist SET date_modified = (cast(strftime('%s', 'now') as int)) WHERE id = NEW.id;
    END;
"#;

/// Builds a `gravity.db` file in memory from `g` and returns its bytes.
pub fn build_gravity_db(g: &Gravity) -> Vec<u8> {
    let mut conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch(SCHEMA).expect("create schema");
    {
        let tx = conn.transaction().expect("begin");
        for r in &g.groups {
            tx.execute(
                r#"INSERT INTO "group"(id, enabled, name, description) VALUES (?1, ?2, ?3, ?4)"#,
                params![r.id, r.enabled, r.name, r.description],
            )
            .expect("insert group");
        }
        for r in &g.adlists {
            tx.execute(
                "INSERT INTO adlist(id, address, enabled, comment, type) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![r.id, r.address, r.enabled, r.comment, r.kind],
            )
            .expect("insert adlist");
        }
        for r in &g.domainlist {
            tx.execute(
                "INSERT INTO domainlist(id, type, domain, enabled, comment) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![r.id, r.kind, r.domain, r.enabled, r.comment],
            )
            .expect("insert domainlist");
        }
        for r in &g.clients {
            tx.execute(
                "INSERT INTO client(id, ip, comment) VALUES (?1, ?2, ?3)",
                params![r.id, r.ip, r.comment],
            )
            .expect("insert client");
        }
        for (table, col, pairs) in [
            ("adlist_by_group", "adlist_id", &g.adlist_by_group),
            (
                "domainlist_by_group",
                "domainlist_id",
                &g.domainlist_by_group,
            ),
            ("client_by_group", "client_id", &g.client_by_group),
        ] {
            let sql = format!("INSERT INTO {table}({col}, group_id) VALUES (?1, ?2)");
            for (item, group) in pairs {
                tx.execute(&sql, params![item, group]).expect("insert link");
            }
        }
        tx.commit().expect("commit");
    }
    conn.serialize(MAIN_DB).expect("serialize").to_vec()
}

/// Builds a zip (deflate) with the given entries.
pub fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in entries {
        zip.start_file(*name, options).expect("start zip entry");
        zip.write_all(data).expect("write zip entry");
    }
    zip.finish().expect("finish zip").into_inner()
}

/// The 9 block lists of the home fixture. List 7 is disabled.
pub const HOME_ADLISTS: usize = 9;

/// Gravity content in the shape of a real home setup (see docs/PLAN.md section 2).
///
/// - 2 groups: Default (id 0) and "Kids" (id 1).
/// - 9 block lists, 1 disabled, all in Default only. Kids has no list.
/// - 5 exact allow, 20 exact deny, 9 regex deny rules, all in Default.
/// - 13 clients: 12 by MAC, 1 by IP. Clients 12 and 13 are only in Kids.
pub fn home_gravity() -> Gravity {
    let groups = vec![
        GroupRow {
            id: 0,
            enabled: true,
            name: "Default".into(),
            description: Some("The default group".into()),
        },
        GroupRow {
            id: 1,
            enabled: true,
            name: "Kids".into(),
            description: Some("Tablets".into()),
        },
    ];
    let adlists = (1..=9)
        .map(|i| AdlistRow {
            id: i,
            address: format!("https://lists{i}.example/hosts.txt"),
            enabled: i != 7,
            comment: (i % 2 == 0).then(|| format!("list {i}")),
            kind: 0,
        })
        .collect::<Vec<_>>();
    let mut domainlist = Vec::new();
    let mut id = 0;
    let mut push = |kind: i64, domain: String, comment: Option<String>| {
        id += 1;
        domainlist.push(DomainRow {
            id,
            kind,
            domain,
            enabled: true,
            comment,
        });
    };
    for i in 1..=5 {
        push(0, format!("cdn{i}.example.org"), Some("needed".into()));
    }
    for i in 1..=20 {
        push(1, format!("tracker{i}.example.net"), None);
    }
    for re in HOME_REGEXES {
        push(3, (*re).to_owned(), None);
    }
    let clients = (1..=13)
        .map(|i| ClientRow {
            id: i,
            ip: if i == 13 {
                "192.0.2.13".to_owned()
            } else {
                format!("02:00:00:00:00:{i:02X}")
            },
            comment: Some(format!("device {i}")),
        })
        .collect::<Vec<_>>();
    let client_by_group = (1..=13).map(|i| (i, i64::from(i >= 12))).collect();
    Gravity {
        adlist_by_group: adlists.iter().map(|a| (a.id, 0)).collect(),
        domainlist_by_group: domainlist.iter().map(|d| (d.id, 0)).collect(),
        groups,
        adlists,
        domainlist,
        clients,
        client_by_group,
    }
}

/// The 9 regex deny rules of the home fixture. None uses a Pi-hole extension.
pub const HOME_REGEXES: [&str; 9] = [
    r"(\.|^)example\.com$",
    r"ads\d+\.example",
    r"^track(er)?[0-9]*\.",
    r"(\.|^)telemetry\.example\.net$",
    r"^ad[sv]?\.",
    r"(\.|^)clicks\.example$",
    r"^pixel\.",
    r"(\.|^)metrics\.example\.org$",
    r"^analytics[0-9]*\.example\.",
];

/// A fake password hash in the Pi-hole format. It is not a hash of a real password.
pub const FAKE_PWHASH: &str =
    "$BALLOON-SHA256$v=1$s=1024,t=32$ZmFrZXNhbHRmYWtlc2FsdA==$ZmFrZWhhc2hmYWtlaGFzaA==";

/// `pihole.toml` of the home fixture.
pub fn home_pihole_toml() -> String {
    format!(
        r#"# Pi-hole configuration file (synthetic)
[dns]
upstreams = ["192.0.2.53", "192.0.2.54", "2001:db8::53", "2001:db8::54"]
interface = ""
listeningMode = "LOCAL"
queryLogging = true
dnssec = true
hosts = []
cnameRecords = []
revServers = []

[dns.cache]
size = 10000

[dns.blocking]
active = true
mode = "NULL"

[dns.rateLimit]
count = 1000
interval = 60

[dhcp]
active = false

[webserver]
port = "80o,443os,[::]:80o,[::]:443os"

[webserver.api]
pwhash = "{FAKE_PWHASH}"
totp_secret = ""
app_pwhash = ""
"#
    )
}

/// `etc/hosts` of the home fixture: system entries and one LAN host.
pub const HOME_HOSTS: &str = "\
127.0.0.1\tlocalhost
::1\tlocalhost ip6-localhost ip6-loopback
ff02::1\tip6-allnodes
ff02::2\tip6-allrouters
127.0.1.1\tpihole
192.0.2.10\tnas.lan
";

/// The full home fixture as a Teleporter zip.
pub fn home_zip() -> Vec<u8> {
    let db = build_gravity_db(&home_gravity());
    let toml = home_pihole_toml();
    build_zip(&[
        ("etc/pihole/pihole.toml", toml.as_bytes()),
        ("etc/pihole/gravity.db", &db),
        ("etc/hosts", HOME_HOSTS.as_bytes()),
        ("etc/pihole/dhcp.leases", b""),
    ])
}
