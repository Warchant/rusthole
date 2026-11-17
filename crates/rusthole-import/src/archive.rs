//! Reads the entries of a Teleporter zip, with size limits.
//!
//! The reader trusts no size field in the zip. It counts the bytes that it really
//! decompresses, and stops one byte after the limit.

use std::io::{Cursor, Read};

use crate::{ImportError, Limits};

/// Path of the FTL config in the zip.
pub const PIHOLE_TOML: &str = "etc/pihole/pihole.toml";
/// Path of the gravity database in the zip.
pub const GRAVITY_DB: &str = "etc/pihole/gravity.db";
/// Path of the hosts file in the zip.
pub const HOSTS: &str = "etc/hosts";

/// The entries that the import uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TeleporterFiles {
    /// Text of `etc/pihole/pihole.toml`.
    pub pihole_toml: Option<String>,
    /// Bytes of `etc/pihole/gravity.db`.
    pub gravity_db: Option<Vec<u8>>,
    /// Text of `etc/hosts`.
    pub hosts: Option<String>,
    /// Names of the other entries. The import does not read them.
    pub skipped: Vec<String>,
}

/// Removes a leading `/` or `./` from an entry name.
fn normalize(name: &str) -> &str {
    let mut n = name;
    // Two steps are enough for `./` and `/`; a longer prefix is not a Teleporter name.
    for _ in 0..2 {
        n = n
            .strip_prefix("./")
            .or_else(|| n.strip_prefix('/'))
            .unwrap_or(n);
    }
    n
}

/// Reads the Teleporter entries from `bytes`.
pub fn read_teleporter(bytes: &[u8], limits: &Limits) -> Result<TeleporterFiles, ImportError> {
    let mut zip =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| ImportError::Zip(e.to_string()))?;
    if zip.len() > limits.max_entries {
        return Err(ImportError::TooManyEntries {
            limit: limits.max_entries,
        });
    }
    let mut out = TeleporterFiles::default();
    let mut total: u64 = 0;
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|e| ImportError::Zip(e.to_string()))?;
        if entry.is_dir() {
            continue;
        }
        let raw_name = entry
            .name()
            .map_err(|e| ImportError::Zip(e.to_string()))?
            .into_owned();
        let name = normalize(&raw_name);
        let slot = match name {
            PIHOLE_TOML => Slot::PiholeToml,
            GRAVITY_DB => Slot::Gravity,
            HOSTS => Slot::Hosts,
            _ => {
                out.skipped.push(name.to_owned());
                continue;
            }
        };
        let taken = match slot {
            Slot::PiholeToml => out.pihole_toml.is_some(),
            Slot::Gravity => out.gravity_db.is_some(),
            Slot::Hosts => out.hosts.is_some(),
        };
        if taken {
            return Err(ImportError::DuplicateEntry(name.to_owned()));
        }
        let remaining = limits.max_total_size.saturating_sub(total);
        let cap = limits.max_entry_size.min(remaining);
        let mut data = Vec::new();
        (&mut entry)
            .take(cap.saturating_add(1))
            .read_to_end(&mut data)
            .map_err(|e| ImportError::Zip(e.to_string()))?;
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if len > cap {
            return Err(if cap < limits.max_entry_size {
                ImportError::TotalTooLarge {
                    limit: limits.max_total_size,
                }
            } else {
                ImportError::EntryTooLarge {
                    name: name.to_owned(),
                    limit: limits.max_entry_size,
                }
            });
        }
        total = total.saturating_add(len);
        match slot {
            Slot::PiholeToml => {
                out.pihole_toml =
                    Some(String::from_utf8(data).map_err(|_| ImportError::NotUtf8(PIHOLE_TOML))?);
            }
            Slot::Gravity => out.gravity_db = Some(data),
            Slot::Hosts => {
                out.hosts = Some(String::from_utf8(data).map_err(|_| ImportError::NotUtf8(HOSTS))?);
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
enum Slot {
    PiholeToml,
    Gravity,
    Hosts,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::build_zip;

    #[test]
    fn reads_known_entries_and_skips_others() {
        let zip = build_zip(&[
            ("etc/pihole/pihole.toml", b"[dns]\n"),
            ("/etc/hosts", b"192.0.2.1 a\n"),
            ("etc/pihole/dhcp.leases", b"x"),
            ("etc/pihole/gravity.db", b"db"),
        ]);
        let f = read_teleporter(&zip, &Limits::default()).unwrap();
        assert_eq!(f.pihole_toml.as_deref(), Some("[dns]\n"));
        assert_eq!(f.hosts.as_deref(), Some("192.0.2.1 a\n"));
        assert_eq!(f.gravity_db.as_deref(), Some(&b"db"[..]));
        assert_eq!(f.skipped, ["etc/pihole/dhcp.leases"]);
    }

    #[test]
    fn refuses_zip_bomb_entry() {
        let big = vec![0u8; 100_000];
        let zip = build_zip(&[("etc/pihole/gravity.db", &big)]);
        // The compressed zip is small, but the entry is 100 kB.
        assert!(zip.len() < 10_000);
        let limits = Limits {
            max_entry_size: 50_000,
            ..Limits::default()
        };
        assert_eq!(
            read_teleporter(&zip, &limits),
            Err(ImportError::EntryTooLarge {
                name: GRAVITY_DB.into(),
                limit: 50_000
            })
        );
        // Exactly at the limit is accepted.
        let limits = Limits {
            max_entry_size: 100_000,
            ..Limits::default()
        };
        assert!(read_teleporter(&zip, &limits).is_ok());
    }

    #[test]
    fn refuses_total_size() {
        let part = vec![b'a'; 60_000];
        let zip = build_zip(&[
            ("etc/pihole/pihole.toml", &part),
            ("etc/pihole/gravity.db", &part),
        ]);
        let limits = Limits {
            max_entry_size: 100_000,
            max_total_size: 100_000,
            ..Limits::default()
        };
        assert_eq!(
            read_teleporter(&zip, &limits),
            Err(ImportError::TotalTooLarge { limit: 100_000 })
        );
    }

    #[test]
    fn refuses_too_many_entries_and_duplicates() {
        let zip = build_zip(&[("a", b"1"), ("b", b"2"), ("c", b"3")]);
        let limits = Limits {
            max_entries: 2,
            ..Limits::default()
        };
        assert_eq!(
            read_teleporter(&zip, &limits),
            Err(ImportError::TooManyEntries { limit: 2 })
        );
        let zip = build_zip(&[("etc/hosts", b"1"), ("./etc/hosts", b"2")]);
        assert_eq!(
            read_teleporter(&zip, &Limits::default()),
            Err(ImportError::DuplicateEntry(HOSTS.into()))
        );
    }

    #[test]
    fn refuses_garbage_and_non_utf8() {
        assert!(matches!(
            read_teleporter(b"not a zip", &Limits::default()),
            Err(ImportError::Zip(_))
        ));
        let zip = build_zip(&[("etc/hosts", &[0xff, 0xfe])]);
        assert_eq!(
            read_teleporter(&zip, &Limits::default()),
            Err(ImportError::NotUtf8(HOSTS))
        );
    }
}
