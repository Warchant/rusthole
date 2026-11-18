//! File helpers for TLS files: bounded reads, atomic writes with a file mode, a private
//! directory, and the file-mode check (amendment A7).
//!
//! On Windows (development only), the functions do not set or check Unix modes. Windows
//! has no such modes; its access control lists are out of scope.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::SystemTime;

use crate::error::TlsError;

/// Mode of a private key file.
pub const KEY_MODE: u32 = 0o600;
/// Mode of a certificate file. A certificate is public.
pub const CERT_MODE: u32 = 0o644;
/// Mode of the TLS directory.
pub const DIR_MODE: u32 = 0o700;

/// Reads at most `limit` bytes from `path`. A larger file is an error.
///
/// `Ok(None)` means that the file does not exist.
pub fn read_limited(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, TlsError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(TlsError::Read {
                path: path.to_owned(),
                source,
            });
        }
    };
    let mut data = Vec::new();
    let take = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    file.take(take)
        .read_to_end(&mut data)
        .map_err(|source| TlsError::Read {
            path: path.to_owned(),
            source,
        })?;
    if data.len() > limit {
        return Err(TlsError::TooLarge {
            what: path.display().to_string(),
            limit,
        });
    }
    Ok(Some(data))
}

/// Like [`read_limited`], but a missing file is an error.
pub fn read_required(path: &Path, limit: usize) -> Result<Vec<u8>, TlsError> {
    read_limited(path, limit)?.ok_or_else(|| TlsError::Read {
        path: path.to_owned(),
        source: io::Error::new(io::ErrorKind::NotFound, "the file does not exist"),
    })
}

/// Writes `data` to `path` atomically, with Unix mode `mode`.
///
/// The function writes a temp file in the same directory, sets its mode, writes the data,
/// flushes it to disk, renames it to `path`, and flushes the directory. An existing file at
/// `path` is replaced. On each error path, the temp file is removed (`NamedTempFile` removes
/// it when it is dropped).
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<(), TlsError> {
    let werr = |source: io::Error| TlsError::Write {
        path: path.to_owned(),
        source,
    };
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut tmp = tempfile::Builder::new()
        .prefix(".rusthole-tls-")
        .suffix(".tmp")
        .tempfile_in(dir)
        .map_err(werr)?;
    // Windows has no Unix modes (see the module documentation).
    #[cfg(unix)]
    set_mode(tmp.as_file(), mode).map_err(werr)?;
    #[cfg(not(unix))]
    let _ = mode;
    tmp.write_all(data).map_err(werr)?;
    tmp.as_file().sync_all().map_err(werr)?;
    tmp.persist(path).map_err(|e| werr(e.error))?;
    // Windows cannot open a directory as a file to flush it.
    #[cfg(unix)]
    sync_dir(dir).map_err(werr)?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Makes the directory `dir` (and its parents) and gives `dir` mode 0700.
pub fn ensure_private_dir(dir: &Path) -> Result<(), TlsError> {
    let werr = |source: io::Error| TlsError::Write {
        path: dir.to_owned(),
        source,
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        builder.mode(DIR_MODE);
        builder.create(dir).map_err(werr)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_MODE)).map_err(werr)?;
    }
    #[cfg(not(unix))]
    builder.create(dir).map_err(werr)?;
    Ok(())
}

/// Returns the Unix mode of a key file when the group or others can read or write it.
///
/// `None` means that the mode is safe, that the file has no mode (Windows), or that the
/// file cannot be read. The caller logs a WARN for `Some`.
pub fn key_mode_too_open(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
        (mode & 0o077 != 0).then_some(mode)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// The size and the modification time of a file. A change of either one means that the
/// file changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStamp {
    /// Size in bytes.
    pub len: u64,
    /// Modification time.
    pub modified: Option<SystemTime>,
}

/// Reads the stamp of `path`.
pub fn file_stamp(path: &Path) -> Result<FileStamp, TlsError> {
    let meta = std::fs::metadata(path).map_err(|source| TlsError::Read {
        path: path.to_owned(),
        source,
    })?;
    Ok(FileStamp {
        len: meta.len(),
        modified: meta.modified().ok(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A temp directory under `target/test-tmp`, not under the system temp directory
    /// (drive C is nearly full).
    ///
    /// `RUSTHOLE_TEST_TMP` sets another base. The file-mode tests use
    /// [`scratch_keeping_modes`].
    pub(crate) fn scratch() -> tempfile::TempDir {
        let base = std::env::var_os("RUSTHOLE_TEST_TMP").map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-tmp"),
            std::path::PathBuf::from,
        );
        std::fs::create_dir_all(&base).unwrap();
        tempfile::tempdir_in(base).unwrap()
    }

    /// A temp directory on a file system that keeps Unix modes, for the file-mode tests.
    ///
    /// A Windows drive in WSL keeps no Unix modes. Thus the function tries the base of
    /// [`scratch`] first, then `/dev/shm/rusthole-test` (a RAM file system), then the system
    /// temp directory. When no base keeps modes, it prints a skip message and gives `None`.
    #[cfg(unix)]
    pub(crate) fn scratch_keeping_modes(test: &str) -> Option<tempfile::TempDir> {
        let first = scratch();
        if keeps_modes(first.path()) {
            return Some(first);
        }
        for base in [
            std::path::PathBuf::from("/dev/shm/rusthole-test"),
            std::env::temp_dir().join("rusthole-test"),
        ] {
            if std::fs::create_dir_all(&base).is_err() {
                continue;
            }
            if let Ok(dir) = tempfile::tempdir_in(&base)
                && keeps_modes(dir.path())
            {
                return Some(dir);
            }
        }
        eprintln!("SKIP {test}: no temp file system keeps Unix modes");
        None
    }

    pub(crate) fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// Tells if the file system of `dir` keeps Unix modes. A Windows drive in WSL does not.
    #[cfg(unix)]
    pub(crate) fn keeps_modes(dir: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        let probe = dir.join("probe");
        std::fs::write(&probe, b"x").unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o640)).unwrap();
        let ok = std::fs::metadata(&probe).unwrap().permissions().mode() & 0o777 == 0o640;
        std::fs::remove_file(&probe).unwrap();
        ok
    }

    #[test]
    fn write_read_and_replace() {
        let dir = scratch();
        let path = dir.path().join("a.pem");
        assert!(read_limited(&path, 10).unwrap().is_none());
        assert!(read_required(&path, 10).is_err());
        write_atomic(&path, b"one", KEY_MODE).unwrap();
        assert_eq!(read_limited(&path, 10).unwrap().unwrap(), b"one");
        write_atomic(&path, b"two", KEY_MODE).unwrap();
        assert_eq!(read_required(&path, 10).unwrap(), b"two");
        assert_eq!(entries(dir.path()), ["a.pem"]);
        assert!(matches!(
            read_limited(&path, 2),
            Err(TlsError::TooLarge { .. })
        ));
    }

    #[test]
    fn failed_write_leaves_no_temp_file() {
        let dir = scratch();
        let path = dir.path().join("no/such/dir/a.pem");
        assert!(matches!(
            write_atomic(&path, b"x", KEY_MODE),
            Err(TlsError::Write { .. })
        ));
        assert_eq!(entries(dir.path()), Vec::<String>::new());
        // A directory at the target path: the rename fails, and the temp file goes away.
        let target = dir.path().join("taken");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("inside"), b"x").unwrap();
        assert!(write_atomic(&target, b"x", KEY_MODE).is_err());
        assert_eq!(entries(dir.path()), ["taken"]);
    }

    #[test]
    fn private_dir_is_made() {
        let dir = scratch();
        let tls = dir.path().join("data/tls");
        ensure_private_dir(&tls).unwrap();
        ensure_private_dir(&tls).unwrap();
        assert!(tls.is_dir());
        #[cfg(unix)]
        if let Some(dir) = scratch_keeping_modes("private_dir_is_made") {
            use std::os::unix::fs::PermissionsExt;
            let tls = dir.path().join("data/tls");
            ensure_private_dir(&tls).unwrap();
            let mode = std::fs::metadata(&tls).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, DIR_MODE);
        }
    }

    #[cfg(unix)]
    #[test]
    fn key_file_mode_is_0600_and_open_mode_is_found() {
        use std::os::unix::fs::PermissionsExt;
        let Some(dir) = scratch_keeping_modes("key_file_mode_is_0600_and_open_mode_is_found")
        else {
            return;
        };
        let path = dir.path().join("k.pem");
        write_atomic(&path, b"x", KEY_MODE).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(key_mode_too_open(&path), None);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(key_mode_too_open(&path), Some(0o640));
    }

    #[test]
    fn stamp_changes_with_content() {
        let dir = scratch();
        let path = dir.path().join("s");
        std::fs::write(&path, b"1").unwrap();
        let a = file_stamp(&path).unwrap();
        std::fs::write(&path, b"22").unwrap();
        assert_ne!(file_stamp(&path).unwrap(), a);
        assert!(file_stamp(&dir.path().join("none")).is_err());
    }
}
