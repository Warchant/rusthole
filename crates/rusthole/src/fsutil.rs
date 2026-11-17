//! File helpers: bounded reads and atomic writes.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// Reads at most `limit` bytes. A larger file is an error.
pub(crate) fn read_limited(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut data)?;
    if u64::try_from(data.len()).unwrap_or(u64::MAX) > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the file is larger than {limit} bytes"),
        ));
    }
    Ok(data)
}

/// Writes `data` to `path` atomically.
///
/// The function writes a temp file in the same directory, flushes it to disk, and renames it
/// to `path`. On Unix, it gives the file mode 0600 and flushes the directory. Without
/// `overwrite`, an existing `path` is an error and stays as it is. On each error path, the
/// temp file is removed (`NamedTempFile` removes it when it is dropped).
pub(crate) fn write_atomic(path: &Path, data: &[u8], overwrite: bool) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut tmp = tempfile::Builder::new()
        .prefix(".rusthole-")
        .suffix(".tmp")
        .tempfile_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    if overwrite {
        tmp.persist(path).map_err(|e| e.error)?;
    } else {
        tmp.persist_noclobber(path).map_err(|e| e.error)?;
    }
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temp directory under the target directory, not under the system temp directory.
    fn scratch() -> tempfile::TempDir {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-tmp");
        std::fs::create_dir_all(&base).unwrap();
        tempfile::tempdir_in(base).unwrap()
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn writes_and_refuses_to_clobber() {
        let dir = scratch();
        let path = dir.path().join("a.toml");
        write_atomic(&path, b"one", false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        let err = write_atomic(&path, b"two", false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        // The give-up path removed its temp file.
        assert_eq!(entries(dir.path()), ["a.toml"]);
        write_atomic(&path, b"three", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"three");
        assert_eq!(entries(dir.path()), ["a.toml"]);
    }

    #[test]
    fn missing_directory_is_an_error() {
        let dir = scratch();
        let path = dir.path().join("no/such/dir/a.toml");
        assert!(write_atomic(&path, b"x", false).is_err());
        assert_eq!(entries(dir.path()), Vec::<String>::new());
    }

    #[cfg(unix)]
    #[test]
    fn file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let path = dir.path().join("secret.toml");
        // Some file systems (for example a Windows drive in WSL) keep no Unix mode.
        // Skip the check there; CI runs it on a real Linux file system.
        let probe = dir.path().join("probe");
        std::fs::write(&probe, b"x").unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o640)).unwrap();
        if std::fs::metadata(&probe).unwrap().permissions().mode() & 0o777 != 0o640 {
            return;
        }
        write_atomic(&path, b"x", false).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn read_limit() {
        let dir = scratch();
        let path = dir.path().join("big");
        std::fs::write(&path, [0u8; 11]).unwrap();
        assert!(read_limited(&path, 10).is_err());
        assert_eq!(read_limited(&path, 11).unwrap().len(), 11);
    }
}
