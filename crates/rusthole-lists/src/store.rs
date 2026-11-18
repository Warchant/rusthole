//! The disk cache of the lists (decision D5): `<data_dir>/lists/<list-id>.txt` (the raw
//! body) and `<data_dir>/lists/<list-id>.json` (the metadata, see
//! [`ListMeta`](rusthole_core::refresh::ListMeta)).
//!
//! Each write is atomic: a temp file in the same directory, write, fsync, rename, and (on
//! Unix) an fsync of the directory. A reader thus sees the old file or the new file, never a
//! part of a file. These functions block: call them on a blocking thread.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use rusthole_core::refresh::meta::MAX_META_BYTES;
use rusthole_core::refresh::{ListMeta, MetaError, parse_meta, render_meta};

/// The name of the cache directory in the data directory.
pub const LISTS_DIR: &str = "lists";

/// The result of a metadata read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaLoad {
    /// No metadata file.
    Missing,
    /// The file cannot be read or used. The caller logs a WARN and fetches the list again.
    Corrupt(String),
    /// The metadata.
    Found(ListMeta),
}

/// The list cache directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskCache {
    dir: PathBuf,
}

impl DiskCache {
    /// The cache in `<data_dir>/lists`.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join(LISTS_DIR),
        }
    }

    /// The cache directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Makes the cache directory and its parents.
    pub fn ensure_dir(&self) -> io::Result<()> {
        fs::create_dir_all(&self.dir)
    }

    /// The path of the body file of list `id`.
    pub fn body_path(&self, id: u32) -> PathBuf {
        self.dir.join(format!("{id}.txt"))
    }

    /// The path of the metadata file of list `id`.
    pub fn meta_path(&self, id: u32) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Reads the metadata of list `id`. Never panics; a bad file gives
    /// [`MetaLoad::Corrupt`].
    pub fn load_meta(&self, id: u32) -> MetaLoad {
        match read_limited(&self.meta_path(id), MAX_META_BYTES as u64) {
            Ok(None) => MetaLoad::Missing,
            Ok(Some(bytes)) => match parse_meta(&bytes) {
                Ok(m) => MetaLoad::Found(m),
                Err(e) => MetaLoad::Corrupt(e.to_string()),
            },
            Err(ReadError::TooLarge) => MetaLoad::Corrupt(
                MetaError::TooLarge {
                    limit: MAX_META_BYTES,
                }
                .to_string(),
            ),
            Err(ReadError::Io(e)) => MetaLoad::Corrupt(e.to_string()),
        }
    }

    /// Reads the body of list `id`, at most `limit` bytes. `Ok(None)`: no file.
    pub fn read_body(&self, id: u32, limit: u64) -> Result<Option<Vec<u8>>, ReadError> {
        read_limited(&self.body_path(id), limit)
    }

    /// Writes the body of list `id` atomically.
    pub fn write_body(&self, id: u32, body: &[u8]) -> io::Result<()> {
        write_atomic(&self.dir, &self.body_path(id), body)
    }

    /// Writes the metadata of list `id` atomically.
    pub fn write_meta(&self, id: u32, meta: &ListMeta) -> io::Result<()> {
        write_atomic(&self.dir, &self.meta_path(id), &render_meta(meta))
    }

    /// Removes both files of list `id`. A missing file is not an error.
    pub fn remove(&self, id: u32) -> io::Result<()> {
        for path in [self.body_path(id), self.meta_path(id)] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Why a bounded read failed.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The file is larger than the limit.
    #[error("the file is larger than the limit")]
    TooLarge,
    /// An I/O error.
    #[error("{0}")]
    Io(#[from] io::Error),
}

/// Reads at most `limit` bytes of `path`. A larger file gives [`ReadError::TooLarge`].
/// `Ok(None)`: the file does not exist.
pub fn read_limited(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, ReadError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let size_hint = file.metadata().map_or(0, |m| m.len());
    if size_hint > limit {
        return Err(ReadError::TooLarge);
    }
    let mut out = Vec::with_capacity(usize::try_from(size_hint).unwrap_or(0));
    // Read one byte more than the limit, to find a file that grew after the size check.
    file.take(limit.saturating_add(1)).read_to_end(&mut out)?;
    if out.len() as u64 > limit {
        return Err(ReadError::TooLarge);
    }
    Ok(Some(out))
}

/// Writes `data` to `path` atomically: temp file in `dir`, write, fsync, rename, fsync of
/// the directory (Unix). On an error, the temp file is removed (`NamedTempFile` removes it
/// when it is dropped) and the old file stays.
pub fn write_atomic(dir: &Path, path: &Path, data: &[u8]) -> io::Result<()> {
    let mut tmp = tempfile::Builder::new().prefix(".tmp-").tempfile_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn write_read_and_remove() {
        let dir = temp();
        let cache = DiskCache::new(dir.path());
        cache.ensure_dir().unwrap();
        assert_eq!(cache.load_meta(1), MetaLoad::Missing);
        assert!(cache.read_body(1, 100).unwrap().is_none());

        cache.write_body(1, b"a.example\n").unwrap();
        let meta = ListMeta::new("http://lists.example/1");
        cache.write_meta(1, &meta).unwrap();
        assert_eq!(cache.load_meta(1), MetaLoad::Found(meta));
        assert_eq!(cache.read_body(1, 100).unwrap().unwrap(), b"a.example\n");
        // The limit is exact.
        assert!(cache.read_body(1, 10).unwrap().is_some());
        assert!(matches!(cache.read_body(1, 9), Err(ReadError::TooLarge)));

        // No temp file stays.
        let names: Vec<_> = fs::read_dir(cache.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");

        cache.remove(1).unwrap();
        cache.remove(1).unwrap();
        assert_eq!(cache.load_meta(1), MetaLoad::Missing);
    }

    #[test]
    fn corrupt_meta_is_reported() {
        let dir = temp();
        let cache = DiskCache::new(dir.path());
        cache.ensure_dir().unwrap();
        fs::write(cache.meta_path(2), b"{ not json").unwrap();
        assert!(matches!(cache.load_meta(2), MetaLoad::Corrupt(_)));
        fs::write(cache.meta_path(2), vec![b' '; MAX_META_BYTES + 1]).unwrap();
        assert!(matches!(cache.load_meta(2), MetaLoad::Corrupt(_)));
    }

    #[test]
    fn failed_write_keeps_the_old_file() {
        let dir = temp();
        let cache = DiskCache::new(dir.path());
        cache.ensure_dir().unwrap();
        cache.write_body(3, b"old").unwrap();
        // The temp directory does not exist: the write fails, the old file stays.
        let err = write_atomic(&dir.path().join("missing"), &cache.body_path(3), b"new");
        assert!(err.is_err());
        assert_eq!(fs::read(cache.body_path(3)).unwrap(), b"old");
    }
}
