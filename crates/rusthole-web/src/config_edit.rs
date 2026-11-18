//! Safe writes of `rusthole.toml` (decision D2, amendment A7).
//!
//! ```mermaid
//! flowchart LR
//!     read[read file + SHA-256] -->|hash differs| conflict[409 config_conflict, reload]
//!     read -->|hash same| edit[change a copy of the Config]
//!     edit --> validate[Config::validate]
//!     validate --> render[toml_edit: change only the values that changed]
//!     render --> check[parse the new text again: same Config?]
//!     check --> write[temp file, fsync, rename, fsync dir, mode 0600]
//! ```
//!
//! [`render`] keeps comments, key order and formatting: it compares the old and the new
//! config value by value and changes only the TOML items that differ. Items of an array of
//! tables (`[[rules]]`, ...) are matched by their stable id, so a comment above a rule stays
//! with that rule.
//!
//! The parser error text of `toml_edit` can quote the source line, which can hold a secret.
//! This module never returns or logs it: it uses [`toml_error_text`] or a fixed text.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rusthole_core::Config;
use rusthole_core::config::{ConfigIssue, toml_error_text};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, TableLike, Value};

use crate::error::{ApiError, FieldError};
use crate::util::sha256;

/// The largest config file that rusthole reads.
pub const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
/// Time limit to get the writer lock.
pub const WRITE_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
/// Time limit for the file I/O of one write.
pub const WRITE_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a config text cannot be rendered.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// The file text is not valid TOML. The text never quotes the file.
    #[error("the config file is not valid TOML: {0}")]
    Parse(String),
    /// The config cannot be written as TOML values.
    #[error("the config cannot be written as TOML: {0}")]
    Serialize(String),
    /// The new text does not parse back to the new config (a bug). Nothing was written.
    #[error("the new config text does not give the same config; nothing was written")]
    Mismatch,
}

/// The key that names an item of an array of tables, for matching old and new items.
fn id_key(array: &str) -> Option<&'static str> {
    match array {
        "clients" => Some("uid"),
        "rules"
        | "groups"
        | "adlists"
        | "records"
        | "cnames"
        | "conditional_forwarding"
        | "api_tokens" => Some("id"),
        _ => None,
    }
}

/// Changes the TOML text `text` so that it gives `new`.
///
/// - `file`: the config that `text` gives (parsed from `text`, no ids added).
/// - `mem`: the config in memory: `file` plus the ids that [`Config::assign_ids`] gave. It
///   names the items of `file` by id.
/// - `new`: the wanted config.
///
/// Only the values that differ between `file` and `new` change in the text. The function
/// checks that the result parses to `new`.
pub fn render(
    text: &str,
    file: &Config,
    mem: &Config,
    new: &Config,
) -> Result<String, RenderError> {
    let mut doc: DocumentMut = text.parse().map_err(|_: toml_edit::TomlError| {
        // Never show the toml_edit error: its text can quote the line. The toml error goes
        // through `toml_error_text`, which hides the text.
        RenderError::Parse(if let Err(te) = toml::from_str::<toml::Table>(text) {
            toml_error_text(text, &te)
        } else {
            "the file cannot be edited".to_owned()
        })
    })?;
    let to_value =
        |c: &Config| toml::Value::try_from(c).map_err(|e| RenderError::Serialize(e.to_string()));
    let (file_v, mem_v, new_v) = (to_value(file)?, to_value(mem)?, to_value(new)?);
    if let (Some(f), Some(m), Some(n)) = (file_v.as_table(), mem_v.as_table(), new_v.as_table()) {
        sync_table(doc.as_table_mut(), f, Some(m), n, "");
    }
    let out = doc.to_string();
    let mut reparsed = Config::from_toml_str(&out).map_err(|_| RenderError::Mismatch)?;
    // Ids that the API did not write yet are given in memory again, as at load.
    reparsed.assign_ids();
    let mut want = new.clone();
    want.assign_ids();
    if reparsed != want {
        return Err(RenderError::Mismatch);
    }
    Ok(out)
}

fn sync_table(
    t: &mut dyn TableLike,
    old: &toml::Table,
    mem: Option<&toml::Table>,
    new: &toml::Table,
    name: &str,
) {
    for (k, nv) in new {
        let mv = mem.and_then(|m| m.get(k));
        match (t.get_mut(k), old.get(k)) {
            (Some(item), Some(ov)) => sync_item(item, ov, mv, nv, k),
            (Some(item), None) => replace(item, nv),
            // A default value that the file does not write and that did not change.
            (None, Some(ov)) if ov == nv => {}
            (None, Some(toml::Value::Table(ot))) if nv.is_table() => {
                // A section that the file does not write: add only the changed keys.
                let mut fresh = Table::new();
                if let Some(nt) = nv.as_table() {
                    sync_table(&mut fresh, ot, mv.and_then(toml::Value::as_table), nt, k);
                }
                if !fresh.is_empty() {
                    t.insert(k, Item::Table(fresh));
                }
            }
            (None, _) => {
                if let Some(item) = to_item(nv) {
                    t.insert(k, item);
                }
            }
        }
    }
    let gone: Vec<String> = old
        .keys()
        .filter(|k| !new.contains_key(k.as_str()))
        .cloned()
        .collect();
    for k in gone {
        t.remove(&k);
    }
    let _ = name;
}

fn sync_item(
    item: &mut Item,
    old: &toml::Value,
    mem: Option<&toml::Value>,
    new: &toml::Value,
    name: &str,
) {
    // The ids that the API adds are in `new` but not in `old`; `mem` has them. A value that
    // did not change keeps its text as it is.
    if old == new {
        return;
    }
    match (item, old, new) {
        (Item::Table(t), toml::Value::Table(ot), toml::Value::Table(nt)) => {
            sync_table(t, ot, mem.and_then(toml::Value::as_table), nt, name);
        }
        (Item::ArrayOfTables(aot), toml::Value::Array(oa), toml::Value::Array(na))
            if na.iter().all(toml::Value::is_table) =>
        {
            sync_aot(aot, oa, mem.and_then(toml::Value::as_array), na, name);
        }
        (item, _, new) => replace(item, new),
    }
}

fn int_of(v: &toml::Value, key: &str) -> Option<i64> {
    v.as_table()?.get(key)?.as_integer()
}

fn sync_aot(
    aot: &mut ArrayOfTables,
    old: &[toml::Value],
    mem: Option<&Vec<toml::Value>>,
    new: &[toml::Value],
    name: &str,
) {
    let key = id_key(name);
    let old_ids: Vec<Option<i64>> = (0..old.len())
        .map(|i| {
            key.and_then(|k| {
                mem.and_then(|m| m.get(i))
                    .and_then(|v| int_of(v, k))
                    .or_else(|| old.get(i).and_then(|v| int_of(v, k)))
            })
        })
        .collect();
    let mut used = vec![false; old.len()];
    let mut tables: Vec<Table> = Vec::with_capacity(new.len());
    let empty = toml::Table::new();
    for (j, nv) in new.iter().enumerate() {
        let new_id = key.and_then(|k| int_of(nv, k));
        let found = match new_id {
            Some(id) => old_ids.iter().position(|o| *o == Some(id)),
            None => old
                .iter()
                .enumerate()
                .position(|(i, ov)| ov == nv && !used.get(i).copied().unwrap_or(true))
                .or_else(|| (j < old.len() && key.is_none()).then_some(j)),
        };
        let found = found.filter(|i| !used.get(*i).copied().unwrap_or(true));
        let nt = nv.as_table().unwrap_or(&empty);
        match found.and_then(|i| aot.get(i).cloned().map(|t| (i, t))) {
            Some((i, mut t)) => {
                if let Some(u) = used.get_mut(i) {
                    *u = true;
                }
                let ot = old.get(i).and_then(toml::Value::as_table).unwrap_or(&empty);
                let mt = mem.and_then(|m| m.get(i)).and_then(toml::Value::as_table);
                sync_table(&mut t, ot, mt, nt, name);
                tables.push(t);
            }
            None => tables.push(new_table(nt)),
        }
    }
    aot.clear();
    for t in tables {
        aot.push(t);
    }
}

/// Replaces an item with a new value. A plain value keeps its comment decor.
fn replace(item: &mut Item, new: &toml::Value) {
    let Some(mut fresh) = to_item(new) else {
        *item = Item::None;
        return;
    };
    if let (Item::Value(old), Item::Value(v)) = (&*item, &mut fresh) {
        *v.decor_mut() = old.decor().clone();
    }
    *item = fresh;
}

fn new_table(t: &toml::Table) -> Table {
    let mut out = Table::new();
    for (k, v) in t {
        if let Some(item) = to_item(v) {
            out.insert(k, item);
        }
    }
    out
}

/// A TOML item for a value: a table, an array of tables, or a plain value.
fn to_item(v: &toml::Value) -> Option<Item> {
    match v {
        toml::Value::Table(t) => Some(Item::Table(new_table(t))),
        toml::Value::Array(a) if !a.is_empty() && a.iter().all(toml::Value::is_table) => {
            let mut aot = ArrayOfTables::new();
            for x in a {
                if let Some(t) = x.as_table() {
                    aot.push(new_table(t));
                }
            }
            Some(Item::ArrayOfTables(aot))
        }
        other => to_value(other).map(Item::Value),
    }
}

fn to_value(v: &toml::Value) -> Option<Value> {
    Some(match v {
        toml::Value::String(s) => Value::from(s.as_str()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => Value::from(*f),
        toml::Value::Boolean(b) => Value::from(*b),
        toml::Value::Datetime(d) => d.to_string().parse::<Value>().ok()?,
        toml::Value::Array(a) => {
            let mut arr = toml_edit::Array::new();
            for x in a {
                arr.push(to_value(x)?);
            }
            Value::Array(arr)
        }
        toml::Value::Table(t) => {
            let mut it = toml_edit::InlineTable::new();
            for (k, x) in t {
                it.insert(k, to_value(x)?);
            }
            Value::InlineTable(it)
        }
    })
}

/// Reads at most [`MAX_CONFIG_BYTES`].
pub fn read_limited(path: &Path) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?
        .take(MAX_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut data)?;
    if u64::try_from(data.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the config file is larger than 16 MiB",
        ));
    }
    Ok(data)
}

/// Writes `data` to `path` atomically: a temp file in the same directory (mode 0600 on
/// Unix), write, fsync, rename, and an fsync of the directory (Unix). On each error path the
/// temp file is removed.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
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
    tmp.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Why a change of the config file failed.
#[derive(Debug, thiserror::Error)]
pub enum EditError {
    /// The file cannot be read or written.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// The file is not valid UTF-8 or TOML, or has a wrong value.
    #[error("{0}")]
    Bad(String),
    /// The new config is not valid.
    #[error("the new config is not valid")]
    Invalid(Vec<ConfigIssue>),
    /// The text cannot be rendered.
    #[error(transparent)]
    Render(#[from] RenderError),
}

/// Changes a config file with `change` (for the CLI, for example `rusthole passwd`). Blocks.
///
/// The function reads the file, applies `change` to the config, validates it, renders the
/// new text with [`render`] and writes it with [`write_atomic`]. Ids that the file does not
/// have stay out of the file.
pub fn edit_file(path: &Path, change: impl FnOnce(&mut Config)) -> Result<(), EditError> {
    let bytes = read_limited(path)?;
    let text = String::from_utf8(bytes).map_err(|_| EditError::Bad("not UTF-8 text".into()))?;
    let file = Config::from_toml_str(&text).map_err(|e| EditError::Bad(e.to_string()))?;
    let mut new = file.clone();
    change(&mut new);
    let issues = new.validate();
    if !issues.is_empty() {
        return Err(EditError::Invalid(issues));
    }
    let out = render(&text, &file, &file, &new)?;
    write_atomic(path, out.as_bytes())?;
    Ok(())
}

/// What the store knows about the file.
#[derive(Debug, Clone)]
struct Current {
    /// The file text as last read or written.
    text: String,
    /// SHA-256 of the text.
    hash: [u8; 32],
    /// The config that the text gives (no ids added).
    file: Config,
}

/// The result of a successful write.
#[derive(Debug, Clone)]
pub struct Written<T> {
    /// What the change function gave.
    pub value: T,
    /// The config before the write.
    pub old: Arc<Config>,
    /// The config after the write.
    pub new: Arc<Config>,
}

/// Why a write through the store failed.
#[derive(Debug)]
pub enum WriteError {
    /// The change function refused the change.
    Api(ApiError),
    /// The file changed on disk. `reloaded` is the config that the store read again (when
    /// it is valid); the caller applies it.
    Conflict {
        /// The config before the reload, and the reloaded config.
        reloaded: Option<(Arc<Config>, Arc<Config>)>,
    },
}

impl From<ApiError> for WriteError {
    fn from(e: ApiError) -> Self {
        Self::Api(e)
    }
}

/// The config file and the config in memory. Reads are lock-free; one writer at a time.
#[derive(Debug)]
pub struct ConfigStore {
    path: PathBuf,
    config: ArcSwap<Config>,
    current: tokio::sync::Mutex<Current>,
}

impl ConfigStore {
    /// A store for `path`. `text` is the file text that gave `config`. The store adds the
    /// ids in memory ([`Config::assign_ids`]).
    pub fn new(path: PathBuf, text: String, config: &Config) -> Self {
        let mut mem = config.clone();
        mem.assign_ids();
        let hash = sha256(text.as_bytes());
        Self {
            path,
            config: ArcSwap::from_pointee(mem),
            current: tokio::sync::Mutex::new(Current {
                text,
                hash,
                file: config.clone(),
            }),
        }
    }

    /// Reads and parses a file. Blocks. It does not validate.
    pub fn open(path: &Path) -> Result<(Self, Arc<Config>), EditError> {
        let bytes = read_limited(path)?;
        let text = String::from_utf8(bytes).map_err(|_| EditError::Bad("not UTF-8 text".into()))?;
        let config = Config::from_toml_str(&text).map_err(|e| EditError::Bad(e.to_string()))?;
        let store = Self::new(path.to_path_buf(), text, &config);
        let cfg = store.get();
        Ok((store, cfg))
    }

    /// The config file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The config in memory (with ids).
    pub fn get(&self) -> Arc<Config> {
        self.config.load_full()
    }

    /// Changes the config with `change` and writes the file. See the module documentation.
    pub async fn update<T: Send + 'static>(
        &self,
        change: impl FnOnce(&mut Config) -> Result<T, ApiError> + Send,
    ) -> Result<Written<T>, WriteError> {
        let mut cur = tokio::time::timeout(WRITE_LOCK_TIMEOUT, self.current.lock())
            .await
            .map_err(|_| ApiError::unavailable("Another config write runs. Try again."))?;
        let path = self.path.clone();
        let disk = blocking(move || read_limited(&path)).await?;
        if sha256(&disk) != cur.hash {
            return Err(self.reload(&mut cur, disk));
        }
        let old = self.get();
        let mut new = (*old).clone();
        let value = change(&mut new)?;
        new.normalize();
        new.assign_ids();
        let issues = new.validate();
        if !issues.is_empty() {
            return Err(ApiError::invalid_many(
                issues
                    .into_iter()
                    .map(|i| FieldError {
                        field: i.path,
                        message: i.message,
                    })
                    .collect(),
            )
            .into());
        }
        let text = render(&cur.text, &cur.file, &old, &new).map_err(|e| {
            tracing::error!(error = %e, "cannot render the config file");
            ApiError::internal()
        })?;
        let file = Config::from_toml_str(&text).map_err(|_| ApiError::internal())?;
        let path = self.path.clone();
        let data = text.clone();
        blocking(move || write_atomic(&path, data.as_bytes())).await?;
        cur.hash = sha256(text.as_bytes());
        cur.text = text;
        cur.file = file;
        let new = Arc::new(new);
        self.config.store(Arc::clone(&new));
        tracing::info!(path = %self.path.display(), "config file written");
        Ok(Written { value, old, new })
    }

    /// The file on disk differs from the last read or write: read it again. A valid file
    /// becomes the new config.
    fn reload(&self, cur: &mut Current, disk: Vec<u8>) -> WriteError {
        tracing::warn!(path = %self.path.display(), "the config file changed on disk; reading it again");
        let Ok(text) = String::from_utf8(disk) else {
            tracing::error!("the changed config file is not UTF-8; the old config stays");
            return WriteError::Conflict { reloaded: None };
        };
        let config = match Config::from_toml_str(&text) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("the changed config file is not valid ({e}); the old config stays");
                return WriteError::Conflict { reloaded: None };
            }
        };
        let issues = config.validate();
        if !issues.is_empty() {
            for i in &issues {
                tracing::error!("the changed config file: {i}");
            }
            tracing::error!("the old config stays until the file is valid");
            return WriteError::Conflict { reloaded: None };
        }
        let mut mem = config.clone();
        mem.assign_ids();
        let old = self.get();
        let new = Arc::new(mem);
        cur.hash = sha256(text.as_bytes());
        cur.text = text;
        cur.file = config;
        self.config.store(Arc::clone(&new));
        WriteError::Conflict {
            reloaded: Some((old, new)),
        }
    }
}

/// Runs blocking file I/O with a time limit.
async fn blocking<R: Send + 'static>(
    f: impl FnOnce() -> io::Result<R> + Send + 'static,
) -> Result<R, ApiError> {
    match tokio::time::timeout(WRITE_IO_TIMEOUT, tokio::task::spawn_blocking(f)).await {
        Ok(Ok(Ok(r))) => Ok(r),
        Ok(Ok(Err(e))) => {
            tracing::error!(error = %e, "config file I/O failed");
            Err(ApiError::internal())
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "config file task failed");
            Err(ApiError::internal())
        }
        Err(_) => {
            tracing::error!("config file I/O timed out");
            Err(ApiError::unavailable("The config file I/O took too long."))
        }
    }
}

#[cfg(test)]
mod tests;
