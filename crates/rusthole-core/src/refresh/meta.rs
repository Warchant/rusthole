//! The metadata file of one cached list: `<data_dir>/lists/<list-id>.json`.
//!
//! The file is small. The shell writes it only when a field changed (amendment D5: less SD
//! card wear). The functions here are pure: the shell gives the wall-clock time (Unix
//! seconds) and the facts of the body (hash, size, entry counts).
//!
//! The file can be corrupt (power loss, a full disk, a person who edits it). [`parse_meta`]
//! never panics; it gives a [`MetaError`], and the shell then fetches the list again.

use serde::{Deserialize, Serialize};

/// The format version of the metadata file.
pub const META_VERSION: u32 = 1;
/// The largest metadata file that [`parse_meta`] reads.
pub const MAX_META_BYTES: usize = 64 * 1024;
/// The longest `ETag` or `Last-Modified` value that is kept. A longer value is not kept
/// (the next fetch is then a full download).
pub const MAX_VALIDATOR_LEN: usize = 512;
/// The longest error text that is kept, in bytes. A longer text is cut.
pub const MAX_ERROR_LEN: usize = 300;
/// The longest URL in a metadata file.
pub const MAX_URL_LEN: usize = 8192;
/// The length of the body hash: SHA-256 in lowercase hex.
pub const HASH_HEX_LEN: usize = 64;

/// Entry counts of the parsed body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryCounts {
    /// Valid names.
    pub valid: u64,
    /// Invalid names and lines.
    pub invalid: u64,
    /// Skipped names and lines (valid syntax that rusthole does not use).
    pub skipped: u64,
}

/// The `ETag` and `Last-Modified` values of a response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    /// The `ETag` header.
    pub etag: Option<String>,
    /// The `Last-Modified` header.
    pub last_modified: Option<String>,
}

impl Validators {
    /// Keeps each value only when it is not empty, not longer than [`MAX_VALIDATOR_LEN`] and
    /// has visible ASCII characters and spaces only (a valid header value to send back).
    #[must_use]
    pub fn bounded(self) -> Self {
        Self {
            etag: self.etag.filter(|v| valid_validator(v)),
            last_modified: self.last_modified.filter(|v| valid_validator(v)),
        }
    }
}

fn valid_validator(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_VALIDATOR_LEN
        && v.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
}

/// The facts of a body that the shell has written to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyFacts {
    /// SHA-256 of the body, lowercase hex.
    pub hash: String,
    /// Size of the body in bytes.
    pub size_bytes: u64,
    /// Entry counts of the parse.
    pub entries: EntryCounts,
}

/// The metadata of one cached list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListMeta {
    /// [`META_VERSION`].
    pub version: u32,
    /// The URL that gave the body. A cache for another URL is not used.
    pub url: String,
    /// The `ETag` of the body, for `If-None-Match`.
    pub etag: Option<String>,
    /// The `Last-Modified` of the body, for `If-Modified-Since`.
    pub last_modified: Option<String>,
    /// SHA-256 of the body file, lowercase hex. `None`: no body on disk.
    pub body_hash: Option<String>,
    /// Size of the body file in bytes.
    pub size_bytes: u64,
    /// Entry counts of the body.
    pub entries: EntryCounts,
    /// The last success (a new body, the same body or "not modified"), Unix seconds.
    pub last_success: Option<i64>,
    /// The last fetch try, Unix seconds.
    pub last_attempt: Option<i64>,
    /// When the body last changed, Unix seconds.
    pub changed_at: Option<i64>,
    /// The error of the last try. `None` after a success.
    pub last_error: Option<String>,
}

/// Why a metadata file cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetaError {
    #[error("the metadata file is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error("the metadata file is not valid JSON: {0}")]
    Json(String),
    #[error("the metadata version {found} is not supported")]
    Version { found: u32 },
    #[error("the metadata field {field} is not valid")]
    BadField { field: &'static str },
}

/// Parses a metadata file. Never panics.
pub fn parse_meta(bytes: &[u8]) -> Result<ListMeta, MetaError> {
    if bytes.len() > MAX_META_BYTES {
        return Err(MetaError::TooLarge {
            limit: MAX_META_BYTES,
        });
    }
    let meta: ListMeta = serde_json::from_slice(bytes).map_err(|e| {
        // The message has a line and a column, never the text of the file.
        MetaError::Json(format!("line {} column {}", e.line(), e.column()))
    })?;
    if meta.version != META_VERSION {
        return Err(MetaError::Version {
            found: meta.version,
        });
    }
    let bad = |field| Err(MetaError::BadField { field });
    if meta.url.is_empty() || meta.url.len() > MAX_URL_LEN {
        return bad("url");
    }
    if meta.etag.as_deref().is_some_and(|v| !valid_validator(v)) {
        return bad("etag");
    }
    if meta
        .last_modified
        .as_deref()
        .is_some_and(|v| !valid_validator(v))
    {
        return bad("last_modified");
    }
    if meta.body_hash.as_deref().is_some_and(|h| {
        h.len() != HASH_HEX_LEN || !h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }) {
        return bad("body_hash");
    }
    if meta
        .last_error
        .as_deref()
        .is_some_and(|e| e.len() > MAX_ERROR_LEN)
    {
        return bad("last_error");
    }
    Ok(meta)
}

/// The bytes of a metadata file (pretty JSON with a final newline).
pub fn render_meta(meta: &ListMeta) -> Vec<u8> {
    // A struct of strings and numbers always serializes. The fallback is never used.
    let mut out = serde_json::to_vec_pretty(meta).unwrap_or_default();
    out.push(b'\n');
    out
}

/// Cuts `text` to at most [`MAX_ERROR_LEN`] bytes, on a character boundary.
pub fn bound_error(text: &str) -> String {
    if text.len() <= MAX_ERROR_LEN {
        return text.to_owned();
    }
    let mut end = MAX_ERROR_LEN;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default().to_owned()
}

impl ListMeta {
    /// Empty metadata for `url`: no body, no try.
    pub fn new(url: &str) -> Self {
        Self {
            version: META_VERSION,
            url: url.to_owned(),
            ..Self::default()
        }
    }

    /// True when the metadata describes a body on disk for `url`.
    pub fn has_body_for(&self, url: &str) -> bool {
        self.url == url && self.body_hash.is_some()
    }

    /// The metadata after a fetch at `now_unix` that gave a body. When the hash is the same,
    /// the body did not change and `changed_at` stays.
    #[must_use]
    pub fn after_body(&self, url: &str, now_unix: i64, v: Validators, body: BodyFacts) -> Self {
        let v = v.bounded();
        let same = self.url == url && self.body_hash.as_deref() == Some(body.hash.as_str());
        Self {
            version: META_VERSION,
            url: url.to_owned(),
            etag: v.etag,
            last_modified: v.last_modified,
            body_hash: Some(body.hash),
            size_bytes: body.size_bytes,
            entries: body.entries,
            last_success: Some(now_unix),
            last_attempt: Some(now_unix),
            changed_at: if same {
                self.changed_at
            } else {
                Some(now_unix)
            },
            last_error: None,
        }
    }

    /// The metadata after a "not modified" answer at `now_unix`. A validator in the answer
    /// replaces the old one; a missing validator keeps the old one.
    #[must_use]
    pub fn after_not_modified(&self, now_unix: i64, v: Validators) -> Self {
        let v = v.bounded();
        Self {
            etag: v.etag.or_else(|| self.etag.clone()),
            last_modified: v.last_modified.or_else(|| self.last_modified.clone()),
            last_success: Some(now_unix),
            last_attempt: Some(now_unix),
            last_error: None,
            ..self.clone()
        }
    }

    /// The metadata after a failed fetch at `now_unix`. The body facts stay: the old copy is
    /// still used.
    #[must_use]
    pub fn after_failure(&self, now_unix: i64, error: &str) -> Self {
        Self {
            last_attempt: Some(now_unix),
            last_error: Some(bound_error(error)),
            ..self.clone()
        }
    }
}
