//! Block list and allow list parsers.
//!
//! The parsers are pure. They read a `&str` line by line and never do I/O. The list refresher
//! (part P3b) downloads the text and gives it to [`parse`].
//!
//! Supported formats:
//!
//! - hosts: `0.0.0.0 name`, `127.0.0.1 name`, `:: name`, several names on one line;
//! - domain only: one name on each line;
//! - ABP subset: `||name^` (the name and all its subdomains), `@@||name^` (an allow entry).
//!   A line with `$` options or other ABP syntax is skipped and counted.
//!
//! [`ListFormat::Auto`] finds the format of each line. Use it when the format is not known,
//! because many lists in the wild mix the formats.
//!
//! Each parser accepts `#` comments (full line and inline), `!` comments, `[...]` ABP headers,
//! CRLF line ends and a UTF-8 byte order mark. A Unicode name becomes punycode (amendment A8).
//! An invalid name is counted, not fatal. A line that is too long is counted as invalid. Too
//! many entries or a text that is too large gives [`ListError`].

#[cfg(test)]
mod tests;

use std::fmt;
use std::net::IpAddr;

use crate::domain::{DomainError, DomainName};

/// Maximum length of one line, in bytes. A longer line is counted as invalid.
pub const MAX_LINE_LEN: usize = 4096;
/// Maximum number of entries in one list. More entries give [`ListError::TooManyEntries`].
pub const MAX_LIST_ENTRIES: usize = 4_000_000;
/// Maximum size of one list text, in bytes. A larger text gives [`ListError::TooLarge`].
pub const MAX_LIST_BYTES: usize = 512 * 1024 * 1024;
/// Maximum size of the entry data of one [`ParsedList`], in bytes. The compiled set uses
/// 32-bit offsets, so this limit keeps the offsets valid.
pub const MAX_LIST_DATA_BYTES: usize = 1024 * 1024 * 1024;
/// Number of invalid lines that [`ParseStats`] keeps as samples.
pub const MAX_INVALID_SAMPLES: usize = 10;
/// Maximum length of the text of one sample, in characters.
pub const MAX_SAMPLE_CHARS: usize = 120;

/// The format of a list text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListFormat {
    /// Find the format of each line. A line that starts with `||` or `@@` is ABP. A line that
    /// starts with an IP address is hosts. Other lines are domain only.
    Auto,
    /// `IP name [name ...]`. A line without an IP address is invalid.
    Hosts,
    /// One name on each line.
    Domains,
    /// `||name^` and `@@||name^`. Other lines are skipped.
    Abp,
}

/// Limits for one parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    /// Maximum line length in bytes. A longer line is counted as invalid.
    pub max_line_len: usize,
    /// Maximum number of entries. More entries give [`ListError::TooManyEntries`].
    pub max_entries: usize,
    /// Maximum text size in bytes. A larger text gives [`ListError::TooLarge`].
    pub max_bytes: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_line_len: MAX_LINE_LEN,
            max_entries: MAX_LIST_ENTRIES,
            max_bytes: MAX_LIST_BYTES,
        }
    }
}

/// How an entry matches a query name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MatchKind {
    /// The name only (hosts and domain-only lines).
    Exact,
    /// The name and each subdomain of it (ABP `||name^`).
    Subtree,
}

/// What an entry does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntryAction {
    /// Block the name. In an allow-kind list, each entry allows.
    Deny,
    /// Allow the name (ABP `@@||name^`).
    Allow,
}

/// One entry of a parsed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListEntry<'a> {
    /// The canonical name: lowercase ASCII, no trailing dot, punycode for Unicode.
    pub name: &'a str,
    /// Exact or subtree.
    pub kind: MatchKind,
    /// Deny or allow.
    pub action: EntryAction,
}

/// A fatal parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListError {
    #[error("the list has more than {limit} entries")]
    TooManyEntries { limit: usize },
    #[error("the list is larger than {limit} bytes")]
    TooLarge { limit: usize },
}

/// Why a line or a name was skipped. A skipped line is valid list syntax that rusthole does
/// not use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReason {
    /// An ABP line with `$` options.
    AbpOptions,
    /// Other ABP syntax: cosmetic filters, URL filters, wildcards, regex filters.
    AbpUnsupported,
    /// A standard hosts name such as `localhost` or `broadcasthost`.
    LocalName,
    /// A name that is an IP address or has a numeric top-level label.
    IpAddress,
    /// A name with one label only (for example `lan`). Blocking it is almost always an error.
    SingleLabel,
}

/// Why a line or a name is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidReason {
    /// The line is longer than the limit.
    LineTooLong,
    /// The text is not a valid domain name.
    BadName(DomainError),
    /// A hosts line has an address but no name.
    NoName,
    /// A domain-only line has more than one word.
    ExtraText,
    /// A line in a hosts list does not start with an IP address.
    NotHosts,
}

impl fmt::Display for InvalidReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooLong => write!(f, "the line is longer than the limit"),
            Self::BadName(e) => write!(f, "{e}"),
            Self::NoName => write!(f, "the hosts line has no name"),
            Self::ExtraText => write!(f, "the line has more than one name"),
            Self::NotHosts => write!(f, "the line does not start with an IP address"),
        }
    }
}

/// Counts of skipped lines and names, by reason.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkipCounts {
    pub abp_options: usize,
    pub abp_unsupported: usize,
    pub local_name: usize,
    pub ip_address: usize,
    pub single_label: usize,
}

impl SkipCounts {
    /// The sum of all counts.
    pub fn total(&self) -> usize {
        self.abp_options
            + self.abp_unsupported
            + self.local_name
            + self.ip_address
            + self.single_label
    }

    fn add(&mut self, reason: SkipReason) {
        let n = match reason {
            SkipReason::AbpOptions => &mut self.abp_options,
            SkipReason::AbpUnsupported => &mut self.abp_unsupported,
            SkipReason::LocalName => &mut self.local_name,
            SkipReason::IpAddress => &mut self.ip_address,
            SkipReason::SingleLabel => &mut self.single_label,
        };
        *n += 1;
    }
}

/// One invalid line, kept as a sample for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSample {
    /// Line number, from 1.
    pub line: usize,
    /// Why the line or a name on it is invalid.
    pub reason: InvalidReason,
    /// The start of the line, at most [`MAX_SAMPLE_CHARS`] characters.
    pub text: String,
}

/// Statistics of one parse.
///
/// `valid`, `invalid` and the skip counts count names. A hosts line with three names can
/// add three. A line-level problem (too long, no name, extra text) counts as one invalid name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseStats {
    /// Number of lines.
    pub lines: usize,
    /// Number of empty lines, comment lines and ABP headers.
    pub comments: usize,
    /// Number of entries in the list.
    pub valid: usize,
    /// Number of invalid names and lines.
    pub invalid: usize,
    /// Skipped names and lines, by reason.
    pub skipped: SkipCounts,
    /// The first [`MAX_INVALID_SAMPLES`] invalid lines.
    pub invalid_samples: Vec<InvalidSample>,
}

/// Flag bit of an entry: subtree match.
pub(crate) const FLAG_SUBTREE: u8 = 1;
/// Flag bit of an entry: allow entry.
pub(crate) const FLAG_ALLOW: u8 = 2;

/// A parsed list in a compact form.
///
/// The entries are in one byte buffer: for each entry, one flags byte, one length byte and
/// the name bytes. One million entries with names of 24 characters use about 26 MB. The
/// policy engine takes over this buffer when it builds its set, so the data is not copied.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ParsedList {
    data: Vec<u8>,
    len: usize,
    /// Statistics of the parse. A list made with [`ParsedList::push`] has only `valid` set.
    pub stats: ParseStats,
}

impl fmt::Debug for ParsedList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedList")
            .field("entries", &self.len)
            .field("data_bytes", &self.data.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl ParsedList {
    /// An empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty list with room for `bytes` bytes of entry data (name length + 2 per entry).
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            data: Vec::with_capacity(bytes.min(MAX_LIST_DATA_BYTES)),
            len: 0,
            stats: ParseStats::default(),
        }
    }

    /// Adds one entry. The name is already valid and canonical.
    pub fn push(
        &mut self,
        name: &DomainName,
        kind: MatchKind,
        action: EntryAction,
    ) -> Result<(), ListError> {
        let bytes = name.as_str().as_bytes();
        let Ok(len) = u8::try_from(bytes.len()) else {
            // A DomainName has at most MAX_NAME_LEN (253) bytes, so this does not occur.
            return Ok(());
        };
        if self.data.len() + bytes.len() + 2 > MAX_LIST_DATA_BYTES {
            return Err(ListError::TooLarge {
                limit: MAX_LIST_DATA_BYTES,
            });
        }
        let mut flags = 0;
        if kind == MatchKind::Subtree {
            flags |= FLAG_SUBTREE;
        }
        if action == EntryAction::Allow {
            flags |= FLAG_ALLOW;
        }
        self.data.push(flags);
        self.data.push(len);
        self.data.extend_from_slice(bytes);
        self.len += 1;
        self.stats.valid += 1;
        Ok(())
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when the list has no entry.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The entries in list order.
    pub fn entries(&self) -> Entries<'_> {
        Entries {
            data: &self.data,
            pos: 0,
        }
    }

    /// Heap bytes that the entry buffer uses.
    pub fn heap_bytes(&self) -> usize {
        self.data.capacity()
    }

    /// Gives the raw entry buffer to the compiled set.
    pub(crate) fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// The raw entry buffer.
    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Reads one entry from a raw entry buffer at `pos`.
/// Returns the flags, the name bytes and the position of the next entry.
pub(crate) fn read_raw_entry(data: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let flags = *data.get(pos)?;
    let len = usize::from(*data.get(pos + 1)?);
    let name = data.get(pos + 2..pos + 2 + len)?;
    Some((flags, name, pos + 2 + len))
}

/// Iterator over the entries of a [`ParsedList`].
#[derive(Debug, Clone)]
pub struct Entries<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Entries<'a> {
    type Item = ListEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (flags, name, next) = read_raw_entry(self.data, self.pos)?;
        self.pos = next;
        let name = std::str::from_utf8(name).ok()?;
        Some(ListEntry {
            name,
            kind: if flags & FLAG_SUBTREE == 0 {
                MatchKind::Exact
            } else {
                MatchKind::Subtree
            },
            action: if flags & FLAG_ALLOW == 0 {
                EntryAction::Deny
            } else {
                EntryAction::Allow
            },
        })
    }
}

/// Parses a list text with the default limits.
pub fn parse_default(text: &str, format: ListFormat) -> Result<ParsedList, ListError> {
    parse(text, format, &ParseLimits::default())
}

/// Parses a list text.
///
/// The function reads each line once. It returns an error only when the text or the number
/// of entries goes over a limit. All other problems are counted in [`ParsedList::stats`].
pub fn parse(
    text: &str,
    format: ListFormat,
    limits: &ParseLimits,
) -> Result<ParsedList, ListError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.len() > limits.max_bytes {
        return Err(ListError::TooLarge {
            limit: limits.max_bytes,
        });
    }
    let mut p = Parser {
        out: ParsedList::with_capacity(text.len().min(64 * 1024 * 1024)),
        limits,
        line_no: 0,
        line: "",
    };
    for line in text.lines() {
        p.line_no += 1;
        p.line = line;
        p.out.stats.lines += 1;
        if line.len() > limits.max_line_len {
            p.invalid(InvalidReason::LineTooLong);
            continue;
        }
        p.parse_line(line, format)?;
    }
    let mut out = p.out;
    if out.data.capacity() > out.data.len() + out.data.len() / 8 {
        out.data.shrink_to_fit();
    }
    Ok(out)
}

struct Parser<'a, 'l> {
    out: ParsedList,
    limits: &'a ParseLimits,
    line_no: usize,
    line: &'l str,
}

/// Markers of ABP cosmetic filters.
const COSMETIC_MARKERS: [&str; 5] = ["##", "#@#", "#?#", "#$#", "#%#"];

impl Parser<'_, '_> {
    fn parse_line(&mut self, line: &str, format: ListFormat) -> Result<(), ListError> {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with('!') || is_abp_header(t) {
            self.out.stats.comments += 1;
            return Ok(());
        }
        match format {
            ListFormat::Abp => self.abp_line(t),
            ListFormat::Hosts => self.hosts_line(strip_comment(t), true),
            ListFormat::Domains => self.domain_line(strip_comment(t)),
            ListFormat::Auto => {
                if looks_like_abp(t) {
                    self.abp_line(t)
                } else {
                    self.hosts_line(strip_comment(t), false)
                }
            }
        }
    }

    /// A hosts line. When `strict` is false, a line without an address is a domain-only
    /// line (auto format).
    fn hosts_line(&mut self, t: &str, strict: bool) -> Result<(), ListError> {
        let mut words = t.split_whitespace();
        let Some(first) = words.next() else {
            self.out.stats.comments += 1;
            return Ok(());
        };
        if first.parse::<IpAddr>().is_ok() {
            let mut any = false;
            for name in words {
                any = true;
                self.add_name(name, MatchKind::Exact, EntryAction::Deny)?;
            }
            if !any {
                self.invalid(InvalidReason::NoName);
            }
            return Ok(());
        }
        if strict {
            self.invalid(InvalidReason::NotHosts);
            return Ok(());
        }
        self.domain_words(first, words)
    }

    fn domain_line(&mut self, t: &str) -> Result<(), ListError> {
        let mut words = t.split_whitespace();
        let Some(first) = words.next() else {
            self.out.stats.comments += 1;
            return Ok(());
        };
        self.domain_words(first, words)
    }

    fn domain_words<'w>(
        &mut self,
        first: &str,
        mut rest: impl Iterator<Item = &'w str>,
    ) -> Result<(), ListError> {
        if rest.next().is_some() {
            self.invalid(InvalidReason::ExtraText);
            return Ok(());
        }
        self.add_name(first, MatchKind::Exact, EntryAction::Deny)
    }

    fn abp_line(&mut self, t: &str) -> Result<(), ListError> {
        if is_cosmetic(t) {
            self.skip(SkipReason::AbpUnsupported);
            return Ok(());
        }
        // Allow a trailing comment after white space: `||x^ # text` or `||x^ ! text`.
        let mut words = t.split_whitespace();
        let rule = words.next().unwrap_or_default();
        if let Some(next) = words.next()
            && !next.starts_with('#')
            && !next.starts_with('!')
        {
            self.skip(SkipReason::AbpUnsupported);
            return Ok(());
        }
        let (action, rest) = match rule.strip_prefix("@@") {
            Some(r) => (EntryAction::Allow, r),
            None => (EntryAction::Deny, rule),
        };
        let Some(rest) = rest.strip_prefix("||") else {
            self.skip(SkipReason::AbpUnsupported);
            return Ok(());
        };
        if rest.contains('$') {
            self.skip(SkipReason::AbpOptions);
            return Ok(());
        }
        let Some(name) = rest.strip_suffix('^') else {
            self.skip(SkipReason::AbpUnsupported);
            return Ok(());
        };
        if name.contains(['*', '/', '|', '^', ':', '?', '=', '&']) {
            self.skip(SkipReason::AbpUnsupported);
            return Ok(());
        }
        self.add_name(name, MatchKind::Subtree, action)
    }

    fn add_name(
        &mut self,
        text: &str,
        kind: MatchKind,
        action: EntryAction,
    ) -> Result<(), ListError> {
        let name = match DomainName::parse_idn(text) {
            Ok(n) => n,
            Err(e) => {
                self.invalid(InvalidReason::BadName(e));
                return Ok(());
            }
        };
        if let Some(reason) = skip_reason(&name) {
            self.skip(reason);
            return Ok(());
        }
        if self.out.len >= self.limits.max_entries {
            return Err(ListError::TooManyEntries {
                limit: self.limits.max_entries,
            });
        }
        self.out.push(&name, kind, action)
    }

    fn skip(&mut self, reason: SkipReason) {
        self.out.stats.skipped.add(reason);
    }

    fn invalid(&mut self, reason: InvalidReason) {
        let stats = &mut self.out.stats;
        stats.invalid += 1;
        if stats.invalid_samples.len() < MAX_INVALID_SAMPLES {
            stats.invalid_samples.push(InvalidSample {
                line: self.line_no,
                reason,
                text: self.line.chars().take(MAX_SAMPLE_CHARS).collect(),
            });
        }
    }
}

fn is_abp_header(t: &str) -> bool {
    t.starts_with('[') && t.ends_with(']')
}

/// True when an auto-format line uses ABP syntax.
fn looks_like_abp(t: &str) -> bool {
    t.starts_with("||")
        || t.starts_with("@@")
        || t.starts_with('|')
        || t.starts_with('/')
        || is_cosmetic(t)
}

/// True when the first word of the line is an ABP cosmetic filter (`example.com##.ad`).
/// Only the first word counts, so `0.0.0.0 ads.example ## note` is a hosts line with a comment.
fn is_cosmetic(t: &str) -> bool {
    let first = t.split_whitespace().next().unwrap_or_default();
    COSMETIC_MARKERS.iter().any(|m| first.contains(m))
}

/// Removes a `#` comment. A domain name never contains `#`.
fn strip_comment(t: &str) -> &str {
    t.split('#').next().unwrap_or_default()
}

/// Standard names in hosts files that must never be blocked.
const LOCAL_NAMES: [&str; 8] = [
    "localhost",
    "localhost.localdomain",
    "localhost4",
    "localhost4.localdomain4",
    "localhost6",
    "localhost6.localdomain6",
    "local",
    "broadcasthost",
];

fn skip_reason(name: &DomainName) -> Option<SkipReason> {
    let s = name.as_str();
    if LOCAL_NAMES.contains(&s) || (s.starts_with("ip6-") && !s.contains('.')) {
        return Some(SkipReason::LocalName);
    }
    let tld = name.labels().next_back().unwrap_or_default();
    if tld.bytes().all(|b| b.is_ascii_digit()) {
        return Some(SkipReason::IpAddress);
    }
    if !s.contains('.') {
        return Some(SkipReason::SingleLabel);
    }
    None
}

/// Writes entries as a list text in `format`.
///
/// Entries that the format cannot hold are left out: hosts and domain-only lists hold exact
/// deny entries only, ABP lists hold subtree entries only, and the auto format holds exact deny
/// entries and subtree entries. [`parse`] reads the text back to the same entries.
pub fn render<'a>(entries: impl IntoIterator<Item = ListEntry<'a>>, format: ListFormat) -> String {
    let mut out = String::new();
    for e in entries {
        let exact_deny = e.kind == MatchKind::Exact && e.action == EntryAction::Deny;
        let line = match (format, e.kind) {
            (ListFormat::Hosts, _) if exact_deny => format!("0.0.0.0 {}", e.name),
            (ListFormat::Domains | ListFormat::Auto, _) if exact_deny => e.name.to_owned(),
            (ListFormat::Abp | ListFormat::Auto, MatchKind::Subtree) => match e.action {
                EntryAction::Deny => format!("||{}^", e.name),
                EntryAction::Allow => format!("@@||{}^", e.name),
            },
            _ => continue,
        };
        out.push_str(&line);
        out.push('\n');
    }
    out
}
