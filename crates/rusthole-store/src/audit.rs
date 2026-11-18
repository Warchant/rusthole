//! The audit log of admin actions (docs/API.md section 13).
//!
//! Choice: the store writes each audit line at once, in its own small transaction, not in
//! the next flush. Admin actions are rare, so the SD-card wear is small, and a crash loses
//! no audit line. In RAM-only mode the lines stay in a bounded ring in RAM.

use std::collections::VecDeque;
use std::net::IpAddr;

use rusthole_core::stats::page::{CursorError, MAX_LIMIT, Page, SortKey, decode, encode};

/// The longest action, in bytes. A longer text is cut.
pub const MAX_ACTION_LEN: usize = 64;
/// The longest target or actor, in bytes.
pub const MAX_TARGET_LEN: usize = 256;
/// The longest detail, in bytes.
pub const MAX_DETAIL_LEN: usize = 1024;
/// The number of audit lines in RAM-only mode.
pub const RAM_AUDIT_LINES: usize = 10_000;

/// A new audit line. The caller never puts a password, a code or a token in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAudit {
    /// Wall-clock time, Unix seconds.
    pub at: i64,
    /// The action, for example `list.update`.
    pub action: String,
    /// The target, for example `list:3`.
    pub target: Option<String>,
    /// `session`, `token:{id}` or `anonymous`.
    pub actor: String,
    /// The address of the admin client.
    pub client_ip: Option<IpAddr>,
    /// True for the result `ok`, false for `error`.
    pub ok: bool,
    /// A short text.
    pub detail: Option<String>,
}

/// One stored audit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// The id. A newer line has a larger id.
    pub id: i64,
    /// Wall-clock time, Unix seconds.
    pub at: i64,
    /// The action.
    pub action: String,
    /// The target.
    pub target: Option<String>,
    /// The actor.
    pub actor: String,
    /// The address of the admin client.
    pub client_ip: Option<IpAddr>,
    /// True for `ok`, false for `error`.
    pub ok: bool,
    /// A short text.
    pub detail: Option<String>,
}

/// Parameters of `GET /audit`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditParams {
    /// Only actions that start with this text, for example `list.`.
    pub action_prefix: Option<String>,
    /// The cursor from the previous page.
    pub cursor: Option<String>,
    /// The page size, clamped to `1..=500`.
    pub limit: usize,
}

/// Cuts `s` to at most `max` bytes at a character boundary.
pub(crate) fn cut(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let end = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= max)
        .last()
        .unwrap_or(0);
    s.get(..end).unwrap_or_default().to_owned()
}

impl NewAudit {
    /// A copy with all texts cut to their limits.
    pub(crate) fn clamped(&self) -> NewAudit {
        NewAudit {
            at: self.at,
            action: cut(&self.action, MAX_ACTION_LEN),
            target: self.target.as_deref().map(|t| cut(t, MAX_TARGET_LEN)),
            actor: cut(&self.actor, MAX_TARGET_LEN),
            client_ip: self.client_ip,
            ok: self.ok,
            detail: self.detail.as_deref().map(|d| cut(d, MAX_DETAIL_LEN)),
        }
    }
}

/// The id after which a page starts, from a cursor.
pub(crate) fn cursor_id(cursor: Option<&str>) -> Result<Option<i64>, CursorError> {
    cursor.map(|c| decode(c).map(|k| k.num)).transpose()
}

/// Makes a page from up to `limit + 1` lines (newest first).
pub(crate) fn page_of(mut lines: Vec<AuditEntry>, limit: usize) -> Page<AuditEntry> {
    let more = lines.len() > limit;
    lines.truncate(limit);
    let next_cursor = if more {
        lines.last().map(|l| {
            encode(&SortKey {
                num: l.id,
                text: String::new(),
                tie: String::new(),
            })
        })
    } else {
        None
    };
    Page {
        items: lines,
        next_cursor,
    }
}

/// The page size for audit pages.
pub(crate) fn audit_limit(limit: usize) -> usize {
    limit.clamp(1, MAX_LIMIT)
}

/// The audit ring of RAM-only mode.
#[derive(Debug, Clone, Default)]
pub(crate) struct RamAudit {
    lines: VecDeque<AuditEntry>,
    next_id: i64,
}

impl RamAudit {
    pub(crate) fn append(&mut self, a: &NewAudit) -> i64 {
        let a = a.clamped();
        self.next_id = self.next_id.saturating_add(1);
        while self.lines.len() >= RAM_AUDIT_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(AuditEntry {
            id: self.next_id,
            at: a.at,
            action: a.action,
            target: a.target,
            actor: a.actor,
            client_ip: a.client_ip,
            ok: a.ok,
            detail: a.detail,
        });
        self.next_id
    }

    pub(crate) fn query(
        &self,
        before: Option<i64>,
        prefix: Option<&str>,
        limit: usize,
    ) -> Vec<AuditEntry> {
        self.lines
            .iter()
            .rev()
            .filter(|l| before.is_none_or(|b| l.id < b))
            .filter(|l| prefix.is_none_or(|p| l.action.starts_with(p)))
            .take(limit)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::cut;

    #[test]
    fn cut_keeps_char_boundaries() {
        assert_eq!(cut("abc", 5), "abc");
        assert_eq!(cut("abcdef", 3), "abc");
        // "é" is 2 bytes: a cut inside it goes back to the boundary.
        assert_eq!(cut("aé", 2), "a");
        assert_eq!(cut("éé", 3), "é");
        assert_eq!(cut("", 0), "");
    }
}
