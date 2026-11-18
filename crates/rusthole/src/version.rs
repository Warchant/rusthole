//! The text of `rusthole --version`: the package version and the git commit.
//!
//! `build.rs` includes this file too (with `#[path]`), so the build script and the binary
//! use the same format. The build script finds the commit and gives the text to the binary
//! in `RUSTHOLE_VERSION_TEXT`.

/// The commit text when the build cannot find the git commit (no git, no repository).
pub(crate) const UNKNOWN_COMMIT: &str = "unknown";

/// The most characters of a commit id that the version text shows.
pub(crate) const COMMIT_LEN: usize = 12;

/// Gives the version text: `0.1.0 (commit 0123456789ab)`, or `0.1.0 (commit unknown)`.
///
/// A commit that is not 7 to 40 hex digits is shown as `unknown`, so the text never holds
/// other data from the build environment.
pub(crate) fn version_text(package_version: &str, commit: Option<&str>) -> String {
    let commit = commit.and_then(clean_commit);
    format!(
        "{package_version} (commit {})",
        commit.as_deref().unwrap_or(UNKNOWN_COMMIT)
    )
}

/// The commit id in lower case, cut to [`COMMIT_LEN`] characters, or `None` when the text is
/// not 7 to 40 hex digits.
pub(crate) fn clean_commit(commit: &str) -> Option<String> {
    let c = commit.trim();
    let hex = c.chars().all(|ch| ch.is_ascii_hexdigit());
    if !(7..=40).contains(&c.len()) || !hex {
        return None;
    }
    Some(
        c.chars()
            .take(COMMIT_LEN)
            .collect::<String>()
            .to_lowercase(),
    )
}
