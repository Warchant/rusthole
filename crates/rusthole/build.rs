//! Finds the git commit for `rusthole --version` and the `/system` API.
//!
//! The commit comes from the `RUSTHOLE_COMMIT` environment variable (the release workflow
//! sets it), else from `git rev-parse HEAD`. When both fail (no git, no repository, for
//! example a source archive), the version text says `commit unknown` and the build goes on.

#[path = "src/version.rs"]
mod version;

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let package_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/version.rs");
    println!("cargo::rerun-if-env-changed=RUSTHOLE_COMMIT");

    let from_env = std::env::var("RUSTHOLE_COMMIT").ok();
    let commit = from_env
        .as_deref()
        .and_then(version::clean_commit)
        .or_else(|| {
            for path in git_watch_paths(&manifest) {
                println!("cargo::rerun-if-changed={}", path.display());
            }
            git(&manifest, &["rev-parse", "HEAD"]).and_then(|c| version::clean_commit(&c))
        });
    if let Some(c) = &commit {
        // `run.rs` reads this value for the `/system` API.
        println!("cargo::rustc-env=RUSTHOLE_COMMIT={c}");
    }
    println!(
        "cargo::rustc-env=RUSTHOLE_VERSION_TEXT={}",
        version::version_text(&package_version, commit.as_deref())
    );
}

/// Runs git in `dir` and gives the first line of its output, or `None` on any error.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let line = text.lines().next()?.trim().to_owned();
    (!line.is_empty()).then_some(line)
}

/// The git files that change when HEAD moves: `HEAD`, the branch ref, `packed-refs` and the
/// HEAD reflog `logs/HEAD`. After `git pack-refs` the branch ref is only in `packed-refs`,
/// and a new commit writes a new loose ref but does not touch `HEAD` or `packed-refs`. Git
/// writes `logs/HEAD` on each commit, checkout and reset, so cargo sees the change.
/// In a worktree `.git` is a file, so git itself gives the paths.
/// A path that does not exist is not watched: cargo would run build.rs on each build.
fn git_watch_paths(dir: &Path) -> Vec<PathBuf> {
    let mut names = vec![
        "HEAD".to_owned(),
        "packed-refs".to_owned(),
        "logs/HEAD".to_owned(),
    ];
    if let Some(r) = git(dir, &["rev-parse", "--symbolic-full-name", "HEAD"])
        && r.starts_with("refs/")
    {
        names.push(r);
    }
    names
        .iter()
        .filter_map(|n| git(dir, &["rev-parse", "--git-path", n]))
        .map(|p| {
            let p = PathBuf::from(p);
            if p.is_absolute() { p } else { dir.join(p) }
        })
        .filter(|p| p.exists())
        .collect()
}
