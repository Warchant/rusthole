//! The policy engine at start (part P3c).
//!
//! [`EngineLoader`] builds the first engine. [`DiskLists`] reads the list files that are
//! already on disk (`<data_dir>/lists/<id>.txt`, the disk cache layout of part P3b) and
//! downloads nothing. Part P3b replaces it with the list refresher, which also swaps new
//! engines into the [`rusthole_dns::EngineHandle`] later.
//!
//! Each build gets a new hash seed from the OS random source (hash-flooding defence of part
//! P3a). A build never uses a fixed seed.

use std::path::{Path, PathBuf};

use anyhow::Context;
use rusthole_core::lists::{self, ListFormat, ParseLimits, ParsedList};
use rusthole_core::policy::BuildReport;
use rusthole_core::{Config, PolicyEngine};

/// Builds the policy engine for a config.
pub(crate) trait EngineLoader: Send + Sync {
    /// Builds an engine. The engine can be empty (no list), but it is never invalid.
    fn load(&self, config: &Config) -> anyhow::Result<(PolicyEngine, BuildReport)>;
}

/// A new hash seed for one engine build, from the OS random source.
pub(crate) fn engine_seed() -> anyhow::Result<[u64; 2]> {
    let a = getrandom::u64().context("the OS random source failed")?;
    let b = getrandom::u64().context("the OS random source failed")?;
    Ok([a, b])
}

/// Reads the enabled lists from `<dir>/<id>.txt`. A missing or bad file is skipped with a
/// warning: the engine then works without that list.
#[derive(Debug, Clone)]
pub(crate) struct DiskLists {
    dir: PathBuf,
}

impl DiskLists {
    /// The list folder of a config: `<data_dir>/lists`.
    pub(crate) fn for_config(config: &Config) -> Self {
        Self {
            dir: Path::new(&config.server.data_dir).join("lists"),
        }
    }

    /// The file of list `id`.
    pub(crate) fn path(&self, id: u32) -> PathBuf {
        self.dir.join(format!("{id}.txt"))
    }

    /// Reads and parses one list file. `None` (with a log line) when it is missing or bad.
    fn read(&self, id: u32) -> Option<ParsedList> {
        let path = self.path(id);
        let max = u64::try_from(lists::MAX_LIST_BYTES).unwrap_or(u64::MAX);
        let bytes = match crate::fsutil::read_limited(&path, max) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(list = id, path = %path.display(), "the list is not on disk yet");
                return None;
            }
            Err(e) => {
                tracing::warn!(list = id, path = %path.display(), error = %e, "cannot read the list file; the list is not used");
                return None;
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        match lists::parse(&text, ListFormat::Auto, &ParseLimits::default()) {
            Ok(parsed) => {
                tracing::info!(
                    list = id,
                    valid = parsed.stats.valid,
                    invalid = parsed.stats.invalid,
                    "list loaded from disk"
                );
                Some(parsed)
            }
            Err(e) => {
                tracing::warn!(list = id, error = %e, "the list file is not usable; the list is not used");
                None
            }
        }
    }
}

impl EngineLoader for DiskLists {
    fn load(&self, config: &Config) -> anyhow::Result<(PolicyEngine, BuildReport)> {
        let seed = engine_seed()?;
        // The iterator reads one list at a time, so only one list text is in memory.
        let lists = config
            .lists
            .adlists
            .iter()
            .filter(|l| l.enabled)
            .filter_map(|l| self.read(l.id).map(|p| (l.id, p)));
        let (engine, report) = PolicyEngine::build_with_seed(config, lists, seed);
        for issue in &report.issues {
            tracing::warn!("policy: {issue}");
        }
        tracing::info!(
            lists = engine.list_count(),
            domains = report.unique_domains,
            missing = report.missing_lists.len(),
            "policy engine built"
        );
        Ok((engine, report))
    }
}

#[cfg(test)]
mod tests {
    use rusthole_core::DomainName;
    use rusthole_core::config::{Adlist, ListKind};

    use super::*;

    fn adlist(id: u32, enabled: bool) -> Adlist {
        Adlist {
            id,
            url: format!("https://lists.example/{id}.txt"),
            kind: ListKind::Block,
            enabled,
            groups: vec!["default".to_owned()],
            comment: None,
        }
    }

    #[test]
    fn seeds_differ() {
        assert_ne!(engine_seed().unwrap(), engine_seed().unwrap());
    }

    #[test]
    fn loads_enabled_lists_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.server.data_dir = dir.path().display().to_string();
        cfg.lists.adlists = vec![
            adlist(1, true),
            adlist(2, false),
            adlist(3, true),
            adlist(4, true),
        ];
        let loader = DiskLists::for_config(&cfg);
        std::fs::create_dir_all(dir.path().join("lists")).unwrap();
        std::fs::write(loader.path(1), "0.0.0.0 one.example\n").unwrap();
        std::fs::write(loader.path(2), "0.0.0.0 two.example\n").unwrap();
        // List 3 has no file. List 4 is not UTF-8 everywhere: the bad line is invalid.
        std::fs::write(loader.path(4), b"four.example\n\xff\xfe bad\n").unwrap();
        let (engine, report) = loader.load(&cfg).unwrap();
        assert_eq!(report.missing_lists, vec![3]);
        let groups = engine.default_groups();
        let blocked = |n: &str| {
            engine
                .check(&groups, true, &DomainName::parse(n).unwrap())
                .is_blocked()
        };
        assert!(blocked("one.example"));
        assert!(!blocked("two.example"));
        assert!(blocked("four.example"));
    }

    #[test]
    fn no_lists_gives_an_empty_engine() {
        let mut cfg = Config::default();
        cfg.server.data_dir = "this-folder-does-not-exist".to_owned();
        cfg.lists.adlists = vec![adlist(1, true)];
        let (engine, report) = DiskLists::for_config(&cfg).load(&cfg).unwrap();
        assert_eq!(engine.unique_domains(), 0);
        assert_eq!(report.missing_lists, vec![1]);
    }
}
