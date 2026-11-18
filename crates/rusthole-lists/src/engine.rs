//! The current policy engine, shared with the DNS path.
//!
//! The DNS path reads the engine with [`EngineHandle::load`]: a lock-free read (`arc-swap`),
//! so a query never waits for a build. The refresher builds a new engine on a blocking
//! thread and swaps it in with one atomic store. The old engine is freed when the last
//! reader drops its reference.
//!
//! A [`GroupSet`](rusthole_core::GroupSet) is valid only for the engine that made it. Make
//! it again from the engine of the same `load`.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::{ArcSwap, Guard};
use rusthole_core::lists::ParsedList;
use rusthole_core::policy::BuildReport;
use rusthole_core::{Config, PolicyEngine};

/// The current engine. Cheap to clone; all clones see the same engine.
#[derive(Clone)]
pub struct EngineHandle {
    current: Arc<ArcSwap<PolicyEngine>>,
    generation: Arc<AtomicU64>,
}

impl fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineHandle")
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl Default for EngineHandle {
    /// A handle with an engine for the default config and no list.
    fn default() -> Self {
        Self::new(PolicyEngine::default())
    }
}

impl EngineHandle {
    /// A handle with `engine` as generation 0.
    pub fn new(engine: PolicyEngine) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(engine)),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The current engine, for one query. Lock-free; it never waits for a build.
    pub fn load(&self) -> Guard<Arc<PolicyEngine>> {
        self.current.load()
    }

    /// The current engine as an `Arc`, to keep for a longer time.
    pub fn current(&self) -> Arc<PolicyEngine> {
        self.current.load_full()
    }

    /// The shared engine cell, for the DNS path (`rusthole_dns::EngineHandle` has this
    /// type). All clones and this cell see the same engine.
    pub fn shared(&self) -> Arc<ArcSwap<PolicyEngine>> {
        Arc::clone(&self.current)
    }

    /// The number of swaps since the start.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Swaps in `engine` and returns the old engine. The caller drops the old engine (on a
    /// blocking thread: freeing a large engine takes time).
    pub fn swap(&self, engine: PolicyEngine) -> Arc<PolicyEngine> {
        let old = self.current.swap(Arc::new(engine));
        self.generation.fetch_add(1, Ordering::AcqRel);
        old
    }
}

/// A hash seed from the OS random source, or `None` when the source fails.
fn random_seed() -> Option<[u64; 2]> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    let (a, b) = bytes.split_at(8);
    let a: [u8; 8] = a.try_into().ok()?;
    let b: [u8; 8] = b.try_into().ok()?;
    Some([u64::from_le_bytes(a), u64::from_le_bytes(b)])
}

/// Builds an engine with a new secret seed from the OS random source for each build (the
/// defence against hash flooding, docs/POLICY.md). When the OS source fails, the build uses
/// [`PolicyEngine::build`], which takes a random seed from the standard library. A fixed
/// seed is never used.
pub fn build_engine(
    config: &Config,
    lists: impl IntoIterator<Item = (u32, ParsedList)>,
) -> (PolicyEngine, BuildReport) {
    if let Some(seed) = random_seed() {
        PolicyEngine::build_with_seed(config, lists, seed)
    } else {
        tracing::error!(
            "the OS random source failed; the engine uses a seed from the standard library"
        );
        PolicyEngine::build(config, lists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_differ() {
        let a = random_seed().unwrap();
        let b = random_seed().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn swap_counts_generations() {
        let h = EngineHandle::default();
        assert_eq!(h.generation(), 0);
        let before = h.current();
        let old = h.swap(PolicyEngine::default());
        assert!(Arc::ptr_eq(&before, &old));
        assert_eq!(h.generation(), 1);
        assert!(!Arc::ptr_eq(&before, &h.current()));
    }
}
