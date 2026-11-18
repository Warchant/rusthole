//! Small runtime helpers: the monotonic clock, the task spawner and the shared ACL.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rusthole_core::acl::Acl;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// Time limit for a lock on a hot path. A lock is held for microseconds only, so a wait this
/// long means a bug. The caller then takes the safe choice (deny, or skip the cache).
pub(crate) const LOCK_TIMEOUT: Duration = Duration::from_millis(100);

/// A monotonic clock in milliseconds since the start of the server. The pure core gets
/// `now_ms` from it.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    start: Instant,
}

impl Clock {
    /// Starts a clock at 0.
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Milliseconds since the start.
    pub fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawns tracked tasks. Each task stops when the hard-stop token is cancelled, so
/// shutdown can always stop all tasks.
#[derive(Debug, Clone)]
pub(crate) struct Spawner {
    tracker: TaskTracker,
    hard: CancellationToken,
}

impl Spawner {
    pub(crate) fn new() -> Self {
        Self {
            tracker: TaskTracker::new(),
            hard: CancellationToken::new(),
        }
    }

    /// Spawns `f` as a tracked task that also stops on the hard-stop token.
    pub(crate) fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let hard = self.hard.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                () = hard.cancelled() => {}
                () = f => {}
            }
        });
    }

    /// The number of running tasks.
    pub(crate) fn len(&self) -> usize {
        self.tracker.len()
    }

    /// Stops all tasks: no new task, then a wait of `grace` for the tasks to end, then a
    /// hard stop and a wait of `hard_wait`. Returns true when all tasks ended in `grace`.
    pub(crate) async fn stop(&self, grace: Duration, hard_wait: Duration) -> bool {
        self.tracker.close();
        if tokio::time::timeout(grace, self.tracker.wait())
            .await
            .is_ok()
        {
            return true;
        }
        self.hard.cancel();
        if tokio::time::timeout(hard_wait, self.tracker.wait())
            .await
            .is_err()
        {
            tracing::error!(
                tasks = self.tracker.len(),
                "DNS tasks did not stop after the hard stop"
            );
        }
        false
    }

    /// Cancels all tasks at once, with no wait. For `Drop`.
    pub(crate) fn hard_stop(&self) {
        self.tracker.close();
        self.hard.cancel();
    }
}

/// The current ACL, shared by the listeners and changed by the interface scan.
#[derive(Debug)]
pub(crate) struct SharedAcl(RwLock<Arc<Acl>>);

impl SharedAcl {
    pub(crate) fn new(acl: Acl) -> Self {
        Self(RwLock::new(Arc::new(acl)))
    }

    /// The current ACL. `None` when the lock times out; the caller then denies.
    pub(crate) fn get(&self) -> Option<Arc<Acl>> {
        self.0.try_read_for(LOCK_TIMEOUT).map(|g| Arc::clone(&g))
    }

    /// Replaces the ACL.
    pub(crate) fn set(&self, acl: Acl) {
        if let Some(mut g) = self.0.try_write_for(LOCK_TIMEOUT) {
            *g = Arc::new(acl);
        } else {
            tracing::error!("cannot update the client ACL: the lock timed out");
        }
    }
}
