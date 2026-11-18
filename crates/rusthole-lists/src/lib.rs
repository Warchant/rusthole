//! List refresher of rusthole (part P3b): download, disk cache, schedule, status and the
//! swap of the policy engine. See docs/LISTS.md.
//!
//! - [`refresher`]: the [`Refresher`] service (load from disk, schedule, fetch, build, swap).
//! - [`engine`]: the [`EngineHandle`] that the DNS path reads without a lock.
//! - [`fetch`]: the HTTP download with the limits of amendment A8.
//! - [`store`]: the disk cache (`<data_dir>/lists/<id>.txt` and `<id>.json`).
//! - [`resolver`]: name lookup in the local zone, then through rusthole's own upstream pool.
//! - [`status`]: the status for the API.
//!
//! The policy (the refresh state machine, the schedule, the metadata rules) is pure code in
//! [`rusthole_core::refresh`]. This crate is the I/O shell around it.

pub mod engine;
pub mod fetch;
pub mod refresher;
pub mod resolver;
pub mod status;
pub mod store;

pub use engine::{EngineHandle, build_engine};
pub use fetch::{FetchError, FetchLimits, FetchOutcome, Fetcher};
pub use refresher::{
    BuildHook, BuildStage, ListsSettings, NotAList, Refresher, RefresherError, UpdateError,
    UpdateTarget, WallClock, check_list_body,
};
pub use resolver::{
    HostLookup, LocalFirstLookup, LocalHost, LookupError, ReqwestResolver, StaticResolver,
    local_host,
};
pub use status::{EngineStatus, ListState, ListStatus, ListsStatus, RefreshPhase, ScheduleStatus};
pub use store::DiskCache;
