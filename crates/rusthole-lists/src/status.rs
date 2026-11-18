//! Status of the lists, for the API (part P5, docs/API.md section 7).
//!
//! Times are Unix seconds from the wall clock. The API formats them.

use rusthole_core::config::ListKind;
use rusthole_core::refresh::EntryCounts;

/// The state of a list for the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListState {
    /// No try yet, and no copy on disk.
    Never,
    /// A fetch runs, or waits for a free fetch slot.
    Updating,
    /// The last try worked.
    Ok,
    /// The last try failed. The list uses the last good copy on disk, if there is one.
    Error,
}

impl ListState {
    /// The API text: `never`, `updating`, `ok` or `error`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Updating => "updating",
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

/// The state of the refresh machine of a list (more detail than [`ListState`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshPhase {
    /// The list is disabled: no machine.
    Disabled,
    /// Waiting for the next due time.
    Idle,
    /// Due: waiting for a free fetch slot.
    Due,
    /// A fetch runs.
    Fetching,
    /// The last fetch failed; a retry is due later.
    Backoff,
}

/// The status of one list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListStatus {
    /// The list id.
    pub id: u32,
    /// The URL.
    pub url: String,
    /// Block or allow.
    pub kind: ListKind,
    /// Enabled in the config.
    pub enabled: bool,
    /// The groups of the list (names).
    pub groups: Vec<String>,
    /// The state for the API.
    pub state: ListState,
    /// The state of the refresh machine.
    pub phase: RefreshPhase,
    /// Consecutive failed fetches.
    pub failures: u32,
    /// The last try.
    pub last_update: Option<i64>,
    /// The last success (a new body or "not modified").
    pub last_success: Option<i64>,
    /// The error of the last try.
    pub last_error: Option<String>,
    /// Entry counts of the current copy.
    pub entries: EntryCounts,
    /// Size of the current copy in bytes.
    pub size_bytes: u64,
    /// The next scheduled fetch. `None` with no schedule, or while a fetch runs or waits.
    pub next_due: Option<i64>,
    /// True when the current engine uses the list.
    pub in_engine: bool,
}

/// The refresh schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleStatus {
    /// `lists.refresh_interval_hours`. 0: no automatic refresh.
    pub interval_hours: u32,
    /// The earliest next scheduled fetch of all lists.
    pub next_run: Option<i64>,
    /// True while a fetch or an engine build runs or waits.
    pub running: bool,
}

/// The engine builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EngineStatus {
    /// Swaps since the start.
    pub generation: u64,
    /// True while a build runs.
    pub building: bool,
    /// The end of the last build.
    pub last_build: Option<i64>,
    /// Unique names in the current engine.
    pub unique_domains: usize,
    /// Entries of all lists in the current engine.
    pub entries: usize,
    /// Heap bytes of the current engine (an estimate).
    pub memory_bytes: usize,
    /// Config values that the last build could not use.
    pub issues: usize,
}

/// The status of all lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListsStatus {
    /// One item for each list of the config, by id.
    pub lists: Vec<ListStatus>,
    /// The schedule.
    pub schedule: ScheduleStatus,
    /// The engine.
    pub engine: EngineStatus,
}

impl ListsStatus {
    /// The status of list `id`.
    pub fn list(&self, id: u32) -> Option<&ListStatus> {
        self.lists.iter().find(|l| l.id == id)
    }
}
