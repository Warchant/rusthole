//! The worker thread of the store, the [`Recorder`] for the DNS path, and the shutdown.
//!
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Running: start
//!     Running --> Running: events (apply), tick (retention, flush when due)
//!     Running --> Final: stop request or all senders gone
//!     Final --> [*]: drain the channel, flush once with the deadline, report "done"
//! ```
//!
//! The DNS path never blocks: [`Recorder::record`] uses `try_send` on a bounded channel.
//! When the channel is full, it drops the event, counts it, and logs a WARN at most once in
//! [`DROP_WARN_INTERVAL_MS`]. The flush runs on the worker thread (a blocking thread, not an
//! async task). Each wait has a time limit.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rusthole_core::stats::StatsEvent;
use rusthole_core::stats::policy::{flush_due, warn_due};

use crate::stats::Stats;
use crate::{StatsSettings, StoreError, wall_now};

/// The longest wait of the worker for an event. Also the longest delay of a stop request.
pub const TICK: Duration = Duration::from_millis(200);
/// The most events that the worker applies in one step.
pub const BATCH: usize = 1024;
/// The default time limit of the final flush at shutdown.
pub const DEFAULT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
/// The shortest time between two "events dropped" warnings, in milliseconds.
pub const DROP_WARN_INTERVAL_MS: u64 = 10_000;

#[derive(Debug)]
enum Msg {
    Event(StatsEvent),
    Wake,
}

#[derive(Debug)]
struct RecShared {
    dropped: Arc<AtomicU64>,
    /// Monotonic milliseconds of the last warning; `u64::MAX` before the first one.
    last_warn_ms: AtomicU64,
    clock: Instant,
}

/// The sender for the DNS path. It is cheap to clone. [`Recorder::record`] never blocks.
#[derive(Debug, Clone)]
pub struct Recorder {
    tx: SyncSender<Msg>,
    shared: Arc<RecShared>,
}

impl Recorder {
    /// Sends one event to the worker. When the channel is full (or the worker stopped), the
    /// event is dropped and counted.
    pub fn record(&self, ev: StatsEvent) {
        if self.tx.try_send(Msg::Event(ev)).is_err() {
            self.on_drop();
        }
    }

    fn on_drop(&self) {
        let s = &self.shared;
        let total = s.dropped.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        let now = u64::try_from(s.clock.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        let last = s.last_warn_ms.load(Ordering::Relaxed);
        let last_opt = (last != u64::MAX).then_some(last);
        if warn_due(last_opt, now, DROP_WARN_INTERVAL_MS)
            && s.last_warn_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                dropped_total = total,
                "statistics queue is full; query events are dropped"
            );
        }
    }

    /// A recorder with no worker (tests only): the caller keeps the receiver.
    #[cfg(test)]
    pub(crate) fn detached(capacity: usize) -> (Self, Receiver<impl Sized>) {
        let (tx, rx) = sync_channel(capacity);
        let rec = Recorder {
            tx,
            shared: Arc::new(RecShared {
                dropped: Arc::new(AtomicU64::new(0)),
                last_warn_ms: AtomicU64::new(u64::MAX),
                clock: Instant::now(),
            }),
        };
        (rec, rx)
    }

    /// The number of dropped events since the start.
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

/// The result of the final flush at shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalFlush {
    /// Nothing to write, or RAM-only mode.
    NotNeeded,
    /// The final flush committed.
    Done,
    /// The final flush failed or did not get its lock in time. The data is lost.
    Failed,
}

/// What [`StatsService::shutdown`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// True when the worker thread ended in the time limit.
    pub stopped: bool,
    /// The result of the final flush, or `None` when the worker did not report in time.
    pub final_flush: Option<FinalFlush>,
}

#[derive(Debug)]
struct Worker {
    stop: Arc<AtomicBool>,
    deadline_ms: Arc<AtomicU64>,
    wake: SyncSender<Msg>,
    done: Receiver<FinalFlush>,
    alive: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

/// The running store: the [`Stats`] handle, the [`Recorder`] and the worker thread.
///
/// Drop stops the worker (with [`DEFAULT_SHUTDOWN_DEADLINE`]). Call
/// [`StatsService::shutdown`] to choose the deadline and to get the report.
#[derive(Debug)]
pub struct StatsService {
    stats: Stats,
    recorder: Recorder,
    worker: Option<Worker>,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl StatsService {
    /// Opens the store and starts the worker thread.
    pub fn start(settings: &StatsSettings) -> Result<Self, StoreError> {
        let dropped = Arc::new(AtomicU64::new(0));
        let stats = Stats::open(settings, Arc::clone(&dropped))?;
        let capacity = settings.channel_capacity.max(1);
        let (tx, rx) = sync_channel(capacity);
        let (done_tx, done_rx) = sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let deadline_ms = Arc::new(AtomicU64::new(millis(DEFAULT_SHUTDOWN_DEADLINE)));
        let alive = Arc::new(AtomicBool::new(true));
        let ctx = WorkerCtx {
            rx,
            stats: stats.clone(),
            interval_ms: millis(settings.flush_interval),
            capacity,
            stop: Arc::clone(&stop),
            deadline_ms: Arc::clone(&deadline_ms),
        };
        let guard = DoneGuard {
            tx: done_tx,
            result: FinalFlush::Failed,
            alive: Arc::clone(&alive),
        };
        let thread = std::thread::Builder::new()
            .name("rusthole-stats".to_owned())
            .spawn(move || worker_main(&ctx, guard))
            .map_err(|e| StoreError::Thread(e.to_string()))?;
        let recorder = Recorder {
            tx: tx.clone(),
            shared: Arc::new(RecShared {
                dropped,
                last_warn_ms: AtomicU64::new(u64::MAX),
                clock: Instant::now(),
            }),
        };
        Ok(Self {
            stats,
            recorder,
            worker: Some(Worker {
                stop,
                deadline_ms,
                wake: tx,
                done: done_rx,
                alive,
                thread,
            }),
        })
    }

    /// The query handle.
    pub fn stats(&self) -> Stats {
        self.stats.clone()
    }

    /// The sender for the DNS path.
    pub fn recorder(&self) -> Recorder {
        self.recorder.clone()
    }

    /// A flag that is true while the worker thread runs (for tests).
    pub fn worker_alive(&self) -> Option<Arc<AtomicBool>> {
        self.worker.as_ref().map(|w| Arc::clone(&w.alive))
    }

    /// Stops the worker: it takes the events in the channel, flushes once in `deadline`,
    /// and ends. The wait for the worker has a time limit; when the worker does not end in
    /// time, the function logs an ERROR and returns (the thread is left to end by itself).
    pub fn shutdown(mut self, deadline: Duration) -> ShutdownReport {
        self.stop_worker(deadline)
    }

    fn stop_worker(&mut self, deadline: Duration) -> ShutdownReport {
        let Some(w) = self.worker.take() else {
            return ShutdownReport {
                stopped: true,
                final_flush: Some(FinalFlush::NotNeeded),
            };
        };
        w.deadline_ms.store(millis(deadline), Ordering::Release);
        w.stop.store(true, Ordering::Release);
        // The worker also sees the stop flag after at most one tick.
        let _ = w.wake.try_send(Msg::Wake);
        let wait = deadline
            .saturating_add(TICK)
            .saturating_add(Duration::from_millis(500));
        let Ok(final_flush) = w.done.recv_timeout(wait) else {
            tracing::error!(
                deadline_ms = millis(deadline),
                "the statistics thread did not stop in time"
            );
            return ShutdownReport {
                stopped: false,
                final_flush: None,
            };
        };
        let stopped = wait_finished(&w.thread, Duration::from_secs(1));
        if stopped {
            // The thread has ended, so this join does not wait.
            if w.thread.join().is_err() {
                tracing::error!("the statistics thread panicked");
            }
        } else {
            tracing::error!("the statistics thread did not end after its report");
        }
        ShutdownReport {
            stopped,
            final_flush: Some(final_flush),
        }
    }
}

impl Drop for StatsService {
    fn drop(&mut self) {
        if self.worker.is_some() {
            let _ = self.stop_worker(DEFAULT_SHUTDOWN_DEADLINE);
        }
    }
}

/// Waits until the thread has ended, at most `limit`. A bounded loop of short sleeps.
fn wait_finished(thread: &JoinHandle<()>, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    for _ in 0..=millis(limit) {
        if thread.is_finished() {
            return true;
        }
        if Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    thread.is_finished()
}

struct WorkerCtx {
    rx: Receiver<Msg>,
    stats: Stats,
    interval_ms: u64,
    capacity: usize,
    stop: Arc<AtomicBool>,
    deadline_ms: Arc<AtomicU64>,
}

/// Sends the final result when the worker ends, also on a panic (Drop runs on unwind).
struct DoneGuard {
    tx: SyncSender<FinalFlush>,
    result: FinalFlush,
    alive: Arc<AtomicBool>,
}

impl Drop for DoneGuard {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        let _ = self.tx.try_send(self.result);
    }
}

/// Takes events from the channel into `batch`: one wait of at most [`TICK`], then at most
/// [`BATCH`] more without a wait. Returns true when all senders are gone.
fn receive(rx: &Receiver<Msg>, batch: &mut Vec<StatsEvent>) -> bool {
    match rx.recv_timeout(TICK) {
        Ok(Msg::Event(e)) => batch.push(e),
        Ok(Msg::Wake) => {}
        Err(RecvTimeoutError::Timeout) => return false,
        Err(RecvTimeoutError::Disconnected) => return true,
    }
    for _ in 0..BATCH {
        match rx.try_recv() {
            Ok(Msg::Event(e)) => batch.push(e),
            Ok(Msg::Wake) => {}
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => return true,
        }
    }
    false
}

fn worker_main(ctx: &WorkerCtx, mut guard: DoneGuard) {
    let clock = Instant::now();
    let mut last_attempt_ms = 0u64;
    let mut batch = Vec::with_capacity(BATCH);
    // Service main loop: it runs until a stop request or until all senders are gone. It is
    // unbounded on purpose: the store lives as long as the server.
    loop {
        let disconnected = receive(&ctx.rx, &mut batch);
        if !batch.is_empty() && ctx.stats.apply(&mut batch).is_err() {
            tracing::error!("statistics RAM lock timed out; a batch of events is lost");
        }
        if ctx.stop.load(Ordering::Acquire) || disconnected {
            break;
        }
        ctx.stats.tick(wall_now());
        let now_ms = millis(clock.elapsed());
        if flush_due(
            ctx.interval_ms,
            now_ms,
            last_attempt_ms,
            ctx.stats.near_full(),
        ) {
            last_attempt_ms = now_ms;
            // On another error, `flush` already logged it and put the data back.
            if let Err(StoreError::Busy) = ctx.stats.flush(wall_now()) {
                tracing::warn!("statistics flush skipped: the database is busy");
            }
        }
    }
    // Final steps: take the events that are still in the channel (a bounded number of
    // steps: the channel holds at most `capacity` events), then flush once.
    let deadline = Duration::from_millis(ctx.deadline_ms.load(Ordering::Acquire));
    let end = Instant::now() + deadline;
    for _ in 0..=ctx.capacity / BATCH + 1 {
        for _ in 0..BATCH {
            match ctx.rx.try_recv() {
                Ok(Msg::Event(e)) => batch.push(e),
                Ok(Msg::Wake) => {}
                Err(_) => break,
            }
        }
        if batch.is_empty() {
            break;
        }
        let _ = ctx.stats.apply(&mut batch);
    }
    let remaining = end.saturating_duration_since(Instant::now());
    guard.result = match ctx.stats.flush_with_timeout(wall_now(), remaining) {
        Ok(Some(_)) => FinalFlush::Done,
        Ok(None) => FinalFlush::NotNeeded,
        Err(e) => {
            tracing::error!(error = %e, "final statistics flush failed");
            FinalFlush::Failed
        }
    };
}
