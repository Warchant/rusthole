//! The report service: cache, job limit and shared jobs (docs/PLAN.md R-D11).
//!
//! ```mermaid
//! flowchart TD
//!     r[request] --> off{external section and setting off?}
//!     off -->|yes| o[status off, nothing sent]
//!     off -->|no| c{in the cache and no refresh?}
//!     c -->|yes| h[cached result]
//!     c -->|no| j{job for this key runs?}
//!     j -->|yes| w[wait for that job]
//!     j -->|no| p{job slot free in 1 s?}
//!     p -->|no| b[Busy: HTTP 429]
//!     p -->|yes| s[start a job task]
//!     s --> w
//! ```
//!
//! A job runs in its own task with the time limit of its section. It holds one of
//! [`MAX_JOBS`] slots until it ends. When the browser goes away, the job goes on and fills
//! the cache; the slot comes back when the job ends.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rusthole_core::DomainName;
use rusthole_core::blocking_state::MonoTime;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use crate::cache::{Cache, Key};
use crate::dns::DnsLookup;
use crate::http::HttpGet;
use crate::model::{Outcome, Section, SectionReport, Status};
use crate::rdap::Rdap;
use crate::tls::TlsProbe;

/// The most jobs at a time.
pub const MAX_JOBS: usize = 4;
/// How long a request waits for a free job slot before it gets [`ReportError::Busy`].
pub const SLOT_WAIT: Duration = Duration::from_secs(1);
/// The time limit of a lock of the shared maps.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(1);
/// The extra time that a waiter gives a job after the section limit.
pub const WAIT_MARGIN: Duration = Duration::from_secs(2);

/// Why a report has no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    /// All job slots are in use.
    #[error("too many reports at a time")]
    Busy,
    /// A lock timed out or a job task stopped (logged at ERROR).
    #[error("internal error")]
    Internal,
}

/// The options of one request.
#[derive(Debug, Clone, Copy)]
pub struct Request {
    /// Skip the cache.
    pub refresh: bool,
    /// The setting `report.external`.
    pub external: bool,
    /// The monotonic time now (cache time to live).
    pub now: MonoTime,
    /// The wall clock now, Unix seconds (`fetched_at`).
    pub wall: i64,
}

/// The sources of the sections.
#[derive(Debug, Clone)]
pub struct Sources {
    /// DNS lookups through the upstream pool.
    pub dns: Arc<dyn DnsLookup>,
    /// HTTPS GET (RDAP).
    pub http: Arc<dyn HttpGet>,
    /// TLS handshakes (the certificate of a name).
    pub tls: Arc<dyn TlsProbe>,
}

#[derive(Debug)]
struct Inner {
    sources: Sources,
    rdap: Rdap,
    cache: Mutex<Cache>,
    slots: Arc<Semaphore>,
    jobs: Mutex<HashMap<Key, watch::Receiver<Option<SectionReport>>>>,
}

/// The report service. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Reporter {
    inner: Arc<Inner>,
}

/// Removes the job entry when the job task ends, also on a panic.
struct JobGuard {
    inner: Arc<Inner>,
    key: Key,
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        match self.inner.jobs.try_lock_for(LOCK_TIMEOUT) {
            Some(mut jobs) => {
                jobs.remove(&self.key);
            }
            None => {
                tracing::error!(section = self.key.0.as_str(), name = %self.key.1, "report job map lock timed out; the entry stays");
            }
        }
    }
}

impl Reporter {
    /// A service with these sources.
    pub fn new(sources: Sources) -> Self {
        Self {
            inner: Arc::new(Inner {
                rdap: Rdap::new(Arc::clone(&sources.http)),
                sources,
                cache: Mutex::new(Cache::new()),
                slots: Arc::new(Semaphore::new(MAX_JOBS)),
                jobs: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The number of free job slots (tests and diagnostics).
    pub fn free_slots(&self) -> usize {
        self.inner.slots.available_permits()
    }

    /// The result of `section` for `name`.
    pub async fn report(
        &self,
        name: &DomainName,
        section: Section,
        req: Request,
    ) -> Result<SectionReport, ReportError> {
        if section.external() && !req.external {
            return Ok(SectionReport {
                section,
                name: name.as_str().to_owned(),
                outcome: Outcome {
                    status: Status::Off,
                    data: Value::Null,
                    error: Some("turned off in the settings (report.external)".to_owned()),
                },
                cached: false,
                fetched_at: req.wall,
            });
        }
        let key: Key = (section, name.as_str().to_owned());
        if !req.refresh {
            let cache = self
                .inner
                .cache
                .try_lock_for(LOCK_TIMEOUT)
                .ok_or_else(lock_error)?;
            if let Some(mut hit) = cache.get(&key, req.now) {
                hit.cached = true;
                return Ok(hit);
            }
        }
        let rx = if let Some(rx) = self.running(&key)? {
            rx
        } else {
            let slot =
                tokio::time::timeout(SLOT_WAIT, Arc::clone(&self.inner.slots).acquire_owned())
                    .await
                    .map_err(|_| ReportError::Busy)?
                    .map_err(|_| ReportError::Internal)?;
            self.start(key, name.clone(), req, slot)?
        };
        wait(rx, section).await
    }

    /// The receiver of the job for `key`, when one runs.
    fn running(
        &self,
        key: &Key,
    ) -> Result<Option<watch::Receiver<Option<SectionReport>>>, ReportError> {
        let jobs = self
            .inner
            .jobs
            .try_lock_for(LOCK_TIMEOUT)
            .ok_or_else(lock_error)?;
        Ok(jobs.get(key).cloned())
    }

    /// Starts the job for `key`, or joins a job that started while this request waited for
    /// a slot (then the slot goes back at once).
    fn start(
        &self,
        key: Key,
        name: DomainName,
        req: Request,
        slot: OwnedSemaphorePermit,
    ) -> Result<watch::Receiver<Option<SectionReport>>, ReportError> {
        let mut jobs = self
            .inner
            .jobs
            .try_lock_for(LOCK_TIMEOUT)
            .ok_or_else(lock_error)?;
        if let Some(rx) = jobs.get(&key) {
            return Ok(rx.clone());
        }
        let (tx, rx) = watch::channel(None);
        jobs.insert(key.clone(), rx.clone());
        drop(jobs);
        let guard = JobGuard {
            inner: Arc::clone(&self.inner),
            key,
        };
        // The task ends within the section limit: `run_section` has a timeout.
        tokio::spawn(async move {
            let _slot = slot;
            let section = guard.key.0;
            let outcome = match tokio::time::timeout(
                section.limit(),
                run_section(&guard.inner, section, &name, req),
            )
            .await
            {
                Ok(o) => o,
                Err(_) => Outcome::failed(format!("no answer in {} s", section.limit().as_secs())),
            };
            let report = SectionReport {
                section,
                name: name.as_str().to_owned(),
                outcome,
                cached: false,
                fetched_at: req.wall,
            };
            if let Some(mut c) = guard.inner.cache.try_lock_for(LOCK_TIMEOUT) {
                c.put(guard.key.clone(), report.clone(), req.now);
            } else {
                tracing::error!(
                    section = section.as_str(),
                    "report cache lock timed out; the result is not kept"
                );
            }
            drop(guard);
            // No receiver is not an error: the browser went away.
            let _ = tx.send(Some(report));
        });
        Ok(rx)
    }
}

fn lock_error() -> ReportError {
    tracing::error!("report lock timed out");
    ReportError::Internal
}

/// Waits for the result of a job, with the section limit and a margin.
async fn wait(
    mut rx: watch::Receiver<Option<SectionReport>>,
    section: Section,
) -> Result<SectionReport, ReportError> {
    match tokio::time::timeout(section.limit() + WAIT_MARGIN, rx.wait_for(Option::is_some)).await {
        Ok(Ok(v)) => v.clone().ok_or(ReportError::Internal),
        Ok(Err(_)) => {
            tracing::error!(
                section = section.as_str(),
                "a report job stopped with no result"
            );
            Err(ReportError::Internal)
        }
        Err(_) => {
            tracing::error!(
                section = section.as_str(),
                "a report job ran past its time limit"
            );
            Err(ReportError::Internal)
        }
    }
}

/// Runs one section (no time limit here; the caller has one).
async fn run_section(inner: &Inner, section: Section, name: &DomainName, req: Request) -> Outcome {
    let s = &inner.sources;
    match section {
        Section::Dns => crate::dns::run(Arc::clone(&s.dns), name).await,
        Section::Rdap => inner.rdap.run(name, req.now).await,
        Section::Tls => crate::tls::run(s.dns.as_ref(), s.tls.as_ref(), name, req.wall).await,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::many_single_char_names)] // Tests: a failure is a test failure.
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::dns::NAME_TYPES;
    use crate::dns::tests::FakeDns;
    use crate::rdap::tests::FakeHttp;
    use crate::tls::NoTls;

    fn req(refresh: bool, now_secs: u64) -> Request {
        Request {
            refresh,
            external: true,
            now: MonoTime::from_duration(Duration::from_secs(now_secs)),
            wall: 1_700_000_000,
        }
    }

    fn name(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    fn service(dns: Arc<FakeDns>) -> Reporter {
        Reporter::new(Sources {
            dns,
            http: Arc::new(FakeHttp::default()),
            tls: Arc::new(NoTls("no TLS in this test".to_owned())),
        })
    }

    const TYPES: usize = NAME_TYPES.len() + crate::dns::BASE_TYPES.len();

    #[tokio::test]
    async fn second_request_is_cached_and_refresh_skips_the_cache() {
        let dns = Arc::new(FakeDns::default());
        let s = service(Arc::clone(&dns));
        let a = s
            .report(&name("a.test"), Section::Dns, req(false, 0))
            .await
            .unwrap();
        assert!(!a.cached);
        assert_eq!(a.outcome.status, Status::Ok);
        let b = s
            .report(&name("a.test"), Section::Dns, req(false, 10))
            .await
            .unwrap();
        assert!(b.cached);
        assert_eq!(dns.calls.load(Ordering::SeqCst), TYPES);
        let c = s
            .report(&name("a.test"), Section::Dns, req(true, 20))
            .await
            .unwrap();
        assert!(!c.cached);
        assert_eq!(dns.calls.load(Ordering::SeqCst), 2 * TYPES);
        // After the time to live, the source is asked again.
        let d = s
            .report(&name("a.test"), Section::Dns, req(false, 20 + 3600))
            .await
            .unwrap();
        assert!(!d.cached);
        assert_eq!(s.free_slots(), MAX_JOBS);
    }

    #[tokio::test]
    async fn an_external_section_is_off_when_the_setting_is_off() {
        let http = Arc::new(FakeHttp::default());
        let s = Reporter::new(Sources {
            dns: Arc::new(FakeDns::default()),
            http: Arc::clone(&http) as Arc<dyn HttpGet>,
            tls: Arc::new(NoTls("no TLS in this test".to_owned())),
        });
        let mut r = req(false, 0);
        r.external = false;
        let off = s.report(&name("a.test"), Section::Rdap, r).await.unwrap();
        assert_eq!(off.outcome.status, Status::Off);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
        // DNS is not an outside service: it works.
        let dns = s.report(&name("a.test"), Section::Dns, r).await.unwrap();
        assert_eq!(dns.outcome.status, Status::Ok);
        // With the setting on, RDAP asks (and fails here: the fake has no answer).
        let on = s
            .report(&name("a.test"), Section::Rdap, req(false, 0))
            .await
            .unwrap();
        assert_eq!(on.outcome.status, Status::Failed);
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn requests_for_the_same_key_share_one_job() {
        let dns = Arc::new(FakeDns {
            delay: Some(Duration::from_millis(500)),
            ..FakeDns::default()
        });
        let s = service(Arc::clone(&dns));
        let n = name("a.test");
        let (a, b) = tokio::join!(
            s.report(&n, Section::Dns, req(false, 0)),
            s.report(&n, Section::Dns, req(true, 0))
        );
        assert_eq!(a.unwrap().outcome, b.unwrap().outcome);
        assert_eq!(dns.calls.load(Ordering::SeqCst), TYPES);
    }

    #[tokio::test(start_paused = true)]
    async fn the_fifth_job_is_busy_and_slots_come_back() {
        let dns = Arc::new(FakeDns {
            delay: Some(Duration::from_secs(3)),
            ..FakeDns::default()
        });
        let s = service(dns);
        let mut running = Vec::new();
        for i in 0..MAX_JOBS {
            let s = s.clone();
            running.push(tokio::spawn(async move {
                s.report(&name(&format!("n{i}.test")), Section::Dns, req(false, 0))
                    .await
            }));
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(s.free_slots(), 0);
        let busy = s
            .report(&name("five.test"), Section::Dns, req(false, 0))
            .await;
        assert_eq!(busy, Err(ReportError::Busy));
        for r in running {
            assert_eq!(r.await.unwrap().unwrap().outcome.status, Status::Ok);
        }
        assert_eq!(s.free_slots(), MAX_JOBS);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_request_keeps_the_job_and_the_slot_comes_back() {
        let dns = Arc::new(FakeDns {
            delay: Some(Duration::from_secs(2)),
            ..FakeDns::default()
        });
        let s = service(Arc::clone(&dns));
        let s2 = s.clone();
        let req_task = tokio::spawn(async move {
            s2.report(&name("gone.test"), Section::Dns, req(false, 0))
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        req_task.abort();
        assert_eq!(s.free_slots(), MAX_JOBS - 1);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(s.free_slots(), MAX_JOBS);
        // The job filled the cache.
        let r = s
            .report(&name("gone.test"), Section::Dns, req(false, 5))
            .await
            .unwrap();
        assert!(r.cached);
        assert_eq!(dns.calls.load(Ordering::SeqCst), TYPES);
    }

    #[tokio::test(start_paused = true)]
    async fn a_section_that_runs_too_long_fails_with_the_section_limit() {
        // Each type waits longer than the section limit: the job stops at 5 s.
        let dns = Arc::new(FakeDns {
            delay: Some(Duration::from_secs(600)),
            ..FakeDns::default()
        });
        let s = service(dns);
        let r = s
            .report(&name("slow.test"), Section::Dns, req(false, 0))
            .await
            .unwrap();
        assert_eq!(r.outcome.status, Status::Failed);
        assert_eq!(s.free_slots(), MAX_JOBS);
    }
}
