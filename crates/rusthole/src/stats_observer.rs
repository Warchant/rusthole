//! Wiring of the statistics store (part P4): the [`QueryObserver`] of the DNS path, and the
//! start and stop of the store.
//!
//! The adapter is here, in the binary, so that `rusthole-store` does not depend on
//! `rusthole-dns`. It changes a [`QueryEvent`] to a [`StatsEvent`] and gives it to the
//! [`Recorder`], which never blocks.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rusthole_core::Config;
use rusthole_core::stats::{StatsEvent, Status};
use rusthole_dns::{AnswerSource, NoopObserver, QueryEvent, QueryObserver, Verdict};
use rusthole_store::{Recorder, StatsService, StatsSettings};

/// The time limit of the final statistics flush at shutdown.
pub(crate) const STATS_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// DNS response code REFUSED.
const RCODE_REFUSED: u16 = 5;

/// The observer that sends each answered query to the statistics store.
#[derive(Debug)]
pub(crate) struct StatsObserver {
    recorder: Recorder,
}

impl QueryObserver for StatsObserver {
    fn on_event(&self, event: &QueryEvent) {
        self.recorder
            .record(to_stats_event(event, rusthole_store::wall_now()));
    }
}

/// The status of a query (docs/API.md section 5).
pub(crate) fn status_of(e: &QueryEvent) -> Status {
    match (e.verdict, e.source) {
        (Verdict::BlockedQuery | Verdict::BlockedAnswer, _) => Status::Blocked,
        (Verdict::Allowed, AnswerSource::Cache) => Status::Cached,
        (Verdict::Allowed, AnswerSource::Upstream) => Status::Forwarded,
        // An answer from the filter that is not a block, or local DNS data (part P3c):
        // local records, CNAMEs, PTRs, private reverse names.
        (Verdict::Allowed, AnswerSource::Filter | AnswerSource::LocalDns) => Status::Local,
        (Verdict::Allowed, AnswerSource::Local) if e.rcode == RCODE_REFUSED => Status::Refused,
        (Verdict::Allowed, AnswerSource::Local) => Status::Error,
    }
}

/// Changes a DNS event to a statistics event. `at` is the wall-clock time (Unix seconds).
///
/// The reason comes from the policy decision of part P3c (see [`reason_of`]).
pub(crate) fn to_stats_event(e: &QueryEvent, at: i64) -> StatsEvent {
    StatsEvent {
        at,
        client: e.client,
        name: e.qname.to_ascii_lowercase(),
        qtype: e.qtype,
        status: status_of(e),
        reason: reason_of(e),
        upstream: e.upstream.map(|a| a.to_string()),
        duration_us: u64::try_from(e.duration.as_micros()).unwrap_or(u64::MAX),
    }
}

/// The reason text of a blocked query for the statistics store: `cname:{target}` when a
/// CNAME target decided, else `list:{id}` (first matching list), `rule:{index}` or
/// `special`. Allowed queries and queries with no engine decision have no reason.
pub(crate) fn reason_of(e: &QueryEvent) -> Option<String> {
    use rusthole_core::policy::Reason;
    if !matches!(e.verdict, Verdict::BlockedQuery | Verdict::BlockedAnswer) {
        return None;
    }
    if let Some(target) = &e.policy.cname_target {
        return Some(format!("cname:{target}"));
    }
    match e.policy.decision?.reason {
        Reason::BlockList { lists } => lists.first().map(|id| format!("list:{id}")),
        Reason::ExactDeny { rule } | Reason::RegexDeny { rule } => Some(format!("rule:{rule}")),
        Reason::SpecialDomain => Some("special".to_owned()),
        Reason::NoMatch
        | Reason::BlockingDisabled
        | Reason::ExactAllow { .. }
        | Reason::RegexAllow { .. }
        | Reason::AllowList { .. } => None,
    }
}

/// Starts the statistics store for `config`. When the database cannot be opened, the
/// store runs in RAM-only mode and logs an ERROR: DNS must work without statistics.
pub(crate) fn start(config: &Config) -> Option<StatsService> {
    let settings = StatsSettings::from_config(&config.stats, Path::new(&config.server.data_dir));
    match StatsService::start(&settings) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::error!(error = %e, "cannot open the statistics database; statistics stay in RAM only");
            let ram = StatsSettings {
                db_path: None,
                ..settings
            };
            match StatsService::start(&ram) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::error!(error = %e, "cannot start the statistics store; no statistics");
                    None
                }
            }
        }
    }
}

/// The observer for the DNS server.
pub(crate) fn observer(service: Option<&StatsService>) -> Arc<dyn QueryObserver> {
    match service {
        Some(s) => Arc::new(StatsObserver {
            recorder: s.recorder(),
        }),
        None => Arc::new(NoopObserver),
    }
}

/// Stops the store: one final flush with a time limit.
pub(crate) fn stop(service: Option<StatsService>) {
    if let Some(s) = service {
        let report = s.shutdown(STATS_SHUTDOWN_DEADLINE);
        tracing::info!(?report, "statistics store stopped");
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    use rusthole_core::stats::query::Range;
    use rusthole_dns::ClientTransport;

    use super::*;

    fn event(verdict: Verdict, source: AnswerSource, rcode: u16) -> QueryEvent {
        QueryEvent {
            client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            transport: ClientTransport::Udp,
            qname: "WWW.Example.com".to_owned(),
            qtype: 28,
            verdict,
            source,
            upstream: (source == AnswerSource::Upstream)
                .then(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53)),
            rcode,
            duration: Duration::from_micros(1500),
            policy: rusthole_dns::PolicyInfo::default(),
        }
    }

    #[test]
    fn statuses_map_from_verdict_and_source() {
        use AnswerSource as S;
        use Verdict as V;
        let cases = [
            (V::BlockedQuery, S::Filter, 0, Status::Blocked),
            (V::BlockedAnswer, S::Upstream, 0, Status::Blocked),
            (V::BlockedAnswer, S::Cache, 0, Status::Blocked),
            (V::Allowed, S::Cache, 0, Status::Cached),
            (V::Allowed, S::Upstream, 3, Status::Forwarded),
            (V::Allowed, S::Filter, 0, Status::Local),
            (V::Allowed, S::Local, 5, Status::Refused),
            (V::Allowed, S::Local, 2, Status::Error),
        ];
        for (v, s, rcode, want) in cases {
            assert_eq!(status_of(&event(v, s, rcode)), want, "{v:?} {s:?} {rcode}");
        }
    }

    #[test]
    fn reasons_come_from_the_policy_decision() {
        use rusthole_core::policy::{Action, Decision, Reason};
        let decided = |verdict, reason| {
            let mut e = event(verdict, AnswerSource::Filter, 0);
            e.policy.decision = Some(Decision {
                action: Action::Allow,
                reason,
                name_index: 0,
            });
            e
        };
        let deny = decided(Verdict::BlockedQuery, Reason::ExactDeny { rule: 3 });
        assert_eq!(reason_of(&deny).as_deref(), Some("rule:3"));
        let special = decided(Verdict::BlockedQuery, Reason::SpecialDomain);
        assert_eq!(reason_of(&special).as_deref(), Some("special"));
        // An allowed query has no reason, even with a deny reason attached.
        let allowed = decided(Verdict::Allowed, Reason::RegexDeny { rule: 1 });
        assert_eq!(reason_of(&allowed), None);
        // A CNAME target that decided wins over the rule.
        let mut cname = decided(Verdict::BlockedAnswer, Reason::RegexDeny { rule: 1 });
        cname.policy.cname_target =
            Some(rusthole_core::DomainName::parse("ads.example.net").unwrap());
        assert_eq!(reason_of(&cname).as_deref(), Some("cname:ads.example.net"));
        // No engine decision: no reason.
        assert_eq!(
            reason_of(&event(Verdict::BlockedQuery, AnswerSource::Filter, 0)),
            None
        );
        // Local DNS answers count as local.
        assert_eq!(
            status_of(&event(Verdict::Allowed, AnswerSource::LocalDns, 0)),
            Status::Local
        );
    }

    #[test]
    fn event_fields_are_copied() {
        let e = to_stats_event(&event(Verdict::Allowed, AnswerSource::Upstream, 0), 1234);
        assert_eq!(e.at, 1234);
        assert_eq!(e.name, "www.example.com");
        assert_eq!(e.qtype, 28);
        assert_eq!(e.upstream.as_deref(), Some("192.0.2.53:53"));
        assert_eq!(e.duration_us, 1500);
        assert_eq!(e.reason, None);
    }

    #[test]
    fn observer_feeds_the_store_and_does_not_block() {
        let service = StatsService::start(&StatsSettings::ram_only()).unwrap();
        let obs = observer(Some(&service));
        let started = Instant::now();
        for _ in 0..1000 {
            obs.on_event(&event(Verdict::Allowed, AnswerSource::Cache, 0));
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        let stats = service.stats();
        let now = rusthole_store::wall_now();
        let end = Instant::now() + Duration::from_secs(5);
        let mut total = 0;
        for _ in 0..1000 {
            total = stats.summary(Range::Day, now).unwrap().counts.total;
            if total == 1000 || Instant::now() > end {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(total, 1000);
        stop(Some(service));
    }
}
