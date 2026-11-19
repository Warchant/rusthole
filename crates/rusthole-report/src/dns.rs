//! The DNS section (docs/PLAN.md R-D6): the records of the name through the upstream pool
//! of rusthole, never the system resolver, the filter or the DNS cache.
//!
//! ```mermaid
//! flowchart LR
//!     n[name] --> a[A, AAAA, MX, TXT, CAA of the name]
//!     n --> b[NS, SOA of the registrable domain]
//!     a --> r[one result for each type]
//!     b --> r
//!     a --> c[CNAME chain from the A answer]
//! ```
//!
//! Each record type has its own result and its own time limit, so one slow type does not
//! fail the section. NXDOMAIN and NODATA are data, not failures. The answer data comes from
//! the network: each value is made safe text with a size limit.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::rr::{RData, Record, RecordType};
use rusthole_core::DomainName;
use rusthole_core::stats::base::registrable;
use rusthole_dns::{HostResolver, LookupAnswer};
use serde_json::{Value, json};
use tokio::task::JoinSet;

use crate::model::{Outcome, Status};

/// The most records shown for each type.
pub const MAX_RECORDS: usize = 32;
/// The most bytes of one TXT value.
pub const MAX_TXT_BYTES: usize = 1024;
/// The most bytes of one other value.
pub const MAX_VALUE_BYTES: usize = 512;
/// The most names in a CNAME chain.
pub const MAX_CHAIN: usize = 16;
/// The time limit of one record type. It is shorter than the section limit (5 s), so the
/// section can give the types that answered.
pub const TYPE_LIMIT: Duration = Duration::from_millis(4500);

/// The types asked for the name itself.
pub const NAME_TYPES: [RecordType; 5] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::MX,
    RecordType::TXT,
    RecordType::CAA,
];
/// The types asked for the registrable domain.
pub const BASE_TYPES: [RecordType; 2] = [RecordType::NS, RecordType::SOA];

/// A boxed lookup future.
pub type LookupFuture<'a> = Pin<Box<dyn Future<Output = Result<LookupAnswer, String>> + Send + 'a>>;

/// One DNS lookup of a name and a type. The production lookup is
/// [`rusthole_dns::HostResolver`]; tests use a fake.
pub trait DnsLookup: Send + Sync + fmt::Debug {
    /// The answer of `name` for `rtype`, or a short reason.
    fn lookup<'a>(&'a self, name: &'a DomainName, rtype: RecordType) -> LookupFuture<'a>;
}

impl DnsLookup for HostResolver {
    fn lookup<'a>(&'a self, name: &'a DomainName, rtype: RecordType) -> LookupFuture<'a> {
        Box::pin(async move {
            HostResolver::lookup(self, name, rtype)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// `s` as safe text of at most `max` bytes: control characters become `?`; a cut text
/// ends with `…`.
pub fn safe_text(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    for ch in s.chars() {
        let ch = if ch.is_control() { '?' } else { ch };
        if out.len() + ch.len_utf8() > max {
            out.push('…');
            return out;
        }
        out.push(ch);
    }
    out
}

/// A DNS name as text with no final dot.
fn name_text(n: &impl fmt::Display) -> String {
    let s = n.to_string();
    safe_text(s.strip_suffix('.').unwrap_or(&s), MAX_VALUE_BYTES)
}

/// The text of one record value, or `None` for a type that the section does not show.
pub fn record_text(data: &RData) -> Option<String> {
    Some(match data {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(a) => a.0.to_string(),
        RData::CNAME(c) => name_text(&c.0),
        RData::NS(n) => name_text(&n.0),
        RData::MX(m) => format!("{} {}", m.preference, name_text(&m.exchange)),
        RData::TXT(t) => {
            let mut joined = Vec::new();
            for part in &t.txt_data {
                joined.extend_from_slice(part);
                // Stop early: a TXT record can hold 64 KiB.
                if joined.len() > MAX_TXT_BYTES * 4 {
                    break;
                }
            }
            safe_text(&String::from_utf8_lossy(&joined), MAX_TXT_BYTES)
        }
        RData::SOA(_) | RData::CAA(_) => safe_text(&data.to_string(), MAX_VALUE_BYTES),
        _ => return None,
    })
}

/// The CNAME chain from `qname` in `answers`: each target in order. The loop has a bound
/// of [`MAX_CHAIN`] steps, so a CNAME loop in an answer stops.
pub fn cname_chain(qname: &str, answers: &[Record]) -> Vec<String> {
    let mut chain = Vec::new();
    let mut current = qname.trim_end_matches('.').to_ascii_lowercase();
    for _ in 0..MAX_CHAIN {
        let next = answers.iter().find_map(|r| match &r.data {
            RData::CNAME(c) if name_text(&r.name).eq_ignore_ascii_case(&current) => {
                Some(name_text(&c.0))
            }
            _ => None,
        });
        let Some(next) = next else { break };
        current = next.to_ascii_lowercase();
        chain.push(next);
    }
    chain
}

/// The result of one type as JSON.
pub fn type_result(name: &str, rtype: RecordType, answer: Result<&LookupAnswer, &str>) -> Value {
    let a = match answer {
        Ok(a) => a,
        Err(reason) => {
            return json!({
                "type": rtype.to_string(), "name": name, "status": "failed",
                "rcode": null, "records": [], "truncated": false,
                "error": safe_text(reason, MAX_VALUE_BYTES),
            });
        }
    };
    let all: Vec<Value> = a
        .answers
        .iter()
        .filter(|r| r.record_type() == rtype)
        .filter_map(|r| {
            record_text(&r.data)
                .map(|v| json!({ "name": name_text(&r.name), "ttl": r.ttl, "value": v }))
        })
        .collect();
    let truncated = all.len() > MAX_RECORDS;
    let records: Vec<Value> = all.into_iter().take(MAX_RECORDS).collect();
    let status = match a.rcode {
        0 if records.is_empty() => "nodata",
        0 => "ok",
        3 => "nxdomain",
        _ => "error",
    };
    json!({
        "type": rtype.to_string(), "name": name, "status": status, "rcode": a.rcode,
        "records": records, "truncated": truncated, "error": null,
    })
}

/// Runs the DNS section for `name`. Each type runs in its own task with [`TYPE_LIMIT`]; when
/// this future is dropped (the section limit), the tasks stop.
pub async fn run(lookup: Arc<dyn DnsLookup>, name: &DomainName) -> Outcome {
    let base = registrable(name.as_str()).to_owned();
    let base_name = DomainName::parse(&base).unwrap_or_else(|_| name.clone());
    let jobs: Vec<(DomainName, RecordType)> = NAME_TYPES
        .iter()
        .map(|t| (name.clone(), *t))
        .chain(BASE_TYPES.iter().map(|t| (base_name.clone(), *t)))
        .collect();
    let mut set = JoinSet::new();
    for (i, (n, t)) in jobs.iter().cloned().enumerate() {
        let lookup = Arc::clone(&lookup);
        set.spawn(async move {
            let r = match tokio::time::timeout(TYPE_LIMIT, lookup.lookup(&n, t)).await {
                Ok(r) => r,
                Err(_) => Err(format!("no answer in {} ms", TYPE_LIMIT.as_millis())),
            };
            (i, r)
        });
    }
    let mut answers: Vec<Option<Result<LookupAnswer, String>>> = vec![None; jobs.len()];
    while let Some(done) = set.join_next().await {
        match done {
            Ok((i, r)) => {
                if let Some(slot) = answers.get_mut(i) {
                    *slot = Some(r);
                }
            }
            Err(e) => tracing::error!(error = %e, "a DNS report task failed"),
        }
    }
    let mut chain = Vec::new();
    let mut types = Vec::with_capacity(jobs.len());
    let mut all_failed = true;
    for ((n, t), a) in jobs.iter().zip(answers) {
        let a = a.unwrap_or_else(|| Err("the lookup task failed".to_owned()));
        if a.is_ok() {
            all_failed = false;
        }
        if *t == RecordType::A
            && let Ok(ans) = &a
        {
            chain = cname_chain(n.as_str(), &ans.answers);
        }
        types.push(type_result(
            n.as_str(),
            *t,
            a.as_ref().map_err(String::as_str),
        ));
    }
    let data = json!({ "name": name.as_str(), "base": base, "cname_chain": chain, "types": types });
    if all_failed {
        return Outcome {
            status: Status::Failed,
            data,
            error: Some("no upstream answer".to_owned()),
        };
    }
    Outcome {
        status: Status::Ok,
        data,
        error: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)] // Tests: a failure is a test failure.
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::rr::Name;
    use hickory_proto::rr::rdata::{A, CNAME, TXT};
    use proptest::prelude::*;

    use super::*;

    pub(crate) fn rec(owner: &str, data: RData) -> Record {
        Record::from_rdata(Name::from_str(&format!("{owner}.")).unwrap(), 300, data)
    }

    pub(crate) fn answer(rcode: u16, answers: Vec<Record>) -> LookupAnswer {
        LookupAnswer {
            rcode,
            answers,
            authorities: Vec::new(),
        }
    }

    /// A fake lookup: a fixed table, a count of calls, and an optional wait.
    #[derive(Debug, Default)]
    pub(crate) struct FakeDns {
        pub(crate) table: HashMap<(String, RecordType), Result<LookupAnswer, String>>,
        pub(crate) calls: AtomicUsize,
        pub(crate) delay: Option<Duration>,
    }

    impl DnsLookup for FakeDns {
        fn lookup<'a>(&'a self, name: &'a DomainName, rtype: RecordType) -> LookupFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if let Some(d) = self.delay {
                    tokio::time::sleep(d).await;
                }
                self.table
                    .get(&(name.as_str().to_owned(), rtype))
                    .cloned()
                    .unwrap_or_else(|| Ok(answer(0, Vec::new())))
            })
        }
    }

    fn name(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    #[test]
    fn safe_text_cuts_and_cleans() {
        assert_eq!(safe_text("v=spf1 -all", 100), "v=spf1 -all");
        assert_eq!(safe_text("a\u{0}b\nc", 100), "a?b?c");
        assert_eq!(safe_text("abcdef", 3), "abc…");
        // A cut never splits a character.
        assert_eq!(safe_text("ééé", 3), "é…");
    }

    #[test]
    fn chain_follows_cnames_in_order() {
        let answers = vec![
            rec(
                "b.cdn.test",
                RData::CNAME(CNAME(Name::from_str("c.cdn.test.").unwrap())),
            ),
            rec(
                "www.example.test",
                RData::CNAME(CNAME(Name::from_str("b.cdn.test.").unwrap())),
            ),
            rec("c.cdn.test", RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))),
        ];
        assert_eq!(
            cname_chain("WWW.example.test", &answers),
            vec!["b.cdn.test", "c.cdn.test"]
        );
    }

    #[test]
    fn chain_loop_stops_at_the_bound() {
        let answers = vec![
            rec(
                "a.test",
                RData::CNAME(CNAME(Name::from_str("b.test.").unwrap())),
            ),
            rec(
                "b.test",
                RData::CNAME(CNAME(Name::from_str("a.test.").unwrap())),
            ),
        ];
        assert_eq!(cname_chain("a.test", &answers).len(), MAX_CHAIN);
    }

    #[test]
    fn type_states() {
        let ok = answer(
            0,
            vec![rec("a.test", RData::A(A(Ipv4Addr::new(192, 0, 2, 1))))],
        );
        assert_eq!(
            type_result("a.test", RecordType::A, Ok(&ok))["status"],
            "ok"
        );
        assert_eq!(
            type_result("a.test", RecordType::A, Ok(&ok))["records"][0]["value"],
            "192.0.2.1"
        );
        assert_eq!(
            type_result("a.test", RecordType::MX, Ok(&ok))["status"],
            "nodata"
        );
        assert_eq!(
            type_result("a.test", RecordType::A, Ok(&answer(3, vec![])))["status"],
            "nxdomain"
        );
        assert_eq!(
            type_result("a.test", RecordType::A, Ok(&answer(2, vec![])))["status"],
            "error"
        );
        let f = type_result("a.test", RecordType::A, Err("timeout"));
        assert_eq!(f["status"], "failed");
        assert_eq!(f["error"], "timeout");
    }

    #[test]
    fn records_are_capped() {
        let many: Vec<Record> = (0..40u8)
            .map(|i| rec("a.test", RData::A(A(Ipv4Addr::new(192, 0, 2, i)))))
            .collect();
        let v = type_result("a.test", RecordType::A, Ok(&answer(0, many)));
        assert_eq!(v["records"].as_array().unwrap().len(), MAX_RECORDS);
        assert_eq!(v["truncated"], true);
    }

    #[tokio::test]
    async fn run_asks_name_and_base_types() {
        let mut dns = FakeDns::default();
        dns.table.insert(
            ("www.example.test".to_owned(), RecordType::TXT),
            Ok(answer(
                0,
                vec![rec(
                    "www.example.test",
                    RData::TXT(TXT::new(vec!["hello".to_owned()])),
                )],
            )),
        );
        dns.table.insert(
            ("www.example.test".to_owned(), RecordType::MX),
            Err("refused".to_owned()),
        );
        let dns = Arc::new(dns);
        let out = run(
            Arc::clone(&dns) as Arc<dyn DnsLookup>,
            &name("www.example.test"),
        )
        .await;
        assert_eq!(out.status, Status::Ok);
        assert_eq!(
            dns.calls.load(Ordering::SeqCst),
            NAME_TYPES.len() + BASE_TYPES.len()
        );
        let types = out.data["types"].as_array().unwrap();
        let get = |t: &str| types.iter().find(|x| x["type"] == t).unwrap().clone();
        assert_eq!(get("TXT")["records"][0]["value"], "hello");
        assert_eq!(get("MX")["status"], "failed");
        assert_eq!(get("NS")["name"], "example.test");
        assert_eq!(out.data["base"], "example.test");
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_type_fails_alone_and_all_failed_is_a_failure() {
        let dns = Arc::new(FakeDns {
            delay: Some(Duration::from_secs(60)),
            ..FakeDns::default()
        });
        let out = run(dns, &name("slow.test")).await;
        assert_eq!(out.status, Status::Failed);
        assert!(
            out.data["types"]
                .as_array()
                .unwrap()
                .iter()
                .all(|t| t["status"] == "failed")
        );
    }

    proptest! {
        /// Safe text has no control character and keeps the byte bound (plus the "…").
        #[test]
        fn safe_text_is_bounded(s in any::<String>(), max in 0usize..64) {
            let t = safe_text(&s, max);
            prop_assert!(t.len() <= max + '…'.len_utf8());
            prop_assert!(!t.chars().any(char::is_control));
        }

        /// Any TXT data gives bounded safe text.
        #[test]
        fn txt_is_bounded(parts in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..300), 0..40)) {
            let txt = TXT::from_bytes(parts.iter().map(Vec::as_slice).collect());
            let t = record_text(&RData::TXT(txt)).unwrap();
            prop_assert!(t.len() <= MAX_TXT_BYTES + '…'.len_utf8());
            prop_assert!(!t.chars().any(char::is_control));
        }
    }
}
