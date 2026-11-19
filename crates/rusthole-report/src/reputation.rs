//! The reputation section (docs/PLAN.md R-D9): signals only, no score.
//!
//! ```mermaid
//! flowchart LR
//!     n[name] --> p[A through the upstream pool: the unfiltered answer]
//!     n --> q[A from Quad9 9.9.9.9]
//!     n --> c[A from Cloudflare 1.1.1.2]
//!     n --> t[Tranco rank of the registrable domain]
//!     p --> v{verdict of each filter}
//!     q --> v
//!     c --> v
//! ```
//!
//! Quad9 and Cloudflare for Families (1.1.1.2) block names of malware and phishing. A block
//! shows as NXDOMAIN (Quad9) or `0.0.0.0` (Cloudflare) while the unfiltered answer has an
//! address. Each source has its own time limit and its own result. The Tranco list ranks the
//! most popular registrable domains (top 1 million): a rank is a popularity signal, not a
//! safety signal.

use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use rusthole_core::DomainName;
use rusthole_core::stats::base::registrable;
use serde_json::{Value, json};
use tokio::net::UdpSocket;

use crate::dns::{DnsLookup, safe_text};
use crate::http::HttpGet;
use crate::model::{Outcome, Status};

/// The filtering resolvers: name, address, and what a block looks like.
pub const FILTERS: [(&str, &str); 2] = [
    ("Quad9", "9.9.9.9:53"),
    ("Cloudflare for Families", "1.1.1.2:53"),
];
/// The time limit of one source.
pub const SOURCE_LIMIT: Duration = Duration::from_secs(4);
/// The most datagrams that one UDP query reads (wrong answers are dropped).
pub const MAX_DATAGRAMS: usize = 8;
/// The Tranco rank API (no key).
pub const TRANCO_URL: &str = "https://tranco-list.eu/api/ranks/domain/";
/// The most bytes of a Tranco answer.
pub const MAX_TRANCO_BYTES: usize = 64 * 1024;

/// A short DNS answer: the response code and the IPv4 addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Short {
    /// The response code.
    pub rcode: u16,
    /// The A records (at most 16).
    pub addrs: Vec<Ipv4Addr>,
}

/// A boxed query future.
pub type AskFuture<'a> = Pin<Box<dyn Future<Output = Result<Short, String>> + Send + 'a>>;

/// One A query to a given DNS server. Tests use a fake.
pub trait ResolverAsk: Send + Sync + fmt::Debug {
    /// Asks `server` for the A records of `name`.
    fn ask<'a>(&'a self, server: SocketAddr, name: &'a DomainName) -> AskFuture<'a>;
}

/// What one filtering resolver says about a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The filter blocks the name (malware, phishing or a similar list).
    Blocked,
    /// The filter gives the name an address.
    Allowed,
    /// The name does not exist (also for the unfiltered answer).
    NoSuchName,
    /// The answers do not show a clear result.
    Unknown,
}

impl Verdict {
    /// The API name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Allowed => "allowed",
            Self::NoSuchName => "no_such_name",
            Self::Unknown => "unknown",
        }
    }
}

/// The verdict of a filter from its answer and the unfiltered answer (pure).
pub fn verdict(filter: &Short, unfiltered: Option<&Short>) -> Verdict {
    let nx = u16::from(ResponseCode::NXDomain);
    let unfiltered_has_addr =
        unfiltered.is_some_and(|u| u.rcode == 0 && u.addrs.iter().any(|a| !a.is_unspecified()));
    if filter.rcode == 0
        && !filter.addrs.is_empty()
        && filter.addrs.iter().all(Ipv4Addr::is_unspecified)
    {
        return Verdict::Blocked;
    }
    if filter.rcode == nx && unfiltered_has_addr {
        return Verdict::Blocked;
    }
    if filter.rcode == 0 && filter.addrs.iter().any(|a| !a.is_unspecified()) {
        return Verdict::Allowed;
    }
    if filter.rcode == nx && unfiltered.is_some_and(|u| u.rcode == nx) {
        return Verdict::NoSuchName;
    }
    Verdict::Unknown
}

/// The latest rank of a Tranco answer, or `None` when the domain is not in the list.
pub fn tranco_rank(body: &[u8]) -> Result<Option<(u64, String)>, String> {
    let v: Value = serde_json::from_slice(body).map_err(|e| format!("Tranco answer: {e}"))?;
    let ranks = v
        .get("ranks")
        .and_then(Value::as_array)
        .ok_or("Tranco answer: no ranks")?;
    // The newest date first; the API sorts this way, but do not trust it.
    let best = ranks
        .iter()
        .take(400)
        .filter_map(|r| {
            let rank = r.get("rank").and_then(Value::as_u64)?;
            let date = r.get("date").and_then(Value::as_str)?;
            Some((rank, safe_text(date, 32)))
        })
        .max_by(|a, b| a.1.cmp(&b.1));
    Ok(best)
}

/// The A records of a hickory answer (at most 16).
fn a_records(records: &[hickory_proto::rr::Record]) -> Vec<Ipv4Addr> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .take(16)
        .collect()
}

/// Runs the reputation section for `name`. Each source runs at the same time with its own
/// time limit.
pub async fn run(
    dns: &dyn DnsLookup,
    ask: &dyn ResolverAsk,
    http: &dyn HttpGet,
    name: &DomainName,
) -> Outcome {
    let base = registrable(name.as_str()).to_owned();
    let unfiltered = async {
        match tokio::time::timeout(SOURCE_LIMIT, dns.lookup(name, RecordType::A)).await {
            Ok(Ok(a)) => Ok(Short {
                rcode: a.rcode,
                addrs: a_records(&a.answers),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("no answer".to_owned()),
        }
    };
    let filter = |label: &'static str, server: &'static str| async move {
        let addr: SocketAddr = server.parse().map_err(|_| "bad server".to_owned())?;
        let r = tokio::time::timeout(SOURCE_LIMIT, ask.ask(addr, name)).await;
        let r = r.map_err(|_| format!("{label}: no answer in {} s", SOURCE_LIMIT.as_secs()))?;
        r.map_err(|e| format!("{label}: {e}"))
    };
    let tranco = async {
        let url = format!("{TRANCO_URL}{base}");
        let r = tokio::time::timeout(SOURCE_LIMIT, http.get(&url, MAX_TRANCO_BYTES))
            .await
            .map_err(|_| format!("no answer in {} s", SOURCE_LIMIT.as_secs()))??;
        if r.status != 200 {
            return Err(format!("HTTP {}", r.status));
        }
        tranco_rank(&r.body)
    };
    let [(l0, s0), (l1, s1)] = FILTERS;
    let (q9, cf, pool, rank) = tokio::join!(filter(l0, s0), filter(l1, s1), unfiltered, tranco);
    let pool_ok = pool.as_ref().ok();
    let mut any_ok = false;
    let mut filters = Vec::new();
    for ((label, server), r) in FILTERS.iter().zip([q9, cf]) {
        filters.push(match r {
            Ok(s) => {
                any_ok = true;
                json!({ "name": label, "server": server, "verdict": verdict(&s, pool_ok).as_str(), "rcode": s.rcode, "error": null })
            }
            Err(e) => json!({ "name": label, "server": server, "verdict": null, "rcode": null, "error": safe_text(&e, 200) }),
        });
    }
    let tranco = match rank {
        Ok(Some((rank, date))) => {
            any_ok = true;
            json!({ "domain": base, "rank": rank, "date": date, "error": null })
        }
        Ok(None) => {
            any_ok = true;
            json!({ "domain": base, "rank": null, "date": null, "error": null })
        }
        Err(e) => {
            json!({ "domain": base, "rank": null, "date": null, "error": safe_text(&e, 200) })
        }
    };
    let data = json!({
        "filters": filters,
        "tranco": tranco,
        "unfiltered_error": pool.as_ref().err().map(|e| safe_text(e, 200)),
    });
    if any_ok {
        Outcome {
            status: Status::Ok,
            data,
            error: None,
        }
    } else {
        Outcome {
            status: Status::Failed,
            data,
            error: Some("no source answered".to_owned()),
        }
    }
}

/// The production query: plain UDP from a random port, a random ID, and the reply checks of
/// the upstream code (the same ID, QR, opcode and question, from the server address).
#[derive(Debug, Clone, Copy, Default)]
pub struct UdpAsk;

impl ResolverAsk for UdpAsk {
    fn ask<'a>(&'a self, server: SocketAddr, name: &'a DomainName) -> AskFuture<'a> {
        Box::pin(async move {
            let qname =
                Name::from_ascii(format!("{}.", name.as_str())).map_err(|e| e.to_string())?;
            let query = Query::query(qname, RecordType::A);
            let mut idb = [0u8; 2];
            getrandom::fill(&mut idb).map_err(|e| e.to_string())?;
            let id = u16::from_be_bytes(idb);
            let bytes = rusthole_dns::wire::upstream_query(id, &query, false)
                .ok_or("cannot make the query")?;
            let sock = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| e.to_string())?;
            sock.send_to(&bytes, server)
                .await
                .map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 1500];
            for _ in 0..MAX_DATAGRAMS {
                let (n, from) = sock.recv_from(&mut buf).await.map_err(|e| e.to_string())?;
                if from != server {
                    continue;
                }
                let Some(reply) = buf.get(..n) else { continue };
                let Ok(m) = rusthole_dns::wire::check_upstream_reply(reply, id, &query) else {
                    continue;
                };
                return Ok(Short {
                    rcode: u16::from(m.metadata.response_code),
                    addrs: a_records(&m.answers),
                });
            }
            Err("no valid reply".to_owned())
        })
    }
}

/// A [`ResolverAsk`] that always fails (tests, tools).
#[derive(Debug, Clone)]
pub struct NoAsk(pub String);

impl ResolverAsk for NoAsk {
    fn ask<'a>(&'a self, _server: SocketAddr, _name: &'a DomainName) -> AskFuture<'a> {
        let reason = self.0.clone();
        Box::pin(async move { Err(reason) })
    }
}

/// Shared handle for [`crate::service::Sources`].
pub type Ask = Arc<dyn ResolverAsk>;

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests: a failure is a test failure.
pub(crate) mod tests {
    use std::collections::HashMap;

    use hickory_proto::rr::rdata::A;
    use proptest::prelude::*;

    use super::*;
    use crate::dns::tests::{FakeDns, answer, rec};
    use crate::rdap::tests::FakeHttp;

    fn short(rcode: u16, addrs: &[[u8; 4]]) -> Short {
        Short {
            rcode,
            addrs: addrs.iter().map(|a| Ipv4Addr::from(*a)).collect(),
        }
    }

    const NX: u16 = 3;

    #[test]
    fn verdicts() {
        let real = short(0, &[[104, 18, 4, 35]]);
        // Cloudflare: 0.0.0.0.
        assert_eq!(
            verdict(&short(0, &[[0, 0, 0, 0]]), Some(&real)),
            Verdict::Blocked
        );
        // Quad9: NXDOMAIN while the name exists.
        assert_eq!(verdict(&short(NX, &[]), Some(&real)), Verdict::Blocked);
        assert_eq!(verdict(&real, Some(&real)), Verdict::Allowed);
        assert_eq!(
            verdict(&short(NX, &[]), Some(&short(NX, &[]))),
            Verdict::NoSuchName
        );
        // No unfiltered answer: NXDOMAIN alone is not a block.
        assert_eq!(verdict(&short(NX, &[]), None), Verdict::Unknown);
        assert_eq!(verdict(&short(2, &[]), Some(&real)), Verdict::Unknown);
    }

    #[test]
    fn tranco_answers() {
        let body = br#"{"ranks":[{"date":"2026-11-17","rank":186},{"date":"2026-11-18","rank":185}],"domain":"example.com"}"#;
        assert_eq!(
            tranco_rank(body).unwrap(),
            Some((185, "2026-11-18".to_owned()))
        );
        assert_eq!(
            tranco_rank(br#"{"ranks":[],"domain":"x.com"}"#).unwrap(),
            None
        );
        assert!(tranco_rank(b"<html>").is_err());
        assert!(tranco_rank(b"{}").is_err());
    }

    /// A fake: fixed answers by server address.
    #[derive(Debug, Default)]
    pub(crate) struct FakeAsk(pub(crate) HashMap<SocketAddr, Result<Short, String>>);

    impl ResolverAsk for FakeAsk {
        fn ask<'a>(&'a self, server: SocketAddr, _name: &'a DomainName) -> AskFuture<'a> {
            let r = self
                .0
                .get(&server)
                .cloned()
                .unwrap_or_else(|| Err("no answer".to_owned()));
            Box::pin(async move { r })
        }
    }

    fn name(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    #[tokio::test]
    async fn run_gives_each_source_its_own_result() {
        let mut dns = FakeDns::default();
        dns.table.insert(
            ("bad.example.com".to_owned(), RecordType::A),
            Ok(answer(
                0,
                vec![rec(
                    "bad.example.com",
                    RData::A(A(Ipv4Addr::new(104, 18, 4, 35))),
                )],
            )),
        );
        let mut ask = FakeAsk::default();
        ask.0
            .insert("9.9.9.9:53".parse().unwrap(), Ok(short(NX, &[])));
        ask.0
            .insert("1.1.1.2:53".parse().unwrap(), Err("timeout".to_owned()));
        let http = FakeHttp::default().with(
            "https://tranco-list.eu/api/ranks/domain/example.com",
            200,
            r#"{"ranks":[{"date":"2026-11-18","rank":185}]}"#,
        );
        let o = run(&dns, &ask, &http, &name("bad.example.com")).await;
        assert_eq!(o.status, Status::Ok);
        assert_eq!(o.data["filters"][0]["verdict"], "blocked");
        assert_eq!(o.data["filters"][1]["verdict"], Value::Null);
        assert_eq!(
            o.data["filters"][1]["error"],
            "Cloudflare for Families: timeout"
        );
        assert_eq!(o.data["tranco"]["rank"], 185);
        assert_eq!(o.data["tranco"]["domain"], "example.com");

        let none = run(
            &dns,
            &FakeAsk::default(),
            &FakeHttp::default(),
            &name("bad.example.com"),
        )
        .await;
        assert_eq!(none.status, Status::Failed);
    }

    #[tokio::test]
    async fn udp_ask_checks_the_reply() {
        // A local server that first sends a reply with a wrong ID, then a good one.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            let q = hickory_proto::op::Message::from_vec(buf.get(..n).unwrap()).unwrap();
            let mut wrong = hickory_proto::op::Message::new(
                q.metadata.id.wrapping_add(1),
                hickory_proto::op::MessageType::Response,
                hickory_proto::op::OpCode::Query,
            );
            wrong.add_queries(q.queries.clone());
            server
                .send_to(&wrong.to_vec().unwrap(), from)
                .await
                .unwrap();
            let mut good = hickory_proto::op::Message::new(
                q.metadata.id,
                hickory_proto::op::MessageType::Response,
                hickory_proto::op::OpCode::Query,
            );
            good.add_queries(q.queries.clone());
            good.add_answer(rec("probe.test", RData::A(A(Ipv4Addr::UNSPECIFIED))));
            server.send_to(&good.to_vec().unwrap(), from).await.unwrap();
        });
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            UdpAsk.ask(addr, &name("probe.test")),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r, short(0, &[[0, 0, 0, 0]]));
        task.await.unwrap();
    }

    /// Live check of the real services (network). Run by hand:
    /// `cargo test -p rusthole-report live -- --ignored`.
    #[tokio::test]
    #[ignore = "uses the network"]
    async fn live_filters_and_tls() {
        let q9 = UdpAsk
            .ask("9.9.9.9:53".parse().unwrap(), &name("isitblocked.org"))
            .await
            .unwrap();
        assert_eq!(q9.rcode, NX, "Quad9 blocks its test name");
        let cf = UdpAsk
            .ask(
                "1.1.1.2:53".parse().unwrap(),
                &name("malware.testcategory.com"),
            )
            .await
            .unwrap();
        assert_eq!(
            cf.addrs,
            vec![Ipv4Addr::UNSPECIFIED],
            "Cloudflare blocks its test name"
        );
        let probe = crate::tls::TlsClient::new(rusthole_tls::system_roots().0);
        let p = crate::tls::TlsProbe::probe(
            &probe,
            &name("one.one.one.one"),
            "1.1.1.1:443".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(p.trusted, Ok(()));
    }

    proptest! {
        /// Any bytes: the Tranco parser never panics.
        #[test]
        fn tranco_parser_is_total(body in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = tranco_rank(&body);
        }

        /// A filter answer with a real address is never "blocked".
        #[test]
        fn a_real_address_is_never_blocked(a in 1u32.., rcode_u in 0u16..1) {
            let s = Short { rcode: rcode_u, addrs: vec![Ipv4Addr::from(a)] };
            prop_assert_eq!(verdict(&s, None), Verdict::Allowed);
        }
    }
}
