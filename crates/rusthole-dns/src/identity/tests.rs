use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};

use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::{Name, Record};
use rusthole_core::Config;
use rusthole_core::config::{
    Client, ConditionalForward, Group, LocalRecord, RecordType as CfgType,
};
use rusthole_core::net::MacAddr;
use tokio::net::UdpSocket;

use super::*;
use crate::neighbors::StaticNeighbors;

fn config(clients: &[(&str, &[&str])]) -> Config {
    let group = |name: &str| Group {
        name: name.to_owned(),
        enabled: true,
        comment: None,
    };
    Config {
        groups: vec![group("default"), group("kids")],
        clients: clients
            .iter()
            .map(|(id, groups)| Client {
                id: (*id).to_owned(),
                groups: groups.iter().map(|g| (*g).to_owned()).collect(),
                comment: None,
            })
            .collect(),
        ..Config::default()
    }
}

fn fast() -> IdentitySettings {
    IdentitySettings {
        neighbor_refresh: Duration::from_millis(20),
        client_cache_ttl: Duration::from_millis(50),
        ptr_timeout: Duration::from_millis(500),
        ..IdentitySettings::default()
    }
}

fn start(cfg: &Config, source: Arc<dyn NeighborSource>) -> IdentityService {
    IdentityService::start(
        ClientTable::from_config(cfg).0,
        Arc::new(LocalZone::from_config(cfg).0),
        source,
        fast(),
    )
    .unwrap()
}

#[test]
fn start_needs_a_runtime() {
    let cfg = config(&[]);
    let r = IdentityService::start(
        ClientTable::from_config(&cfg).0,
        Arc::new(LocalZone::default()),
        Arc::new(StaticNeighbors::default()),
        fast(),
    );
    assert!(r.is_err());
}

/// Calls `f` until it returns true, at most 5 seconds.
async fn eventually(mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the condition did not come true"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn a_mac_that_comes_later_is_used() {
    let cfg = config(&[("02:00:00:00:00:01", &["kids"])]);
    let src = Arc::new(StaticNeighbors::default());
    let svc = start(&cfg, src.clone());
    let r = svc.resolver();
    let first = r.identify(ip("192.0.2.7"));
    assert_eq!(first.matched, Some(MatchedBy::Default));
    assert_eq!(first.groups.as_ref(), ["default".to_owned()]);
    assert_eq!(first.mac, None);
    let mac = MacAddr::parse("02:00:00:00:00:01").unwrap();
    src.set(HashMap::from([(Ipv4Addr::new(192, 0, 2, 7), mac)]));
    eventually(|| r.identify(ip("192.0.2.7")).matched == Some(MatchedBy::Mac)).await;
    let c = r.identify(ip("192.0.2.7"));
    assert_eq!(c.mac, Some(mac));
    assert_eq!(c.groups.as_ref(), ["kids".to_owned()]);
    // No host-name client: no PTR task.
    assert!(r.ptr.is_none());
    assert_eq!(svc.task_count(), 1);
    assert!(svc.shutdown(Duration::from_secs(2)).await);
}

#[tokio::test]
async fn host_name_from_local_records() {
    let mut cfg = config(&[("nas.lan", &["kids"])]);
    cfg.local_dns.records = vec![LocalRecord {
        name: "nas.lan".to_owned(),
        record_type: CfgType::A,
        value: "192.0.2.10".to_owned(),
    }];
    let svc = start(&cfg, Arc::new(StaticNeighbors::default()));
    let r = svc.resolver();
    // The first query uses the default until the name is known.
    let first = r.identify(ip("192.0.2.10"));
    assert_eq!(first.matched, Some(MatchedBy::Default));
    eventually(|| r.identify(ip("192.0.2.10")).matched == Some(MatchedBy::Hostname)).await;
    assert_eq!(
        r.identify(ip("192.0.2.10")).groups.as_ref(),
        ["kids".to_owned()]
    );
    assert_eq!(r.hostname_of(ip("192.0.2.10")).unwrap().as_str(), "nas.lan");
    assert!(svc.shutdown(Duration::from_secs(2)).await);
}

/// A fake conditional forwarding server: it answers each PTR query with `printer.lan`.
async fn fake_ptr_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = sock.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&count);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            c.fetch_add(1, Ordering::SeqCst);
            let mut m = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
            m.queries.clone_from(&q.queries);
            if let Some(query) = q.queries.first() {
                m.answers.push(Record::from_rdata(
                    query.name().clone(),
                    600,
                    RData::PTR(PTR(Name::from_ascii("Printer.LAN.").unwrap())),
                ));
            }
            let _ = sock.send_to(&m.to_vec().unwrap(), peer).await;
        }
    });
    (addr, count)
}

#[tokio::test]
async fn host_name_from_conditional_forwarding() {
    let (server, count) = fake_ptr_server().await;
    let mut cfg = config(&[("printer.lan", &["kids"])]);
    cfg.local_dns.conditional_forwarding = vec![ConditionalForward {
        enabled: true,
        cidr: "127.0.0.0/8".to_owned(),
        server: server.to_string(),
        domain: None,
    }];
    let svc = start(&cfg, Arc::new(StaticNeighbors::default()));
    let r = svc.resolver();
    // Many queries before the answer start one lookup only.
    for _ in 0..20 {
        let _ = r.identify(ip("127.0.0.1"));
    }
    eventually(|| r.identify(ip("127.0.0.1")).matched == Some(MatchedBy::Hostname)).await;
    assert_eq!(
        r.hostname_of(ip("127.0.0.1")).unwrap().as_str(),
        "printer.lan"
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(svc.shutdown(Duration::from_secs(2)).await);
}

#[tokio::test]
async fn no_ptr_lookup_without_a_local_server() {
    let cfg = config(&[("printer.lan", &["kids"])]);
    let svc = start(&cfg, Arc::new(StaticNeighbors::default()));
    let r = svc.resolver();
    let peek = |addr: &str| {
        let ptr = r.ptr.as_ref().unwrap();
        ptr.cache.lock().get(&ip(addr), r.clock.now_ms()).cloned()
    };
    // A public address and a private address with no forward: no name, and no query to
    // any upstream (the config has no conditional forwarding server).
    for addr in ["198.51.100.20", "192.0.2.20"] {
        let _ = r.identify(ip(addr));
        eventually(|| peek(addr) == Some(PtrEntry::Unknown)).await;
        assert_eq!(r.identify(ip(addr)).matched, Some(MatchedBy::Default));
    }
    // An IP match needs no host name, so no lookup starts.
    let cfg = config(&[("printer.lan", &["kids"]), ("192.0.2.30", &["kids"])]);
    let svc2 = start(&cfg, Arc::new(StaticNeighbors::default()));
    let r2 = svc2.resolver();
    assert_eq!(r2.identify(ip("192.0.2.30")).matched, Some(MatchedBy::Ip));
    assert!(r2.ptr.as_ref().unwrap().cache.lock().is_empty());
    assert!(svc.shutdown(Duration::from_secs(2)).await);
    assert!(svc2.shutdown(Duration::from_secs(2)).await);
}

#[tokio::test]
async fn shutdown_and_drop_stop_every_task() {
    let cfg = config(&[("printer.lan", &["kids"])]);
    let svc = start(&cfg, Arc::new(StaticNeighbors::default()));
    assert_eq!(svc.task_count(), 2);
    assert!(svc.shutdown(Duration::from_secs(2)).await);
    assert_eq!(svc.task_count(), 0);

    let svc = start(&cfg, Arc::new(StaticNeighbors::default()));
    let spawner = svc.spawner.clone();
    assert_eq!(spawner.len(), 2);
    drop(svc);
    eventually(|| spawner.len() == 0).await;
}
