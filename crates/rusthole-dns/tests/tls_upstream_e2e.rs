//! End-to-end tests of the DoT and DoH upstreams and the clock fallback (part P7). The
//! upstreams are fake servers on 127.0.0.1 with a local-ca test certificate that the client
//! config trusts.
// Test code: a failed setup step is a test failure, so unwrap and panic are the right result.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use hickory_proto::op::{Message, ResponseCode};
use rusthole_core::upstream_health::{HealthConfig, HealthState};
use rusthole_dns::{
    DnsServer, DnsSettings, FixedWallClock, HandlerSettings, ListenMode, PoolSettings, ServerDeps,
    StaticInterfaces, TcpLimits, TlsTarget, UpstreamMode, UpstreamProto, UpstreamServer,
};
use tokio::net::UdpSocket;

/// The build time for these tests. The fake wall clock is around it.
const BUILD: i64 = 1_800_000_000;
const GOOD_CLOCK: i64 = BUILD + 3600;
const BAD_CLOCK: i64 = 0;

fn target(name: &str, addr: SocketAddr, path: &str) -> Arc<TlsTarget> {
    Arc::new(TlsTarget {
        name: name.to_owned(),
        addrs: vec![addr],
        port: addr.port(),
        path: path.to_owned(),
    })
}

fn dot(name: &str, addr: SocketAddr) -> UpstreamServer {
    UpstreamServer {
        addr,
        proto: UpstreamProto::Tls(target(name, addr, "")),
    }
}

fn doh(name: &str, addr: SocketAddr) -> UpstreamServer {
    UpstreamServer {
        addr,
        proto: UpstreamProto::Https(target(name, addr, "/dns-query")),
    }
}

fn udp(addr: SocketAddr) -> UpstreamServer {
    UpstreamServer {
        addr,
        proto: UpstreamProto::Udp,
    }
}

fn settings(servers: Vec<UpstreamServer>, fallback: Vec<UpstreamServer>) -> DnsSettings {
    DnsSettings {
        listen: ListenMode::Addrs(vec![LOCALHOST]),
        port: 0,
        acl_auto_local: true,
        acl_allow: Vec::new(),
        // No cache: each query goes to an upstream.
        handler: HandlerSettings {
            cache_entries: 0,
            ..HandlerSettings::default()
        },
        pool: PoolSettings {
            servers,
            fallback,
            timeout: Duration::from_millis(700),
            max_attempts: 3,
            max_inflight: 64,
            max_inflight_per_client: 64,
            health: HealthConfig::default(),
        },
        rescan_interval: Duration::from_secs(30),
        tcp: TcpLimits::default(),
        local: Arc::default(),
        doh: None,
        build_time_unix: BUILD,
        clock_check_interval: Duration::from_secs(60),
    }
}

async fn start(ca: &TestCa, s: DnsSettings, clock: Arc<FixedWallClock>) -> DnsServer {
    rusthole_dns::start(
        s,
        ServerDeps {
            interfaces: Arc::new(StaticInterfaces::default()),
            upstream_tls: Some(ca.upstream_tls()),
            wall_clock: clock,
            ..ServerDeps::default()
        },
    )
    .await
    .unwrap()
}

fn good_clock() -> Arc<FixedWallClock> {
    Arc::new(FixedWallClock::new(GOOD_CLOCK))
}

async fn ask(server: &DnsServer, id: u16, name: &str) -> Message {
    let sock = UdpSocket::bind((LOCALHOST, 0)).await.unwrap();
    sock.send_to(&query_msg(id, name), server.bound()[0].udp)
        .await
        .unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let m = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(m.metadata.id, id);
    m
}

/// The expected first A record of an answer from a fake that answers 192.0.2.`last`.
#[allow(clippy::unnecessary_wraps)] // Compared with `first_a`, which gives an Option.
fn a(last: u8) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::new(192, 0, 2, last))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_answers_and_reuses_the_connection() {
    let ca = test_ca(&["dns.test"]);
    let up = fake_dot(&ca, DotMode::Answer, 7).await;
    let server = start(
        &ca,
        settings(vec![dot("dns.test", up.addr)], vec![]),
        good_clock(),
    )
    .await;
    for i in 0..3u16 {
        let m = ask(&server, 100 + i, &format!("q{i}.example.")).await;
        assert_eq!(first_a(&m), a(7));
    }
    assert_eq!(
        up.conns.load(Ordering::SeqCst),
        1,
        "one connection for all queries"
    );
    assert_eq!(up.queries.load(Ordering::SeqCst), 3);
    assert_eq!(server.upstream_tls_connections(), 1);
    // The client sent the host name of the upstream as SNI.
    assert_eq!(*up.sni.lock(), vec!["dns.test".to_owned()]);
    // Shutdown closes the upstream connection.
    assert!(server.shutdown(WAIT).await);
    assert_eq!(server.task_count(), 0);
    assert!(eventually(|| up.closed.load(Ordering::SeqCst) == 1).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_ignores_wrong_id_and_wrong_question() {
    let ca = test_ca(&["dns.test"]);
    let up = fake_dot(&ca, DotMode::Tricky, 7).await;
    let server = start(
        &ca,
        settings(vec![dot("dns.test", up.addr)], vec![]),
        good_clock(),
    )
    .await;
    let m = ask(&server, 5, "tricky.example.").await;
    assert_eq!(first_a(&m), a(7), "the right answer, not 192.0.2.66");
    assert_eq!(server.upstream_health()[0], HealthState::Healthy);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_timeout_goes_to_the_next_upstream() {
    let ca = test_ca(&["dns.test"]);
    let silent = fake_dot(&ca, DotMode::Silent, 7).await;
    let good = fake_dot(&ca, DotMode::Answer, 8).await;
    let server = start(
        &ca,
        settings(
            vec![dot("dns.test", silent.addr), dot("dns.test", good.addr)],
            vec![],
        ),
        good_clock(),
    )
    .await;
    let m = ask(&server, 6, "slow.example.").await;
    assert_eq!(first_a(&m), a(8));
    assert_eq!(silent.queries.load(Ordering::SeqCst), 1);
    assert!(matches!(
        server.upstream_health()[0],
        HealthState::Suspect { .. }
    ));
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_certificate_for_another_name_fails() {
    let ca = test_ca(&["dns.test"]);
    let up = fake_dot(&ca, DotMode::Answer, 7).await;
    let plain = fake_udp(9).await;
    // The certificate has dns.test, not other.test.
    let server = start(
        &ca,
        settings(vec![dot("other.test", up.addr), udp(plain.addr)], vec![]),
        good_clock(),
    )
    .await;
    let m = ask(&server, 7, "name.example.").await;
    assert_eq!(first_a(&m), a(9), "the next upstream answered");
    assert_eq!(
        up.queries.load(Ordering::SeqCst),
        0,
        "no query over a bad TLS session"
    );
    assert!(matches!(
        server.upstream_health()[0],
        HealthState::Suspect { .. }
    ));
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_reconnects_after_the_server_closes() {
    let ca = test_ca(&["dns.test"]);
    let up = fake_dot(&ca, DotMode::Answer, 7).await;
    let server = start(
        &ca,
        settings(vec![dot("dns.test", up.addr)], vec![]),
        good_clock(),
    )
    .await;
    assert_eq!(first_a(&ask(&server, 1, "one.example.").await), a(7));
    assert!(server.shutdown(WAIT).await);
    // A new server (new pool) connects again.
    let server = start(
        &ca,
        settings(vec![dot("dns.test", up.addr)], vec![]),
        good_clock(),
    )
    .await;
    assert_eq!(first_a(&ask(&server, 2, "two.example.").await), a(7));
    assert_eq!(up.conns.load(Ordering::SeqCst), 2);
    assert!(server.shutdown(WAIT).await);
}

/// A server that closes its connections is not an upstream failure: the next query opens a
/// new connection (a failed reused connection gets one retry on a new one).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_server_close_is_not_a_failure() {
    let ca = test_ca(&["dns.test"]);
    let up = fake_dot(&ca, DotMode::CloseAfterAnswer, 7).await;
    let server = start(
        &ca,
        settings(vec![dot("dns.test", up.addr)], vec![]),
        good_clock(),
    )
    .await;
    for i in 0..4u16 {
        let m = ask(&server, 10 + i, &format!("c{i}.example.")).await;
        assert_eq!(first_a(&m), a(7));
        assert_eq!(server.upstream_health()[0], HealthState::Healthy);
    }
    assert_eq!(up.conns.load(Ordering::SeqCst), 4);
    assert!(server.shutdown(WAIT).await);
}

/// The query timeout of the tests with a connection that goes silent. It is long, so that
/// one timeout and two timeouts are far apart on a loaded machine.
const SILENT_TIMEOUT: Duration = Duration::from_millis(1500);

/// A reused connection that stays open but stops answering: the query times out once and
/// goes to the next upstream at once (no second try on a new connection with a new
/// timeout). The dead connection is not used again.
async fn silent_reused_connection_goes_to_the_next_upstream(dot_up: bool) {
    let ca = test_ca(&["dns.test"]);
    let (up, server_entry) = if dot_up {
        let up = fake_dot(&ca, DotMode::FirstConnGoesSilent, 7).await;
        let e = dot("dns.test", up.addr);
        (up, e)
    } else {
        let up = fake_doh(&ca, DohMode::FirstConnGoesSilent, 7).await;
        let e = doh("dns.test", up.addr);
        (up, e)
    };
    let plain = fake_udp(9).await;
    let mut s = settings(vec![server_entry, udp(plain.addr)], vec![]);
    s.pool.timeout = SILENT_TIMEOUT;
    let server = start(&ca, s, good_clock()).await;
    // The first query uses the first connection, which answers.
    assert_eq!(first_a(&ask(&server, 20, "e0.example.").await), a(7));
    assert_eq!(server.upstream_tls_connections(), 1);
    // The second query reuses that connection, which is now silent.
    let start = std::time::Instant::now();
    let m = ask(&server, 21, "e1.example.").await;
    let waited = start.elapsed();
    assert_eq!(first_a(&m), a(9), "the next upstream answered");
    // One connection and two queries: no second try on a new connection.
    assert_eq!(up.conns.load(Ordering::SeqCst), 1, "dot={dot_up}");
    assert_eq!(up.queries.load(Ordering::SeqCst), 2, "dot={dot_up}");
    assert_eq!(up.first_conn_queries.load(Ordering::SeqCst), 2);
    assert!(
        waited < SILENT_TIMEOUT + SILENT_TIMEOUT / 2,
        "about one timeout, not two: {waited:?}"
    );
    // The dead connection is not used again.
    assert_eq!(server.upstream_tls_connections(), 0, "dot={dot_up}");
    assert!(matches!(
        server.upstream_health()[0],
        HealthState::Suspect { .. }
    ));
    assert!(server.shutdown(WAIT).await);
    assert_eq!(server.task_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_silent_reused_connection_goes_to_the_next_upstream() {
    silent_reused_connection_goes_to_the_next_upstream(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_silent_reused_connection_goes_to_the_next_upstream() {
    silent_reused_connection_goes_to_the_next_upstream(false).await;
}

/// All DoT connections of an upstream are full: the extra queries go to the next upstream,
/// and the full upstream stays healthy (a local limit is not an upstream fault).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_dot_upstream_stays_healthy() {
    const BURST: u16 = 200;
    let ca = test_ca(&["dns.test"]);
    let slow = fake_dot(&ca, DotMode::Slow, 7).await;
    let plain = fake_udp(9).await;
    let mut s = settings(vec![dot("dns.test", slow.addr), udp(plain.addr)], vec![]);
    s.pool.timeout = Duration::from_secs(3);
    s.pool.max_inflight = 512;
    // One client sends the full burst: give it all slots.
    s.pool.max_inflight_per_client = 512;
    let server = start(&ca, s, good_clock()).await;
    let sock = UdpSocket::bind((LOCALHOST, 0)).await.unwrap();
    let to = server.bound()[0].udp;
    for i in 0..BURST {
        sock.send_to(&query_msg(i, &format!("full{i}.example.")), to)
            .await
            .unwrap();
    }
    let (mut from_dot, mut from_plain) = (0, 0);
    // The health of the DoT upstream when an overflow answer comes and no DoT answer came
    // yet. (Later DoT answers would hide a failure count, so the check is here.)
    let mut early_health = Vec::new();
    let mut buf = [0u8; 2048];
    for _ in 0..BURST {
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let m = Message::from_vec(&buf[..n]).unwrap();
        match first_a(&m) {
            x if x == a(7) => from_dot += 1,
            x if x == a(9) => {
                from_plain += 1;
                if from_dot == 0 {
                    early_health.push(server.upstream_health()[0]);
                }
            }
            x => panic!("unexpected answer {x:?}"),
        }
    }
    let cap = rusthole_dns::dot::MAX_CONNS * 2 * rusthole_dns::dot::MAX_PIPELINE;
    assert!(from_dot <= cap, "{from_dot}");
    assert!(from_plain > 0, "some queries found the DoT upstream full");
    assert!(
        !early_health.is_empty(),
        "overflow answers came before DoT answers"
    );
    assert!(
        early_health.iter().all(|h| *h == HealthState::Healthy),
        "{early_health:?}"
    );
    assert_eq!(server.upstream_health()[0], HealthState::Healthy);
    assert!(server.shutdown(WAIT).await);
}

/// Many queries at the same time on a cold pool open few connections: one connect at a
/// time, and the waiting queries use that connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_queries_opens_few_connections() {
    let ca = test_ca(&["dns.test"]);
    let d = fake_dot(&ca, DotMode::Answer, 7).await;
    let h = fake_doh(&ca, DohMode::Answer, 8).await;
    for (up, last, max_conns) in [
        (dot("dns.test", d.addr), 7, rusthole_dns::dot::MAX_CONNS),
        (doh("dns.test", h.addr), 8, 1),
    ] {
        let server = Arc::new(start(&ca, settings(vec![up], vec![]), good_clock()).await);
        let mut tasks = Vec::new();
        for i in 0..20u16 {
            let s = Arc::clone(&server);
            tasks.push(tokio::spawn(async move {
                first_a(&ask(&s, 500 + i, &format!("burst{i}.example.")).await)
            }));
        }
        for t in tasks {
            assert_eq!(t.await.unwrap(), a(last));
        }
        assert!(server.upstream_tls_connections() <= max_conns);
        assert!(server.shutdown(WAIT).await);
    }
    assert!(d.conns.load(Ordering::SeqCst) <= rusthole_dns::dot::MAX_CONNS);
    assert_eq!(h.conns.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_answers_with_id_zero_and_reuses_the_connection() {
    let ca = test_ca(&["dns.test"]);
    let up = fake_doh(&ca, DohMode::Answer, 7).await;
    let server = start(
        &ca,
        settings(vec![doh("dns.test", up.addr)], vec![]),
        good_clock(),
    )
    .await;
    for i in 0..3u16 {
        // The client ID comes back, although the upstream query used ID 0.
        let m = ask(&server, 300 + i, &format!("h{i}.example.")).await;
        assert_eq!(first_a(&m), a(7));
    }
    assert_eq!(up.conns.load(Ordering::SeqCst), 1);
    assert_eq!(up.queries.load(Ordering::SeqCst), 3);
    assert_eq!(server.upstream_tls_connections(), 1);
    // The client sent the host name of the URL as SNI.
    assert_eq!(*up.sni.lock(), vec!["dns.test".to_owned()]);
    assert!(server.shutdown(WAIT).await);
    assert_eq!(server.task_count(), 0);
    assert!(eventually(|| up.closed.load(Ordering::SeqCst) == 1).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_wrong_id_or_question_goes_to_the_next_upstream() {
    let ca = test_ca(&["dns.test"]);
    let wrong_id = fake_doh(&ca, DohMode::WrongId, 66).await;
    let wrong_q = fake_doh(&ca, DohMode::WrongQuestion, 66).await;
    let good = fake_doh(&ca, DohMode::Answer, 8).await;
    let server = start(
        &ca,
        settings(
            vec![
                doh("dns.test", wrong_id.addr),
                doh("dns.test", wrong_q.addr),
                doh("dns.test", good.addr),
            ],
            vec![],
        ),
        good_clock(),
    )
    .await;
    let m = ask(&server, 8, "mismatch.example.").await;
    assert_eq!(first_a(&m), a(8));
    let health = server.upstream_health();
    assert!(matches!(health[0], HealthState::Suspect { .. }));
    assert!(matches!(health[1], HealthState::Suspect { .. }));
    assert_eq!(health[2], HealthState::Healthy);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_timeout_and_wrong_name_go_to_the_next_upstream() {
    let ca = test_ca(&["dns.test"]);
    let silent = fake_doh(&ca, DohMode::Silent, 66).await;
    let named = fake_doh(&ca, DohMode::Answer, 66).await;
    let plain = fake_udp(9).await;
    // A mixed pool: DoH (silent), DoH (wrong name), plain UDP.
    let server = start(
        &ca,
        settings(
            vec![
                doh("dns.test", silent.addr),
                doh("other.test", named.addr),
                udp(plain.addr),
            ],
            vec![],
        ),
        good_clock(),
    )
    .await;
    let m = ask(&server, 9, "mixed.example.").await;
    assert_eq!(first_a(&m), a(9));
    assert_eq!(named.queries.load(Ordering::SeqCst), 0);
    let health = server.upstream_health();
    assert!(matches!(health[0], HealthState::Suspect { .. }));
    assert!(matches!(health[1], HealthState::Suspect { .. }));
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_pool_uses_health_then_order() {
    let ca = test_ca(&["dns.test"]);
    let d = fake_dot(&ca, DotMode::Answer, 7).await;
    let h = fake_doh(&ca, DohMode::Answer, 8).await;
    let plain = fake_udp(9).await;
    let server = start(
        &ca,
        settings(
            vec![
                udp(plain.addr),
                dot("dns.test", d.addr),
                doh("dns.test", h.addr),
            ],
            vec![],
        ),
        good_clock(),
    )
    .await;
    // All healthy: the first one in config order answers.
    assert_eq!(first_a(&ask(&server, 1, "m1.example.").await), a(9));
    assert_eq!(d.queries.load(Ordering::SeqCst), 0);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clock_not_plausible_uses_the_fallback_then_switches_back() {
    let ca = test_ca(&["dns.test"]);
    let d = fake_dot(&ca, DotMode::Answer, 7).await;
    let fb = fake_udp(9).await;
    let clock = Arc::new(FixedWallClock::new(BAD_CLOCK));
    let server = start(
        &ca,
        settings(vec![dot("dns.test", d.addr)], vec![udp(fb.addr)]),
        Arc::clone(&clock),
    )
    .await;
    assert_eq!(server.upstream_mode(), UpstreamMode::Fallback);
    let m = ask(&server, 1, "f1.example.").await;
    assert_eq!(first_a(&m), a(9), "the fallback answered");
    assert_eq!(d.conns.load(Ordering::SeqCst), 0, "DoT was skipped");
    assert_eq!(fb.count.load(Ordering::SeqCst), 1);
    // NTP sets the clock: the next check goes back to the encrypted upstream.
    clock.set(GOOD_CLOCK);
    assert_eq!(server.check_clock(), UpstreamMode::Encrypted);
    let m = ask(&server, 2, "f2.example.").await;
    assert_eq!(first_a(&m), a(7), "DoT answered");
    assert_eq!(
        fb.count.load(Ordering::SeqCst),
        1,
        "the fallback is not used"
    );
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clock_not_plausible_without_fallback_still_tries_encrypted() {
    let ca = test_ca(&["dns.test"]);
    let d = fake_dot(&ca, DotMode::Answer, 7).await;
    let clock = Arc::new(FixedWallClock::new(BAD_CLOCK));
    let server = start(&ca, settings(vec![dot("dns.test", d.addr)], vec![]), clock).await;
    // The ERROR is logged (see the unit tests of `clock`); the DoT upstream is tried.
    assert_eq!(server.upstream_mode(), UpstreamMode::EncryptedUnverified);
    let m = ask(&server, 1, "nf.example.").await;
    // The fake clock does not change the real TLS check, so DoT answers here.
    assert_eq!(first_a(&m), a(7));
    assert_eq!(d.queries.load(Ordering::SeqCst), 1);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clock_task_checks_on_its_period() {
    let ca = test_ca(&["dns.test"]);
    let d = fake_dot(&ca, DotMode::Answer, 7).await;
    let fb = fake_udp(9).await;
    let clock = Arc::new(FixedWallClock::new(BAD_CLOCK));
    let mut s = settings(vec![dot("dns.test", d.addr)], vec![udp(fb.addr)]);
    s.clock_check_interval = Duration::from_millis(50);
    let server = start(&ca, s, Arc::clone(&clock)).await;
    assert_eq!(server.upstream_mode(), UpstreamMode::Fallback);
    clock.set(GOOD_CLOCK);
    assert!(eventually(|| server.upstream_mode() == UpstreamMode::Encrypted).await);
    clock.set(BAD_CLOCK);
    assert!(eventually(|| server.upstream_mode() == UpstreamMode::Fallback).await);
    assert!(server.shutdown(WAIT).await);
    assert_eq!(server.task_count(), 0);
}

/// m1: the clock is after the build time, but the DoT certificate is not yet valid (as with
/// a wrong clock). The handshake fails with a date error, so the pool uses the fallback.
/// When a handshake passes again (here: the upstream gets a valid certificate), the clock
/// task probe makes the pool go back to the DoT upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_date_errors_use_the_fallback_then_switch_back() {
    const YEAR: i64 = 365 * 24 * 3600;
    let good = test_ca(&["dns.test"]);
    let future = test_ca_at(&["dns.test"], rusthole_tls::now_unix() + 3 * YEAR);
    let cert = Arc::new(parking_lot::Mutex::new(future.server_config()));
    let d = fake_dot_switch(Arc::clone(&cert), DotMode::Answer, 7).await;
    let fb = fake_udp(9).await;
    let mut roots = good.roots.clone();
    roots.roots.extend(future.roots.roots.iter().cloned());
    let mut s = settings(vec![dot("dns.test", d.addr)], vec![udp(fb.addr)]);
    s.clock_check_interval = Duration::from_millis(50);
    let server = rusthole_dns::start(
        s,
        ServerDeps {
            interfaces: Arc::new(StaticInterfaces::default()),
            upstream_tls: Some(rusthole_dns::UpstreamTls::with_roots(roots).unwrap()),
            wall_clock: good_clock(),
            ..ServerDeps::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(server.upstream_mode(), UpstreamMode::Encrypted);
    // The first query fails: the only allowed upstream has a date error.
    let m = ask(&server, 1, "date1.example.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(server.upstream_mode(), UpstreamMode::Fallback);
    // The clock check does not undo the date fallback.
    assert_eq!(server.check_clock(), UpstreamMode::Fallback);
    let m = ask(&server, 2, "date2.example.").await;
    assert_eq!(first_a(&m), a(9), "the fallback answered");
    // The upstream gets a valid certificate: the next probe passes.
    *cert.lock() = good.server_config();
    assert!(eventually(|| server.upstream_mode() == UpstreamMode::Encrypted).await);
    let m = ask(&server, 3, "date3.example.").await;
    assert_eq!(first_a(&m), a(7), "DoT answered");
    assert_eq!(fb.count.load(Ordering::SeqCst), 1);
    assert!(server.shutdown(WAIT).await);
    assert_eq!(server.task_count(), 0);
}

/// m1: without a fallback, date errors do not change the mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_date_errors_without_fallback_keep_the_mode() {
    let future = test_ca_at(
        &["dns.test"],
        rusthole_tls::now_unix() + 3 * 365 * 24 * 3600,
    );
    let d = fake_dot(&future, DotMode::Answer, 7).await;
    let server = start(
        &future,
        settings(vec![dot("dns.test", d.addr)], vec![]),
        good_clock(),
    )
    .await;
    let m = ask(&server, 1, "date4.example.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(server.upstream_mode(), UpstreamMode::Encrypted);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skipped_upstreams_get_no_probe() {
    let ca = test_ca(&["dns.test"]);
    let d = fake_dot(&ca, DotMode::Silent, 7).await;
    let fb = fake_udp(9).await;
    let clock = Arc::new(FixedWallClock::new(GOOD_CLOCK));
    let server = start(
        &ca,
        settings(vec![dot("dns.test", d.addr)], vec![udp(fb.addr)]),
        Arc::clone(&clock),
    )
    .await;
    // Make the DoT upstream go down (the silent fake times out).
    for i in 0..3u16 {
        let m = ask(&server, i, &format!("down{i}.example.")).await;
        assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    }
    assert!(matches!(
        server.upstream_health()[0],
        HealthState::Down { .. }
    ));
    let before = d.queries.load(Ordering::SeqCst);
    clock.set(BAD_CLOCK);
    assert_eq!(server.check_clock(), UpstreamMode::Fallback);
    // The prober runs each 500 ms; the backoff of the first probe is 1 s.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        d.queries.load(Ordering::SeqCst),
        before,
        "no probe while skipped"
    );
    assert!(matches!(
        server.upstream_health()[0],
        HealthState::Down { .. }
    ));
    assert!(server.shutdown(WAIT).await);
}
