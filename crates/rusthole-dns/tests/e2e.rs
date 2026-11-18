//! End-to-end tests: a real server on 127.0.0.1 with free ports, and fake upstream servers.
// Test helpers: a failed setup step is a test failure, so unwrap and panic are the right result.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rusthole_core::acl::InterfaceNet;
use rusthole_core::net::Cidr;
use rusthole_core::upstream_health::{HealthConfig, HealthState};
use rusthole_dns::{
    AllowAll, DnsServer, DnsSettings, HandlerSettings, ListenMode, NoopObserver, PoolSettings,
    ServerDeps, StartError, StaticInterfaces, TcpLimits, UpstreamProto, UpstreamServer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const WAIT: Duration = Duration::from_secs(3);

// ---------- fake upstream ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Answer with A 192.0.2.1.
    Answer,
    /// UDP: an empty reply with TC. TCP: the full answer.
    Truncate,
    /// Send a wrong ID, a wrong question and a spoofed source first, then the answer.
    Tricky,
    /// Never answer.
    Silent,
    /// Answer SERVFAIL.
    ServFail,
    /// Answer after a delay in milliseconds.
    Delay(u64),
}

#[derive(Debug)]
struct Fake {
    addr: SocketAddr,
    udp: Arc<AtomicUsize>,
    tcp: Arc<AtomicUsize>,
    mode: Arc<std::sync::Mutex<Mode>>,
}

impl Fake {
    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
}

fn answer(q: &Message, last: u8) -> Message {
    let mut m = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
    m.metadata.recursion_available = true;
    m.queries.clone_from(&q.queries);
    if let Some(query) = q.queries.first() {
        m.answers.push(Record::from_rdata(
            query.name().clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, last))),
        ));
    }
    m
}

/// A UDP socket and a TCP listener on the same free port of `ip` (a loopback address). The
/// ports are random (CSPRNG), not from the OS: on Windows, the OS gives TCP ports in
/// sequence, and a full sequence can be in a UDP excluded port range.
async fn bind_udp_tcp(ip: IpAddr) -> (UdpSocket, TcpListener) {
    for _ in 0..256 {
        let port = 1024 + u16::try_from(getrandom::u32().unwrap() % 64_512).unwrap();
        if let Ok(udp) = UdpSocket::bind((ip, port)).await
            && let Ok(tcp) = TcpListener::bind((ip, port)).await
        {
            return (udp, tcp);
        }
    }
    panic!("no free port");
}

// One test helper with the UDP and TCP sides of the fake together: easier to read than split.
#[allow(clippy::too_many_lines)]
async fn fake(mode: Mode) -> Fake {
    let shared_mode = Arc::new(std::sync::Mutex::new(mode));
    let (udp, tcp) = bind_udp_tcp(LOCALHOST).await;
    let addr = udp.local_addr().unwrap();
    let udp_count = Arc::new(AtomicUsize::new(0));
    let tcp_count = Arc::new(AtomicUsize::new(0));
    let udp = Arc::new(udp);
    {
        let count = Arc::clone(&udp_count);
        let shared_mode = Arc::clone(&shared_mode);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                let Ok(q) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let udp = Arc::clone(&udp);
                let mode = *shared_mode.lock().unwrap();
                tokio::spawn(async move {
                    let send = |m: Message| {
                        let udp = Arc::clone(&udp);
                        async move {
                            udp.send_to(&m.to_vec().unwrap(), peer).await.unwrap();
                        }
                    };
                    match mode {
                        Mode::Answer => send(answer(&q, 1)).await,
                        Mode::Truncate => {
                            let mut m = answer(&q, 1);
                            m.answers.clear();
                            m.metadata.truncation = true;
                            send(m).await;
                        }
                        Mode::Tricky => {
                            let mut wrong_id = answer(&q, 66);
                            wrong_id.metadata.id = q.metadata.id.wrapping_add(1);
                            send(wrong_id).await;
                            let mut wrong_q = answer(&q, 66);
                            wrong_q.queries = vec![Query::query(
                                Name::from_ascii("other.example.").unwrap(),
                                RecordType::A,
                            )];
                            send(wrong_q).await;
                            // Right ID and question, but from another source port.
                            let spoof = UdpSocket::bind((LOCALHOST, 0)).await.unwrap();
                            spoof
                                .send_to(&answer(&q, 66).to_vec().unwrap(), peer)
                                .await
                                .unwrap();
                            tokio::time::sleep(Duration::from_millis(30)).await;
                            send(answer(&q, 1)).await;
                        }
                        Mode::Silent => {}
                        Mode::ServFail => {
                            let mut m = answer(&q, 1);
                            m.answers.clear();
                            m.metadata.response_code = ResponseCode::ServFail;
                            send(m).await;
                        }
                        Mode::Delay(ms) => {
                            tokio::time::sleep(Duration::from_millis(ms)).await;
                            send(answer(&q, 1)).await;
                        }
                    }
                });
            }
        });
    }
    {
        let count = Arc::clone(&tcp_count);
        let shared_mode = Arc::clone(&shared_mode);
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = tcp.accept().await else {
                    continue;
                };
                let count = Arc::clone(&count);
                let mode = *shared_mode.lock().unwrap();
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if s.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let q = Message::from_vec(&buf).unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    if mode == Mode::Silent {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        return;
                    }
                    let out = answer(&q, 1).to_vec().unwrap();
                    let mut framed = u16::try_from(out.len()).unwrap().to_be_bytes().to_vec();
                    framed.extend_from_slice(&out);
                    let _ = s.write_all(&framed).await;
                });
            }
        });
    }
    Fake {
        addr,
        udp: udp_count,
        tcp: tcp_count,
        mode: shared_mode,
    }
}

// ---------- server setup ----------

fn udp_upstream(f: &Fake) -> UpstreamServer {
    UpstreamServer {
        addr: f.addr,
        proto: UpstreamProto::Udp,
    }
}

fn settings(servers: Vec<UpstreamServer>) -> DnsSettings {
    DnsSettings {
        listen: ListenMode::Addrs(vec![LOCALHOST]),
        port: 0,
        acl_auto_local: true,
        acl_allow: Vec::new(),
        handler: HandlerSettings::default(),
        pool: PoolSettings {
            servers,
            timeout: Duration::from_millis(300),
            max_attempts: 3,
            max_inflight: 64,
            health: HealthConfig::default(),
        },
        rescan_interval: Duration::from_secs(30),
        tcp: TcpLimits::default(),
    }
}

fn deps(interfaces: Arc<StaticInterfaces>) -> ServerDeps {
    ServerDeps {
        interfaces,
        filter: Arc::new(AllowAll),
        observer: Arc::new(NoopObserver),
    }
}

async fn start(settings: DnsSettings) -> DnsServer {
    rusthole_dns::start(settings, deps(Arc::new(StaticInterfaces::default())))
        .await
        .unwrap()
}

fn first_udp(server: &DnsServer) -> SocketAddr {
    server.bound()[0].udp
}

// ---------- client ----------

fn query(id: u16, qname: &str, edns: bool) -> Vec<u8> {
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_ascii(qname).unwrap(),
        RecordType::A,
    ));
    if edns {
        let mut e = Edns::new();
        e.set_max_payload(1232);
        m.set_edns(e);
    }
    m.to_vec().unwrap()
}

async fn ask_udp_wait(server: SocketAddr, id: u16, qname: &str, wait: Duration) -> Option<Message> {
    let sock = UdpSocket::bind((LOCALHOST, 0)).await.unwrap();
    sock.send_to(&query(id, qname, true), server).await.unwrap();
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(Message::from_vec(&buf[..n]).unwrap()),
        _ => None,
    }
}

async fn ask_udp(server: SocketAddr, id: u16, qname: &str) -> Message {
    ask_udp_wait(server, id, qname, WAIT)
        .await
        .unwrap_or_else(|| panic!("no answer for {qname}"))
}

async fn tcp_send(s: &mut TcpStream, bytes: &[u8]) {
    let mut framed = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(bytes);
    s.write_all(&framed).await.unwrap();
}

async fn tcp_recv(s: &mut TcpStream) -> Option<Message> {
    let mut len = [0u8; 2];
    match tokio::time::timeout(WAIT, s.read_exact(&mut len)).await {
        Ok(Ok(_)) => {}
        _ => return None,
    }
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    tokio::time::timeout(WAIT, s.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    Some(Message::from_vec(&buf).unwrap())
}

fn a_value(m: &Message) -> Ipv4Addr {
    match &m.answers.first().unwrap().data {
        RData::A(a) => a.0,
        other => panic!("not an A record: {other:?}"),
    }
}

/// True when UDP and TCP can bind `addr` again: the server released its sockets.
async fn port_is_free(addr: SocketAddr) -> bool {
    UdpSocket::bind(addr).await.is_ok() && TcpListener::bind(addr).await.is_ok()
}

// ---------- tests ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_then_answers_from_cache() {
    let up = fake(Mode::Answer).await;
    let server = start(settings(vec![udp_upstream(&up)])).await;
    let addr = first_udp(&server);

    let m = ask_udp(addr, 11, "www.example.com.").await;
    assert_eq!(m.metadata.id, 11);
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(a_value(&m), Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(up.udp.load(Ordering::SeqCst), 1);

    let m = ask_udp(addr, 12, "WWW.example.com.").await;
    assert_eq!(m.metadata.id, 12);
    assert_eq!(a_value(&m), Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(
        up.udp.load(Ordering::SeqCst),
        1,
        "second query must come from the cache"
    );
    assert_eq!(server.cache_len(), 1);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_client_with_two_queries_on_one_connection() {
    let up = fake(Mode::Answer).await;
    let server = start(settings(vec![udp_upstream(&up)])).await;
    let tcp = server.bound()[0].tcp;
    let mut s = TcpStream::connect(tcp).await.unwrap();
    tcp_send(&mut s, &query(1, "a.example.", false)).await;
    tcp_send(&mut s, &query(2, "b.example.", false)).await;
    let m1 = tcp_recv(&mut s).await.unwrap();
    let m2 = tcp_recv(&mut s).await.unwrap();
    assert_eq!((m1.metadata.id, m2.metadata.id), (1, 2));
    assert_eq!(a_value(&m2), Ipv4Addr::new(192, 0, 2, 1));
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_reply_is_retried_over_tcp() {
    let up = fake(Mode::Truncate).await;
    let server = start(settings(vec![udp_upstream(&up)])).await;
    let m = ask_udp(first_udp(&server), 21, "tc.example.").await;
    assert!(!m.metadata.truncation);
    assert_eq!(a_value(&m), Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(up.udp.load(Ordering::SeqCst), 1);
    assert_eq!(up.tcp.load(Ordering::SeqCst), 1);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_id_wrong_question_and_spoofed_source_are_ignored() {
    let up = fake(Mode::Tricky).await;
    let server = start(settings(vec![udp_upstream(&up)])).await;
    let m = ask_udp(first_udp(&server), 31, "poison.example.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    // .66 is in each wrong reply; only the last, correct reply has .1.
    assert_eq!(a_value(&m), Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(m.answers.len(), 1);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_fails_over_to_the_second_upstream() {
    let silent = fake(Mode::Silent).await;
    let good = fake(Mode::Answer).await;
    let server = start(settings(vec![udp_upstream(&silent), udp_upstream(&good)])).await;
    let m = ask_udp(first_udp(&server), 41, "failover.example.").await;
    assert_eq!(a_value(&m), Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(silent.udp.load(Ordering::SeqCst), 1);
    assert_eq!(good.udp.load(Ordering::SeqCst), 1);
    let health = server.upstream_health();
    assert_eq!(health[0], HealthState::Suspect { failures: 1 });
    assert_eq!(health[1], HealthState::Healthy);
    // The next query goes to the healthy upstream first.
    let _ = ask_udp(first_udp(&server), 42, "next.example.").await;
    assert_eq!(silent.udp.load(Ordering::SeqCst), 1);
    assert_eq!(good.udp.load(Ordering::SeqCst), 2);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn servfail_fails_over_but_keeps_health() {
    let bad = fake(Mode::ServFail).await;
    let good = fake(Mode::Answer).await;
    let server = start(settings(vec![udp_upstream(&bad), udp_upstream(&good)])).await;
    let m = ask_udp(first_udp(&server), 43, "sf.example.").await;
    assert_eq!(a_value(&m), Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(server.upstream_health()[0], HealthState::Healthy);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_upstreams_failing_gives_servfail() {
    let silent = fake(Mode::Silent).await;
    let server = start(settings(vec![UpstreamServer {
        addr: silent.addr,
        proto: UpstreamProto::Udp,
    }]))
    .await;
    let m = ask_udp(first_udp(&server), 44, "dead.example.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(m.metadata.id, 44);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn off_net_client_gets_no_udp_answer_and_tcp_refused() {
    let up = fake(Mode::Answer).await;
    let mut s = settings(vec![udp_upstream(&up)]);
    // Loopback is not allowed: the client 127.0.0.1 is off-net for this ACL.
    s.acl_auto_local = false;
    s.acl_allow = vec![Cidr::parse("198.51.100.0/24").unwrap()];
    let server = start(s).await;
    let bound = server.bound()[0];

    assert!(
        ask_udp_wait(bound.udp, 51, "x.example.", Duration::from_millis(500))
            .await
            .is_none()
    );
    let mut t = TcpStream::connect(bound.tcp).await.unwrap();
    tcp_send(&mut t, &query(52, "x.example.", false)).await;
    let m = tcp_recv(&mut t).await.unwrap();
    assert_eq!(m.metadata.id, 52);
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    // The server closes the connection after REFUSED.
    assert!(tcp_recv(&mut t).await.is_none());
    assert_eq!(up.udp.load(Ordering::SeqCst), 0);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_off_net_tcp_connection_closes_after_the_short_limit() {
    let up = fake(Mode::Answer).await;
    let mut s = settings(vec![udp_upstream(&up)]);
    s.acl_auto_local = false;
    s.acl_allow = vec![Cidr::parse("198.51.100.0/24").unwrap()];
    // A LAN client may stay idle for 10 s; an off-net client gets 1 s.
    s.tcp.idle_timeout = Duration::from_secs(10);
    let server = start(s).await;
    let tcp = server.bound()[0].tcp;
    let started = std::time::Instant::now();
    let mut t = TcpStream::connect(tcp).await.unwrap();
    let mut buf = [0u8; 2];
    let read = tokio::time::timeout(WAIT, t.read(&mut buf)).await;
    // EOF (or a reset) before the time limit of the test.
    assert!(
        matches!(read, Ok(Ok(0) | Err(_))),
        "the connection must close: {read:?}"
    );
    assert!(started.elapsed() < Duration::from_millis(2500));
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acl_follows_the_fake_interface_list() {
    let up = fake(Mode::Answer).await;
    let mut s = settings(vec![udp_upstream(&up)]);
    s.acl_auto_local = true;
    let net = |a: u8, b: u8, c: u8| InterfaceNet {
        addr: Ipv4Addr::new(a, b, c, 10),
        prefix: 24,
    };
    let ifs = Arc::new(StaticInterfaces::new(vec![net(192, 0, 2)]));
    let server = rusthole_dns::start(s, deps(Arc::clone(&ifs)))
        .await
        .unwrap();
    let lan: IpAddr = "192.0.2.77".parse().unwrap();
    let other: IpAddr = "198.51.100.7".parse().unwrap();
    let acl = server.acl().unwrap();
    assert!(acl.allows(lan));
    assert!(!acl.allows(other));
    assert!(acl.allows(LOCALHOST));

    ifs.set(vec![net(198, 51, 100)]);
    server.rescan().await;
    let acl = server.acl().unwrap();
    assert!(!acl.allows(lan));
    assert!(acl.allows(other));
    assert!(acl.allows(LOCALHOST));
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_local_allows_loopback_with_a_fake_interface_list() {
    let up = fake(Mode::Answer).await;
    let mut s = settings(vec![udp_upstream(&up)]);
    s.acl_auto_local = true;
    // The fake host has one LAN interface. Off-net decisions for other client addresses
    // are in the handler unit tests (the client address is an input there).
    let ifs = Arc::new(StaticInterfaces::new(vec![InterfaceNet {
        addr: Ipv4Addr::new(192, 0, 2, 10),
        prefix: 24,
    }]));
    let server = rusthole_dns::start(s, deps(Arc::clone(&ifs)))
        .await
        .unwrap();
    let addr = first_udp(&server);
    // auto_local allows loopback.
    assert!(ask_udp_wait(addr, 1, "a.example.", WAIT).await.is_some());
    assert!(server.shutdown(WAIT).await);
}

// On other systems, "auto" binds 127.0.0.1 only (development mode).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_listen_rebinds_when_interfaces_change() {
    let up = fake(Mode::Answer).await;
    let mut s = settings(vec![udp_upstream(&up)]);
    s.listen = ListenMode::Auto;
    let net = |last: u8| InterfaceNet {
        addr: Ipv4Addr::new(127, 0, 0, last),
        prefix: 8,
    };
    let ifs = Arc::new(StaticInterfaces::new(vec![net(1)]));
    let server = rusthole_dns::start(s, deps(Arc::clone(&ifs)))
        .await
        .unwrap();
    let bound = server.bound();
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].udp.ip(), LOCALHOST);
    assert!(
        ask_udp_wait(bound[0].udp, 1, "a.example.", WAIT)
            .await
            .is_some()
    );

    ifs.set(vec![net(1), net(2)]);
    server.rescan().await;
    let bound = server.bound();
    assert_eq!(bound.len(), 2);
    let second = bound
        .iter()
        .find(|b| b.udp.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
        .unwrap()
        .udp;
    assert!(ask_udp_wait(second, 2, "b.example.", WAIT).await.is_some());

    let first = bound.iter().find(|b| b.udp.ip() == LOCALHOST).unwrap().udp;
    ifs.set(vec![net(2)]);
    server.rescan().await;
    let bound = server.bound();
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].udp, second);
    // The removed address is released.
    let mut freed = false;
    for _ in 0..50 {
        if UdpSocket::bind(first).await.is_ok() {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(freed, "the old listener must be closed");
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identical_queries_in_flight_share_one_upstream_query() {
    let up = fake(Mode::Delay(150)).await;
    let server = start(settings(vec![udp_upstream(&up)])).await;
    let addr = first_udp(&server);
    let mut tasks = Vec::new();
    for i in 0..10u16 {
        tasks.push(tokio::spawn(async move {
            ask_udp(addr, 100 + i, "same.example.").await
        }));
    }
    for (i, t) in tasks.into_iter().enumerate() {
        let m = t.await.unwrap();
        assert_eq!(usize::from(m.metadata.id), 100 + i);
        assert_eq!(a_value(&m), Ipv4Addr::new(192, 0, 2, 1));
    }
    assert_eq!(up.udp.load(Ordering::SeqCst), 1);
    assert_eq!(server.inflight_upstream(), 0);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_finishes_in_flight_query_and_stops_all_tasks() {
    let up = fake(Mode::Delay(150)).await;
    let server = start(settings(vec![udp_upstream(&up)])).await;
    let bound = server.bound()[0];
    assert!(server.task_count() >= 3);
    let pending = tokio::spawn(async move { ask_udp(bound.udp, 61, "slow.example.").await });
    // Wait until the query is in flight: the upstream has it.
    for _ in 0..400 {
        if up.udp.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(up.udp.load(Ordering::SeqCst), 1);
    assert!(server.shutdown(WAIT).await);
    assert_eq!(server.task_count(), 0);
    // The query that was in flight still got its answer.
    let m = pending.await.unwrap();
    assert_eq!(a_value(&m), Ipv4Addr::new(192, 0, 2, 1));
    assert!(port_is_free(bound.udp).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_hard_stops_after_grace() {
    let up = fake(Mode::Silent).await;
    let mut s = settings(vec![udp_upstream(&up)]);
    s.pool.timeout = Duration::from_secs(10);
    let server = start(s).await;
    let bound = server.bound()[0];
    let _pending =
        tokio::spawn(async move { ask_udp_wait(bound.udp, 62, "stuck.example.", WAIT).await });
    // Wait until the query is in flight: the upstream has it.
    for _ in 0..400 {
        if up.udp.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(up.udp.load(Ordering::SeqCst), 1);
    // The upstream never answers: the grace time ends, and the hard stop ends the tasks.
    assert!(!server.shutdown(Duration::from_millis(200)).await);
    assert_eq!(server.task_count(), 0);
    assert!(port_is_free(bound.udp).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_server_stops_all_tasks() {
    let up = fake(Mode::Answer).await;
    let server = start(settings(vec![udp_upstream(&up)])).await;
    let bound = server.bound()[0];
    drop(server);
    let mut freed = false;
    for _ in 0..100 {
        if port_is_free(bound.udp).await {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(freed, "the sockets must be closed after drop");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_error_stops_the_listeners_it_started() {
    let up = fake(Mode::Answer).await;
    // 127.0.0.2 is busy on this port, so its bind fails after 127.0.0.1 is bound. The port
    // comes from the blocker, so it is free for UDP and TCP (not in an excluded range).
    let second = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let blocker = bind_udp_tcp(second).await;
    let port = blocker.0.local_addr().unwrap().port();
    let mut s = settings(vec![udp_upstream(&up)]);
    s.port = port;
    s.listen = ListenMode::Addrs(vec![LOCALHOST, second]);
    let err = rusthole_dns::start(s, deps(Arc::new(StaticInterfaces::default())))
        .await
        .unwrap_err();
    assert!(matches!(err, StartError::Bind { .. }), "{err}");
    drop(blocker);
    assert!(port_is_free(SocketAddr::new(LOCALHOST, port)).await);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_listen_with_no_address_fails() {
    let up = fake(Mode::Answer).await;
    let mut s = settings(vec![udp_upstream(&up)]);
    s.listen = ListenMode::Auto;
    let err = rusthole_dns::start(s, deps(Arc::new(StaticInterfaces::default())))
        .await
        .unwrap_err();
    assert!(matches!(err, StartError::NoListener), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn down_upstream_is_probed_and_recovers() {
    let flaky = fake(Mode::Silent).await;
    let good = fake(Mode::Answer).await;
    let mut s = settings(vec![udp_upstream(&flaky), udp_upstream(&good)]);
    s.pool.health = HealthConfig {
        down_after: 1,
        base_backoff_ms: 100,
        max_backoff_ms: 1_000,
    };
    let server = start(s).await;
    let m = ask_udp(first_udp(&server), 71, "probe.example.").await;
    assert_eq!(a_value(&m), Ipv4Addr::new(192, 0, 2, 1));
    assert!(matches!(
        server.upstream_health()[0],
        HealthState::Down { .. } | HealthState::Probing { .. }
    ));
    flaky.set_mode(Mode::Answer);
    let mut recovered = false;
    for _ in 0..100 {
        if server.upstream_health()[0] == HealthState::Healthy {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(recovered, "{:?}", server.upstream_health());
    // The probe reached the upstream.
    assert!(flaky.udp.load(Ordering::SeqCst) >= 2);
    assert!(server.shutdown(WAIT).await);
}

#[cfg(not(target_os = "linux"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_listen_binds_only_loopback_outside_linux() {
    let up = fake(Mode::Answer).await;
    let mut s = settings(vec![udp_upstream(&up)]);
    s.listen = ListenMode::Auto;
    // A LAN interface in the fake list is not bound on this OS.
    let ifs = Arc::new(StaticInterfaces::new(vec![InterfaceNet {
        addr: Ipv4Addr::new(192, 0, 2, 10),
        prefix: 24,
    }]));
    let server = rusthole_dns::start(s, deps(ifs)).await.unwrap();
    let bound = server.bound();
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].udp.ip(), LOCALHOST);
    assert!(
        ask_udp_wait(bound[0].udp, 1, "a.example.", WAIT)
            .await
            .is_some()
    );
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failover_stops_after_max_attempts() {
    let mut fakes = Vec::new();
    for _ in 0..5 {
        fakes.push(fake(Mode::Silent).await);
    }
    let mut s = settings(fakes.iter().map(udp_upstream).collect());
    s.pool.timeout = Duration::from_millis(100);
    s.pool.max_attempts = 3;
    let server = start(s).await;
    let m = ask_udp(first_udp(&server), 81, "bound.example.").await;
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    let counts: Vec<usize> = fakes.iter().map(|f| f.udp.load(Ordering::SeqCst)).collect();
    assert_eq!(counts, vec![1, 1, 1, 0, 0]);
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_connection_closes_after_max_queries() {
    let up = fake(Mode::Answer).await;
    let mut s = settings(vec![udp_upstream(&up)]);
    s.tcp.max_queries_per_connection = 2;
    let server = start(s).await;
    let tcp = server.bound()[0].tcp;
    let mut c = TcpStream::connect(tcp).await.unwrap();
    for id in 1..=3u16 {
        tcp_send(&mut c, &query(id, "limit.example.", false)).await;
    }
    assert_eq!(tcp_recv(&mut c).await.unwrap().metadata.id, 1);
    assert_eq!(tcp_recv(&mut c).await.unwrap().metadata.id, 2);
    assert!(
        tcp_recv(&mut c).await.is_none(),
        "the third query must not get an answer"
    );
    assert!(server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_resolver_uses_the_upstream_pool() {
    let up = fake(Mode::Answer).await;
    let server = start(settings(vec![udp_upstream(&up)])).await;
    let resolver = server.host_resolver();
    let name = rusthole_core::DomainName::parse("lists.example").unwrap();
    let addrs = resolver.resolve_ipv4(&name).await.unwrap();
    assert_eq!(addrs, vec![Ipv4Addr::new(192, 0, 2, 1)]);
    assert_eq!(up.udp.load(Ordering::SeqCst), 1);
    // The lookup does not fill the DNS cache.
    assert_eq!(server.cache_len(), 0);

    up.set_mode(Mode::ServFail);
    let err = resolver.resolve_ipv4(&name).await.unwrap_err();
    assert_eq!(err, rusthole_dns::ResolveError::Rcode(2));

    // After the stop, a lookup fails and does not hang.
    server.shutdown(Duration::from_millis(500)).await;
    up.set_mode(Mode::Answer);
    let result = tokio::time::timeout(WAIT, resolver.resolve_ipv4(&name)).await;
    assert_eq!(
        result,
        Ok(Err(rusthole_dns::ResolveError::Upstream(
            rusthole_dns::UpstreamError::Stopped
        )))
    );
}
