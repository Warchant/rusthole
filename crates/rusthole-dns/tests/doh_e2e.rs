//! End-to-end tests of the DoH listener (part P7): a real server on 127.0.0.1 with a free
//! port, a local-ca test certificate, a fake plain upstream and a DoH client that trusts the
//! test CA.
// Test code: a failed setup step is a test failure, so unwrap and panic are the right result.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use hickory_proto::op::ResponseCode;
use parking_lot::Mutex;
use rusthole_core::DomainName;
use rusthole_core::net::Cidr;
use rusthole_core::upstream_health::HealthConfig;
use rusthole_dns::{
    BlockKind, BlockReply, ClientTransport, DnsServer, DnsSettings, DohLimits, DohSettings,
    FilterVerdict, HandlerSettings, ListenMode, PoolSettings, QueryContext, QueryEvent,
    QueryFilter, QueryObserver, ServerDeps, StartError, StaticInterfaces, TcpLimits, UpstreamProto,
    UpstreamServer,
};

/// Blocks `blocked.example` with the NULL reply.
#[derive(Debug)]
struct BlockOne;

impl QueryFilter for BlockOne {
    fn on_query(&self, ctx: &QueryContext) -> FilterVerdict {
        if ctx.qname == "blocked.example" {
            FilterVerdict::Block(BlockReply {
                kind: BlockKind::Null,
                ttl: 2,
            })
        } else {
            FilterVerdict::Allow
        }
    }

    fn on_answer(&self, _ctx: &QueryContext, _names: &[DomainName]) -> FilterVerdict {
        FilterVerdict::Allow
    }
}

/// Records the transport of each query event.
#[derive(Debug, Default)]
struct Events(Mutex<Vec<ClientTransport>>);

impl QueryObserver for Events {
    fn on_event(&self, event: &QueryEvent) {
        self.0.lock().push(event.transport);
    }
}

fn settings(upstream: SocketAddr, limits: DohLimits) -> DnsSettings {
    DnsSettings {
        listen: ListenMode::Addrs(vec![LOCALHOST]),
        port: 0,
        acl_auto_local: true,
        acl_allow: Vec::new(),
        handler: HandlerSettings::default(),
        pool: PoolSettings {
            servers: vec![UpstreamServer {
                addr: upstream,
                proto: UpstreamProto::Udp,
            }],
            fallback: Vec::new(),
            timeout: Duration::from_millis(500),
            max_attempts: 3,
            max_inflight: 64,
            health: HealthConfig::default(),
        },
        rescan_interval: Duration::from_secs(30),
        tcp: TcpLimits::default(),
        local: Arc::default(),
        doh: Some(DohSettings {
            listen: ListenMode::Addrs(vec![LOCALHOST]),
            port: 0,
            limits,
        }),
        build_time_unix: rusthole_tls::MIN_BUILD_TIME_UNIX,
        clock_check_interval: Duration::from_secs(60),
    }
}

struct Harness {
    server: DnsServer,
    ca: TestCa,
    doh: SocketAddr,
    up: FakeUdp,
    events: Arc<Events>,
}

async fn harness_with(limits: DohLimits, edit: impl FnOnce(&mut DnsSettings)) -> Harness {
    let ca = test_ca(&["doh.lan", "dns.test"]);
    let up = fake_udp(1).await;
    let mut s = settings(up.addr, limits);
    edit(&mut s);
    let events = Arc::new(Events::default());
    let server = rusthole_dns::start(
        s,
        ServerDeps {
            interfaces: Arc::new(StaticInterfaces::default()),
            filter: Arc::new(BlockOne),
            observer: events.clone(),
            doh_tls: Some(rusthole_tls::doh_server_config(&ca.store).unwrap()),
            ..ServerDeps::default()
        },
    )
    .await
    .unwrap();
    let doh = server.doh_bound()[0];
    assert!(doh.ip().is_loopback());
    Harness {
        server,
        ca,
        doh,
        up,
        events,
    }
}

async fn harness() -> Harness {
    harness_with(DohLimits::default(), |_| {}).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_and_post_answer_over_http2() {
    let h = harness().await;
    let client = h.ca.client(&[b"h2"]);
    // GET with ID 0 (RFC 8484).
    let r = doh_request(
        &client,
        h.doh,
        get_req(h.doh, &query_msg(0, "a.example."), true),
    )
    .await
    .unwrap();
    assert_eq!(r.alpn.as_deref(), Some(&b"h2"[..]), "HTTP/2 is negotiated");
    assert_eq!(r.status, 200);
    assert_eq!(r.headers["content-type"], "application/dns-message");
    assert_eq!(r.headers["cache-control"], "max-age=300");
    let m = r.message();
    assert_eq!(m.metadata.id, 0);
    assert_eq!(first_a(&m), Some("192.0.2.1".parse().unwrap()));
    // POST with another ID: the reply has the same ID.
    let r = doh_request(
        &client,
        h.doh,
        post_req(
            h.doh,
            query_msg(4242, "b.example."),
            "application/dns-message",
            true,
        ),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.message().metadata.id, 4242);
    assert_eq!(first_a(&r.message()), Some("192.0.2.1".parse().unwrap()));
    assert_eq!(h.up.count.load(Ordering::SeqCst), 2);
    // DoH queries go through the observer like plain queries (statistics).
    assert_eq!(
        *h.events.0.lock(),
        vec![ClientTransport::Https, ClientTransport::Https]
    );
    assert!(h.server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http11_works_too() {
    let h = harness().await;
    let client = h.ca.client(&[b"http/1.1"]);
    let r = doh_request(
        &client,
        h.doh,
        get_req(h.doh, &query_msg(0, "c.example."), false),
    )
    .await
    .unwrap();
    assert_eq!(r.alpn.as_deref(), Some(&b"http/1.1"[..]));
    assert_eq!(r.status, 200);
    assert_eq!(first_a(&r.message()), Some("192.0.2.1".parse().unwrap()));
    assert!(h.server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_control_is_the_lowest_ttl_of_the_reply() {
    let h = harness().await;
    let client = h.ca.client(&[b"h2"]);
    let q = query_msg(0, "ttl.example.");
    let r = doh_request(&client, h.doh, get_req(h.doh, &q, true))
        .await
        .unwrap();
    assert_eq!(r.headers["cache-control"], "max-age=300");
    // A cached answer has an aged TTL; max-age follows it.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = doh_request(&client, h.doh, get_req(h.doh, &q, true))
        .await
        .unwrap();
    let ttl = r.message().answers[0].ttl;
    assert!(ttl < 300, "{ttl}");
    assert_eq!(
        r.headers["cache-control"],
        format!("max-age={ttl}").as_str()
    );
    assert_eq!(h.up.count.load(Ordering::SeqCst), 1);
    assert!(h.server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_errors_get_the_right_status() {
    let h = harness().await;
    for h2 in [true, false] {
        let alpn: &[u8] = if h2 { b"h2" } else { b"http/1.1" };
        let client = h.ca.client(&[alpn]);
        let send = |req| doh_request(&client, h.doh, req);
        // Wrong content type: 415.
        let r = send(post_req(
            h.doh,
            query_msg(0, "x.example."),
            "application/json",
            h2,
        ))
        .await
        .unwrap();
        assert_eq!(r.status, 415, "h2={h2}");
        // A body over 65535 bytes: 413.
        let r = send(post_req(
            h.doh,
            vec![0u8; 70_000],
            "application/dns-message",
            h2,
        ))
        .await
        .unwrap();
        assert_eq!(r.status, 413, "h2={h2}");
        // Bad base64url: 400.
        let req = http::Request::get(uri(h.doh, "/dns-query?dns=!!notbase64!!", h2))
            .header("host", "doh.lan")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();
        assert_eq!(send(req).await.unwrap().status, 400, "h2={h2}");
        // A message that is not a query (QR=1): 400.
        let mut resp = query_msg(0, "x.example.");
        resp[2] |= 0x80;
        assert_eq!(
            send(post_req(h.doh, resp, "application/dns-message", h2))
                .await
                .unwrap()
                .status,
            400
        );
        // Another path: 404.
        let req = http::Request::get(uri(h.doh, "/other", h2))
            .header("host", "doh.lan")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();
        assert_eq!(send(req).await.unwrap().status, 404, "h2={h2}");
        // Another method: 405.
        let req = http::Request::put(uri(h.doh, "/dns-query", h2))
            .header("host", "doh.lan")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();
        let r = send(req).await.unwrap();
        assert_eq!(r.status, 405, "h2={h2}");
        assert_eq!(r.headers["allow"], "GET, POST");
        // A too-long GET parameter: 414.
        let long = "A".repeat(rusthole_dns::doh_wire::MAX_GET_PARAM + 8);
        let req = http::Request::get(uri(h.doh, &format!("/dns-query?dns={long}"), h2))
            .header("host", "doh.lan")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();
        assert_eq!(send(req).await.unwrap().status, 414, "h2={h2}");
    }
    assert_eq!(h.up.count.load(Ordering::SeqCst), 0);
    assert!(h.server.shutdown(WAIT).await);
}

/// A chunked body has no Content-Length, so the streaming limit must stop it: 413. The
/// client sends a little more than the limit and does not end the body. The server must
/// answer before the body ends (a server that reads the full body first waits until its
/// request timeout of 20 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_body_over_the_limit_gets_413() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let limits = DohLimits {
        request_timeout: Duration::from_secs(20),
        ..DohLimits::default()
    };
    let h = harness_with(limits, |_| {}).await;
    let tcp = tokio::net::TcpStream::connect(h.doh).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from("doh.lan").unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(h.ca.client(&[b"http/1.1"]))
        .connect(name, tcp)
        .await
        .unwrap();
    let head = "POST /dns-query HTTP/1.1\r\nHost: doh.lan\r\n\
                Content-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n";
    tls.write_all(head.as_bytes()).await.unwrap();
    let chunk = vec![0u8; 16 * 1024];
    // 4 chunks of 16 KiB: 65536 bytes, one more than the limit. No last chunk: the body
    // does not end. The server can answer before the end, so a write error is not a test
    // failure.
    for _ in 0..4 {
        let mut c = format!("{:x}\r\n", chunk.len()).into_bytes();
        c.extend_from_slice(&chunk);
        c.extend_from_slice(b"\r\n");
        if tls.write_all(&c).await.is_err() {
            break;
        }
    }
    let _ = tls.flush().await;
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf))
        .await
        .expect("the server answers before the body ends")
        .unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 413"), "{text}");
    assert_eq!(h.up.count.load(Ordering::SeqCst), 0);
    assert!(h.server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_applies_to_doh_clients() {
    let h = harness().await;
    let client = h.ca.client(&[b"h2"]);
    let r = doh_request(
        &client,
        h.doh,
        get_req(h.doh, &query_msg(0, "blocked.example."), true),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    let m = r.message();
    assert_eq!(first_a(&m), Some(std::net::Ipv4Addr::UNSPECIFIED));
    assert_eq!(r.headers["cache-control"], "max-age=2");
    assert_eq!(h.up.count.load(Ordering::SeqCst), 0);
    assert!(h.server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn off_net_client_is_refused() {
    // Loopback is not allowed: the client 127.0.0.1 is off-net for this ACL.
    let h = harness_with(DohLimits::default(), |s| {
        s.acl_auto_local = false;
        s.acl_allow = vec![Cidr::parse("198.51.100.0/24").unwrap()];
    })
    .await;
    let client = h.ca.client(&[b"h2"]);
    let r = doh_request(
        &client,
        h.doh,
        get_req(h.doh, &query_msg(0, "x.example."), true),
    )
    .await;
    assert!(r.is_err(), "{r:?}");
    assert_eq!(h.up.count.load(Ordering::SeqCst), 0);
    assert!(h.server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_gives_refused() {
    let h = harness_with(DohLimits::default(), |s| {
        s.handler.rate_queries = 1;
        s.handler.rate_interval_seconds = 3600;
    })
    .await;
    let client = h.ca.client(&[b"h2"]);
    let r = doh_request(
        &client,
        h.doh,
        get_req(h.doh, &query_msg(0, "r1.example."), true),
    )
    .await
    .unwrap();
    assert_eq!(rcode(&r.message()), ResponseCode::NoError);
    let r = doh_request(
        &client,
        h.doh,
        get_req(h.doh, &query_msg(0, "r2.example."), true),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(rcode(&r.message()), ResponseCode::Refused);
    assert!(h.server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_limits_apply() {
    let limits = DohLimits {
        max_per_client: 1,
        ..DohLimits::default()
    };
    let h = harness_with(limits, |_| {}).await;
    // One connection holds the only slot of this client.
    let hold = tokio::net::TcpStream::connect(h.doh).await.unwrap();
    assert!(eventually(|| h.server.doh_connections() == 1).await);
    let client = h.ca.client(&[b"h2"]);
    let r = doh_request(
        &client,
        h.doh,
        get_req(h.doh, &query_msg(0, "x.example."), true),
    )
    .await;
    assert!(r.is_err(), "{r:?}");
    drop(hold);
    assert!(eventually(|| h.server.doh_connections() == 0).await);
    let r = doh_request(
        &client,
        h.doh,
        get_req(h.doh, &query_msg(0, "x.example."), true),
    )
    .await;
    assert_eq!(r.unwrap().status, 200);
    assert!(h.server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_timeout_closes_a_silent_connection() {
    let limits = DohLimits {
        handshake_timeout: Duration::from_millis(200),
        ..DohLimits::default()
    };
    let h = harness_with(limits, |_| {}).await;
    let _silent = tokio::net::TcpStream::connect(h.doh).await.unwrap();
    assert!(eventually(|| h.server.doh_connections() == 1).await);
    assert!(eventually(|| h.server.doh_connections() == 0).await);
    assert!(h.server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_connection_closes() {
    let limits = DohLimits {
        idle_timeout: Duration::from_millis(200),
        ..DohLimits::default()
    };
    let h = harness_with(limits, |_| {}).await;
    let client = h.ca.client(&[b"h2"]);
    let r = doh_request(
        &client,
        h.doh,
        get_req(h.doh, &query_msg(0, "x.example."), true),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    // The test client keeps its connection open; the server closes it when idle.
    assert!(eventually(|| h.server.doh_connections() == 0).await);
    assert!(h.server.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_stops_the_doh_listener_and_its_connections() {
    let h = harness().await;
    let client = h.ca.client(&[b"h2"]);
    let r = doh_request(
        &client,
        h.doh,
        get_req(h.doh, &query_msg(0, "x.example."), true),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    // An open idle connection (a client that did not close).
    let _open = tokio::net::TcpStream::connect(h.doh).await.unwrap();
    assert!(eventually(|| h.server.doh_connections() >= 1).await);
    assert!(h.server.shutdown(WAIT).await);
    assert_eq!(h.server.task_count(), 0);
    assert_eq!(h.server.doh_connections(), 0);
    assert_eq!(h.server.doh_bound(), Vec::<SocketAddr>::new());
    // The port is free again.
    assert!(tokio::net::TcpListener::bind(h.doh).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_without_a_tls_config_does_not_start() {
    let up = fake_udp(1).await;
    let err = rusthole_dns::start(
        settings(up.addr, DohLimits::default()),
        ServerDeps {
            interfaces: Arc::new(StaticInterfaces::default()),
            ..ServerDeps::default()
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StartError::DohNoTls), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_doh_port_stops_the_start_and_its_tasks() {
    let ca = test_ca(&["doh.lan"]);
    let up = fake_udp(1).await;
    let blocker = tokio::net::TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let mut s = settings(up.addr, DohLimits::default());
    if let Some(d) = s.doh.as_mut() {
        d.port = blocker.local_addr().unwrap().port();
    }
    let err = rusthole_dns::start(
        s,
        ServerDeps {
            interfaces: Arc::new(StaticInterfaces::default()),
            doh_tls: Some(rusthole_tls::doh_server_config(&ca.store).unwrap()),
            ..ServerDeps::default()
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StartError::DohBind { .. }), "{err}");
}

// On other systems, "auto" binds 127.0.0.1 only (development mode), so the rebind cannot
// be seen there.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_auto_listen_rebinds_when_interfaces_change() {
    use rusthole_core::acl::InterfaceNet;
    use std::net::{IpAddr, Ipv4Addr};
    let ca = test_ca(&["doh.lan"]);
    let up = fake_udp(1).await;
    let mut s = settings(up.addr, DohLimits::default());
    if let Some(d) = s.doh.as_mut() {
        d.listen = ListenMode::Auto;
    }
    let net = |last: u8| InterfaceNet {
        addr: Ipv4Addr::new(127, 0, 0, last),
        prefix: 8,
    };
    let ifs = Arc::new(StaticInterfaces::new(vec![net(1)]));
    let server = rusthole_dns::start(
        s,
        ServerDeps {
            interfaces: ifs.clone(),
            doh_tls: Some(rusthole_tls::doh_server_config(&ca.store).unwrap()),
            ..ServerDeps::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(server.doh_bound().len(), 1);
    ifs.set(vec![net(1), net(2)]);
    server.rescan().await;
    let bound = server.doh_bound();
    assert_eq!(bound.len(), 2);
    let second = *bound
        .iter()
        .find(|a| a.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
        .unwrap();
    let client = ca.client(&[b"h2"]);
    let r = doh_request(
        &client,
        second,
        get_req(second, &query_msg(0, "x.example."), true),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    ifs.set(vec![net(2)]);
    server.rescan().await;
    assert_eq!(server.doh_bound(), vec![second]);
    assert!(server.shutdown(WAIT).await);
}
