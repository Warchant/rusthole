//! Test helpers for the DoH listener and the DoT and DoH upstreams: a test CA, fake
//! upstream servers on 127.0.0.1, and a DoH client. Nothing binds an address that is not
//! loopback (no Windows firewall prompt).
// Test helpers: a failed setup step is a test failure, so unwrap and panic are the right result.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    dead_code,
    unreachable_pub
)]

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use rusthole_core::config::TlsMode;
use rusthole_dns::UpstreamTls;
use rusthole_tls::{CertStore, TlsSettings};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
pub const WAIT: Duration = Duration::from_secs(5);

// ---------- test CA ----------

/// A local CA with a server certificate for `localhost`, `127.0.0.1` and `names`.
pub struct TestCa {
    pub store: Arc<CertStore>,
    pub roots: RootCertStore,
    _dir: tempfile::TempDir,
}

pub fn test_ca(names: &[&str]) -> TestCa {
    test_ca_at(names, rusthole_tls::now_unix())
}

/// A test CA and server certificate made at `now_unix`. A time far in the future gives a
/// certificate that is not yet valid for the real clock (review item m1).
pub fn test_ca_at(names: &[&str], now_unix: i64) -> TestCa {
    let dir = tempfile::Builder::new()
        .prefix("rusthole-p7-")
        .tempdir_in(temp_root())
        .unwrap();
    let settings = TlsSettings {
        mode: TlsMode::LocalCa,
        cert_path: None,
        key_path: None,
        names: names.iter().map(|s| (*s).to_owned()).collect(),
        data_dir: dir.path().to_owned(),
    };
    let (store, _) = CertStore::open(settings, &[LOCALHOST], now_unix).unwrap();
    let ca_path = store.info().ca_cert_path.unwrap();
    let mut roots = RootCertStore::empty();
    for c in rusthole_tls::pem::parse_cert_chain(&std::fs::read(ca_path).unwrap(), "ca").unwrap() {
        roots.add(c).unwrap();
    }
    TestCa {
        store,
        roots,
        _dir: dir,
    }
}

/// `D:\tmp` on the owner's machine when it exists (drive C is nearly full), else the
/// system temp folder.
fn temp_root() -> std::path::PathBuf {
    let d = Path::new("D:/tmp");
    if cfg!(windows) && d.is_dir() {
        d.to_owned()
    } else {
        std::env::temp_dir()
    }
}

impl TestCa {
    pub fn upstream_tls(&self) -> UpstreamTls {
        UpstreamTls::with_roots(self.roots.clone()).unwrap()
    }

    pub fn client(&self, alpn: &[&[u8]]) -> Arc<ClientConfig> {
        rusthole_tls::client_config_with_roots(
            self.roots.clone(),
            alpn.iter().map(|p| p.to_vec()).collect(),
        )
        .unwrap()
    }

    pub fn server_config(&self) -> Arc<ServerConfig> {
        rusthole_tls::admin_server_config(&self.store).unwrap()
    }
}

// ---------- DNS messages ----------

pub fn query_msg(id: u16, name: &str) -> Vec<u8> {
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    m.to_vec().unwrap()
}

/// An answer to `q`: A 192.0.2.`last` with TTL `ttl`.
pub fn answer(q: &Message, last: u8, ttl: u32) -> Message {
    let mut m = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
    m.metadata.recursion_available = true;
    m.queries.clone_from(&q.queries);
    if let Some(query) = q.queries.first() {
        m.answers.push(Record::from_rdata(
            query.name().clone(),
            ttl,
            RData::A(A(Ipv4Addr::new(192, 0, 2, last))),
        ));
    }
    m
}

pub fn first_a(m: &Message) -> Option<Ipv4Addr> {
    m.answers.iter().find_map(|r| match &r.data {
        RData::A(a) => Some(a.0),
        _ => None,
    })
}

// ---------- fake plain upstream ----------

pub struct FakeUdp {
    pub addr: SocketAddr,
    pub count: Arc<AtomicUsize>,
}

/// A UDP upstream on 127.0.0.1 that answers A 192.0.2.`last` with TTL 300.
pub async fn fake_udp(last: u8) -> FakeUdp {
    let sock = Arc::new(UdpSocket::bind((LOCALHOST, 0)).await.unwrap());
    let addr = sock.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&count);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            c.fetch_add(1, Ordering::SeqCst);
            let _ = sock
                .send_to(&answer(&q, last, 300).to_vec().unwrap(), peer)
                .await;
        }
    });
    FakeUdp { addr, count }
}

// ---------- fake DoT upstream ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotMode {
    /// Answer each query.
    Answer,
    /// Send a reply with a wrong ID and one with a wrong question first, then the answer.
    Tricky,
    /// Read queries, never answer.
    Silent,
    /// Answer, then close the connection (a server that closes idle connections).
    CloseAfterAnswer,
    /// The first connection answers its first query, then goes silent but stays open (a
    /// dead connection). Other connections answer each query.
    FirstConnGoesSilent,
    /// Answer each query after 600 ms, many at the same time (pipelining).
    Slow,
}

pub struct FakeTls {
    pub addr: SocketAddr,
    /// TCP connections accepted.
    pub conns: Arc<AtomicUsize>,
    /// Queries answered or read.
    pub queries: Arc<AtomicUsize>,
    /// Connections that ended (EOF or error).
    pub closed: Arc<AtomicUsize>,
    /// Queries read on the first connection.
    pub first_conn_queries: Arc<AtomicUsize>,
    /// The TLS SNI of each accepted connection ("" when the client sent none).
    pub sni: Arc<Mutex<Vec<String>>>,
}

/// Records the SNI of an accepted TLS connection.
fn record_sni(sni: &Mutex<Vec<String>>, conn: &rustls::ServerConnection) {
    sni.lock()
        .push(conn.server_name().unwrap_or_default().to_owned());
}

/// A DoT upstream on 127.0.0.1 with the certificate of `ca`. Answers A 192.0.2.`last`.
pub async fn fake_dot(ca: &TestCa, mode: DotMode, last: u8) -> FakeTls {
    fake_dot_switch(Arc::new(Mutex::new(ca.server_config())), mode, last).await
}

/// A DoT upstream like [`fake_dot`]. Each new connection uses the server config that is in
/// `config` now, so a test can change the certificate.
pub async fn fake_dot_switch(
    config: Arc<Mutex<Arc<ServerConfig>>>,
    mode: DotMode,
    last: u8,
) -> FakeTls {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let queries = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let first_conn_queries = Arc::new(AtomicUsize::new(0));
    let sni = Arc::new(Mutex::new(Vec::new()));
    let (c1, q1, x1, f1, s1) = (
        Arc::clone(&conns),
        Arc::clone(&queries),
        Arc::clone(&closed),
        Arc::clone(&first_conn_queries),
        Arc::clone(&sni),
    );
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let first = c1.fetch_add(1, Ordering::SeqCst) == 0;
            let acceptor = TlsAcceptor::from(Arc::clone(&*config.lock()));
            let q1 = Arc::clone(&q1);
            let x1 = Arc::clone(&x1);
            let f1 = Arc::clone(&f1);
            let s1 = Arc::clone(&s1);
            tokio::spawn(async move {
                let mut on_this_conn = 0usize;
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    x1.fetch_add(1, Ordering::SeqCst);
                    return;
                };
                record_sni(&s1, tls.get_ref().1);
                if mode == DotMode::Slow {
                    slow_dot(tls, q1, last).await;
                    x1.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                loop {
                    let mut len = [0u8; 2];
                    if tls.read_exact(&mut len).await.is_err() {
                        break;
                    }
                    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if tls.read_exact(&mut buf).await.is_err() {
                        break;
                    }
                    q1.fetch_add(1, Ordering::SeqCst);
                    on_this_conn += 1;
                    if first {
                        f1.fetch_add(1, Ordering::SeqCst);
                    }
                    let q = Message::from_vec(&buf).unwrap();
                    let silent = mode == DotMode::Silent
                        || (mode == DotMode::FirstConnGoesSilent && first && on_this_conn > 1);
                    if silent {
                        continue;
                    }
                    for framed in dot_replies(mode, &q, last) {
                        if tls.write_all(&framed).await.is_err() {
                            break;
                        }
                    }
                    if mode == DotMode::CloseAfterAnswer {
                        let _ = tls.shutdown().await;
                        break;
                    }
                }
                x1.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    FakeTls {
        addr,
        conns,
        queries,
        closed,
        first_conn_queries,
        sni,
    }
}

/// The framed replies of a fake DoT upstream to `q`: for [`DotMode::Tricky`] a reply with a
/// wrong ID and one with a wrong question first, then the answer.
fn dot_replies(mode: DotMode, q: &Message, last: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if mode == DotMode::Tricky {
        let mut wrong_id = answer(q, 66, 300);
        wrong_id.metadata.id = q.metadata.id.wrapping_add(1);
        out.push(wrong_id);
        let mut wrong_q = answer(q, 66, 300);
        wrong_q.queries = vec![Query::query(
            Name::from_ascii("other.example.").unwrap(),
            RecordType::A,
        )];
        out.push(wrong_q);
    }
    out.push(answer(q, last, 300));
    out.into_iter()
        .map(|m| {
            let b = m.to_vec().unwrap();
            let mut framed = u16::try_from(b.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&b);
            framed
        })
        .collect()
}

/// One connection of [`DotMode::Slow`]: each query gets its answer after 600 ms, so many
/// queries are open at the same time.
async fn slow_dot(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    queries: Arc<AtomicUsize>,
    last: u8,
) {
    let (mut rd, mut wr) = tokio::io::split(tls);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(async move {
        while let Some(framed) = rx.recv().await {
            if wr.write_all(&framed).await.is_err() {
                break;
            }
        }
    });
    loop {
        let mut len = [0u8; 2];
        if rd.read_exact(&mut len).await.is_err() {
            break;
        }
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
        if rd.read_exact(&mut buf).await.is_err() {
            break;
        }
        queries.fetch_add(1, Ordering::SeqCst);
        let q = Message::from_vec(&buf).unwrap();
        let tx = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(600)).await;
            let b = answer(&q, last, 300).to_vec().unwrap();
            let mut framed = u16::try_from(b.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&b);
            let _ = tx.send(framed);
        });
    }
    writer.abort();
}

// ---------- fake DoH upstream ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohMode {
    /// Answer each POST with ID 0.
    Answer,
    /// Answer with a wrong ID.
    WrongId,
    /// Answer with a wrong question.
    WrongQuestion,
    /// Never answer.
    Silent,
    /// The first connection answers its first request, then never answers but stays open.
    /// Other connections answer each request.
    FirstConnGoesSilent,
}

/// A DoH upstream (HTTP/2 only) on 127.0.0.1 with the certificate of `ca`.
pub async fn fake_doh(ca: &TestCa, mode: DohMode, last: u8) -> FakeTls {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut cfg = (*ca.server_config()).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let conns = Arc::new(AtomicUsize::new(0));
    let queries = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let first_conn_queries = Arc::new(AtomicUsize::new(0));
    let sni = Arc::new(Mutex::new(Vec::new()));
    let (c1, q1, x1, f1, s1) = (
        Arc::clone(&conns),
        Arc::clone(&queries),
        Arc::clone(&closed),
        Arc::clone(&first_conn_queries),
        Arc::clone(&sni),
    );
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let first = c1.fetch_add(1, Ordering::SeqCst) == 0;
            let acceptor = acceptor.clone();
            let q1 = Arc::clone(&q1);
            let x1 = Arc::clone(&x1);
            let f1 = Arc::clone(&f1);
            let s1 = Arc::clone(&s1);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    x1.fetch_add(1, Ordering::SeqCst);
                    return;
                };
                record_sni(&s1, tls.get_ref().1);
                let on_this_conn = Arc::new(AtomicUsize::new(0));
                let svc =
                    hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                        let q1 = Arc::clone(&q1);
                        let f1 = Arc::clone(&f1);
                        let on_this_conn = Arc::clone(&on_this_conn);
                        async move {
                            assert_eq!(req.method(), http::Method::POST);
                            assert_eq!(req.headers()["content-type"], "application/dns-message");
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let q = Message::from_vec(&body).unwrap();
                            assert_eq!(q.metadata.id, 0, "DoH upstream queries use ID 0");
                            q1.fetch_add(1, Ordering::SeqCst);
                            let n = on_this_conn.fetch_add(1, Ordering::SeqCst) + 1;
                            if first {
                                f1.fetch_add(1, Ordering::SeqCst);
                            }
                            let mut a = answer(&q, last, 300);
                            match mode {
                                DohMode::Answer => {}
                                DohMode::FirstConnGoesSilent => {
                                    if first && n > 1 {
                                        tokio::time::sleep(Duration::from_secs(30)).await;
                                    }
                                }
                                DohMode::WrongId => a.metadata.id = 7,
                                DohMode::WrongQuestion => {
                                    a.queries = vec![Query::query(
                                        Name::from_ascii("other.example.").unwrap(),
                                        RecordType::A,
                                    )];
                                }
                                DohMode::Silent => {
                                    tokio::time::sleep(Duration::from_secs(30)).await;
                                }
                            }
                            let mut resp =
                                http::Response::new(Full::new(Bytes::from(a.to_vec().unwrap())));
                            resp.headers_mut().insert(
                                "content-type",
                                http::HeaderValue::from_static("application/dns-message"),
                            );
                            Ok::<_, Infallible>(resp)
                        }
                    });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
                x1.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    FakeTls {
        addr,
        conns,
        queries,
        closed,
        first_conn_queries,
        sni,
    }
}

// ---------- DoH client ----------

/// A DoH reply as the test client sees it.
#[derive(Debug)]
pub struct DohReply {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: Bytes,
    pub alpn: Option<Vec<u8>>,
}

impl DohReply {
    pub fn message(&self) -> Message {
        Message::from_vec(&self.body).unwrap()
    }
}

/// Sends one HTTP request to the DoH listener at `addr` over a new TLS connection.
/// `alpn`: `h2` or `http/1.1`.
pub async fn doh_request(
    client: &Arc<ClientConfig>,
    addr: SocketAddr,
    req: http::Request<Full<Bytes>>,
) -> Result<DohReply, String> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let name = ServerName::try_from("doh.lan").unwrap();
    let tls = tokio::time::timeout(
        WAIT,
        TlsConnector::from(Arc::clone(client)).connect(name, tcp),
    )
    .await
    .map_err(|_| "handshake timeout".to_owned())?
    .map_err(|e| e.to_string())?;
    let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let io = TokioIo::new(tls);
    let resp = if alpn.as_deref() == Some(b"h2") {
        let (mut send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        tokio::time::timeout(WAIT, send.send_request(req))
            .await
            .map_err(|_| "request timeout".to_owned())?
            .map_err(|e| e.to_string())?
    } else {
        let (mut send, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        tokio::time::timeout(WAIT, send.send_request(req))
            .await
            .map_err(|_| "request timeout".to_owned())?
            .map_err(|e| e.to_string())?
    };
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok(DohReply {
        status,
        headers,
        body,
        alpn,
    })
}

pub fn uri(addr: SocketAddr, path_and_query: &str, h2: bool) -> String {
    if h2 {
        format!("https://doh.lan:{}{path_and_query}", addr.port())
    } else {
        path_and_query.to_owned()
    }
}

pub fn get_req(addr: SocketAddr, msg: &[u8], h2: bool) -> http::Request<Full<Bytes>> {
    let p = rusthole_dns::doh_wire::encode_get_param(msg);
    http::Request::get(uri(addr, &format!("/dns-query?dns={p}"), h2))
        .header("host", "doh.lan")
        .header("accept", "application/dns-message")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

pub fn post_req(
    addr: SocketAddr,
    body: Vec<u8>,
    content_type: &str,
    h2: bool,
) -> http::Request<Full<Bytes>> {
    http::Request::post(uri(addr, "/dns-query", h2))
        .header("host", "doh.lan")
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Waits until `f` is true, at most 5 s.
pub async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..500 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

pub fn rcode(m: &Message) -> ResponseCode {
    m.metadata.response_code
}
