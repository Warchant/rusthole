//! Test helpers: a small HTTP/1.1 server on 127.0.0.1 (port 0), plain or TLS, and helpers
//! for the refresher. No test binds a non-loopback address (docs/ENGINEERING.md).

// Each test binary uses a part of the helpers. A failed setup step is a test failure, so
// unwrap and panic are the right result.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::format_push_string
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusthole_core::config::{Adlist, ListKind};
use rusthole_core::{Config, DomainName};
use rusthole_lists::{
    EngineHandle, FetchLimits, ListsSettings, ListsStatus, Refresher, StaticResolver,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// The host name that the static resolver maps to 127.0.0.1.
pub const TEST_HOST: &str = "lists.test";

/// One request that the server got.
#[derive(Debug, Clone)]
pub struct Req {
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One response.
#[derive(Debug, Clone, Default)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Send no `Content-Length`; the body ends when the connection closes.
    pub no_length: bool,
    /// Never answer.
    pub hang: bool,
    /// Send this file as the body (streamed in chunks, so the server holds little memory).
    pub file: Option<std::path::PathBuf>,
    /// Wait this long before the answer.
    pub delay: Option<Duration>,
}

impl Resp {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            ..Self::default()
        }
    }

    pub fn status(status: u16) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }

    pub fn hang() -> Self {
        Self {
            hang: true,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

pub type Handler = Arc<dyn Fn(&Req) -> Resp + Send + Sync>;

/// A running test server. Dropping it stops it.
pub struct TestServer {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<Req>>>,
    /// Connections open now, and the highest number seen.
    pub open: Arc<AtomicUsize>,
    pub max_open: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.addr.port())
    }

    /// A URL with the test host name (the static resolver maps it to 127.0.0.1).
    pub fn host_url(&self, scheme: &str, path: &str) -> String {
        format!("{scheme}://{TEST_HOST}:{}{path}", self.addr.port())
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    pub fn last_request(&self) -> Req {
        self.requests.lock().unwrap().last().unwrap().clone()
    }
}

pub async fn serve(handler: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> TestServer {
    serve_with(Arc::new(handler), None).await
}

pub async fn serve_tls(
    handler: impl Fn(&Req) -> Resp + Send + Sync + 'static,
    acceptor: tokio_rustls::TlsAcceptor,
) -> TestServer {
    serve_with(Arc::new(handler), Some(acceptor)).await
}

async fn serve_with(handler: Handler, tls: Option<tokio_rustls::TlsAcceptor>) -> TestServer {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let open = Arc::new(AtomicUsize::new(0));
    let max_open = Arc::new(AtomicUsize::new(0));
    let (reqs, op, mx) = (
        Arc::clone(&requests),
        Arc::clone(&open),
        Arc::clone(&max_open),
    );
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let handler = Arc::clone(&handler);
            let reqs = Arc::clone(&reqs);
            let tls = tls.clone();
            let (op, mx) = (Arc::clone(&op), Arc::clone(&mx));
            tokio::spawn(async move {
                let now = op.fetch_add(1, Ordering::SeqCst) + 1;
                mx.fetch_max(now, Ordering::SeqCst);
                match tls {
                    Some(acceptor) => {
                        if let Ok(Ok(s)) =
                            tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream))
                                .await
                        {
                            handle(s, &handler, &reqs).await;
                        }
                    }
                    None => handle(stream, &handler, &reqs).await,
                }
                op.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    TestServer {
        addr,
        requests,
        open,
        max_open,
        task,
    }
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    handler: &Handler,
    reqs: &Mutex<Vec<Req>>,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return;
        }
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => return,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let path = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or("/")
        .to_owned();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let req = Req { path, headers };
    reqs.lock().unwrap().push(req.clone());
    let resp = handler(&req);
    if resp.hang {
        tokio::time::sleep(Duration::from_secs(60)).await;
        return;
    }
    if let Some(d) = resp.delay {
        tokio::time::sleep(d).await;
    }
    let mut out = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", resp.status);
    let file_len = resp
        .file
        .as_ref()
        .map(|p| std::fs::metadata(p).unwrap().len());
    if !resp.no_length {
        let len = file_len.unwrap_or(resp.body.len() as u64);
        out.push_str(&format!("Content-Length: {len}\r\n"));
    }
    for (n, v) in &resp.headers {
        out.push_str(&format!("{n}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let _ = s.write_all(out.as_bytes()).await;
    if let Some(path) = &resp.file {
        use std::io::Read as _;
        let mut f = std::fs::File::open(path).unwrap();
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = f.read(&mut buf).unwrap();
            if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    }
    let _ = s.write_all(&resp.body).await;
    let _ = s.flush().await;
    let _ = s.shutdown().await;
}

/// A TLS client config with no roots (for plain HTTP tests).
pub fn no_roots_tls() -> Arc<rustls::ClientConfig> {
    rusthole_tls::client_config_with_roots(rustls::RootCertStore::empty(), Vec::new()).unwrap()
}

/// The static resolver of the tests: `lists.test` is 127.0.0.1.
pub fn test_lookup() -> Arc<StaticResolver> {
    Arc::new(StaticResolver::new().with(TEST_HOST, &[LOCALHOST]))
}

/// Short limits for tests.
pub fn test_limits() -> FetchLimits {
    FetchLimits {
        connect_timeout: Duration::from_secs(2),
        read_timeout: Duration::from_secs(2),
        total_timeout: Duration::from_secs(3),
        ..FetchLimits::default()
    }
}

/// A config with block lists `(id, url)` in the default group and a data directory.
pub fn config(dir: &std::path::Path, lists: &[(u32, &str)]) -> Config {
    let mut c = Config::default();
    c.server.data_dir = dir.to_string_lossy().into_owned();
    c.lists.refresh_interval_hours = 24;
    c.lists.adlists = lists
        .iter()
        .map(|(id, url)| Adlist {
            id: *id,
            url: (*url).to_owned(),
            kind: ListKind::Block,
            enabled: true,
            groups: vec!["default".to_owned()],
            comment: None,
        })
        .collect();
    c
}

/// A wall clock that the test sets.
#[derive(Debug, Clone)]
pub struct TestClock(pub Arc<AtomicI64>);

impl TestClock {
    pub fn new(unix: i64) -> Self {
        Self(Arc::new(AtomicI64::new(unix)))
    }

    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

/// Settings for tests: fixed wall clock, short limits, no TLS roots.
pub fn settings(config: &Config, clock: &TestClock) -> ListsSettings {
    let mut s = ListsSettings::from_config(config);
    let c = Arc::clone(&clock.0);
    s.wall_clock = Arc::new(move || c.load(Ordering::SeqCst));
    s.limits = test_limits();
    s.tls = Some(no_roots_tls());
    s.max_sleep = Duration::from_millis(200);
    s
}

/// Waits until `cond` is true for the status, at most `limit`. Panics with the last status
/// after the limit.
pub async fn wait_for(
    r: &Refresher,
    limit: Duration,
    cond: impl Fn(&ListsStatus) -> bool,
) -> ListsStatus {
    let step = Duration::from_millis(20);
    let rounds = (limit.as_millis() / step.as_millis()).max(1);
    let mut last = None;
    for _ in 0..rounds {
        if let Some(st) = r.status() {
            if cond(&st) {
                return st;
            }
            last = Some(st);
        }
        tokio::time::sleep(step).await;
    }
    panic!("condition not met in {limit:?}; last status: {last:#?}");
}

pub const WAIT: Duration = Duration::from_secs(10);

/// True when the engine blocks `name` for the default group.
pub fn blocked(engine: &EngineHandle, name: &str) -> bool {
    let e = engine.load();
    e.check(&e.default_groups(), true, &DomainName::parse(name).unwrap())
        .is_blocked()
}

pub fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}
