//! Test harness: a real admin listener on 127.0.0.1 (port 0) over HTTPS, with a reqwest
//! client that trusts the local CA of the test. No test binds a non-loopback address.

// Test helpers: each test binary uses a part of them.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Method, StatusCode};
use rusthole_core::Config;
use rusthole_dns::{BlockingControl, StaticInterfaces};
use rusthole_lists::{ListsSettings, Refresher};
use rusthole_store::{StatsService, StatsSettings};
use rusthole_tls::{CertStore, TlsSettings};
use rusthole_web::assets::{AssetSource, PlaceholderAssets};
use rusthole_web::clock::ManualClock;
use rusthole_web::config_edit::ConfigStore;
use rusthole_web::{AdminDeps, AdminServer, AdminSettings, AppState, NoLiveApply, SystemStatic};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde_json::Value;

pub const PASSWORD: &str = "correct horse battery";
/// 2026-11-17 08:10:00 UTC.
pub const WALL: i64 = 1_794_903_000;

pub struct Options {
    pub extra_toml: String,
    pub assets: Arc<dyn AssetSource>,
    pub header_timeout: Duration,
    pub stall_timeout: Duration,
    pub with_password: bool,
    pub report: Option<rusthole_report::Reporter>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            extra_toml: String::new(),
            assets: Arc::new(PlaceholderAssets),
            header_timeout: Duration::from_secs(10),
            stall_timeout: Duration::from_secs(40),
            with_password: true,
            report: None,
        }
    }
}

pub struct Harness {
    pub server: AdminServer,
    pub addr: SocketAddr,
    pub base: String,
    pub client: reqwest::Client,
    pub clock: Arc<ManualClock>,
    pub state: AppState,
    pub config_path: PathBuf,
    pub stats: Option<StatsService>,
    pub lists: Arc<Refresher>,
    pub dir: tempfile::TempDir,
    pub ca_pem: Vec<u8>,
}

/// The password hash of the test (made once: Argon2 is slow in debug builds).
pub fn password_hash() -> &'static str {
    static H: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    H.get_or_init(|| rusthole_web::password::hash_password(PASSWORD).unwrap())
}

pub fn config_text(data_dir: &str, opts: &Options) -> String {
    let pw = if opts.with_password {
        format!("password_hash = \"{}\"\n", password_hash())
    } else {
        String::new()
    };
    format!(
        r#"# Test config: keep this comment.
config_version = 1

[server]
data_dir = '{data_dir}'
dns_port = 5353

[server.admin]
listen = ["127.0.0.1"]
port = 8443

[stats]
flush_interval_seconds = 0

[admin]
{pw}session_ttl_seconds = 28800

[tls]
mode = "local-ca"
names = ["rusthole.lan"]
{extra}
"#,
        extra = opts.extra_toml
    )
}

pub async fn harness(opts: Options) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let data_s = data.display().to_string();
    let text = config_text(&data_s, &opts);
    let config_path = dir.path().join("rusthole.toml");
    std::fs::write(&config_path, &text).unwrap();
    let (store, cfg) = ConfigStore::open(&config_path).unwrap();
    assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
    let store = Arc::new(store);
    let clock = ManualClock::new(WALL);

    let (certs, _) = CertStore::open(
        TlsSettings::from_config(&cfg),
        &["127.0.0.1".parse().unwrap()],
        rusthole_tls::now_unix(),
    )
    .unwrap();
    let ca_path = certs.info().ca_cert_path.unwrap();
    let ca_pem = std::fs::read(&ca_path).unwrap();
    let tls = rusthole_tls::admin_server_config(&certs).unwrap();

    let stats = StatsService::start(&StatsSettings::ram_only()).unwrap();
    let lists = Arc::new(
        Refresher::load(Arc::clone(&cfg), ListsSettings::from_config(&cfg))
            .await
            .unwrap(),
    );
    let deps = AdminDeps {
        config: store,
        clock: clock.clone(),
        stats: Some(stats.stats()),
        lists: Some(Arc::clone(&lists)),
        engine: lists.engine().shared(),
        blocking: Arc::new(BlockingControl::new(true)),
        live: Arc::new(NoLiveApply),
        tls: Some(certs),
        system: SystemStatic {
            version: "0.1.0".into(),
            commit: None,
            started_at: WALL,
            config_path: config_path.display().to_string(),
            data_dir: data_s,
            listeners: Vec::new(),
        },
        interfaces: Arc::new(StaticInterfaces::default()),
        assets: opts.assets,
        report: opts.report,
    };
    let app_state = AppState::new(deps);
    let mut settings = AdminSettings::new(vec!["127.0.0.1:0".parse().unwrap()]);
    settings.header_timeout = opts.header_timeout;
    settings.stall_timeout = opts.stall_timeout;
    let server = rusthole_web::start(settings, tls, app_state.clone())
        .await
        .unwrap();
    let addr = server.bound()[0];
    let client = client_for(&ca_pem);
    Harness {
        server,
        addr,
        base: format!("https://127.0.0.1:{}", addr.port()),
        client,
        clock,
        state: app_state,
        config_path,
        stats: Some(stats),
        lists,
        dir,
        ca_pem,
    }
}

pub fn client_for(ca_pem: &[u8]) -> reqwest::Client {
    let ca = CertificateDer::from_pem_slice(ca_pem).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(rusthole_tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    reqwest::Client::builder()
        .tls_backend_preconfigured(cfg)
        .http1_only()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

/// A response: status, headers and the JSON body (or `Null`).
#[derive(Debug)]
pub struct Resp {
    pub status: StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub body: Value,
    pub text: String,
}

impl Resp {
    pub fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }
}

/// The credentials of a request.
#[derive(Debug, Clone, Default)]
pub struct Creds {
    pub cookie: Option<String>,
    pub csrf: Option<String>,
    pub bearer: Option<String>,
}

impl Harness {
    /// Sends `head` (the request line and the headers, with no body) over a new TLS
    /// connection, and gives the full answer as text. The read stops at EOF or after 10 s.
    ///
    /// Use it for a request whose body the server refuses before it reads the body. reqwest
    /// (hyper) writes the body first; when the server answers and closes early, the write
    /// can fail with "broken pipe" before reqwest reads the answer.
    pub async fn raw_head(&self, head: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ca = CertificateDer::from_pem_slice(&self.ca_pem).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let mut cfg = rustls::ClientConfig::builder_with_provider(rusthole_tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let name = rustls_pki_types::ServerName::IpAddress(self.addr.ip().into());
        let io = async {
            let tcp = tokio::net::TcpStream::connect(self.addr).await.unwrap();
            let mut tls = connector.connect(name, tcp).await.unwrap();
            tls.write_all(head.as_bytes()).await.unwrap();
            tls.flush().await.unwrap();
            let mut out = Vec::new();
            // The server can close with no TLS close_notify: keep what came before.
            let _ = tls.read_to_end(&mut out).await;
            String::from_utf8_lossy(&out).into_owned()
        };
        tokio::time::timeout(Duration::from_secs(10), io)
            .await
            .unwrap()
    }

    pub async fn req(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        creds: &Creds,
    ) -> Resp {
        self.req_with(method, path, body, creds, &[]).await
    }

    pub async fn req_with(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        creds: &Creds,
        headers: &[(&str, &str)],
    ) -> Resp {
        let mut r = self.client.request(method, format!("{}{path}", self.base));
        if let Some(c) = &creds.cookie {
            r = r.header("cookie", format!("__Host-rusthole_session={c}"));
        }
        if let Some(t) = &creds.csrf {
            r = r.header("x-csrf-token", t);
        }
        if let Some(b) = &creds.bearer {
            r = r.header("authorization", format!("Bearer {b}"));
        }
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        if let Some(b) = body {
            r = r
                .header("content-type", "application/json")
                .body(serde_json::to_vec(&b).unwrap());
        }
        let resp = r.send().await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp {
            status,
            headers,
            body,
            text,
        }
    }

    pub async fn get(&self, path: &str, creds: &Creds) -> Resp {
        self.req(Method::GET, path, None, creds).await
    }

    /// Logs in with the test password. Returns the session.
    pub async fn login(&self) -> Creds {
        self.login_with(serde_json::json!({ "password": PASSWORD }))
            .await
    }

    pub async fn login_with(&self, body: Value) -> Creds {
        let r = self
            .req(
                Method::POST,
                "/api/v1/auth/login",
                Some(body),
                &Creds::default(),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text);
        let cookie = r.headers["set-cookie"].to_str().unwrap().to_owned();
        let id = cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("__Host-rusthole_session=")
            .unwrap()
            .to_owned();
        Creds {
            cookie: Some(id),
            csrf: Some(r.body["csrf_token"].as_str().unwrap().to_owned()),
            bearer: None,
        }
    }

    pub fn config_text(&self) -> String {
        std::fs::read_to_string(&self.config_path).unwrap()
    }

    pub fn config(&self) -> Arc<Config> {
        self.state.config()
    }

    pub async fn stop(mut self) {
        assert!(self.server.shutdown(Duration::from_secs(5)).await);
        assert_eq!(self.server.task_count(), 0);
        assert!(self.lists.shutdown(Duration::from_secs(5)).await);
        if let Some(s) = self.stats.take() {
            s.shutdown(Duration::from_secs(5));
        }
    }
}

/// Fills `{id}`, `{key}` and `{name}` in a route path.
pub fn fill(path: &str) -> String {
    let mut out = path.replace("{id}", "1");
    out = out.replace("{key}", "02%3A00%3A00%3A00%3A00%3A01");
    out.replace("{name}", "a.example")
}

pub fn method_of(m: &str) -> Method {
    Method::from_bytes(m.to_ascii_uppercase().as_bytes()).unwrap()
}

pub type Map = HashMap<String, Value>;
