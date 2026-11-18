use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use rusthole_core::config::{Adlist, ListKind, LocalRecord, RecordType as CfgType};
use rusthole_dns::{ListenMode, StaticInterfaces, StaticNeighbors, UpstreamProto, UpstreamServer};
use rusthole_lists::UpdateTarget;
use rusthole_store::{StatsService, StatsSettings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::*;

/// A loopback HTTP server that answers every request with `body`.
async fn list_server(body: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, task)
}

/// A config with list 1 (from `list_url`), a local record and the admin listener.
fn test_config(data_dir: &Path, list_url: &str) -> (Config, String) {
    let text = format!(
        "# test config\nconfig_version = 1\n\n[server]\ndata_dir = '{}'\ndns_listen = [\"127.0.0.1\"]\n\n[server.admin]\nlisten = [\"127.0.0.1\"]\n\n[stats]\nflush_interval_seconds = 0\n",
        data_dir.display()
    );
    let mut cfg = Config::from_toml_str(&text).unwrap();
    cfg.lists.adlists = vec![Adlist {
        id: 1,
        url: list_url.to_owned(),
        kind: ListKind::Block,
        enabled: true,
        groups: vec!["default".to_owned()],
        comment: None,
    }];
    cfg.local_dns.records = vec![LocalRecord {
        id: None,
        name: "nas.lan".to_owned(),
        record_type: CfgType::A,
        value: "192.0.2.10".to_owned(),
        enabled: true,
        comment: None,
    }];
    assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
    let text = cfg.to_toml_string().unwrap();
    (cfg, text)
}

/// DNS settings for 127.0.0.1 only, with a loopback upstream that does not answer.
fn settings_for(cfg: &Config, port: u16) -> DnsSettings {
    let (mut s, _) = DnsSettings::from_config(cfg).unwrap();
    s.listen = ListenMode::Addrs(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    s.port = port;
    s.pool.servers = vec![UpstreamServer {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
        proto: UpstreamProto::Udp,
    }];
    s
}

fn env_for(
    cfg: &Config,
    neighbors: Arc<dyn NeighborSource>,
    admin: SocketAddr,
    stats: Option<rusthole_store::Stats>,
) -> RunEnv {
    RunEnv {
        neighbors,
        interfaces: Arc::new(StaticInterfaces::default()),
        lists: ListsSettings::from_config(cfg),
        admin_listen: Some(vec![admin]),
        stats,
        rule_ids: RuleIds::new(cfg),
        config_path: "rusthole.toml".to_owned(),
        certs: None,
        cert_check: CERT_CHECK,
    }
}

fn test_deps() -> ServerDeps {
    ServerDeps {
        interfaces: Arc::new(StaticInterfaces::default()),
        ..ServerDeps::default()
    }
}

async fn ask(addr: SocketAddr, name: &str) -> Option<Message> {
    let mut m = Message::new(77, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    sock.send_to(&m.to_vec().unwrap(), addr).await.unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    Message::from_vec(&buf[..n]).ok()
}

/// Waits until only the test holds `src`: the neighbor task ended and dropped its copy.
async fn released(src: &Arc<StaticNeighbors>) -> bool {
    for _ in 0..500 {
        if Arc::strong_count(src) == 1 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

struct Seen {
    dns: Vec<BoundListener>,
    admin: Vec<SocketAddr>,
    refresher: Arc<Refresher>,
    identity: Arc<IdentityService>,
    blocking: bool,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_from_http_is_blocked_after_update_now_and_every_task_stops() {
    let dir = tempfile::tempdir().unwrap();
    let (http, http_task) = list_server("0.0.0.0 blocked.example\n").await;
    let (cfg, text) = test_config(dir.path(), &format!("http://{http}/list.txt"));
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, &text).unwrap();
    let store = Arc::new(ConfigStore::new(path, text, &cfg));
    let service = StatsService::start(&StatsSettings::ram_only()).unwrap();
    let src = Arc::new(StaticNeighbors::default());
    let neighbors: Arc<dyn NeighborSource> = src.clone();
    let env = env_for(
        &cfg,
        neighbors,
        "127.0.0.1:0".parse().unwrap(),
        Some(service.stats()),
    );
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Seen>();
    let settings = settings_for(&cfg, 0);
    let task = tokio::spawn(async move {
        serve_all(
            store,
            settings,
            test_deps(),
            env,
            async move {
                let _ = stop_rx.await;
            },
            move |r| {
                let _ = ready_tx.send(Seen {
                    dns: r.dns.clone(),
                    admin: r.admin.clone(),
                    refresher: Arc::clone(r.refresher),
                    identity: Arc::clone(r.policy.identity()),
                    blocking: r.policy.filter().blocking().is_blocking(),
                });
            },
        )
        .await
    });
    let seen = tokio::time::timeout(Duration::from_secs(20), ready_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(seen.blocking);
    let dns = seen.dns[0].udp;
    // The local record answers at once, with no list.
    let m = ask(dns, "nas.lan.").await.unwrap();
    assert!(m.metadata.authoritative);
    assert_eq!(m.answers[0].data, RData::A(A(Ipv4Addr::new(192, 0, 2, 10))));

    // The refresher fetches the list now; the engine swaps; the name is blocked.
    seen.refresher.update_now(UpdateTarget::All).unwrap();
    let mut blocked = false;
    for _ in 0..200 {
        if let Some(m) = ask(dns, "blocked.example.").await
            && m.answers.first().map(|a| &a.data) == Some(&RData::A(A(Ipv4Addr::UNSPECIFIED)))
        {
            blocked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(blocked, "the list from the HTTP server must block the name");
    // The admin listener accepts connections.
    let admin = seen.admin[0];
    assert!(tokio::net::TcpStream::connect(admin).await.is_ok());
    assert!(seen.refresher.task_count() > 0);
    assert_eq!(seen.identity.task_count(), 1);

    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // Every task stopped: the refresher, the identity tasks, the DNS server, the admin
    // listener.
    assert_eq!(seen.refresher.task_count(), 0);
    assert_eq!(seen.identity.task_count(), 0);
    assert!(released(&src).await);
    assert!(UdpSocket::bind(dns).await.is_ok());
    assert!(TcpListener::bind(admin).await.is_ok());
    service.shutdown(Duration::from_secs(5));
    http_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dns_start_error_stops_the_started_parts() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, text) = test_config(dir.path(), "http://127.0.0.1:9/list.txt");
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, &text).unwrap();
    let store = Arc::new(ConfigStore::new(path, text, &cfg));
    let blocker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = blocker.local_addr().unwrap().port();
    let src = Arc::new(StaticNeighbors::default());
    let neighbors: Arc<dyn NeighborSource> = src.clone();
    let env = env_for(&cfg, neighbors, "127.0.0.1:0".parse().unwrap(), None);
    let err = serve_all(
        store,
        settings_for(&cfg, port),
        test_deps(),
        env,
        std::future::pending(),
        |_| panic!("the server must not start"),
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{err:#}").contains("cannot listen"), "{err:#}");
    assert!(released(&src).await);
    drop(blocker);
}

/// m16: a failed admin bind must not stop DNS (owner decision). rusthole logs an ERROR and
/// runs DNS with no admin listener. This test replaces the old test that asserted the
/// opposite (`an_admin_start_error_stops_the_dns_server_too`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admin_bind_error_keeps_dns_running() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, text) = test_config(dir.path(), "http://127.0.0.1:9/list.txt");
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, &text).unwrap();
    let store = Arc::new(ConfigStore::new(path, text, &cfg));
    let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let busy_addr = busy.local_addr().unwrap();
    let src = Arc::new(StaticNeighbors::default());
    let neighbors: Arc<dyn NeighborSource> = src.clone();
    let env = env_for(&cfg, neighbors, busy_addr, None);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let (ready_tx, ready_rx) =
        tokio::sync::oneshot::channel::<(Vec<BoundListener>, Vec<SocketAddr>)>();
    let settings = settings_for(&cfg, 0);
    let task = tokio::spawn(async move {
        serve_all(
            store,
            settings,
            test_deps(),
            env,
            async move {
                let _ = stop_rx.await;
            },
            move |r| {
                let _ = ready_tx.send((r.dns.clone(), r.admin.clone()));
            },
        )
        .await
    });
    let (dns, admin) = tokio::time::timeout(Duration::from_secs(20), ready_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(admin.is_empty(), "no admin address is bound");
    let m = ask(dns[0].udp, "nas.lan.").await.unwrap();
    assert!(m.metadata.authoritative, "DNS must answer");
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(released(&src).await);
    drop(busy);
}

/// A self-signed certificate (PEM pair) for `127.0.0.1`, `localhost` and `extra`.
fn cert_pair(extra: &[&str]) -> rusthole_tls::generate::GeneratedPair {
    let mut names: std::collections::BTreeSet<String> =
        extra.iter().map(|n| (*n).to_owned()).collect();
    names.insert("localhost".to_owned());
    let sans = rusthole_tls::SanSet {
        names,
        ips: [IpAddr::V4(Ipv4Addr::LOCALHOST)].into_iter().collect(),
    };
    rusthole_tls::generate::self_signed(&sans, rusthole_tls::now_unix() - 60).unwrap()
}

fn der_of(pem: &str) -> Vec<u8> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::from_pem_slice(pem.as_bytes())
        .unwrap()
        .to_vec()
}

/// The certificate that the TLS server at `addr` shows to a new connection.
async fn served_cert(addr: SocketAddr, trust: &[&str]) -> Vec<u8> {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for pem in trust {
        roots
            .add(rustls::pki_types::CertificateDer::from_pem_slice(pem.as_bytes()).unwrap())
            .unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(rusthole_tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
    let tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(name, tcp))
        .await
        .unwrap()
        .unwrap();
    tls.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

/// M2: in mode `file`, a new certificate file is used for the next TLS connection of the
/// admin listener and of the DoH listener (one shared store), with no restart. m18: the
/// live listener list has the DoH address. The reload task stops with the other parts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_certificate_file_is_used_for_new_connections() {
    let dir = tempfile::tempdir().unwrap();
    let (mut cfg, _) = test_config(dir.path(), "http://127.0.0.1:9/list.txt");
    let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    let a = cert_pair(&[]);
    std::fs::write(&cert_path, &a.cert_pem).unwrap();
    std::fs::write(&key_path, &a.key_pem).unwrap();
    cfg.tls.mode = Some(rusthole_core::config::TlsMode::File);
    cfg.tls.cert_path = Some(cert_path.display().to_string());
    cfg.tls.key_path = Some(key_path.display().to_string());
    cfg.server.doh.enabled = true;
    let text = cfg.to_toml_string().unwrap();
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, &text).unwrap();
    let store = Arc::new(ConfigStore::new(path, text, &cfg));
    let (certs, doh_tls) = crate::doh::server_tls(&cfg).unwrap().unwrap();
    let mut env = env_for(
        &cfg,
        Arc::new(StaticNeighbors::default()),
        "127.0.0.1:0".parse().unwrap(),
        None,
    );
    env.certs = Some(Arc::clone(&certs));
    env.cert_check = Duration::from_millis(100);
    let mut settings = settings_for(&cfg, 0);
    settings.doh = Some(rusthole_dns::DohSettings {
        listen: ListenMode::Addrs(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        port: 0,
        limits: rusthole_dns::DohLimits::default(),
    });
    let deps = ServerDeps {
        doh_tls: Some(doh_tls),
        ..test_deps()
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let (ready_tx, ready_rx) =
        tokio::sync::oneshot::channel::<(Vec<SocketAddr>, Vec<(String, SocketAddr)>)>();
    let task = tokio::spawn(async move {
        serve_all(
            store,
            settings,
            deps,
            env,
            async move {
                let _ = stop_rx.await;
            },
            move |r| {
                let _ = ready_tx.send((r.admin.clone(), live_listeners(r.server)));
            },
        )
        .await
    });
    let (admin, listeners) = tokio::time::timeout(Duration::from_secs(20), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let doh: Vec<SocketAddr> = listeners
        .iter()
        .filter(|(k, _)| k == "doh")
        .map(|(_, a)| *a)
        .collect();
    assert_eq!(doh.len(), 1, "{listeners:?}");
    assert!(listeners.iter().any(|(k, _)| k == "dns"), "{listeners:?}");
    let b = cert_pair(&["new-name.lan"]);
    let trust = [a.cert_pem.as_str(), b.cert_pem.as_str()];
    assert_eq!(served_cert(admin[0], &trust).await, der_of(&a.cert_pem));
    assert_eq!(served_cert(doh[0], &trust).await, der_of(&a.cert_pem));
    // The new pair has one more name: the files differ in size, so the stamps differ.
    std::fs::write(&key_path, &b.key_pem).unwrap();
    std::fs::write(&cert_path, &b.cert_pem).unwrap();
    let want = der_of(&b.cert_pem);
    let mut seen = false;
    for _ in 0..100 {
        if served_cert(admin[0], &trust).await == want {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen, "the admin listener must use the new certificate");
    assert_eq!(served_cert(doh[0], &trust).await, want);
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // Each part that held the store (the reload task, the listeners) stopped.
    let mut free = false;
    for _ in 0..500 {
        if Arc::strong_count(&certs) == 1 {
            free = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(free, "a task still holds the certificate store");
}

#[test]
fn cert_check_policy() {
    let hour = Duration::from_secs(3600);
    assert!(cert_check_due(true, false, Duration::ZERO));
    assert!(cert_check_due(false, true, Duration::ZERO));
    assert!(!cert_check_due(false, false, Duration::from_secs(3599)));
    assert!(cert_check_due(false, false, hour));
}

/// m11: when a stored name is cleared, kept or replaced.
#[test]
fn identity_names() {
    use rusthole_store::Identity;
    let id = |mac: Option<&str>, name: Option<&str>| Identity {
        mac: mac.map(str::to_owned),
        name: name.map(str::to_owned),
    };
    let mac = Some("02:00:00:00:00:01");
    let s = |v: &str| Some(v.to_owned());
    // A new local name replaces the stored name.
    assert_eq!(
        next_identity(&id(mac, Some("old.lan")), None, s("nas.lan"), true),
        Some(id(mac, Some("nas.lan")))
    );
    // A removed local record clears the name; the MAC stays.
    assert_eq!(
        next_identity(&id(mac, Some("nas.lan")), None, None, true),
        Some(id(mac, None))
    );
    // A PTR name stays when its cache entry ends.
    assert_eq!(
        next_identity(&id(mac, Some("printer.lan")), None, None, false),
        None
    );
    // No change: nothing to write.
    assert_eq!(
        next_identity(
            &id(mac, Some("nas.lan")),
            s("02:00:00:00:00:01"),
            s("nas.lan"),
            true
        ),
        None
    );
    assert_eq!(next_identity(&Identity::default(), None, None, false), None);
    // A new MAC is written.
    assert_eq!(
        next_identity(&Identity::default(), s("02:00:00:00:00:02"), None, false),
        Some(id(Some("02:00:00:00:00:02"), None))
    );
}

/// m11: the identity sync reads the local zone of the resolver at each round. A record that
/// a live apply adds gives the name; a record that a live apply removes clears it.
#[tokio::test]
async fn the_identity_sync_follows_live_local_records() {
    use rusthole_core::stats::{StatsEvent, Status};
    let service = StatsService::start(&StatsSettings::ram_only()).unwrap();
    let stats = service.stats();
    let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    stats
        .apply(&mut vec![StatsEvent {
            at: rusthole_store::wall_now(),
            client,
            name: "example.com".to_owned(),
            qtype: 1,
            status: Status::Forwarded,
            reason: None,
            upstream: Some("192.0.2.53:53".to_owned()),
            duration_us: 1000,
        }])
        .unwrap();
    let name_of = || {
        stats
            .clients_index()
            .unwrap()
            .all()
            .find(|m| m.ip == client)
            .and_then(|m| m.name.clone())
    };
    let (mut cfg, _) = test_config(Path::new("."), "http://127.0.0.1:9/list.txt");
    cfg.local_dns.records.clear();
    let zone = |c: &Config| Arc::new(rusthole_core::localdns::LocalZone::from_config(c).0);
    let resolver = rusthole_dns::ClientResolver::new(
        ClientTable::from_config(&cfg).0,
        zone(&cfg),
        Arc::new(rusthole_dns::NeighborTable::default()),
        IdentitySettings::default(),
    );
    let prev = sync_once(&stats, &resolver, None).unwrap();
    assert_eq!(name_of(), None);
    // A live apply adds the record `nas.lan` for the client address.
    let (with, _) = test_config(Path::new("."), "http://127.0.0.1:9/list.txt");
    assert!(resolver.set_config(ClientTable::from_config(&with).0, zone(&with)));
    let prev = sync_once(&stats, &resolver, Some(&prev)).unwrap();
    assert_eq!(name_of().as_deref(), Some("nas.lan"));
    // A live apply removes it again.
    assert!(resolver.set_config(ClientTable::from_config(&cfg).0, zone(&cfg)));
    sync_once(&stats, &resolver, Some(&prev)).unwrap();
    assert_eq!(name_of(), None);
    drop(service);
}
