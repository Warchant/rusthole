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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admin_start_error_stops_the_dns_server_too() {
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
    let err = serve_all(
        store,
        settings_for(&cfg, 0),
        test_deps(),
        env,
        std::future::pending(),
        |_| panic!("the server must not start"),
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{err:#}").contains("admin"), "{err:#}");
    assert!(released(&src).await);
    drop(busy);
}
