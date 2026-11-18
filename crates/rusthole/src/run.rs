//! The `run` command: load the config, start the policy and the DNS server, wait for a stop
//! signal, stop.
//!
//! ```mermaid
//! sequenceDiagram
//!     participant M as main
//!     participant P as policy (part P3c)
//!     participant S as DNS server
//!     M->>M: load and validate config (exit 1 on a problem)
//!     M->>P: neighbor task, client resolver, engine (lists on disk), filter
//!     M->>S: start with the filter (bind, upstream pool, rescan)
//!     M->>M: wait for SIGTERM / SIGINT / Ctrl+C
//!     M->>S: shutdown (stop accept, finish in-flight queries, hard stop after grace)
//!     M->>P: shutdown (neighbor and PTR tasks)
//!     M->>M: stop the runtime (time limit)
//! ```

use std::future::Future;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rusthole_core::Config;
use rusthole_core::clients::ClientTable;
use rusthole_dns::server::SHUTDOWN_GRACE;
use rusthole_dns::{
    BlockingControl, BoundListener, DnsSettings, IdentityService, IdentitySettings, NeighborSource,
    PolicyFilter, ServerDeps, SystemNeighbors, engine_handle,
};

use crate::engine::{DiskLists, EngineLoader};

/// Time limit for the runtime to stop after the server stopped.
const RUNTIME_STOP: Duration = Duration::from_secs(2);

/// Runs the server until a stop signal.
pub(crate) fn run(path: &Path, out: &mut impl Write) -> anyhow::Result<ExitCode> {
    let Some(config) = crate::load_config(path, out)? else {
        return Ok(ExitCode::FAILURE);
    };
    let (settings, warnings) = DnsSettings::from_config(&config)
        .with_context(|| format!("cannot use {}", path.display()))?;
    for w in &warnings {
        tracing::warn!("{w}");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rusthole")
        .build()
        .context("cannot start the async runtime")?;
    let loader = DiskLists::for_config(&config);
    let result = runtime.block_on(serve_with_policy(
        &config,
        settings,
        ServerDeps::default(),
        &loader,
        Arc::new(SystemNeighbors),
        stop_signal(),
        |_, _| {},
    ));
    runtime.shutdown_timeout(RUNTIME_STOP);
    result?;
    Ok(ExitCode::SUCCESS)
}

/// Starts the DNS server, gives the bound listeners to `ready`, waits for `stop`, then
/// stops the server and all its tasks.
///
/// Each exit path stops the tasks: a start error stops them inside `start`, and after
/// `stop` the shutdown stops them (with a hard stop after the grace time).
pub(crate) async fn serve(
    settings: DnsSettings,
    deps: ServerDeps,
    stop: impl Future<Output = ()>,
    ready: impl FnOnce(Vec<BoundListener>),
) -> anyhow::Result<()> {
    let server = rusthole_dns::start(settings, deps)
        .await
        .context("cannot start the DNS server")?;
    tracing::info!("rusthole is running");
    ready(server.bound());
    stop.await;
    tracing::info!("stop signal received; stopping");
    server.shutdown(SHUTDOWN_GRACE).await;
    Ok(())
}

/// The policy parts of a running server (part P3c): the client identity tasks and the
/// filter with the engine and the blocking toggle.
#[derive(Debug)]
pub(crate) struct Policy {
    identity: Arc<IdentityService>,
    filter: Arc<PolicyFilter>,
}

impl Policy {
    /// Builds the engine with `loader`, starts the neighbor and PTR tasks, and makes the
    /// filter. A loader error stops nothing, because no task started yet. Call it inside a
    /// tokio runtime.
    pub(crate) fn start(
        config: &Config,
        settings: &DnsSettings,
        loader: &dyn EngineLoader,
        neighbors: Arc<dyn NeighborSource>,
    ) -> anyhow::Result<Self> {
        let (engine, _report) = loader
            .load(config)
            .context("cannot build the policy engine")?;
        let (table, issues) = ClientTable::from_config(config);
        for issue in &issues {
            tracing::warn!("clients: {issue}");
        }
        let identity = Arc::new(
            IdentityService::start(
                table,
                Arc::clone(&settings.local),
                neighbors,
                IdentitySettings::default(),
            )
            .context("cannot start the client identity tasks")?,
        );
        let filter = Arc::new(PolicyFilter::new(
            engine_handle(engine),
            Arc::new(BlockingControl::new(config.blocking.enabled)),
            identity.resolver(),
        ));
        Ok(Self { identity, filter })
    }

    /// The filter (the engine handle and the blocking toggle are in it). Part P5 gives the
    /// toggle to the API; until then only tests use it.
    #[cfg(test)]
    pub(crate) fn filter(&self) -> &Arc<PolicyFilter> {
        &self.filter
    }

    /// The client identity service.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> &Arc<IdentityService> {
        &self.identity
    }
}

/// Starts the policy, then the DNS server with the policy filter ([`serve`]). Each exit
/// path (start error of the server, stop signal) stops the policy tasks too.
pub(crate) async fn serve_with_policy(
    config: &Config,
    settings: DnsSettings,
    base: ServerDeps,
    loader: &dyn EngineLoader,
    neighbors: Arc<dyn NeighborSource>,
    stop: impl Future<Output = ()>,
    ready: impl FnOnce(Vec<BoundListener>, &Policy),
) -> anyhow::Result<()> {
    let policy = Policy::start(config, &settings, loader, neighbors)?;
    let deps = ServerDeps {
        filter: Arc::clone(&policy.filter) as Arc<dyn rusthole_dns::QueryFilter>,
        ..base
    };
    let result = serve(settings, deps, stop, |bound| ready(bound, &policy)).await;
    if !policy.identity.shutdown(SHUTDOWN_GRACE).await {
        tracing::warn!("client identity tasks did not stop in time");
    }
    result
}

/// Waits for SIGTERM or SIGINT (Unix), or Ctrl+C (all systems).
///
/// The wait has no time limit on purpose: the server runs until it gets a stop signal.
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = int.recv() => {}
                }
                return;
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "cannot listen for SIGTERM or SIGINT; using Ctrl+C only");
            }
        }
    }
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %e, "cannot listen for Ctrl+C; stop the process with a kill");
        // No stop signal can come. The server runs until the process is killed.
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, RecordType};
    use rusthole_core::config::{Adlist, ListKind, LocalRecord, RecordType as CfgType};
    use rusthole_dns::{
        ListenMode, StaticInterfaces, StaticNeighbors, UpstreamProto, UpstreamServer,
    };
    use tokio::net::{TcpListener, UdpSocket};

    use super::*;

    /// Settings for 127.0.0.1 only, with a loopback upstream: no test query leaves the host.
    fn test_settings(port: u16) -> DnsSettings {
        let (mut s, _) = DnsSettings::from_config(&Config::default()).unwrap();
        s.listen = ListenMode::Addrs(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        s.port = port;
        s.pool.servers = vec![UpstreamServer {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
            proto: UpstreamProto::Udp,
        }];
        s
    }

    fn test_deps() -> ServerDeps {
        ServerDeps {
            interfaces: Arc::new(StaticInterfaces::default()),
            ..ServerDeps::default()
        }
    }

    /// A query with opcode STATUS (2). The server answers REFUSED at once, with no upstream.
    const STATUS_QUERY: [u8; 12] = [0x12, 0x34, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    /// True when the server at `addr` answers [`STATUS_QUERY`].
    async fn answers(addr: SocketAddr) -> bool {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        sock.send_to(&STATUS_QUERY, addr).await.unwrap();
        let mut buf = [0u8; 512];
        // On Windows, an ICMP "port unreachable" gives an error here; that is "no answer".
        matches!(
            tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await,
            Ok(Ok((n, _))) if n >= 12 && buf[..2] == STATUS_QUERY[..2]
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_stops_all_tasks_on_the_stop_signal() {
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Vec<BoundListener>>();
        let task = tokio::spawn(serve(
            test_settings(0),
            test_deps(),
            async move {
                let _ = stop_rx.await;
            },
            move |bound| {
                let _ = ready_tx.send(bound);
            },
        ));
        let bound = tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .unwrap()
            .unwrap();
        let [listener] = bound[..] else {
            panic!("one listener expected: {bound:?}");
        };
        // The server answers while it runs.
        assert!(answers(listener.udp).await);
        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        // All sockets are closed after the stop.
        assert!(!answers(listener.udp).await);
        assert!(UdpSocket::bind(listener.udp).await.is_ok());
        assert!(TcpListener::bind(listener.tcp).await.is_ok());
    }

    /// A config with list 1 on disk (it blocks `blocked.example`) and a local record.
    fn policy_config(data_dir: &Path) -> Config {
        let mut cfg = Config::default();
        cfg.server.data_dir = data_dir.display().to_string();
        cfg.lists.adlists = vec![Adlist {
            id: 1,
            url: "https://lists.example/hosts.txt".to_owned(),
            kind: ListKind::Block,
            enabled: true,
            groups: vec!["default".to_owned()],
            comment: None,
        }];
        cfg.local_dns.records = vec![LocalRecord {
            name: "nas.lan".to_owned(),
            record_type: CfgType::A,
            value: "192.0.2.10".to_owned(),
        }];
        let lists = data_dir.join("lists");
        std::fs::create_dir_all(&lists).unwrap();
        std::fs::write(lists.join("1.txt"), "0.0.0.0 blocked.example\n").unwrap();
        cfg
    }

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

    async fn ask(addr: SocketAddr, name: &str) -> Message {
        let mut m = Message::new(77, MessageType::Query, OpCode::Query);
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        sock.send_to(&m.to_vec().unwrap(), addr).await.unwrap();
        let mut buf = [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        Message::from_vec(&buf[..n]).unwrap()
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_blocks_a_listed_name_and_answers_a_local_record() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = policy_config(dir.path());
        let src = Arc::new(StaticNeighbors::default());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) =
            tokio::sync::oneshot::channel::<(Vec<BoundListener>, Arc<IdentityService>)>();
        let loader = DiskLists::for_config(&cfg);
        let settings = settings_for(&cfg, 0);
        let neighbors: Arc<dyn NeighborSource> = src.clone();
        let task = tokio::spawn(async move {
            serve_with_policy(
                &cfg,
                settings,
                test_deps(),
                &loader,
                neighbors,
                async move {
                    let _ = stop_rx.await;
                },
                move |bound, policy| {
                    assert!(policy.filter().blocking().is_blocking());
                    let _ = ready_tx.send((bound, Arc::clone(policy.identity())));
                },
            )
            .await
        });
        let (bound, identity) = tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .unwrap()
            .unwrap();
        let addr = bound[0].udp;
        let m = ask(addr, "blocked.example.").await;
        assert_eq!(m.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
        let m = ask(addr, "nas.lan.").await;
        assert!(m.metadata.authoritative);
        assert_eq!(m.answers[0].data, RData::A(A(Ipv4Addr::new(192, 0, 2, 10))));
        assert_eq!(identity.task_count(), 1);

        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        // Shutdown stopped every task: the server, the neighbor task.
        assert_eq!(identity.task_count(), 0);
        assert!(released(&src).await);
        assert!(UdpSocket::bind(bound[0].udp).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_start_error_stops_the_policy_tasks() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = policy_config(dir.path());
        let blocker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = blocker.local_addr().unwrap().port();
        let src = Arc::new(StaticNeighbors::default());
        let neighbors: Arc<dyn NeighborSource> = src.clone();
        let err = serve_with_policy(
            &cfg,
            settings_for(&cfg, port),
            test_deps(),
            &DiskLists::for_config(&cfg),
            neighbors,
            std::future::pending(),
            |_, _| panic!("the server must not start"),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("cannot listen"), "{err:#}");
        assert!(released(&src).await);
        drop(blocker);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_returns_the_start_error() {
        // The port is busy while the blocker lives, so the bind fails.
        let blocker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = blocker.local_addr().unwrap().port();
        let err = serve(
            test_settings(port),
            test_deps(),
            std::future::pending(),
            |_| panic!("the server must not start"),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("cannot listen"), "{err:#}");
        drop(blocker);
    }
}
