//! The `run` command: load the config, start the DNS server, wait for a stop signal, stop.
//!
//! ```mermaid
//! sequenceDiagram
//!     participant M as main
//!     participant S as DNS server
//!     M->>M: load and validate config (exit 1 on a problem)
//!     M->>S: start (bind, upstream pool, rescan)
//!     M->>M: wait for SIGTERM / SIGINT / Ctrl+C
//!     M->>S: shutdown (stop accept, finish in-flight queries, hard stop after grace)
//!     M->>M: stop the runtime (time limit)
//! ```

use std::future::Future;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use rusthole_dns::server::SHUTDOWN_GRACE;
use rusthole_dns::{BoundListener, DnsSettings, ServerDeps};

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
    let result = runtime.block_on(serve(
        settings,
        ServerDeps::default(),
        stop_signal(),
        |_| {},
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

    use rusthole_core::Config;
    use rusthole_dns::{ListenMode, StaticInterfaces, UpstreamProto, UpstreamServer};
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
