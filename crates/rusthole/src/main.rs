//! rusthole command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Default config file path on Linux.
const DEFAULT_CONFIG: &str = "/etc/rusthole/rusthole.toml";

#[derive(Debug, Parser)]
#[command(
    name = "rusthole",
    version,
    about = "DNS ad blocker. One static binary."
)]
struct Cli {
    /// Path to the config file.
    #[arg(short, long, global = true, default_value = DEFAULT_CONFIG, env = "RUSTHOLE_CONFIG")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the DNS server, the DNS-over-HTTPS server and the admin UI.
    Run,
    /// Read and validate the config file, then exit.
    CheckConfig,
    /// Convert a Pi-hole v6 Teleporter export (zip) into a rusthole config file.
    Import {
        /// Path to the Teleporter zip file.
        teleporter: PathBuf,
    },
    /// Set the admin password. Reads the password from the terminal.
    Passwd,
}

fn main() -> ExitCode {
    init_logging();
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Run => anyhow::bail!("`run` is not available yet (part P2)"),
        Command::CheckConfig => anyhow::bail!("`check-config` is not available yet (part P1)"),
        Command::Import { .. } => anyhow::bail!("`import` is not available yet (part P1)"),
        Command::Passwd => anyhow::bail!("`passwd` is not available yet (part P5)"),
    }
}

/// Log to stderr. The `RUSTHOLE_LOG` environment variable sets the filter (default `info`).
fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("RUSTHOLE_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_valid() {
        Cli::command().debug_assert();
    }
}
