//! rusthole command-line entry point.

mod fsutil;
mod passwd;
mod run;
mod stats_observer;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use rusthole_core::Config;

/// Default config file path on Linux.
const DEFAULT_CONFIG: &str = "/etc/rusthole/rusthole.toml";
/// Largest config file that rusthole reads.
const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
/// Largest Teleporter zip that rusthole reads.
const MAX_ZIP_BYTES: u64 = 1024 * 1024 * 1024;

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
    /// Read and validate the config file. Exit code 1 means that the config has problems.
    CheckConfig,
    /// Convert a Pi-hole v6 Teleporter export (zip) into a rusthole config file.
    Import {
        /// Path to the Teleporter zip file.
        teleporter: PathBuf,
        /// Path of the new config file.
        #[arg(short, long, default_value = "rusthole.toml")]
        output: PathBuf,
        /// Replace the output file if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Set the admin password. Reads the password two times from the terminal (no echo).
    Passwd {
        /// Set up TOTP (a second login factor) instead: prints the otpauth URI one time.
        #[arg(long, conflicts_with = "disable_totp")]
        totp: bool,
        /// Turn TOTP off.
        #[arg(long)]
        disable_totp: bool,
    },
}

fn main() -> ExitCode {
    init_logging();
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(err) => {
            tracing::error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<ExitCode> {
    // The report and the issues are the output of the command, so they go to stdout.
    let mut out = std::io::stdout().lock();
    match &cli.command {
        Command::Run => run::run(&cli.config, &mut out),
        Command::CheckConfig => check_config(&cli.config, &mut out),
        Command::Import {
            teleporter,
            output,
            force,
        } => import(teleporter, output, *force, &mut out),
        Command::Passwd { totp, disable_totp } => {
            passwd::run(&cli.config, *totp, *disable_totp, &mut out)
        }
    }
}

/// Loads and validates a config file. Prints each issue.
fn check_config(path: &Path, out: &mut impl Write) -> anyhow::Result<ExitCode> {
    if load_config(path, out)?.is_none() {
        return Ok(ExitCode::FAILURE);
    }
    writeln!(out, "{}: config is valid", path.display())?;
    Ok(ExitCode::SUCCESS)
}

/// Reads, parses and validates a config file. Prints each problem to `out` and returns
/// `None` when the config has a problem.
fn load_config(path: &Path, out: &mut impl Write) -> anyhow::Result<Option<Config>> {
    Ok(load_config_text(path, out)?.map(|(c, _)| c))
}

/// Like [`load_config`], and also returns the file text (the admin API keeps it to edit the
/// file).
fn load_config_text(path: &Path, out: &mut impl Write) -> anyhow::Result<Option<(Config, String)>> {
    let bytes = fsutil::read_limited(path, MAX_CONFIG_BYTES)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("{} is not UTF-8 text", path.display()))?;
    let config = match Config::from_toml_str(&text) {
        Ok(c) => c,
        Err(e) => {
            writeln!(out, "{}: {e}", path.display())?;
            return Ok(None);
        }
    };
    let issues = config.validate();
    if issues.is_empty() {
        return Ok(Some((config, text)));
    }
    for issue in &issues {
        writeln!(out, "{}: {issue}", path.display())?;
    }
    writeln!(out, "{} problem(s) found", issues.len())?;
    Ok(None)
}

/// Header of an imported config file.
const IMPORT_HEADER: &str = "\
# rusthole config, made by `rusthole import` from a Pi-hole v6 Teleporter export.
# docs/CONFIG.md explains each field. Set the admin password with `rusthole passwd`.

";

/// Imports a Teleporter zip and writes the config file atomically.
fn import(
    zip: &Path,
    output: &Path,
    force: bool,
    out: &mut impl Write,
) -> anyhow::Result<ExitCode> {
    if !force && output.exists() {
        anyhow::bail!("{} exists; use --force to replace it", output.display());
    }
    let bytes = fsutil::read_limited(zip, MAX_ZIP_BYTES)
        .with_context(|| format!("cannot read {}", zip.display()))?;
    let imported = rusthole_import::import_teleporter(&bytes, &rusthole_import::Limits::default())
        .with_context(|| format!("cannot import {}", zip.display()))?;
    let text = format!("{IMPORT_HEADER}{}", imported.config.to_toml_string()?);
    fsutil::write_atomic(output, text.as_bytes(), force)
        .with_context(|| format!("cannot write {}", output.display()))?;
    write!(out, "{}", imported.report)?;
    writeln!(out, "Wrote {}", output.display())?;
    let issues = imported.config.validate();
    if issues.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    // The import makes a valid config, so this is a bug. Show it, and keep the file.
    for issue in &issues {
        writeln!(out, "{}: {issue}", output.display())?;
    }
    Ok(ExitCode::FAILURE)
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
