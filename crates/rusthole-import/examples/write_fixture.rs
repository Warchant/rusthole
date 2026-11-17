//! Writes the synthetic home-setup Teleporter zip to a file, or fuzz seeds to a directory.
//!
//! Use:
//!
//! - `cargo run -p rusthole-import --features testkit --example write_fixture -- OUT.zip`
//! - `cargo run -p rusthole-import --features testkit --example write_fixture -- --seeds DIR`
//!
//! With `--seeds`, the tool writes valid seeds for the fuzz targets into `DIR/<target>/`:
//! `teleporter_zip/home.zip`, `pihole_toml/home.toml`, `config_parse/home.toml` (the config
//! that the import makes from the home fixture) and `config_parse/docs-example.toml` (the full
//! example of docs/CONFIG.md). CI uses this, so each fuzz run starts from valid input and
//! reaches the deep code.

use std::path::Path;
use std::process::ExitCode;

use rusthole_import::testkit::{home_pihole_toml, home_zip};
use rusthole_import::{Limits, import_teleporter};

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn write_seeds(dir: &Path) -> Result<(), String> {
    let zip = home_zip();
    let imported =
        import_teleporter(&zip, &Limits::default()).map_err(|e| format!("import: {e}"))?;
    let config = imported
        .config
        .to_toml_string()
        .map_err(|e| format!("config: {e}"))?;
    write(&dir.join("teleporter_zip").join("home.zip"), &zip)?;
    write(
        &dir.join("pihole_toml").join("home.toml"),
        home_pihole_toml().as_bytes(),
    )?;
    write(
        &dir.join("config_parse").join("home.toml"),
        config.as_bytes(),
    )?;
    // The full example of docs/CONFIG.md has each section (DoT and DoH upstreams, admin
    // hashes, CNAME records, ...), so the fuzzer also starts with these paths.
    let doc = include_str!("../../../docs/CONFIG.md");
    let example = doc
        .split_once("```toml\n")
        .and_then(|(_, rest)| rest.split_once("```"))
        .map(|(text, _)| text)
        .ok_or("docs/CONFIG.md has no TOML example")?;
    write(
        &dir.join("config_parse").join("docs-example.toml"),
        example.as_bytes(),
    )
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [flag, dir] if flag == "--seeds" => write_seeds(Path::new(dir)),
        [path] => write(Path::new(path), &home_zip()),
        _ => Err("usage: write_fixture OUT.zip | write_fixture --seeds DIR".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // This is a developer tool; stderr is the right place for errors.
            #[allow(clippy::print_stderr)]
            {
                eprintln!("{e}");
            }
            ExitCode::FAILURE
        }
    }
}
