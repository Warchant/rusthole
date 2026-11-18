//! Picks the UI folder that the binary embeds (decision D14).
//!
//! When `web/dist/index.html` exists (after `bun run build` in `web/`), the binary embeds
//! `web/dist`. Otherwise it embeds the small placeholder page in `placeholder/`. This script
//! never runs bun or Node.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let dist = manifest.join("../../web/dist");
    let placeholder = manifest.join("placeholder");
    let index = dist.join("index.html");
    println!("cargo::rerun-if-changed={}", index.display());
    println!("cargo::rerun-if-changed={}", dist.display());
    println!("cargo::rerun-if-changed={}", placeholder.display());
    let (folder, from_dist) = if index.is_file() {
        (dist, true)
    } else {
        (placeholder.clone(), false)
    };
    // rust-embed reads the folder from this variable.
    let folder = folder.canonicalize().unwrap_or(folder);
    let placeholder = placeholder.canonicalize().unwrap_or(placeholder);
    println!("cargo::rustc-env=RUSTHOLE_WEB_DIST={}", folder.display());
    println!(
        "cargo::rustc-env=RUSTHOLE_WEB_PLACEHOLDER={}",
        placeholder.display()
    );
    println!(
        "cargo::rustc-env=RUSTHOLE_WEB_FROM_DIST={}",
        if from_dist { "1" } else { "0" }
    );
}
