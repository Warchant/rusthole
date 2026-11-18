//! Writes the build time into the binary (`RUSTHOLE_BUILD_UNIX`, Unix seconds).
//!
//! `clock_plausible` compares the wall clock with this time (amendment A6). The build uses
//! `SOURCE_DATE_EPOCH` when it is set, so a reproducible build gives the same binary.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let from_env = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok());
    let secs = from_env.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0)
    });
    println!("cargo:rustc-env=RUSTHOLE_BUILD_UNIX={secs}");
}
