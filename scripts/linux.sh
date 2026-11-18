#!/usr/bin/env bash
# Run a cargo command for Linux from Windows through WSL.
#
# Use from Windows:
#   wsl -d Ubuntu-22.04 -- bash -lc '/mnt/e/bohdan/rusthole/scripts/linux.sh test --workspace'
#   wsl -d Ubuntu-22.04 -- bash -lc '/mnt/e/bohdan/rusthole/scripts/linux.sh fuzz domain_parse 60'
#
# Drive C is nearly full, so the cargo cache and the build output go to drive D.
set -euo pipefail

export CARGO_HOME="${CARGO_HOME_LINUX:-/mnt/d/tmp/wsl-cargo-home}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR_LINUX:-/mnt/d/tmp/rusthole-target-linux}"
export TMPDIR="${TMPDIR_LINUX:-/mnt/d/tmp}"
# rustup is in the user's default cargo home, not in CARGO_HOME above.
export PATH="$HOME/.cargo/bin:$PATH"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

if [[ "${1:-}" == "fuzz" ]]; then
    target="${2:?fuzz target name}"
    seconds="${3:-60}"
    cd fuzz
    exec cargo +nightly fuzz run "$target" --target-dir "$CARGO_TARGET_DIR/fuzz" -- \
        -max_total_time="$seconds" -rss_limit_mb=2048
fi

# Test binaries (and `cargo run`) get their temp directory on a RAM file system. On drive D
# (a Windows drive), each fsync can take seconds when other programs write to the disk, and
# tests with a time limit then fail. rustc and the linker keep TMPDIR on drive D.
test_tmp="/dev/shm/rusthole-test"
if mkdir -p "$test_tmp" 2>/dev/null; then
    host="$(rustc -vV | sed -n 's/^host: //p' | tr 'a-z-' 'A-Z_')"
    export "CARGO_TARGET_${host}_RUNNER=env TMPDIR=$test_tmp"
fi

exec cargo "$@"
