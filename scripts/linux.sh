#!/usr/bin/env bash
# Run a cargo command for Linux from Windows through WSL.
#
# Use from Windows:
#   wsl -d Ubuntu-22.04 -- bash -lc '/mnt/e/bohdan/rusthole/scripts/linux.sh test --workspace'
#   wsl -d Ubuntu-22.04 -- bash -lc '/mnt/e/bohdan/rusthole/scripts/linux.sh fuzz domain_parse 60'
#
# "fuzz" runs scripts/fuzz.sh with the pinned nightly of .github/workflows/ci.yml
# (FUZZ_NIGHTLY), and with the seeds in fuzz/seeds/<target>.
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
    # The pinned nightly of the CI fuzz job (amendment A8), not a floating nightly.
    pinned="$(sed -n 's/^[[:space:]]*FUZZ_NIGHTLY:[[:space:]]*//p' .github/workflows/ci.yml |
        head -n 1 | tr -d "\"' \r")"
    if [[ ! "$pinned" =~ ^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        echo "error: no pinned FUZZ_NIGHTLY in .github/workflows/ci.yml (got '$pinned')" >&2
        exit 1
    fi
    toolchain="$pinned"
    if ! rustup run "$pinned" rustc --version >/dev/null 2>&1; then
        # The floating "nightly" can be the same build. Then use it: no download.
        sysroot="$(rustup run nightly rustc --print sysroot 2>/dev/null || true)"
        manifest="$sysroot/lib/rustlib/multirust-channel-manifest.toml"
        if [[ -n "$sysroot" && -f "$manifest" ]] &&
            grep -qx "date = \"${pinned#nightly-}\"" "$manifest"; then
            toolchain=nightly
        else
            rustup toolchain install "$pinned" --profile minimal
        fi
    fi
    echo "fuzz toolchain: $toolchain (pinned: $pinned)"
    export FUZZ_TOOLCHAIN="$toolchain" FUZZ_TARGET_DIR="$CARGO_TARGET_DIR/fuzz"
    exec bash scripts/fuzz.sh one "$target" "$seconds"
fi

# Test binaries (and `cargo run`) get their temp directory on a RAM file system. On drive D
# (a Windows drive), each fsync can take seconds when other programs write to the disk, and
# tests with a time limit then fail. rustc and the linker keep TMPDIR on drive D.
test_tmp="/dev/shm/rusthole-test"
if mkdir -p "$test_tmp" 2>/dev/null; then
    host="$(rustc -vV | sed -n 's/^host: //p' | tr 'a-z-' 'A-Z_')"
    # The test helpers that keep their files out of the system temp directory (drive C on
    # Windows) read RUSTHOLE_TEST_TMP first. See docs/ENGINEERING.md.
    export "CARGO_TARGET_${host}_RUNNER=env TMPDIR=$test_tmp RUSTHOLE_TEST_TMP=$test_tmp"
fi

exec cargo "$@"
