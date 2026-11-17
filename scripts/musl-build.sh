#!/usr/bin/env bash
# Build static musl binaries of rusthole with cargo-zigbuild, and check that they are static.
#
# Use from Windows (WSL):
#   wsl -d Ubuntu-22.04 -- bash /mnt/e/bohdan/rusthole/scripts/musl-build.sh
#   wsl -d Ubuntu-22.04 -- bash /mnt/e/bohdan/rusthole/scripts/musl-build.sh aarch64-unknown-linux-musl
#
# The script installs zig (Python package `ziglang`) and cargo-zigbuild on drive D when they
# are missing. Drive C is nearly full, so all caches and the build output go to drive D.
set -euo pipefail

base="${RUSTHOLE_TMP_LINUX:-/mnt/d/tmp}"
export CARGO_HOME="${CARGO_HOME_LINUX:-$base/wsl-cargo-home}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR_LINUX:-$base/rusthole-target-linux}"
export TMPDIR="$base"
export XDG_CACHE_HOME="$base/xdg-cache"
export ZIG_GLOBAL_CACHE_DIR="$base/zig-cache"
export ZIG_LOCAL_CACHE_DIR="$base/zig-cache"
zig_dir="$base/wsl-zig"
# rustup is in the user's default cargo home, not in CARGO_HOME above.
export PATH="$zig_dir/ziglang:$CARGO_HOME/bin:$HOME/.cargo/bin:$PATH"

if ! command -v zig >/dev/null; then
    python3 -m pip install --no-cache-dir --target "$zig_dir" ziglang
fi
if ! command -v cargo-zigbuild >/dev/null; then
    cargo install --locked cargo-zigbuild
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then
    targets=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
fi

for target in "${targets[@]}"; do
    rustup target add "$target" >/dev/null
    cargo zigbuild --release --locked --target "$target" -p rusthole
    bin="$CARGO_TARGET_DIR/$target/release/rusthole"
    info="$(file "$bin")"
    echo "$info"
    echo "size: $(stat -c %s "$bin") bytes"
    if ! grep -Eq 'statically linked|static-pie linked' <<<"$info" || grep -q 'dynamically linked' <<<"$info"; then
        echo "error: $bin is not a static binary" >&2
        exit 1
    fi
done
