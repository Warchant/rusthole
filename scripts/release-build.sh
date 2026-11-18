#!/usr/bin/env bash
# Build release binaries of rusthole: the web UI first, then one static musl binary for each
# target, with the UI inside the binary.
#
# Use:
#   bash scripts/release-build.sh x86_64-unknown-linux-musl
#   bash scripts/release-build.sh x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#
# From Windows (WSL), with the build output and the caches on drive D:
#   wsl -d Ubuntu-22.04 -- bash /mnt/e/bohdan/rusthole/scripts/release-build.sh x86_64-unknown-linux-musl
#
# Steps:
#   1. `bun install --frozen-lockfile` and `bun run build` in web/ (this makes web/dist).
#   2. `cargo zigbuild --release --locked --target <target> -p rusthole`.
#   3. Check that the binary is static, that it has the right CPU type, and that it holds
#      the built UI (not the placeholder page).
#   4. Copy the binary to <out>/rusthole-<arch>-linux-musl and print its size.
#
# Needs: bun, rustup, cargo, cargo-zigbuild, zig (or the Python package ziglang), file.
# In WSL, the script installs zig and cargo-zigbuild on drive D when they are missing (as
# scripts/musl-build.sh does), and uses bun from /mnt/d/tmp/wsl-bun.
#
# Environment:
#   CARGO_TARGET_DIR   build folder (default: target/ in the repo; in WSL the shared folder
#                      /mnt/d/tmp/rusthole-target-linux)
#   RELEASE_OUT_DIR    folder for the named binaries (default: <build folder>/release-out)
#   SKIP_WEB_BUILD=1   use the web/dist that is there (for example from a CI artifact)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

if [[ $# -eq 0 ]]; then
    echo "usage: $0 <target>..." >&2
    echo "targets: x86_64-unknown-linux-musl aarch64-unknown-linux-musl" >&2
    exit 2
fi

# The owner's machine: WSL with drive C nearly full. Put all caches and the build output on
# drive D, and use the shared Linux build folder.
if grep -qi microsoft /proc/version 2>/dev/null && [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
    base="${RUSTHOLE_TMP_LINUX:-/mnt/d/tmp}"
    export CARGO_HOME="${CARGO_HOME_LINUX:-$base/wsl-cargo-home}"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR_LINUX:-$base/rusthole-target-linux}"
    export TMPDIR="$base"
    export XDG_CACHE_HOME="$base/xdg-cache"
    export ZIG_GLOBAL_CACHE_DIR="$base/zig-cache"
    export ZIG_LOCAL_CACHE_DIR="$base/zig-cache"
    export BUN_INSTALL="${BUN_INSTALL:-$base/wsl-bun}"
    export BUN_INSTALL_CACHE_DIR="${BUN_INSTALL_CACHE_DIR:-$base/wsl-bun-cache}"
    zig_dir="$base/wsl-zig"
    # rustup is in the user's default cargo home, not in CARGO_HOME above.
    export PATH="$BUN_INSTALL/bin:$zig_dir/ziglang:$CARGO_HOME/bin:$HOME/.cargo/bin:$PATH"
    if ! command -v zig >/dev/null; then
        python3 -m pip install --no-cache-dir --target "$zig_dir" ziglang
    fi
    if ! command -v cargo-zigbuild >/dev/null; then
        cargo install --locked cargo-zigbuild
    fi
fi

target_dir="${CARGO_TARGET_DIR:-$repo/target}"
out_dir="${RELEASE_OUT_DIR:-$target_dir/release-out}"

for tool in rustup cargo cargo-zigbuild file; do
    if ! command -v "$tool" >/dev/null; then
        echo "error: $tool is not installed" >&2
        exit 1
    fi
done
# cargo-zigbuild finds zig on PATH, or the Python package `ziglang` (pip install ziglang).
if ! command -v zig >/dev/null && ! python3 -m ziglang version >/dev/null 2>&1; then
    echo "error: zig is not installed (pip install ziglang)" >&2
    exit 1
fi

# 1. The web UI.
if [[ "${SKIP_WEB_BUILD:-0}" != "1" ]]; then
    if ! command -v bun >/dev/null; then
        echo "error: bun is not installed (see web/README.md)" >&2
        exit 1
    fi
    (cd web && bun install --frozen-lockfile && bun run build)
fi
index="web/dist/index.html"
if [[ ! -f "$index" ]]; then
    echo "error: $index does not exist; build the web UI first" >&2
    exit 1
fi
# The name of the main script has a content hash (Vite). Only the built UI has this text,
# so the check below cannot pass with the placeholder page.
ui_marker="$(grep -oE '/assets/[A-Za-z0-9._-]+\.js' "$index" | head -n 1 || true)"
if [[ -z "$ui_marker" ]]; then
    echo "error: $index has no /assets/*.js script" >&2
    exit 1
fi
echo "web UI marker: $ui_marker"

mkdir -p "$out_dir"
for target in "$@"; do
    case "$target" in
        x86_64-unknown-linux-musl) arch=x86_64 file_arch='x86-64' ;;
        aarch64-unknown-linux-musl) arch=aarch64 file_arch='ARM aarch64' ;;
        *)
            echo "error: unsupported target $target" >&2
            exit 2
            ;;
    esac
    rustup target add "$target" >/dev/null
    # build.rs of the web crate picks web/dist when web/dist/index.html exists.
    cargo zigbuild --release --locked --target "$target" -p rusthole
    bin="$target_dir/$target/release/rusthole"

    # 2. Static and the right CPU type.
    info="$(file -b "$bin")"
    echo "$target: $info"
    if ! grep -Eq 'statically linked|static-pie linked' <<<"$info" || grep -q 'dynamically linked' <<<"$info"; then
        echo "error: $bin is not a static binary" >&2
        exit 1
    fi
    if ! grep -qF "$file_arch" <<<"$info"; then
        echo "error: $bin is not a $file_arch binary" >&2
        exit 1
    fi

    # 3. The built UI is inside the binary.
    if ! grep -aqF "$ui_marker" "$bin"; then
        echo "error: $bin does not hold the built web UI ($ui_marker)" >&2
        exit 1
    fi

    # 4. The named copy for the release, and its size.
    dest="$out_dir/rusthole-$arch-linux-musl"
    cp "$bin" "$dest.tmp"
    chmod 0755 "$dest.tmp"
    mv -f "$dest.tmp" "$dest"
    size="$(stat -c %s "$dest")"
    echo "$target: $dest: $size bytes ($((size / 1024 / 1024)) MiB)"
    if [[ "$(uname -m)" == "$arch" ]]; then
        echo "$target: $("$dest" --version)"
    fi
done
