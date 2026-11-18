#!/usr/bin/env bash
# Run the aarch64 binary on an x86_64 host with qemu-user (CI jobs "smoke-aarch64").
#
# Use:
#   bash scripts/aarch64-check.sh path/to/rusthole-aarch64
#
# Steps:
#   1. `file` must say that the binary is a static ARM aarch64 binary.
#   2. `--version` must run.
#   3. `check-config` must accept the packaged config (packaging/rusthole.toml).
#   4. The smoke test (scripts/smoke-test.sh) runs on the binary.
#
# The script calls qemu-aarch64-static (or qemu-aarch64) directly through a small wrapper,
# so it does not need a binfmt_misc entry. QEMU sets another qemu binary. On an aarch64
# host, the script runs the binary directly. On Ubuntu: sudo apt-get install qemu-user-static.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 path/to/rusthole-aarch64" >&2
    exit 2
fi
bin="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

info="$(file -b "$bin")"
echo "file: $info"
if [[ "$info" != *"ARM aarch64"* ]]; then
    echo "FAIL: $bin is not an aarch64 binary" >&2
    exit 1
fi
if [[ "$info" != *"statically linked"* && "$info" != *"static-pie linked"* ]]; then
    echo "FAIL: $bin is not static" >&2
    exit 1
fi
chmod +x "$bin"

work="$(mktemp -d "${TMPDIR:-/tmp}/rusthole-aarch64.XXXXXX")"
trap 'rm -rf "$work"' EXIT
run="$bin"
if [[ "$(uname -m)" != "aarch64" ]]; then
    qemu="${QEMU:-}"
    if [[ -z "$qemu" ]]; then
        qemu="$(command -v qemu-aarch64-static || command -v qemu-aarch64 || true)"
    fi
    if [[ -z "$qemu" || ! -x "$qemu" ]]; then
        echo "FAIL: no qemu-aarch64; install qemu-user-static" >&2
        exit 1
    fi
    # A wrapper with exec: the smoke test sends SIGTERM to this process, which is then qemu.
    # qemu gives the signal to the binary.
    run="$work/rusthole"
    printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$qemu" "$bin" >"$run"
    chmod +x "$run"
    echo "qemu: $qemu"
fi

version="$("$run" --version)"
echo "PASS: --version: $version"
"$run" check-config -c "$repo/packaging/rusthole.toml"
echo "PASS: check-config of packaging/rusthole.toml"
bash "$here/smoke-test.sh" "$run"
