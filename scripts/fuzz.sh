#!/usr/bin/env bash
# Run the fuzz targets (CI job "fuzz" and `scripts/linux.sh fuzz`).
#
# Use:
#   FUZZ_TOOLCHAIN=nightly-2026-11-17 bash scripts/fuzz.sh all SECONDS
#   FUZZ_TOOLCHAIN=nightly-2026-11-17 bash scripts/fuzz.sh one TARGET SECONDS
#
# FUZZ_TOOLCHAIN is the rustup toolchain (a nightly). FUZZ_TARGET_DIR (optional) is the
# cargo target directory of the fuzz build.
#
# Each run reads two corpus folders: fuzz/corpus/<target> (not in git; new inputs go here)
# and fuzz/seeds/<target> (in git; libFuzzer does not write to it). libFuzzer writes crash
# inputs to fuzz/artifacts/<target>/.
#
# "all" gets the target list from `cargo fuzz list`. It stops with an error when the command
# fails, or when the list does not have one name for each [[bin]] in fuzz/Cargo.toml. It runs
# each target, also after a failure, and gives exit code 1 when one or more targets failed.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain="${FUZZ_TOOLCHAIN:?set FUZZ_TOOLCHAIN to the pinned nightly}"
cargo_args=()
if [[ -n "${FUZZ_TARGET_DIR:-}" ]]; then
    cargo_args+=(--target-dir "$FUZZ_TARGET_DIR")
fi

cd "$repo/fuzz"

# The libFuzzer options of one target.
fuzz_opts() {
    local target="$1" seconds="$2"
    local opts=(-max_total_time="$seconds" -rss_limit_mb=2048)
    case "$target" in
        # Rules and names: the deep paths need inputs with many lines (the seeds have
        # 0.3 to 1 KiB). Without a limit, libFuzzer takes the largest seed as the limit.
        regex_rules | policy_check) opts+=(-max_len=4096) ;;
    esac
    printf '%s\n' "${opts[@]}"
}

run_one() {
    local target="$1" seconds="$2"
    local corpus="corpus/$target" seeds="seeds/$target"
    mkdir -p "$corpus"
    local dirs=("$corpus")
    if [[ -d "$seeds" ]]; then
        dirs+=("$seeds")
    fi
    local opts
    mapfile -t opts < <(fuzz_opts "$target" "$seconds")
    echo "== fuzz $target for $seconds s (corpus: ${dirs[*]})"
    cargo "+$toolchain" fuzz run "${cargo_args[@]}" "$target" "${dirs[@]}" -- "${opts[@]}"
}

# Prints the target names. Fails when `cargo fuzz list` fails or gives a wrong count.
list_targets() {
    local text
    if ! text="$(cargo "+$toolchain" fuzz list)"; then
        echo "error: cargo fuzz list failed" >&2
        return 1
    fi
    local names=()
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] && names+=("$line")
    done <<<"$text"
    local want
    want="$(grep -c '^\[\[bin\]\]' Cargo.toml || true)"
    if [[ "$want" -lt 1 || "${#names[@]}" -ne "$want" ]]; then
        echo "error: cargo fuzz list gave ${#names[@]} targets; fuzz/Cargo.toml has $want" >&2
        return 1
    fi
    printf '%s\n' "${names[@]}"
}

case "${1:-}" in
    all)
        seconds="${2:?seconds per target}"
        targets_text="$(list_targets)"
        mapfile -t targets <<<"$targets_text"
        failed=()
        for t in "${targets[@]}"; do
            if ! run_one "$t" "$seconds"; then
                failed+=("$t")
            fi
        done
        if [[ ${#failed[@]} -gt 0 ]]; then
            echo "error: these fuzz targets failed: ${failed[*]} (inputs in fuzz/artifacts)" >&2
            exit 1
        fi
        echo "all ${#targets[@]} fuzz targets passed"
        ;;
    one)
        run_one "${2:?fuzz target name}" "${3:?seconds}"
        ;;
    *)
        echo "usage: $0 all SECONDS | $0 one TARGET SECONDS" >&2
        exit 2
        ;;
esac
