#!/usr/bin/env bash
# Run the fuzz targets (CI jobs "fuzz" and "fuzz-nightly", and `scripts/linux.sh fuzz`).
#
# Use:
#   FUZZ_TOOLCHAIN=nightly-2026-11-17 bash scripts/fuzz.sh all SECONDS
#   FUZZ_TOOLCHAIN=nightly-2026-11-17 bash scripts/fuzz.sh one TARGET SECONDS
#   FUZZ_TOOLCHAIN=nightly-2026-11-17 bash scripts/fuzz.sh cmin
#
# Modes:
#   all   Build every target with one `cargo fuzz build`, then run each built binary for
#         SECONDS. It runs each target, also after a failure, and gives exit code 1 when one
#         or more targets failed.
#   one   Run one target with `cargo fuzz run` (it builds the target first).
#   cmin  Build every target, then minimize each corpus folder with libFuzzer -merge=1: keep
#         only the inputs that add coverage. A failed merge keeps the old folder and gives
#         exit code 1.
#
# Environment:
#   FUZZ_TOOLCHAIN    The rustup toolchain (a nightly). Necessary.
#   FUZZ_TARGET_DIR   The cargo target directory of the fuzz build (default fuzz/target).
#   FUZZ_JOBS         The number of targets that "all" and "cmin" run at the same time
#                     (default 1).
#   FUZZ_CORPUS_DIR   The corpus folder (default fuzz/corpus). New inputs go to
#                     <corpus>/<target>. The nightly CI job stores it on the branch
#                     "fuzz-corpus".
#   FUZZ_ARTIFACT_DIR The folder for crash inputs (default fuzz/artifacts).
#   FUZZ_HOST         The target triple (default: the host of FUZZ_TOOLCHAIN).
#   FUZZ_BIN_DIR      The folder of the built binaries (default: <target dir>/<host>/release).
#
# Each run also reads fuzz/seeds/<target> (in git). libFuzzer does not write to it.
#
# "all" and "cmin" get the target list from `cargo fuzz list`. They stop with an error when
# the command fails, or when the list does not have one name for each [[bin]] in
# fuzz/Cargo.toml.
#
# "all" runs the binaries directly, not with `cargo fuzz run`: each `cargo fuzz run` starts
# cargo again, and the cargo lock lets only one of them work at a time.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain="${FUZZ_TOOLCHAIN:?set FUZZ_TOOLCHAIN to the pinned nightly}"
# The target triple: the host of the toolchain. cargo-fuzz takes its own host as the
# default target, and a prebuilt cargo-fuzz can be a musl build. AddressSanitizer does not
# work with the static libc of musl.
host="${FUZZ_HOST:-$(rustc "+$toolchain" -vV | sed -n 's/^host: //p')}"
cargo_args=(--target "$host")
if [[ -n "${FUZZ_TARGET_DIR:-}" ]]; then
    cargo_args+=(--target-dir "$FUZZ_TARGET_DIR")
fi

cd "$repo/fuzz"
corpus_root="$(mkdir -p "${FUZZ_CORPUS_DIR:-corpus}" && cd "${FUZZ_CORPUS_DIR:-corpus}" && pwd)"
artifact_root="$(mkdir -p "${FUZZ_ARTIFACT_DIR:-artifacts}" && cd "${FUZZ_ARTIFACT_DIR:-artifacts}" && pwd)"

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

# The corpus folders of one target: the corpus (made if it is not there) and the seeds.
corpus_dirs() {
    local target="$1"
    mkdir -p "$corpus_root/$target"
    printf '%s\n' "$corpus_root/$target"
    if [[ -d "seeds/$target" ]]; then
        printf '%s\n' "seeds/$target"
    fi
}

# "one": cargo builds the target, then runs it.
run_one() {
    local target="$1" seconds="$2"
    local dirs opts
    mapfile -t dirs < <(corpus_dirs "$target")
    mapfile -t opts < <(fuzz_opts "$target" "$seconds")
    mkdir -p "$artifact_root/$target"
    echo "== fuzz $target for $seconds s (corpus: ${dirs[*]})"
    cargo "+$toolchain" fuzz run "${cargo_args[@]}" "$target" "${dirs[@]}" -- \
        -artifact_prefix="$artifact_root/$target/" "${opts[@]}"
}

# The folder of the binaries that `cargo fuzz build` made.
bin_dir() {
    if [[ -n "${FUZZ_BIN_DIR:-}" ]]; then
        printf '%s\n' "$FUZZ_BIN_DIR"
        return
    fi
    printf '%s\n' "${FUZZ_TARGET_DIR:-$repo/fuzz/target}/$host/release"
}

# "all": run one built binary.
run_bin() {
    local target="$1" seconds="$2"
    local dirs opts
    mapfile -t dirs < <(corpus_dirs "$target")
    mapfile -t opts < <(fuzz_opts "$target" "$seconds")
    mkdir -p "$artifact_root/$target"
    echo "== fuzz $target for $seconds s (corpus: ${dirs[*]})"
    "$bins/$target" -artifact_prefix="$artifact_root/$target/" "${opts[@]}" "${dirs[@]}"
}

# "cmin": merge the corpus of one target into a new folder, then replace the old folder.
# The seeds are in git, so they do not go into the merge.
cmin_bin() {
    local target="$1"
    local old="$corpus_root/$target" new="$corpus_root/.cmin-$target"
    mkdir -p "$old"
    rm -rf "$new"
    mkdir -p "$new"
    local before after
    before="$(find "$old" -type f | wc -l)"
    echo "== cmin $target ($before inputs)"
    if [[ "$before" -eq 0 ]]; then
        rmdir "$new"
        return 0
    fi
    if ! "$bins/$target" -merge=1 -rss_limit_mb=2048 -artifact_prefix="$artifact_root/$target/" \
        "$new" "$old"; then
        rm -rf "$new"
        echo "error: the merge of $target failed; the old corpus stays" >&2
        return 1
    fi
    rm -rf "$old"
    mv "$new" "$old"
    after="$(find "$old" -type f | wc -l)"
    echo "cmin $target: $before -> $after inputs"
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

# Gets the target list, checks FUZZ_JOBS and builds all targets. Sets targets, jobs, bins.
prepare() {
    local targets_text
    targets_text="$(list_targets)"
    mapfile -t targets <<<"$targets_text"
    jobs="${FUZZ_JOBS:-1}"
    if ! [[ "$jobs" =~ ^[1-9][0-9]*$ ]]; then
        echo "error: FUZZ_JOBS must be a positive number, not '$jobs'" >&2
        exit 2
    fi
    # One build for all targets: cargo builds them in parallel.
    echo "== build all ${#targets[@]} fuzz targets"
    cargo "+$toolchain" fuzz build "${cargo_args[@]}"
    bins="$(bin_dir)"
}

# Runs "$1 <target> $2..." for each target, at most $jobs at the same time, and prints each
# log in the list order. Sets failed to the targets that failed.
for_each_target() {
    local fn="$1"
    shift
    logs="$(mktemp -d "${TMPDIR:-/tmp}/rusthole-fuzz.XXXXXX")"
    trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$logs"' EXIT
    # Each task writes its exit code to "$logs/<target>.rc". The loop has one step for each
    # target, and each task ends (a run stops after its -max_total_time), so it is bounded.
    local running=0 t
    for t in "${targets[@]}"; do
        if [[ "$running" -ge "$jobs" ]]; then
            wait -n || true
            running=$((running - 1))
        fi
        (
            if "$fn" "$t" "$@" >"$logs/$t.log" 2>&1; then
                echo 0 >"$logs/$t.rc"
            else
                echo 1 >"$logs/$t.rc"
            fi
        ) &
        running=$((running + 1))
    done
    wait || true
    failed=()
    for t in "${targets[@]}"; do
        if [[ "$(cat "$logs/$t.rc" 2>/dev/null || echo 1)" == 0 ]]; then
            tail -n 5 "$logs/$t.log"
        else
            cat "$logs/$t.log" 2>/dev/null || true
            failed+=("$t")
        fi
    done
}

case "${1:-}" in
    all)
        seconds="${2:?seconds per target}"
        prepare
        for_each_target run_bin "$seconds"
        if [[ ${#failed[@]} -gt 0 ]]; then
            echo "error: these fuzz targets failed: ${failed[*]} (inputs in $artifact_root)" >&2
            exit 1
        fi
        echo "all ${#targets[@]} fuzz targets passed"
        ;;
    one)
        run_one "${2:?fuzz target name}" "${3:?seconds}"
        ;;
    cmin)
        prepare
        for_each_target cmin_bin
        if [[ ${#failed[@]} -gt 0 ]]; then
            echo "error: the corpus merge failed for: ${failed[*]}" >&2
            exit 1
        fi
        echo "the corpus of all ${#targets[@]} fuzz targets is minimized"
        ;;
    *)
        echo "usage: $0 all SECONDS | $0 one TARGET SECONDS | $0 cmin" >&2
        exit 2
        ;;
esac
