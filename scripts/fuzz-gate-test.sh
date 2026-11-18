#!/usr/bin/env bash
# Test of the target list gate, the parallel runs and cmin of scripts/fuzz.sh, with a fake
# cargo and fake fuzz binaries. No build, no fuzzing.
#
# Use:
#   bash scripts/fuzz-gate-test.sh
#
# Cases for "all": `cargo fuzz list` fails, gives no names, or gives too few names: fuzz.sh
# must fail and run no target. A full list: fuzz.sh runs each target, with 1 or 4 jobs. One
# target fails: fuzz.sh runs all targets and then fails. A failed build or a bad FUZZ_JOBS:
# no target runs. Cases for "cmin": each corpus is minimized; a failed merge keeps that
# corpus, the other merges go on, and cmin fails.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/rusthole-fuzz-gate.XXXXXX")"
trap 'rm -rf "$work"' EXIT

mapfile -t all_names < <(sed -n 's/^name = "\(.*\)"$/\1/p' "$repo/fuzz/Cargo.toml" | tail -n +2)
[[ ${#all_names[@]} -ge 3 ]] || {
    echo "FAIL: fewer than 3 target names in fuzz/Cargo.toml" >&2
    exit 1
}

mkdir -p "$work/bin" "$work/fuzzbin"
# The fake cargo: FAKE_LIST is the mode of `cargo fuzz list`. `cargo fuzz build` writes one
# fake fuzz binary for each name to $FUZZ_BIN_DIR (FAKE_BUILD=fail makes it fail).
cat >"$work/bin/cargo" <<'CARGO'
#!/usr/bin/env bash
shift # +toolchain
case "$1 $2" in
    "fuzz list")
        case "$FAKE_LIST" in
            fail) exit 1 ;;
            empty) exit 0 ;;
            short) printf '%s\n' $FAKE_NAMES | tail -n +2 ;;
            full) printf '%s\n' $FAKE_NAMES ;;
        esac
        ;;
    "fuzz build")
        [[ "${FAKE_BUILD:-}" != fail ]] || exit 1
        for n in $FAKE_NAMES; do
            cp "$FAKE_BIN" "$FUZZ_BIN_DIR/$n"
            chmod +x "$FUZZ_BIN_DIR/$n"
        done
        ;;
    *) exit 3 ;;
esac
CARGO
chmod +x "$work/bin/cargo"

# The fake fuzz binary. When it fuzzes, it adds its name to $FAKE_RUNS; FAKE_CRASH is a
# target that fails. With -merge=1 it adds its name to $FAKE_MERGES and copies the first
# input of the old folder to the new folder; FAKE_MERGE_FAIL is a target whose merge fails.
cat >"$work/fake-fuzz-bin" <<'BIN'
#!/usr/bin/env bash
name="$(basename "$0")"
dirs=()
merge=0
for a in "$@"; do
    case "$a" in
        -merge=1) merge=1 ;;
        -*) ;;
        *) dirs+=("$a") ;;
    esac
done
if [[ $merge -eq 1 ]]; then
    echo "$name" >>"$FAKE_MERGES"
    [[ "$name" != "${FAKE_MERGE_FAIL:-}" ]] || exit 1
    first="$(find "${dirs[1]}" -type f | sort | head -n 1)"
    cp "$first" "${dirs[0]}/"
    exit 0
fi
echo "$name" >>"$FAKE_RUNS"
[[ "$name" != "${FAKE_CRASH:-}" ]]
BIN

export PATH="$work/bin:$PATH" FUZZ_TOOLCHAIN=nightly-test FAKE_NAMES="${all_names[*]}"
export FUZZ_HOST=x86_64-unknown-linux-gnu
export FAKE_RUNS="$work/runs" FAKE_MERGES="$work/merges" FAKE_BIN="$work/fake-fuzz-bin"
export FUZZ_BIN_DIR="$work/fuzzbin" FUZZ_CORPUS_DIR="$work/corpus"
export FUZZ_ARTIFACT_DIR="$work/artifacts"

fails=0
fail() {
    echo "FAIL: $*" >&2
    fails=$((fails + 1))
}

# check NAME WANT_CODE WANT_CALLS [VAR=VALUE...]: runs fuzz.sh "${MODE[@]}". WANT_CALLS is the
# number of fake binary calls (runs and merges).
check() {
    local name="$1" want_code="$2" want_calls="$3"
    shift 3
    rm -f "$FAKE_RUNS" "$FAKE_MERGES"
    touch "$FAKE_RUNS" "$FAKE_MERGES"
    local code=0
    env "$@" bash "$repo/scripts/fuzz.sh" "${MODE[@]}" >"$work/out" 2>&1 || code=$?
    local calls
    calls="$(cat "$FAKE_RUNS" "$FAKE_MERGES" | wc -l)"
    if [[ ( "$want_code" == 0 && "$code" != 0 ) || ( "$want_code" != 0 && "$code" == 0 ) || "$calls" -ne "$want_calls" ]]; then
        fail "$name: exit code $code, $calls calls (want code $want_code, $want_calls calls)"
        sed 's/^/    /' "$work/out" >&2
    else
        echo "PASS: $name"
    fi
}

n=${#all_names[@]}
MODE=(all 1)
check "cargo fuzz list fails" 1 0 FAKE_LIST=fail
check "cargo fuzz list gives no names" 1 0 FAKE_LIST=empty
check "cargo fuzz list gives too few names" 1 0 FAKE_LIST=short
check "a full list runs each target" 0 "$n" FAKE_LIST=full
check "a failed target fails the job after all runs" 1 "$n" FAKE_LIST=full FAKE_CRASH="${all_names[0]}"
check "a failed build runs no target" 1 0 FAKE_LIST=full FAKE_BUILD=fail
check "4 jobs run each target" 0 "$n" FAKE_LIST=full FUZZ_JOBS=4
check "4 jobs: a failed target fails the job after all runs" 1 "$n" FAKE_LIST=full FUZZ_JOBS=4 FAKE_CRASH="${all_names[2]}"
check "a bad FUZZ_JOBS value runs no target" 1 0 FAKE_LIST=full FUZZ_JOBS=0

# cmin: each target has 3 inputs. A merge keeps 1 of them. A failed merge keeps all 3.
fill_corpus() {
    rm -rf "$FUZZ_CORPUS_DIR"
    local t i
    for t in "${all_names[@]}"; do
        mkdir -p "$FUZZ_CORPUS_DIR/$t"
        for i in 1 2 3; do
            echo "$t $i" >"$FUZZ_CORPUS_DIR/$t/input-$i"
        done
    done
}
count_inputs() {
    find "$FUZZ_CORPUS_DIR/$1" -type f | wc -l
}

MODE=(cmin)
fill_corpus
check "cmin merges each target" 0 "$n" FAKE_LIST=full FUZZ_JOBS=4
for t in "${all_names[@]}"; do
    if [[ "$(count_inputs "$t")" -ne 1 ]]; then
        fail "cmin left $(count_inputs "$t") inputs for $t (want 1)"
    fi
done
if find "$FUZZ_CORPUS_DIR" -maxdepth 1 -name '.cmin-*' | grep -q .; then
    fail "cmin left a temp folder"
fi

fill_corpus
check "a failed merge fails cmin after all merges" 1 "$n" FAKE_LIST=full FAKE_MERGE_FAIL="${all_names[1]}"
if [[ "$(count_inputs "${all_names[1]}")" -ne 3 ]]; then
    fail "a failed merge changed the corpus of ${all_names[1]}"
fi
if [[ "$(count_inputs "${all_names[0]}")" -ne 1 ]]; then
    fail "a failed merge of another target stopped the merge of ${all_names[0]}"
fi

fill_corpus
check "cmin: a failed list merges nothing" 1 0 FAKE_LIST=fail
if [[ "$(count_inputs "${all_names[0]}")" -ne 3 ]]; then
    fail "a failed list changed a corpus"
fi

if [[ $fails -ne 0 ]]; then
    exit 1
fi
echo "all fuzz gate tests passed"
