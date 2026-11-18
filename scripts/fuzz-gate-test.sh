#!/usr/bin/env bash
# Test of the target list gate in scripts/fuzz.sh, with a fake cargo. No build, no fuzzing.
#
# Use:
#   bash scripts/fuzz-gate-test.sh
#
# Cases: `cargo fuzz list` fails, gives no names, or gives too few names: fuzz.sh must fail
# and run no target. A full list: fuzz.sh runs each target. One target fails: fuzz.sh runs
# all targets and then fails.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/rusthole-fuzz-gate.XXXXXX")"
trap 'rm -rf "$work"' EXIT

mapfile -t all_names < <(sed -n 's/^name = "\(.*\)"$/\1/p' "$repo/fuzz/Cargo.toml" | tail -n +2)
[[ ${#all_names[@]} -ge 1 ]] || {
    echo "FAIL: no target names in fuzz/Cargo.toml" >&2
    exit 1
}

mkdir -p "$work/bin"
# The fake cargo: FAKE_LIST is the mode of `cargo fuzz list`; each `cargo fuzz run` call adds
# the target name to $work/runs. FAKE_CRASH is a target that fails.
cat >"$work/bin/cargo" <<'EOF'
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
    "fuzz run")
        echo "$3" >>"$FAKE_RUNS"
        [[ "$3" != "${FAKE_CRASH:-}" ]]
        ;;
    *) exit 3 ;;
esac
EOF
chmod +x "$work/bin/cargo"

export PATH="$work/bin:$PATH" FUZZ_TOOLCHAIN=nightly-test FAKE_NAMES="${all_names[*]}"
export FAKE_RUNS="$work/runs"

fails=0
check() {
    local name="$1" want_code="$2" want_runs="$3"
    shift 3
    rm -f "$FAKE_RUNS"
    touch "$FAKE_RUNS"
    local code=0
    env "$@" bash "$repo/scripts/fuzz.sh" all 1 >"$work/out" 2>&1 || code=$?
    local runs
    runs="$(wc -l <"$FAKE_RUNS")"
    if [[ ( "$want_code" == 0 && "$code" != 0 ) || ( "$want_code" != 0 && "$code" == 0 ) || "$runs" -ne "$want_runs" ]]; then
        echo "FAIL: $name: exit code $code, $runs runs (want code $want_code, $want_runs runs)" >&2
        sed 's/^/    /' "$work/out" >&2
        fails=$((fails + 1))
    else
        echo "PASS: $name"
    fi
}

n=${#all_names[@]}
check "cargo fuzz list fails" 1 0 FAKE_LIST=fail
check "cargo fuzz list gives no names" 1 0 FAKE_LIST=empty
check "cargo fuzz list gives too few names" 1 0 FAKE_LIST=short
check "a full list runs each target" 0 "$n" FAKE_LIST=full
check "a failed target fails the job after all runs" 1 "$n" FAKE_LIST=full FAKE_CRASH="${all_names[0]}"

if [[ $fails -ne 0 ]]; then
    exit 1
fi
echo "all fuzz gate tests passed"
