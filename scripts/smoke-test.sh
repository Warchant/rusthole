#!/usr/bin/env bash
# End-to-end smoke test of a rusthole binary on Linux (CI job "smoke" and local runs in WSL).
#
# Use:
#   bash scripts/smoke-test.sh path/to/rusthole
#   SMOKE_REAL_DOH=1 bash scripts/smoke-test.sh path/to/rusthole   (also a real DoH upstream;
#                                                              needs the internet)
#
# The test binds loopback addresses only. It needs bash, python3, dig and curl.
#
# Steps:
#   1. Set the admin password with `rusthole passwd` (two lines on stdin).
#   2. Start `rusthole run` with DNS on 127.0.0.1:5353, the admin UI on 127.0.0.1:8443, DoH
#      on 127.0.0.1:8053 (tls.mode local-ca), a block list from a local HTTP server, and a
#      fake upstream on 127.0.0.1:5354 that answers 192.0.2.1 for each A query.
#   3. dig: an allowed name (192.0.2.1), a blocked name (0.0.0.0), a local record.
#   4. The admin UI: GET / gives the UI; GET /api/v1/stats/summary without a login gives
#      401; a login gives a session; the summary counts the three queries of step 3.
#   5. DoH: RFC 8484 POST queries (blocked, local, allowed), and `curl --doh-url`. curl
#      checks the certificate with the local CA (no -k).
#   6. SIGTERM: rusthole stops with exit code 0.
#   Also: a fake systemd notification socket (NOTIFY_SOCKET) gets READY=1 after the start
#   and STOPPING=1 at the stop (the unit has Type=notify).
#
# Environment: SMOKE_DNS_PORT, SMOKE_ADMIN_PORT, SMOKE_DOH_PORT, SMOKE_UPSTREAM_PORT,
# SMOKE_LIST_PORT change the ports. SMOKE_KEEP=1 keeps the work folder.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 path/to/rusthole" >&2
    exit 2
fi
bin="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper="$here/smoke-helper.py"

dns_port="${SMOKE_DNS_PORT:-5353}"
admin_port="${SMOKE_ADMIN_PORT:-8443}"
doh_port="${SMOKE_DOH_PORT:-8053}"
upstream_port="${SMOKE_UPSTREAM_PORT:-5354}"
list_port="${SMOKE_LIST_PORT:-8099}"
password="smoke-test-password-$$"

for tool in python3 dig curl; do
    command -v "$tool" >/dev/null || {
        echo "error: $tool is not installed" >&2
        exit 1
    }
done
[[ -x "$bin" ]] || chmod +x "$bin"

# A RAM file system when there is one: modes work there, and fsync is fast.
tmp_base="${TMPDIR:-/tmp}"
if [[ -d /dev/shm && -w /dev/shm ]]; then
    tmp_base=/dev/shm
fi
work="$(mktemp -d "$tmp_base/rusthole-smoke.XXXXXX")"
pids=()
rusthole_pid=""

cleanup() {
    local code=$?
    if [[ -n "$rusthole_pid" ]] && kill -0 "$rusthole_pid" 2>/dev/null; then
        kill -KILL "$rusthole_pid" 2>/dev/null || true
    fi
    for p in "${pids[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    if [[ $code -ne 0 && -f "$work/rusthole.log" ]]; then
        echo "---- rusthole log (last 60 lines) ----" >&2
        tail -n 60 "$work/rusthole.log" >&2
    fi
    if [[ "${SMOKE_KEEP:-0}" == "1" ]]; then
        echo "work folder kept: $work" >&2
    else
        rm -rf "$work"
    fi
    exit "$code"
}
trap cleanup EXIT INT TERM

pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# Waits until a command succeeds: at most $1 tries, 0.5 s apart.
retry() {
    local tries="$1"
    shift
    local i
    for ((i = 0; i < tries; i++)); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

q() { dig +short +time=2 +tries=1 @127.0.0.1 -p "$dns_port" "$@" A; }

echo "binary: $("$bin" --version)"
echo "work folder: $work"

# --- Fixtures: a block list, a fake upstream, a config. ---------------------------------
mkdir -p "$work/www" "$work/data"
cat >"$work/www/block.txt" <<'EOF'
# Synthetic block list for the smoke test.
0.0.0.0 ads.smoke.example
blocked.smoke.example
EOF
python3 -m http.server --bind 127.0.0.1 --directory "$work/www" "$list_port" \
    >"$work/http.log" 2>&1 &
pids+=($!)
python3 "$helper" serve "$upstream_port" >"$work/upstream.log" 2>&1 &
pids+=($!)
retry 20 curl -fsS "http://127.0.0.1:$list_port/block.txt" || fail "the list server did not start"

config="$work/rusthole.toml"
cat >"$config" <<EOF
# Smoke test config. Loopback only.
config_version = 1

[server]
dns_listen = ["127.0.0.1"]
dns_port = $dns_port
data_dir = "$work/data"

[server.doh]
enabled = true
listen = ["127.0.0.1"]
port = $doh_port

[server.admin]
enabled = true
listen = ["127.0.0.1"]
port = $admin_port

[upstreams]
timeout_ms = 2000

[[upstreams.servers]]
url = "udp://127.0.0.1:$upstream_port"

[stats]
flush_interval_seconds = 0

[[lists.adlists]]
id = 1
url = "http://127.0.0.1:$list_port/block.txt"
kind = "block"

[[local_dns.records]]
name = "nas.lan"
type = "A"
value = "192.0.2.10"

[[local_dns.records]]
name = "listserver.lan"
type = "A"
value = "127.0.0.1"

[tls]
mode = "local-ca"
names = ["rusthole.lan"]
EOF
"$bin" check-config -c "$config" || fail "check-config"
pass "check-config"

# --- 1. The admin password, from stdin (no terminal in CI). ------------------------------
printf '%s\n%s\n' "$password" "$password" | "$bin" passwd -c "$config" >"$work/passwd.log" 2>&1 ||
    fail "rusthole passwd: $(cat "$work/passwd.log")"
grep -qF "password_hash = \"\$argon2id\$" "$config" || fail "the config has no Argon2id hash"
pass "rusthole passwd (stdin)"

# --- 2. Start the server, with a fake systemd notification socket (Type=notify). ----------
notify_sock="$work/notify.sock"
notify_log="$work/notify.log"
: >"$notify_log"
python3 "$helper" notify "$notify_sock" "$notify_log" >"$work/notify-listener.log" 2>&1 &
pids+=($!)
retry 20 test -S "$notify_sock" || fail "the notification socket did not start"
NOTIFY_SOCKET="$notify_sock" RUSTHOLE_LOG=info "$bin" run -c "$config" >"$work/rusthole.log" 2>&1 &
rusthole_pid=$!
retry 60 grep -q "rusthole is running" "$work/rusthole.log" || fail "rusthole did not start"
pass "rusthole run (pid $rusthole_pid)"
retry 20 grep -qx "READY=1" "$notify_log" || fail "rusthole sent no READY=1 to NOTIFY_SOCKET"
grep -q "STOPPING=1" "$notify_log" && fail "rusthole sent STOPPING=1 before the stop"
pass "systemd notification: READY=1 ($(grep '^STATUS=' "$notify_log" || true))"

# The list download runs after the start. Wait until the blocked name is blocked.
blocked_now() { [[ "$(q blocked.smoke.example)" == "0.0.0.0" ]]; }
retry 60 blocked_now || fail "the block list was not loaded"

# --- 4a. The admin API without a login. -----------------------------------------------------
admin="https://127.0.0.1:$admin_port"
ca="$work/data/tls/ca.pem"
[[ -f "$ca" ]] || fail "no local CA at $ca"
code="$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$ca" "$admin/api/v1/stats/summary")"
[[ "$code" == "401" ]] || fail "GET /api/v1/stats/summary without a login gave $code, not 401"
pass "stats summary without a login: 401"

# --- 4b. Log in, keep the cookie and the CSRF token. ------------------------------------------
jar="$work/cookies.txt"
login_body="$(printf '{"password":"%s"}' "$password")"
login="$(curl -sS --fail-with-body --cacert "$ca" -c "$jar" -H 'Content-Type: application/json' \
    --data-binary "$login_body" "$admin/api/v1/auth/login")" || fail "login: $login"
csrf="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])' <<<"$login")"
[[ -n "$csrf" ]] || fail "the login gave no CSRF token"
grep -q '__Host-rusthole_session' "$jar" || fail "the login set no session cookie"
pass "login (session cookie and CSRF token)"

summary() {
    curl -sS --fail-with-body --cacert "$ca" -b "$jar" -H "X-CSRF-Token: $csrf" \
        "$admin/api/v1/stats/summary"
}
field() { python3 -c "import json,sys; print(json.load(sys.stdin)[\"$1\"])"; }
before="$(summary)" || fail "GET /api/v1/stats/summary: $before"
pass "stats summary with the session: 200"
# The statistics get the queries a short time after the answer. Wait until the queries of
# the list wait above are all counted, so that they do not go into the deltas below.
for ((i = 0; i < 20; i++)); do
    sleep 1
    now="$(summary)" || fail "GET /api/v1/stats/summary"
    if [[ "$(field queries <<<"$now")" == "$(field queries <<<"$before")" ]]; then
        break
    fi
    before="$now"
done

# --- 3. Plain DNS. --------------------------------------------------------------------------
[[ "$(q allowed.smoke.example)" == "192.0.2.1" ]] || fail "allowed name: not 192.0.2.1"
pass "dig allowed.smoke.example = 192.0.2.1 (upstream)"
[[ "$(q ads.smoke.example)" == "0.0.0.0" ]] || fail "blocked name: not 0.0.0.0"
pass "dig ads.smoke.example = 0.0.0.0 (blocked)"
[[ "$(q nas.lan)" == "192.0.2.10" ]] || fail "local record: not 192.0.2.10"
pass "dig nas.lan = 192.0.2.10 (local record)"

# --- 4c. The statistics count the three queries. ------------------------------------------
delta() {
    local now="$1" name="$2"
    echo $(($(field "$name" <<<"$now") - $(field "$name" <<<"$before")))
}
counted() {
    local now
    now="$(summary)" || return 1
    [[ "$(delta "$now" queries)" -ge 3 ]]
}
retry 40 counted || fail "the statistics did not count the queries: before $before, now $(summary)"
after="$(summary)"
[[ "$(delta "$after" queries)" -eq 3 ]] || fail "queries: +$(delta "$after" queries), not +3"
[[ "$(delta "$after" blocked)" -eq 1 ]] || fail "blocked: +$(delta "$after" blocked), not +1"
[[ "$(delta "$after" local)" -eq 1 ]] || fail "local: +$(delta "$after" local), not +1"
upstream=$(($(delta "$after" forwarded) + $(delta "$after" cached)))
[[ "$upstream" -eq 1 ]] || fail "forwarded + cached: +$upstream, not +1"
pass "stats summary counts the queries: $after"

# --- 4d. The UI. ------------------------------------------------------------------------------
page="$(curl -sS --fail-with-body --cacert "$ca" "$admin/")" || fail "GET /"
grep -q '<div id="app">' <<<"$page" || fail "GET / did not give the built web UI"
grep -qE '/assets/[A-Za-z0-9._-]+\.js' <<<"$page" || fail "GET / has no UI script"
pass "GET / gives the web UI"

# --- 5. DoH. ------------------------------------------------------------------------------------
doh="https://127.0.0.1:$doh_port/dns-query"
doh_post() {
    local name="$1"
    python3 "$helper" query "$name" "$work/q.bin"
    curl -sS --fail-with-body --cacert "$ca" -H 'Content-Type: application/dns-message' \
        -H 'Accept: application/dns-message' --data-binary "@$work/q.bin" \
        -o "$work/a.bin" "$doh" || return 1
    python3 "$helper" answer "$work/a.bin"
}
[[ "$(doh_post blocked.smoke.example)" == "rcode=0 a=0.0.0.0" ]] || fail "DoH blocked name"
pass "DoH POST blocked.smoke.example = 0.0.0.0"
[[ "$(doh_post nas.lan)" == "rcode=0 a=192.0.2.10" ]] || fail "DoH local record"
pass "DoH POST nas.lan = 192.0.2.10"
[[ "$(doh_post other.smoke.example)" == "rcode=0 a=192.0.2.1" ]] || fail "DoH allowed name"
pass "DoH POST other.smoke.example = 192.0.2.1"
# curl finds listserver.lan through rusthole DoH, then downloads the list from it.
body="$(curl -sS --fail-with-body --cacert "$ca" --doh-url "$doh" \
    "http://listserver.lan:$list_port/block.txt")" || fail "curl --doh-url"
grep -q 'blocked.smoke.example' <<<"$body" || fail "curl --doh-url gave the wrong page"
pass "curl --doh-url resolves listserver.lan through rusthole"

# --- 6. Stop with SIGTERM. -------------------------------------------------------------------
kill -TERM "$rusthole_pid"
stopped=0
for ((i = 0; i < 60; i++)); do
    if ! kill -0 "$rusthole_pid" 2>/dev/null; then
        stopped=1
        break
    fi
    sleep 0.5
done
[[ "$stopped" -eq 1 ]] || fail "rusthole did not stop in 30 s after SIGTERM"
set +e
wait "$rusthole_pid"
code=$?
set -e
rusthole_pid=""
[[ "$code" -eq 0 ]] || fail "rusthole exit code after SIGTERM: $code"
grep -q "stop signal received" "$work/rusthole.log" || fail "no stop message in the log"
pass "SIGTERM: exit code 0"
grep -qx "STOPPING=1" "$notify_log" || fail "rusthole sent no STOPPING=1 to NOTIFY_SOCKET"
pass "systemd notification: STOPPING=1"

if grep -E ' ERROR ' "$work/rusthole.log"; then
    fail "the log has ERROR lines"
fi
pass "no ERROR in the log"

# --- Optional: a real DoH upstream (needs the internet; not in CI). -----------------------
if [[ "${SMOKE_REAL_DOH:-0}" == "1" ]]; then
    real="$work/real-doh.toml"
    mkdir -p "$work/data-real"
    cat >"$real" <<EOF
config_version = 1

[server]
dns_listen = ["127.0.0.1"]
dns_port = $dns_port
data_dir = "$work/data-real"

[server.admin]
enabled = false

[[upstreams.servers]]
url = "https://cloudflare-dns.com/dns-query"
bootstrap = ["1.1.1.1"]
EOF
    RUSTHOLE_LOG=info "$bin" run -c "$real" >"$work/rusthole.log" 2>&1 &
    rusthole_pid=$!
    retry 60 grep -q "rusthole is running" "$work/rusthole.log" || fail "real DoH: rusthole did not start"
    answer=""
    for ((i = 0; i < 10; i++)); do
        answer="$(dig +short +time=5 +tries=1 @127.0.0.1 -p "$dns_port" example.com A | head -n 1)"
        [[ -n "$answer" ]] && break
        sleep 1
    done
    [[ "$answer" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "real DoH: no answer for example.com"
    pass "real DoH upstream (cloudflare-dns.com, bootstrap 1.1.1.1): example.com = $answer"
    kill -TERM "$rusthole_pid"
    for ((i = 0; i < 60; i++)); do
        kill -0 "$rusthole_pid" 2>/dev/null || break
        sleep 0.5
    done
    set +e
    wait "$rusthole_pid"
    code=$?
    set -e
    rusthole_pid=""
    [[ "$code" -eq 0 ]] || fail "real DoH: exit code after SIGTERM: $code"
fi

echo "ALL SMOKE CHECKS PASSED"
