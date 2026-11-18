#!/usr/bin/env bash
# Tests of packaging/install.sh and packaging/uninstall.sh in DESTDIR mode. No root, no
# systemd, no real rusthole binary: a fake binary and fake host commands.
#
# Use:
#   bash scripts/install-test.sh
#
# Cases:
#   1. DESTDIR mode does not touch the real host: no systemctl, useradd, userdel or chown.
#   2. An upgrade to a binary that refuses the config fails before it replaces the binary.
#   3. The script refuses a config that is a symbolic link, and a data folder that is a link.
#   4. The output tells the admin to run "rusthole passwd" as the user rusthole.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/rusthole-install-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# The fake host commands write their name and arguments to $CALLS.
mkdir -p "$work/bin"
for cmd in systemctl useradd userdel chown journalctl; do
    # $* and $CALLS expand in the fake command, not here.
    # shellcheck disable=SC2016
    printf '#!/bin/sh\necho "%s $*" >>"$CALLS"\n' "$cmd" >"$work/bin/$cmd"
    chmod +x "$work/bin/$cmd"
done
export PATH="$work/bin:$PATH" CALLS="$work/calls"

# Two fake rusthole binaries. "good" accepts each config. "strict" refuses each config.
fake_bin() {
    local name="$1" check_code="$2"
    cat >"$work/$name" <<EOF
#!/bin/sh
case "\$1" in
    --version) echo "rusthole 0.0.0-$name" ;;
    check-config) exit $check_code ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$work/$name"
}
fake_bin good 0
fake_bin strict 1

fails=0
pass() { echo "PASS: $1"; }
fail() {
    echo "FAIL: $1" >&2
    if [[ -f "$work/out" ]]; then
        sed 's/^/    /' "$work/out" >&2
    fi
    fails=$((fails + 1))
}

install_into() {
    local root="$1"
    shift
    DESTDIR="$root" sh "$repo/packaging/install.sh" "$@" >"$work/out" 2>&1
}

# 1. DESTDIR mode: install, upgrade, uninstall --purge. No call of a host command.
root="$work/root1"
: >"$CALLS"
if install_into "$root" --binary "$work/good" &&
    install_into "$root" --binary "$work/good" &&
    DESTDIR="$root" sh "$repo/packaging/uninstall.sh" --purge >"$work/out" 2>&1; then
    if [[ -s "$CALLS" ]]; then
        fail "DESTDIR mode called host commands: $(tr '\n' ';' <"$CALLS")"
    elif [[ -e "$root/usr/local/bin/rusthole" || -e "$root/etc/rusthole" ]]; then
        fail "uninstall --purge left files in DESTDIR"
    else
        pass "DESTDIR mode does not touch the real host"
    fi
else
    fail "install or uninstall in DESTDIR mode failed"
fi

# 2. An upgrade to a binary that refuses the config keeps the old binary.
root="$work/root2"
if ! install_into "$root" --binary "$work/good"; then
    fail "first install failed"
elif install_into "$root" --binary "$work/strict"; then
    fail "an upgrade to a binary that refuses the config did not fail"
elif ! cmp -s "$root/usr/local/bin/rusthole" "$work/good"; then
    fail "the upgrade replaced the binary before the config check"
elif compgen -G "$root/usr/local/bin/rusthole.new.*" >/dev/null; then
    fail "the upgrade left a temp binary"
else
    pass "an upgrade checks the config with the new binary first"
fi

# 3a. A config that is a symbolic link: refuse, and do not change the link target.
root="$work/root3"
mkdir -p "$root/etc/rusthole"
echo "secret" >"$work/target"
chmod 0644 "$work/target"
ln -s "$work/target" "$root/etc/rusthole/rusthole.toml"
if install_into "$root" --binary "$work/good"; then
    fail "the script accepted a config that is a symbolic link"
elif [[ "$(stat -c %a "$work/target")" != 644 || -e "$root/usr/local/bin/rusthole" ]]; then
    fail "the script changed the host before it refused the config link"
else
    pass "a config that is a symbolic link is refused"
fi

# 3b. A data folder that is a symbolic link: refuse.
root="$work/root4"
mkdir -p "$root/var/lib" "$work/elsewhere"
ln -s "$work/elsewhere" "$root/var/lib/rusthole"
if install_into "$root" --binary "$work/good"; then
    fail "the script accepted a data folder that is a symbolic link"
else
    pass "a data folder that is a symbolic link is refused"
fi

# 4. The password hint names the user rusthole and says why.
root="$work/root5"
if install_into "$root" --binary "$work/good" &&
    grep -q 'sudo -u rusthole rusthole passwd' "$work/out" &&
    grep -q 'cannot read' "$work/out"; then
    pass "the output tells the admin to run passwd as the user rusthole"
else
    fail "the output has no passwd hint with the user rusthole and the reason"
fi

if [[ $fails -ne 0 ]]; then
    echo "$fails install test(s) failed" >&2
    exit 1
fi
echo "all install tests passed"
