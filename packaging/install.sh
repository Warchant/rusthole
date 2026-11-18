#!/bin/sh
# Install or upgrade rusthole on a Linux host with systemd: Ubuntu, Debian, or Raspberry Pi
# OS 64-bit. docs/INSTALL.md explains each step.
#
# Use (as root, from the folder with the release files):
#   sudo sh install.sh [options]
#
# Options:
#   --binary PATH            the rusthole binary (default: rusthole-<arch>-linux-musl next
#                            to this script, else ./rusthole)
#   --import FILE            make the config from a Pi-hole v6 Teleporter export (zip). Only
#                            when no config exists.
#   --disable-resolved-stub  turn off the systemd-resolved stub listener on 127.0.0.53:53
#                            and point /etc/resolv.conf at the upstream list of
#                            systemd-resolved. Read docs/INSTALL.md first.
#   --no-start               install and enable the service, but do not start it (an
#                            upgrade stops a running service and does not start it)
#   -h, --help               show this help
#
# The script is idempotent: run it again with a new binary to upgrade. It keeps the config
# and the data. It never overwrites an existing config. An upgrade checks the existing config
# with the new binary before it replaces the old binary.
#
# DESTDIR (tests only): install into a staging tree, for example DESTDIR=/tmp/root. This
# mode does not touch the real host: no root, no user, no chown, no systemctl.
set -eu

DESTDIR="${DESTDIR:-}"
BIN="$DESTDIR/usr/local/bin/rusthole"
CONF_DIR="$DESTDIR/etc/rusthole"
CONF="$CONF_DIR/rusthole.toml"
DATA_DIR="$DESTDIR/var/lib/rusthole"
UNIT="$DESTDIR/etc/systemd/system/rusthole.service"
RESOLVED_DROPIN_DIR="$DESTDIR/etc/systemd/resolved.conf.d"
RESOLVED_DROPIN="$RESOLVED_DROPIN_DIR/rusthole.conf"
RESOLV_CONF="$DESTDIR/etc/resolv.conf"
# The upstream list of systemd-resolved. The host keeps working DNS when rusthole stops.
RESOLVED_UPSTREAM=/run/systemd/resolve/resolv.conf
SERVICE_USER=rusthole

here="$(cd "$(dirname "$0")" && pwd)"
binary=""
import_file=""
disable_stub=0
start=1

say() { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
}

# DESTDIR mode (staging) or the real host.
staging=0
[ -n "$DESTDIR" ] && staging=1

# Refuse a path that is a symbolic link. Root changes the owner and the mode of these paths,
# and the service user can write in their parent folders. A link could point root at another
# file (for example /etc/shadow).
refuse_link() {
    if [ -L "$1" ]; then
        die "$1 is a symbolic link; rusthole needs a real file or folder there. Remove the link, then run the script again."
    fi
}

# Give a path to the service user. -h: never follow a symbolic link. Not in DESTDIR mode: the
# staging tree is not the real host.
give_to_service() {
    [ "$staging" -eq 1 ] && return 0
    chown -h "$SERVICE_USER:$SERVICE_USER" "$1"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --binary)
            [ $# -ge 2 ] || die "--binary needs a path"
            binary="$2"
            shift 2
            ;;
        --import)
            [ $# -ge 2 ] || die "--import needs a file"
            import_file="$2"
            shift 2
            ;;
        --disable-resolved-stub)
            disable_stub=1
            shift
            ;;
        --no-start)
            start=0
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

if [ "$staging" -eq 0 ]; then
    [ "$(id -u)" -eq 0 ] || die "run this script as root (sudo sh install.sh)"
fi

# 1. The CPU type. Release binaries exist for x86_64 and aarch64 only.
machine="$(uname -m)"
case "$machine" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) die "rusthole supports x86_64 and aarch64 only; this host is $machine. A Raspberry Pi needs a 64-bit OS." ;;
esac

# 2. The binary.
if [ -z "$binary" ]; then
    if [ -f "$here/rusthole-$arch-linux-musl" ]; then
        binary="$here/rusthole-$arch-linux-musl"
    elif [ -f "$here/rusthole" ]; then
        binary="$here/rusthole"
    else
        die "no binary found; give it with --binary PATH (rusthole-$arch-linux-musl)"
    fi
fi
[ -f "$binary" ] || die "$binary does not exist"
if [ -n "$import_file" ] && [ ! -f "$import_file" ]; then
    die "$import_file does not exist"
fi

# Copy the binary next to its place first: a temp file and a rename, so a running rusthole is
# not changed in place, and a binary that does not run is never installed.
mkdir -p "$(dirname "$BIN")"
tmp_bin="$BIN.new.$$"
# stopped=1: step 6 stopped the running service. When the script then fails, the exit handler
# starts the service again, so the LAN keeps its DNS.
stopped=0
on_exit() {
    rc=$?
    rm -f "$tmp_bin"
    if [ "$rc" -ne 0 ] && [ "$stopped" -eq 1 ]; then
        warn "the install failed after the service stopped; starting rusthole.service again"
        systemctl start rusthole.service || warn "rusthole.service did not start; see: journalctl -u rusthole"
    fi
}
trap on_exit EXIT
cp "$binary" "$tmp_bin"
chmod 0755 "$tmp_bin"
version="$("$tmp_bin" --version 2>/dev/null)" || die "$binary does not run on this host (wrong CPU type?)"
say "Installing $version"

# 3. No symbolic links in the paths of the service. -e is false for a link to nothing, so the
# config test is also -L.
for p in "$CONF_DIR" "$DATA_DIR" "$CONF"; do
    refuse_link "$p"
done
if [ -e "$CONF" ] && [ ! -f "$CONF" ]; then
    die "$CONF is not a regular file"
fi
if [ -e "$CONF" ] && [ -n "$import_file" ]; then
    die "$CONF exists; move it away to import $import_file, then run the script again"
fi
# The files of the release must exist before the script changes the host.
[ -f "$here/rusthole.service" ] || die "the unit $here/rusthole.service is missing"
if [ ! -e "$CONF" ] && [ -z "$import_file" ] && [ ! -f "$here/rusthole.toml" ]; then
    die "the default config $here/rusthole.toml is missing"
fi

# 4. An upgrade: check the existing config with the new binary, before the old binary is
# replaced. When the check fails, the old binary and the service stay as they are.
if [ -e "$CONF" ] && [ -z "$import_file" ]; then
    if ! "$tmp_bin" check-config -c "$CONF"; then
        die "the new binary refuses $CONF (see above); the old binary and the service are not changed"
    fi
    say "The new binary accepts $CONF"
fi

# 5. The system user (no login, no home directory).
if [ "$staging" -eq 1 ]; then
    say "DESTDIR mode: no system user"
elif getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    say "User $SERVICE_USER exists"
else
    nologin=/usr/sbin/nologin
    [ -x "$nologin" ] || nologin=/sbin/nologin
    useradd --system --user-group --no-create-home --home-dir /var/lib/rusthole \
        --shell "$nologin" --comment "rusthole DNS ad blocker" "$SERVICE_USER"
    say "Made the system user $SERVICE_USER"
fi

# 6. Stop a running service before root changes the owner and the mode of its files. Then the
# service user cannot replace a file with a link between the link test and the change. The
# last step starts the service again.
if [ "$staging" -eq 0 ] && [ -d /run/systemd/system ] &&
    systemctl is-active --quiet rusthole.service; then
    stopped=1
    systemctl stop rusthole.service
    say "Stopped rusthole.service for the upgrade"
fi

# 7. The binary.
mv -f "$tmp_bin" "$BIN"
say "Installed $BIN"

# 8. The directories: only the rusthole user can read them.
for d in "$CONF_DIR" "$DATA_DIR"; do
    mkdir -p "$d"
    refuse_link "$d"
    give_to_service "$d"
    chmod 0750 "$d"
done

# 9. The config. Never overwrite an existing one.
if [ -e "$CONF" ]; then
    if [ -n "$import_file" ]; then
        die "$CONF exists; move it away to import $import_file, then run the script again"
    fi
    say "Kept the config $CONF"
elif [ -n "$import_file" ]; then
    "$BIN" import "$import_file" -o "$CONF"
    say "Made $CONF from $import_file"
else
    [ -f "$here/rusthole.toml" ] || die "the default config $here/rusthole.toml is missing"
    cp "$here/rusthole.toml" "$CONF"
    say "Wrote the default config $CONF"
fi
refuse_link "$CONF"
[ -f "$CONF" ] || die "$CONF is not a regular file"
give_to_service "$CONF"
chmod 0600 "$CONF"
if ! "$BIN" check-config -c "$CONF"; then
    die "$CONF has problems (see above); fix them, then run the script again"
fi

# 10. The systemd-resolved stub listener on 127.0.0.53:53. In DESTDIR mode, the script
# changes only the files in the staging tree.
stub_active=0
if [ "$staging" -eq 1 ]; then
    stub_active=1
elif command -v ss >/dev/null 2>&1 && ss -Hlnu 2>/dev/null | grep -q '127\.0\.0\.53[:%]'; then
    stub_active=1
fi
if [ "$disable_stub" -eq 1 ]; then
    if [ "$stub_active" -eq 0 ] && [ ! -e "$RESOLVED_DROPIN" ]; then
        say "The systemd-resolved stub listener is not active; nothing to change"
    else
        mkdir -p "$RESOLVED_DROPIN_DIR"
        old_link=""
        if [ -L "$RESOLV_CONF" ]; then
            old_link="$(readlink "$RESOLV_CONF")"
        fi
        if [ ! -e "$RESOLVED_DROPIN" ]; then
            {
                say "# Written by rusthole install.sh. uninstall.sh removes it."
                say "# rusthole-resolv-conf-link: $old_link"
                say "[Resolve]"
                say "DNSStubListener=no"
            } >"$RESOLVED_DROPIN"
        fi
        if [ "$staging" -eq 0 ]; then
            systemctl restart systemd-resolved
        fi
        if [ -L "$RESOLV_CONF" ] || [ ! -e "$RESOLV_CONF" ]; then
            ln -sfn "$RESOLVED_UPSTREAM" "$RESOLV_CONF"
            say "Turned off the stub listener; $RESOLV_CONF now points to $RESOLVED_UPSTREAM"
        else
            warn "$RESOLV_CONF is a file, not a link; it stays as it is. Make sure that it does not name 127.0.0.53."
        fi
    fi
elif [ "$stub_active" -eq 1 ] && [ "$staging" -eq 0 ]; then
    say "Note: systemd-resolved listens on 127.0.0.53:53. rusthole binds each address on its own,"
    say "      so they do not clash. To replace the stub, see docs/INSTALL.md (--disable-resolved-stub)."
fi

# Another DNS server on port 53 (for example dnsmasq or Pi-hole) stops rusthole from binding.
if [ "$staging" -eq 0 ] && command -v ss >/dev/null 2>&1; then
    others="$(ss -Hlnup 'sport = :53' 2>/dev/null | grep -v -e '127\.0\.0\.53[:%]' -e '127\.0\.0\.54[:%]' -e '"rusthole"' || true)"
    if [ -n "$others" ]; then
        warn "another program listens on port 53; rusthole cannot bind these addresses:"
        printf '%s\n' "$others" >&2
    fi
fi

# The password command must run as the user rusthole. As root, it writes a config that only
# root can read, and the service cannot start.
passwd_hint() {
    say "Next step:       set the admin password, as the user rusthole:"
    say "                 sudo -u rusthole rusthole passwd -c /etc/rusthole/rusthole.toml"
    say "                 Do not run it as root: then the config belongs to root, the service"
    say "                 cannot read it, and rusthole does not start."
}

# 11. The systemd unit.
mkdir -p "$(dirname "$UNIT")"
if [ -f "$here/rusthole.service" ]; then
    cp "$here/rusthole.service" "$UNIT.new.$$"
    chmod 0644 "$UNIT.new.$$"
    mv -f "$UNIT.new.$$" "$UNIT"
else
    die "the unit $here/rusthole.service is missing"
fi
if [ "$staging" -eq 1 ]; then
    say "DESTDIR mode: installed into $DESTDIR; no systemctl"
    passwd_hint
    exit 0
fi
if [ ! -d /run/systemd/system ]; then
    warn "systemd does not run on this host; start rusthole by hand: $BIN run -c $CONF"
    exit 0
fi
systemctl daemon-reload
systemctl enable rusthole.service >/dev/null
if [ "$start" -eq 0 ]; then
    say "Installed and enabled rusthole.service (not started: --no-start)"
    exit 0
fi
# Type=notify: systemctl returns when rusthole sent READY=1 (all listeners are bound), or
# when the start failed.
# From here, a failed start is the result of this step, not of an earlier failure.
stopped=0
if ! systemctl restart rusthole.service; then
    systemctl --no-pager status rusthole.service >&2 || true
    die "rusthole did not start; see: journalctl -u rusthole"
fi
say "rusthole.service is running"

# 9. The next steps.
admin_port="$(awk '
    /^\[/ { in_admin = ($0 ~ /^\[server\.admin\]/) }
    in_admin && /^[ \t]*port[ \t]*=/ { gsub(/[^0-9]/, "", $0); print; exit }
' "$CONF")"
[ -n "$admin_port" ] || admin_port=8443
addr="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1 || true)"
[ -n "$addr" ] || addr="<this host>"
fingerprint=""
i=0
while [ -z "$fingerprint" ] && [ "$i" -lt 10 ]; do
    fingerprint="$(journalctl -u rusthole.service -o cat --no-pager -n 200 2>/dev/null |
        grep 'TLS certificate in use' | tail -n 1 |
        sed -n 's/.*[^_]fingerprint=\([0-9A-F:]*\).*/\1/p' || true)"
    [ -n "$fingerprint" ] && break
    i=$((i + 1))
    sleep 1
done

say ""
say "Admin UI:        https://$addr:$admin_port/"
if [ -n "$fingerprint" ]; then
    say "TLS fingerprint: $fingerprint"
    say "                 (compare it with the fingerprint that the browser shows)"
else
    say "TLS fingerprint: see journalctl -u rusthole | grep fingerprint"
fi
passwd_hint
say "Then point the DNS server of your router (DHCP) or of your devices at $addr."
