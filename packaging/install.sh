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
#   --no-start               install and enable the service, but do not start it
#   -h, --help               show this help
#
# The script is idempotent: run it again with a new binary to upgrade. It keeps the config
# and the data. It never overwrites an existing config.
#
# DESTDIR (tests only): install into a staging tree, for example DESTDIR=/tmp/root.
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
    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
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

[ "$(id -u)" -eq 0 ] || die "run this script as root (sudo sh install.sh)"

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
trap 'rm -f "$tmp_bin"' EXIT
cp "$binary" "$tmp_bin"
chmod 0755 "$tmp_bin"
version="$("$tmp_bin" --version 2>/dev/null)" || die "$binary does not run on this host (wrong CPU type?)"
say "Installing $version"

# 3. The system user (no login, no home directory).
if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    say "User $SERVICE_USER exists"
else
    nologin=/usr/sbin/nologin
    [ -x "$nologin" ] || nologin=/sbin/nologin
    useradd --system --user-group --no-create-home --home-dir /var/lib/rusthole \
        --shell "$nologin" --comment "rusthole DNS ad blocker" "$SERVICE_USER"
    say "Made the system user $SERVICE_USER"
fi

# 4. The binary.
mv -f "$tmp_bin" "$BIN"
trap - EXIT
say "Installed $BIN"

# 5. The directories: only the rusthole user can read them.
for d in "$CONF_DIR" "$DATA_DIR"; do
    mkdir -p "$d"
    chown "$SERVICE_USER:$SERVICE_USER" "$d"
    chmod 0750 "$d"
done

# 6. The config. Never overwrite an existing one.
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
chown "$SERVICE_USER:$SERVICE_USER" "$CONF"
chmod 0600 "$CONF"
if ! "$BIN" check-config -c "$CONF"; then
    die "$CONF has problems (see above); fix them, then run the script again"
fi

# 7. The systemd-resolved stub listener on 127.0.0.53:53.
stub_active=0
if command -v ss >/dev/null 2>&1 && ss -Hlnu 2>/dev/null | grep -q '127\.0\.0\.53[:%]'; then
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
        systemctl restart systemd-resolved
        if [ -L "$RESOLV_CONF" ] || [ ! -e "$RESOLV_CONF" ]; then
            ln -sfn "$RESOLVED_UPSTREAM" "$RESOLV_CONF"
            say "Turned off the stub listener; $RESOLV_CONF now points to $RESOLVED_UPSTREAM"
        else
            warn "$RESOLV_CONF is a file, not a link; it stays as it is. Make sure that it does not name 127.0.0.53."
        fi
    fi
elif [ "$stub_active" -eq 1 ]; then
    say "Note: systemd-resolved listens on 127.0.0.53:53. rusthole binds each address on its own,"
    say "      so they do not clash. To replace the stub, see docs/INSTALL.md (--disable-resolved-stub)."
fi

# Another DNS server on port 53 (for example dnsmasq or Pi-hole) stops rusthole from binding.
if command -v ss >/dev/null 2>&1; then
    others="$(ss -Hlnup 'sport = :53' 2>/dev/null | grep -v -e '127\.0\.0\.53[:%]' -e '127\.0\.0\.54[:%]' -e '"rusthole"' || true)"
    if [ -n "$others" ]; then
        warn "another program listens on port 53; rusthole cannot bind these addresses:"
        printf '%s\n' "$others" >&2
    fi
fi

# 8. The systemd unit.
mkdir -p "$(dirname "$UNIT")"
if [ -f "$here/rusthole.service" ]; then
    cp "$here/rusthole.service" "$UNIT.new.$$"
    chmod 0644 "$UNIT.new.$$"
    mv -f "$UNIT.new.$$" "$UNIT"
else
    die "the unit $here/rusthole.service is missing"
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
say "Next step:       set the admin password:"
say "                 sudo -u rusthole rusthole passwd -c /etc/rusthole/rusthole.toml"
say "Then point the DNS server of your router (DHCP) or of your devices at $addr."
