#!/bin/sh
# Remove rusthole from a Linux host. docs/INSTALL.md explains the steps.
#
# Use (as root):
#   sudo sh uninstall.sh            remove the service and the binary; keep the config and
#                                   the data
#   sudo sh uninstall.sh --purge    also remove /etc/rusthole, /var/lib/rusthole and the
#                                   rusthole user
#
# When install.sh turned off the systemd-resolved stub listener, this script turns it on
# again and restores the /etc/resolv.conf link.
#
# DESTDIR (tests only): remove from a staging tree, for example DESTDIR=/tmp/root.
set -eu

DESTDIR="${DESTDIR:-}"
BIN="$DESTDIR/usr/local/bin/rusthole"
CONF_DIR="$DESTDIR/etc/rusthole"
DATA_DIR="$DESTDIR/var/lib/rusthole"
UNIT="$DESTDIR/etc/systemd/system/rusthole.service"
RESOLVED_DROPIN="$DESTDIR/etc/systemd/resolved.conf.d/rusthole.conf"
RESOLV_CONF="$DESTDIR/etc/resolv.conf"
SERVICE_USER=rusthole

purge=0

say() { printf '%s\n' "$*"; }
die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --purge)
            purge=1
            shift
            ;;
        -h | --help)
            sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run this script as root (sudo sh uninstall.sh)"

systemd=0
[ -d /run/systemd/system ] && systemd=1

# 1. The service.
if [ "$systemd" -eq 1 ]; then
    systemctl disable --now rusthole.service >/dev/null 2>&1 || true
fi
if [ -e "$UNIT" ]; then
    rm -f "$UNIT"
    say "Removed $UNIT"
fi
if [ "$systemd" -eq 1 ]; then
    systemctl daemon-reload
    systemctl reset-failed rusthole.service >/dev/null 2>&1 || true
fi

# 2. The binary.
if [ -e "$BIN" ]; then
    rm -f "$BIN"
    say "Removed $BIN"
fi

# 3. The systemd-resolved stub listener (only when install.sh turned it off).
if [ -f "$RESOLVED_DROPIN" ]; then
    old_link="$(sed -n 's/^# rusthole-resolv-conf-link: //p' "$RESOLVED_DROPIN" | head -n 1)"
    rm -f "$RESOLVED_DROPIN"
    if [ -n "$old_link" ] && [ -L "$RESOLV_CONF" ]; then
        ln -sfn "$old_link" "$RESOLV_CONF"
        say "Restored the link $RESOLV_CONF -> $old_link"
    fi
    if [ "$systemd" -eq 1 ]; then
        systemctl restart systemd-resolved || say "Restart systemd-resolved by hand"
    fi
    say "Turned on the systemd-resolved stub listener again"
fi

# 4. The config, the data and the user (only with --purge).
if [ "$purge" -eq 1 ]; then
    rm -rf "$CONF_DIR" "$DATA_DIR"
    say "Removed $CONF_DIR and $DATA_DIR"
    if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        userdel "$SERVICE_USER" >/dev/null 2>&1 || say "Remove the user $SERVICE_USER by hand"
        say "Removed the user $SERVICE_USER"
    fi
else
    say "Kept $CONF_DIR and $DATA_DIR (use --purge to remove them)"
fi
say "rusthole is removed"
