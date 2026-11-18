# rusthole

A DNS ad blocker for home and small office networks, written in Rust.
It does a job like Pi-hole, but it is not a Pi-hole rewrite.

Status: early development. See [docs/PLAN.md](docs/PLAN.md) for the plan and the order of work.
The admin REST API contract is in [docs/API.md](docs/API.md).

## Goals

- One static binary for Linux on x86_64 and aarch64 (Raspberry Pi 3/4/5, 64-bit OS).
- The web UI is inside the binary.
- One TOML config file.
- Import of a Pi-hole v6 Teleporter export: adlists, allow and deny rules, regex rules,
  groups and clients.
- Ad blocking with groups and clients (by IP, CIDR or MAC address).
- Query log and per-client statistics, with few writes to the SD card.
- DNS over HTTPS: as a server for clients, and to reach upstream servers.
- Safe defaults: only clients on the local network get answers, every admin endpoint
  needs a login, and the login has a brute-force ban.
- No `unsafe` code in rusthole crates. Property tests and fuzz tests for parsers and
  state machines.

## Install

Download all release files into one folder: the two binaries, `install.sh`, `uninstall.sh`,
`rusthole.service`, `rusthole.toml` and `SHA256SUMS`. Get them from the
[releases page](https://github.com/warchant/rusthole/releases).
[docs/INSTALL.md](docs/INSTALL.md#1-download-and-verify) gives a command that downloads them.
The install script needs the unit and the default config next to it. Verify `SHA256SUMS`,
then run the install script:

```bash
sha256sum -c SHA256SUMS
sudo sh install.sh
sudo -u rusthole rusthole passwd -c /etc/rusthole/rusthole.toml
```

The script installs a hardened systemd service on port 53, with the admin UI on port 8443.
[docs/INSTALL.md](docs/INSTALL.md) explains each step: Pi-hole import, systemd-resolved,
firewall ports, upgrade, uninstall and troubleshooting.

## Build

```bash
cargo build --release
```

Release builds (static musl binaries with the web UI inside) use `scripts/release-build.sh`.
See [docs/INSTALL.md](docs/INSTALL.md#build-from-source).

## Development

See [docs/ENGINEERING.md](docs/ENGINEERING.md).

## License

MIT OR Apache-2.0, at your option.
