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

## Build

```bash
cargo build --release
```

## Development

See [docs/ENGINEERING.md](docs/ENGINEERING.md).

## License

MIT OR Apache-2.0, at your option.
