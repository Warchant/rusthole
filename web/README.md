# rusthole web UI

This folder has the admin web UI of rusthole. It uses Svelte 5, Vite and TypeScript.
The REST API contract is in [docs/API.md](../docs/API.md).

The Rust binary embeds the build output (`web/dist`) with `rust-embed`. `cargo build`
does not run bun or Node. If `web/dist` is missing, the binary embeds a placeholder page.

## Requirements

- [bun](https://bun.sh) 1.4 or later. bun installs the packages and runs the scripts.

## Install

```bash
cd web
bun install --frozen-lockfile
```

## Run the dev server with mock data

```bash
bun run dev
```

Then open http://localhost:5173.

- The dev server uses the mock API (`VITE_MOCK=1` in `.env.development`). You do not
  need the Rust backend.
- The mock password is `rusthole`. When you turn on TOTP, any 6-digit code is valid.
- The mock keeps its data in memory. A page reload resets the data and logs you out.
- All mock names and addresses are synthetic: IPs from `192.0.2.0/24`, MACs like
  `02:00:00:00:00:01`, and domains under `example.com` or the `.example` TLD.

## Run the dev server with a real backend

```bash
bun run dev:api
```

The dev server sends `/api` requests to `https://127.0.0.1:8443`. To use a different
address, change `RUSTHOLE_API` in `.env.api`.

## Build

```bash
bun run build
```

The output goes to `web/dist`. The production build does not contain the mock.

To see the build with the strict CSP of the admin listener, run `bun run preview`.
The preview server sends the same `Content-Security-Policy` header.

## Checks

```bash
bun run check   # svelte-check and tsc
bun run test    # vitest unit tests (not `bun test`, which is a different test runner)
```

## Rules for UI code

- Do not use inline scripts, inline `style` attributes, `style:` directives, Svelte
  transitions or `eval`. The CSP blocks them. Use CSS classes and SVG attributes.
- Do not load resources from other hosts. Use the system font stack.
- Do not keep secrets in `localStorage`. The CSRF token stays in memory.
- All API calls go through `src/lib/api/client.ts`.
- rusthole v1 uses IPv4 transport only. Forms accept IPv4 for client ids, CIDRs and
  servers, and show a hint for IPv6.
