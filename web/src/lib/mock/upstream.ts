// The mock port of `UpstreamUrl::parse` (crates/rusthole-core/src/net.rs) and the
// upstream checks of `PATCH /settings` (crates/rusthole-web/src/settings.rs). Only the
// mock uses it. The UI does not check the upstream grammar; it shows the 422 of the
// server, so the browser never refuses a value that the server accepts.

import { isHostname, isIPv4, looksLikeIPv6 } from '../validate';

export type Transport = 'udp' | 'tcp' | 'tls' | 'https';

export interface UpstreamUrl {
  transport: Transport;
  host: { kind: 'ip'; v6: boolean; text: string } | { kind: 'name'; text: string };
  port: number;
  path: string;
}

export type ParseResult = { ok: true; value: UpstreamUrl } | { ok: false; error: string };

const DEFAULT_PORT: Record<Transport, number> = { udp: 53, tcp: 53, tls: 853, https: 443 };

/** IPv4 or IPv6 text without brackets. The IPv6 test is an approximation of the Rust parser. */
function ipKind(s: string): 'v4' | 'v6' | null {
  if (isIPv4(s)) return 'v4';
  if (s.includes(':') && looksLikeIPv6(s) && !s.includes('/')) return 'v6';
  return null;
}

/** Digits only, 0 to 65535. Null on bad syntax. */
function parsePort(text: string): number | null {
  if (!/^\d+$/.test(text)) return null;
  const n = Number(text);
  return n <= 65535 ? n : null;
}

/** `host`, `host:port`, `[v6]` or `[v6]:port`. Null on bad syntax. */
function splitHostPort(authority: string, defaultPort: number): [string, number] | null {
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    if (end < 0) return null;
    const host = authority.slice(1, end);
    const after = authority.slice(end + 1);
    if (after === '') return [host, defaultPort];
    if (!after.startsWith(':')) return null;
    const port = parsePort(after.slice(1));
    return port === null ? null : [host, port];
  }
  if (authority.split(':').length === 2) {
    const [host = '', portText = ''] = authority.split(':');
    const port = parsePort(portText);
    return port === null ? null : [host, port];
  }
  return [authority, defaultPort];
}

/** `parse_socket_addr(input, 53)`: an IP address, or an address with a port. */
function parseSocketAddr(input: string): ParseResult {
  const s = input.trim();
  let host: string;
  let port: number;
  const kind = ipKind(s);
  if (kind) {
    host = s;
    port = 53;
  } else {
    const split = /^\[.*\]:\d+$/.test(s) || /^[^:]+:\d+$/.test(s) ? splitHostPort(s, 53) : null;
    if (!split || !ipKind(split[0])) return { ok: false, error: `${JSON.stringify(input)} is not an address with an optional port` };
    [host, port] = split;
  }
  if (port === 0) return { ok: false, error: 'port 0 is not allowed' };
  return { ok: true, value: { transport: 'udp', host: { kind: 'ip', v6: ipKind(host) === 'v6', text: host }, port, path: '' } };
}

/** Parses an upstream URL with the grammar of `UpstreamUrl::parse`. */
export function parseUpstreamUrl(input: string): ParseResult {
  const s = input.trim();
  const sep = s.indexOf('://');
  if (sep < 0) return parseSocketAddr(s);
  const scheme = s.slice(0, sep).toLowerCase();
  const rest = s.slice(sep + 3);
  if (scheme !== 'udp' && scheme !== 'tcp' && scheme !== 'tls' && scheme !== 'https') {
    return { ok: false, error: `${JSON.stringify(input)} has no scheme that rusthole knows (use udp://, tcp://, tls:// or https://)` };
  }
  const transport: Transport = scheme;
  const bad: ParseResult = { ok: false, error: `${JSON.stringify(input)} is not a valid upstream URL` };
  const slash = rest.indexOf('/');
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? '' : rest.slice(slash);
  if (transport === 'https') {
    if (/[\s\u0000-\u001f\u007f]/.test(path)) return bad;
  } else if (path !== '' && path !== '/') {
    return bad;
  }
  if (authority.includes('@') || authority === '') return bad;
  const split = splitHostPort(authority, DEFAULT_PORT[transport]);
  if (!split) return bad;
  const [hostText, port] = split;
  if (port === 0) return { ok: false, error: 'port 0 is not allowed' };
  const kind = ipKind(hostText);
  let host: UpstreamUrl['host'];
  if (kind) host = { kind: 'ip', v6: kind === 'v6', text: hostText };
  else if (transport === 'tls' || transport === 'https') {
    if (!isHostname(hostText)) return { ok: false, error: `host name is not valid: ${hostText}` };
    host = { kind: 'name', text: hostText.toLowerCase() };
  } else {
    return { ok: false, error: `the host of a plain DNS upstream must be an IP address, not ${JSON.stringify(hostText)}` };
  }
  const outPath = transport === 'https' ? (path === '' || path === '/' ? '/dns-query' : path) : '';
  return { ok: true, value: { transport, host, port, path: outPath } };
}

/** The message of the server for an IPv6 value in v1 (A11). */
export const IPV6_LATER = 'IPv6 comes in a later version.';

/**
 * The field errors of the `upstreams` section of `PATCH /settings`, as the server gives
 * them (see the recorded answers in fixtures/). First the server checks each field.
 * Only when all fields are good, it checks the full config: then a new DoT or DoH
 * upstream with a host name has no bootstrap addresses and gets an error (review item
 * m19). `known` holds the servers of the config, which keep their bootstrap addresses.
 */
export function upstreamErrors(
  servers: string[],
  timeoutMs: unknown,
  known: string[],
): { field: string; message: string }[] {
  const out: { field: string; message: string }[] = [];
  if (servers.length === 0 || servers.length > 8) out.push({ field: 'upstreams.servers', message: 'Give 1 to 8 servers.' });
  const names: number[] = [];
  servers.forEach((s, i) => {
    const r = parseUpstreamUrl(s);
    if (!r.ok) out.push({ field: `upstreams.servers[${i}]`, message: r.error });
    else if (r.value.host.kind === 'ip' && r.value.host.v6) out.push({ field: `upstreams.servers[${i}]`, message: IPV6_LATER });
    else if (r.value.host.kind === 'name' && !known.includes(s.trim())) names.push(i);
  });
  if (typeof timeoutMs !== 'number' || timeoutMs < 100 || timeoutMs > 10000) {
    out.push({ field: 'upstreams.timeout_ms', message: 'Use 100 to 10000.' });
  }
  if (out.length > 0) return out;
  return names.map((i) => ({
    field: `upstreams.servers[${i}].bootstrap`,
    message: 'a DoT or DoH upstream with a host name needs bootstrap IP addresses',
  }));
}
