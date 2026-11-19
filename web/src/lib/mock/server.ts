// A mock of the admin API at the fetch level (VITE_MOCK=1). The real API client
// runs on top of it, so the CSRF header, 401 and 429 paths run as in production.
// The mock keeps its state in memory. A page reload resets it.
// Mock password: "rusthole". Any 6-digit code is a valid TOTP code.

import type * as T from '../api/types';
import { classifyClientMatch, checkCidrs, checkForwardDomain, checkServers, isHttpUrl, isIPv4, looksLikeIPv6 } from '../validate';
import { upstreamErrors } from './upstream';
import {
  clientNames,
  clientTotals,
  firstSeenDays,
  groupNamesByBase,
  hoursFor,
  MOCK_CLIENTS,
  MOCK_DOMAINS,
  recentQueries,
  timeline,
  type MockClient,
} from './data';

export const MOCK_PASSWORD = 'rusthole';
const BAN_AFTER = 5;
const BAN_SECONDS = 30;

type Json = unknown;

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: { field: string; message: string }[],
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}

const iso = (ms: number) => new Date(ms).toISOString();
const ago = (seconds: number) => iso(Date.now() - seconds * 1000);

function randomToken(bytes: number): string {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomBase32(chars: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const a = new Uint8Array(chars);
  crypto.getRandomValues(a);
  return [...a].map((b) => alphabet[b % 32]).join('');
}

// ---- state -----------------------------------------------------------------

function initialState() {
  const groups: T.Group[] = [
    // The server rule for names: lower case (see groupName below). The default group is "default".
    { id: 0, name: 'default', enabled: true, comment: 'All clients that match no other entry', lists: 0, rules: 0, clients: 0 },
    { id: 1, name: 'kids', enabled: true, comment: 'Strict lists', lists: 0, rules: 0, clients: 0 },
    { id: 2, name: 'guests', enabled: true, comment: 'No block lists', lists: 0, rules: 0, clients: 0 },
  ];
  const status = (entries: number, hoursAgo: number, error: string | null = null): T.ListStatus => ({
    state: error ? 'error' : 'ok',
    last_update_at: ago(hoursAgo * 3600),
    last_success_at: error ? ago((hoursAgo + 48) * 3600) : ago(hoursAgo * 3600),
    entries,
    invalid_lines: Math.floor(entries / 9000),
    size_bytes: entries * 27,
    last_error: error,
  });
  const lists: T.Adlist[] = [
    { id: 1, url: 'https://lists.example.org/hosts.txt', comment: 'Main block list', kind: 'block', enabled: true, groups: [0, 1], status: status(120433, 5) },
    { id: 2, url: 'https://lists.example.org/trackers-abp.txt', comment: 'Trackers (ABP format)', kind: 'block', enabled: true, groups: [0, 1], status: status(48210, 5) },
    { id: 3, url: 'https://filters.example.net/kids.txt', comment: 'Extra list for kids', kind: 'block', enabled: true, groups: [1], status: status(210554, 5) },
    { id: 4, url: 'https://old.example.com/list.txt', comment: 'Old mirror', kind: 'block', enabled: true, groups: [0], status: status(9120, 5, 'HTTP 404') },
    { id: 5, url: 'https://lists.example.org/big-list.txt', comment: 'Too many false positives', kind: 'block', enabled: false, groups: [0], status: status(0, 400) },
    { id: 6, url: 'https://lists.example.org/allow.txt', comment: 'Common false positives', kind: 'allow', enabled: true, groups: [0, 1], status: status(312, 5) },
  ];
  lists[4]!.status = { ...lists[4]!.status, state: 'never', last_update_at: null, last_success_at: null };
  const rule = (id: number, kind: T.RuleKind, action: T.RuleAction, pattern: string, groupsIds: number[], comment: string, enabled = true): T.Rule => ({
    id, kind, action, pattern, enabled, groups: groupsIds, comment, created_at: ago(86400 * (30 - id)), updated_at: ago(86400 * (10 - (id % 10))),
  });
  const rules: T.Rule[] = [
    rule(1, 'exact', 'allow', 'cdn.example.com', [0, 1], 'Needed for video'),
    rule(2, 'exact', 'allow', 'checkout.shop.example', [0], 'Shop payment page'),
    rule(3, 'exact', 'deny', 'telemetry.example.com', [0, 1], 'Telemetry'),
    rule(4, 'exact', 'deny', 'www.social.example', [1], 'No social media for kids'),
    rule(5, 'regex', 'deny', '^ads?[0-9]*\\.', [0, 1], 'Ad subdomains'),
    rule(6, 'regex', 'deny', '(^|\\.)tracker\\.example$', [0, 1], 'Tracker domain and subdomains'),
    rule(7, 'regex', 'deny', '^(.+\\.)?game\\.example$', [1], 'Games on school days', false),
    rule(8, 'regex', 'allow', '^img\\.', [0], 'Images'),
  ];
  const clients: T.Client[] = [
    { id: 1, match: '02:00:00:00:00:01', kind: 'mac', groups: [0], comment: 'laptop' },
    { id: 2, match: '02:00:00:00:00:02', kind: 'mac', groups: [0], comment: 'phone' },
    { id: 3, match: '02:00:00:00:00:03', kind: 'mac', groups: [0], comment: 'tv' },
    { id: 4, match: '02:00:00:00:00:04', kind: 'mac', groups: [1], comment: 'tablet' },
    { id: 5, match: '02:00:00:00:00:07', kind: 'mac', groups: [1], comment: 'console' },
    { id: 6, match: '192.0.2.128/25', kind: 'cidr', groups: [2], comment: 'guest network' },
  ];
  return {
    authed: false,
    csrf: null as string | null,
    failures: 0,
    banUntilMs: 0,
    totp: { enabled: false, pending: false },
    blocking: { enabled: true, untilMs: null as number | null },
    groups,
    lists,
    rules,
    clients,
    records: [
      { id: 1, name: 'nas.lan', type: 'A', address: '192.0.2.20', comment: 'File server', enabled: true },
      { id: 2, name: 'printer.lan', type: 'A', address: '192.0.2.14', comment: '', enabled: true },
      { id: 3, name: 'nas.lan', type: 'AAAA', address: '2001:db8::20', comment: 'AAAA records are DNS content', enabled: true },
    ] as T.LocalRecord[],
    cnames: [
      { id: 1, name: 'files.lan', target: 'nas.lan', comment: '', enabled: true },
      { id: 2, name: 'media.lan', target: 'nas.lan', comment: 'Media server', enabled: true },
    ] as T.LocalCname[],
    forwarders: [
      { id: 1, domain: 'lan', servers: ['192.0.2.1'], comment: 'Router', enabled: true },
      { id: 2, domain: '2.0.192.in-addr.arpa', servers: ['192.0.2.1'], comment: 'Reverse lookup for client names', enabled: true },
    ] as T.Forwarder[],
    tokens: [
      { id: 1, name: 'backup script', prefix: 'rh_Ab3d', created_at: ago(86400 * 20), last_used_at: ago(3600 * 6), last_used_ip: '192.0.2.20' },
      { id: 2, name: 'home dashboard', prefix: 'rh_x7Qp', created_at: ago(86400 * 3), last_used_at: null, last_used_ip: null },
    ] as T.ApiToken[],
    // The server sends the config text of each upstream. The default config and an
    // import write `udp://IP:PORT`. A DoT or DoH host name has bootstrap addresses in
    // the config file.
    settings: {
      upstreams: { servers: ['udp://192.0.2.53:53', 'udp://198.51.100.53:53', 'tls://dns.example:853'], timeout_ms: 2000 },
      blocking: { mode: 'null', custom_ipv4: null, custom_ipv6: null, blocked_ttl: 2, special_domains: true, cname_check: true },
      cache: { enabled: true, max_entries: 10000, min_ttl: 0, max_ttl: 86400, negative_ttl: 300 },
      rate_limit: { queries_per_second: 50, burst: 200 },
      acl: { extra_cidrs: ['198.51.100.0/24'], local_subnets: ['192.0.2.0/24'] },
      stats: { flush_interval_seconds: 60, retention_days: 30, recent_queries_size: 1000 },
      lists: { refresh_interval_hours: 24 },
      report: { external: true },
    } as Omit<T.Settings, 'restart_required'>,
    /** True after a change of upstreams or stats, until a restart (a mock reset). */
    restartRequired: false,
    audit: makeAudit(),
    nextId: 100,
    lastScheduleRunMs: Date.now() - 5 * 3600 * 1000,
    startedMs: Date.now() - 92_000 * 1000,
  };
}

function makeAudit(): T.AuditEntry[] {
  const actions: [string, string | null, string | null][] = [
    ['auth.login', null, null],
    ['list.update', 'list:5', 'enabled=false'],
    ['rule.create', 'rule:8', null],
    ['blocking.set', null, 'enabled=false duration=300'],
    ['client.update', 'client:4', 'groups=[1]'],
    ['auth.login_failed', null, null],
    ['settings.update', 'settings', 'section=cache'],
    ['list.refresh', 'list:all', null],
    ['token.create', 'token:2', null],
    ['dns.create', 'record:2', null],
  ];
  const out: T.AuditEntry[] = [];
  for (let i = 0; i < 120; i++) {
    const [action, target, detail] = actions[i % actions.length]!;
    out.push({
      id: 1200 - i,
      at: ago(i * 3700 + 120),
      action,
      target,
      actor: action.startsWith('auth.') ? 'anonymous' : i % 7 === 0 ? 'token:1' : 'session',
      client_ip: i % 5 === 0 ? '192.0.2.11' : '192.0.2.10',
      result: action === 'auth.login_failed' ? 'error' : 'ok',
      detail,
    });
  }
  return out;
}

let state = initialState();
refreshGroupCounts();

/** Resets the mock state. For tests. */
export function resetMock(): void {
  state = initialState();
  refreshGroupCounts();
}

/** Changes the mock state directly. For tests. */
export function changeMock(change: (s: ReturnType<typeof initialState>) => void): void {
  change(state);
  refreshGroupCounts();
}

function audit(action: string, target: string | null, detail: string | null = null, result: 'ok' | 'error' = 'ok') {
  const top = state.audit[0]?.id ?? 0;
  state.audit.unshift({
    id: top + 1,
    at: iso(Date.now()),
    action,
    target,
    actor: state.authed ? 'session' : 'anonymous',
    client_ip: '192.0.2.10',
    result,
    detail,
  });
}

// ---- helpers -----------------------------------------------------------------

function range(q: URLSearchParams): T.Range {
  const r = q.get('range') ?? '24h';
  if (r !== '24h' && r !== '7d' && r !== '30d') throw new HttpError(400, 'bad_request', 'range must be 24h, 7d or 30d.');
  return r;
}

function page<X>(items: X[], q: URLSearchParams, defLimit = 50): T.Page<X> {
  const limit = Number(q.get('limit') ?? defLimit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new HttpError(400, 'bad_request', 'limit must be 1 to 500.');
  const cursor = q.get('cursor');
  const start = cursor ? Number(cursor) : 0;
  if (!Number.isInteger(start) || start < 0) throw new HttpError(400, 'bad_request', 'The cursor is not valid.');
  const slice = items.slice(start, start + limit);
  return { items: slice, next_cursor: start + limit < items.length ? String(start + limit) : null };
}

function all<X>(items: X[]): T.Page<X> {
  return { items, next_cursor: null };
}

function pct(part: number, total: number): number {
  return total > 0 ? Math.round((part / total) * 10000) / 100 : 0;
}

function findClient(key: string): MockClient {
  const c = MOCK_CLIENTS.find((x) => x.key === key);
  if (!c) throw new HttpError(404, 'not_found', 'No client has this key.');
  return c;
}

function configuredFor(c: MockClient): T.Client | null {
  return (
    // The order of the server (docs/CLIENTS.md): IP, MAC, then the CIDR.
    state.clients.find((x) => x.match === c.ip) ??
    state.clients.find((x) => x.match === c.mac) ??
    state.clients.find((x) => x.kind === 'cidr' && inCidr(c.ip, x.match)) ??
    null
  );
}

function inCidr(ip: string, cidr: string): boolean {
  const [net, bits] = cidr.split('/');
  if (!net || !bits || !isIPv4(ip) || !isIPv4(net)) return false;
  const toInt = (s: string) => s.split('.').reduce((a, p) => (a << 8) + Number(p), 0) >>> 0;
  const mask = Number(bits) === 0 ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return (toInt(ip) & mask) === (toInt(net) & mask);
}

function clientName(c: MockClient): string | null {
  const cfg = configuredFor(c);
  if (cfg && cfg.kind !== 'cidr' && cfg.comment) return cfg.comment;
  return c.host;
}

function statsClient(c: MockClient, r: T.Range): T.StatsClient {
  const t = clientTotals(c, r, Date.now());
  const names = clientNames(c, r, Date.now());
  const last = names.reduce((m, n) => (n.last_seen_at && n.last_seen_at > m ? n.last_seen_at : m), '');
  return {
    key: c.key,
    name: clientName(c),
    ip: c.ip,
    mac: c.mac,
    client_id: configuredFor(c)?.id ?? null,
    queries: t.queries,
    blocked: t.blocked,
    blocked_percent: pct(t.blocked, t.queries),
    unique_domains: t.unique,
    first_seen_at: ago(firstSeenDays(c) * 86400),
    last_seen_at: last || null,
  };
}

function sortBy<X extends { queries: number; blocked: number; last_seen_at: string | null }>(
  items: X[],
  sort: string | null,
  nameOf: (x: X) => string,
): X[] {
  const s = sort ?? 'queries';
  const copy = items.slice();
  if (s === 'queries') copy.sort((a, b) => b.queries - a.queries);
  else if (s === 'blocked') copy.sort((a, b) => b.blocked - a.blocked);
  else if (s === 'last_seen') copy.sort((a, b) => (b.last_seen_at ?? '').localeCompare(a.last_seen_at ?? ''));
  else if (s === 'name') copy.sort((a, b) => nameOf(a).localeCompare(nameOf(b)));
  else throw new HttpError(400, 'bad_request', 'sort is not valid.');
  return copy;
}

function domainRows(r: T.Range) {
  const map = new Map<string, { name: string; base: string; queries: number; blocked: number; clients: Set<string>; last_seen_at: string | null }>();
  for (const c of MOCK_CLIENTS) {
    for (const n of clientNames(c, r, Date.now())) {
      let row = map.get(n.name);
      if (!row) {
        row = { name: n.name, base: n.base, queries: 0, blocked: 0, clients: new Set(), last_seen_at: null };
        map.set(n.name, row);
      }
      row.queries += n.queries;
      row.blocked += n.blocked;
      row.clients.add(c.key);
      if (!row.last_seen_at || (n.last_seen_at && n.last_seen_at > row.last_seen_at)) row.last_seen_at = n.last_seen_at;
    }
  }
  return [...map.values()];
}

function hoursResponse(r: T.Range, q: URLSearchParams, hours: T.HourArrays): T.Hours {
  return { range: r, utc_offset_minutes: Number(q.get('utc_offset_minutes') ?? 0), ...hours };
}

function blockingState(): T.BlockingState {
  const b = state.blocking;
  if (b.untilMs !== null && Date.now() >= b.untilMs) {
    b.enabled = true;
    b.untilMs = null;
  }
  if (b.untilMs === null) return { enabled: b.enabled, remaining_seconds: null, until_at: null };
  return {
    enabled: false,
    remaining_seconds: Math.max(0, Math.ceil((b.untilMs - Date.now()) / 1000)),
    until_at: iso(b.untilMs),
  };
}

function refreshGroupCounts(): void {
  for (const g of state.groups) {
    g.lists = state.lists.filter((x) => x.groups.includes(g.id)).length;
    g.rules = state.rules.filter((x) => x.groups.includes(g.id)).length;
    g.clients = state.clients.filter((x) => x.groups.includes(g.id)).length;
  }
}

function invalid(field: string, message: string): never {
  throw new HttpError(422, 'validation_failed', 'The request has invalid fields.', [{ field, message }]);
}

function obj(body: Json): Record<string, unknown> {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new HttpError(400, 'bad_request', 'The body must be a JSON object.');
  }
  return body as Record<string, unknown>;
}

function onlyFields(body: Record<string, unknown>, allowed: string[]): void {
  // The server (serde, deny_unknown_fields) names the field "body" in this 422.
  for (const k of Object.keys(body)) {
    if (!allowed.includes(k)) invalid('body', `unknown field \`${k}\`, expected one of ${allowed.map((a) => `\`${a}\``).join(', ')}`);
  }
}

function checkGroups(ids: unknown): number[] {
  if (!Array.isArray(ids) || !ids.every((x) => typeof x === 'number')) invalid('groups', 'Use a list of group ids.');
  for (const id of ids as number[]) if (!state.groups.some((g) => g.id === id)) invalid('groups', `Group ${id} does not exist.`);
  return ids as number[];
}

function byId<X extends { id: number }>(items: X[], id: number): X {
  const it = items.find((x) => x.id === id);
  if (!it) throw new HttpError(404, 'not_found', 'The resource does not exist.');
  return it;
}

function startListUpdate(ids: number[]): void {
  for (const id of ids) {
    const l = state.lists.find((x) => x.id === id);
    if (l) l.status = { ...l.status, state: 'updating' };
  }
  setTimeout(() => {
    for (const id of ids) {
      const l = state.lists.find((x) => x.id === id);
      if (!l) continue;
      const failed = l.url.includes('old.example.com');
      const entries = l.status.entries || 25000 + (id * 7919) % 40000;
      l.status = {
        ...l.status,
        state: failed ? 'error' : 'ok',
        last_update_at: iso(Date.now()),
        last_success_at: failed ? l.status.last_success_at : iso(Date.now()),
        entries,
        size_bytes: entries * 27,
        last_error: failed ? 'HTTP 404' : null,
      };
    }
    state.lastScheduleRunMs = Date.now();
  }, 2500);
}

// ---- routes ------------------------------------------------------------------

type Handler = (ctx: { q: URLSearchParams; body: Json; params: string[] }) => Json | Promise<Json>;
const routes: [string, RegExp, Handler][] = [];
function route(method: string, path: string, handler: Handler): void {
  const re = new RegExp(`^${path.replace(/:[a-z]+/g, '([^/]+)')}$`);
  routes.push([method, re, handler]);
}

function crudRoutes<X extends { id: number }>(
  base: string,
  items: () => X[],
  make: (body: Record<string, unknown>, old: X | null) => X,
  label: string,
) {
  route('GET', base, () => all(items()));
  route('GET', `${base}/:id`, ({ params }) => byId(items(), Number(params[0])));
  route('POST', base, ({ body }) => {
    const it = make(obj(body), null);
    items().push(it);
    refreshGroupCounts();
    audit(`${label}.create`, `${label}:${it.id}`);
    return it;
  });
  route('PATCH', `${base}/:id`, ({ params, body }) => {
    const list = items();
    const old = byId(list, Number(params[0]));
    const next = make(obj(body), old);
    list[list.indexOf(old)] = next;
    refreshGroupCounts();
    audit(`${label}.update`, `${label}:${old.id}`, Object.keys(obj(body)).join(','));
    return next;
  });
  route('DELETE', `${base}/:id`, ({ params }) => {
    const list = items();
    const old = byId(list, Number(params[0]));
    list.splice(list.indexOf(old), 1);
    refreshGroupCounts();
    audit(`${label}.delete`, `${label}:${old.id}`);
    return undefined;
  });
}

// Auth
route('POST', '/auth/login', ({ body }) => {
  const now = Date.now();
  if (now < state.banUntilMs) {
    const wait = Math.ceil((state.banUntilMs - now) / 1000);
    throw new HttpError(429, 'rate_limited', 'Too many failed logins. Wait and try again.', undefined, wait);
  }
  const b = obj(body);
  if (state.totp.enabled && (b.totp === undefined || b.totp === '')) {
    throw new HttpError(401, 'totp_required', 'Enter the code from your authenticator app.');
  }
  const okPassword = b.password === MOCK_PASSWORD;
  const okTotp = !state.totp.enabled || /^\d{6}$/.test(String(b.totp));
  if (!okPassword || !okTotp) {
    state.failures += 1;
    audit('auth.login_failed', null, null, 'error');
    if (state.failures >= BAN_AFTER) {
      state.banUntilMs = now + BAN_SECONDS * 1000;
      state.failures = 0;
      audit('auth.ban', null, `seconds=${BAN_SECONDS}`);
    }
    throw new HttpError(401, 'invalid_credentials', 'The password or the code is not correct.');
  }
  state.failures = 0;
  state.authed = true;
  state.csrf = randomToken(32);
  audit('auth.login', null);
  return { csrf_token: state.csrf, expires_at: iso(now + 86400_000), totp_enabled: state.totp.enabled };
});
route('POST', '/auth/logout', () => {
  audit('auth.logout', null);
  state.authed = false;
  state.csrf = null;
  return undefined;
});
route('GET', '/auth/session', () => ({
  csrf_token: state.csrf,
  expires_at: iso(Date.now() + 86400_000),
  totp_enabled: state.totp.enabled,
}));
route('GET', '/auth/totp', () => state.totp);
route('POST', '/auth/totp/setup', ({ body }) => {
  if (obj(body).password !== MOCK_PASSWORD) throw new HttpError(401, 'invalid_credentials', 'The password is not correct.');
  if (state.totp.enabled) throw new HttpError(409, 'conflict', 'TOTP is already on.');
  state.totp = { enabled: false, pending: true };
  audit('totp.setup', null);
  return {
    otpauth_uri: `otpauth://totp/rusthole:admin?secret=${randomBase32(32)}&issuer=rusthole&algorithm=SHA1&digits=6&period=30`,
    expires_at: iso(Date.now() + 600_000),
  };
});
route('POST', '/auth/totp/confirm', ({ body }) => {
  if (!state.totp.pending) throw new HttpError(409, 'conflict', 'Start the setup first.');
  if (!/^\d{6}$/.test(String(obj(body).code))) throw new HttpError(401, 'invalid_credentials', 'The code is not correct.');
  state.totp = { enabled: true, pending: false };
  audit('totp.enable', null);
  return state.totp;
});
route('POST', '/auth/totp/disable', ({ body }) => {
  const b = obj(body);
  if (b.password !== MOCK_PASSWORD || !/^\d{6}$/.test(String(b.code))) {
    throw new HttpError(401, 'invalid_credentials', 'The password or the code is not correct.');
  }
  state.totp = { enabled: false, pending: false };
  audit('totp.disable', null);
  return state.totp;
});

// Blocking
route('GET', '/blocking', () => blockingState());
route('PUT', '/blocking', ({ body }) => {
  const b = obj(body);
  onlyFields(b, ['enabled', 'duration_seconds']);
  if (typeof b.enabled !== 'boolean') invalid('enabled', 'Use true or false.');
  const d = b.duration_seconds;
  if (d !== undefined) {
    if (b.enabled) invalid('duration_seconds', 'A timer is only for "enabled": false.');
    if (typeof d !== 'number' || !Number.isInteger(d) || d < 1 || d > 86400) invalid('duration_seconds', 'Use 1 to 86400 seconds.');
  }
  state.blocking = { enabled: b.enabled as boolean, untilMs: d === undefined ? null : Date.now() + (d as number) * 1000 };
  audit('blocking.set', null, `enabled=${String(b.enabled)}${d ? ` duration=${String(d)}` : ''}`);
  return blockingState();
});

// Statistics
route('GET', '/stats/summary', ({ q }) => {
  const r = range(q);
  const tl = timeline(r, Date.now(), MOCK_CLIENTS);
  const sum = (a: number[]) => a.reduce((s, x) => s + x, 0);
  const queries = sum(tl.queries);
  const blocked = sum(tl.blocked);
  const cached = sum(tl.cached);
  const local = Math.round(queries * 0.011);
  return {
    range: r,
    from: tl.from,
    to: tl.to,
    queries,
    blocked,
    blocked_percent: pct(blocked, queries),
    cached,
    forwarded: Math.max(0, sum(tl.forwarded) - local),
    local,
    unique_domains: MOCK_DOMAINS.length * 37 + (r === '24h' ? 0 : r === '7d' ? 610 : 1440),
    unique_clients: MOCK_CLIENTS.length,
  } satisfies T.Summary;
});
route('GET', '/stats/timeline', ({ q }) => {
  const r = range(q);
  const key = q.get('client');
  const clients = key ? [findClient(key)] : MOCK_CLIENTS;
  return timeline(r, Date.now(), clients, q.get('domain') ?? undefined);
});
route('GET', '/stats/hours', ({ q }) => {
  const r = range(q);
  const key = q.get('client');
  const domain = q.get('domain');
  const base = q.get('base');
  if (domain && base) throw new HttpError(400, 'bad_request', 'Use domain or base, not both.');
  const clients = key ? [findClient(key)] : MOCK_CLIENTS;
  return hoursResponse(r, q, hoursFor(clients, r, Date.now(), (n, b) => (!domain || n === domain) && (!base || b === base)));
});
function topDomains(q: URLSearchParams, blocked: boolean): T.Page<T.TopDomain> {
  const r = range(q);
  const limit = Number(q.get('limit') ?? 10);
  const key = q.get('client');
  let rows: { name: string; base: string; queries: number; blocked: number }[];
  if (key) rows = clientNames(findClient(key), r, Date.now());
  else rows = domainRows(r);
  const items = rows
    .filter((x) => (blocked ? x.blocked > 0 : x.blocked === 0))
    .map((x) => ({ name: x.name, base: x.base, count: blocked ? x.blocked : x.queries }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
  return all(items);
}
route('GET', '/stats/top/domains', ({ q }) => topDomains(q, false));
route('GET', '/stats/top/blocked', ({ q }) => topDomains(q, true));
route('GET', '/stats/top/clients', ({ q }) => {
  const r = range(q);
  const limit = Number(q.get('limit') ?? 10);
  const items = MOCK_CLIENTS.map((c) => statsClient(c, r))
    .sort((a, b) => b.queries - a.queries)
    .slice(0, limit)
    .map((c) => ({ key: c.key, name: c.name, ip: c.ip, count: c.queries, blocked: c.blocked }));
  return all(items);
});
route('GET', '/stats/query-types', ({ q }) => {
  const days = { '24h': 1, '7d': 7, '30d': 30 }[range(q)];
  const base: [string, number][] = [['A', 30110], ['AAAA', 12002], ['HTTPS', 4100], ['PTR', 1210], ['TXT', 420], ['SRV', 210], ['SVCB', 98], ['MX', 40], ['TYPE65280', 3]];
  return all(base.map(([type, count]) => ({ type, count: Math.round(count * days) })));
});
route('GET', '/stats/upstreams', ({ q }) => {
  const days = { '24h': 1, '7d': 7, '30d': 30 }[range(q)];
  return all([
    { name: 'cache', kind: 'cache', count: 20114 * days, avg_ms: null },
    { name: '192.0.2.53:53', kind: 'upstream', count: 12100 * days, avg_ms: 18.4 },
    { name: '198.51.100.53:53', kind: 'upstream', count: 9330 * days, avg_ms: 24.9 },
    { name: 'blocked', kind: 'blocked', count: 6120 * days, avg_ms: null },
    { name: 'local', kind: 'local', count: 512 * days, avg_ms: null },
  ] satisfies T.UpstreamShare[]);
});
route('GET', '/stats/clients', ({ q }) => {
  const r = range(q);
  const filter = (q.get('q') ?? '').toLowerCase();
  let items = MOCK_CLIENTS.map((c) => statsClient(c, r));
  if (filter) {
    items = items.filter((c) => [c.name ?? '', c.ip, c.mac ?? ''].some((s) => s.toLowerCase().includes(filter)));
  }
  return page(sortBy(items, q.get('sort'), (c) => c.name ?? c.ip), q);
});
route('GET', '/stats/clients/:key', ({ q, params }) => {
  const r = range(q);
  const c = findClient(decodeURIComponent(params[0]!));
  const base = statsClient(c, r);
  const t = clientTotals(c, r, Date.now());
  const cfg = configuredFor(c);
  return {
    ...base,
    ips: c.mac ? [c.ip, c.ip.replace(/\.(\d+)$/, (_m, n: string) => `.${Number(n) + 100}`)] : [c.ip],
    groups: cfg ? cfg.groups : [0],
    range: r,
    unique_bases: t.bases,
    utc_offset_minutes: Number(q.get('utc_offset_minutes') ?? 0),
    hours: hoursFor([c], r, Date.now(), () => true),
  } satisfies T.StatsClientDetail;
});
route('GET', '/stats/clients/:key/domains', ({ q, params }) => {
  const r = range(q);
  const c = findClient(decodeURIComponent(params[0]!));
  const filter = (q.get('q') ?? '').toLowerCase();
  const blockedOnly = q.get('blocked_only') === 'true';
  const namesLimit = Number(q.get('names_limit') ?? 50);
  let names = clientNames(c, r, Date.now());
  if (blockedOnly) names = names.filter((n) => n.blocked > 0);
  let groups = groupNamesByBase(names);
  if (filter) {
    groups = groupNamesByBase(
      names.filter((n) => n.name.includes(filter) || n.base.includes(filter)),
    );
  }
  groups = sortBy(groups, q.get('sort'), (g) => g.base).map((g) => ({ ...g, names: g.names.slice(0, namesLimit) }));
  return page(groups, q);
});
route('GET', '/stats/domains', ({ q }) => {
  const r = range(q);
  const text = (q.get('q') ?? '').toLowerCase().trim();
  if (!text) throw new HttpError(400, 'bad_request', 'q is required.');
  let rows = domainRows(r).filter((x) => x.name.includes(text));
  if (q.get('blocked_only') === 'true') rows = rows.filter((x) => x.blocked > 0);
  const items = rows
    .sort((a, b) => b.queries - a.queries)
    .map((x) => ({ name: x.name, base: x.base, queries: x.queries, blocked: x.blocked, clients: x.clients.size, last_seen_at: x.last_seen_at }));
  return page(items, q);
});
route('GET', '/stats/domains/:name', ({ q, params }) => {
  const r = range(q);
  const name = decodeURIComponent(params[0]!).toLowerCase();
  const known = MOCK_DOMAINS.find((x) => x.name === name);
  const clients: T.DomainClient[] = [];
  let first: string | null = null;
  let last: string | null = null;
  for (const c of MOCK_CLIENTS) {
    const n = clientNames(c, r, Date.now()).find((x) => x.name === name);
    if (!n) continue;
    clients.push({ key: c.key, name: clientName(c), ip: c.ip, queries: n.queries, blocked: n.blocked, last_seen_at: n.last_seen_at });
    if (!first || (n.first_seen_at && n.first_seen_at < first)) first = n.first_seen_at;
    if (!last || (n.last_seen_at && n.last_seen_at > last)) last = n.last_seen_at;
  }
  clients.sort((a, b) => b.queries - a.queries);
  const parts = name.split('.');
  return {
    name,
    base: known?.base ?? parts.slice(-2).join('.'),
    range: r,
    queries: clients.reduce((s, x) => s + x.queries, 0),
    blocked: clients.reduce((s, x) => s + x.blocked, 0),
    first_seen_at: first,
    last_seen_at: last,
    clients,
    utc_offset_minutes: Number(q.get('utc_offset_minutes') ?? 0),
    hours: hoursFor(MOCK_CLIENTS, r, Date.now(), (n) => n === name),
  } satisfies T.DomainDetail;
});

// Recent queries
route('GET', '/queries/recent', ({ q }) => {
  const limit = Number(q.get('limit') ?? 100);
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new HttpError(400, 'bad_request', 'limit must be 1 to 1000.');
  const client = q.get('client');
  const status = q.get('status');
  const text = (q.get('q') ?? '').toLowerCase();
  const items = recentQueries(Date.now(), state.settings.stats.recent_queries_size).filter(
    (x) => (!client || x.client_key === client) && (!status || x.status === status) && (!text || x.name.includes(text)),
  );
  return all(items.slice(0, limit));
});

// Lists
route('GET', '/lists', () => {
  const interval = state.settings.lists.refresh_interval_hours;
  return {
    items: state.lists,
    next_cursor: null,
    schedule: {
      interval_hours: interval,
      next_run_at: interval > 0 ? iso(state.lastScheduleRunMs + interval * 3600_000) : null,
      running: state.lists.some((l) => l.status.state === 'updating'),
    },
  } satisfies T.ListsResponse;
});
function makeList(b: Record<string, unknown>, old: T.Adlist | null): T.Adlist {
  onlyFields(b, ['url', 'comment', 'kind', 'enabled', 'groups']);
  const url = b.url ?? old?.url;
  if (typeof url !== 'string' || !isHttpUrl(url)) invalid('url', 'Use an http or https URL.');
  if (state.lists.some((l) => l.url === url && l.id !== old?.id)) throw new HttpError(409, 'conflict', 'A list with this URL already exists.');
  const kind = b.kind ?? old?.kind ?? 'block';
  if (kind !== 'block' && kind !== 'allow') invalid('kind', 'Use block or allow.');
  return {
    id: old?.id ?? state.nextId++,
    url,
    comment: typeof b.comment === 'string' ? b.comment : (old?.comment ?? ''),
    kind,
    enabled: typeof b.enabled === 'boolean' ? b.enabled : (old?.enabled ?? true),
    groups: b.groups !== undefined ? checkGroups(b.groups) : (old?.groups ?? [0]),
    status: old?.status ?? { state: 'never', last_update_at: null, last_success_at: null, entries: 0, invalid_lines: 0, size_bytes: 0, last_error: null },
  };
}
route('POST', '/lists', ({ body }) => {
  const l = makeList(obj(body), null);
  state.lists.push(l);
  refreshGroupCounts();
  audit('list.create', `list:${l.id}`);
  startListUpdate([l.id]);
  return l;
});
route('PATCH', '/lists/:id', ({ params, body }) => {
  const old = byId(state.lists, Number(params[0]));
  const next = makeList(obj(body), old);
  state.lists[state.lists.indexOf(old)] = next;
  refreshGroupCounts();
  audit('list.update', `list:${old.id}`, Object.entries(obj(body)).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(' '));
  return next;
});
route('DELETE', '/lists/:id', ({ params }) => {
  const old = byId(state.lists, Number(params[0]));
  state.lists.splice(state.lists.indexOf(old), 1);
  refreshGroupCounts();
  audit('list.delete', `list:${old.id}`);
  return undefined;
});
route('POST', '/lists/update', () => {
  if (state.lists.some((l) => l.status.state === 'updating')) throw new HttpError(503, 'unavailable', 'An update already runs.');
  startListUpdate(state.lists.filter((l) => l.enabled).map((l) => l.id));
  audit('list.refresh', 'list:all');
  return { started: true };
});
route('POST', '/lists/:id/update', ({ params }) => {
  const l = byId(state.lists, Number(params[0]));
  if (l.status.state === 'updating') throw new HttpError(503, 'unavailable', 'An update of this list already runs.');
  startListUpdate([l.id]);
  audit('list.refresh', `list:${l.id}`);
  return { started: true };
});

// Domain report (docs/API.md section 17). Fixed data, no network.
const REPORT_SECTIONS: T.ReportSection[] = ['dns', 'rdap', 'tls'];
route('GET', '/report/domain/:name/:section', ({ q, params }) => {
  const name = decodeURIComponent(params[0]!).trim().toLowerCase();
  const section = params[1] as T.ReportSection;
  if (!/^[a-z0-9.-]+$/.test(name) || name.length > 253) throw new HttpError(400, 'bad_request', 'The name is not a valid domain name.');
  if (!REPORT_SECTIONS.includes(section)) throw new HttpError(400, 'bad_request', `Unknown section. Use one of: ${REPORT_SECTIONS.join(', ')}.`);
  const refresh = q.get('refresh');
  if (refresh !== null && !['true', 'false', '1', '0'].includes(refresh)) throw new HttpError(400, 'bad_request', '`refresh` is true or false.');
  const parts = name.split('.');
  const base = parts.slice(-2).join('.');
  const fetched_at = new Date().toISOString().replace(/[.][0-9]+Z$/, 'Z');
  if ((section === 'rdap' || section === 'tls') && !state.settings.report.external) {
    return { section, name, status: 'off', cached: false, fetched_at, data: null, error: 'turned off in the settings (report.external)' } satisfies T.ReportResult;
  }
  if (section === 'tls') {
    const nowS = Math.floor(Date.now() / 1000);
    const tls: T.TlsReport = {
      address: '203.0.113.80:443',
      trusted: true,
      trust_error: null,
      version: 'TLSv1_3',
      chain: [
        { subject: name, subject_org: null, issuer: 'Example CA R1', issuer_org: 'Example CA', names: [name, base], names_truncated: false, not_before: nowS - 30 * 86400, not_after: nowS + 60 * 86400, days_left: 60, self_signed: false, key: '1.2.840.10045.2.1', signature: '1.2.840.10045.4.3.2' },
        { subject: 'Example CA R1', subject_org: 'Example CA', issuer: 'Example Root', issuer_org: 'Example CA', names: [], names_truncated: false, not_before: nowS - 900 * 86400, not_after: nowS + 900 * 86400, days_left: 900, self_signed: false, key: '1.2.840.10045.2.1', signature: '1.2.840.10045.4.3.3' },
      ],
    };
    return { section, name, status: 'ok', cached: false, fetched_at, data: tls, error: null } satisfies T.ReportResult;
  }
  if (section === 'rdap') {
    if (!state.settings.report.external) {
      return { section, name, status: 'off', cached: false, fetched_at, data: null, error: 'turned off in the settings (report.external)' } satisfies T.ReportResult;
    }
    if (base.endsWith('.lan')) {
      return { section, name, status: 'unavailable', cached: false, fetched_at, data: { domain: base }, error: `IANA lists no RDAP server for ${base}` } satisfies T.ReportResult;
    }
    const rdap: T.RdapReport = {
      domain: base,
      server: 'https://rdap.example/',
      registrar: 'Example Registrar Inc.',
      registrar_iana_id: '9999',
      registrant: null,
      abuse_email: 'abuse@registrar.example',
      created: '2001-05-02T04:00:00Z',
      updated: '2025-01-01T00:00:00Z',
      expires: '2030-05-03T04:00:00Z',
      status: ['client transfer prohibited'],
      nameservers: [`ns1.${base}`, `ns2.${base}`],
      dnssec: false,
    };
    return { section, name, status: 'ok', cached: false, fetched_at, data: rdap, error: null } satisfies T.ReportResult;
  }
  const rec = (value: string) => [{ name, ttl: 300, value }];
  const t = (type: string, n: string, records: T.DnsRecord[]): T.DnsTypeResult => ({
    type, name: n, status: records.length > 0 ? 'ok' : 'nodata', rcode: 0, records, truncated: false, error: null,
  });
  const data: T.DnsReport = {
    name,
    base,
    cname_chain: name.startsWith('www.') ? [`${base}.cdn.example`] : [],
    types: [
      t('A', name, rec('192.0.2.80')),
      t('AAAA', name, []),
      t('MX', name, []),
      t('TXT', name, rec('v=spf1 -all')),
      t('CAA', name, []),
      t('NS', base, [{ name: base, ttl: 3600, value: `ns1.${base}` }]),
      { ...t('SOA', base, []), status: 'failed', rcode: null, error: 'no answer in 4500 ms' },
    ],
  };
  return { section, name, status: 'ok', cached: false, fetched_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), data, error: null } satisfies T.ReportResult<T.DnsReport>;
});

// Domain search: which list or rule blocks a name
route('GET', '/search/domain', ({ q }) => {
  const name = (q.get('name') ?? '').trim().toLowerCase();
  if (!name) throw new HttpError(400, 'bad_request', 'name is required.');
  const known = MOCK_DOMAINS.find((x) => x.name === name);
  const matches: T.DomainMatch[] = [];
  const list = (id: number) => state.lists.find((l) => l.id === id);
  if (known?.blocked && known.name !== 'use-application-dns.net' && list(1)) {
    const l = list(1)!;
    matches.push({ source: 'list', id: l.id, label: l.url, kind: l.kind, match: 'exact', pattern: name, enabled: l.enabled, groups: l.groups });
  }
  if (name.endsWith('tracker.example') && list(2)) {
    const l = list(2)!;
    matches.push({ source: 'list', id: l.id, label: l.url, kind: l.kind, match: 'parent', pattern: '||tracker.example^', enabled: l.enabled, groups: l.groups });
  }
  if (name.startsWith('img.') && list(6)) {
    const l = list(6)!;
    matches.push({ source: 'list', id: l.id, label: l.url, kind: l.kind, match: 'exact', pattern: name, enabled: l.enabled, groups: l.groups });
  }
  for (const r of state.rules) {
    // The mock is the only place that uses JavaScript RegExp. The real server uses Rust regex.
    let hit = false;
    if (r.kind === 'exact') hit = r.pattern === name;
    else {
      try {
        hit = new RegExp(r.pattern, 'i').test(name);
      } catch {
        hit = false;
      }
    }
    if (hit) {
      matches.push({ source: 'rule', id: r.id, label: r.comment || `${r.kind} ${r.action}`, kind: r.action === 'allow' ? 'allow' : 'block', match: r.kind === 'exact' ? 'exact' : 'regex', pattern: r.pattern, enabled: r.enabled, groups: r.groups });
    }
  }
  if (name === 'use-application-dns.net' || name === 'mask.icloud.com' || name === 'mask-h2.icloud.com') {
    matches.push({ source: 'special', id: null, label: name.startsWith('use') ? 'Firefox DoH canary' : 'iCloud Private Relay', kind: 'block', match: 'exact', pattern: name, enabled: state.settings.blocking.special_domains, groups: [] });
  }
  const verdicts = state.groups.map((g) => {
    const active = matches.filter((m) => m.enabled && (m.source === 'special' || m.groups.includes(g.id)));
    const allow = active.find((m) => m.kind === 'allow');
    const block = active.find((m) => m.kind === 'block');
    const by = (m: T.DomainMatch) => (m.source === 'special' ? 'special' : `${m.source}:${String(m.id)}`);
    if (allow) return { group_id: g.id, group_name: g.name, verdict: 'allowed' as const, by: by(allow) };
    if (block) return { group_id: g.id, group_name: g.name, verdict: 'blocked' as const, by: by(block) };
    return { group_id: g.id, group_name: g.name, verdict: 'none' as const, by: null };
  });
  return { name, verdicts, matches, truncated: false } satisfies T.DomainVerdicts;
});

// Rules
crudRoutes<T.Rule>('/rules', () => state.rules, (b, old) => {
  onlyFields(b, ['kind', 'action', 'pattern', 'enabled', 'groups', 'comment']);
  const kind = b.kind ?? old?.kind;
  const action = b.action ?? old?.action;
  const pattern = b.pattern ?? old?.pattern;
  if (kind !== 'exact' && kind !== 'regex') invalid('kind', 'Use exact or regex.');
  if (action !== 'allow' && action !== 'deny') invalid('action', 'Use allow or deny.');
  if (typeof pattern !== 'string' || pattern.trim() === '') invalid('pattern', 'Enter a pattern.');
  if (kind === 'regex') {
    try {
      new RegExp(pattern);
    } catch (e) {
      invalid('pattern', `The regex is not valid: ${(e as Error).message}`);
    }
  }
  if (state.rules.some((r) => r.kind === kind && r.action === action && r.pattern === pattern && r.id !== old?.id)) {
    throw new HttpError(409, 'conflict', 'This rule already exists.');
  }
  return {
    id: old?.id ?? state.nextId++,
    kind,
    action,
    pattern: kind === 'exact' ? pattern.trim().toLowerCase() : pattern,
    enabled: typeof b.enabled === 'boolean' ? b.enabled : (old?.enabled ?? true),
    groups: b.groups !== undefined ? checkGroups(b.groups) : (old?.groups ?? [0]),
    comment: typeof b.comment === 'string' ? b.comment : (old?.comment ?? ''),
    created_at: old?.created_at ?? iso(Date.now()),
    updated_at: iso(Date.now()),
  };
}, 'rule');
route('POST', '/rules/test', ({ body }) => {
  const b = obj(body);
  const pattern = String(b.pattern ?? '');
  const domain = String(b.domain ?? '').toLowerCase();
  if (b.kind === 'exact') return { valid: pattern !== '', matches: pattern.toLowerCase() === domain, error: null };
  try {
    return { valid: true, matches: new RegExp(pattern, 'i').test(domain), error: null };
  } catch (e) {
    return { valid: false, matches: false, error: (e as Error).message };
  }
});

// Groups. The name rule is `is_valid_group_name` of the server: 1 to 64 characters
// a-z, 0-9, '-', '_', '.', and the first one is a letter or a digit. Names are case
// sensitive, so a conflict needs the same name.
const GROUP_NAME = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
route('DELETE', '/groups/:id', ({ params }) => {
  const id = Number(params[0]);
  if (id === 0) throw new HttpError(409, 'conflict', 'The default group cannot be deleted.');
  const old = byId(state.groups, id);
  state.groups.splice(state.groups.indexOf(old), 1);
  for (const x of [...state.lists, ...state.rules, ...state.clients]) x.groups = x.groups.filter((g) => g !== id);
  refreshGroupCounts();
  audit('group.delete', `group:${old.id}`);
  return undefined;
});
crudRoutes<T.Group>('/groups', () => state.groups, (b, old) => {
  onlyFields(b, ['name', 'enabled', 'comment']);
  const raw = b.name ?? old?.name;
  const name = typeof raw === 'string' ? raw.trim() : '';
  if (!GROUP_NAME.test(name)) {
    invalid('name', "Use 1 to 64 characters: a-z, 0-9, '-', '_', '.'. Start with a letter or a digit.");
  }
  if (state.groups.some((g) => g.name === name && g.id !== old?.id)) {
    throw new HttpError(409, 'conflict', 'A group with this name exists.');
  }
  if (old?.id === 0 && name !== old.name) throw new HttpError(409, 'conflict', 'The default group cannot get a new name.');
  return {
    id: old?.id ?? state.nextId++,
    name,
    enabled: typeof b.enabled === 'boolean' ? b.enabled : (old?.enabled ?? true),
    comment: typeof b.comment === 'string' ? b.comment : (old?.comment ?? ''),
    lists: old?.lists ?? 0,
    rules: old?.rules ?? 0,
    clients: old?.clients ?? 0,
  };
}, 'group');

// Clients
route('GET', '/clients/seen', ({ q }) => {
  const items: T.SeenClient[] = MOCK_CLIENTS.map((c) => ({
    ip: c.ip,
    mac: c.mac,
    name: c.host,
    first_seen_at: ago(firstSeenDays(c) * 86400),
    last_seen_at: statsClient(c, '30d').last_seen_at,
    // The server counts the queries of the last 30 days (Range::Month).
    queries: clientTotals(c, '30d', Date.now()).queries,
    client_id: configuredFor(c)?.id ?? null,
  }));
  items.push({ ip: '192.0.2.31', mac: '02:00:00:00:00:31', name: null, first_seen_at: ago(3600 * 5), last_seen_at: ago(600), queries: 37, client_id: null });
  return page(items, q, 200);
});
crudRoutes<T.Client>('/clients', () => state.clients, (b, old) => {
  onlyFields(b, ['match', 'groups', 'comment']);
  const match = typeof b.match === 'string' ? b.match.trim().toLowerCase() : old?.match;
  if (typeof match !== 'string') invalid('match', 'Enter an IP address, CIDR, MAC address or host name.');
  const kind = classifyClientMatch(match);
  if (!kind.ok) invalid('match', kind.error);
  if (state.clients.some((c) => c.match === match && c.id !== old?.id)) throw new HttpError(409, 'conflict', 'This client already exists.');
  return {
    id: old?.id ?? state.nextId++,
    match,
    kind: kind.value,
    groups: b.groups !== undefined ? checkGroups(b.groups) : (old?.groups ?? [0]),
    comment: typeof b.comment === 'string' ? b.comment : (old?.comment ?? ''),
  };
}, 'client');

// Local DNS
function hostField(b: Record<string, unknown>, key: string, fallback?: string): string {
  const v = b[key] ?? fallback;
  if (typeof v !== 'string' || !/^[a-z0-9_.-]+$/i.test(v)) invalid(key, 'Enter a valid domain name.');
  return v.toLowerCase();
}
function common<O extends { comment: string; enabled: boolean }>(b: Record<string, unknown>, old: O | null) {
  return {
    comment: typeof b.comment === 'string' ? b.comment : (old?.comment ?? ''),
    enabled: typeof b.enabled === 'boolean' ? b.enabled : (old?.enabled ?? true),
  };
}
crudRoutes<T.LocalRecord>('/dns/records', () => state.records, (b, old) => {
  onlyFields(b, ['name', 'type', 'address', 'comment', 'enabled']);
  const name = hostField(b, 'name', old?.name);
  const type = b.type ?? old?.type;
  const address = b.address ?? old?.address;
  if (type !== 'A' && type !== 'AAAA') invalid('type', 'Use A or AAAA.');
  if (typeof address !== 'string') invalid('address', 'Enter an address.');
  if (type === 'A' && !isIPv4(address)) invalid('address', 'An A record needs an IPv4 address.');
  if (type === 'AAAA' && !looksLikeIPv6(address)) invalid('address', 'An AAAA record needs an IPv6 address.');
  if (state.cnames.some((c) => c.name === name)) throw new HttpError(409, 'conflict', 'This name already has a CNAME.');
  return { id: old?.id ?? state.nextId++, name, type, address, ...common(b, old) };
}, 'dns');
crudRoutes<T.LocalCname>('/dns/cnames', () => state.cnames, (b, old) => {
  onlyFields(b, ['name', 'target', 'comment', 'enabled']);
  const name = hostField(b, 'name', old?.name);
  if (state.records.some((r) => r.name === name)) throw new HttpError(409, 'conflict', 'This name already has an A or AAAA record.');
  return { id: old?.id ?? state.nextId++, name, target: hostField(b, 'target', old?.target), ...common(b, old) };
}, 'dns');
crudRoutes<T.Forwarder>('/dns/forwarders', () => state.forwarders, (b, old) => {
  onlyFields(b, ['domain', 'servers', 'comment', 'enabled']);
  const servers = (b.servers ?? old?.servers) as string[];
  const err = Array.isArray(servers) ? checkServers(servers, 1) : 'Use a list of servers.';
  if (err) invalid('servers', err);
  const domainErr = checkForwardDomain(String(b.domain ?? old?.domain ?? ''));
  if (domainErr) invalid('domain', domainErr);
  return { id: old?.id ?? state.nextId++, domain: hostField(b, 'domain', old?.domain), servers, ...common(b, old) };
}, 'dns');

// Tokens
route('GET', '/tokens', () => all(state.tokens));
route('POST', '/tokens', ({ body }) => {
  const b = obj(body);
  if (typeof b.name !== 'string' || b.name.trim() === '') invalid('name', 'Enter a name.');
  if (b.password !== MOCK_PASSWORD) throw new HttpError(401, 'invalid_credentials', 'The password is not correct.');
  const secret = `rh_${randomToken(32)}`;
  const token: T.ApiToken = { id: state.nextId++, name: b.name.trim(), prefix: secret.slice(0, 7), created_at: iso(Date.now()), last_used_at: null, last_used_ip: null };
  state.tokens.push(token);
  audit('token.create', `token:${token.id}`);
  return { token, secret } satisfies T.CreatedToken;
});
route('DELETE', '/tokens/:id', ({ params }) => {
  const t = byId(state.tokens, Number(params[0]));
  state.tokens.splice(state.tokens.indexOf(t), 1);
  audit('token.revoke', `token:${t.id}`);
  return undefined;
});

// Settings
function settingsOut(): T.Settings {
  return { ...structuredClone(state.settings), restart_required: state.restartRequired };
}
route('GET', '/settings', () => settingsOut());
route('PATCH', '/settings', ({ body }) => {
  const b = obj(body);
  // `restart_required` is read-only: the server refuses it as an unknown field.
  onlyFields(b, ['upstreams', 'blocking', 'cache', 'rate_limit', 'acl', 'stats', 'lists', 'report']);
  const next = structuredClone(state.settings);
  if (b.upstreams) {
    const u = b.upstreams as T.Settings['upstreams'];
    const servers = Array.isArray(u.servers) ? u.servers : [];
    const errors = upstreamErrors(servers, u.timeout_ms, state.settings.upstreams.servers);
    if (errors.length > 0) throw new HttpError(422, 'validation_failed', 'The request has invalid fields.', errors);
    next.upstreams = { servers: servers.map((x) => x.trim()), timeout_ms: u.timeout_ms };
  }
  if (b.acl) {
    const a = b.acl as Record<string, unknown>;
    if ('local_subnets' in a) invalid('acl.local_subnets', 'This field is read-only.');
    const cidrs = (a.extra_cidrs ?? []) as string[];
    const err = checkCidrs(cidrs, 64);
    if (err) invalid('acl.extra_cidrs', err);
    next.acl = { ...next.acl, extra_cidrs: cidrs };
  }
  if (b.blocking) {
    const bl = b.blocking as T.Settings['blocking'];
    if (bl.mode === 'custom_ip' && (!bl.custom_ipv4 || !isIPv4(bl.custom_ipv4))) invalid('blocking.custom_ipv4', 'Enter an IPv4 address.');
    next.blocking = bl;
  }
  if (b.cache) {
    const c = b.cache as T.Settings['cache'];
    if (c.min_ttl > c.max_ttl) invalid('cache.min_ttl', 'min_ttl must not be more than max_ttl.');
    next.cache = c;
  }
  if (b.rate_limit) next.rate_limit = b.rate_limit as T.Settings['rate_limit'];
  if (b.stats) {
    const s = b.stats as T.Settings['stats'];
    if (s.flush_interval_seconds !== 0 && (s.flush_interval_seconds < 10 || s.flush_interval_seconds > 3600)) {
      invalid('stats.flush_interval_seconds', 'Use 0, or 10 to 3600.');
    }
    if (s.retention_days < 1 || s.retention_days > 365) invalid('stats.retention_days', 'Use 1 to 365.');
    if (s.recent_queries_size < 100 || s.recent_queries_size > 100000) invalid('stats.recent_queries_size', 'Use 100 to 100000.');
    next.stats = s;
  }
  if (b.report) next.report = { external: Boolean((b.report as T.Settings['report']).external) };
  if (b.lists) {
    const l = b.lists as T.Settings['lists'];
    if (l.refresh_interval_hours < 0 || l.refresh_interval_hours > 168) invalid('lists.refresh_interval_hours', 'Use 0, or 1 to 168.');
    next.lists = l;
  }
  // As `restart_fields_changed` of the server: a real change of upstreams or stats
  // needs a restart. The flag stays true until the restart.
  if (JSON.stringify(next.upstreams) !== JSON.stringify(state.settings.upstreams) || JSON.stringify(next.stats) !== JSON.stringify(state.settings.stats)) {
    state.restartRequired = true;
  }
  state.settings = next;
  audit('settings.update', 'settings', `sections=${Object.keys(b).join(',')}`);
  return settingsOut();
});

// Audit and system
route('GET', '/audit', ({ q }) => {
  const prefix = q.get('action') ?? '';
  return page(state.audit.filter((a) => a.action.startsWith(prefix)), q);
});
route('GET', '/system', () => ({
  version: '0.1.0-mock',
  commit: null,
  started_at: iso(state.startedMs),
  uptime_seconds: Math.floor((Date.now() - state.startedMs) / 1000),
  memory_rss_bytes: 41943040,
  list_entries: state.lists.filter((l) => l.enabled).reduce((s, l) => s + l.status.entries, 0),
  config_path: '/etc/rusthole/rusthole.toml',
  data_dir: '/var/lib/rusthole',
  os: 'linux',
  arch: 'aarch64',
  // The server sends one row for each bound address. With the packaged config
  // ("auto"), a host with a LAN address has two dns rows and two admin rows.
  listeners: [
    { kind: 'dns', address: '127.0.0.1:53' },
    { kind: 'dns', address: '192.0.2.2:53' },
    { kind: 'doh', address: '192.0.2.2:443' },
    { kind: 'admin', address: '127.0.0.1:8443' },
    { kind: 'admin', address: '192.0.2.2:8443' },
  ],
}) satisfies T.SystemInfo);

// ---- fetch entry point ------------------------------------------------------

function json(status: number, body: Json, headers: Record<string, string> = {}): Response {
  if (status === 204 || body === undefined) return new Response(null, { status: 204, headers });
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

function errorResponse(e: HttpError): Response {
  const headers: Record<string, string> = {};
  if (e.retryAfter !== undefined) headers['Retry-After'] = String(e.retryAfter);
  return json(
    e.status,
    { code: e.code, message: e.message, details: e.details, retry_after_seconds: e.retryAfter ?? null },
    headers,
  );
}

export interface MockOptions {
  /** Delay of each answer in ms, to look like a network. */
  latencyMs?: number;
}

/** A fetch function that answers /api/v1 requests from the mock state. */
export function createMockFetch(options: MockOptions = {}) {
  const latency = options.latencyMs ?? 120;
  return async function mockFetch(input: string, init: RequestInit = {}): Promise<Response> {
    if (latency > 0) await new Promise((r) => setTimeout(r, latency * (0.5 + Math.random())));
    if (init.signal?.aborted) throw new DOMException('The request was stopped.', 'AbortError');
    const url = new URL(input, 'https://rusthole.invalid');
    const path = url.pathname.replace(/^\/api\/v1/, '');
    const method = (init.method ?? 'GET').toUpperCase();
    const headers = (init.headers ?? {}) as Record<string, string>;
    try {
      const isLogin = method === 'POST' && path === '/auth/login';
      if (!isLogin && !state.authed) throw new HttpError(401, 'unauthorized', 'Log in first.');
      if (!isLogin && method !== 'GET' && headers['X-CSRF-Token'] !== state.csrf) {
        throw new HttpError(403, 'csrf_failed', 'The X-CSRF-Token header is missing or not valid.');
      }
      let body: Json = undefined;
      if (typeof init.body === 'string' && init.body !== '') {
        try {
          body = JSON.parse(init.body) as Json;
        } catch {
          throw new HttpError(400, 'bad_request', 'The body is not valid JSON.');
        }
      }
      let pathMatched = false;
      for (const [m, re, handler] of routes) {
        const match = re.exec(path);
        if (!match) continue;
        pathMatched = true;
        if (m !== method) continue;
        const result = await handler({ q: url.searchParams, body, params: match.slice(1) });
        const status = method === 'POST' && result !== undefined && /^\/(lists|rules|groups|clients|dns\/\w+|tokens)$/.test(path) ? 201 : method === 'POST' && /\/update$/.test(path) ? 202 : 200;
        return json(status, result);
      }
      if (pathMatched) throw new HttpError(405, 'method_not_allowed', 'This method is not allowed here.');
      throw new HttpError(404, 'not_found', 'The path does not exist.');
    } catch (e) {
      if (e instanceof HttpError) return errorResponse(e);
      return json(500, { code: 'internal', message: `Mock fault: ${(e as Error).message}` });
    }
  };
}

