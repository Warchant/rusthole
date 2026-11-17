// Synthetic statistics for the mock API. All names and addresses are neutral:
// IPs from 192.0.2.0/24 (TEST-NET-1), local MACs 02:00:00:00:00:xx, and
// domains under example.com/.net/.org or the reserved ".example" TLD.
// The data is deterministic: a seeded generator makes the same values each time.

import type {
  DomainGroup,
  DomainName,
  HourArrays,
  QueryStatus,
  Range,
  RecentQuery,
  Timeline,
} from '../api/types';

/** mulberry32: a small seeded PRNG. Returns values in [0, 1). */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hashString(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}

type Profile = 'work' | 'evening' | 'flat' | 'night';

export interface MockClient {
  key: string;
  ip: string;
  mac: string | null;
  host: string | null;
  /** Queries per day. */
  volume: number;
  profile: Profile;
  /** Extra weight for ad and tracker names (0 to 1). */
  adBias: number;
}

export const MOCK_CLIENTS: MockClient[] = [
  { key: '02:00:00:00:00:01', ip: '192.0.2.10', mac: '02:00:00:00:00:01', host: 'laptop.lan', volume: 4200, profile: 'work', adBias: 0.3 },
  { key: '02:00:00:00:00:02', ip: '192.0.2.11', mac: '02:00:00:00:00:02', host: 'phone.lan', volume: 3100, profile: 'evening', adBias: 0.6 },
  { key: '02:00:00:00:00:03', ip: '192.0.2.12', mac: '02:00:00:00:00:03', host: 'tv.lan', volume: 2600, profile: 'evening', adBias: 1 },
  { key: '02:00:00:00:00:04', ip: '192.0.2.13', mac: '02:00:00:00:00:04', host: 'tablet.lan', volume: 1500, profile: 'evening', adBias: 0.7 },
  { key: '02:00:00:00:00:05', ip: '192.0.2.14', mac: '02:00:00:00:00:05', host: 'printer.lan', volume: 140, profile: 'flat', adBias: 0.1 },
  { key: '02:00:00:00:00:06', ip: '192.0.2.20', mac: '02:00:00:00:00:06', host: 'nas.lan', volume: 900, profile: 'flat', adBias: 0.05 },
  { key: '02:00:00:00:00:07', ip: '192.0.2.15', mac: '02:00:00:00:00:07', host: 'console.lan', volume: 1100, profile: 'night', adBias: 0.5 },
  { key: '02:00:00:00:00:08', ip: '192.0.2.16', mac: '02:00:00:00:00:08', host: 'watch.lan', volume: 300, profile: 'flat', adBias: 0.4 },
  { key: '192.0.2.150', ip: '192.0.2.150', mac: null, host: null, volume: 420, profile: 'evening', adBias: 0.5 },
];

export interface MockDomain {
  name: string;
  base: string;
  weight: number;
  blocked: boolean;
  ad: boolean;
}

function d(name: string, base: string, weight: number, blocked = false, ad = blocked): MockDomain {
  return { name, base, weight, blocked, ad };
}

export const MOCK_DOMAINS: MockDomain[] = [
  d('www.example.com', 'example.com', 10),
  d('cdn.example.com', 'example.com', 8),
  d('api.example.com', 'example.com', 6),
  d('static.example.com', 'example.com', 4),
  d('telemetry.example.com', 'example.com', 3, true),
  d('mail.example.org', 'example.org', 5),
  d('www.example.org', 'example.org', 4),
  d('img.example.org', 'example.org', 3),
  d('ads.example.net', 'example.net', 4, true),
  d('pixel.example.net', 'example.net', 3, true),
  d('www.example.net', 'example.net', 3),
  d('update.example.net', 'example.net', 1),
  d('www.video.example', 'video.example', 6),
  d('cdn1.video.example', 'video.example', 7),
  d('cdn2.video.example', 'video.example', 5),
  d('ads.video.example', 'video.example', 3, true),
  d('www.social.example', 'social.example', 6),
  d('graph.social.example', 'social.example', 5),
  d('track.social.example', 'social.example', 3, true),
  d('www.news.example', 'news.example', 4),
  d('img.news.example', 'news.example', 3),
  d('t.tracker.example', 'tracker.example', 4, true),
  d('collect.tracker.example', 'tracker.example', 3, true),
  d('sync.tracker.example', 'tracker.example', 2, true),
  d('beacon.metrics.example', 'metrics.example', 3, true),
  d('www.shop.example', 'shop.example', 3),
  d('checkout.shop.example', 'shop.example', 1),
  d('push.cloud.example', 'cloud.example', 4),
  d('sync.cloud.example', 'cloud.example', 4),
  d('time.cloud.example', 'cloud.example', 2),
  d('lobby.game.example', 'game.example', 3),
  d('ads.game.example', 'game.example', 2, true),
  d('nas.lan', 'nas.lan', 2, false),
  d('use-application-dns.net', 'use-application-dns.net', 0.5, true, false),
];

const PROFILES: Record<Profile, number[]> = {
  work: [1, 1, 0.5, 0.5, 0.5, 0.5, 1, 3, 6, 9, 10, 10, 8, 9, 10, 10, 9, 8, 6, 5, 4, 3, 2, 1],
  evening: [2, 1, 0.5, 0.3, 0.3, 0.3, 1, 3, 4, 3, 3, 3, 4, 3, 3, 3, 4, 6, 8, 10, 10, 9, 6, 4],
  flat: [5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5],
  night: [6, 5, 3, 1, 0.5, 0.3, 0.3, 0.3, 0.5, 1, 1, 1, 1, 1, 2, 3, 4, 5, 6, 8, 9, 10, 9, 8],
};

function profileShare(p: Profile, hour: number): number {
  const arr = PROFILES[p];
  const sum = arr.reduce((a, b) => a + b, 0);
  return (arr[((hour % 24) + 24) % 24] ?? 0) / sum;
}

export const RANGE_DAYS: Record<Range, number> = { '24h': 1, '7d': 7, '30d': 30 };
export const BUCKET_SECONDS: Record<Range, number> = { '24h': 600, '7d': 3600, '30d': 14400 };

interface Cell {
  domain: MockDomain;
  perDay: number;
}

const cellCache = new Map<string, Cell[]>();

/** The names that one client resolves, with queries per day. */
export function clientCells(c: MockClient): Cell[] {
  const cached = cellCache.get(c.key);
  if (cached) return cached;
  const r = rng(hashString(c.key));
  const cells: Cell[] = [];
  let total = 0;
  const raw: { domain: MockDomain; w: number }[] = [];
  for (const domain of MOCK_DOMAINS) {
    if (c.host === 'printer.lan' && !domain.base.startsWith('cloud') && domain.base !== 'example.com') continue;
    if (c.host === 'nas.lan' && domain.ad) continue;
    if (r() < 0.25) continue;
    const w = domain.weight * (0.3 + r()) * (domain.ad ? 0.4 + c.adBias * 1.6 : 1);
    raw.push({ domain, w });
    total += w;
  }
  for (const { domain, w } of raw) {
    cells.push({ domain, perDay: Math.max(1, Math.round((c.volume * w) / total)) });
  }
  cellCache.set(c.key, cells);
  return cells;
}

/** First seen offset in days before now, per client (stable). */
export function firstSeenDays(c: MockClient): number {
  return 12 + (hashString(c.key) % 18);
}

export interface Totals {
  queries: number;
  blocked: number;
}

function scale(perDay: number, range: Range, key: string): number {
  const jitter = 0.9 + rng(hashString(key + range))() * 0.2;
  return Math.round(perDay * RANGE_DAYS[range] * jitter);
}

export function clientNames(c: MockClient, range: Range, nowMs: number): (DomainName & { base: string })[] {
  return clientCells(c).map(({ domain, perDay }) => {
    const queries = scale(perDay, range, c.key + domain.name);
    const r = rng(hashString(c.key + domain.name + 'seen'));
    const lastAgo = Math.floor(r() * 3 * 3600 * (domain.weight < 2 ? 6 : 1));
    const firstAgo = Math.floor((firstSeenDays(c) - r() * 5) * 86400);
    return {
      name: domain.name,
      base: domain.base,
      queries,
      blocked: domain.blocked ? queries : 0,
      first_seen_at: new Date(nowMs - firstAgo * 1000).toISOString(),
      last_seen_at: new Date(nowMs - lastAgo * 1000).toISOString(),
    };
  });
}

export function clientTotals(c: MockClient, range: Range, nowMs: number): Totals & { unique: number; bases: number } {
  const names = clientNames(c, range, nowMs);
  return {
    queries: names.reduce((s, n) => s + n.queries, 0),
    blocked: names.reduce((s, n) => s + n.blocked, 0),
    unique: names.length,
    bases: new Set(names.map((n) => n.base)).size,
  };
}

export function groupNamesByBase(names: (DomainName & { base: string })[]): DomainGroup[] {
  const map = new Map<string, DomainGroup>();
  for (const n of names) {
    let g = map.get(n.base);
    if (!g) {
      g = { base: n.base, queries: 0, blocked: 0, first_seen_at: null, last_seen_at: null, names_total: 0, names: [] };
      map.set(n.base, g);
    }
    g.queries += n.queries;
    g.blocked += n.blocked;
    g.names_total += 1;
    const { base: _base, ...name } = n;
    g.names.push(name);
    if (!g.first_seen_at || (n.first_seen_at && n.first_seen_at < g.first_seen_at)) g.first_seen_at = n.first_seen_at;
    if (!g.last_seen_at || (n.last_seen_at && n.last_seen_at > g.last_seen_at)) g.last_seen_at = n.last_seen_at;
  }
  for (const g of map.values()) g.names.sort((a, b) => b.queries - a.queries);
  return [...map.values()];
}

/** Spreads a total over 24 hours with the client profile and a little noise. */
function spreadHours(total: number, profile: Profile, seed: number): number[] {
  const r = rng(seed);
  return Array.from({ length: 24 }, (_, h) => Math.round(total * profileShare(profile, h) * (0.85 + r() * 0.3)));
}

export function hoursFor(
  clients: MockClient[],
  range: Range,
  nowMs: number,
  filter: (domain: string, base: string) => boolean,
): HourArrays {
  const queries = new Array<number>(24).fill(0);
  const blocked = new Array<number>(24).fill(0);
  for (const c of clients) {
    for (const n of clientNames(c, range, nowMs)) {
      if (!filter(n.name, n.base)) continue;
      const q = spreadHours(n.queries, c.profile, hashString(c.key + n.name));
      q.forEach((v, h) => {
        queries[h] = (queries[h] ?? 0) + v;
        if (n.blocked > 0) blocked[h] = (blocked[h] ?? 0) + v;
      });
    }
  }
  return { queries, blocked };
}

export function timeline(range: Range, nowMs: number, clients: MockClient[], domain?: string): Timeline {
  const bucket = BUCKET_SECONDS[range];
  const n = Math.round((RANGE_DAYS[range] * 86400) / bucket);
  const endMs = Math.ceil(nowMs / (bucket * 1000)) * bucket * 1000;
  const fromMs = endMs - n * bucket * 1000;
  const out: Timeline = {
    range,
    from: new Date(fromMs).toISOString(),
    to: new Date(endMs).toISOString(),
    bucket_seconds: bucket,
    queries: [],
    blocked: [],
    cached: [],
    forwarded: [],
  };
  const perClient = clients.map((c) => {
    const names = clientNames(c, '24h', nowMs).filter((x) => !domain || x.name === domain);
    const q = names.reduce((s, x) => s + x.queries, 0);
    const b = names.reduce((s, x) => s + x.blocked, 0);
    return { c, q, b };
  });
  for (let i = 0; i < n; i++) {
    const t = fromMs + i * bucket * 1000;
    const hour = new Date(t).getHours();
    const r = rng(Math.floor(t / 1000) ^ hashString(domain ?? ''));
    let q = 0;
    let b = 0;
    for (const { c, q: cq, b: cb } of perClient) {
      const share = profileShare(c.profile, hour) * (bucket / 3600);
      const noise = 0.75 + r() * 0.5;
      q += cq * share * noise;
      b += cb * share * noise;
    }
    // The last bucket is partial.
    const part = i === n - 1 ? Math.min(1, (nowMs - t) / (bucket * 1000)) : 1;
    const qi = Math.round(q * part);
    const bi = Math.min(qi, Math.round(b * part));
    const cached = Math.round((qi - bi) * (0.38 + r() * 0.1));
    out.queries.push(qi);
    out.blocked.push(bi);
    out.cached.push(cached);
    out.forwarded.push(Math.max(0, qi - bi - cached));
  }
  return out;
}

const TYPES = ['A', 'AAAA', 'HTTPS', 'A', 'A', 'AAAA', 'PTR', 'A', 'TXT', 'SRV'];
const UPSTREAMS = ['192.0.2.53:53', '198.51.100.53:53'];

/** A "live" ring buffer: entry j happens at second 3j, so new entries come with time. */
export function recentQueries(nowMs: number, count: number): RecentQuery[] {
  const seq = Math.floor(nowMs / 3000);
  const out: RecentQuery[] = [];
  for (let i = 0; i < count; i++) {
    const j = seq - i;
    const r = rng(j);
    const c = MOCK_CLIENTS[Math.floor(r() * MOCK_CLIENTS.length)] ?? MOCK_CLIENTS[0]!;
    const cells = clientCells(c);
    const cell = cells[Math.floor(r() * cells.length)] ?? cells[0]!;
    const roll = r();
    let status: QueryStatus;
    if (cell.domain.blocked) status = 'blocked';
    else if (cell.domain.name.endsWith('.lan')) status = 'local';
    else if (roll < 0.45) status = 'cached';
    else if (roll < 0.995) status = 'forwarded';
    else status = 'error';
    const upstream = status === 'forwarded' ? (UPSTREAMS[Math.floor(r() * 2)] ?? null) : null;
    out.push({
      at: new Date(j * 3000 - Math.floor(r() * 2500)).toISOString(),
      client_key: c.key,
      client_ip: c.ip,
      client_name: c.host,
      name: cell.domain.name,
      type: TYPES[Math.floor(r() * TYPES.length)] ?? 'A',
      status,
      reason:
        status === 'blocked'
          ? cell.domain.base === 'tracker.example'
            ? 'list:2'
            : cell.domain.name === 'use-application-dns.net'
              ? 'special'
              : 'list:1'
          : status === 'local'
            ? 'local:1'
            : null,
      upstream,
      duration_ms:
        status === 'forwarded' ? Math.round((8 + r() * 40) * 10) / 10 : Math.round(r() * 5) / 10,
    });
  }
  return out;
}
