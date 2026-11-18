// A contract test of the mock (review item m28). It sends the requests of
// fixtures/real-api.json to the mock and compares the answers with the answers
// that a real rusthole server gave. A difference here hides faults of the UI.
import { beforeEach, describe, expect, it } from 'vitest';
import recorded from './fixtures/real-api.json';
import { changeMock, createMockFetch, MOCK_PASSWORD, resetMock } from './server';

interface Case {
  name: string;
  method: string;
  path: string;
  body?: unknown;
  response: { status: number; body: unknown };
}

const CASES = (recorded as { cases: Case[] }).cases;

/** The JSON type of each value. `null` in the real answer matches any type. */
function shape(v: unknown): unknown {
  if (v === null) return 'null';
  if (Array.isArray(v)) return v.map(shape);
  if (typeof v === 'object') {
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, x]) => [k, shape(x)]));
  }
  return typeof v;
}

/** Compares the shape of a mock answer with a real answer. Returns the differences. */
function diff(real: unknown, mock: unknown, path = '$'): string[] {
  if (real === 'null') return [];
  if (Array.isArray(real)) {
    if (!Array.isArray(mock)) return [`${path}: array in the real answer`];
    const first = real[0];
    if (first === undefined) return [];
    return mock.flatMap((m, i) => diff(first, m, `${path}[${i}]`));
  }
  if (typeof real === 'object' && real !== null) {
    if (typeof mock !== 'object' || mock === null || Array.isArray(mock)) return [`${path}: object in the real answer`];
    const r = real as Record<string, unknown>;
    const m = mock as Record<string, unknown>;
    const keys = new Set([...Object.keys(r), ...Object.keys(m)]);
    return [...keys].flatMap((k) => {
      if (!(k in m)) return [`${path}.${k}: missing in the mock`];
      if (!(k in r)) return [`${path}.${k}: not in the real answer`];
      return diff(r[k], m[k], `${path}.${k}`);
    });
  }
  return real === mock || mock === 'null' ? [] : [`${path}: ${String(real)} in the real answer, ${String(mock)} in the mock`];
}

let mockFetch = createMockFetch({ latencyMs: 0 });
let csrf = '';

async function send(c: Case, token = csrf): Promise<{ status: number; body: unknown }> {
  let body = c.body;
  if (body === 'same cache section') {
    const now = await send({ name: 'get', method: 'GET', path: '/settings', response: { status: 200, body: null } });
    body = { cache: (now.body as { cache: unknown }).cache };
  }
  const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-CSRF-Token': token };
  const res = await mockFetch(`/api/v1${c.path}`, { method: c.method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, body: text ? (JSON.parse(text) as unknown) : null };
}

beforeEach(async () => {
  resetMock();
  // The same config as the recording: one group and the same upstreams.
  changeMock((s) => {
    s.groups.splice(1);
    for (const x of [...s.lists, ...s.rules, ...s.clients]) x.groups = [0];
    s.settings.upstreams = { servers: ['udp://192.0.2.53:53', 'tls://dns.example:853'], timeout_ms: 2000 };
  });
  mockFetch = createMockFetch({ latencyMs: 0 });
  const login = await mockFetch('/api/v1/auth/login', { method: 'POST', headers: {}, body: JSON.stringify({ password: MOCK_PASSWORD }) });
  csrf = ((await login.json()) as { csrf_token: string }).csrf_token;
});

describe('the mock agrees with recorded answers of the real API (m28)', () => {
  it('has the recorded cases', () => {
    expect(CASES.length).toBeGreaterThan(10);
  });

  it('gives the same status, error and shape for each recorded request, in order', async () => {
    for (const c of CASES) {
      const got = await send(c, c.name === 'csrf-stale' ? 'stale' : csrf);
      const real = c.response;
      expect(got.status, c.name).toBe(real.status);
      if (real.status >= 400) {
        const r = real.body as { code: string; message: string; details?: { field: string; message: string }[] };
        const m = got.body as typeof r;
        expect(m.code, c.name).toBe(r.code);
        expect((m.details ?? []).map((d) => d.field), c.name).toEqual((r.details ?? []).map((d) => d.field));
        if (c.name === 'patch-restart-field') {
          // The real message has a position in the JSON text, from serde.
          expect(m.details?.[0]?.message, c.name).toContain('unknown field `restart_required`');
        } else {
          expect(m.message, c.name).toBe(r.message);
          expect(m.details ?? [], c.name).toEqual(r.details ?? []);
        }
      } else {
        expect(diff(shape(real.body), shape(got.body)), c.name).toEqual([]);
      }
    }
  });

  it('sends the facts that the UI needs, as the real server does', async () => {
    const real = (name: string) => CASES.find((c) => c.name === name)!.response.body as Record<string, unknown>;
    const run = async (name: string) => (await send(CASES.find((c) => c.name === name)!)).body as Record<string, unknown>;
    // M4: GET /system has one row for each bound address, so a kind comes two times.
    const kinds = (b: Record<string, unknown>) => (b.listeners as { kind: string }[]).map((l) => l.kind);
    const dup = (k: string[]) => k.length > new Set(k).size;
    expect(dup(kinds(real('system')))).toBe(true);
    expect(dup(kinds(await run('system')))).toBe(true);
    // M5: GET /settings sends the config text of the upstreams.
    const servers = (b: Record<string, unknown>) => (b.upstreams as { servers: string[] }).servers;
    expect(servers(await run('settings'))).toEqual(servers(real('settings')));
    // M6: restart_required is false at start.
    expect((await run('settings')).restart_required).toBe(real('settings').restart_required);
    // Group names: the default group is "default".
    expect((await run('groups')).items).toMatchObject([{ id: 0, name: 'default' }]);
  });
});
