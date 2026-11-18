import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createClient } from '../api/client';
import { makeApi } from '../api/endpoints';
import { createMockFetch, MOCK_PASSWORD, resetMock } from './server';

function setup() {
  let csrf: string | null = null;
  const onUnauthorized = vi.fn();
  const onRateLimited = vi.fn();
  const mockFetch = createMockFetch({ latencyMs: 0 });
  const client = createClient({ fetch: mockFetch, getCsrfToken: () => csrf, onUnauthorized, onRateLimited });
  const api = makeApi(client);
  return {
    api,
    client,
    mockFetch,
    onUnauthorized,
    onRateLimited,
    async login() {
      const s = await api.auth.login({ password: MOCK_PASSWORD });
      csrf = s.csrf_token;
      return s;
    },
    dropCsrf() {
      csrf = null;
    },
  };
}

beforeEach(() => resetMock());

describe('mock API', () => {
  it('needs a session for every path except login', async () => {
    const t = setup();
    await expect(t.api.auth.session()).rejects.toMatchObject({ status: 401, code: 'unauthorized' });
    expect(t.onUnauthorized).toHaveBeenCalledTimes(1);
    const s = await t.login();
    expect(s.csrf_token.length).toBeGreaterThan(20);
    await expect(t.api.auth.session()).resolves.toMatchObject({ csrf_token: s.csrf_token });
  });

  it('rejects a write without the CSRF header', async () => {
    const t = setup();
    await t.login();
    t.dropCsrf();
    await expect(t.api.blocking.set({ enabled: false })).rejects.toMatchObject({ status: 403, code: 'csrf_failed' });
  });

  it('bans after failed logins and gives a wait time', async () => {
    const t = setup();
    for (let i = 0; i < 5; i++) {
      await expect(t.api.auth.login({ password: 'wrong' })).rejects.toMatchObject({ code: 'invalid_credentials' });
    }
    const err = await t.api.auth.login({ password: MOCK_PASSWORD }).catch((e: unknown) => e);
    expect(err).toMatchObject({ status: 429, code: 'rate_limited', retryAfterSeconds: 30 });
    expect(t.onRateLimited).toHaveBeenCalledWith(30, err);
  });

  it('asks for TOTP when it is on', async () => {
    const t = setup();
    await t.login();
    const setupResp = await t.api.auth.totpSetup(MOCK_PASSWORD);
    expect(setupResp.otpauth_uri).toMatch(/^otpauth:\/\/totp\//);
    await t.api.auth.totpConfirm('123456');
    await expect(t.api.auth.login({ password: MOCK_PASSWORD })).rejects.toMatchObject({ code: 'totp_required' });
    await expect(t.api.auth.login({ password: MOCK_PASSWORD, totp: '654321' })).resolves.toMatchObject({
      totp_enabled: true,
    });
  });

  it('sets the blocking timer', async () => {
    const t = setup();
    await t.login();
    const s = await t.api.blocking.set({ enabled: false, duration_seconds: 300 });
    expect(s.enabled).toBe(false);
    expect(s.remaining_seconds).toBeGreaterThan(298);
    await expect(t.api.blocking.set({ enabled: true })).resolves.toMatchObject({ enabled: true, remaining_seconds: null });
  });

  it('gives statistics with the documented shapes', async () => {
    const t = setup();
    await t.login();
    const tl = await t.api.stats.timeline('24h');
    expect(tl.bucket_seconds).toBe(600);
    expect(tl.queries).toHaveLength(144);
    expect(tl.blocked).toHaveLength(144);
    const hours = await t.api.stats.hours('7d');
    expect(hours.queries).toHaveLength(24);
    const summary = await t.api.stats.summary('24h');
    expect(summary.queries).toBe(tl.queries.reduce((a, b) => a + b, 0));
  });

  it('pages client domains by group, and a group is never split', async () => {
    const t = setup();
    await t.login();
    const key = '02:00:00:00:00:01';
    const first = await t.api.stats.clientDomains(key, '24h', { limit: 3 });
    expect(first.items).toHaveLength(3);
    expect(first.next_cursor).not.toBeNull();
    const second = await t.api.stats.clientDomains(key, '24h', { limit: 3, cursor: first.next_cursor });
    const bases = [...first.items, ...second.items].map((g) => g.base);
    expect(new Set(bases).size).toBe(bases.length);
    for (const g of first.items) {
      expect(g.names.reduce((s, n) => s + n.queries, 0)).toBe(g.queries);
      expect(g.names_total).toBe(g.names.length);
    }
  });

  it('rejects an IPv6 client id (A11)', async () => {
    const t = setup();
    await t.login();
    await expect(t.api.clients.create({ match: '2001:db8::10', groups: [0], comment: '' })).rejects.toMatchObject({
      status: 422,
      details: [{ field: 'match', message: expect.stringContaining('IPv6') as unknown }],
    });
    await expect(t.api.clients.create({ match: '192.0.2.99', groups: [0], comment: 'new' })).resolves.toMatchObject({
      kind: 'ip',
    });
  });

  it('creates, changes and deletes a rule', async () => {
    const t = setup();
    await t.login();
    const r = await t.api.rules.create({ kind: 'exact', action: 'deny', pattern: 'Bad.Example.com', enabled: true, groups: [0], comment: '' });
    expect(r.pattern).toBe('bad.example.com');
    const changed = await t.api.rules.update(r.id, { enabled: false });
    expect(changed.enabled).toBe(false);
    await t.api.rules.remove(r.id);
    await expect(t.api.rules.get(r.id)).rejects.toMatchObject({ status: 404 });
  });

  it('counts the members of each group', async () => {
    const t = setup();
    await t.login();
    const groups = (await t.api.groups.list()).items;
    const kids = groups.find((g) => g.name === 'Kids');
    expect(kids).toMatchObject({ lists: 4, clients: 2 });
  });

  it('never returns secrets in settings or token lists', async () => {
    const t = setup();
    await t.login();
    const text = JSON.stringify([await t.api.settings.get(), await t.api.tokens.list()]);
    expect(text).not.toMatch(/password|secret|hash/i);
  });
});
