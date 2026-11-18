// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import App from './App.svelte';
import { api } from './lib/api';
import { createClient } from './lib/api/client';
import { makeApi } from './lib/api/endpoints';
import { createMockFetch, MOCK_PASSWORD } from './lib/mock/server';
import { session, toasts } from './lib/state.svelte';
import { button, cleanup, json, render, startMockApi, until } from './test/harness';

afterEach(() => {
  cleanup();
  toasts.length = 0;
});

/** A second tab: its own client on the same mock server. */
async function loginInOtherTab(): Promise<void> {
  let csrf: string | null = null;
  const other = makeApi(createClient({ fetch: createMockFetch({ latencyMs: 0 }), getCsrfToken: () => csrf }));
  csrf = (await other.auth.login({ password: MOCK_PASSWORD })).csrf_token;
}

describe('stale CSRF token (m25)', () => {
  it('a write works after a login in another tab', async () => {
    const t = await startMockApi();
    const before = session.csrf;
    await loginInOtherTab();
    await expect(api.blocking.set({ enabled: false })).resolves.toMatchObject({ enabled: false });
    expect(t.calls).toEqual(['PUT /blocking', 'GET /auth/session', 'PUT /blocking']);
    expect(session.csrf).not.toBe(before);
  });

  it('a failed logout keeps the user logged in and tells the user', async () => {
    await startMockApi((url, init) =>
      init.method === 'POST' && url.endsWith('/auth/logout') ? json(500, { code: 'internal', message: 'Fault.' }) : null,
    );
    const root = render(App);
    await until(() => root.querySelector('nav') !== null, 'the app shell');
    button(root, 'Log out').click();
    await until(() => toasts.some((x) => x.text.includes('still logged in')), 'the logout toast');
    expect(session.status).toBe('authed');
  });

  it('a logout works after a login in another tab', async () => {
    const t = await startMockApi();
    const root = render(App);
    await until(() => root.querySelector('nav') !== null, 'the app shell');
    await loginInOtherTab();
    button(root, 'Log out').click();
    await until(() => session.status === 'anon', 'the logout');
    expect(t.calls.filter((c) => c.startsWith('POST /auth/logout'))).toHaveLength(2);
  });
});
