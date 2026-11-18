// Helpers for component tests in happy-dom. The pages run on the real API client
// and on the mock API, so the CSRF header and error paths run as in production.

import { flushSync, mount, unmount, type Component } from 'svelte';
import { initApi, api } from '../lib/api';
import type { FetchFn } from '../lib/api/client';
import { createMockFetch, MOCK_PASSWORD, resetMock } from '../lib/mock/server';
import { clearSession, session, setSession } from '../lib/state.svelte';

/** A fetch function that can change a mock answer. Return null to use the mock. */
export type Override = (url: string, init: RequestInit) => Promise<Response | null> | Response | null;

export interface Harness {
  /** Each request that went to the server: "METHOD /path?query". */
  calls: string[];
  /** The mock fetch function, without the override. */
  mockFetch: FetchFn;
}

/** Resets the mock, connects the API object to it and logs in. */
export async function startMockApi(override?: Override): Promise<Harness> {
  resetMock();
  clearSession();
  const mockFetch = createMockFetch({ latencyMs: 0 });
  const calls: string[] = [];
  const fetchFn: FetchFn = async (url, init) => {
    calls.push(`${init.method ?? 'GET'} ${url.replace(/^\/api\/v1/, '')}`);
    const changed = override ? await override(url, init) : null;
    return changed ?? mockFetch(url, init);
  };
  initApi({
    fetch: fetchFn,
    getCsrfToken: () => session.csrf,
    refreshCsrfToken: async () => {
      const s = await api.auth.session();
      setSession(s.csrf_token, s.totp_enabled);
      return s.csrf_token;
    },
  });
  const s = await api.auth.login({ password: MOCK_PASSWORD });
  setSession(s.csrf_token, s.totp_enabled);
  calls.length = 0;
  return { calls, mockFetch };
}

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

let mounted: { target: HTMLElement; app: ReturnType<typeof mount> } | null = null;

/** Mounts a component in a new element of the document body. */
export function render<P extends Record<string, unknown>>(component: Component<P>, props?: P): HTMLElement {
  cleanup();
  const target = document.createElement('div');
  document.body.append(target);
  const app = mount(component, { target, props: props ?? ({} as P) });
  mounted = { target, app };
  flushSync();
  return target;
}

/** Unmounts the last component. Call it in afterEach. */
export function cleanup(): void {
  if (!mounted) return;
  void unmount(mounted.app);
  mounted.target.remove();
  mounted = null;
}

/** The longest wait of `until`, in event loop turns. */
const MAX_TURNS = 200;

/**
 * Lets promises and timers of 0 ms run until `cond` is true. It stops after
 * MAX_TURNS turns and throws, so a test cannot hang.
 */
export async function until(cond: () => boolean, what = 'the condition'): Promise<void> {
  for (let i = 0; i <= MAX_TURNS; i++) {
    flushSync();
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 0));
  }
  throw new Error(`Timed out while waiting for ${what}.`);
}

/** Lets the pending work run for a number of turns. */
export async function settle(turns = 20): Promise<void> {
  for (let i = 0; i < turns; i++) {
    flushSync();
    await new Promise((r) => setTimeout(r, 0));
  }
  flushSync();
}

export function text(el: Element | null | undefined): string {
  return (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

/** Finds a button by its text. */
export function button(root: ParentNode, label: string): HTMLButtonElement {
  const b = [...root.querySelectorAll('button')].find((x) => text(x) === label);
  if (!b) throw new Error(`No button "${label}".`);
  return b;
}
