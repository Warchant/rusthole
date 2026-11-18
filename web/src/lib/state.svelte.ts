// Shared UI state. Secrets (the CSRF token) stay in memory only. localStorage
// holds only view settings (time range and theme).

import { ApiError, errorText } from './api';
import { RANGES, type Range } from './api/types';
import { parseHash, type Route } from './routes';

export type SessionStatus = 'unknown' | 'anon' | 'authed';

export const session = $state({
  status: 'unknown' as SessionStatus,
  csrf: null as string | null,
  totpEnabled: false,
});

export function setSession(csrf: string, totpEnabled: boolean): void {
  session.csrf = csrf;
  session.totpEnabled = totpEnabled;
  session.status = 'authed';
}

export function clearSession(): void {
  session.csrf = null;
  session.status = 'anon';
}

// ---- toasts ----

export interface Toast {
  id: number;
  kind: 'error' | 'ok' | 'info';
  text: string;
}

export const toasts = $state<Toast[]>([]);
let nextToastId = 1;

export function toast(kind: Toast['kind'], text: string, ms = 5000): void {
  const id = nextToastId++;
  toasts.push({ id, kind, text });
  if (toasts.length > 4) toasts.shift();
  setTimeout(() => dismissToast(id), ms);
}

export function dismissToast(id: number): void {
  const i = toasts.findIndex((t) => t.id === id);
  if (i >= 0) toasts.splice(i, 1);
}

/** Shows an error toast. A 401 goes to the login page, so it shows nothing. */
export function toastError(err: unknown): void {
  if (err instanceof ApiError && err.code === 'unauthorized') return;
  toast('error', errorText(err), 8000);
}

// ---- preferences ----

function readStored(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStored(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Storage can be off (private mode). The setting then lasts until reload.
  }
}

const storedRange = readStored('rusthole.range');

export const prefs = $state({
  range: (RANGES as readonly string[]).includes(storedRange ?? '') ? (storedRange as Range) : ('24h' as Range),
});

export function setRange(r: Range): void {
  prefs.range = r;
  writeStored('rusthole.range', r);
}

export type Theme = 'auto' | 'light' | 'dark';

export const theme = $state({ value: (readStored('rusthole.theme') ?? 'auto') as Theme });

export function applyTheme(t: Theme): void {
  theme.value = t;
  writeStored('rusthole.theme', t);
  if (t === 'auto') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
}

// ---- router ----

export const nav = $state({ route: parseHash(location.hash) as Route });

export function startRouter(): void {
  window.addEventListener('hashchange', () => {
    nav.route = parseHash(location.hash);
    window.scrollTo(0, 0);
  });
}

export function go(hash: string): void {
  if (location.hash !== hash) location.hash = hash;
}

// ---- data loading ----

export interface Resource<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/**
 * Loads data in an effect. The effect runs again when state that `fn` reads
 * before its first await changes (for example the time range). The old data
 * stays visible while new data loads. An answer that comes late is dropped.
 */
export function resource<T>(fn: () => Promise<T>): Resource<T> {
  let version = $state(0);
  const r: Resource<T> = $state({
    data: null,
    error: null,
    loading: true,
    reload: () => {
      version += 1;
    },
  });
  $effect(() => {
    void version;
    let live = true;
    r.loading = true;
    fn()
      .then((d) => {
        if (!live) return;
        r.data = d;
        r.error = null;
      })
      .catch((e: unknown) => {
        if (!live) return;
        r.error = errorText(e);
        if (e instanceof ApiError && e.code === 'config_conflict') r.reload();
      })
      .finally(() => {
        if (live) r.loading = false;
      });
    return () => {
      live = false;
    };
  });
  return r;
}

/**
 * Runs a write. It shows a toast on success or failure, and calls `after`
 * (usually a reload) in both cases, so the view shows the server state.
 */
export async function act(work: () => Promise<unknown>, okText: string | null, after?: () => void): Promise<boolean> {
  try {
    await work();
    if (okText) toast('ok', okText, 3000);
    return true;
  } catch (e) {
    toastError(e);
    return false;
  } finally {
    after?.();
  }
}
