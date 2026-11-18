import { mount } from 'svelte';
import './app.css';
import App from './App.svelte';
import { api, initApi } from './lib/api';
import type { FetchFn } from './lib/api/client';
import { formatDuration } from './lib/format';
import { applyTheme, clearSession, go, session, setSession, startRouter, theme, toast } from './lib/state.svelte';

// The mock is in the bundle only when VITE_MOCK is "1" (bun run dev).
// In a production build this branch is removed.
let fetchFn: FetchFn = (url, init) => fetch(url, init);
if (import.meta.env.VITE_MOCK === '1') {
  const mock = await import('./lib/mock/server');
  fetchFn = mock.createMockFetch();
}

initApi({
  fetch: fetchFn,
  getCsrfToken: () => session.csrf,
  // Another tab can log in again and so change the CSRF token of the session.
  // Then a write gets 403 csrf_failed: read the new token and try one more time.
  refreshCsrfToken: async () => {
    const s = await api.auth.session();
    setSession(s.csrf_token, s.totp_enabled);
    return s.csrf_token;
  },
  onUnauthorized: () => {
    if (session.status === 'authed') toast('info', 'The session ended. Log in again.');
    clearSession();
    go('#/login');
  },
  onRateLimited: (seconds) => {
    toast('error', `Too many requests. Try again in ${formatDuration(seconds)}.`, 8000);
  },
});

applyTheme(theme.value);
startRouter();

const target = document.getElementById('app');
if (!target) throw new Error('The #app element is missing.');
mount(App, { target });
