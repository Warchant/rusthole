import { mount } from 'svelte';
import './app.css';
import App from './App.svelte';
import { initApi } from './lib/api';
import type { FetchFn } from './lib/api/client';
import { formatDuration } from './lib/format';
import { applyTheme, clearSession, go, session, startRouter, theme, toast } from './lib/state.svelte';

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
