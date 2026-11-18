<script lang="ts">
  import type { Component } from 'svelte';
  import Toasts from './components/Toasts.svelte';
  import { api } from './lib/api';
  import type { RouteName } from './lib/routes';
  import { act, applyTheme, clearSession, go, nav, session, setSession, theme, type Theme } from './lib/state.svelte';
  import Audit from './pages/Audit.svelte';
  import ClientDetail from './pages/ClientDetail.svelte';
  import Clients from './pages/Clients.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Domains from './pages/Domains.svelte';
  import Groups from './pages/Groups.svelte';
  import Lists from './pages/Lists.svelte';
  import LocalDns from './pages/LocalDns.svelte';
  import Login from './pages/Login.svelte';
  import NotFound from './pages/NotFound.svelte';
  import Queries from './pages/Queries.svelte';
  import Rules from './pages/Rules.svelte';
  import Settings from './pages/Settings.svelte';

  const PAGES: Record<Exclude<RouteName, 'login'>, Component> = {
    dashboard: Dashboard,
    clients: Clients,
    client: ClientDetail,
    domains: Domains,
    lists: Lists,
    rules: Rules,
    groups: Groups,
    dns: LocalDns,
    settings: Settings,
    audit: Audit,
    queries: Queries,
    not_found: NotFound,
  };

  const LINKS: { href: string; label: string; names: RouteName[] }[] = [
    { href: '#/', label: 'Dashboard', names: ['dashboard'] },
    { href: '#/clients', label: 'Clients', names: ['clients', 'client'] },
    { href: '#/domains', label: 'Domains', names: ['domains'] },
    { href: '#/queries', label: 'Recent queries', names: ['queries'] },
    { href: '#/lists', label: 'Lists', names: ['lists'] },
    { href: '#/rules', label: 'Rules', names: ['rules'] },
    { href: '#/groups', label: 'Groups', names: ['groups'] },
    { href: '#/dns', label: 'Local DNS', names: ['dns'] },
    { href: '#/audit', label: 'Audit log', names: ['audit'] },
    { href: '#/settings', label: 'Settings', names: ['settings'] },
  ];

  const THEMES: Theme[] = ['auto', 'light', 'dark'];

  let menuOpen = $state(false);

  // At start: a valid session cookie gives the CSRF token again (docs/API.md 3.1).
  $effect(() => {
    api.auth
      .session()
      .then((s) => setSession(s.csrf_token, s.totp_enabled))
      .catch(() => clearSession());
  });

  // Close the phone menu after each navigation.
  $effect(() => {
    void nav.route;
    menuOpen = false;
  });

  async function logout() {
    await act(() => api.auth.logout(), null);
    clearSession();
    go('#/login');
  }

  const Page = $derived(nav.route.name === 'login' ? Dashboard : PAGES[nav.route.name]);
  const routeKey = $derived(`${nav.route.name}/${JSON.stringify(nav.route.params)}`);
</script>

{#if session.status === 'unknown'}
  <p class="empty">Loading…</p>
{:else if session.status === 'anon'}
  <Login />
{:else}
  <div class="shell">
    <header class="topbar">
      <button
        type="button"
        class="menu-btn"
        aria-expanded={menuOpen}
        aria-controls="nav"
        onclick={() => (menuOpen = !menuOpen)}>Menu</button
      >
      <a class="brand" href="#/">
        <svg viewBox="0 0 32 32" width="22" height="22" aria-hidden="true"
          ><circle cx="16" cy="16" r="14" class="ring" /><circle cx="16" cy="16" r="6" class="hole" /></svg
        >
        rusthole
      </a>
      {#if import.meta.env.VITE_MOCK === '1'}<span class="badge warn">mock data</span>{/if}
    </header>
    <nav id="nav" class:open={menuOpen} aria-label="Main">
      <ul>
        {#each LINKS as l (l.href)}
          <li>
            <a href={l.href} aria-current={l.names.includes(nav.route.name) ? 'page' : undefined}>{l.label}</a>
          </li>
        {/each}
      </ul>
      <div class="nav-foot">
        <div class="segmented theme" role="group" aria-label="Theme">
          {#each THEMES as t (t)}
            <button type="button" aria-pressed={theme.value === t} onclick={() => applyTheme(t)}>{t}</button>
          {/each}
        </div>
        <button type="button" class="small" onclick={logout}>Log out</button>
      </div>
    </nav>
    <main class="content">
      {#key routeKey}
        <Page />
      {/key}
    </main>
  </div>
{/if}
<Toasts />

<style>
  .shell {
    display: grid;
    grid-template-columns: 210px 1fr;
    grid-template-rows: auto 1fr;
    grid-template-areas: 'top top' 'nav main';
    min-height: 100vh;
  }
  .topbar {
    grid-area: top;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.6rem 1rem;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    position: sticky;
    top: 0;
    z-index: 20;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    font-weight: 700;
    font-size: 1.05rem;
    color: var(--text);
  }
  .brand:hover {
    text-decoration: none;
  }
  .ring {
    fill: var(--accent);
  }
  .hole {
    fill: var(--surface);
  }
  .menu-btn {
    display: none;
  }
  nav {
    grid-area: nav;
    border-right: 1px solid var(--border);
    background: var(--surface);
    padding: 0.75rem 0.5rem;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    position: sticky;
    top: 49px;
    height: calc(100vh - 49px);
    overflow-y: auto;
  }
  nav ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  nav a {
    display: block;
    padding: 0.45rem 0.75rem;
    border-radius: 7px;
    color: var(--text);
  }
  nav a:hover {
    background: var(--surface-2);
    text-decoration: none;
  }
  nav a[aria-current='page'] {
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: 600;
  }
  .nav-foot {
    display: grid;
    gap: 0.5rem;
    padding: 0.75rem 0.5rem 0;
  }
  .theme button {
    flex: 1;
    text-transform: capitalize;
    padding: 0.25rem 0.4rem;
    font-size: 0.82rem;
  }
  .nav-foot > button {
    justify-content: center;
  }
  .content {
    grid-area: main;
    padding: 1.25rem;
    min-width: 0;
    max-width: 1400px;
  }

  @media (max-width: 760px) {
    .shell {
      grid-template-columns: 1fr;
      grid-template-areas: 'top' 'main';
    }
    .menu-btn {
      display: inline-flex;
    }
    nav {
      display: none;
      position: fixed;
      top: 49px;
      left: 0;
      right: 0;
      height: auto;
      max-height: calc(100vh - 49px);
      border-right: none;
      border-bottom: 1px solid var(--border);
      z-index: 19;
      box-shadow: 0 8px 20px rgb(0 0 0 / 15%);
    }
    nav.open {
      display: flex;
    }
    .content {
      padding: 1rem;
    }
  }
</style>
