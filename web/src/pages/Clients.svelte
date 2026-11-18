<script lang="ts">
  import RangePicker from '../components/RangePicker.svelte';
  import Status from '../components/Status.svelte';
  import { api, errorText } from '../lib/api';
  import type { ClientSort, StatsClient } from '../lib/api/types';
  import { formatCount, formatPercent, formatRelative } from '../lib/format';
  import { mergeByKey } from '../lib/grouping';
  import { href } from '../lib/routes';
  import { go, nav, prefs } from '../lib/state.svelte';
  import ClientsConfigured from './ClientsConfigured.svelte';

  const tab = $derived(nav.route.query.get('tab') ?? 'activity');
  const TABS = [
    { id: 'activity', label: 'Activity' },
    { id: 'configured', label: 'Configured clients' },
  ];

  let q = $state('');
  let debounced = $state('');
  let sort = $state<ClientSort>('queries');
  let items = $state<StatsClient[]>([]);
  let cursor = $state<string | null>(null);
  let loading = $state(false);
  let error = $state<string | null>(null);

  $effect(() => {
    const value = q;
    const t = setTimeout(() => (debounced = value.trim()), 250);
    return () => clearTimeout(t);
  });

  let generation = 0;
  async function load(reset: boolean) {
    const gen = reset ? ++generation : generation;
    loading = true;
    try {
      const page = await api.stats.clients(prefs.range, {
        q: debounced || undefined,
        sort,
        limit: 50,
        cursor: reset ? null : cursor,
      });
      if (gen !== generation) return;
      // Merge by key: a client can come again on the next page (keyed each block).
      items = mergeByKey(reset ? [] : items, page.items, (c) => c.key);
      cursor = page.next_cursor;
      error = null;
    } catch (e) {
      if (gen === generation) error = errorText(e);
    } finally {
      if (gen === generation) loading = false;
    }
  }

  $effect(() => {
    if (tab !== 'activity') return;
    void [prefs.range, debounced, sort];
    void load(true);
  });
</script>

<div class="page-head">
  <h1>Clients</h1>
  {#if tab === 'activity'}<RangePicker />{/if}
</div>

<div class="segmented tabs" role="group" aria-label="View">
  {#each TABS as t (t.id)}
    <button type="button" aria-pressed={tab === t.id} onclick={() => go(`#/clients?tab=${t.id}`)}
      >{t.label}</button
    >
  {/each}
</div>

{#if tab === 'activity'}
  <section class="card">
    <div class="row filters">
      <input type="search" placeholder="Filter by name, IP or MAC" aria-label="Filter clients" bind:value={q} />
      <label class="check small muted">
        Sort
        <select bind:value={sort}>
          <option value="queries">Queries</option>
          <option value="blocked">Blocked</option>
          <option value="last_seen">Last seen</option>
          <option value="name">Name</option>
        </select>
      </label>
    </div>
    {#if items.length === 0}
      {#if !loading && !error}<p class="empty">No clients in this range.</p>{/if}
      <Status {loading} {error} retry={() => load(true)} />
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Client</th>
              <th>IP</th>
              <th class="hide-sm">MAC</th>
              <th class="num">Queries</th>
              <th class="num">Blocked</th>
              <th class="num hide-sm">Domains</th>
              <th class="hide-sm">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {#each items as c (c.key)}
              <tr>
                <td>
                  <a href={href('/clients', c.key)}>{c.name ?? c.ip}</a>
                  {#if c.client_id === null}<span class="badge" title="No configured client matches">default</span>{/if}
                </td>
                <td class="mono">{c.ip}</td>
                <td class="mono hide-sm">{c.mac ?? '—'}</td>
                <td class="num">{formatCount(c.queries)}</td>
                <td class="num">
                  {formatCount(c.blocked)} <span class="muted small">{formatPercent(c.blocked_percent)}</span>
                </td>
                <td class="num hide-sm">{formatCount(c.unique_domains)}</td>
                <td class="hide-sm nowrap">{formatRelative(c.last_seen_at, Date.now())}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if error}<Status loading={false} {error} />{/if}
      {#if cursor}
        <div class="more"><button type="button" disabled={loading} onclick={() => load(false)}>Load more</button></div>
      {/if}
    {/if}
  </section>
{:else}
  <ClientsConfigured />
{/if}

<style>
  .tabs {
    margin-bottom: 1rem;
  }
  .filters {
    margin-bottom: 0.75rem;
  }
  .filters input {
    flex: 1;
    max-width: 22rem;
  }
  .more {
    text-align: center;
    margin-top: 0.75rem;
  }
  @media (max-width: 640px) {
    .hide-sm {
      display: none;
    }
  }
</style>
