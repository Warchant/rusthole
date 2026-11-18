<script lang="ts">
  // The last queries from the RAM ring buffer (docs/API.md 6).
  import Status from '../components/Status.svelte';
  import { api } from '../lib/api';
  import { QUERY_STATUSES, type QueryStatus } from '../lib/api/types';
  import { href } from '../lib/routes';
  import { resource } from '../lib/state.svelte';

  const REFRESH_MS = 5000;

  let status = $state<'' | QueryStatus>('');
  let q = $state('');
  let debounced = $state('');
  let live = $state(true);

  $effect(() => {
    const value = q;
    const t = setTimeout(() => (debounced = value.trim().toLowerCase()), 300);
    return () => clearTimeout(t);
  });

  const recent = resource(() =>
    api.queries.recent({ limit: 200, status: status || undefined, q: debounced || undefined }),
  );

  $effect(() => {
    if (!live) return;
    const t = setInterval(() => recent.reload(), REFRESH_MS);
    return () => clearInterval(t);
  });

  const timeFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  function badgeClass(s: QueryStatus): string {
    if (s === 'blocked' || s === 'error' || s === 'refused') return 'bad';
    if (s === 'cached' || s === 'local') return 'ok';
    return 'info';
  }
</script>

<div class="page-head">
  <h1>Recent queries</h1>
  <label class="check small"><input type="checkbox" bind:checked={live} /> Refresh every 5 s</label>
</div>

<section class="card">
  <div class="row filters">
    <input type="search" placeholder="Filter by name" aria-label="Filter by name" bind:value={q} />
    <select aria-label="Status" bind:value={status}>
      <option value="">All statuses</option>
      {#each QUERY_STATUSES as s (s)}<option value={s}>{s}</option>{/each}
    </select>
  </div>
  <p class="hint">rusthole keeps only the last queries in RAM. For long-term data, see the dashboard and the client pages.</p>
  {#if recent.data}
    {#if recent.data.items.length === 0}
      <p class="empty">No queries match.</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>Client</th><th>Name</th><th>Type</th><th>Status</th><th class="num">Time (ms)</th></tr></thead>
          <tbody>
            {#each recent.data.items as r, i (r.at + r.name + i)}
              <tr>
                <td class="nowrap mono small">{timeFmt.format(Date.parse(r.at))}</td>
                <td class="nowrap"><a href={href('/clients', r.client_key)}>{r.client_name ?? r.client_ip}</a></td>
                <td class="mono"><a href={`#/domains?name=${encodeURIComponent(r.name)}`}>{r.name}</a></td>
                <td>{r.type}</td>
                <td>
                  <span class="badge {badgeClass(r.status)}">{r.status}</span>
                  {#if r.reason}<span class="muted small mono">{r.reason}</span>{/if}
                  {#if r.upstream}<span class="muted small mono">{r.upstream}</span>{/if}
                </td>
                <td class="num">{r.duration_ms.toFixed(1)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {:else}
    <Status loading={recent.loading} error={recent.error} retry={recent.reload} />
  {/if}
</section>

<style>
  .filters {
    margin-bottom: 0.5rem;
  }
  .filters input {
    flex: 1;
    max-width: 22rem;
  }
  p {
    margin: 0 0 0.5rem;
  }
</style>
