<script lang="ts">
  // One client: totals, hour-of-day histogram, queries over time, and the
  // domains it resolved, grouped by registrable domain (docs/API.md 5.6).
  import ClientName from '../components/ClientName.svelte';
  import HourHistogram from '../components/HourHistogram.svelte';
  import RangePicker from '../components/RangePicker.svelte';
  import Status from '../components/Status.svelte';
  import TimeSeries from '../components/TimeSeries.svelte';
  import { api, errorText } from '../lib/api';
  import type { ClientSort, DomainGroup, HourArrays } from '../lib/api/types';
  import { formatCount, formatDateTime, formatHour, formatPercent, formatRelative } from '../lib/format';
  import { groupNames, mergeGroupPages, peakHour, shareOf } from '../lib/grouping';
  import { nav, prefs, resource } from '../lib/state.svelte';

  const key = nav.route.params.key ?? '';

  const detail = resource(() => api.stats.client(key, prefs.range));
  const timeline = resource(() => api.stats.timeline(prefs.range, { client: key }));
  const groups = resource(() => api.groups.list());
  const groupMap = $derived(new Map((groups.data?.items ?? []).map((g) => [g.id, g.name])));

  let q = $state('');
  let debounced = $state('');
  let sort = $state<ClientSort>('queries');
  let blockedOnly = $state(false);
  let rows = $state<DomainGroup[]>([]);
  let cursor = $state<string | null>(null);
  let loading = $state(false);
  let error = $state<string | null>(null);
  let open = $state<Record<string, boolean>>({});
  let groupHours = $state<Record<string, HourArrays | 'loading' | string>>({});

  $effect(() => {
    const value = q;
    const t = setTimeout(() => (debounced = value.trim().toLowerCase()), 250);
    return () => clearTimeout(t);
  });

  let generation = 0;
  async function load(reset: boolean) {
    const gen = reset ? ++generation : generation;
    loading = true;
    try {
      const page = await api.stats.clientDomains(key, prefs.range, {
        q: debounced || undefined,
        sort,
        blocked_only: blockedOnly || undefined,
        limit: 25,
        names_limit: 50,
        cursor: reset ? null : cursor,
      });
      if (gen !== generation) return;
      rows = reset ? page.items : mergeGroupPages(rows, page.items);
      cursor = page.next_cursor;
      error = null;
      if (reset) {
        open = {};
        groupHours = {};
      }
    } catch (e) {
      if (gen === generation) error = errorText(e);
    } finally {
      if (gen === generation) loading = false;
    }
  }

  $effect(() => {
    void [prefs.range, debounced, sort, blockedOnly];
    void load(true);
  });

  async function toggle(base: string) {
    open[base] = !open[base];
    if (open[base] && groupHours[base] === undefined) {
      groupHours[base] = 'loading';
      try {
        const h = await api.stats.hours(prefs.range, { client: key, base });
        groupHours[base] = { queries: h.queries, blocked: h.blocked };
      } catch (e) {
        groupHours[base] = errorText(e);
      }
    }
  }

  const peak = $derived(detail.data ? peakHour(detail.data.hours) : null);
</script>

<div class="page-head">
  <div>
    <a class="small" href="#/clients">← Clients</a>
    <h1>{detail.data?.name ?? detail.data?.ip ?? key}</h1>
  </div>
  <RangePicker />
</div>

<div class="stack">
  {#if detail.data}
    {@const d = detail.data}
    <div class="card meta">
      <div><span class="muted small">IP</span><br /><span class="mono">{d.ips.join(', ')}</span></div>
      <div><span class="muted small">MAC</span><br /><span class="mono">{d.mac ?? 'unknown'}</span></div>
      <div>
        <span class="muted small">Groups</span><br />{groupNames(d.groups, groupMap)}
        {#if d.client_id === null}<span class="badge" title="No configured client matches">not configured</span>{/if}
      </div>
      <div><span class="muted small">First seen</span><br />{formatDateTime(d.first_seen_at)}</div>
      <div><span class="muted small">Last seen</span><br />{formatRelative(d.last_seen_at, Date.now())}</div>
    </div>
    <ClientName detail={d} onsaved={detail.reload} />
    <div class="stats">
      <div class="stat"><div class="label">Queries</div><div class="value">{formatCount(d.queries)}</div></div>
      <div class="stat">
        <div class="label">Blocked</div>
        <div class="value blocked-text">{formatPercent(d.blocked_percent)}</div>
        <div class="sub">{formatCount(d.blocked)} queries</div>
      </div>
      <div class="stat">
        <div class="label">Domains</div>
        <div class="value">{formatCount(d.unique_bases)}</div>
        <div class="sub">{formatCount(d.unique_domains)} full names</div>
      </div>
      <div class="stat">
        <div class="label">Busiest hour</div>
        <div class="value">{peak === null ? '—' : formatHour(peak)}</div>
      </div>
    </div>
    <div class="grid-2">
      <section class="card">
        <h2>By hour of day</h2>
        <HourHistogram hours={d.hours} />
      </section>
      <section class="card">
        <h2>Queries over time</h2>
        {#if timeline.data}
          <TimeSeries timeline={timeline.data} />
        {:else}
          <Status loading={timeline.loading} error={timeline.error} retry={timeline.reload} />
        {/if}
      </section>
    </div>
  {:else}
    <Status loading={detail.loading} error={detail.error} retry={detail.reload} />
  {/if}

  <section class="card">
    <h2>Domains</h2>
    <div class="row filters">
      <input type="search" placeholder="Filter by name" aria-label="Filter domains" bind:value={q} />
      <label class="check small muted">
        Sort
        <select bind:value={sort}>
          <option value="queries">Queries</option>
          <option value="blocked">Blocked</option>
          <option value="last_seen">Last seen</option>
          <option value="name">Name</option>
        </select>
      </label>
      <label class="check small"><input type="checkbox" bind:checked={blockedOnly} /> Blocked only</label>
    </div>

    {#if rows.length === 0}
      {#if !loading && !error}<p class="empty">No domains match.</p>{/if}
      <Status {loading} {error} retry={() => load(true)} />
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th class="num">Queries</th>
              <th class="num">Blocked</th>
              <th class="hide-sm">First seen</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {#each rows as g (g.base)}
              <tr class:blocked-row={g.blocked > 0 && g.blocked === g.queries}>
                <td>
                  <button type="button" class="link expand" aria-expanded={!!open[g.base]} onclick={() => toggle(g.base)}>
                    <span class="caret" aria-hidden="true">{open[g.base] ? '▾' : '▸'}</span>
                    {g.base}
                  </button>
                  <span class="muted small">{g.names_total} {g.names_total === 1 ? 'name' : 'names'}</span>
                </td>
                <td class="num">{formatCount(g.queries)}</td>
                <td class="num" class:blocked-text={g.blocked > 0}>
                  {formatCount(g.blocked)}
                  {#if g.blocked > 0}<span class="small muted">{formatPercent(shareOf(g.blocked, g.queries), 0)}</span>{/if}
                </td>
                <td class="hide-sm nowrap">{formatDateTime(g.first_seen_at)}</td>
                <td class="nowrap">{formatRelative(g.last_seen_at, Date.now())}</td>
              </tr>
              {#if open[g.base]}
                <tr class="sub">
                  <td colspan="5">
                    <div class="expanded">
                      <div class="hours">
                        {#if typeof groupHours[g.base] === 'object'}
                          <HourHistogram hours={groupHours[g.base] as HourArrays} height={80} compact />
                        {:else if groupHours[g.base] === 'loading'}
                          <p class="muted small">Loading histogram…</p>
                        {:else}
                          <p class="field-error">{groupHours[g.base]}</p>
                        {/if}
                      </div>
                      <table class="names">
                        <tbody>
                          {#each g.names as n (n.name)}
                            <tr>
                              <td class="mono"><a href={`#/domains?name=${encodeURIComponent(n.name)}`}>{n.name}</a></td>
                              <td class="num">{formatCount(n.queries)}</td>
                              <td class="num" class:blocked-text={n.blocked > 0}>{formatCount(n.blocked)}</td>
                              <td class="nowrap hide-sm">{formatDateTime(n.first_seen_at)}</td>
                              <td class="nowrap">{formatRelative(n.last_seen_at, Date.now())}</td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                      {#if g.names_total > g.names.length}
                        <p class="hint">Shows {g.names.length} of {g.names_total} names (most queried first).</p>
                      {/if}
                    </div>
                  </td>
                </tr>
              {/if}
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
</div>

<style>
  .meta {
    display: grid;
    gap: 0.75rem;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  }
  .filters {
    margin-bottom: 0.75rem;
  }
  .filters input[type='search'] {
    flex: 1;
    max-width: 22rem;
  }
  .expand {
    font-weight: 600;
    gap: 0.25rem;
  }
  .caret {
    display: inline-block;
    width: 0.8rem;
    color: var(--muted);
  }
  .expanded {
    display: grid;
    gap: 0.5rem;
  }
  .hours {
    max-width: 420px;
  }
  .names td {
    border-bottom: none;
    padding: 0.2rem 0.5rem;
  }
  .more {
    text-align: center;
    margin-top: 0.75rem;
  }
  p {
    margin: 0;
  }
  @media (max-width: 640px) {
    .hide-sm {
      display: none;
    }
  }
</style>
