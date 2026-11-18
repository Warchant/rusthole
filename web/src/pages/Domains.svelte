<script lang="ts">
  // Search a domain: query counts, which clients asked for it, and which list
  // or rule blocks it (docs/API.md 5.7 and 7.1).
  import BlockDomain from '../components/BlockDomain.svelte';
  import HourHistogram from '../components/HourHistogram.svelte';
  import RangePicker from '../components/RangePicker.svelte';
  import Status from '../components/Status.svelte';
  import { api, errorText } from '../lib/api';
  import type { DomainDetail, DomainSearchItem, DomainVerdicts } from '../lib/api/types';
  import { formatCount, formatDateTime, formatPercent, formatRelative } from '../lib/format';
  import { groupByBase, shareOf } from '../lib/grouping';
  import { href } from '../lib/routes';
  import { go, nav, prefs } from '../lib/state.svelte';

  const selected = $derived(nav.route.query.get('name'));

  let q = $state(nav.route.query.get('q') ?? '');
  let results = $state<DomainSearchItem[] | null>(null);
  let searchError = $state<string | null>(null);
  let searching = $state(false);

  let detail = $state<DomainDetail | null>(null);
  let verdicts = $state<DomainVerdicts | null>(null);
  let detailError = $state<string | null>(null);
  let detailLoading = $state(false);

  const grouped = $derived(results ? groupByBase(results) : []);

  function submit(e: SubmitEvent) {
    e.preventDefault();
    const text = q.trim().toLowerCase();
    if (!text) return;
    go(`#/domains?q=${encodeURIComponent(text)}`);
  }

  function check() {
    const text = q.trim().toLowerCase();
    if (text) go(`#/domains?name=${encodeURIComponent(text)}`);
  }

  // Search when the "q" in the address changes.
  $effect(() => {
    const text = nav.route.query.get('q');
    const r = prefs.range;
    if (!text || selected) return;
    q = text;
    let live = true;
    searching = true;
    api.stats
      .domains(r, text, { limit: 100 })
      .then((p) => {
        if (live) {
          results = p.items;
          searchError = null;
        }
      })
      .catch((e: unknown) => {
        if (live) searchError = errorText(e);
      })
      .finally(() => {
        if (live) searching = false;
      });
    return () => {
      live = false;
    };
  });

  // Load the detail when a name is selected.
  $effect(() => {
    const name = selected;
    const r = prefs.range;
    if (!name) return;
    q = name;
    let live = true;
    detailLoading = true;
    detail = null;
    verdicts = null;
    Promise.all([api.stats.domain(name, r), api.search.domain(name)])
      .then(([d, v]) => {
        if (!live) return;
        detail = d;
        verdicts = v;
        detailError = null;
      })
      .catch((e: unknown) => {
        if (live) detailError = errorText(e);
      })
      .finally(() => {
        if (live) detailLoading = false;
      });
    return () => {
      live = false;
    };
  });

  // After a block, load the verdicts again. The counts do not change.
  function reloadVerdicts() {
    const name = selected;
    if (!name) return;
    api.search
      .domain(name)
      .then((v) => {
        if (selected === name) verdicts = v;
      })
      .catch((e: unknown) => {
        if (selected === name) detailError = errorText(e);
      });
  }

  function sourceLink(m: { source: string; id: number | null }): string | null {
    if (m.source === 'list') return '#/lists';
    if (m.source === 'rule') return '#/rules';
    return null;
  }
</script>

<div class="page-head">
  <h1>Domains</h1>
  <RangePicker />
</div>

<div class="stack">
  <form class="card row search" onsubmit={submit}>
    <input type="search" placeholder="Part of a name, e.g. example.net" aria-label="Domain" bind:value={q} />
    <button type="submit" class="primary">Search</button>
    <button type="button" onclick={check} title="Show counts and the lists and rules for this exact name">Check exact name</button>
  </form>

  {#if selected}
    {#if detail && verdicts}
      {@const d = detail}
      <div class="stats">
        <div class="stat"><div class="label">Name</div><div class="value name mono">{d.name}</div><div class="sub">Domain: {d.base}</div></div>
        <div class="stat"><div class="label">Queries</div><div class="value">{formatCount(d.queries)}</div></div>
        <div class="stat">
          <div class="label">Blocked</div>
          <div class="value blocked-text">{formatCount(d.blocked)}</div>
          <div class="sub">{formatPercent(shareOf(d.blocked, d.queries))}</div>
        </div>
        <div class="stat"><div class="label">Last seen</div><div class="value small-value">{formatRelative(d.last_seen_at, Date.now())}</div><div class="sub">First: {formatDateTime(d.first_seen_at)}</div></div>
      </div>

      <div class="row actions">
        <BlockDomain name={d.name} onblocked={reloadVerdicts} />
      </div>

      <section class="card">
        <h2>Lists and rules</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Group</th><th>Result</th><th>Reason</th></tr></thead>
            <tbody>
              {#each verdicts.verdicts as v (v.group_id)}
                <tr>
                  <td>{v.group_name}</td>
                  <td>
                    <span class="badge" class:bad={v.verdict === 'blocked'} class:ok={v.verdict === 'allowed'}>{v.verdict === 'none' ? 'not listed' : v.verdict}</span>
                  </td>
                  <td class="mono small">{v.by ?? '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if verdicts.matches.length > 0}
          <h3 class="matches-title">Matches</h3>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Source</th><th>Kind</th><th>Match</th><th>Pattern</th><th>State</th></tr></thead>
              <tbody>
                {#each verdicts.matches as m, i (i)}
                  {@const link = sourceLink(m)}
                  <tr class:off={!m.enabled}>
                    <td>
                      {#if link}<a href={link}>{m.source} {m.id}</a>{:else}{m.source}{/if}
                      <div class="muted small label-cell">{m.label}</div>
                    </td>
                    <td><span class="badge" class:bad={m.kind === 'block'} class:ok={m.kind === 'allow'}>{m.kind}</span></td>
                    <td>{m.match}</td>
                    <td class="mono">{m.pattern}</td>
                    <td>{m.enabled ? 'enabled' : 'disabled'}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if verdicts.truncated}<p class="hint">The search stopped early. More matches can exist.</p>{/if}
        {:else}
          <p class="muted">No list or rule has this name.</p>
        {/if}
      </section>

      <div class="grid-2">
        <section class="card">
          <h2>By hour of day</h2>
          <HourHistogram hours={d.hours} />
        </section>
        <section class="card">
          <h2>Clients</h2>
          {#if d.clients.length === 0}
            <p class="empty">No client asked for this name in this range.</p>
          {:else}
            <div class="table-wrap">
              <table>
                <thead><tr><th>Client</th><th class="num">Queries</th><th class="num">Blocked</th><th>Last seen</th></tr></thead>
                <tbody>
                  {#each d.clients as c (c.key)}
                    <tr>
                      <td><a href={href('/clients', c.key)}>{c.name ?? c.ip}</a> <span class="muted small mono">{c.ip}</span></td>
                      <td class="num">{formatCount(c.queries)}</td>
                      <td class="num">{formatCount(c.blocked)}</td>
                      <td class="nowrap">{formatRelative(c.last_seen_at, Date.now())}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </section>
      </div>
    {:else}
      <Status loading={detailLoading} error={detailError} />
    {/if}
  {:else if results}
    <section class="card">
      <h2>Results <span class="muted small">{results.length} names in {grouped.length} domains</span></h2>
      {#if results.length === 0}
        <p class="empty">No queries for a name like this. Use "Check exact name" to see the lists and rules.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th class="num">Queries</th><th class="num">Blocked</th><th class="num">Clients</th><th>Last seen</th></tr></thead>
            <tbody>
              {#each grouped as g (g.base)}
                <tr class="sub"><td colspan="5"><strong>{g.base}</strong> <span class="muted small">{formatCount(g.queries)} queries</span></td></tr>
                {#each g.items as r (r.name)}
                  <tr>
                    <td class="mono"><a href={`#/domains?name=${encodeURIComponent(r.name)}`}>{r.name}</a></td>
                    <td class="num">{formatCount(r.queries)}</td>
                    <td class="num" class:blocked-text={r.blocked > 0}>{formatCount(r.blocked)}</td>
                    <td class="num">{r.clients}</td>
                    <td class="nowrap">{formatRelative(r.last_seen_at, Date.now())}</td>
                  </tr>
                {/each}
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {:else if searching || searchError}
    <Status loading={searching} error={searchError} />
  {:else}
    <p class="muted">Enter a part of a domain name to search the statistics, or check an exact name.</p>
  {/if}
</div>

<style>
  .search input {
    flex: 1;
    min-width: 12rem;
  }
  .name {
    font-size: 1rem;
    overflow-wrap: anywhere;
  }
  .small-value {
    font-size: 1.1rem;
  }
  .actions {
    flex-wrap: wrap;
  }
  .matches-title {
    margin-top: 1rem;
  }
  .label-cell {
    overflow-wrap: anywhere;
  }
  p {
    margin: 0.5rem 0 0;
  }
</style>
