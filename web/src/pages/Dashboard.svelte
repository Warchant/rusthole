<script lang="ts">
  import BlockingControl from '../components/BlockingControl.svelte';
  import HourHistogram from '../components/HourHistogram.svelte';
  import RangePicker from '../components/RangePicker.svelte';
  import ShareBars from '../components/ShareBars.svelte';
  import Status from '../components/Status.svelte';
  import TimeSeries from '../components/TimeSeries.svelte';
  import { api } from '../lib/api';
  import { formatCount, formatHour, formatPercent } from '../lib/format';
  import { peakHour, shareOf, withOther } from '../lib/grouping';
  import { href } from '../lib/routes';
  import { prefs, resource } from '../lib/state.svelte';

  const summary = resource(() => api.stats.summary(prefs.range));
  const timeline = resource(() => api.stats.timeline(prefs.range));
  const hours = resource(() => api.stats.hours(prefs.range));
  const top = resource(() => {
    const r = prefs.range;
    return Promise.all([api.stats.topDomains(r, 10), api.stats.topBlocked(r, 10), api.stats.topClients(r, 10)]);
  });
  const types = resource(() => api.stats.queryTypes(prefs.range));
  const upstreams = resource(() => api.stats.upstreams(prefs.range));

  const domainLink = (name: string) => `#/domains?name=${encodeURIComponent(name)}`;
  const typesTotal = $derived((types.data?.items ?? []).reduce((s, x) => s + x.count, 0));
  const upTotal = $derived((upstreams.data?.items ?? []).reduce((s, x) => s + x.count, 0));
  const peak = $derived(hours.data ? peakHour(hours.data) : null);
</script>

<div class="page-head">
  <h1>Dashboard</h1>
  <RangePicker />
</div>

<div class="stack">
  <BlockingControl />

  {#if summary.data}
    {@const s = summary.data}
    <div class="stats">
      <div class="stat"><div class="label">Queries</div><div class="value">{formatCount(s.queries)}</div></div>
      <div class="stat">
        <div class="label">Blocked</div>
        <div class="value blocked-text">{formatCount(s.blocked)}</div>
        <div class="sub">{formatPercent(s.blocked_percent)} of queries</div>
      </div>
      <div class="stat">
        <div class="label">Cached</div>
        <div class="value">{formatCount(s.cached)}</div>
        <div class="sub">{formatPercent(shareOf(s.cached, s.queries))}</div>
      </div>
      <div class="stat">
        <div class="label">Forwarded</div>
        <div class="value">{formatCount(s.forwarded)}</div>
        <div class="sub">{formatPercent(shareOf(s.forwarded, s.queries))}</div>
      </div>
      <div class="stat">
        <div class="label">Clients</div>
        <div class="value">{formatCount(s.unique_clients)}</div>
        <div class="sub">{formatCount(s.unique_domains)} domains</div>
      </div>
    </div>
  {:else}
    <Status loading={summary.loading} error={summary.error} retry={summary.reload} />
  {/if}

  <div class="grid-2">
    <section class="card">
      <h2>Queries over time</h2>
      {#if timeline.data}
        <TimeSeries timeline={timeline.data} />
      {:else}
        <Status loading={timeline.loading} error={timeline.error} retry={timeline.reload} />
      {/if}
    </section>
    <section class="card">
      <h2>
        By hour of day
        {#if peak !== null}<span class="muted small">· busiest hour {formatHour(peak)}</span>{/if}
      </h2>
      {#if hours.data}
        <HourHistogram hours={hours.data} />
      {:else}
        <Status loading={hours.loading} error={hours.error} retry={hours.reload} />
      {/if}
    </section>
  </div>

  {#if top.data}
    {@const [domains, blocked, clients] = top.data}
    <div class="grid">
      <section class="card">
        <h2>Top domains</h2>
        <ShareBars items={domains.items.map((d) => ({ label: d.name, value: d.count, href: domainLink(d.name) }))} />
      </section>
      <section class="card">
        <h2>Top blocked</h2>
        <ShareBars
          items={blocked.items.map((d) => ({ label: d.name, value: d.count, href: domainLink(d.name), tone: 'blocked' as const }))}
        />
      </section>
      <section class="card">
        <h2>Top clients</h2>
        <ShareBars
          items={clients.items.map((c) => ({
            label: c.name ?? c.ip,
            sub: c.name ? c.ip : undefined,
            value: c.count,
            href: href('/clients', c.key),
          }))}
        />
      </section>
    </div>
  {:else}
    <Status loading={top.loading} error={top.error} retry={top.reload} />
  {/if}

  <div class="grid">
    <section class="card">
      <h2>Query types</h2>
      {#if types.data}
        <ShareBars
          total={typesTotal}
          items={withOther(types.data.items, 7, (count) => ({ type: 'Other', count })).map((t) => ({
            label: t.type,
            value: t.count,
          }))}
        />
      {:else}
        <Status loading={types.loading} error={types.error} retry={types.reload} />
      {/if}
    </section>
    <section class="card">
      <h2>Answer source</h2>
      {#if upstreams.data}
        <ShareBars
          total={upTotal}
          items={upstreams.data.items.map((u) => ({
            label: u.kind === 'upstream' ? u.name : u.name[0]?.toUpperCase() + u.name.slice(1),
            sub: u.avg_ms !== null ? `${u.avg_ms.toFixed(1)} ms` : undefined,
            value: u.count,
            tone: u.kind === 'blocked' ? ('blocked' as const) : u.kind === 'upstream' ? ('accent' as const) : ('muted' as const),
          }))}
        />
      {:else}
        <Status loading={upstreams.loading} error={upstreams.error} retry={upstreams.reload} />
      {/if}
    </section>
  </div>
</div>
