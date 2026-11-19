<script lang="ts">
  // The domain report (docs/API.md section 17). Each section has its own request,
  // so each card fills in when its source answers. One slow or failed source does
  // not block the others.
  import { untrack } from 'svelte';
  import { api, ApiError, errorText } from '../lib/api';
  import type { DnsReport, ReportResult, ReportSection } from '../lib/api/types';
  import { formatDateTime } from '../lib/format';
  import { REPORT_SECTIONS, statusText } from '../lib/report';

  let { name }: { name: string } = $props();

  type View = { state: 'loading' } | { state: 'done'; result: ReportResult } | { state: 'error'; text: string };

  let views = $state<Partial<Record<ReportSection, View>>>({});
  let generation = 0;

  function loadOne(section: ReportSection, refresh: boolean, gen: number) {
    views[section] = { state: 'loading' };
    api.report
      .domain(name, section, refresh)
      .then((result) => {
        if (gen === generation) views[section] = { state: 'done', result };
      })
      .catch((e: unknown) => {
        if (gen !== generation) return;
        const busy = e instanceof ApiError && e.status === 429;
        views[section] = { state: 'error', text: busy ? 'Too many reports run now. Try again in a few seconds.' : errorText(e) };
      });
  }

  function loadAll(refresh: boolean) {
    const gen = ++generation;
    for (const s of REPORT_SECTIONS) loadOne(s.id, refresh, gen);
  }

  // A new name loads a new report.
  $effect(() => {
    void name;
    // The loads write `views`: untrack, so the writes do not run this effect again.
    untrack(() => {
      views = {};
      loadAll(false);
    });
    return () => {
      generation++;
    };
  });

  const loading = $derived(REPORT_SECTIONS.some((s) => views[s.id]?.state === 'loading'));
</script>

<section class="card report" aria-label="Domain report">
  <div class="head">
    <h2>Report <span class="muted small mono">{name}</span></h2>
    <button type="button" disabled={loading} onclick={() => loadAll(true)} title="Ask all sources again (skip the cache)">Refresh</button>
  </div>
  <p class="hint">rusthole asks these sources itself. The browser does not contact them.</p>

  {#each REPORT_SECTIONS as s (s.id)}
    {@const v = views[s.id]}
    <div class="section" data-section={s.id}>
      <h3>
        {s.title}
        {#if v?.state === 'done'}
          <span class="badge" class:ok={v.result.status === 'ok'} class:bad={v.result.status === 'failed'}>{statusText(v.result.status)}</span>
          <span class="muted small">{v.result.cached ? 'from cache, ' : ''}{formatDateTime(v.result.fetched_at)}</span>
        {:else if v?.state === 'loading' || !v}
          <span class="muted small">Loading…</span>
        {/if}
      </h3>
      {#if v?.state === 'error'}
        <p class="field-error">{v.text}</p>
        <button type="button" class="small" onclick={() => loadOne(s.id, false, generation)}>Try again</button>
      {:else if v?.state === 'done'}
        {@const r = v.result}
        {#if r.error}<p class:field-error={r.status === 'failed'} class:muted={r.status !== 'failed'}>{r.error}</p>{/if}
        {#if r.data && s.id === 'dns'}
          {@const d = r.data as DnsReport}
          {#if d.cname_chain.length > 0}
            <p class="small">CNAME chain: <span class="mono">{[d.name, ...d.cname_chain].join(' → ')}</span></p>
          {/if}
          <div class="table-wrap">
            <table>
              <thead><tr><th>Type</th><th>Name</th><th>Result</th><th>Values</th></tr></thead>
              <tbody>
                {#each d.types as t (t.type + t.name)}
                  <tr>
                    <td>{t.type}</td>
                    <td class="mono small">{t.name}</td>
                    <td>
                      <span class="badge" class:ok={t.status === 'ok'} class:bad={t.status === 'failed' || t.status === 'error'}>{t.status}</span>
                      {#if t.error}<div class="muted small">{t.error}</div>{/if}
                    </td>
                    <td class="mono small values">
                      {#each t.records as rec, i (i)}
                        <div title={`TTL ${rec.ttl} s`}>{rec.value}</div>
                      {/each}
                      {#if t.truncated}<div class="muted">More records exist.</div>{/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      {/if}
    </div>
  {/each}
</section>

<style>
  .head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.5rem;
  }
  .section {
    margin-top: 1rem;
  }
  .section h3 {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
  }
  .values {
    overflow-wrap: anywhere;
  }
  p {
    margin: 0.25rem 0;
  }
</style>
