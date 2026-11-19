<script lang="ts">
  // The domain report (docs/API.md section 17). Each section has its own request,
  // so each card fills in when its source answers. One slow or failed source does
  // not block the others.
  import { untrack } from 'svelte';
  import { api, ApiError, errorText } from '../lib/api';
  import type { DnsReport, RdapReport, ReportResult, ReportSection, ReputationReport, TlsReport } from '../lib/api/types';
  import { formatDateTime } from '../lib/format';
  import { ageDays, REPORT_SECTIONS, statusText, verdictText } from '../lib/report';

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
        {:else if r.data && s.id === 'rdap'}
          {@const d = r.data as RdapReport}
          {@const age = ageDays(d.created, Date.now())}
          <dl class="facts">
            <dt>Domain</dt><dd class="mono">{d.domain ?? '—'}</dd>
            <dt>Registrar</dt><dd>{d.registrar ?? '—'}{#if d.registrar_iana_id} <span class="muted small">(IANA {d.registrar_iana_id})</span>{/if}</dd>
            <dt>Owner</dt><dd>{d.registrant ?? 'not public'}</dd>
            <dt>Created</dt>
            <dd>
              {d.created ? formatDateTime(d.created) : '—'}
              {#if age !== null}<span class="badge" class:bad={age < 30}>{age < 1 ? 'today' : `${age} days ago`}</span>{/if}
            </dd>
            <dt>Expires</dt><dd>{d.expires ? formatDateTime(d.expires) : '—'}</dd>
            <dt>Updated</dt><dd>{d.updated ? formatDateTime(d.updated) : '—'}</dd>
            <dt>Status</dt><dd class="small">{d.status.length > 0 ? d.status.join(', ') : '—'}</dd>
            <dt>Name servers</dt><dd class="mono small">{d.nameservers.length > 0 ? d.nameservers.join(', ') : '—'}</dd>
            <dt>DNSSEC</dt><dd>{d.dnssec === null ? '—' : d.dnssec ? 'signed' : 'not signed'}</dd>
            <dt>Abuse contact</dt><dd class="mono small">{d.abuse_email ?? '—'}</dd>
          </dl>
          {#if d.server}<p class="hint">Source: {d.server}</p>{/if}
        {:else if r.data && s.id === 'tls'}
          {@const d = r.data as TlsReport}
          {@const leaf = d.chain[0]}
          <p>
            <span class="badge" class:ok={d.trusted} class:bad={!d.trusted}>{d.trusted ? 'trusted' : 'not trusted'}</span>
            <span class="muted small">{d.address}{d.version ? `, ${d.version}` : ''}</span>
          </p>
          {#if d.trust_error}<p class="muted small">{d.trust_error}</p>{/if}
          {#if leaf && !leaf.error}
            <dl class="facts">
              <dt>Subject</dt><dd class="mono">{leaf.subject ?? '—'}{#if leaf.subject_org} <span class="muted small">({leaf.subject_org})</span>{/if}</dd>
              <dt>Issuer</dt><dd>{leaf.issuer ?? '—'}{#if leaf.issuer_org} <span class="muted small">({leaf.issuer_org})</span>{/if}{#if leaf.self_signed} <span class="badge bad">self-signed</span>{/if}</dd>
              <dt>Valid</dt>
              <dd>
                {formatDateTime(new Date(leaf.not_before * 1000).toISOString())} – {formatDateTime(new Date(leaf.not_after * 1000).toISOString())}
                <span class="badge" class:bad={leaf.days_left < 14}>{leaf.days_left < 0 ? 'expired' : `${leaf.days_left} days left`}</span>
              </dd>
              <dt>Names</dt><dd class="mono small">{leaf.names.join(', ') || '—'}{leaf.names_truncated ? ' …' : ''}</dd>
            </dl>
          {/if}
          {#if d.chain.length > 1}
            <p class="hint">Chain: {d.chain.map((c) => c.subject ?? '?').join(' → ')}</p>
          {/if}
        {:else if r.data && s.id === 'reputation'}
          {@const d = r.data as ReputationReport}
          <dl class="facts">
            {#each d.filters as f (f.server)}
              <dt>{f.name}</dt>
              <dd>
                <span class="badge" class:bad={f.verdict === 'blocked'} class:ok={f.verdict === 'allowed'}>{verdictText(f.verdict)}</span>
                {#if f.error}<span class="muted small">{f.error}</span>{/if}
              </dd>
            {/each}
            <dt>Tranco rank</dt>
            <dd>
              {#if d.tranco.error}<span class="muted small">{d.tranco.error}</span>
              {:else if d.tranco.rank !== null}#{d.tranco.rank.toLocaleString()} <span class="muted small">of the top 1 million ({d.tranco.domain}, {d.tranco.date})</span>
              {:else}not in the top 1 million <span class="muted small">({d.tranco.domain})</span>{/if}
            </dd>
          </dl>
          <p class="hint">Signals only, not a score. A filter block is a strong sign. A high rank shows that a domain is popular, not that it is safe.</p>
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
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 1rem;
    margin: 0.5rem 0 0;
  }
  .facts dt {
    color: var(--muted);
  }
  .facts dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .values {
    overflow-wrap: anywhere;
  }
  p {
    margin: 0.25rem 0;
  }
</style>
