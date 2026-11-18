<script lang="ts">
  import Status from '../components/Status.svelte';
  import { api, errorText } from '../lib/api';
  import type { AuditEntry } from '../lib/api/types';
  import { formatDateTime } from '../lib/format';

  const FILTERS = [
    { value: '', label: 'All actions' },
    { value: 'auth.', label: 'Login and logout' },
    { value: 'blocking.', label: 'Blocking' },
    { value: 'list.', label: 'Lists' },
    { value: 'rule.', label: 'Rules' },
    { value: 'group.', label: 'Groups' },
    { value: 'client.', label: 'Clients' },
    { value: 'dns.', label: 'Local DNS' },
    { value: 'settings.', label: 'Settings' },
    { value: 'token.', label: 'Tokens' },
    { value: 'totp.', label: 'TOTP' },
  ];

  let action = $state('');
  let items = $state<AuditEntry[]>([]);
  let cursor = $state<string | null>(null);
  let loading = $state(false);
  let error = $state<string | null>(null);

  let generation = 0;
  async function load(reset: boolean) {
    const gen = reset ? ++generation : generation;
    loading = true;
    try {
      const page = await api.audit.list({ action: action || undefined, limit: 50, cursor: reset ? null : cursor });
      if (gen !== generation) return;
      items = reset ? page.items : [...items, ...page.items];
      cursor = page.next_cursor;
      error = null;
    } catch (e) {
      if (gen === generation) error = errorText(e);
    } finally {
      if (gen === generation) loading = false;
    }
  }

  $effect(() => {
    void action;
    void load(true);
  });
</script>

<div class="page-head">
  <h1>Audit log</h1>
  <select aria-label="Filter actions" bind:value={action}>
    {#each FILTERS as f (f.value)}<option value={f.value}>{f.label}</option>{/each}
  </select>
</div>

<section class="card">
  {#if items.length === 0}
    {#if !loading && !error}<p class="empty">No entries.</p>{/if}
    <Status {loading} {error} retry={() => load(true)} />
  {:else}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>By</th><th>Client IP</th><th>Result</th></tr></thead>
        <tbody>
          {#each items as a (a.id)}
            <tr>
              <td class="nowrap">{formatDateTime(a.at)}</td>
              <td class="mono">
                {a.action}
                {#if a.detail}<div class="muted small">{a.detail}</div>{/if}
              </td>
              <td class="mono">{a.target ?? '—'}</td>
              <td>{a.actor}</td>
              <td class="mono">{a.client_ip}</td>
              <td><span class="badge" class:ok={a.result === 'ok'} class:bad={a.result === 'error'}>{a.result}</span></td>
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

<style>
  .more {
    text-align: center;
    margin-top: 0.75rem;
  }
</style>
