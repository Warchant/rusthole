<script lang="ts">
  // Configured clients (CRUD) and the list of seen clients for a quick add.
  import GroupPicker from '../components/GroupPicker.svelte';
  import Status from '../components/Status.svelte';
  import { api } from '../lib/api';
  import type { Client, SeenClient } from '../lib/api/types';
  import { formatCount, formatRelative } from '../lib/format';
  import { groupNames } from '../lib/grouping';
  import { act, resource } from '../lib/state.svelte';
  import { classifyClientMatch, IPV6_HINT } from '../lib/validate';

  const clients = resource(() => api.clients.list());
  const groups = resource(() => api.groups.list());
  const seen = resource(() => api.clients.seen({ limit: 200 }));

  const groupMap = $derived(new Map((groups.data?.items ?? []).map((g) => [g.id, g.name])));

  let editing = $state<Client | null>(null);
  let match = $state('');
  let comment = $state('');
  let chosen = $state<number[]>([0]);
  let touched = $state(false);

  const check = $derived(classifyClientMatch(match));
  const formError = $derived(touched && !check.ok ? check.error : null);

  function reset() {
    editing = null;
    match = '';
    comment = '';
    chosen = [0];
    touched = false;
  }

  function edit(c: Client) {
    editing = c;
    match = c.match;
    comment = c.comment;
    chosen = [...c.groups];
    touched = false;
    window.scrollTo(0, 0);
  }

  function prefill(s: SeenClient) {
    reset();
    match = s.mac ?? s.ip;
    comment = s.name?.replace(/\.lan$/, '') ?? '';
    window.scrollTo(0, 0);
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    touched = true;
    if (!check.ok) return;
    const body = { match: match.trim(), comment: comment.trim(), groups: chosen };
    const target = editing;
    const ok = await act(
      () => (target ? api.clients.update(target.id, body) : api.clients.create(body)),
      target ? 'Client saved.' : 'Client added.',
      () => {
        clients.reload();
        seen.reload();
      },
    );
    if (ok) reset();
  }

  async function remove(c: Client) {
    if (!confirm(`Delete the client "${c.comment || c.match}"?`)) return;
    await act(() => api.clients.remove(c.id), 'Client deleted.', () => {
      clients.reload();
      seen.reload();
    });
  }
</script>

<div class="stack">
  <section class="card">
    <h2>{editing ? 'Edit client' : 'Add a client'}</h2>
    <form class="form" onsubmit={save}>
      <label class="field">
        IP, CIDR, MAC or host name
        <input
          bind:value={match}
          onblur={() => (touched = match !== '')}
          placeholder="192.0.2.10 or 02:00:00:00:00:01"
          aria-invalid={formError !== null}
          required
        />
      </label>
      <label class="field">
        Name (comment)
        <input bind:value={comment} placeholder="laptop" />
      </label>
      <div class="field wide">
        <span class="hint">Groups</span>
        <GroupPicker groups={groups.data?.items ?? []} bind:value={chosen} />
      </div>
      <div class="wide">
        {#if formError}
          <p class="field-error">{formError}</p>
        {:else}
          <p class="hint">
            {check.ok ? `Kind: ${check.value.toUpperCase()}.` : ''} rusthole v1 uses IPv4 only. {IPV6_HINT.split('.')[0]}.
          </p>
        {/if}
        <div class="row">
          <button type="submit" class="primary">{editing ? 'Save' : 'Add client'}</button>
          {#if editing}<button type="button" onclick={reset}>Cancel</button>{/if}
        </div>
      </div>
    </form>
  </section>

  <section class="card">
    <h2>Configured clients</h2>
    {#if clients.data}
      {#if clients.data.items.length === 0}
        <p class="empty">No configured clients. All clients use the Default group.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Name</th><th>Match</th><th>Kind</th><th>Groups</th><th></th></tr>
            </thead>
            <tbody>
              {#each clients.data.items as c (c.id)}
                <tr>
                  <td>{c.comment || '—'}</td>
                  <td class="mono">{c.match}</td>
                  <td><span class="badge">{c.kind}</span></td>
                  <td>{groupNames(c.groups, groupMap)}</td>
                  <td class="actions">
                    <button type="button" class="small" onclick={() => edit(c)}>Edit</button>
                    <button type="button" class="small danger" onclick={() => remove(c)}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {:else}
      <Status loading={clients.loading} error={clients.error} retry={clients.reload} />
    {/if}
  </section>

  <section class="card">
    <h2>Seen clients</h2>
    <p class="hint">Clients that sent queries. Add one to put it in a group.</p>
    {#if seen.data}
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Name</th><th>IP</th><th>MAC</th><th class="num">Queries (24 h)</th><th>Last seen</th><th></th></tr>
          </thead>
          <tbody>
            {#each seen.data.items as s (s.ip)}
              <tr>
                <td>{s.name ?? '—'}</td>
                <td class="mono">{s.ip}</td>
                <td class="mono">{s.mac ?? '—'}</td>
                <td class="num">{formatCount(s.queries)}</td>
                <td class="nowrap">{formatRelative(s.last_seen_at, Date.now())}</td>
                <td class="actions">
                  {#if s.client_id === null}
                    <button type="button" class="small" onclick={() => prefill(s)}>Add</button>
                  {:else}
                    <span class="badge ok">configured</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <Status loading={seen.loading} error={seen.error} retry={seen.reload} />
    {/if}
  </section>
</div>

<style>
  p {
    margin: 0 0 0.5rem;
  }
</style>
