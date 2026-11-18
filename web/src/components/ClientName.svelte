<script lang="ts">
  // Gives a seen client a name. The name is the comment of a configured client
  // (docs/API.md section 9). If a configured client matches, this form changes its
  // comment. If not, it adds a configured client for the MAC or an IP address of
  // the device. The new client gets the groups that the device has now, so the
  // blocking does not change. A CIDR client is a network, not a device: this form
  // does not change its comment, it adds a client for the device.
  import { api } from '../lib/api';
  import type { Client, StatsClientDetail } from '../lib/api/types';
  import { act } from '../lib/state.svelte';

  let { detail, onsaved }: { detail: StatsClientDetail; onsaved: () => void } = $props();

  let configured = $state<Client | null>(null);
  let loadError = $state<string | null>(null);
  let name = $state('');
  let target = $state('');
  let saving = $state(false);

  // The configured client to change: not a CIDR client (a network).
  const own = $derived(configured && configured.kind !== 'cidr' ? configured : null);
  // The values that a new configured client can match: the MAC first, then each IP.
  const targets = $derived([...(detail.mac ? [detail.mac] : []), ...detail.ips.filter((ip) => !ip.includes(':'))]);

  $effect(() => {
    const id = detail.client_id;
    let live = true;
    configured = null;
    loadError = null;
    name = detail.name ?? '';
    if (id !== null) {
      api.clients
        .get(id)
        .then((c) => {
          if (!live) return;
          configured = c;
          name = c.kind === 'cidr' ? '' : c.comment;
        })
        .catch(() => {
          if (live) loadError = 'Cannot read the configured client.';
        });
    }
    return () => {
      live = false;
    };
  });

  $effect(() => {
    if (!targets.includes(target)) target = targets[0] ?? '';
  });

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const text = name.trim();
    saving = true;
    const c = own;
    const groups = configured ? [...configured.groups] : [0];
    const ok = c
      ? await act(() => api.clients.update(c.id, { comment: text }), 'Name saved.')
      : await act(() => api.clients.create({ match: target, groups, comment: text }), 'Client added with this name.');
    saving = false;
    if (ok) onsaved();
  }
</script>

<section class="card">
  <h2>Name</h2>
  {#if detail.client_id !== null && !configured}
    {#if loadError}<p class="field-error">{loadError}</p>{:else}<p class="muted small">Loading…</p>{/if}
  {:else if !own && targets.length === 0}
    <p class="muted">This client has no MAC or IPv4 address to match.</p>
  {:else}
    <form class="row name-form" onsubmit={save}>
      <input bind:value={name} placeholder="laptop" aria-label="Client name" maxlength="500" />
      {#if own}
        <span class="muted small">Configured client: <span class="mono">{own.match}</span> ({own.kind.toUpperCase()})</span>
      {:else}
        <label class="check small muted">
          Match by
          <select bind:value={target} aria-label="Match by">
            {#each targets as t (t)}
              <option value={t}>{t === detail.mac ? `MAC ${t}` : `IP ${t}`}</option>
            {/each}
          </select>
        </label>
      {/if}
      <button type="submit" class="primary" disabled={saving}>Save name</button>
    </form>
    {#if !own}
      <p class="hint">
        This adds a configured client with the groups that the device has now{configured
          ? ` (from the network ${configured.match})`
          : ' (default)'}. A MAC match follows the device when its IP changes. An IP match wins over a MAC match. Change the
        groups on the Clients page.
      </p>
    {/if}
  {/if}
</section>

<style>
  .name-form input {
    flex: 1;
    min-width: 10rem;
    max-width: 22rem;
  }
  p {
    margin: 0.5rem 0 0;
  }
</style>
