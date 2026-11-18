<script lang="ts">
  import Status from '../components/Status.svelte';
  import { api } from '../lib/api';
  import type { Group } from '../lib/api/types';
  import { act, resource } from '../lib/state.svelte';

  const groups = resource(() => api.groups.list());

  let editing = $state<Group | null>(null);
  let name = $state('');
  let comment = $state('');

  function reset() {
    editing = null;
    name = '';
    comment = '';
  }

  function edit(g: Group) {
    editing = g;
    name = g.name;
    comment = g.comment;
    window.scrollTo(0, 0);
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const body = { name: name.trim(), comment: comment.trim() };
    const target = editing;
    const ok = await act(
      () => (target ? api.groups.update(target.id, body) : api.groups.create({ ...body, enabled: true })),
      target ? 'Group saved.' : 'Group added.',
      groups.reload,
    );
    if (ok) reset();
  }

  const toggle = (g: Group) => act(() => api.groups.update(g.id, { enabled: !g.enabled }), null, groups.reload);

  async function remove(g: Group) {
    if (!confirm(`Delete the group "${g.name}"? Lists, rules and clients lose this group.`)) return;
    await act(() => api.groups.remove(g.id), 'Group deleted.', groups.reload);
  }
</script>

<div class="page-head"><h1>Groups</h1></div>

<div class="stack">
  <section class="card">
    <h2>{editing ? 'Edit group' : 'Add a group'}</h2>
    <form class="form" onsubmit={save}>
      <label class="field">
        Name
        <input bind:value={name} maxlength="64" required />
      </label>
      <label class="field">
        Comment
        <input bind:value={comment} />
      </label>
      <div class="row">
        <button type="submit" class="primary">{editing ? 'Save' : 'Add group'}</button>
        {#if editing}<button type="button" onclick={reset}>Cancel</button>{/if}
      </div>
    </form>
  </section>

  <section class="card">
    <p class="hint">
      Lists, rules and clients attach to groups. A client that matches no configured client uses the Default group.
    </p>
    {#if groups.data}
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>On</th><th>Name</th><th class="num">Lists</th><th class="num">Rules</th><th class="num">Clients</th><th></th></tr>
          </thead>
          <tbody>
            {#each groups.data.items as g (g.id)}
              <tr class:off={!g.enabled}>
                <td><input type="checkbox" checked={g.enabled} aria-label="Enabled" onchange={() => toggle(g)} /></td>
                <td>
                  {g.name}
                  {#if g.id === 0}<span class="badge info">default</span>{/if}
                  {#if g.comment}<div class="muted small">{g.comment}</div>{/if}
                </td>
                <td class="num">{g.lists}</td>
                <td class="num">{g.rules}</td>
                <td class="num">{g.clients}</td>
                <td class="actions">
                  <button type="button" class="small" onclick={() => edit(g)}>Edit</button>
                  {#if g.id !== 0}<button type="button" class="small danger" onclick={() => remove(g)}>Delete</button>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <Status loading={groups.loading} error={groups.error} retry={groups.reload} />
    {/if}
  </section>
</div>

<style>
  p {
    margin: 0 0 0.5rem;
  }
</style>
