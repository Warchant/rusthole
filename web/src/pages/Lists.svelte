<script lang="ts">
  import GroupPicker from '../components/GroupPicker.svelte';
  import Status from '../components/Status.svelte';
  import { poll } from '../lib/activity';
  import { api } from '../lib/api';
  import type { Adlist, ListKind } from '../lib/api/types';
  import { formatCount, formatDateTime, formatRelative } from '../lib/format';
  import { groupNames } from '../lib/grouping';
  import { act, actToggle, resource } from '../lib/state.svelte';
  import { isHttpUrl } from '../lib/validate';

  const lists = resource(() => api.lists.list());
  const groups = resource(() => api.groups.list());
  const settings = resource(() => api.settings.get());
  const groupMap = $derived(new Map((groups.data?.items ?? []).map((g) => [g.id, g.name])));

  const running = $derived(
    !!lists.data && (lists.data.schedule.running || lists.data.items.some((l) => l.status.state === 'updating')),
  );

  // Poll while an update runs. The poll stops while the tab is hidden or the user
  // is away (lib/activity.ts).
  $effect(() => {
    if (!running) return;
    return poll(() => lists.reload(), 1500);
  });

  let editing = $state<Adlist | null>(null);
  let url = $state('');
  let comment = $state('');
  let kind = $state<ListKind>('block');
  let chosen = $state<number[]>([0]);
  let urlError = $state<string | null>(null);

  function reset() {
    editing = null;
    url = '';
    comment = '';
    kind = 'block';
    chosen = [0];
    urlError = null;
  }

  function edit(l: Adlist) {
    editing = l;
    url = l.url;
    comment = l.comment;
    kind = l.kind;
    chosen = [...l.groups];
    window.scrollTo(0, 0);
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!isHttpUrl(url.trim())) {
      urlError = 'Use an http or https URL.';
      return;
    }
    urlError = null;
    const body = { url: url.trim(), comment: comment.trim(), kind, groups: chosen };
    const target = editing;
    const ok = await act(
      () => (target ? api.lists.update(target.id, body) : api.lists.create(body)),
      target ? 'List saved.' : 'List added. The first download starts now.',
      lists.reload,
    );
    if (ok) reset();
  }

  const toggle = (e: Event, l: Adlist) => actToggle(e, () => api.lists.update(l.id, { enabled: !l.enabled }), lists.reload);
  const refresh = (l: Adlist) => act(() => api.lists.refresh(l.id), 'Update started.', lists.reload);
  const refreshAll = () => act(() => api.lists.refreshAll(), 'Update of all lists started.', lists.reload);

  async function remove(l: Adlist) {
    if (!confirm(`Delete the list ${l.url}?`)) return;
    await act(() => api.lists.remove(l.id), 'List deleted.', lists.reload);
  }

  async function setInterval_(hours: number) {
    await act(() => api.settings.update({ lists: { refresh_interval_hours: hours } }), 'Schedule saved.', () => {
      lists.reload();
      settings.reload();
    });
  }

  const INTERVALS = [0, 6, 12, 24, 48, 168];
  const intervalLabel = (h: number) => (h === 0 ? 'Manual only' : h === 168 ? 'Every week' : `Every ${h} h`);

  function stateBadge(l: Adlist): { cls: string; text: string } {
    switch (l.status.state) {
      case 'ok':
        return { cls: 'ok', text: 'ok' };
      case 'error':
        return { cls: 'bad', text: 'error' };
      case 'updating':
        return { cls: 'info', text: 'updating' };
      default:
        return { cls: '', text: 'never updated' };
    }
  }
</script>

<div class="page-head">
  <h1>Lists</h1>
  <button type="button" class="primary" disabled={running} onclick={refreshAll}>{running ? 'Updating…' : 'Update all now'}</button>
</div>

<div class="stack">
  {#if lists.data}
    {@const s = lists.data.schedule}
    <section class="card row between">
      <div>
        <strong>Refresh schedule</strong>
        <div class="muted small">
          {#if s.next_run_at}Next run: {formatDateTime(s.next_run_at)} ({formatRelative(s.next_run_at, Date.now())}){:else}Lists update only when you start it.{/if}
        </div>
      </div>
      <label class="check small">
        Interval
        <select
          value={settings.data?.lists.refresh_interval_hours ?? s.interval_hours}
          onchange={(e) => setInterval_(Number(e.currentTarget.value))}
        >
          {#each INTERVALS as h (h)}
            <option value={h}>{intervalLabel(h)}</option>
          {/each}
          {#if !INTERVALS.includes(s.interval_hours)}<option value={s.interval_hours}>Every {s.interval_hours} h</option>{/if}
        </select>
      </label>
    </section>
  {/if}

  <section class="card">
    <h2>{editing ? 'Edit list' : 'Add a list'}</h2>
    <form class="form" onsubmit={save}>
      <label class="field wide">
        URL
        <input type="url" bind:value={url} placeholder="https://lists.example.org/hosts.txt" required aria-invalid={urlError !== null} />
      </label>
      <label class="field">
        Comment
        <input bind:value={comment} />
      </label>
      <label class="field">
        Kind
        <select bind:value={kind}>
          <option value="block">Block list</option>
          <option value="allow">Allow list</option>
        </select>
      </label>
      <div class="field wide">
        <span class="hint">Groups</span>
        <GroupPicker groups={groups.data?.items ?? []} bind:value={chosen} />
      </div>
      <div class="wide">
        {#if urlError}<p class="field-error">{urlError}</p>{/if}
        <p class="hint">Formats: hosts file, one domain per line, or ABP rules (<code>||example.com^</code>).</p>
        <div class="row">
          <button type="submit" class="primary">{editing ? 'Save' : 'Add list'}</button>
          {#if editing}<button type="button" onclick={reset}>Cancel</button>{/if}
        </div>
      </div>
    </form>
  </section>

  <section class="card">
    {#if lists.data}
      {#if lists.data.items.length === 0}
        <p class="empty">No lists. Add a list above.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>On</th><th>List</th><th>Kind</th><th>Groups</th><th>Status</th><th class="num">Entries</th><th></th></tr>
            </thead>
            <tbody>
              {#each lists.data.items as l (l.id)}
                {@const b = stateBadge(l)}
                <tr class:off={!l.enabled}>
                  <td><input type="checkbox" checked={l.enabled} aria-label="Enabled" onchange={(e) => toggle(e, l)} /></td>
                  <td class="list-cell">
                    <div class="mono">{l.url}</div>
                    {#if l.comment}<div class="muted small">{l.comment}</div>{/if}
                  </td>
                  <td><span class="badge" class:bad={l.kind === 'block'} class:ok={l.kind === 'allow'}>{l.kind}</span></td>
                  <td>{groupNames(l.groups, groupMap)}</td>
                  <td class="status-cell">
                    <span class="badge {b.cls}">{b.text}</span>
                    <div class="muted small">Last success: {formatRelative(l.status.last_success_at, Date.now())}</div>
                    {#if l.status.last_update_at && l.status.last_update_at !== l.status.last_success_at}
                      <div class="muted small">Last try: {formatRelative(l.status.last_update_at, Date.now())}</div>
                    {/if}
                    {#if l.status.last_error}<div class="field-error">{l.status.last_error}</div>{/if}
                  </td>
                  <td class="num">
                    {formatCount(l.status.entries)}
                    {#if l.status.invalid_lines > 0}<div class="muted small">{formatCount(l.status.invalid_lines)} bad lines</div>{/if}
                  </td>
                  <td class="actions">
                    <button type="button" class="small" disabled={l.status.state === 'updating'} onclick={() => refresh(l)}>Update</button>
                    <button type="button" class="small" onclick={() => edit(l)}>Edit</button>
                    <button type="button" class="small danger" onclick={() => remove(l)}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {:else}
      <Status loading={lists.loading} error={lists.error} retry={lists.reload} />
    {/if}
  </section>
</div>

<style>
  .list-cell {
    max-width: 28rem;
  }
  .status-cell {
    min-width: 10rem;
  }
  p {
    margin: 0 0 0.5rem;
  }
</style>
