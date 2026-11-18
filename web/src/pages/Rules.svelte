<script lang="ts">
  // Exact and regex rules. The regex test calls the server (Rust regex,
  // case-insensitive). The UI never tests with JavaScript RegExp.
  import GroupPicker from '../components/GroupPicker.svelte';
  import Status from '../components/Status.svelte';
  import { api, errorText } from '../lib/api';
  import type { Rule, RuleAction, RuleKind, RuleTestResult } from '../lib/api/types';
  import { formatRelative } from '../lib/format';
  import { groupNames } from '../lib/grouping';
  import { act, actToggle, resource } from '../lib/state.svelte';

  const rules = resource(() => api.rules.list());
  const groups = resource(() => api.groups.list());
  const groupMap = $derived(new Map((groups.data?.items ?? []).map((g) => [g.id, g.name])));

  let filterKind = $state<'all' | RuleKind>('all');
  let filterAction = $state<'all' | RuleAction>('all');
  const shown = $derived(
    (rules.data?.items ?? []).filter(
      (r) => (filterKind === 'all' || r.kind === filterKind) && (filterAction === 'all' || r.action === filterAction),
    ),
  );

  let editing = $state<Rule | null>(null);
  let kind = $state<RuleKind>('exact');
  let action = $state<RuleAction>('deny');
  let pattern = $state('');
  let comment = $state('');
  let chosen = $state<number[]>([0]);

  let testDomain = $state('');
  let test = $state<RuleTestResult | null>(null);
  let testError = $state<string | null>(null);

  // Test the pattern against the domain on the server, with a short delay.
  $effect(() => {
    const p = pattern;
    const d = testDomain.trim();
    const k = kind;
    test = null;
    testError = null;
    if (!p || !d) return;
    let live = true;
    const t = setTimeout(() => {
      api.rules
        .test(k, p, d)
        .then((r) => {
          if (live) test = r;
        })
        .catch((e: unknown) => {
          if (live) testError = errorText(e);
        });
    }, 300);
    return () => {
      live = false;
      clearTimeout(t);
    };
  });

  function reset() {
    editing = null;
    kind = 'exact';
    action = 'deny';
    pattern = '';
    comment = '';
    chosen = [0];
  }

  function edit(r: Rule) {
    editing = r;
    kind = r.kind;
    action = r.action;
    pattern = r.pattern;
    comment = r.comment;
    chosen = [...r.groups];
    window.scrollTo(0, 0);
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const body = { kind, action, pattern: pattern.trim(), comment: comment.trim(), groups: chosen };
    const target = editing;
    const ok = await act(
      () => (target ? api.rules.update(target.id, body) : api.rules.create({ ...body, enabled: true })),
      target ? 'Rule saved.' : 'Rule added.',
      rules.reload,
    );
    if (ok) reset();
  }

  const toggle = (e: Event, r: Rule) => actToggle(e, () => api.rules.update(r.id, { enabled: !r.enabled }), rules.reload);

  async function remove(r: Rule) {
    if (!confirm(`Delete the rule ${r.pattern}?`)) return;
    await act(() => api.rules.remove(r.id), 'Rule deleted.', rules.reload);
  }
</script>

<div class="page-head">
  <h1>Rules</h1>
</div>

<div class="stack">
  <section class="card">
    <h2>{editing ? 'Edit rule' : 'Add a rule'}</h2>
    <form class="form" onsubmit={save}>
      <label class="field">
        Type
        <select bind:value={kind}>
          <option value="exact">Exact domain</option>
          <option value="regex">Regex</option>
        </select>
      </label>
      <label class="field">
        Action
        <select bind:value={action}>
          <option value="deny">Deny (block)</option>
          <option value="allow">Allow</option>
        </select>
      </label>
      <label class="field wide">
        {kind === 'exact' ? 'Domain' : 'Regex (case-insensitive)'}
        <input class="mono" bind:value={pattern} placeholder={kind === 'exact' ? 'ads.example.net' : '^ads?[0-9]*\\.'} required />
      </label>
      <label class="field">
        Comment
        <input bind:value={comment} />
      </label>
      <label class="field">
        Test against a domain
        <input bind:value={testDomain} placeholder="ads.example.net" />
      </label>
      <div class="field wide">
        <span class="hint">Groups</span>
        <GroupPicker groups={groups.data?.items ?? []} bind:value={chosen} />
      </div>
      <div class="wide">
        {#if testError}
          <p class="field-error">{testError}</p>
        {:else if test}
          {#if !test.valid}
            <p class="field-error">The pattern is not valid: {test.error}</p>
          {:else if test.matches}
            <p class="notice ok">The pattern matches {testDomain.trim()}.</p>
          {:else}
            <p class="notice">The pattern does not match {testDomain.trim()}.</p>
          {/if}
        {/if}
        <p class="hint">An allow rule beats a deny rule. The regex engine is the Rust <code>regex</code> crate (no look-around, no back-references).</p>
        <div class="row">
          <button type="submit" class="primary">{editing ? 'Save' : 'Add rule'}</button>
          {#if editing}<button type="button" onclick={reset}>Cancel</button>{/if}
        </div>
      </div>
    </form>
  </section>

  <section class="card">
    <div class="row filters">
      <div class="segmented" role="group" aria-label="Type">
        {#each ['all', 'exact', 'regex'] as const as k (k)}
          <button type="button" aria-pressed={filterKind === k} onclick={() => (filterKind = k)}>{k}</button>
        {/each}
      </div>
      <div class="segmented" role="group" aria-label="Action">
        {#each ['all', 'deny', 'allow'] as const as a (a)}
          <button type="button" aria-pressed={filterAction === a} onclick={() => (filterAction = a)}>{a}</button>
        {/each}
      </div>
    </div>
    {#if rules.data}
      {#if shown.length === 0}
        <p class="empty">No rules.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>On</th><th>Pattern</th><th>Type</th><th>Action</th><th>Groups</th><th>Changed</th><th></th></tr></thead>
            <tbody>
              {#each shown as r (r.id)}
                <tr class:off={!r.enabled}>
                  <td><input type="checkbox" checked={r.enabled} aria-label="Enabled" onchange={(e) => toggle(e, r)} /></td>
                  <td>
                    <div class="mono">{r.pattern}</div>
                    {#if r.comment}<div class="muted small">{r.comment}</div>{/if}
                  </td>
                  <td><span class="badge">{r.kind}</span></td>
                  <td><span class="badge" class:bad={r.action === 'deny'} class:ok={r.action === 'allow'}>{r.action}</span></td>
                  <td>{groupNames(r.groups, groupMap)}</td>
                  <td class="nowrap">{formatRelative(r.updated_at, Date.now())}</td>
                  <td class="actions">
                    <button type="button" class="small" onclick={() => edit(r)}>Edit</button>
                    <button type="button" class="small danger" onclick={() => remove(r)}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {:else}
      <Status loading={rules.loading} error={rules.error} retry={rules.reload} />
    {/if}
  </section>
</div>

<style>
  .filters {
    margin-bottom: 0.75rem;
  }
  .segmented button {
    text-transform: capitalize;
  }
  p {
    margin: 0 0 0.5rem;
  }
</style>
