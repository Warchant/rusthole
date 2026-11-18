<script lang="ts">
  // The "Block" button of the Domains page: it adds an exact deny rule for one
  // name (docs/API.md section 8) after a confirmation with a group choice.
  import { api, ApiError, errorText } from '../lib/api';
  import type { Group } from '../lib/api/types';
  import { toast } from '../lib/state.svelte';
  import GroupPicker from './GroupPicker.svelte';

  const BLOCK_COMMENT = 'Blocked from the Domains page';

  let { name, onblocked }: { name: string; onblocked: () => void } = $props();

  let open = $state(false);
  let groups = $state<Group[]>([]);
  let chosen = $state<number[]>([0]);
  let busy = $state(false);
  let result = $state<{ ok: boolean; text: string } | null>(null);

  // A new name closes the confirmation and clears the old result.
  $effect(() => {
    void name;
    open = false;
    result = null;
  });

  async function start() {
    open = true;
    result = null;
    chosen = [0];
    try {
      groups = (await api.groups.list()).items;
    } catch (e) {
      result = { ok: false, text: errorText(e) };
    }
  }

  async function confirmBlock() {
    busy = true;
    try {
      const rule = await api.rules.create({
        kind: 'exact',
        action: 'deny',
        pattern: name,
        enabled: true,
        groups: [...chosen],
        comment: BLOCK_COMMENT,
      });
      result = { ok: true, text: `Blocked: exact deny rule ${rule.id} for ${rule.pattern}.` };
      toast('ok', `Blocked ${rule.pattern}.`, 3000);
      open = false;
      onblocked();
    } catch (e) {
      const exists = e instanceof ApiError && e.status === 409;
      result = { ok: false, text: exists ? 'An exact deny rule for this name exists. Change it on the Rules page.' : errorText(e) };
    } finally {
      busy = false;
    }
  }
</script>

<button type="button" class="danger" onclick={start} disabled={open}>Block</button>

{#if open}
  <div class="card confirm" role="group" aria-label="Confirm block">
    <p>Add an exact deny rule for <strong class="mono">{name}</strong>? Other names of this domain stay as they are.</p>
    <div class="field">
      <span class="hint">Groups</span>
      <GroupPicker {groups} bind:value={chosen} />
    </div>
    <div class="row">
      <button type="button" class="danger solid" disabled={busy || chosen.length === 0} onclick={confirmBlock}>Block {name}</button>
      <button type="button" onclick={() => (open = false)}>Cancel</button>
    </div>
    {#if chosen.length === 0}<p class="field-error">Select one group or more.</p>{/if}
  </div>
{/if}
{#if result}
  <p class="result" class:field-error={!result.ok} class:ok-text={result.ok} role="status">
    {result.text}
    {#if result.ok}<a href="#/rules">Rules</a>{/if}
  </p>
{/if}

<style>
  .confirm {
    flex-basis: 100%;
    display: grid;
    gap: 0.5rem;
  }
  .result {
    flex-basis: 100%;
    margin: 0;
  }
  p {
    margin: 0;
  }
</style>
