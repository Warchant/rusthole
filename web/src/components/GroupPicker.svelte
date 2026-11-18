<script lang="ts">
  import type { Group } from '../lib/api/types';

  let { groups, value = $bindable([]) }: { groups: Group[]; value: number[] } = $props();

  function toggle(id: number, on: boolean) {
    value = on ? [...value, id].sort((a, b) => a - b) : value.filter((x) => x !== id);
  }
</script>

<div class="row picker" role="group" aria-label="Groups">
  {#each groups as g (g.id)}
    <label class="check small">
      <input type="checkbox" checked={value.includes(g.id)} onchange={(e) => toggle(g.id, e.currentTarget.checked)} />
      {g.name}
    </label>
  {/each}
</div>

<style>
  .picker {
    gap: 0.4rem 0.9rem;
    min-height: 2rem;
  }
</style>
