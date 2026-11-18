<script lang="ts">
  import { RANGES } from '../lib/api/types';
  import { prefs, setRange } from '../lib/state.svelte';

  const LABELS = { '24h': '24 h', '7d': '7 days', '30d': '30 days' } as const;
</script>

<div class="segmented" role="group" aria-label="Time range">
  {#each RANGES as r (r)}
    <button type="button" aria-pressed={prefs.range === r} onclick={() => setRange(r)}>{LABELS[r]}</button>
  {/each}
</div>
