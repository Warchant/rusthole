<script lang="ts" module>
  export interface ShareItem {
    label: string;
    value: number;
    href?: string;
    sub?: string;
    tone?: 'accent' | 'blocked' | 'muted';
  }
</script>

<script lang="ts">
  // A ranked list with a bar for each item. The bar is SVG, so no inline style is needed (CSP).
  import { formatCount, formatPercent } from '../lib/format';
  import { shareOf } from '../lib/grouping';

  let {
    items,
    total = null,
    empty = 'No data.',
  }: { items: ShareItem[]; total?: number | null; empty?: string } = $props();

  const max = $derived(Math.max(1, ...items.map((i) => i.value)));
</script>

{#if items.length === 0}
  <p class="empty">{empty}</p>
{:else}
  <ul class="bars">
    {#each items as item, i (i)}
      <li>
        <div class="row between line">
          <span class="label">
            {#if item.href}<a href={item.href}>{item.label}</a>{:else}{item.label}{/if}
            {#if item.sub}<span class="muted small"> {item.sub}</span>{/if}
          </span>
          <span class="num small">
            {formatCount(item.value)}
            {#if total !== null}<span class="muted">· {formatPercent(shareOf(item.value, total))}</span>{/if}
          </span>
        </div>
        <svg class="track" viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true">
          <rect class="bg" x="0" y="0" width="100" height="4" rx="2" />
          <rect class={item.tone ?? 'accent'} x="0" y="0" width={(item.value / max) * 100} height="4" rx="2" />
        </svg>
      </li>
    {/each}
  </ul>
{/if}

<style>
  .bars {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  li + li {
    margin-top: 0.55rem;
  }
  .line {
    flex-wrap: nowrap;
  }
  .label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }
  .track {
    display: block;
    width: 100%;
    height: 5px;
    margin-top: 0.2rem;
  }
  .bg {
    fill: var(--surface-2);
  }
  .accent {
    fill: var(--accent);
  }
  .blocked {
    fill: var(--blocked);
  }
  .muted {
    fill: var(--muted);
  }
</style>
