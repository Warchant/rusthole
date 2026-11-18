<script lang="ts">
  // Hour-of-day histogram: 24 stacked bars (allowed and blocked).
  import type { HourArrays } from '../lib/api/types';
  import { allowedSeries } from '../lib/grouping';
  import { niceTicks } from '../lib/chart';
  import { formatCompact, formatCount, formatHour, formatPercent } from '../lib/format';
  import { shareOf } from '../lib/grouping';

  let { hours, height = 180, compact = false }: { hours: HourArrays; height?: number; compact?: boolean } = $props();

  let width = $state(480);
  let hover = $state<number | null>(null);

  const PAD = $derived(compact ? { left: 4, right: 4, top: 4, bottom: 16 } : { left: 40, right: 6, top: 8, bottom: 22 });
  const plotW = $derived(Math.max(24, width - PAD.left - PAD.right));
  const plotH = $derived(height - PAD.top - PAD.bottom);
  const ticks = $derived(niceTicks(Math.max(1, ...hours.queries), compact ? 1 : 4));
  const top = $derived(ticks[ticks.length - 1] ?? 1);
  const allowed = $derived(allowedSeries(hours.queries, hours.blocked));
  const slot = $derived(plotW / 24);
  const barW = $derived(Math.max(2, slot * 0.72));
  const y = (v: number) => PAD.top + plotH - (v / top) * plotH;
  const h = (v: number) => (v / top) * plotH;
  const labelHours = $derived(compact ? [0, 6, 12, 18] : [0, 3, 6, 9, 12, 15, 18, 21]);
</script>

<div class="hist" bind:clientWidth={width}>
  {#if !compact}
    <div class="readout small" aria-live="polite">
      {#if hover !== null}
        {@const q = hours.queries[hover] ?? 0}
        {@const b = hours.blocked[hover] ?? 0}
        <span class="muted">{formatHour(hover)}–{String(hover).padStart(2, '0')}:59</span>
        <span>{formatCount(q)} queries</span>
        <span class="blocked-text">{formatCount(b)} blocked ({formatPercent(shareOf(b, q))})</span>
      {:else}
        <span><i class="key q"></i>Allowed</span>
        <span><i class="key b"></i>Blocked</span>
        <span class="muted">Local time</span>
      {/if}
    </div>
  {/if}
  <svg {width} {height} role="img" aria-label="Queries by hour of day">
    {#if !compact}
      {#each ticks as t (t)}
        <line class="grid" x1={PAD.left} x2={width - PAD.right} y1={y(t)} y2={y(t)} />
        <text class="axis" x={PAD.left - 6} y={y(t) + 4} text-anchor="end">{formatCompact(t)}</text>
      {/each}
    {/if}
    {#each allowed as a, hr (hr)}
      {@const b = hours.blocked[hr] ?? 0}
      {@const x = PAD.left + hr * slot + (slot - barW) / 2}
      <g
        class="bar"
        class:dim={hover !== null && hover !== hr}
        role="presentation"
        onpointerenter={() => (hover = hr)}
        onpointerleave={() => (hover = null)}
      >
        <title>{formatHour(hr)}: {formatCount(hours.queries[hr] ?? 0)} queries, {formatCount(b)} blocked</title>
        <rect class="slot" x={PAD.left + hr * slot} y={PAD.top} width={slot} height={plotH} />
        <rect class="allowed" {x} y={y(a + b)} width={barW} height={h(a)} rx="1.5" />
        <rect class="blocked" {x} y={y(b)} width={barW} height={h(b)} rx="1.5" />
      </g>
    {/each}
    {#each labelHours as hr (hr)}
      <text class="axis" x={PAD.left + hr * slot + slot / 2} y={height - (compact ? 3 : 6)} text-anchor="middle">
        {compact ? hr : formatHour(hr)}
      </text>
    {/each}
  </svg>
</div>

<style>
  .hist {
    width: 100%;
    min-width: 0;
  }
  svg {
    display: block;
  }
  .readout {
    display: flex;
    flex-wrap: wrap;
    gap: 0.9rem;
    min-height: 1.4rem;
  }
  .key {
    display: inline-block;
    width: 0.7rem;
    height: 0.7rem;
    border-radius: 2px;
    margin-right: 0.3rem;
    vertical-align: -1px;
  }
  .key.q {
    background: var(--accent);
  }
  .key.b {
    background: var(--blocked);
  }
  .grid {
    stroke: var(--chart-grid);
  }
  .axis {
    fill: var(--muted);
    font-size: 11px;
  }
  .slot {
    fill: transparent;
  }
  .allowed {
    fill: var(--accent);
  }
  .blocked {
    fill: var(--blocked);
  }
  .bar.dim .allowed,
  .bar.dim .blocked {
    opacity: 0.45;
  }
</style>
