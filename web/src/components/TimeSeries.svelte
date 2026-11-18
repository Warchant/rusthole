<script lang="ts">
  // Queries over time: total queries and blocked queries as two areas.
  import type { Timeline } from '../lib/api/types';
  import { areaPath, bucketAt, linePath, niceTicks } from '../lib/chart';
  import { formatCompact, formatCount } from '../lib/format';

  let { timeline, height = 200 }: { timeline: Timeline; height?: number } = $props();

  let width = $state(600);
  let hover = $state<number | null>(null);

  const PAD = { left: 40, right: 8, top: 8, bottom: 22 };

  const fromMs = $derived(Date.parse(timeline.from));
  const n = $derived(timeline.queries.length);
  const plotW = $derived(Math.max(10, width - PAD.left - PAD.right));
  const plotH = $derived(height - PAD.top - PAD.bottom);
  const ticks = $derived(niceTicks(Math.max(1, ...timeline.queries), 4));
  const top = $derived(ticks[ticks.length - 1] ?? 1);
  const xs = $derived(timeline.queries.map((_, i) => PAD.left + ((i + 0.5) / Math.max(1, n)) * plotW));
  const y = (v: number) => PAD.top + plotH - (v / top) * plotH;
  const qY = $derived(timeline.queries.map(y));
  const bY = $derived(timeline.blocked.map(y));
  const base = $derived(PAD.top + plotH);

  const daysRange = $derived(timeline.bucket_seconds >= 3600);
  const timeFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });
  const dayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
  const fullFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

  const xLabels = $derived.by(() => {
    const count = Math.max(2, Math.min(7, Math.floor(plotW / 90)));
    const out: { x: number; text: string }[] = [];
    for (let k = 0; k < count; k++) {
      const i = Math.round((k / (count - 1)) * (n - 1));
      const t = fromMs + i * timeline.bucket_seconds * 1000;
      out.push({ x: xs[i] ?? 0, text: daysRange ? dayFmt.format(t) : timeFmt.format(t) });
    }
    return out;
  });

  function onMove(e: PointerEvent) {
    const rect = (e.currentTarget as SVGRectElement).getBoundingClientRect();
    hover = bucketAt(e.clientX - rect.left, rect.width, n);
  }

  const readout = $derived.by(() => {
    if (hover === null) return null;
    const t = fromMs + hover * timeline.bucket_seconds * 1000;
    return {
      time: fullFmt.format(t),
      queries: timeline.queries[hover] ?? 0,
      blocked: timeline.blocked[hover] ?? 0,
    };
  });
</script>

<div class="chart" bind:clientWidth={width}>
  <div class="readout small" aria-live="polite">
    {#if readout}
      <span class="muted">{readout.time}</span>
      <span><i class="key q"></i>{formatCount(readout.queries)} queries</span>
      <span><i class="key b"></i>{formatCount(readout.blocked)} blocked</span>
    {:else}
      <span><i class="key q"></i>Queries</span>
      <span><i class="key b"></i>Blocked</span>
      <span class="muted">{formatCount(timeline.bucket_seconds / 60)} min per bar</span>
    {/if}
  </div>
  <svg {width} {height} role="img" aria-label="Queries over time">
    {#each ticks as t (t)}
      <line class="grid" x1={PAD.left} x2={width - PAD.right} y1={y(t)} y2={y(t)} />
      <text class="axis" x={PAD.left - 6} y={y(t) + 4} text-anchor="end">{formatCompact(t)}</text>
    {/each}
    <path class="area-q" d={areaPath(xs, qY, base)} />
    <path class="line-q" d={linePath(xs, qY)} />
    <path class="area-b" d={areaPath(xs, bY, base)} />
    <path class="line-b" d={linePath(xs, bY)} />
    {#each xLabels as l, i (i)}
      <text class="axis" x={l.x} y={height - 6} text-anchor={i === 0 ? 'start' : i === xLabels.length - 1 ? 'end' : 'middle'}>{l.text}</text>
    {/each}
    {#if hover !== null}
      <line class="cursor" x1={xs[hover]} x2={xs[hover]} y1={PAD.top} y2={base} />
    {/if}
    <rect
      role="presentation"
      class="hit"
      x={PAD.left}
      y={PAD.top}
      width={plotW}
      height={plotH}
      onpointermove={onMove}
      onpointerleave={() => (hover = null)}
    />
  </svg>
</div>

<style>
  .chart {
    width: 100%;
    min-width: 0;
  }
  svg {
    display: block;
    overflow: visible;
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
  .area-q {
    fill: var(--accent);
    opacity: 0.18;
  }
  .line-q {
    fill: none;
    stroke: var(--accent);
    stroke-width: 1.5;
  }
  .area-b {
    fill: var(--blocked);
    opacity: 0.25;
  }
  .line-b {
    fill: none;
    stroke: var(--blocked);
    stroke-width: 1.5;
  }
  .cursor {
    stroke: var(--muted);
    stroke-dasharray: 3 3;
  }
  .hit {
    fill: transparent;
    cursor: crosshair;
  }
</style>
