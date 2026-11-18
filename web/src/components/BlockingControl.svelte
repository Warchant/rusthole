<script lang="ts">
  // Blocking on/off with a timer. The countdown starts from the server value
  // `remaining_seconds` and uses performance.now() (a monotonic clock).
  import { poll } from '../lib/activity';
  import { api } from '../lib/api';
  import type { BlockingState } from '../lib/api/types';
  import { MAX_TIMER_SECONDS, remainingSeconds, TIMER_PRESETS } from '../lib/countdown';
  import { formatCountdown, formatDuration, parseDurationInput } from '../lib/format';
  import { toastError } from '../lib/state.svelte';

  const POLL_MS = 30_000;

  let blocking = $state<BlockingState | null>(null);
  let fetchedAt = 0;
  let now = $state(performance.now());
  let busy = $state(false);
  let custom = $state('');
  let customError = $state<string | null>(null);

  const left = $derived(
    blocking?.remaining_seconds != null ? remainingSeconds(blocking.remaining_seconds, fetchedAt, now) : null,
  );

  function accept(s: BlockingState) {
    blocking = s;
    fetchedAt = performance.now();
    now = fetchedAt;
  }

  async function refresh() {
    try {
      accept(await api.blocking.get());
    } catch (e) {
      toastError(e);
    }
  }

  async function set(enabled: boolean, seconds?: number) {
    busy = true;
    try {
      accept(await api.blocking.set(enabled ? { enabled: true } : { enabled: false, duration_seconds: seconds }));
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }

  function setCustom(e: SubmitEvent) {
    e.preventDefault();
    const s = parseDurationInput(custom);
    if (s === null || s > MAX_TIMER_SECONDS) {
      customError = 'Use for example 90, 10m or 1h30m (at most 24 h).';
      return;
    }
    customError = null;
    custom = '';
    void set(false, s);
  }

  $effect(() => {
    void refresh();
    const tick = setInterval(() => {
      now = performance.now();
    }, 1000);
    // The poll stops while the tab is hidden or the user is away (lib/activity.ts).
    const stopPoll = poll(() => void refresh(), POLL_MS);
    return () => {
      clearInterval(tick);
      stopPoll();
    };
  });

  // When the timer ends, ask the server for the new state.
  $effect(() => {
    if (left === 0) void refresh();
  });
</script>

<section class="card blocking" class:off={blocking && !blocking.enabled} aria-label="Blocking">
  {#if !blocking}
    <p class="muted">Loading blocking state…</p>
  {:else if blocking.enabled}
    <div class="row between">
      <div class="state">
        <span class="dot on" aria-hidden="true"></span>
        <strong>Blocking is on</strong>
      </div>
    </div>
    <div class="row controls">
      <span class="muted small">Disable for</span>
      {#each TIMER_PRESETS as p (p.seconds)}
        <button type="button" class="small" disabled={busy} onclick={() => set(false, p.seconds)}>{p.label}</button>
      {/each}
      <form class="row custom" onsubmit={setCustom}>
        <input class="timer-input" aria-label="Custom time" placeholder="e.g. 10m" bind:value={custom} />
        <button type="submit" class="small" disabled={busy || custom.trim() === ''}>Disable</button>
      </form>
      <button type="button" class="small danger" disabled={busy} onclick={() => set(false)}>Until I enable it</button>
    </div>
    {#if customError}<p class="field-error">{customError}</p>{/if}
  {:else}
    <div class="row between">
      <div class="state">
        <span class="dot" aria-hidden="true"></span>
        <strong>Blocking is off</strong>
        {#if left !== null}
          <span class="muted">· on again in <span class="countdown">{formatCountdown(left)}</span></span>
        {:else}
          <span class="muted">· until you enable it</span>
        {/if}
      </div>
      <button type="button" class="primary" disabled={busy} onclick={() => set(true)}>Enable now</button>
    </div>
    {#if left !== null && left > 0}
      <p class="muted small">Total timer: {formatDuration(blocking.remaining_seconds ?? 0)} when loaded.</p>
    {/if}
  {/if}
</section>

<style>
  .blocking.off {
    border-color: var(--blocked);
    background: var(--blocked-soft);
  }
  .state {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    flex-wrap: wrap;
  }
  .dot {
    width: 0.65rem;
    height: 0.65rem;
    border-radius: 50%;
    background: var(--blocked);
  }
  .dot.on {
    background: var(--ok);
  }
  .controls {
    margin-top: 0.6rem;
  }
  .custom {
    gap: 0.3rem;
  }
  .timer-input {
    width: 6.5rem;
    padding: 0.2rem 0.5rem;
  }
  .countdown {
    font-variant-numeric: tabular-nums;
    font-weight: 600;
    color: var(--text);
  }
  p {
    margin: 0.4rem 0 0;
  }
</style>
