<script lang="ts">
  import { dismissToast, toasts } from '../lib/state.svelte';
</script>

<div class="toasts" aria-live="polite">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}" role={t.kind === 'error' ? 'alert' : 'status'}>
      <span>{t.text}</span>
      <button type="button" class="link" aria-label="Close" onclick={() => dismissToast(t.id)}>×</button>
    </div>
  {/each}
</div>

<style>
  .toasts {
    position: fixed;
    right: 1rem;
    bottom: 1rem;
    left: 1rem;
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 0.5rem;
    pointer-events: none;
    z-index: 50;
  }
  .toast {
    pointer-events: auto;
    display: flex;
    gap: 0.75rem;
    align-items: flex-start;
    max-width: 28rem;
    padding: 0.6rem 0.8rem;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--surface);
    box-shadow: 0 4px 16px rgb(0 0 0 / 15%);
  }
  .toast.error {
    border-color: var(--blocked);
  }
  .toast.ok {
    border-color: var(--ok);
  }
  button {
    font-size: 1.1rem;
    line-height: 1;
    color: var(--muted);
  }
</style>
