<script lang="ts">
  // Shows "Loading" or an error for a resource that has no data yet.
  let { loading, error, retry }: { loading: boolean; error: string | null; retry?: () => void } = $props();
</script>

{#if error}
  <div class="notice error row between" role="alert">
    <span>{error}</span>
    {#if retry}<button type="button" class="small" onclick={retry}>Try again</button>{/if}
  </div>
{:else if loading}
  <p class="empty">Loading…</p>
{/if}
