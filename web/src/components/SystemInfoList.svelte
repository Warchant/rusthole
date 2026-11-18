<script lang="ts">
  // The facts of GET /system (docs/API.md 14). The server sends one row for each
  // bound address, so two listeners can have the same kind.
  import type { SystemInfo } from '../lib/api/types';
  import { formatBytes, formatCount, formatDateTime, formatDuration } from '../lib/format';

  let { info }: { info: SystemInfo } = $props();
</script>

<dl class="sys">
  <dt>Version</dt><dd>{info.version}{info.commit ? ` (${info.commit})` : ''}</dd>
  <dt>Uptime</dt><dd>{formatDuration(info.uptime_seconds)} (since {formatDateTime(info.started_at)})</dd>
  <dt>Memory (RSS)</dt><dd>{formatBytes(info.memory_rss_bytes)}</dd>
  <dt>List entries</dt><dd>{formatCount(info.list_entries)}</dd>
  <dt>Config file</dt><dd class="mono">{info.config_path}</dd>
  <dt>Data folder</dt><dd class="mono">{info.data_dir}</dd>
  <dt>Platform</dt><dd>{info.os} / {info.arch}</dd>
  <dt>Listeners</dt>
  <dd>{#each info.listeners as l (`${l.kind} ${l.address}`)}<div class="listener"><span class="badge">{l.kind}</span> <span class="mono">{l.address}</span></div>{/each}</dd>
</dl>

<style>
  .sys {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.35rem 1rem;
    margin: 0 0 0.75rem;
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    min-width: 0;
  }
</style>
