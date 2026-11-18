<script lang="ts">
  // Settings (docs/API.md 12). Each section saves alone with PATCH /settings.
  // Listener addresses, TLS files and the password are not here: they are in
  // rusthole.toml and `rusthole passwd`.
  import Status from '../components/Status.svelte';
  import { api, ApiError, errorText } from '../lib/api';
  import type { Settings, SettingsPatch } from '../lib/api/types';
  import { formatBytes, formatCount, formatDateTime, formatDuration } from '../lib/format';
  import { resource, toast } from '../lib/state.svelte';
  import { checkCidrs, checkServers, IPV6_HINT, isIPv4, splitList } from '../lib/validate';
  import SettingsSecurity from './SettingsSecurity.svelte';

  const system = resource(() => api.system.get());

  let saved = $state<Settings | null>(null);
  let draft = $state<Settings | null>(null);
  let loadError = $state<string | null>(null);
  let upstreamText = $state('');
  let cidrText = $state('');
  let errors = $state<Record<string, string | null>>({});

  function accept(s: Settings) {
    saved = s;
    draft = structuredClone(s);
    upstreamText = s.upstreams.servers.join('\n');
    cidrText = s.acl.extra_cidrs.join('\n');
  }

  async function load() {
    try {
      accept(await api.settings.get());
      loadError = null;
    } catch (e) {
      loadError = errorText(e);
    }
  }

  $effect(() => {
    void load();
  });

  function setSection<K extends keyof Settings>(target: Settings, key: K, value: Settings[K]) {
    target[key] = value;
  }

  /**
   * Saves one section. On success, only that section of the draft changes, so
   * unsaved edits in other sections stay. On a 422 the input stays, so the user
   * can correct it. Only a config conflict loads all data again.
   */
  async function save(section: keyof SettingsPatch, patch: SettingsPatch, label: string) {
    errors[section] = null;
    try {
      const next = await api.settings.update(patch);
      saved = next;
      if (draft) {
        setSection(draft, section, structuredClone(next[section]));
        if (section === 'upstreams') upstreamText = next.upstreams.servers.join('\n');
        if (section === 'acl') cidrText = next.acl.extra_cidrs.join('\n');
      }
      toast('ok', `${label} saved.`, 3000);
    } catch (e) {
      errors[section] = errorText(e);
      if (e instanceof ApiError && e.code === 'config_conflict') await load();
    }
  }

  function saveUpstreams(e: SubmitEvent) {
    e.preventDefault();
    if (!draft) return;
    const servers = splitList(upstreamText);
    const err = checkServers(servers, 8);
    if (err) {
      errors.upstreams = err;
      return;
    }
    void save('upstreams', { upstreams: { ...draft.upstreams, servers } }, 'Upstreams');
  }

  function saveBlocking(e: SubmitEvent) {
    e.preventDefault();
    if (!draft) return;
    const b = { ...draft.blocking };
    if (b.mode === 'custom_ip') {
      if (!b.custom_ipv4 || !isIPv4(b.custom_ipv4)) {
        errors.blocking = 'Enter an IPv4 address for the custom reply.';
        return;
      }
    } else {
      b.custom_ipv4 = null;
      b.custom_ipv6 = null;
    }
    void save('blocking', { blocking: b }, 'Blocking');
  }

  function saveAcl(e: SubmitEvent) {
    e.preventDefault();
    const cidrs = splitList(cidrText);
    const err = checkCidrs(cidrs, 64);
    if (err) {
      errors.acl = err;
      return;
    }
    void save('acl', { acl: { extra_cidrs: cidrs } }, 'Access control');
  }

  function saveSection(key: 'cache' | 'rate_limit' | 'stats', label: string) {
    return (e: SubmitEvent) => {
      e.preventDefault();
      if (!draft) return;
      void save(key, { [key]: draft[key] } as SettingsPatch, label);
    };
  }
</script>

<div class="page-head"><h1>Settings</h1></div>

{#if !draft}
  <Status loading={!loadError} error={loadError} retry={load} />
{:else}
  <div class="stack">
    <div class="grid-2">
      <section class="card">
        <h2>Upstream DNS servers</h2>
        <form class="form" onsubmit={saveUpstreams}>
          <label class="field wide">
            Servers (one per line, IPv4 with an optional port)
            <textarea rows="3" bind:value={upstreamText}></textarea>
          </label>
          <label class="field">
            Timeout (ms)
            <input type="number" min="100" max="10000" bind:value={draft.upstreams.timeout_ms} />
          </label>
          <div class="wide">
            <p class="hint">{IPV6_HINT} DNS over TLS and DNS over HTTPS upstreams come in a later part.</p>
            {#if errors.upstreams}<p class="field-error">{errors.upstreams}</p>{/if}
            <button type="submit" class="primary">Save</button>
          </div>
        </form>
      </section>

      <section class="card">
        <h2>Blocking</h2>
        <form class="form" onsubmit={saveBlocking}>
          <label class="field">
            Reply for blocked names
            <select bind:value={draft.blocking.mode}>
              <option value="null">0.0.0.0 and :: (default)</option>
              <option value="nxdomain">NXDOMAIN</option>
              <option value="refused">REFUSED</option>
              <option value="custom_ip">Custom IP</option>
            </select>
          </label>
          <label class="field">
            TTL of blocked replies (s)
            <input type="number" min="0" max="3600" bind:value={draft.blocking.blocked_ttl} />
          </label>
          {#if draft.blocking.mode === 'custom_ip'}
            <label class="field">
              Custom IPv4
              <input class="mono" bind:value={draft.blocking.custom_ipv4} placeholder="192.0.2.2" />
            </label>
            <label class="field">
              Custom IPv6 (AAAA reply, optional)
              <input class="mono" bind:value={draft.blocking.custom_ipv6} placeholder="::" />
            </label>
          {/if}
          <label class="check wide">
            <input type="checkbox" bind:checked={draft.blocking.special_domains} />
            Special domains (Firefox DoH canary, iCloud Private Relay)
          </label>
          <label class="check wide">
            <input type="checkbox" bind:checked={draft.blocking.cname_check} />
            Check CNAME targets (stops CNAME cloaking)
          </label>
          <div class="wide">
            {#if errors.blocking}<p class="field-error">{errors.blocking}</p>{/if}
            <button type="submit" class="primary">Save</button>
          </div>
        </form>
      </section>

      <section class="card">
        <h2>Cache</h2>
        <form class="form" onsubmit={saveSection('cache', 'Cache')}>
          <label class="check wide"><input type="checkbox" bind:checked={draft.cache.enabled} /> Cache on</label>
          <label class="field">Max entries<input type="number" min="0" max="1000000" bind:value={draft.cache.max_entries} /></label>
          <label class="field">Min TTL (s)<input type="number" min="0" bind:value={draft.cache.min_ttl} /></label>
          <label class="field">Max TTL (s)<input type="number" min="0" bind:value={draft.cache.max_ttl} /></label>
          <label class="field">Negative TTL (s)<input type="number" min="0" bind:value={draft.cache.negative_ttl} /></label>
          <div class="wide">
            {#if errors.cache}<p class="field-error">{errors.cache}</p>{/if}
            <button type="submit" class="primary">Save</button>
          </div>
        </form>
      </section>

      <section class="card">
        <h2>Rate limit</h2>
        <form class="form" onsubmit={saveSection('rate_limit', 'Rate limit')}>
          <label class="field">
            Queries per second per client (0 = no limit)
            <input type="number" min="0" bind:value={draft.rate_limit.queries_per_second} />
          </label>
          <label class="field">Burst<input type="number" min="0" bind:value={draft.rate_limit.burst} /></label>
          <div class="wide">
            {#if errors.rate_limit}<p class="field-error">{errors.rate_limit}</p>{/if}
            <button type="submit" class="primary">Save</button>
          </div>
        </form>
      </section>

      <section class="card">
        <h2>Access control</h2>
        <form class="form" onsubmit={saveAcl}>
          <div class="wide">
            <span class="hint">Local subnets (found on the interfaces, always allowed)</span>
            <div class="mono">{saved?.acl.local_subnets.join(', ') || 'none'}</div>
          </div>
          <label class="field wide">
            Extra allowed IPv4 CIDRs (one per line)
            <textarea rows="3" bind:value={cidrText} placeholder="198.51.100.0/24"></textarea>
          </label>
          <div class="wide">
            <p class="hint">Other clients get no answer. {IPV6_HINT}</p>
            {#if errors.acl}<p class="field-error">{errors.acl}</p>{/if}
            <button type="submit" class="primary">Save</button>
          </div>
        </form>
      </section>

      <section class="card">
        <h2>Statistics</h2>
        <form class="form" onsubmit={saveSection('stats', 'Statistics')}>
          <label class="field">
            Flush to disk every (s, 0 = RAM only)
            <input type="number" min="0" max="3600" bind:value={draft.stats.flush_interval_seconds} />
          </label>
          <label class="field">Keep for (days)<input type="number" min="1" max="365" bind:value={draft.stats.retention_days} /></label>
          <label class="field">
            Recent queries kept in RAM
            <input type="number" min="100" max="100000" bind:value={draft.stats.recent_queries_size} />
          </label>
          <div class="wide">
            <p class="hint">A longer flush interval gives fewer writes to the SD card. A crash loses the data since the last flush.</p>
            {#if errors.stats}<p class="field-error">{errors.stats}</p>{/if}
            <button type="submit" class="primary">Save</button>
          </div>
        </form>
      </section>
    </div>

    <SettingsSecurity />

    <section class="card">
      <h2>System</h2>
      {#if system.data}
        {@const s = system.data}
        <dl class="sys">
          <dt>Version</dt><dd>{s.version}{s.commit ? ` (${s.commit})` : ''}</dd>
          <dt>Uptime</dt><dd>{formatDuration(s.uptime_seconds)} (since {formatDateTime(s.started_at)})</dd>
          <dt>Memory (RSS)</dt><dd>{formatBytes(s.memory_rss_bytes)}</dd>
          <dt>List entries</dt><dd>{formatCount(s.list_entries)}</dd>
          <dt>Config file</dt><dd class="mono">{s.config_path}</dd>
          <dt>Data folder</dt><dd class="mono">{s.data_dir}</dd>
          <dt>Platform</dt><dd>{s.os} / {s.arch}</dd>
          <dt>Listeners</dt>
          <dd>{#each s.listeners as l (l.kind)}<div><span class="badge">{l.kind}</span> <span class="mono">{l.address}</span></div>{/each}</dd>
        </dl>
        <p class="hint">To change the password, run <code>rusthole passwd</code> on the server.</p>
      {:else}
        <Status loading={system.loading} error={system.error} retry={system.reload} />
      {/if}
    </section>
  </div>
{/if}

<style>
  p {
    margin: 0 0 0.5rem;
  }
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
