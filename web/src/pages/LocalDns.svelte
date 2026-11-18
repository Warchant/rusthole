<script lang="ts">
  // Local A/AAAA records, CNAMEs and conditional forwarding (docs/API.md 10).
  import Status from '../components/Status.svelte';
  import { api } from '../lib/api';
  import type { Forwarder, LocalCname, LocalRecord } from '../lib/api/types';
  import { act, resource } from '../lib/state.svelte';
  import { checkForwardDomain, checkServers, IPV6_HINT, isHostname, isIPv4, looksLikeIPv6, splitList } from '../lib/validate';

  const records = resource(() => api.dns.records.list());
  const cnames = resource(() => api.dns.cnames.list());
  const forwarders = resource(() => api.dns.forwarders.list());

  // Records
  let rec = $state({ id: null as number | null, name: '', type: 'A' as 'A' | 'AAAA', address: '', comment: '' });
  let recError = $state<string | null>(null);

  function editRecord(r: LocalRecord) {
    rec = { id: r.id, name: r.name, type: r.type, address: r.address, comment: r.comment };
  }

  async function saveRecord(e: SubmitEvent) {
    e.preventDefault();
    const address = rec.address.trim();
    if (!isHostname(rec.name.trim())) recError = 'Enter a valid name, for example nas.lan.';
    else if (rec.type === 'A' && !isIPv4(address)) recError = 'An A record needs an IPv4 address.';
    else if (rec.type === 'AAAA' && !looksLikeIPv6(address)) recError = 'An AAAA record needs an IPv6 address.';
    else recError = null;
    if (recError) return;
    const body = { name: rec.name.trim(), type: rec.type, address, comment: rec.comment.trim() };
    const id = rec.id;
    const ok = await act(
      () => (id !== null ? api.dns.records.update(id, body) : api.dns.records.create({ ...body, enabled: true })),
      'Record saved.',
      records.reload,
    );
    if (ok) rec = { id: null, name: '', type: 'A', address: '', comment: '' };
  }

  // CNAMEs
  let cn = $state({ id: null as number | null, name: '', target: '', comment: '' });
  let cnError = $state<string | null>(null);

  function editCname(c: LocalCname) {
    cn = { id: c.id, name: c.name, target: c.target, comment: c.comment };
  }

  async function saveCname(e: SubmitEvent) {
    e.preventDefault();
    cnError = isHostname(cn.name.trim()) && isHostname(cn.target.trim()) ? null : 'Enter valid names.';
    if (cnError) return;
    const body = { name: cn.name.trim(), target: cn.target.trim(), comment: cn.comment.trim() };
    const id = cn.id;
    const ok = await act(
      () => (id !== null ? api.dns.cnames.update(id, body) : api.dns.cnames.create({ ...body, enabled: true })),
      'CNAME saved.',
      cnames.reload,
    );
    if (ok) cn = { id: null, name: '', target: '', comment: '' };
  }

  // Conditional forwarding
  let fw = $state({ id: null as number | null, domain: '', servers: '', comment: '' });
  let fwError = $state<string | null>(null);

  function editForwarder(f: Forwarder) {
    fw = { id: f.id, domain: f.domain, servers: f.servers.join(', '), comment: f.comment };
  }

  async function saveForwarder(e: SubmitEvent) {
    e.preventDefault();
    const servers = splitList(fw.servers);
    fwError = checkForwardDomain(fw.domain) ?? checkServers(servers, 4);
    if (fwError) return;
    const body = { domain: fw.domain.trim(), servers, comment: fw.comment.trim() };
    const id = fw.id;
    const ok = await act(
      () => (id !== null ? api.dns.forwarders.update(id, body) : api.dns.forwarders.create({ ...body, enabled: true })),
      'Forwarding saved.',
      forwarders.reload,
    );
    if (ok) fw = { id: null, domain: '', servers: '', comment: '' };
  }

  async function remove(kind: 'records' | 'cnames' | 'forwarders', id: number, label: string, after: () => void) {
    if (!confirm(`Delete ${label}?`)) return;
    await act(() => api.dns[kind].remove(id), 'Deleted.', after);
  }

  const toggleRecord = (r: LocalRecord) => act(() => api.dns.records.update(r.id, { enabled: !r.enabled }), null, records.reload);
  const toggleCname = (c: LocalCname) => act(() => api.dns.cnames.update(c.id, { enabled: !c.enabled }), null, cnames.reload);
  const toggleForwarder = (f: Forwarder) =>
    act(() => api.dns.forwarders.update(f.id, { enabled: !f.enabled }), null, forwarders.reload);
</script>

<div class="page-head"><h1>Local DNS</h1></div>

<div class="stack">
  <section class="card">
    <h2>Records (A and AAAA)</h2>
    <form class="form" onsubmit={saveRecord}>
      <label class="field">Name<input bind:value={rec.name} placeholder="nas.lan" required /></label>
      <label class="field">
        Type
        <select bind:value={rec.type}>
          <option value="A">A (IPv4)</option>
          <option value="AAAA">AAAA (IPv6)</option>
        </select>
      </label>
      <label class="field">Address<input class="mono" bind:value={rec.address} placeholder={rec.type === 'A' ? '192.0.2.20' : '2001:db8::20'} required /></label>
      <label class="field">Comment<input bind:value={rec.comment} /></label>
      <div class="row wide">
        <button type="submit" class="primary">{rec.id !== null ? 'Save' : 'Add record'}</button>
        {#if rec.id !== null}<button type="button" onclick={() => (rec = { id: null, name: '', type: 'A', address: '', comment: '' })}>Cancel</button>{/if}
        {#if recError}<span class="field-error">{recError}</span>{/if}
      </div>
    </form>
    {#if records.data}
      <div class="table-wrap list">
        <table>
          <thead><tr><th>On</th><th>Name</th><th>Type</th><th>Address</th><th>Comment</th><th></th></tr></thead>
          <tbody>
            {#each records.data.items as r (r.id)}
              <tr class:off={!r.enabled}>
                <td><input type="checkbox" checked={r.enabled} aria-label="Enabled" onchange={() => toggleRecord(r)} /></td>
                <td class="mono">{r.name}</td>
                <td><span class="badge">{r.type}</span></td>
                <td class="mono">{r.address}</td>
                <td>{r.comment}</td>
                <td class="actions">
                  <button type="button" class="small" onclick={() => editRecord(r)}>Edit</button>
                  <button type="button" class="small danger" onclick={() => remove('records', r.id, r.name, records.reload)}>Delete</button>
                </td>
              </tr>
            {:else}
              <tr><td colspan="6" class="empty">No records.</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <Status loading={records.loading} error={records.error} retry={records.reload} />
    {/if}
  </section>

  <section class="card">
    <h2>CNAMEs</h2>
    <form class="form" onsubmit={saveCname}>
      <label class="field">Name<input bind:value={cn.name} placeholder="files.lan" required /></label>
      <label class="field">Target<input bind:value={cn.target} placeholder="nas.lan" required /></label>
      <label class="field">Comment<input bind:value={cn.comment} /></label>
      <div class="row">
        <button type="submit" class="primary">{cn.id !== null ? 'Save' : 'Add CNAME'}</button>
        {#if cn.id !== null}<button type="button" onclick={() => (cn = { id: null, name: '', target: '', comment: '' })}>Cancel</button>{/if}
        {#if cnError}<span class="field-error">{cnError}</span>{/if}
      </div>
    </form>
    {#if cnames.data}
      <div class="table-wrap list">
        <table>
          <thead><tr><th>On</th><th>Name</th><th>Target</th><th>Comment</th><th></th></tr></thead>
          <tbody>
            {#each cnames.data.items as c (c.id)}
              <tr class:off={!c.enabled}>
                <td><input type="checkbox" checked={c.enabled} aria-label="Enabled" onchange={() => toggleCname(c)} /></td>
                <td class="mono">{c.name}</td>
                <td class="mono">{c.target}</td>
                <td>{c.comment}</td>
                <td class="actions">
                  <button type="button" class="small" onclick={() => editCname(c)}>Edit</button>
                  <button type="button" class="small danger" onclick={() => remove('cnames', c.id, c.name, cnames.reload)}>Delete</button>
                </td>
              </tr>
            {:else}
              <tr><td colspan="5" class="empty">No CNAMEs.</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <Status loading={cnames.loading} error={cnames.error} retry={cnames.reload} />
    {/if}
  </section>

  <section class="card">
    <h2>Conditional forwarding</h2>
    <p class="hint">
      Send queries for a local domain or a reverse zone to your router, for example <code>lan</code> or
      <code>2.0.192.in-addr.arpa</code>. Servers are IPv4 addresses. {IPV6_HINT.split('.')[0]}.
    </p>
    <form class="form" onsubmit={saveForwarder}>
      <label class="field">Domain<input bind:value={fw.domain} placeholder="lan" required /></label>
      <label class="field">Servers (IPv4, up to 4)<input class="mono" bind:value={fw.servers} placeholder="192.0.2.1" required /></label>
      <label class="field">Comment<input bind:value={fw.comment} /></label>
      <div class="row">
        <button type="submit" class="primary">{fw.id !== null ? 'Save' : 'Add forwarding'}</button>
        {#if fw.id !== null}<button type="button" onclick={() => (fw = { id: null, domain: '', servers: '', comment: '' })}>Cancel</button>{/if}
      </div>
      {#if fwError}<p class="field-error wide">{fwError}</p>{/if}
    </form>
    {#if forwarders.data}
      <div class="table-wrap list">
        <table>
          <thead><tr><th>On</th><th>Domain</th><th>Servers</th><th>Comment</th><th></th></tr></thead>
          <tbody>
            {#each forwarders.data.items as f (f.id)}
              <tr class:off={!f.enabled}>
                <td><input type="checkbox" checked={f.enabled} aria-label="Enabled" onchange={() => toggleForwarder(f)} /></td>
                <td class="mono">{f.domain}</td>
                <td class="mono">{f.servers.join(', ')}</td>
                <td>{f.comment}</td>
                <td class="actions">
                  <button type="button" class="small" onclick={() => editForwarder(f)}>Edit</button>
                  <button type="button" class="small danger" onclick={() => remove('forwarders', f.id, f.domain, forwarders.reload)}>Delete</button>
                </td>
              </tr>
            {:else}
              <tr><td colspan="5" class="empty">No conditional forwarding.</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <Status loading={forwarders.loading} error={forwarders.error} retry={forwarders.reload} />
    {/if}
  </section>
</div>

<style>
  .list {
    margin-top: 1rem;
  }
  p {
    margin: 0 0 0.75rem;
  }
</style>
