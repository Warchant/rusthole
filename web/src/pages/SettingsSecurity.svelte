<script lang="ts">
  // API tokens and TOTP (docs/API.md 11). A new token and the otpauth URI are
  // shown one time only. They stay in component memory and go when you leave.
  import Status from '../components/Status.svelte';
  import { api, errorText } from '../lib/api';
  import type { ApiToken, CreatedToken, TotpSetup } from '../lib/api/types';
  import { formatDateTime, formatRelative } from '../lib/format';
  import { act, resource, session, toast } from '../lib/state.svelte';

  const tokens = resource(() => api.tokens.list());
  const totp = resource(() => api.auth.totp());

  // Tokens
  let tokenName = $state('');
  let tokenPassword = $state('');
  let created = $state<CreatedToken | null>(null);
  let tokenError = $state<string | null>(null);

  async function createToken(e: SubmitEvent) {
    e.preventDefault();
    tokenError = null;
    try {
      created = await api.tokens.create(tokenName.trim(), tokenPassword);
      tokenName = '';
      tokenPassword = '';
      tokens.reload();
    } catch (err) {
      tokenError = errorText(err);
      tokenPassword = '';
    }
  }

  async function revoke(t: ApiToken) {
    if (!confirm(`Revoke the token "${t.name}"? Scripts that use it stop working.`)) return;
    await act(() => api.tokens.revoke(t.id), 'Token revoked.', tokens.reload);
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast('ok', 'Copied.', 2000);
    } catch {
      toast('error', 'Cannot copy. Select the text and copy it.');
    }
  }

  // TOTP
  let totpPassword = $state('');
  let totpCode = $state('');
  let setup = $state<TotpSetup | null>(null);
  let totpError = $state<string | null>(null);
  let totpBusy = $state(false);

  const secretFromUri = $derived(setup ? (new URL(setup.otpauth_uri).searchParams.get('secret') ?? '') : '');

  async function totpStep(work: () => Promise<void>) {
    totpBusy = true;
    totpError = null;
    try {
      await work();
    } catch (err) {
      totpError = errorText(err);
    } finally {
      totpPassword = '';
      totpCode = '';
      totpBusy = false;
    }
  }

  const startSetup = (e: SubmitEvent) => {
    e.preventDefault();
    return totpStep(async () => {
      setup = await api.auth.totpSetup(totpPassword);
      totp.reload();
    });
  };

  const confirmSetup = (e: SubmitEvent) => {
    e.preventDefault();
    return totpStep(async () => {
      await api.auth.totpConfirm(totpCode.trim());
      setup = null;
      session.totpEnabled = true;
      toast('ok', 'TOTP is on. The next login asks for a code.');
      totp.reload();
    });
  };

  const disable = (e: SubmitEvent) => {
    e.preventDefault();
    return totpStep(async () => {
      await api.auth.totpDisable(totpPassword, totpCode.trim());
      session.totpEnabled = false;
      toast('ok', 'TOTP is off.');
      totp.reload();
    });
  };
</script>

<div class="grid-2">
  <section class="card">
    <h2>API tokens</h2>
    <p class="hint">Scripts send a token in the header <code>Authorization: Bearer …</code>.</p>
    {#if created}
      <div class="notice ok new-token">
        <p>Token "{created.token.name}" is ready. Copy it now. You cannot see it again.</p>
        <div class="secret-box">{created.secret}</div>
        <div class="row">
          <button type="button" class="small" onclick={() => copy(created?.secret ?? '')}>Copy</button>
          <button type="button" class="small" onclick={() => (created = null)}>I copied it</button>
        </div>
      </div>
    {/if}
    <form class="form" onsubmit={createToken}>
      <label class="field">Name<input bind:value={tokenName} required placeholder="backup script" /></label>
      <label class="field">
        Your password
        <input type="password" autocomplete="current-password" bind:value={tokenPassword} required />
      </label>
      <div class="wide">
        {#if tokenError}<p class="field-error">{tokenError}</p>{/if}
        <button type="submit" class="primary">Create token</button>
      </div>
    </form>
    {#if tokens.data}
      <div class="table-wrap list">
        <table>
          <thead><tr><th>Name</th><th>Prefix</th><th>Created</th><th>Last used</th><th></th></tr></thead>
          <tbody>
            {#each tokens.data.items as t (t.id)}
              <tr>
                <td>{t.name}</td>
                <td class="mono">{t.prefix}…</td>
                <td class="nowrap">{formatDateTime(t.created_at)}</td>
                <td class="nowrap">
                  {formatRelative(t.last_used_at, Date.now())}
                  {#if t.last_used_ip}<div class="muted small mono">{t.last_used_ip}</div>{/if}
                </td>
                <td class="actions"><button type="button" class="small danger" onclick={() => revoke(t)}>Revoke</button></td>
              </tr>
            {:else}
              <tr><td colspan="5" class="empty">No tokens.</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <Status loading={tokens.loading} error={tokens.error} retry={tokens.reload} />
    {/if}
  </section>

  <section class="card">
    <h2>Two-factor login (TOTP)</h2>
    {#if totp.data}
      {#if totp.data.enabled}
        <p><span class="badge ok">on</span> The login asks for a code from your authenticator app.</p>
        <form class="form" onsubmit={disable}>
          <label class="field">Your password<input type="password" autocomplete="current-password" bind:value={totpPassword} required /></label>
          <label class="field">Current code<input inputmode="numeric" maxlength="6" bind:value={totpCode} required /></label>
          <div class="wide"><button type="submit" class="danger" disabled={totpBusy}>Turn off TOTP</button></div>
        </form>
      {:else if setup}
        <p>Add this account to your authenticator app. Then enter the code that the app shows.</p>
        <p class="hint">Account URI (the app can read it as a link or text):</p>
        <div class="secret-box">{setup.otpauth_uri}</div>
        <p class="hint">Key for manual entry: <code>{secretFromUri}</code>. The setup ends at {formatDateTime(setup.expires_at)}.</p>
        <form class="form" onsubmit={confirmSetup}>
          <label class="field">Code<input inputmode="numeric" maxlength="6" bind:value={totpCode} required /></label>
          <div class="row">
            <button type="submit" class="primary" disabled={totpBusy}>Turn on</button>
            <button type="button" onclick={() => (setup = null)}>Cancel</button>
          </div>
        </form>
      {:else}
        <p><span class="badge">off</span> The login asks only for the password.</p>
        <form class="form" onsubmit={startSetup}>
          <label class="field">Your password<input type="password" autocomplete="current-password" bind:value={totpPassword} required /></label>
          <div class="wide"><button type="submit" class="primary" disabled={totpBusy}>Set up TOTP</button></div>
        </form>
      {/if}
      {#if totpError}<p class="field-error">{totpError}</p>{/if}
    {:else}
      <Status loading={totp.loading} error={totp.error} retry={totp.reload} />
    {/if}
  </section>
</div>

<style>
  p {
    margin: 0 0 0.6rem;
  }
  .new-token {
    margin-bottom: 1rem;
    display: grid;
    gap: 0.5rem;
  }
  .new-token p {
    margin: 0;
  }
  .secret-box {
    margin-bottom: 0.6rem;
    color: var(--text);
  }
  .list {
    margin-top: 1rem;
  }
</style>
