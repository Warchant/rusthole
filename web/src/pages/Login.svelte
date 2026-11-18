<script lang="ts">
  import { api, ApiError, errorText } from '../lib/api';
  import { formatCountdown } from '../lib/format';
  import { remainingSeconds } from '../lib/countdown';
  import { go, setSession } from '../lib/state.svelte';

  let password = $state('');
  let totp = $state('');
  let needTotp = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let ban = $state<{ seconds: number; start: number } | null>(null);
  let now = $state(performance.now());

  const banLeft = $derived(ban ? remainingSeconds(ban.seconds, ban.start, now) : 0);

  $effect(() => {
    if (!ban) return;
    const t = setInterval(() => {
      now = performance.now();
      if (banLeft <= 0) ban = null;
    }, 500);
    return () => clearInterval(t);
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (busy || banLeft > 0) return;
    busy = true;
    error = null;
    try {
      const s = await api.auth.login(needTotp ? { password, totp: totp.trim() } : { password });
      password = '';
      totp = '';
      setSession(s.csrf_token, s.totp_enabled);
      go('#/');
    } catch (err) {
      if (err instanceof ApiError && err.code === 'totp_required') {
        needTotp = true;
        error = null;
      } else if (err instanceof ApiError && err.status === 429) {
        ban = { seconds: err.retryAfterSeconds ?? 60, start: performance.now() };
        now = performance.now();
        error = null;
      } else {
        error = errorText(err);
        totp = '';
      }
    } finally {
      busy = false;
    }
  }
</script>

<main class="login">
  <form class="card" onsubmit={submit}>
    <div class="brand">
      <svg viewBox="0 0 32 32" width="28" height="28" aria-hidden="true"
        ><circle cx="16" cy="16" r="14" class="ring" /><circle cx="16" cy="16" r="6" class="hole" /></svg
      >
      <h1>rusthole</h1>
    </div>
    <label class="field">
      Password
      <!-- svelte-ignore a11y_autofocus -->
      <input type="password" autocomplete="current-password" required autofocus bind:value={password} />
    </label>
    {#if needTotp}
      <label class="field">
        Code from your authenticator app
        <!-- svelte-ignore a11y_autofocus -->
        <input
          inputmode="numeric"
          autocomplete="one-time-code"
          pattern={'[0-9]{6}'}
          maxlength="6"
          required
          autofocus
          bind:value={totp}
        />
      </label>
    {/if}
    {#if banLeft > 0}
      <p class="notice error" role="alert">Too many failed logins. Try again in {formatCountdown(banLeft)}.</p>
    {:else if error}
      <p class="notice error" role="alert">{error}</p>
    {/if}
    <button type="submit" class="primary" disabled={busy || banLeft > 0}>{busy ? 'Logging in…' : 'Log in'}</button>
    {#if import.meta.env.VITE_MOCK === '1'}
      <p class="hint">Mock mode: the password is <code>rusthole</code>. Any 6-digit code is a valid TOTP code.</p>
    {/if}
  </form>
</main>

<style>
  .login {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 1rem;
  }
  form {
    width: min(100%, 22rem);
    display: grid;
    gap: 0.9rem;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .ring {
    fill: var(--accent);
  }
  .hole {
    fill: var(--surface);
  }
  button {
    justify-content: center;
  }
  p {
    margin: 0;
  }
</style>
