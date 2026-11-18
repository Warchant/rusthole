// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import { changeMock } from '../lib/mock/server';
import { toasts } from '../lib/state.svelte';
import { button, cleanup, render, startMockApi, text, until } from '../test/harness';
import { packagedUpstreams } from '../test/packaged';
import Settings from './Settings.svelte';

afterEach(() => {
  cleanup();
  toasts.length = 0;
});

function upstreamForm(root: HTMLElement): HTMLFormElement {
  const h = [...root.querySelectorAll('h2')].find((x) => text(x) === 'Upstream DNS servers');
  const form = h?.parentElement?.querySelector('form');
  if (!form) throw new Error('No upstream form.');
  return form;
}

function setValue(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
}

describe('Settings page', () => {
  it('shows each listener of GET /system, also two of the same kind (M4)', async () => {
    await startMockApi();
    const root = render(Settings);
    await until(() => root.querySelectorAll('.listener').length > 0, 'the listener rows');
    expect([...root.querySelectorAll('.listener')].map(text)).toEqual([
      'dns 127.0.0.1:53',
      'dns 192.0.2.2:53',
      'doh 192.0.2.2:443',
      'admin 127.0.0.1:8443',
      'admin 192.0.2.2:8443',
    ]);
  });

  it('saves the packaged upstreams after a change of the timeout only (M5)', async () => {
    const packaged = packagedUpstreams();
    expect(packaged).toEqual(['udp://9.9.9.9:53', 'udp://1.1.1.1:53']);
    const t = await startMockApi();
    changeMock((s) => {
      s.settings.upstreams = { servers: packaged, timeout_ms: 2000 };
    });
    const root = render(Settings);
    await until(() => root.querySelector('textarea') !== null, 'the settings form');
    const form = upstreamForm(root);
    expect(form.querySelector('textarea')?.value).toBe(packaged.join('\n'));
    setValue(form.querySelector<HTMLInputElement>('input[type=number]')!, '3000');
    button(form, 'Save').click();
    await until(() => t.calls.includes('PATCH /settings'), 'the PATCH request');
    await until(() => toasts.some((x) => x.text.startsWith('Upstreams saved')), 'the toast');
    expect(form.querySelector('.field-error')).toBeNull();
  });

  it.each([
    'tcp://192.0.2.53:53',
    'tls://192.0.2.53:853',
    'https://192.0.2.53/dns-query',
    'tls://dns.example:853',
    '192.0.2.53',
    '192.0.2.53:5353',
  ])('sends the upstream form %s to the server (M5)', async (server) => {
    const t = await startMockApi();
    const root = render(Settings);
    await until(() => root.querySelector('textarea') !== null, 'the settings form');
    const form = upstreamForm(root);
    setValue(form.querySelector('textarea')!, server);
    button(form, 'Save').click();
    await until(() => t.calls.includes('PATCH /settings'), 'the PATCH request');
  });

  it('shows the 422 of the server for a bad upstream (M5)', async () => {
    const t = await startMockApi();
    const root = render(Settings);
    await until(() => root.querySelector('textarea') !== null, 'the settings form');
    const form = upstreamForm(root);
    setValue(form.querySelector('textarea')!, 'udp://dns.example');
    button(form, 'Save').click();
    await until(() => form.querySelector('.field-error') !== null, 'the field error');
    expect(t.calls).toContain('PATCH /settings');
    expect(text(form.querySelector('.field-error'))).toContain('must be an IP address');
  });

  it('shows a restart notice while restart_required is true (M6)', async () => {
    await startMockApi();
    const root = render(Settings);
    await until(() => root.querySelector('textarea') !== null, 'the settings form');
    expect(root.querySelector('.restart-notice')).toBeNull();
    const form = upstreamForm(root);
    setValue(form.querySelector<HTMLInputElement>('input[type=number]')!, '3000');
    button(form, 'Save').click();
    await until(() => root.querySelector('.restart-notice') !== null, 'the restart notice');
    expect(text(root.querySelector('.restart-notice'))).toMatch(/restart/i);

    // A later save of a live section does not remove the notice.
    const cacheForm = [...root.querySelectorAll('h2')].find((x) => text(x) === 'Cache')!.parentElement!.querySelector('form')!;
    button(cacheForm, 'Save').click();
    await until(() => toasts.some((x) => x.text.startsWith('Cache saved')), 'the cache toast');
    expect(root.querySelector('.restart-notice')).not.toBeNull();

    // A new visit of the page shows the notice from GET /settings.
    cleanup();
    const again = render(Settings);
    await until(() => again.querySelector('textarea') !== null, 'the settings form');
    expect(again.querySelector('.restart-notice')).not.toBeNull();
  });
});
