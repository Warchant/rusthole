// @vitest-environment happy-dom
// The "Name" form of the client page: it changes the comment of the configured
// client, or adds a configured client for the device with its current groups.
import { afterEach, describe, expect, it } from 'vitest';
import { parseHash } from '../lib/routes';
import { nav } from '../lib/state.svelte';
import { button, cleanup, render, startMockApi, text, until } from '../test/harness';
import ClientDetail from './ClientDetail.svelte';

afterEach(() => cleanup());

function open(key: string): HTMLElement {
  nav.route = parseHash(`#/clients/${encodeURIComponent(key)}`);
  return render(ClientDetail);
}

function nameCard(root: HTMLElement): HTMLElement {
  const card = [...root.querySelectorAll('section')].find((s) => text(s.querySelector('h2')) === 'Name');
  if (!card) throw new Error('No "Name" card.');
  return card as HTMLElement;
}

function setInput(el: HTMLInputElement | HTMLSelectElement, value: string): void {
  el.value = value;
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
}

describe('Client name', () => {
  it('changes the comment of a configured MAC client', async () => {
    const h = await startMockApi();
    const root = open('02:00:00:00:00:01');
    await until(() => root.querySelector('input[aria-label="Client name"]') !== null && text(root.querySelector('h1')) === 'laptop', 'the form');
    const card = nameCard(root);
    await until(() => text(card).includes('Configured client: 02:00:00:00:00:01 (MAC)'), 'the configured client');
    const input = card.querySelector<HTMLInputElement>('input[aria-label="Client name"]')!;
    expect(input.value).toBe('laptop');
    setInput(input, 'work laptop');
    button(card, 'Save name').click();
    await until(() => text(root.querySelector('h1')) === 'work laptop', 'the new name');
    expect(h.calls).toContain('PATCH /clients/1');
    expect(h.calls.some((c) => c.startsWith('POST /clients'))).toBe(false);
  });

  it('adds a MAC client in the default group for a device with no configured client', async () => {
    const h = await startMockApi();
    const root = open('02:00:00:00:00:05');
    await until(() => root.querySelector('select[aria-label="Match by"]') !== null, 'the form');
    const card = nameCard(root);
    const select = card.querySelector<HTMLSelectElement>('select')!;
    expect(select.value).toBe('02:00:00:00:00:05');
    expect([...select.options].map((o) => o.value)).toEqual(['02:00:00:00:00:05', '192.0.2.14', '192.0.2.114']);
    setInput(card.querySelector<HTMLInputElement>('input')!, 'printer');
    button(card, 'Save name').click();
    await until(() => text(root.querySelector('h1')) === 'printer', 'the new name');
    expect(h.calls).toContain('POST /clients');
    const list = await (await h.mockFetch('/api/v1/clients', { method: 'GET' })).json();
    const added = list.items.find((c: { match: string }) => c.match === '02:00:00:00:00:05');
    expect(added).toMatchObject({ kind: 'mac', groups: [0], comment: 'printer' });
  });

  it('adds an IP client with the groups of the CIDR network, and keeps the network comment', async () => {
    const h = await startMockApi();
    const root = open('192.0.2.150');
    await until(() => root.querySelector('select[aria-label="Match by"]') !== null, 'the form');
    const card = nameCard(root);
    await until(() => text(card).includes('from the network 192.0.2.128/25'), 'the network hint');
    expect(card.querySelector<HTMLSelectElement>('select')!.value).toBe('192.0.2.150');
    setInput(card.querySelector<HTMLInputElement>('input')!, 'guest phone');
    button(card, 'Save name').click();
    await until(() => text(root.querySelector('h1')) === 'guest phone', 'the new name');
    expect(h.calls.some((c) => c.startsWith('PATCH'))).toBe(false);
    const list = await (await h.mockFetch('/api/v1/clients', { method: 'GET' })).json();
    expect(list.items.find((c: { match: string }) => c.match === '192.0.2.150')).toMatchObject({ kind: 'ip', groups: [2] });
    expect(list.items.find((c: { match: string }) => c.match === '192.0.2.128/25').comment).toBe('guest network');
  });
});
