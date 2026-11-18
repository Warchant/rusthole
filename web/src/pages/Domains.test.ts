// @vitest-environment happy-dom
// The "Block" button of the Domains page: a confirmation with groups, then an
// exact deny rule (docs/PLAN.md R-D13).
import { afterEach, describe, expect, it } from 'vitest';
import { parseHash } from '../lib/routes';
import { nav } from '../lib/state.svelte';
import { button, cleanup, json, render, startMockApi, text, until } from '../test/harness';
import Domains from './Domains.svelte';

afterEach(() => cleanup());

const NAME = 'www.shop.example';

function open(name: string): HTMLElement {
  nav.route = parseHash(`#/domains?name=${encodeURIComponent(name)}`);
  return render(Domains);
}

function boxes(root: HTMLElement): Map<string, HTMLInputElement> {
  const group = root.querySelector('[aria-label="Confirm block"]')!;
  return new Map([...group.querySelectorAll('label')].map((l) => [text(l), l.querySelector('input')!]));
}

async function confirmOpen(root: HTMLElement): Promise<void> {
  await until(() => [...root.querySelectorAll('button')].some((b) => text(b) === 'Block'), 'the Block button');
  button(root, 'Block').click();
  await until(() => boxes(root).size === 3, 'the groups');
}

describe('Block button', () => {
  it('adds an exact deny rule in the selected groups and shows it in the matches', async () => {
    const h = await startMockApi();
    const root = open(NAME);
    await confirmOpen(root);
    expect(h.calls.some((c) => c.startsWith('POST'))).toBe(false);
    const b = boxes(root);
    expect(b.get('default')!.checked).toBe(true);
    b.get('kids')!.click();
    button(root, `Block ${NAME}`).click();
    await until(() => text(root.querySelector('[role="status"]')).startsWith('Blocked: exact deny rule'), 'the result');
    expect(h.calls).toContain('POST /rules');
    const rules = await (await h.mockFetch('/api/v1/rules', { method: 'GET' })).json();
    const rule = rules.items.find((r: { pattern: string }) => r.pattern === NAME);
    expect(rule).toMatchObject({ kind: 'exact', action: 'deny', groups: [0, 1], enabled: true, comment: 'Blocked from the Domains page' });
    await until(() => [...root.querySelectorAll('td.mono')].some((td) => text(td) === NAME), 'the new match');
    expect(root.querySelector('[aria-label="Confirm block"]')).toBeNull();
  });

  it('sends nothing on Cancel', async () => {
    const h = await startMockApi();
    const root = open(NAME);
    await confirmOpen(root);
    button(root, 'Cancel').click();
    await until(() => root.querySelector('[aria-label="Confirm block"]') === null, 'the closed confirmation');
    expect(h.calls.some((c) => c.startsWith('POST'))).toBe(false);
  });

  it('cannot block with no group', async () => {
    await startMockApi();
    const root = open(NAME);
    await confirmOpen(root);
    boxes(root).get('default')!.click();
    await until(() => button(root, `Block ${NAME}`).disabled, 'the disabled button');
    expect(text(root.querySelector('[aria-label="Confirm block"] .field-error'))).toBe('Select one group or more.');
  });

  it('shows a clear message when the rule exists (409)', async () => {
    await startMockApi((url, init) =>
      init.method === 'POST' && url.endsWith('/rules') ? json(409, { code: 'conflict', message: 'This rule already exists.' }) : null,
    );
    const root = open(NAME);
    await confirmOpen(root);
    button(root, `Block ${NAME}`).click();
    await until(() => text(root.querySelector('[role="status"]')).includes('exists'), 'the result');
    expect(text(root.querySelector('[role="status"]'))).toBe('An exact deny rule for this name exists. Change it on the Rules page.');
  });
});
