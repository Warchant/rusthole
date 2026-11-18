// @vitest-environment happy-dom
// m24: when the server refuses a toggle, the checkbox goes back to the server state.
import type { Component } from 'svelte';
import { afterEach, describe, expect, it } from 'vitest';
import { toasts } from '../lib/state.svelte';
import { cleanup, json, render, settle, startMockApi, until } from '../test/harness';
import Groups from './Groups.svelte';
import Lists from './Lists.svelte';
import LocalDns from './LocalDns.svelte';
import Rules from './Rules.svelte';

afterEach(() => {
  cleanup();
  toasts.length = 0;
});

const PAGES: [string, Component][] = [
  ['Lists', Lists],
  ['Rules', Rules],
  ['Groups', Groups],
  ['LocalDns', LocalDns],
];

const boxes = (root: HTMLElement) => [...root.querySelectorAll<HTMLInputElement>('input[type=checkbox][aria-label=Enabled]')];

describe.each(PAGES)('%s page toggles', (_name, page) => {
  it('puts the checkbox back when the server refuses the change', async () => {
    let refused = 0;
    await startMockApi((_url, init) => {
      if (init.method !== 'PATCH') return null;
      refused += 1;
      return json(409, { code: 'conflict', message: 'The change is refused.' });
    });
    const root = render(page);
    await until(() => boxes(root).length > 0, 'the checkboxes');
    // LocalDns has three tables. Try the first box of each table.
    const tables = [...root.querySelectorAll('table')];
    const firsts = tables.map((t) => t.querySelector<HTMLInputElement>('input[type=checkbox][aria-label=Enabled]')).filter((b) => b !== null);
    expect(firsts.length).toBeGreaterThan(0);
    for (const [i, box] of firsts.entries()) {
      const before = box.checked;
      box.click();
      expect(box.checked).toBe(!before);
      await until(() => refused === i + 1, 'the refused PATCH');
      await until(() => toasts.length === i + 1, 'the error toast');
      await settle();
      expect(box.checked).toBe(before);
    }
  });

  it('keeps the new state when the server accepts the change', async () => {
    await startMockApi();
    const root = render(page);
    await until(() => boxes(root).length > 0, 'the checkboxes');
    const index = 0;
    const before = boxes(root)[index]!.checked;
    boxes(root)[index]!.click();
    await until(() => boxes(root)[index]?.checked === !before, 'the new state');
    await settle();
    expect(boxes(root)[index]?.checked).toBe(!before);
  });
});
