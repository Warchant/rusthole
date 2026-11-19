// @vitest-environment happy-dom
// The "Block" and "Report" buttons of the Domains page (docs/PLAN.md section 9).
import { afterEach, describe, expect, it } from 'vitest';
import { changeMock } from '../lib/mock/server';
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

describe('Report button', () => {
  function section(root: HTMLElement, id: string): HTMLElement {
    return root.querySelector<HTMLElement>(`[data-section="${id}"]`)!;
  }

  it('shows the DNS section, and Refresh skips the cache', async () => {
    const h = await startMockApi();
    const root = open(NAME);
    await until(() => [...root.querySelectorAll('button')].some((b) => text(b) === 'Report'), 'the Report button');
    expect(root.querySelector('[aria-label="Domain report"]')).toBeNull();
    button(root, 'Report').click();
    await until(() => text(section(root, 'dns')).includes('192.0.2.80'), 'the DNS records');
    const dns = section(root, 'dns');
    expect(text(dns)).toContain(`CNAME chain: ${NAME} → shop.example.cdn.example`);
    expect(text(dns)).toContain('no answer in 4500 ms');
    expect(h.calls).toContain(`GET /report/domain/${NAME}/dns`);
    button(root, 'Refresh').click();
    await until(() => h.calls.includes(`GET /report/domain/${NAME}/dns?refresh=true`), 'the refresh request');
    // A second click closes the report.
    button(root, 'Report').click();
    await until(() => root.querySelector('[aria-label="Domain report"]') === null, 'the closed report');
  });

  it('shows the RDAP section next to DNS, and "off" when the setting is off', async () => {
    const h = await startMockApi();
    const root = open(NAME);
    await until(() => [...root.querySelectorAll('button')].some((b) => text(b) === 'Report'), 'the Report button');
    button(root, 'Report').click();
    await until(() => text(section(root, 'rdap')).includes('Example Registrar Inc.'), 'the RDAP data');
    const rdap = text(section(root, 'rdap'));
    expect(rdap).toContain('not public');
    expect(rdap).toContain('ns1.shop.example, ns2.shop.example');
    expect(h.calls).toContain(`GET /report/domain/${NAME}/rdap`);
    await until(() => text(section(root, 'tls')).includes('60 days left'), 'the TLS data');
    expect(text(section(root, 'tls'))).toContain('trusted');
    expect(text(section(root, 'tls'))).toContain('Chain: www.shop.example → Example CA R1');
    changeMock((s) => {
      s.settings.report.external = false;
    });
    button(root, 'Refresh').click();
    await until(() => text(section(root, 'rdap')).includes('turned off in the settings'), 'the off state');
    expect(text(section(root, 'tls'))).toContain('turned off in the settings');
    // DNS still works.
    expect(text(section(root, 'dns'))).toContain('192.0.2.80');
  });

  it('a failed section shows its error and a retry, and the page stays usable', async () => {
    let fail = true;
    await startMockApi((url) =>
      url.includes('/report/domain/') && fail ? json(429, { code: 'busy', message: 'Too many reports run now.' }) : null,
    );
    const root = open(NAME);
    await until(() => [...root.querySelectorAll('button')].some((b) => text(b) === 'Report'), 'the Report button');
    button(root, 'Report').click();
    await until(() => text(section(root, 'dns')).includes('Too many reports'), 'the busy text');
    fail = false;
    button(section(root, 'dns'), 'Try again').click();
    await until(() => text(section(root, 'dns')).includes('192.0.2.80'), 'the records after the retry');
    // The Block button still works.
    expect(button(root, 'Block').disabled).toBe(false);
  });

  it('a section with status "off" shows its reason, not a failure', async () => {
    await startMockApi((url) =>
      url.includes('/report/domain/')
        ? json(200, { section: 'dns', name: NAME, status: 'off', cached: false, fetched_at: '2026-11-18T10:00:00Z', data: null, error: 'turned off in the settings (report.external)' })
        : null,
    );
    const root = open(NAME);
    await until(() => [...root.querySelectorAll('button')].some((b) => text(b) === 'Report'), 'the Report button');
    button(root, 'Report').click();
    await until(() => text(section(root, 'dns')).includes('turned off in the settings'), 'the off text');
    expect(text(section(root, 'dns'))).toContain('turned off');
    expect(section(root, 'dns').querySelector('.field-error')).toBeNull();
  });
});
