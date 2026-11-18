// @vitest-environment happy-dom
// m26: "Load more" merges pages by key. A client can come again on the next page
// when its count changed between two requests.
import { afterEach, describe, expect, it } from 'vitest';
import type { StatsClient } from '../lib/api/types';
import { button, cleanup, json, render, settle, startMockApi, text, until } from '../test/harness';
import Clients from './Clients.svelte';
import ClientsConfigured from './ClientsConfigured.svelte';

afterEach(() => cleanup());

function client(n: number, queries: number): StatsClient {
  return {
    key: `02:00:00:00:00:0${n}`,
    name: `host${n}.lan`,
    ip: `192.0.2.${10 + n}`,
    mac: `02:00:00:00:00:0${n}`,
    client_id: null,
    queries,
    blocked: 0,
    blocked_percent: 0,
    unique_domains: 1,
    first_seen_at: null,
    last_seen_at: null,
  };
}

describe('Clients page', () => {
  it('merges a client that comes again on the next page (m26)', async () => {
    await startMockApi((url) => {
      if (!url.includes('/stats/clients?')) return null;
      if (!url.includes('cursor=')) return json(200, { items: [client(1, 300), client(2, 200)], next_cursor: 'p2' });
      // Client 2 got more queries and comes again, with the new count.
      return json(200, { items: [client(2, 210), client(3, 100)], next_cursor: null });
    });
    const root = render(Clients);
    await until(() => root.querySelectorAll('tbody tr').length === 2, 'the first page');
    button(root, 'Load more').click();
    await until(() => root.querySelectorAll('tbody tr').length === 3, 'the second page');
    await settle();
    const rows = [...root.querySelectorAll('tbody tr')].map((r) => text(r.querySelector('td')));
    expect(rows).toEqual(['host1.lan default', 'host2.lan default', 'host3.lan default']);
    expect(text(root.querySelectorAll('tbody tr')[1]?.querySelectorAll('td')[3])).toBe('210');
  });

  it('labels the seen-client count with the period of the API: 30 days (m27)', async () => {
    await startMockApi();
    const root = render(ClientsConfigured);
    await until(() => [...root.querySelectorAll('h2')].some((h) => text(h) === 'Seen clients'), 'the seen clients');
    const seen = [...root.querySelectorAll('section')].find((x) => text(x.querySelector('h2')) === 'Seen clients')!;
    await until(() => seen.querySelector('th') !== null, 'the table');
    const headers = [...seen.querySelectorAll('th')].map(text);
    expect(headers).toContain('Queries (30 days)');
    expect(headers.join(' ')).not.toContain('24 h');
  });
});
