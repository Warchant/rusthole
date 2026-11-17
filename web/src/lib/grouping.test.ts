import { describe, expect, it } from 'vitest';
import type { DomainGroup } from './api/types';
import { areaPath, bucketAt, niceStep, niceTicks } from './chart';
import { allowedSeries, groupByBase, groupNames, mergeGroupPages, peakHour, shareOf, withOther } from './grouping';
import { href, parseHash } from './routes';

function group(base: string, queries: number): DomainGroup {
  return {
    base,
    queries,
    blocked: 0,
    first_seen_at: null,
    last_seen_at: null,
    names_total: 1,
    names: [{ name: `www.${base}`, queries, blocked: 0, first_seen_at: null, last_seen_at: null }],
  };
}

describe('groupByBase', () => {
  it('groups rows by base, adds counts and sorts', () => {
    const rows = [
      { name: 'cdn.example.com', base: 'example.com', queries: 10, blocked: 0 },
      { name: 'ads.example.net', base: 'example.net', queries: 50, blocked: 50 },
      { name: 'www.example.com', base: 'example.com', queries: 30, blocked: 0 },
      { name: 'telemetry.example.com', base: 'example.com', queries: 20, blocked: 20 },
    ];
    const groups = groupByBase(rows);
    expect(groups.map((g) => g.base)).toEqual(['example.com', 'example.net']);
    expect(groups[0]).toMatchObject({ queries: 60, blocked: 20 });
    expect(groups[0]?.items.map((r) => r.name)).toEqual([
      'www.example.com',
      'telemetry.example.com',
      'cdn.example.com',
    ]);
  });

  it('sorts ties by name and handles no rows', () => {
    const groups = groupByBase([
      { base: 'b.example', queries: 1, blocked: 0 },
      { base: 'a.example', queries: 1, blocked: 0 },
    ]);
    expect(groups.map((g) => g.base)).toEqual(['a.example', 'b.example']);
    expect(groupByBase([])).toEqual([]);
  });
});

describe('mergeGroupPages', () => {
  it('appends new groups and keeps the order', () => {
    const merged = mergeGroupPages([group('a.example', 9)], [group('b.example', 5), group('c.example', 1)]);
    expect(merged.map((g) => g.base)).toEqual(['a.example', 'b.example', 'c.example']);
  });
  it('replaces a group that comes again and does not change the input', () => {
    const loaded = [group('a.example', 9), group('b.example', 5)];
    const merged = mergeGroupPages(loaded, [group('a.example', 12)]);
    expect(merged.map((g) => [g.base, g.queries])).toEqual([
      ['a.example', 12],
      ['b.example', 5],
    ]);
    expect(loaded[0]?.queries).toBe(9);
  });
});

describe('series helpers', () => {
  it('shareOf is 0 for a total of 0', () => {
    expect(shareOf(5, 0)).toBe(0);
    expect(shareOf(1, 4)).toBe(25);
  });
  it('allowedSeries subtracts and clamps', () => {
    expect(allowedSeries([10, 5, 3], [2, 6])).toEqual([8, 0, 3]);
  });
  it('withOther keeps the top items and adds the rest', () => {
    const items = [
      { name: 'A', count: 5 },
      { name: 'B', count: 50 },
      { name: 'C', count: 20 },
      { name: 'D', count: 1 },
    ];
    const out = withOther(items, 3, (count) => ({ name: 'Other', count }));
    expect(out).toEqual([
      { name: 'B', count: 50 },
      { name: 'C', count: 20 },
      { name: 'Other', count: 6 },
    ]);
    expect(withOther(items, 4, (count) => ({ name: 'Other', count }))).toBe(items);
  });
  it('peakHour finds the busiest hour', () => {
    const queries = Array.from({ length: 24 }, (_, h) => (h === 19 ? 100 : h));
    expect(peakHour({ queries, blocked: [] })).toBe(19);
    expect(peakHour({ queries: new Array<number>(24).fill(0), blocked: [] })).toBeNull();
  });
  it('groupNames uses names and shows unknown ids', () => {
    const names = new Map([[0, 'Default']]);
    expect(groupNames([0, 7], names)).toBe('Default, #7');
    expect(groupNames([], names)).toBe('none');
  });
});

describe('chart helpers', () => {
  it('niceStep gives 1, 2 or 5 times a power of 10', () => {
    expect(niceStep(100, 4)).toBe(50);
    expect(niceStep(950, 4)).toBe(500);
    expect(niceStep(3, 4)).toBe(1);
    expect(niceStep(0, 4)).toBe(1);
  });
  it('niceTicks covers the maximum', () => {
    expect(niceTicks(310, 4)).toEqual([0, 100, 200, 300, 400]);
    expect(niceTicks(0, 4)).toEqual([0, 1]);
  });
  it('areaPath closes the shape on the baseline', () => {
    expect(areaPath([0, 10], [5, 2], 20)).toBe('M0,20L0,5L10,2L10,20Z');
    expect(areaPath([], [], 20)).toBe('');
  });
  it('bucketAt maps pixels to buckets', () => {
    expect(bucketAt(0, 240, 24)).toBe(0);
    expect(bucketAt(239, 240, 24)).toBe(23);
    expect(bucketAt(500, 240, 24)).toBe(23);
    expect(bucketAt(-5, 240, 24)).toBe(0);
    expect(bucketAt(5, 240, 0)).toBe(-1);
  });
});

describe('routes', () => {
  it('parses the static routes', () => {
    expect(parseHash('').name).toBe('dashboard');
    expect(parseHash('#/').name).toBe('dashboard');
    expect(parseHash('#/lists').name).toBe('lists');
    expect(parseHash('#/lists/').name).toBe('lists');
    expect(parseHash('#/nope').name).toBe('not_found');
  });
  it('decodes a client key with colons', () => {
    const link = href('/clients', '02:00:00:00:00:01');
    expect(link).toBe('#/clients/02%3A00%3A00%3A00%3A00%3A01');
    const r = parseHash(link);
    expect(r.name).toBe('client');
    expect(r.params.key).toBe('02:00:00:00:00:01');
  });
  it('reads the query part', () => {
    const r = parseHash('#/domains?name=ads.example.net');
    expect(r.name).toBe('domains');
    expect(r.query.get('name')).toBe('ads.example.net');
  });
  it('keeps a bad escape as it is', () => {
    expect(parseHash('#/clients/%E0%A4%A').params.key).toBe('%E0%A4%A');
  });
});
