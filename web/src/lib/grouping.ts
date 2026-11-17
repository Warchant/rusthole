// Pure data helpers for statistics views.

import type { DomainGroup, HourArrays } from './api/types';

/** Percent of `part` in `total`. 0 when `total` is 0. */
export function shareOf(part: number, total: number): number {
  return total > 0 ? (part / total) * 100 : 0;
}

/** Allowed = queries - blocked, per bucket. Never below 0. */
export function allowedSeries(queries: number[], blocked: number[]): number[] {
  return queries.map((q, i) => Math.max(0, q - (blocked[i] ?? 0)));
}

/**
 * Adds the next page of groups to the loaded groups. The server never splits a
 * group between pages; if a base comes again, the new copy replaces the old one.
 */
export function mergeGroupPages(loaded: DomainGroup[], next: DomainGroup[]): DomainGroup[] {
  const index = new Map(loaded.map((g, i) => [g.base, i]));
  const out = loaded.slice();
  for (const g of next) {
    const at = index.get(g.base);
    if (at === undefined) {
      index.set(g.base, out.length);
      out.push(g);
    } else {
      out[at] = g;
    }
  }
  return out;
}

export interface BaseGroup<T> {
  base: string;
  queries: number;
  blocked: number;
  items: T[];
}

/**
 * Groups flat rows by their registrable domain (`base`, from the server).
 * Groups are sorted by queries, high to low; rows in a group keep that order too.
 */
export function groupByBase<T extends { base: string; queries: number; blocked: number }>(
  rows: T[],
): BaseGroup<T>[] {
  const map = new Map<string, BaseGroup<T>>();
  for (const row of rows) {
    let g = map.get(row.base);
    if (!g) {
      g = { base: row.base, queries: 0, blocked: 0, items: [] };
      map.set(row.base, g);
    }
    g.queries += row.queries;
    g.blocked += row.blocked;
    g.items.push(row);
  }
  const groups = [...map.values()];
  for (const g of groups) g.items.sort((a, b) => b.queries - a.queries);
  groups.sort((a, b) => b.queries - a.queries || a.base.localeCompare(b.base));
  return groups;
}

/** Keeps the first `max` items and adds the rest as one "Other" item. */
export function withOther<T extends { count: number }>(
  items: T[],
  max: number,
  makeOther: (count: number) => T,
): T[] {
  if (items.length <= max) return items;
  const sorted = items.slice().sort((a, b) => b.count - a.count);
  const head = sorted.slice(0, max - 1);
  const rest = sorted.slice(max - 1).reduce((sum, it) => sum + it.count, 0);
  return [...head, makeOther(rest)];
}

/** The hour with the most queries, or null when all hours are 0. */
export function peakHour(hours: HourArrays): number | null {
  let best: number | null = null;
  let bestValue = 0;
  hours.queries.forEach((v, h) => {
    if (v > bestValue) {
      bestValue = v;
      best = h;
    }
  });
  return best;
}

/** Text for a list of group ids, with names from a lookup. */
export function groupNames(ids: number[], names: Map<number, string>): string {
  if (ids.length === 0) return 'none';
  return ids.map((id) => names.get(id) ?? `#${id}`).join(', ');
}
