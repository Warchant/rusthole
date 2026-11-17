// Hash routes ("#/clients/abc"). A hash router needs no server fallback, so
// the embedded static files work as they are.

export type RouteName =
  | 'dashboard'
  | 'clients'
  | 'client'
  | 'domains'
  | 'lists'
  | 'rules'
  | 'groups'
  | 'dns'
  | 'settings'
  | 'audit'
  | 'queries'
  | 'login'
  | 'not_found';

export interface Route {
  name: RouteName;
  params: Record<string, string>;
  query: URLSearchParams;
}

const TABLE: [RegExp, RouteName, string[]][] = [
  [/^\/$/, 'dashboard', []],
  [/^\/clients$/, 'clients', []],
  [/^\/clients\/([^/]+)$/, 'client', ['key']],
  [/^\/domains$/, 'domains', []],
  [/^\/lists$/, 'lists', []],
  [/^\/rules$/, 'rules', []],
  [/^\/groups$/, 'groups', []],
  [/^\/dns$/, 'dns', []],
  [/^\/settings$/, 'settings', []],
  [/^\/audit$/, 'audit', []],
  [/^\/queries$/, 'queries', []],
  [/^\/login$/, 'login', []],
];

/** Parses a location hash ("#/clients/x?tab=a") into a route. */
export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#/, '') || '/';
  const [pathPart = '/', queryPart = ''] = raw.split('?', 2);
  const path = pathPart.length > 1 ? pathPart.replace(/\/+$/, '') : pathPart;
  const query = new URLSearchParams(queryPart);
  for (const [re, name, keys] of TABLE) {
    const m = re.exec(path);
    if (!m) continue;
    const params: Record<string, string> = {};
    keys.forEach((k, i) => {
      try {
        params[k] = decodeURIComponent(m[i + 1] ?? '');
      } catch {
        params[k] = m[i + 1] ?? '';
      }
    });
    return { name, params, query };
  }
  return { name: 'not_found', params: {}, query };
}

/** Builds a hash link: href('/clients', key) -> "#/clients/<encoded key>". */
export function href(path: string, ...segments: string[]): string {
  return `#${path}${segments.map((s) => `/${encodeURIComponent(s)}`).join('')}`;
}
