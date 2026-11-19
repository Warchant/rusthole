// Typed functions for each endpoint in docs/API.md.

import type { Client } from './client';
import type * as T from './types';

const enc = encodeURIComponent;

/** The browser offset for hour-of-day histograms (docs/API.md, section 1.4). */
export function browserUtcOffsetMinutes(date: Date = new Date()): number {
  return -date.getTimezoneOffset();
}

export interface PageQuery {
  limit?: number;
  cursor?: string | null;
}

function crud<Item, Input>(c: Client, base: string) {
  return {
    list: () => c.get<T.Page<Item>>(base),
    get: (id: number) => c.get<Item>(`${base}/${id}`),
    create: (input: Input) => c.post<Item>(base, input),
    update: (id: number, patch: Partial<Input>) => c.patch<Item>(`${base}/${id}`, patch),
    remove: (id: number) => c.del(`${base}/${id}`),
  };
}

export function makeApi(c: Client) {
  const tz = () => browserUtcOffsetMinutes();
  return {
    auth: {
      login: (req: T.LoginRequest) => c.post<T.SessionInfo>('/auth/login', req),
      logout: () => c.post<void>('/auth/logout'),
      session: () => c.get<T.SessionInfo>('/auth/session'),
      totp: () => c.get<T.TotpState>('/auth/totp'),
      totpSetup: (password: string) => c.post<T.TotpSetup>('/auth/totp/setup', { password }),
      totpConfirm: (code: string) => c.post<T.TotpState>('/auth/totp/confirm', { code }),
      totpDisable: (password: string, code: string) =>
        c.post<T.TotpState>('/auth/totp/disable', { password, code }),
    },
    blocking: {
      get: () => c.get<T.BlockingState>('/blocking'),
      set: (req: T.BlockingRequest) => c.put<T.BlockingState>('/blocking', req),
    },
    stats: {
      summary: (range: T.Range) => c.get<T.Summary>('/stats/summary', { range }),
      timeline: (range: T.Range, filter: { client?: string; domain?: string } = {}) =>
        c.get<T.Timeline>('/stats/timeline', { range, ...filter }),
      hours: (range: T.Range, filter: { client?: string; domain?: string; base?: string } = {}) =>
        c.get<T.Hours>('/stats/hours', { range, utc_offset_minutes: tz(), ...filter }),
      topDomains: (range: T.Range, limit = 10, client?: string) =>
        c.get<T.Page<T.TopDomain>>('/stats/top/domains', { range, limit, client }),
      topBlocked: (range: T.Range, limit = 10, client?: string) =>
        c.get<T.Page<T.TopDomain>>('/stats/top/blocked', { range, limit, client }),
      topClients: (range: T.Range, limit = 10) =>
        c.get<T.Page<T.TopClient>>('/stats/top/clients', { range, limit }),
      queryTypes: (range: T.Range) => c.get<T.Page<T.QueryTypeCount>>('/stats/query-types', { range }),
      upstreams: (range: T.Range) => c.get<T.Page<T.UpstreamShare>>('/stats/upstreams', { range }),
      clients: (range: T.Range, q: { q?: string; sort?: T.ClientSort } & PageQuery = {}) =>
        c.get<T.Page<T.StatsClient>>('/stats/clients', { range, ...q }),
      client: (key: string, range: T.Range) =>
        c.get<T.StatsClientDetail>(`/stats/clients/${enc(key)}`, { range, utc_offset_minutes: tz() }),
      clientDomains: (
        key: string,
        range: T.Range,
        q: { q?: string; sort?: T.ClientSort; names_limit?: number; blocked_only?: boolean } & PageQuery = {},
      ) => c.get<T.Page<T.DomainGroup>>(`/stats/clients/${enc(key)}/domains`, { range, ...q }),
      domains: (range: T.Range, q: string, page: PageQuery & { blocked_only?: boolean } = {}) =>
        c.get<T.Page<T.DomainSearchItem>>('/stats/domains', { range, q, ...page }),
      domain: (name: string, range: T.Range) =>
        c.get<T.DomainDetail>(`/stats/domains/${enc(name)}`, { range, utc_offset_minutes: tz() }),
    },
    queries: {
      recent: (q: { limit?: number; client?: string; status?: T.QueryStatus; q?: string } = {}) =>
        c.get<T.Page<T.RecentQuery>>('/queries/recent', q),
    },
    lists: {
      list: () => c.get<T.ListsResponse>('/lists'),
      create: (input: Partial<T.AdlistInput> & { url: string }) => c.post<T.Adlist>('/lists', input),
      update: (id: number, patch: Partial<T.AdlistInput>) => c.patch<T.Adlist>(`/lists/${id}`, patch),
      remove: (id: number) => c.del(`/lists/${id}`),
      refresh: (id: number) => c.post<{ started: boolean }>(`/lists/${id}/update`),
      refreshAll: () => c.post<{ started: boolean }>('/lists/update'),
    },
    search: {
      domain: (name: string) => c.get<T.DomainVerdicts>('/search/domain', { name }),
    },
    report: {
      domain: (name: string, section: T.ReportSection, refresh = false) =>
        c.get<T.ReportResult>(`/report/domain/${enc(name)}/${section}`, refresh ? { refresh: 'true' } : {}),
    },
    rules: {
      ...crud<T.Rule, T.RuleInput>(c, '/rules'),
      test: (kind: T.RuleKind, pattern: string, domain: string) =>
        c.post<T.RuleTestResult>('/rules/test', { kind, pattern, domain }),
    },
    groups: crud<T.Group, T.GroupInput>(c, '/groups'),
    clients: {
      ...crud<T.Client, T.ClientInput>(c, '/clients'),
      seen: (page: PageQuery = {}) => c.get<T.Page<T.SeenClient>>('/clients/seen', { ...page }),
    },
    dns: {
      records: crud<T.LocalRecord, T.LocalRecordInput>(c, '/dns/records'),
      cnames: crud<T.LocalCname, T.LocalCnameInput>(c, '/dns/cnames'),
      forwarders: crud<T.Forwarder, T.ForwarderInput>(c, '/dns/forwarders'),
    },
    tokens: {
      list: () => c.get<T.Page<T.ApiToken>>('/tokens'),
      create: (name: string, password: string) => c.post<T.CreatedToken>('/tokens', { name, password }),
      revoke: (id: number) => c.del(`/tokens/${id}`),
    },
    settings: {
      get: () => c.get<T.Settings>('/settings'),
      update: (patch: T.SettingsPatch) => c.patch<T.Settings>('/settings', patch),
    },
    audit: {
      list: (q: PageQuery & { action?: string } = {}) => c.get<T.Page<T.AuditEntry>>('/audit', { ...q }),
    },
    system: {
      get: () => c.get<T.SystemInfo>('/system'),
    },
  };
}

export type Api = ReturnType<typeof makeApi>;
