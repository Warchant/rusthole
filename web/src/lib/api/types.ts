// Types for the admin REST API. They follow docs/API.md. Keep the two in step.

export type Range = '24h' | '7d' | '30d';
export const RANGES: readonly Range[] = ['24h', '7d', '30d'];

/** RFC 3339 time stamp in UTC. */
export type Timestamp = string;

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  details?: { field: string; message: string }[];
  retry_after_seconds?: number | null;
}

// Section 3: authentication

export interface SessionInfo {
  csrf_token: string;
  expires_at: Timestamp;
  totp_enabled: boolean;
}

export interface LoginRequest {
  password: string;
  totp?: string;
}

// Section 4: blocking

export interface BlockingState {
  enabled: boolean;
  remaining_seconds: number | null;
  until_at: Timestamp | null;
}

export type BlockingRequest =
  | { enabled: true }
  | { enabled: false; duration_seconds?: number };

// Section 5: statistics

export type QueryStatus = 'forwarded' | 'cached' | 'blocked' | 'local' | 'refused' | 'error';
export const QUERY_STATUSES: readonly QueryStatus[] = [
  'forwarded',
  'cached',
  'blocked',
  'local',
  'refused',
  'error',
];

export interface Summary {
  range: Range;
  from: Timestamp;
  to: Timestamp;
  queries: number;
  blocked: number;
  blocked_percent: number;
  cached: number;
  forwarded: number;
  local: number;
  unique_domains: number;
  unique_clients: number;
}

export interface Timeline {
  range: Range;
  from: Timestamp;
  to: Timestamp;
  bucket_seconds: number;
  queries: number[];
  blocked: number[];
  cached: number[];
  forwarded: number[];
}

export interface HourArrays {
  queries: number[];
  blocked: number[];
}

export interface Hours extends HourArrays {
  range: Range;
  utc_offset_minutes: number;
}

export interface TopDomain {
  name: string;
  base: string;
  count: number;
}

export interface TopClient {
  key: string;
  name: string | null;
  ip: string;
  count: number;
  blocked: number;
}

export interface QueryTypeCount {
  type: string;
  count: number;
}

export interface UpstreamShare {
  name: string;
  kind: 'upstream' | 'cache' | 'blocked' | 'local';
  count: number;
  avg_ms: number | null;
}

export interface StatsClient {
  key: string;
  name: string | null;
  ip: string;
  mac: string | null;
  client_id: number | null;
  queries: number;
  blocked: number;
  blocked_percent: number;
  unique_domains: number;
  first_seen_at: Timestamp | null;
  last_seen_at: Timestamp | null;
}

export interface StatsClientDetail extends StatsClient {
  ips: string[];
  groups: number[];
  range: Range;
  unique_bases: number;
  utc_offset_minutes: number;
  hours: HourArrays;
}

export interface DomainName {
  name: string;
  queries: number;
  blocked: number;
  first_seen_at: Timestamp | null;
  last_seen_at: Timestamp | null;
}

export interface DomainGroup {
  base: string;
  queries: number;
  blocked: number;
  first_seen_at: Timestamp | null;
  last_seen_at: Timestamp | null;
  names_total: number;
  names: DomainName[];
}

export type ClientSort = 'queries' | 'blocked' | 'last_seen' | 'name';

export interface DomainSearchItem {
  name: string;
  base: string;
  queries: number;
  blocked: number;
  clients: number;
  last_seen_at: Timestamp | null;
}

export interface DomainClient {
  key: string;
  name: string | null;
  ip: string;
  queries: number;
  blocked: number;
  last_seen_at: Timestamp | null;
}

export interface DomainDetail {
  name: string;
  base: string;
  range: Range;
  queries: number;
  blocked: number;
  first_seen_at: Timestamp | null;
  last_seen_at: Timestamp | null;
  clients: DomainClient[];
  utc_offset_minutes: number;
  hours: HourArrays;
}

// Section 6: recent queries

export interface RecentQuery {
  at: Timestamp;
  client_key: string;
  client_ip: string;
  client_name: string | null;
  name: string;
  type: string;
  status: QueryStatus;
  reason: string | null;
  upstream: string | null;
  duration_ms: number;
}

// Section 7: lists

export type ListKind = 'block' | 'allow';
export type ListState = 'never' | 'updating' | 'ok' | 'error';

export interface ListStatus {
  state: ListState;
  last_update_at: Timestamp | null;
  last_success_at: Timestamp | null;
  entries: number;
  invalid_lines: number;
  size_bytes: number;
  last_error: string | null;
}

export interface Adlist {
  id: number;
  url: string;
  comment: string;
  kind: ListKind;
  enabled: boolean;
  groups: number[];
  status: ListStatus;
}

export type AdlistInput = Pick<Adlist, 'url' | 'comment' | 'kind' | 'enabled' | 'groups'>;

export interface ListSchedule {
  interval_hours: number;
  next_run_at: Timestamp | null;
  running: boolean;
}

export interface ListsResponse extends Page<Adlist> {
  schedule: ListSchedule;
}

export type Verdict = 'blocked' | 'allowed' | 'none';

export interface DomainMatch {
  source: 'list' | 'rule' | 'special';
  id: number | null;
  label: string;
  kind: ListKind;
  match: 'exact' | 'parent' | 'regex';
  pattern: string;
  enabled: boolean;
  groups: number[];
}

export interface DomainVerdicts {
  name: string;
  verdicts: { group_id: number; group_name: string; verdict: Verdict; by: string | null }[];
  matches: DomainMatch[];
  truncated: boolean;
}

// Section 8: rules

export type RuleKind = 'exact' | 'regex';
export type RuleAction = 'allow' | 'deny';

export interface Rule {
  id: number;
  kind: RuleKind;
  action: RuleAction;
  pattern: string;
  enabled: boolean;
  groups: number[];
  comment: string;
  /** null for a rule that the API did not make (for example from an import). */
  created_at: Timestamp | null;
  updated_at: Timestamp | null;
}

export type RuleInput = Pick<Rule, 'kind' | 'action' | 'pattern' | 'enabled' | 'groups' | 'comment'>;

export interface RuleTestResult {
  valid: boolean;
  matches: boolean;
  error: string | null;
}

// Section 9: groups and clients

export interface Group {
  id: number;
  name: string;
  enabled: boolean;
  comment: string;
  lists: number;
  rules: number;
  clients: number;
}

export type GroupInput = Pick<Group, 'name' | 'enabled' | 'comment'>;

export type ClientKind = 'ip' | 'cidr' | 'mac' | 'host';

export interface Client {
  id: number;
  match: string;
  kind: ClientKind;
  groups: number[];
  comment: string;
}

export type ClientInput = Pick<Client, 'match' | 'groups' | 'comment'>;

export interface SeenClient {
  ip: string;
  mac: string | null;
  name: string | null;
  first_seen_at: Timestamp | null;
  last_seen_at: Timestamp | null;
  queries: number;
  client_id: number | null;
}

// Section 10: local DNS

export interface LocalRecord {
  id: number;
  name: string;
  type: 'A' | 'AAAA';
  address: string;
  comment: string;
  enabled: boolean;
}
export type LocalRecordInput = Omit<LocalRecord, 'id'>;

export interface LocalCname {
  id: number;
  name: string;
  target: string;
  comment: string;
  enabled: boolean;
}
export type LocalCnameInput = Omit<LocalCname, 'id'>;

export interface Forwarder {
  id: number;
  domain: string;
  servers: string[];
  comment: string;
  enabled: boolean;
}
export type ForwarderInput = Omit<Forwarder, 'id'>;

// Section 11: tokens and TOTP

export interface ApiToken {
  id: number;
  name: string;
  prefix: string;
  created_at: Timestamp | null;
  last_used_at: Timestamp | null;
  last_used_ip: string | null;
}

export interface CreatedToken {
  token: ApiToken;
  secret: string;
}

export interface TotpState {
  enabled: boolean;
  pending: boolean;
}

export interface TotpSetup {
  otpauth_uri: string;
  expires_at: Timestamp;
}

// Section 12: settings

export type BlockingMode = 'null' | 'nxdomain' | 'nodata' | 'custom_ip';

export interface Settings {
  upstreams: { servers: string[]; timeout_ms: number };
  blocking: {
    mode: BlockingMode;
    custom_ipv4: string | null;
    custom_ipv6: string | null;
    blocked_ttl: number;
    special_domains: boolean;
    cname_check: boolean;
  };
  cache: {
    enabled: boolean;
    max_entries: number;
    min_ttl: number;
    max_ttl: number;
    negative_ttl: number;
  };
  rate_limit: { queries_per_second: number; burst: number };
  acl: { extra_cidrs: string[]; local_subnets: string[] };
  stats: { flush_interval_seconds: number; retention_days: number; recent_queries_size: number };
  lists: { refresh_interval_hours: number };
  /**
   * True when a change since the start needs a restart (upstreams, statistics,
   * listeners, TLS). It stays true until the restart. Read-only.
   */
  restart_required: boolean;
}

/** The body of PATCH /settings. `acl.local_subnets` and `restart_required` are read-only. */
export type SettingsPatch = Partial<Omit<Settings, 'acl' | 'restart_required'>> & {
  acl?: { extra_cidrs: string[] };
};

// Section 13: audit log

export interface AuditEntry {
  id: number;
  at: Timestamp;
  action: string;
  target: string | null;
  actor: string;
  client_ip: string;
  result: 'ok' | 'error';
  detail: string | null;
}

// Section 14: system

export interface SystemInfo {
  version: string;
  commit: string | null;
  started_at: Timestamp;
  uptime_seconds: number;
  memory_rss_bytes: number | null;
  list_entries: number;
  config_path: string;
  data_dir: string;
  os: string;
  arch: string;
  listeners: { kind: 'dns' | 'doh' | 'admin'; address: string }[];
}
