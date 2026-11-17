# rusthole admin REST API (v1)

This document is the contract between the admin API (part P5, Rust) and the web UI
(part P6, `web/`). The UI is built on this contract. P5 implements it.
[PLAN.md](PLAN.md) has the decisions (D9, D10, A7, A9). Where this document and PLAN.md
differ, PLAN.md wins, and this document must be updated.

## 1. General rules

| Item | Rule |
|---|---|
| Base path | `/api/v1`. All paths below are relative to it. |
| Transport | HTTPS on the admin listener. The UI and the API have the same origin. |
| Body | JSON (`Content-Type: application/json; charset=utf-8`), UTF-8. Maximum request body: 64 KiB. |
| Field names | `snake_case`. |
| Time stamps | RFC 3339 strings in UTC, for example `"2026-11-17T08:30:00Z"`. Field names end in `_at`. A time that is not known is `null`. |
| Durations | Integer seconds. Field names end in `_seconds`, or `_ms` for milliseconds. |
| Ids | CRUD resources have an integer `id`. The server makes the id. The id does not change and is not used again. |
| Unknown fields | The server rejects a request body with an unknown field (422). The server can add new fields to a response. The UI ignores fields that it does not know. |
| Read-only fields | A field that is marked "read-only" is in responses only. The server rejects it in a request body (422). |
| Versioning | A change that breaks a client goes to `/api/v2`. Additive changes stay in v1. |

### 1.1 Methods

| Method | Use | Success status |
|---|---|---|
| `GET` | Read. Has no side effects. | 200 |
| `POST` on a collection | Create. The response body is the new resource. | 201 |
| `POST` on an action path (for example `/lists/3/update`) | Start an action. | 200 or 202 |
| `PATCH` | Partial update. The body holds a subset of the writable top-level fields. Each field in the body replaces its old value. A nested object or an array is replaced as a whole. The response body is the full resource. | 200 |
| `PUT` | Replace a singleton (for example `/blocking`). | 200 |
| `DELETE` | Delete. No body. | 204 |

### 1.2 Collections and pagination

A collection response has this shape:

```json
{ "items": [ ... ], "next_cursor": null }
```

- Short collections (lists, rules, groups, clients, local DNS, tokens) return all items.
  `next_cursor` is always `null` for them.
- Long collections (audit log, per-client domains, domain search, clients in statistics)
  accept `limit` and `cursor`.
  - `limit`: integer, 1 to 500. The default is 50.
  - `cursor`: an opaque string. Copy it from `next_cursor` of the previous page. Do not
    parse it.
  - `next_cursor` is `null` on the last page.
- A bad `limit` or a bad `cursor` gives 400 `bad_request`.

### 1.3 Time range for statistics

Statistics endpoints accept `range`:

| `range` | Period | `bucket_seconds` in timelines | Buckets |
|---|---|---|---|
| `24h` (default) | Last 24 hours | 600 (10 min) | 144 |
| `7d` | Last 7 days | 3600 (1 h) | 168 |
| `30d` | Last 30 days | 14400 (4 h) | 180 |

The server aligns the range to bucket boundaries. `from` is the start of the first
bucket. `to` is the end of the last bucket (the current, partial bucket). The retention
setting (`stats.retention_days`) can make the real data shorter than the range. Then the
older buckets are zero.

### 1.4 Hour-of-day histograms and time zone

An hour-of-day histogram has 24 buckets. Bucket 0 is 00:00–00:59, bucket 23 is
23:00–23:59. The server adds them up over the whole `range`.

- The client sends `utc_offset_minutes` (integer, -840 to 840, default 0). The UI sends
  the browser offset (`-new Date().getTimezoneOffset()`).
- The server keeps hourly aggregates in UTC. It moves each aggregate by the offset before
  it takes the hour. If the offset is not a whole number of hours, the server rounds it
  down to a whole hour.
- The response gives `utc_offset_minutes`: the offset that the server really used.
- The server uses one fixed offset for the whole range. A daylight-saving change inside
  the range moves some hours by one bucket. This error is accepted.

### 1.5 Registrable domain

`base` is the registrable domain of a name (one label below the public suffix), for
example `cdn.example.co.uk` → `example.co.uk`. The server calculates it with the Public
Suffix List. The UI does not calculate it. A name that has no registrable domain (for
example a single label or a reverse zone) is its own `base`.

## 2. Errors

Every error response has a JSON body with this shape:

```json
{
  "code": "validation_failed",
  "message": "The request has invalid fields.",
  "details": [ { "field": "url", "message": "Use an http or https URL." } ],
  "retry_after_seconds": null
}
```

- `code`: a stable, machine-readable string (table below).
- `message`: an English sentence for people. The UI can show it.
- `details`: optional. A list of field errors for 422.
- `retry_after_seconds`: optional. Set for 429.

| Status | `code` | When |
|---|---|---|
| 400 | `bad_request` | The JSON is bad, or a query parameter is bad. |
| 401 | `unauthorized` | No valid session and no valid token. |
| 401 | `invalid_credentials` | Login: the password or the TOTP code is wrong. |
| 401 | `totp_required` | Login: TOTP is on and the body has no `totp` code. |
| 403 | `csrf_failed` | A write with a session cookie has no valid `X-CSRF-Token`. |
| 403 | `forbidden` | The `Host` header is not allowed, or the client address is not in the ACL. |
| 404 | `not_found` | The path or the resource does not exist. |
| 405 | `method_not_allowed` | The path exists, but not with this method. |
| 409 | `config_conflict` | The config file changed on disk after rusthole read it (A7). The server does not write. The UI must reload the data and try again. |
| 409 | `conflict` | The write breaks a rule, for example a duplicate name, or delete of the default group. |
| 413 | `payload_too_large` | The body is larger than 64 KiB. |
| 422 | `validation_failed` | A field is not valid. `details` tells which. |
| 429 | `rate_limited` | Login ban (D10) or too many requests. The `Retry-After` header and `retry_after_seconds` give the wait time in seconds. |
| 500 | `internal` | Server fault. The message does not show internal data. |
| 503 | `unavailable` | The server cannot do this now, for example a list update already runs. |

## 3. Authentication

Only these paths work without authentication (D9):

- `POST /auth/login`
- static assets of the UI (paths outside `/api/`)

All other paths return 401 `unauthorized` without a valid session or token.

### 3.1 Session (browser)

```mermaid
sequenceDiagram
    participant UI
    participant API
    UI->>API: GET /auth/session
    API-->>UI: 401 unauthorized
    UI->>API: POST /auth/login {password}
    API-->>UI: 401 totp_required (TOTP is on)
    UI->>API: POST /auth/login {password, totp}
    API-->>UI: 200 {csrf_token} + Set-Cookie
    UI->>API: PATCH /lists/3 + X-CSRF-Token
    API-->>UI: 200
    Note over UI: Page reload: the token is lost
    UI->>API: GET /auth/session (cookie)
    API-->>UI: 200 {csrf_token}
```

#### `POST /auth/login`

Request:

```json
{ "password": "…", "totp": "123456" }
```

- `totp` is optional. Send it when TOTP is on.
- If TOTP is on and the body has no `totp`, the server returns 401 `totp_required`. It
  does not check the password in this case, so this response does not tell if the
  password is correct.
- A wrong password or a wrong TOTP code gives 401 `invalid_credentials`. The response does
  not tell which one is wrong.
- A TOTP code cannot be used two times (A7).
- With no password set in the config, every login fails (A7). You set the password with
  `rusthole passwd`. The API has no endpoint to set or change the password.
- Each failure counts in the ban state machine (per IPv4 address, per IPv6 /64). During a
  ban the server returns 429 `rate_limited` with `Retry-After`, and it does not check the
  password.

Response 200:

```json
{
  "csrf_token": "b64url-random-32-bytes",
  "expires_at": "2026-11-18T08:30:00Z",
  "totp_enabled": true
}
```

The response sets the session cookie:

```
Set-Cookie: rusthole_session=<random>; Path=/; Secure; HttpOnly; SameSite=Strict
```

The cookie has no `Max-Age`. The server keeps the session expiry. The session expires 24 h
after the last request (idle) and 7 days after login (absolute). Assumption: these values
can change in P5.

#### `POST /auth/logout`

Needs the session and `X-CSRF-Token`. The server deletes the session and clears the
cookie. Response: 204.

#### `GET /auth/session`

Response 200 with a valid session (same shape as login):

```json
{
  "csrf_token": "b64url-random-32-bytes",
  "expires_at": "2026-11-18T08:30:00Z",
  "totp_enabled": true
}
```

Response 401 `unauthorized` without a valid session.

The UI keeps the CSRF token in memory only. After a page reload, the UI calls this
endpoint to get the token again.

### 3.2 CSRF

- Every request that is not `GET` and uses the session cookie must have the header
  `X-CSRF-Token: <csrf_token>`. The value must be equal to the token of the session.
  Else the server returns 403 `csrf_failed`.
- The token is fixed for the life of the session.
- `POST /auth/login` does not need the header.

### 3.3 API tokens (scripts)

- A script sends `Authorization: Bearer <token>`. The token format is `rh_` followed by
  43 base64url characters.
- A request with a bearer token does not use a cookie. CSRF does not apply to it.
- The server keeps only a hash of the token. It shows the token one time, in the
  response of `POST /tokens`.
- A failed token check counts in the ban state machine (A7).
- A token has the same rights as the admin session, with one exception: a token cannot
  create tokens and cannot change TOTP.

### 3.4 Other security rules (P5)

These rules are not visible in the JSON, but the UI depends on them:

- `Host` check against the configured names and addresses (DNS rebinding). Else 403.
- Security headers on every response:
  `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Strict-Transport-Security: max-age=31536000`.
- API responses have `Cache-Control: no-store`.
- The UI uses no inline scripts, no inline styles, no `eval` and no external resources.

## 4. Blocking

### `GET /blocking`

```json
{
  "enabled": false,
  "remaining_seconds": 287,
  "until_at": "2026-11-17T08:35:00Z"
}
```

- `enabled`: `true` if blocking is on.
- `remaining_seconds`: when blocking is off with a timer, the seconds until blocking goes
  on again. Else `null`.
- `until_at`: the same time as a time stamp, for people. The UI counts down from
  `remaining_seconds` with a monotonic clock. It does not compare `until_at` with the
  browser clock.

### `PUT /blocking`

Request, one of:

```json
{ "enabled": true }
{ "enabled": false }
{ "enabled": false, "duration_seconds": 300 }
```

- `duration_seconds`: 1 to 86400. Blocking goes on again after this time. Without it,
  blocking stays off until the next `PUT`.
- `duration_seconds` with `"enabled": true` gives 422.

Response 200: the new state (same shape as `GET`).

## 5. Statistics

All statistics endpoints accept `range` (section 1.3). Endpoints with an hour-of-day
histogram also accept `utc_offset_minutes` (section 1.4).

Each query has one status:

| Status | Meaning |
|---|---|
| `forwarded` | Sent to an upstream server. |
| `cached` | Answered from the cache. |
| `blocked` | Blocked by a list, a rule, a special domain or a CNAME check. |
| `local` | Answered from a local record. |
| `refused` | Refused (rate limit). Off-net clients are not counted. |
| `error` | No answer from upstreams (SERVFAIL). |

### 5.1 `GET /stats/summary`

```json
{
  "range": "24h",
  "from": "2026-11-16T08:40:00Z",
  "to": "2026-11-17T08:40:00Z",
  "queries": 48210,
  "blocked": 6120,
  "blocked_percent": 12.69,
  "cached": 20114,
  "forwarded": 21430,
  "local": 512,
  "unique_domains": 1830,
  "unique_clients": 9
}
```

`blocked_percent` is `0` when `queries` is `0`. The server rounds it to 2 decimals.

### 5.2 `GET /stats/timeline`

Queries over time. Optional filters: `client` (a client key, section 5.6) and `domain`
(an exact name).

```json
{
  "range": "24h",
  "from": "2026-11-16T08:40:00Z",
  "to": "2026-11-17T08:40:00Z",
  "bucket_seconds": 600,
  "queries":   [310, 295, 288],
  "blocked":   [41, 39, 30],
  "cached":    [120, 110, 100],
  "forwarded": [149, 146, 158]
}
```

- The arrays have the same length. Bucket `i` starts at `from + i * bucket_seconds`.
- Every bucket is present. A bucket without queries has `0`.

### 5.3 `GET /stats/hours`

Hour-of-day histogram. Optional filters (they can be used together):

- `client`: a client key (section 5.6).
- `domain`: an exact name, for example `cdn.example.com`.
- `base`: a registrable domain, for example `example.com` (all names below it).

`domain` and `base` together give 400.

```json
{
  "range": "7d",
  "utc_offset_minutes": 120,
  "queries": [12, 8, 5, 3, 2, 2, 9, 40, 88, 95, 90, 87, 92, 85, 80, 84, 90, 110, 140, 150, 130, 100, 60, 30],
  "blocked": [1, 1, 0, 0, 0, 0, 1, 5, 11, 12, 10, 9, 12, 10, 9, 10, 11, 15, 20, 22, 18, 12, 7, 3]
}
```

Both arrays have exactly 24 items.

### 5.4 Top lists

| Path | Item |
|---|---|
| `GET /stats/top/domains` | Most queried names that were not blocked. |
| `GET /stats/top/blocked` | Most blocked names. |
| `GET /stats/top/clients` | Clients with the most queries. |

Parameters: `range`, `limit` (1 to 100, default 10). `top/domains` and `top/blocked`
also accept `client`.

Domain item:

```json
{ "items": [ { "name": "cdn.example.com", "base": "example.com", "count": 4210 } ], "next_cursor": null }
```

Client item:

```json
{ "items": [ { "key": "02:00:00:00:00:01", "name": "laptop", "ip": "192.0.2.10", "count": 9120, "blocked": 1180 } ], "next_cursor": null }
```

### 5.5 Query types and upstream share

#### `GET /stats/query-types`

```json
{ "items": [ { "type": "A", "count": 30110 }, { "type": "AAAA", "count": 12002 }, { "type": "HTTPS", "count": 4100 } ], "next_cursor": null }
```

`type` is the record type name. An unknown type has the form `TYPE65280`.

#### `GET /stats/upstreams`

Where the answers came from.

```json
{
  "items": [
    { "name": "192.0.2.53:53", "kind": "upstream", "count": 12100, "avg_ms": 18.4 },
    { "name": "cache", "kind": "cache", "count": 20114, "avg_ms": null },
    { "name": "blocked", "kind": "blocked", "count": 6120, "avg_ms": null },
    { "name": "local", "kind": "local", "count": 512, "avg_ms": null }
  ],
  "next_cursor": null
}
```

`kind` is one of `upstream`, `cache`, `blocked`, `local`. `avg_ms` is the mean answer time
of an upstream, or `null`.

### 5.6 Clients in statistics

A seen client has a `key`. The key is the MAC address (lower case, colon form) when the
server knows it, else the IP address. The key can have `:` and `/` characters. The UI
encodes it with `encodeURIComponent` in a path.

#### `GET /stats/clients`

Parameters: `range`, `limit`, `cursor`, `q` (filter: a part of the name, IP or MAC),
`sort` (`queries` (default), `blocked`, `last_seen`, `name`).

```json
{
  "items": [
    {
      "key": "02:00:00:00:00:01",
      "name": "laptop",
      "ip": "192.0.2.10",
      "mac": "02:00:00:00:00:01",
      "client_id": 4,
      "queries": 9120,
      "blocked": 1180,
      "blocked_percent": 12.94,
      "unique_domains": 412,
      "first_seen_at": "2026-11-10T07:00:00Z",
      "last_seen_at": "2026-11-17T08:39:00Z"
    }
  ],
  "next_cursor": "opaque"
}
```

- `name`: the configured client comment, else the name from conditional forwarding or
  local records, else `null`.
- `client_id`: the id of the configured client (section 9) that matches, or `null`.

#### `GET /stats/clients/{key}`

```json
{
  "key": "02:00:00:00:00:01",
  "name": "laptop",
  "ip": "192.0.2.10",
  "ips": ["192.0.2.10", "2001:db8::10"],
  "mac": "02:00:00:00:00:01",
  "client_id": 4,
  "groups": [0],
  "range": "24h",
  "queries": 9120,
  "blocked": 1180,
  "blocked_percent": 12.94,
  "unique_domains": 412,
  "unique_bases": 96,
  "first_seen_at": "2026-11-10T07:00:00Z",
  "last_seen_at": "2026-11-17T08:39:00Z",
  "utc_offset_minutes": 120,
  "hours": {
    "queries": [ "24 integers" ],
    "blocked": [ "24 integers" ]
  }
}
```

- `ips`: all addresses that the client used in the range.
- `groups`: the groups that apply to the client now.
- `first_seen_at` is the first query in the stored data, not only in the range.
- `hours` has the same arrays as `GET /stats/hours?client={key}`.

#### `GET /stats/clients/{key}/domains`

The names that the client resolved, grouped by registrable domain (section 1.5).

Parameters: `range`, `limit` (groups per page), `cursor`, `q` (filter: a part of a name),
`sort` (`queries` (default), `blocked`, `last_seen`, `name`), `names_limit` (names per
group, 1 to 200, default 50), `blocked_only` (`true` or `false`, default `false`).

```json
{
  "items": [
    {
      "base": "example.com",
      "queries": 2210,
      "blocked": 140,
      "first_seen_at": "2026-11-16T09:12:00Z",
      "last_seen_at": "2026-11-17T08:38:00Z",
      "names_total": 3,
      "names": [
        { "name": "www.example.com", "queries": 1200, "blocked": 0, "first_seen_at": "2026-11-16T09:12:00Z", "last_seen_at": "2026-11-17T08:38:00Z" },
        { "name": "cdn.example.com", "queries": 870, "blocked": 0, "first_seen_at": "2026-11-16T09:12:00Z", "last_seen_at": "2026-11-17T08:30:00Z" },
        { "name": "telemetry.example.com", "queries": 140, "blocked": 140, "first_seen_at": "2026-11-16T10:00:00Z", "last_seen_at": "2026-11-17T08:00:00Z" }
      ]
    }
  ],
  "next_cursor": null
}
```

- The server pages by group. A group is never split between pages.
- `names` are sorted by `queries`, high to low. `names_total` is the number of names
  in the group. If `names_total` is larger than `names_limit`, `names` has only the first
  `names_limit` names.
- With `q`, a group is in the result if its base or one of its names has `q`. `names`
  then has only the matching names, and the group counts are for these names only.
- The hour-of-day histogram of one group or one name comes from
  `GET /stats/hours?client={key}&base=…` or `…&domain=…`.

### 5.7 Domains in statistics

#### `GET /stats/domains`

Search names in the statistics. Parameters: `range`, `q` (required, 1 to 253 characters, a
part of a name), `limit`, `cursor`, `blocked_only`.

```json
{
  "items": [
    { "name": "ads.example.net", "base": "example.net", "queries": 812, "blocked": 812, "clients": 6, "last_seen_at": "2026-11-17T08:20:00Z" }
  ],
  "next_cursor": null
}
```

#### `GET /stats/domains/{name}`

```json
{
  "name": "ads.example.net",
  "base": "example.net",
  "range": "24h",
  "queries": 812,
  "blocked": 812,
  "first_seen_at": "2026-11-12T10:00:00Z",
  "last_seen_at": "2026-11-17T08:20:00Z",
  "clients": [
    { "key": "02:00:00:00:00:03", "name": "tv", "ip": "192.0.2.12", "queries": 400, "blocked": 400, "last_seen_at": "2026-11-17T08:20:00Z" }
  ],
  "utc_offset_minutes": 120,
  "hours": { "queries": [ "24 integers" ], "blocked": [ "24 integers" ] }
}
```

- `clients`: at most 100 clients, sorted by `queries`.
- A name with no queries in the range gives 200 with zero counts and an empty `clients`.

## 6. Recent queries

The server keeps the last queries in a ring buffer in RAM (A9). The size is
`stats.recent_queries_size`. The data is lost at restart.

### `GET /queries/recent`

Parameters: `limit` (1 to 1000, default 100), `client` (a client key), `status` (a
status from section 5), `q` (a part of a name).

```json
{
  "items": [
    {
      "at": "2026-11-17T08:39:59Z",
      "client_key": "02:00:00:00:00:02",
      "client_ip": "192.0.2.11",
      "client_name": "phone",
      "name": "ads.example.net",
      "type": "A",
      "status": "blocked",
      "reason": "list:3",
      "upstream": null,
      "duration_ms": 0.2
    }
  ],
  "next_cursor": null
}
```

- Newest first. No pagination.
- `reason`: why the query has this status, or `null`. Forms: `list:{id}`, `rule:{id}`,
  `special`, `cname:{name}`, `local:{id}`.
- `upstream`: the upstream that answered, or `null`.

## 7. Lists (adlists)

### List object

```json
{
  "id": 3,
  "url": "https://lists.example.org/hosts.txt",
  "comment": "Main block list",
  "kind": "block",
  "enabled": true,
  "groups": [0],
  "status": {
    "state": "ok",
    "last_update_at": "2026-11-17T03:00:00Z",
    "last_success_at": "2026-11-17T03:00:00Z",
    "entries": 120433,
    "invalid_lines": 12,
    "size_bytes": 3402112,
    "last_error": null
  }
}
```

| Field | Type | Rule |
|---|---|---|
| `id` | integer | Read-only. |
| `url` | string | `http` or `https` URL. Unique. Required. |
| `comment` | string | Default `""`. Up to 500 characters. |
| `kind` | `block` or `allow` | Default `block`. |
| `enabled` | boolean | Default `true`. |
| `groups` | integer array | Group ids. Default `[0]`. |
| `status` | object | Read-only. |
| `status.state` | `never`, `updating`, `ok`, `error` | `error` means the last try failed. The list then uses the last good copy on disk, if there is one. |
| `status.last_update_at` | time or null | The last try. |
| `status.last_success_at` | time or null | The last successful download (or "not changed" answer). |
| `status.entries` | integer | Valid domains in the current copy. |
| `status.last_error` | string or null | A short text, for example `"HTTP 404"`. |

### Endpoints

| Method and path | Action |
|---|---|
| `GET /lists` | All lists, plus the refresh schedule. |
| `POST /lists` | Add a list. Body: `url` and optional writable fields. Response 201. The server starts an update of the new list. |
| `GET /lists/{id}` | One list. |
| `PATCH /lists/{id}` | Change `url`, `comment`, `kind`, `enabled`, `groups`. |
| `DELETE /lists/{id}` | Delete the list and its file on disk. 204. |
| `POST /lists/{id}/update` | Start an update of one list. 202. |
| `POST /lists/update` | Start an update of all enabled lists. 202. |

`GET /lists` response:

```json
{
  "items": [ { "id": 3, "url": "…", "…": "…" } ],
  "next_cursor": null,
  "schedule": {
    "interval_hours": 24,
    "next_run_at": "2026-11-18T03:00:00Z",
    "running": false
  }
}
```

- The schedule interval is the setting `lists.refresh_interval_hours` (section 12).
- `202` responses have the body `{ "started": true }`. If an update already runs, the
  server returns 503 `unavailable`.
- The UI polls `GET /lists` while `schedule.running` is `true` or a list has state
  `updating`.

### 7.1 `GET /search/domain` — which list or rule blocks a name

Parameter: `name` (required, a domain name). The server changes an IDN to punycode.

```json
{
  "name": "ads.example.net",
  "verdicts": [
    { "group_id": 0, "group_name": "Default", "verdict": "blocked", "by": "list:3" },
    { "group_id": 1, "group_name": "Kids", "verdict": "blocked", "by": "rule:7" }
  ],
  "matches": [
    { "source": "list", "id": 3, "label": "https://lists.example.org/hosts.txt", "kind": "block", "match": "exact", "pattern": "ads.example.net", "enabled": true, "groups": [0] },
    { "source": "list", "id": 5, "label": "https://lists.example.org/abp.txt", "kind": "block", "match": "parent", "pattern": "||example.net^", "enabled": false, "groups": [0] },
    { "source": "rule", "id": 7, "label": "regex deny", "kind": "block", "match": "regex", "pattern": "^ads\\.", "enabled": true, "groups": [1] },
    { "source": "special", "id": null, "label": "Firefox DoH canary", "kind": "block", "match": "exact", "pattern": "use-application-dns.net", "enabled": true, "groups": [] }
  ],
  "truncated": false
}
```

- `verdicts`: one item per group. `verdict` is `blocked`, `allowed` or `none`. `by` is
  the reason in the same form as in section 6, or `null`.
- `matches`: every list, rule or special domain that has the name. `kind` is `block` or
  `allow`. `match` is `exact`, `parent` (a pattern for a parent domain that covers
  subdomains) or `regex`.
- The server scans the list files on disk (A9). It stops after 100 matches or 5 s. Then
  `truncated` is `true`.

## 8. Rules

### Rule object

```json
{
  "id": 7,
  "kind": "regex",
  "action": "deny",
  "pattern": "^ads\\.",
  "enabled": true,
  "groups": [0],
  "comment": "ad subdomains",
  "created_at": "2026-11-10T07:00:00Z",
  "updated_at": "2026-11-12T07:00:00Z"
}
```

| Field | Type | Rule |
|---|---|---|
| `kind` | `exact` or `regex` | Required. |
| `action` | `allow` or `deny` | Required. Allow beats deny. |
| `pattern` | string | Required. For `exact`: a domain name (the server changes an IDN to punycode). For `regex`: a Rust `regex` pattern, case-insensitive, with a size limit (A8). |
| `enabled` | boolean | Default `true`. |
| `groups` | integer array | Default `[0]`. |
| `comment` | string | Default `""`. |
| `created_at`, `updated_at` | time | Read-only. |

`kind` and `pattern` together are unique per `action`. A duplicate gives 409 `conflict`.

### Endpoints

| Method and path | Action |
|---|---|
| `GET /rules` | All rules. Optional filters: `kind`, `action`. |
| `POST /rules` | Add. 201. |
| `GET /rules/{id}` | One rule. |
| `PATCH /rules/{id}` | Change. |
| `DELETE /rules/{id}` | Delete. 204. |
| `POST /rules/test` | Test a pattern against a name. |

### `POST /rules/test`

Request:

```json
{ "kind": "regex", "pattern": "^ads\\.", "domain": "ads.example.net" }
```

Response 200:

```json
{ "valid": true, "matches": true, "error": null }
```

- An invalid regex gives 200 with `"valid": false`, `"matches": false` and the parser
  error in `error`. It does not give 422, because the test itself worked.
- The server uses the same engine as the policy (Rust `regex`, case-insensitive). The UI
  must not test with JavaScript `RegExp`, because the two engines differ.

## 9. Groups and clients

### Group object

```json
{ "id": 1, "name": "Kids", "enabled": true, "comment": "", "lists": 2, "rules": 4, "clients": 3 }
```

- `name`: required, unique, 1 to 64 characters.
- `lists`, `rules`, `clients`: read-only counts of members.
- Group `0` is the default group. Its name is `Default`. It cannot be deleted (409
  `conflict`). Clients that match no configured client use group 0.
- When a group is deleted, the server removes its id from all lists, rules and clients.

| Method and path | Action |
|---|---|
| `GET /groups` | All groups. |
| `POST /groups` | Add. 201. |
| `GET /groups/{id}` | One group. |
| `PATCH /groups/{id}` | Change `name`, `enabled`, `comment`. |
| `DELETE /groups/{id}` | Delete. 204. |

### Client object (configured clients)

```json
{ "id": 4, "match": "02:00:00:00:00:01", "kind": "mac", "groups": [0, 1], "comment": "laptop" }
```

| Field | Type | Rule |
|---|---|---|
| `match` | string | Required, unique. An IPv4 or IPv6 address, a CIDR, a MAC address, or a host name. |
| `kind` | `ip`, `cidr`, `mac`, `host` | Read-only. The server finds it from `match`. |
| `groups` | integer array | Default `[0]`. |
| `comment` | string | Default `""`. The UI shows it as the client name. |

The `match` value is never a path segment. Paths use the integer `id`.

| Method and path | Action |
|---|---|
| `GET /clients` | All configured clients. |
| `POST /clients` | Add. 201. |
| `GET /clients/{id}` | One client. |
| `PATCH /clients/{id}` | Change `match`, `groups`, `comment`. |
| `DELETE /clients/{id}` | Delete. 204. |
| `GET /clients/seen` | Clients that sent queries, to add them quickly. |

### `GET /clients/seen`

Parameters: `limit` (default 200), `cursor`.

```json
{
  "items": [
    {
      "ip": "192.0.2.14",
      "mac": "02:00:00:00:00:05",
      "name": "printer.lan",
      "first_seen_at": "2026-11-10T07:00:00Z",
      "last_seen_at": "2026-11-17T08:00:00Z",
      "queries": 321,
      "client_id": null
    }
  ],
  "next_cursor": null
}
```

- `mac`: from the neighbor table, or `null`.
- `name`: from conditional forwarding (reverse lookup) or local records, or `null`.
- `client_id`: the configured client that matches, or `null`.

## 10. Local DNS

### Local records (A and AAAA)

```json
{ "id": 2, "name": "nas.lan", "type": "A", "address": "192.0.2.20", "comment": "", "enabled": true }
```

- `type` is `A` or `AAAA`. `address` must have the same family.
- One name can have more than one record.

### Local CNAMEs

```json
{ "id": 1, "name": "files.lan", "target": "nas.lan", "comment": "", "enabled": true }
```

- `name` must not also have a local A or AAAA record (409 `conflict`).

### Conditional forwarding

```json
{ "id": 1, "domain": "lan", "servers": ["192.0.2.1"], "comment": "router", "enabled": true }
```

- `domain`: a domain or a reverse zone, for example `2.0.192.in-addr.arpa`.
- `servers`: 1 to 4 addresses, with an optional port (`192.0.2.1:53`).

| Collection | Paths |
|---|---|
| Records | `GET POST /dns/records`, `GET PATCH DELETE /dns/records/{id}` |
| CNAMEs | `GET POST /dns/cnames`, `GET PATCH DELETE /dns/cnames/{id}` |
| Conditional forwarding | `GET POST /dns/forwarders`, `GET PATCH DELETE /dns/forwarders/{id}` |

## 11. API tokens and TOTP

### Tokens

Token object (the hash is never returned):

```json
{ "id": 2, "name": "backup script", "prefix": "rh_Ab3d", "created_at": "2026-11-10T07:00:00Z", "last_used_at": "2026-11-17T06:00:00Z", "last_used_ip": "192.0.2.10" }
```

| Method and path | Action |
|---|---|
| `GET /tokens` | All tokens. |
| `POST /tokens` | Create. Session only (not a token). |
| `DELETE /tokens/{id}` | Revoke. 204. |

`POST /tokens` request (the password is asked again, because a token gives long access):

```json
{ "name": "backup script", "password": "…" }
```

Response 201. The server shows `secret` only in this response:

```json
{ "token": { "id": 3, "name": "backup script", "prefix": "rh_Q9xk", "created_at": "…", "last_used_at": null, "last_used_ip": null }, "secret": "rh_Q9xk…" }
```

A wrong password gives 401 `invalid_credentials` and counts in the ban state machine.

### TOTP

```mermaid
stateDiagram-v2
    [*] --> Off
    Off --> Pending: POST /auth/totp/setup
    Pending --> On: POST /auth/totp/confirm (valid code)
    Pending --> Off: setup expires (10 min)
    On --> Off: POST /auth/totp/disable
```

| Method and path | Request | Response |
|---|---|---|
| `GET /auth/totp` | | `{ "enabled": true, "pending": false }` |
| `POST /auth/totp/setup` | `{ "password": "…" }` | `{ "otpauth_uri": "otpauth://totp/rusthole:admin?secret=…&issuer=rusthole&algorithm=SHA1&digits=6&period=30", "expires_at": "…" }` |
| `POST /auth/totp/confirm` | `{ "code": "123456" }` | `{ "enabled": true, "pending": false }` |
| `POST /auth/totp/disable` | `{ "password": "…", "code": "123456" }` | `{ "enabled": false, "pending": false }` |

- These paths need a session. A token cannot use them (403 `forbidden`).
- The server shows `otpauth_uri` only in the `setup` response, between setup and
  confirm. After confirm, no endpoint returns the secret.
- `setup` when TOTP is already on gives 409 `conflict`.
- A wrong password or code gives 401 `invalid_credentials` and counts in the ban state
  machine.

## 12. Settings

### `GET /settings`

```json
{
  "upstreams": {
    "servers": ["192.0.2.53", "198.51.100.53"],
    "timeout_ms": 2000
  },
  "blocking": {
    "mode": "null",
    "custom_ipv4": null,
    "custom_ipv6": null,
    "blocked_ttl": 2,
    "special_domains": true,
    "cname_check": true
  },
  "cache": {
    "enabled": true,
    "max_entries": 10000,
    "min_ttl": 0,
    "max_ttl": 86400,
    "negative_ttl": 300
  },
  "rate_limit": {
    "queries_per_second": 50,
    "burst": 200
  },
  "acl": {
    "extra_cidrs": ["198.51.100.0/24"],
    "local_subnets": ["192.0.2.0/24", "2001:db8::/64"]
  },
  "stats": {
    "flush_interval_seconds": 60,
    "retention_days": 30,
    "recent_queries_size": 1000
  },
  "lists": {
    "refresh_interval_hours": 24
  }
}
```

| Field | Rule |
|---|---|
| `upstreams.servers` | 1 to 8 items. Plain `IP` or `IP:port`. P7 adds `tls://` and `https://` forms. |
| `upstreams.timeout_ms` | 100 to 10000. |
| `blocking.mode` | `null` (`0.0.0.0` and `::`, the default), `nxdomain`, `refused`, `custom_ip`. |
| `blocking.custom_ipv4`, `custom_ipv6` | Used only with `custom_ip`. Else `null`. |
| `blocking.blocked_ttl` | 0 to 3600 seconds. |
| `blocking.special_domains` | A3 list on or off. |
| `blocking.cname_check` | A4 deep CNAME check on or off. |
| `cache.max_entries` | 0 to 1000000. |
| `cache.min_ttl`, `max_ttl`, `negative_ttl` | Seconds. `min_ttl` ≤ `max_ttl`. |
| `rate_limit.queries_per_second` | Per client. 0 = no limit. |
| `acl.extra_cidrs` | Up to 64 CIDRs in addition to the local subnets (D7). |
| `acl.local_subnets` | Read-only. The subnets that the server found on its interfaces. |
| `stats.flush_interval_seconds` | 0 (RAM only) or 10 to 3600 (D5). |
| `stats.retention_days` | 1 to 365. |
| `stats.recent_queries_size` | 100 to 100000. |
| `lists.refresh_interval_hours` | 0 (manual only) or 1 to 168. |

The response never has secrets: no password hash, no TOTP secret, no token hashes, no TLS
key.

### `PATCH /settings`

The body holds one or more top-level sections. Each section in the body replaces the old
section as a whole. Do not send read-only fields (`acl.local_subnets`).

```json
{ "cache": { "enabled": true, "max_entries": 20000, "min_ttl": 0, "max_ttl": 86400, "negative_ttl": 300 } }
```

Response 200: the full settings (same shape as `GET`). The server applies the change
without a restart and writes the config file (D2). If the file changed on disk since
the server read it, the response is 409 `config_conflict`.

Listener addresses, TLS files and the password are not in this API. Change them in
`rusthole.toml` and restart, or use `rusthole passwd`.

## 13. Audit log

### `GET /audit`

Parameters: `limit`, `cursor`, `action` (a prefix, for example `list.`).

```json
{
  "items": [
    {
      "id": 1042,
      "at": "2026-11-17T08:31:00Z",
      "action": "list.update",
      "target": "list:3",
      "actor": "session",
      "client_ip": "192.0.2.10",
      "result": "ok",
      "detail": "enabled=false"
    }
  ],
  "next_cursor": "opaque"
}
```

- Newest first.
- `actor`: `session`, `token:{id}`, or `anonymous` (login).
- `result`: `ok` or `error`.
- `detail`: a short text, or `null`. It never has a password, a code or a token.
- Actions: `auth.login`, `auth.login_failed`, `auth.logout`, `auth.ban`, `blocking.set`,
  `list.create`, `list.update`, `list.delete`, `list.refresh`, `rule.create`,
  `rule.update`, `rule.delete`, `group.create`, `group.update`, `group.delete`,
  `client.create`, `client.update`, `client.delete`, `dns.create`, `dns.update`,
  `dns.delete`, `settings.update`, `token.create`, `token.revoke`, `totp.setup`,
  `totp.enable`, `totp.disable`.

## 14. System

### `GET /system`

```json
{
  "version": "0.1.0",
  "commit": "abc1234",
  "started_at": "2026-11-16T07:00:00Z",
  "uptime_seconds": 92000,
  "memory_rss_bytes": 41943040,
  "list_entries": 370211,
  "config_path": "/etc/rusthole/rusthole.toml",
  "data_dir": "/var/lib/rusthole",
  "os": "linux",
  "arch": "aarch64",
  "listeners": [
    { "kind": "dns", "address": "192.0.2.2:53" },
    { "kind": "doh", "address": "192.0.2.2:443" },
    { "kind": "admin", "address": "192.0.2.2:8443" }
  ]
}
```

- `memory_rss_bytes`: `null` if the OS does not give it.
- `list_entries`: unique domains in the compiled block and allow sets.

## 15. Endpoint index

| Method | Path | Section |
|---|---|---|
| POST | `/auth/login` | 3.1 |
| POST | `/auth/logout` | 3.1 |
| GET | `/auth/session` | 3.1 |
| GET | `/auth/totp` | 11 |
| POST | `/auth/totp/setup`, `/auth/totp/confirm`, `/auth/totp/disable` | 11 |
| GET, PUT | `/blocking` | 4 |
| GET | `/stats/summary`, `/stats/timeline`, `/stats/hours` | 5 |
| GET | `/stats/top/domains`, `/stats/top/blocked`, `/stats/top/clients` | 5.4 |
| GET | `/stats/query-types`, `/stats/upstreams` | 5.5 |
| GET | `/stats/clients`, `/stats/clients/{key}`, `/stats/clients/{key}/domains` | 5.6 |
| GET | `/stats/domains`, `/stats/domains/{name}` | 5.7 |
| GET | `/queries/recent` | 6 |
| GET, POST | `/lists` | 7 |
| GET, PATCH, DELETE | `/lists/{id}` | 7 |
| POST | `/lists/{id}/update`, `/lists/update` | 7 |
| GET | `/search/domain` | 7.1 |
| GET, POST | `/rules` | 8 |
| GET, PATCH, DELETE | `/rules/{id}` | 8 |
| POST | `/rules/test` | 8 |
| GET, POST | `/groups`, `/clients`, `/dns/records`, `/dns/cnames`, `/dns/forwarders`, `/tokens` | 9–11 |
| GET, PATCH, DELETE | `/groups/{id}`, `/clients/{id}`, `/dns/records/{id}`, `/dns/cnames/{id}`, `/dns/forwarders/{id}` | 9, 10 |
| DELETE | `/tokens/{id}` | 11 |
| GET | `/clients/seen` | 9 |
| GET, PATCH | `/settings` | 12 |
| GET | `/audit` | 13 |
| GET | `/system` | 14 |

Not in the API on purpose: password change (A7: `rusthole passwd` only), config reload
(A9: no), DHCP.

## 16. Open questions and assumptions for P5

1. **Stable ids.** The config file (`rusthole.toml`) must keep an `id` for each list, rule,
   group, client and local DNS item, so that ids do not change after a restart or an
   import. The import (P1) must give ids. Assumption: P1 or P5 adds this to the schema.
2. **Session lifetime.** 24 h idle and 7 days absolute are assumptions.
3. **Hour buckets.** The server keeps hourly UTC aggregates per client and per name.
   Offsets that are not a whole number of hours are rounded down (section 1.4). If this is
   too coarse, P4 can keep 15-minute aggregates.
4. **Client key.** The key is the MAC, else the IP. A client without a known MAC that
   changes its IP shows as two clients.
5. **Rule timestamps.** `created_at` and `updated_at` need storage in the config or in the
   data directory.
6. **Domain search cost.** `GET /search/domain` scans list files on disk. The limits (100
   matches, 5 s) are assumptions.
7. **Rate limit for the API.** Only the login ban is defined. A general request limit for
   the API is open.
