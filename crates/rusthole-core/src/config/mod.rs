//! The `rusthole.toml` config model.
//!
//! The config is one TOML file. `config_version` is the first key. Each section has defaults,
//! so a file with only `config_version = 1` is a full, valid config. An unknown key is an
//! error, so a typo does not go unseen.
//!
//! Parsing is pure: [`Config::from_toml_str`] reads a string, and [`Config::validate`] returns
//! every problem with its TOML path. The loader in the binary reads the file.
//!
//! Values that the user types as text (addresses, CIDR blocks, URLs, domains, patterns) stay
//! text in this model. [`Config::validate`] parses them. Thus one call reports all problems,
//! not only the first one, and a config writes back to the same text.
//!
//! docs/CONFIG.md has a full example file and the meaning of each field.

mod ids;
mod validate;

#[cfg(test)]
mod tests;

use std::fmt;

use serde::{Deserialize, Serialize};

pub use ids::{DEFAULT_GROUP_ID, IdKind, next_free_id};
pub use validate::{
    ConfigIssue, IPV6_NOT_SUPPORTED, MAX_CACHE_BYTES, MAX_CACHE_ENTRIES, MAX_GROUP_NAME_LEN,
    MAX_RECENT_QUERIES, MAX_TLS_NAMES, MAX_UPSTREAM_TIMEOUT_MS, MIN_CACHE_BYTES, check_list_url,
    is_argon2id_phc, is_valid_group_name, tls_name_problem,
};

/// The config version that this build reads and writes.
pub const CURRENT_VERSION: u32 = 1;

/// The name of the group that always exists. A client with no entry is in this group.
pub const DEFAULT_GROUP: &str = "default";

/// Why a config text cannot be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("the config is not valid TOML or has a wrong key or value: {0}")]
    Toml(String),
    #[error("`config_version` is missing; add `config_version = {CURRENT_VERSION}` at the top")]
    MissingVersion,
    #[error("`config_version` must be an integer")]
    BadVersionType,
    #[error(
        "config_version {found} is not supported; this rusthole reads version {CURRENT_VERSION}"
    )]
    UnsupportedVersion { found: i64 },
    #[error("the config cannot be written as TOML: {0}")]
    Serialize(String),
}

/// The full rusthole config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The schema version. It is required. This build reads version 1.
    pub config_version: u32,
    /// Listen addresses and ports.
    #[serde(default)]
    pub server: Server,
    /// Upstream DNS servers.
    #[serde(default)]
    pub upstreams: Upstreams,
    /// How rusthole answers a blocked name.
    #[serde(default)]
    pub blocking: Blocking,
    /// DNS answer cache.
    #[serde(default)]
    pub cache: Cache,
    /// Which clients can use rusthole.
    #[serde(default)]
    pub acl: Acl,
    /// Per-client query rate limit.
    #[serde(default)]
    pub rate_limit: RateLimit,
    /// Query log and statistics.
    #[serde(default)]
    pub stats: Stats,
    /// Subscribed block and allow lists.
    #[serde(default)]
    pub lists: Lists,
    /// Exact and regex rules.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Groups. Lists, rules and clients refer to groups by name.
    #[serde(default = "default_groups")]
    pub groups: Vec<Group>,
    /// Known clients and their groups.
    #[serde(default)]
    pub clients: Vec<Client>,
    /// Local DNS records and conditional forwarding.
    #[serde(default)]
    pub local_dns: LocalDns,
    /// Admin login and API tokens.
    #[serde(default)]
    pub admin: Admin,
    /// TLS certificate for the admin listener and the DoH listener.
    #[serde(default)]
    pub tls: Tls,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: CURRENT_VERSION,
            server: Server::default(),
            upstreams: Upstreams::default(),
            blocking: Blocking::default(),
            cache: Cache::default(),
            acl: Acl::default(),
            rate_limit: RateLimit::default(),
            stats: Stats::default(),
            lists: Lists::default(),
            rules: Vec::new(),
            groups: default_groups(),
            clients: Vec::new(),
            local_dns: LocalDns::default(),
            admin: Admin::default(),
            tls: Tls::default(),
        }
    }
}

impl Config {
    /// Parses a config text.
    ///
    /// The function reads `config_version` first. An older version goes through [`migrate`].
    /// A newer or unknown version is an error. The function does not call
    /// [`Config::validate`].
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let table: toml::Table = text
            .parse()
            .map_err(|e: toml::de::Error| ConfigError::Toml(toml_error_text(text, &e)))?;
        let version = match table.get("config_version") {
            None => return Err(ConfigError::MissingVersion),
            Some(toml::Value::Integer(v)) => *v,
            Some(_) => return Err(ConfigError::BadVersionType),
        };
        let mut config: Self = if version == i64::from(CURRENT_VERSION) {
            // Parse the text again (not the table): the errors then have line numbers.
            toml::from_str(text).map_err(|e| ConfigError::Toml(toml_error_text(text, &e)))?
        } else {
            let migrated = migrate(table, version)?;
            // The migrated table has no spans in `text`, so the error has the message only.
            toml::Value::Table(migrated)
                .try_into()
                .map_err(|e: toml::de::Error| ConfigError::Toml(toml_error_text("", &e)))?
        };
        config.normalize();
        Ok(config)
    }

    /// Changes each valid domain value to its canonical form: lowercase ASCII, no trailing
    /// dot, and punycode (`xn--`) for a Unicode name (amendment A8).
    ///
    /// [`Config::from_toml_str`] calls this function, so the code that uses a loaded config
    /// can read each domain field with [`DomainName::parse`](crate::DomainName::parse).
    /// The function does not change a value that is not a valid domain name;
    /// [`Config::validate`] reports it. The fields are: exact rule values,
    /// `blocking.special_domains`, local record names, CNAME names and targets, conditional
    /// forwarding domains, client IDs that are host names, and `tls.names`. Regex rules and
    /// URLs do not change. A second call changes nothing.
    pub fn normalize(&mut self) {
        for rule in &mut self.rules {
            if rule.kind == RuleKind::Exact {
                normalize_domain(&mut rule.value);
            }
        }
        for d in &mut self.blocking.special_domains {
            normalize_domain(d);
        }
        for r in &mut self.local_dns.records {
            normalize_domain(&mut r.name);
        }
        for c in &mut self.local_dns.cnames {
            normalize_domain(&mut c.name);
            normalize_domain(&mut c.target);
        }
        for f in &mut self.local_dns.conditional_forwarding {
            if let Some(d) = &mut f.domain {
                normalize_domain(d);
            }
        }
        for c in &mut self.clients {
            if let Ok(id @ crate::net::ClientId::Hostname(_)) = crate::net::ClientId::parse(&c.id) {
                c.id = id.to_string();
            }
        }
        for n in &mut self.tls.names {
            normalize_domain(n);
        }
    }

    /// Writes the config as TOML text. [`Config::from_toml_str`] reads it back to an equal
    /// value.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string(self).map_err(|e| ConfigError::Serialize(e.to_string()))
    }

    /// Returns every problem in the config. An empty list means that the config is valid.
    pub fn validate(&self) -> Vec<ConfigIssue> {
        validate::validate(self)
    }

    /// Returns the certificate and key paths for TLS mode `file`, if the config gives them.
    ///
    /// `tls.cert_path` and `tls.key_path` come first. The older fields `admin.tls_cert_path`
    /// and `admin.tls_key_path` are the second source, so that files from before the `[tls]`
    /// section keep their meaning. The function gives a pair only when both paths of one
    /// source are set.
    pub fn tls_files(&self) -> Option<(&str, &str)> {
        match (&self.tls.cert_path, &self.tls.key_path) {
            (Some(c), Some(k)) => Some((c.as_str(), k.as_str())),
            _ => match (&self.admin.tls_cert_path, &self.admin.tls_key_path) {
                (Some(c), Some(k)) => Some((c.as_str(), k.as_str())),
                _ => None,
            },
        }
    }

    /// Returns the TLS mode that rusthole uses.
    ///
    /// An explicit `tls.mode` wins. Without it, the mode is `file` when the config gives a
    /// certificate and a key (see [`Config::tls_files`]), and `self-signed` otherwise.
    pub fn tls_mode(&self) -> TlsMode {
        self.tls.mode.unwrap_or(if self.tls_files().is_some() {
            TlsMode::File
        } else {
            TlsMode::SelfSigned
        })
    }
}

/// Changes `value` to the canonical form of the domain name, if it is a valid name.
fn normalize_domain(value: &mut String) {
    if let Ok(d) = crate::DomainName::parse_idn(value)
        && d.as_str() != value.as_str()
    {
        d.as_str().clone_into(value);
    }
}

/// Describes a TOML error by line, column and the first line of the message only.
///
/// The `Display` text of a toml error quotes the bad source line. That line can hold a
/// password hash, a TOTP secret or a token hash, so rusthole must never print it. A serde
/// message can also quote a string value (`invalid type: string "..."`), so this function
/// replaces each double-quoted part of the message with `"<redacted>"`. Key and variant names
/// use backticks in these messages, so they stay.
///
/// `text` is the source text of the error. Give an empty text when the error has no span in a
/// source text; the result then has the message only.
pub fn toml_error_text(text: &str, e: &toml::de::Error) -> String {
    let message = redact_quoted(e.message().lines().next().unwrap_or_default());
    match e.span().and_then(|span| text.get(..span.start)) {
        Some(before) if !text.is_empty() => {
            let line = before.matches('\n').count() + 1;
            let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
            format!("line {line}, column {column}: {message}")
        }
        _ => message,
    }
}

/// Replaces the content of each double-quoted part of `message` with `<redacted>`.
/// An unclosed quote hides the rest of the message.
fn redact_quoted(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut inside = false;
    let mut escaped = false;
    for c in message.chars() {
        if inside {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                inside = false;
                out.push_str("<redacted>\"");
            }
            continue;
        }
        out.push(c);
        if c == '"' {
            inside = true;
        }
    }
    if inside {
        out.push_str("<redacted>");
    }
    out
}

/// Changes a config table from an older version to [`CURRENT_VERSION`].
///
/// Version 1 is the first version, so no older version exists yet. Each later version adds
/// one step here (`1 => 2`, `2 => 3`, ...). The function refuses an unknown version.
pub fn migrate(table: toml::Table, from_version: i64) -> Result<toml::Table, ConfigError> {
    match from_version {
        v if v == i64::from(CURRENT_VERSION) => Ok(table),
        found => Err(ConfigError::UnsupportedVersion { found }),
    }
}

fn default_groups() -> Vec<Group> {
    vec![Group {
        id: None,
        name: DEFAULT_GROUP.to_owned(),
        enabled: true,
        comment: None,
    }]
}

fn default_group_names() -> Vec<String> {
    vec![DEFAULT_GROUP.to_owned()]
}

fn auto_listen() -> Vec<String> {
    vec![AUTO.to_owned()]
}

fn yes() -> bool {
    true
}

// serde gives the value by reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_true(b: &bool) -> bool {
    *b
}

/// The listen keyword for "every local IPv4 address".
pub const AUTO: &str = "auto";

/// Listen addresses and ports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    /// DNS listen addresses (UDP and TCP). `"auto"` means each IPv4 address on each local
    /// interface; rusthole binds each one and rebinds when interfaces change.
    /// Otherwise give IPv4 addresses. v1 refuses an IPv6 address (amendment A11).
    /// Default: `["auto"]`.
    pub dns_listen: Vec<String>,
    /// DNS port. Default: 53.
    pub dns_port: u16,
    /// DNS-over-HTTPS listener (path `/dns-query`).
    pub doh: DohListener,
    /// Admin UI and REST API listener (HTTPS).
    pub admin: AdminListener,
    /// The data directory: downloaded lists, the query database and the TLS files
    /// (decision D2). Default: [`DEFAULT_DATA_DIR`].
    pub data_dir: String,
}

/// The default data directory: `/var/lib/rusthole`.
///
/// Windows builds are for development only (PLAN.md section 7). They use `rusthole-data` in
/// the working directory, because that directory needs no administrator rights.
pub const DEFAULT_DATA_DIR: &str = if cfg!(windows) {
    "rusthole-data"
} else {
    "/var/lib/rusthole"
};

impl Default for Server {
    fn default() -> Self {
        Self {
            dns_listen: auto_listen(),
            dns_port: 53,
            doh: DohListener::default(),
            admin: AdminListener::default(),
            data_dir: DEFAULT_DATA_DIR.to_owned(),
        }
    }
}

/// DNS-over-HTTPS listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DohListener {
    /// Default: false. DoH clients need a certificate that they trust (a file or the local
    /// CA), so you turn DoH on after you set up TLS.
    pub enabled: bool,
    /// Listen addresses: `["auto"]` or IPv4 addresses. Default: `["auto"]`.
    pub listen: Vec<String>,
    /// Default: 443. It must not be `dns_port`, because DNS also uses TCP.
    pub port: u16,
}

impl Default for DohListener {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: auto_listen(),
            port: 443,
        }
    }
}

/// Admin UI and REST API listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AdminListener {
    /// Default: true.
    pub enabled: bool,
    /// Listen addresses: `["auto"]` or IPv4 addresses. Default: `["auto"]`.
    pub listen: Vec<String>,
    /// Default: 8443. It must not be `dns_port` or (when DoH is on) the DoH port.
    pub port: u16,
}

impl Default for AdminListener {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: auto_listen(),
            port: 8443,
        }
    }
}

/// Upstream DNS servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Upstreams {
    /// The servers. rusthole sends each query to a healthy server and fails over.
    pub servers: Vec<Upstream>,
    /// Plain DNS servers (`udp://` or `tcp://` with an IPv4 address). rusthole uses them only
    /// while the system clock is not valid, because TLS needs a valid clock (amendment A6).
    /// Default: empty.
    pub fallback_plain: Vec<String>,
    /// Time limit for one upstream query, in milliseconds. Default: 2000.
    pub timeout_ms: u32,
}

impl Default for Upstreams {
    fn default() -> Self {
        Self {
            servers: vec![
                Upstream {
                    url: "udp://9.9.9.9:53".to_owned(),
                    bootstrap: Vec::new(),
                },
                Upstream {
                    url: "udp://1.1.1.1:53".to_owned(),
                    bootstrap: Vec::new(),
                },
            ],
            fallback_plain: Vec::new(),
            timeout_ms: 2000,
        }
    }
}

/// One upstream DNS server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// `8.8.8.8`, `udp://8.8.8.8:53`, `tcp://8.8.8.8`, `tls://dns.example:853` (DoT) or
    /// `https://dns.example/dns-query` (DoH). An IP address must be IPv4 in v1 (amendment A11).
    pub url: String,
    /// IPv4 addresses of the DoT or DoH host. Required when the URL has a host name, so that
    /// rusthole does not need DNS to find its own upstream (amendment A6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bootstrap: Vec<String>,
}

/// How rusthole answers a blocked name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlockingMode {
    /// `0.0.0.0` for A, `::` for AAAA, NODATA for other types.
    #[default]
    Null,
    /// NXDOMAIN for all types.
    Nxdomain,
    /// NODATA (no error, no answer) for all types.
    Nodata,
    /// `ipv4` for A, `ipv6` for AAAA, NODATA for other types. A missing address gives NODATA
    /// for that type.
    Ip,
}

/// Blocking settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Blocking {
    /// Default: true. False forwards all queries.
    pub enabled: bool,
    /// Reply mode. Default: `null`.
    pub mode: BlockingMode,
    /// IPv4 address for mode `ip`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    /// IPv6 address for mode `ip`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    /// TTL of a blocked answer, in seconds. Default: 2.
    pub blocked_ttl: u32,
    /// Names that get NXDOMAIN for all clients (amendment A3): the Firefox DoH canary and
    /// iCloud Private Relay. An empty list turns this off.
    pub special_domains: Vec<String>,
    /// Check each CNAME target in an upstream answer against the client policy
    /// (amendment A4). This stops CNAME cloaking. Default: true.
    pub deep_cname_check: bool,
}

/// The default special domains (amendment A3).
pub const SPECIAL_DOMAINS: [&str; 3] = [
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com",
];

impl Default for Blocking {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: BlockingMode::Null,
            ipv4: None,
            ipv6: None,
            blocked_ttl: 2,
            special_domains: SPECIAL_DOMAINS.iter().map(|s| (*s).to_owned()).collect(),
            deep_cname_check: true,
        }
    }
}

/// Default of `cache.max_bytes`: 16 MiB.
pub const DEFAULT_CACHE_BYTES: u64 = 16 * 1024 * 1024;

/// DNS answer cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Cache {
    /// Maximum number of answers. 0 turns the cache off. Default: 10000.
    pub max_entries: u32,
    /// Most memory of the cache, in bytes (review item M1). The cache counts the encoded
    /// answer, the key and a fixed overhead for each answer, and drops the least recently
    /// used answers to stay below this value. Default: 16 MiB.
    pub max_bytes: u64,
    /// Lowest TTL in seconds. A shorter upstream TTL goes up to this value. Default: 0.
    pub min_ttl: u32,
    /// Highest TTL in seconds. Default: 86400.
    pub max_ttl: u32,
    /// TTL of NXDOMAIN and NODATA answers when the upstream gives no SOA. Default: 300.
    pub negative_ttl: u32,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_bytes: DEFAULT_CACHE_BYTES,
            min_ttl: 0,
            max_ttl: 86_400,
            negative_ttl: 300,
        }
    }
}

/// Which clients can use rusthole (decision D7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Acl {
    /// Allow loopback and each IPv4 subnet on a local interface. Default: true.
    pub auto_local: bool,
    /// More allowed IPv4 networks (CIDR, for example `192.0.2.0/24`). Default: empty.
    pub allow: Vec<String>,
}

impl Default for Acl {
    fn default() -> Self {
        Self {
            auto_local: true,
            allow: Vec::new(),
        }
    }
}

/// Per-client query rate limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimit {
    /// Queries that one client can send in one interval. 0 turns the limit off.
    /// Default: 1000.
    pub queries: u32,
    /// Interval length in seconds. Default: 60.
    pub interval_seconds: u32,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            queries: 1000,
            interval_seconds: 60,
        }
    }
}

/// Query log and statistics (decision D5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Stats {
    /// Seconds between two writes to the database. 0 keeps all data in RAM only.
    /// Default: 60.
    pub flush_interval_seconds: u32,
    /// Days of history to keep in the database. Default: 30.
    pub retention_days: u32,
    /// Size of the in-RAM ring of recent queries. Default: 1000.
    pub recent_queries: u32,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            flush_interval_seconds: 60,
            retention_days: 30,
            recent_queries: 1000,
        }
    }
}

/// Subscribed lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Lists {
    /// Hours between two list refreshes. 0 turns the automatic refresh off. Default: 24.
    pub refresh_interval_hours: u32,
    /// The lists.
    pub adlists: Vec<Adlist>,
}

impl Default for Lists {
    fn default() -> Self {
        Self {
            refresh_interval_hours: 24,
            adlists: Vec::new(),
        }
    }
}

/// Block list or allow list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListKind {
    /// Names in the list are blocked.
    Block,
    /// Names in the list are allowed. Allow beats block.
    Allow,
}

/// One subscribed list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adlist {
    /// A unique number. It names the list in statistics and in the disk cache.
    pub id: u32,
    /// `http://` or `https://` URL of the list.
    pub url: String,
    /// `block` or `allow`.
    pub kind: ListKind,
    /// Default: true.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The groups that use this list. Default: `["default"]`. An empty list means no group.
    #[serde(default = "default_group_names")]
    pub groups: Vec<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// How a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    /// The value is one domain name. It matches that name only.
    Exact,
    /// The value is a regex (`regex` crate syntax, case-insensitive).
    Regex,
}

/// What a rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Block the name.
    Deny,
    /// Allow the name. Allow beats deny.
    Allow,
}

/// One exact or regex rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The stable id of the rule (docs/API.md). The API writes it. A rule without an id gets
    /// one in memory at load (see [`Config::assign_ids`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    /// `exact` or `regex`.
    pub kind: RuleKind,
    /// `deny` or `allow`.
    pub action: RuleAction,
    /// A domain name (kind `exact`) or a pattern (kind `regex`).
    pub value: String,
    /// Default: true.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The groups that use this rule. Default: `["default"]`. An empty list means no group.
    #[serde(default = "default_group_names")]
    pub groups: Vec<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// When the API made the rule (RFC 3339, UTC). The API writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// When the API last changed the rule (RFC 3339, UTC). The API writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// One group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// The stable id of the group (docs/API.md). The group `default` has id 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    /// A unique name: 1 to 64 characters from `a-z`, `0-9`, `-`, `_`, `.`; the first one is a
    /// letter or a digit. The group `default` must exist.
    pub name: String,
    /// A disabled group applies no list and no rule. Default: true.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// One known client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    /// The stable number of the client in the API (docs/API.md). The key `id` holds the
    /// match text, so this number has the key `uid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// An IPv4 address, an IPv4 CIDR block, a MAC address or a host name. v1 refuses an
    /// IPv6 address or block (amendment A11).
    pub id: String,
    /// The groups of this client. Default: `["default"]`. An empty list means no group, so no
    /// list and no rule applies to the client.
    #[serde(default = "default_group_names")]
    pub groups: Vec<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Local DNS data (decision D13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct LocalDns {
    /// A and AAAA records.
    pub records: Vec<LocalRecord>,
    /// CNAME records.
    pub cnames: Vec<LocalCname>,
    /// Send queries for a domain or a reverse zone to a local DNS server.
    pub conditional_forwarding: Vec<ConditionalForward>,
}

/// The type of a local record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordType {
    /// IPv4 address.
    A,
    /// IPv6 address.
    #[serde(rename = "AAAA")]
    Aaaa,
}

/// One local A or AAAA record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRecord {
    /// The stable id of the record (docs/API.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    /// The domain name.
    pub name: String,
    /// `A` or `AAAA`.
    #[serde(rename = "type")]
    pub record_type: RecordType,
    /// The IP address. Its family must match the type.
    pub value: String,
    /// Default: true. A disabled record is not answered.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// One local CNAME record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCname {
    /// The stable id of the CNAME (docs/API.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    /// The alias.
    pub name: String,
    /// The target name.
    pub target: String,
    /// TTL in seconds. Default: the cache rules apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    /// Default: true. A disabled CNAME is not answered.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// One conditional forwarding rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalForward {
    /// The stable id of the rule (docs/API.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    /// Default: true.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Reverse lookups (PTR) for addresses in this network go to `server`. An empty text
    /// means no network: then `domain` is required.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cidr: String,
    /// The local DNS server: an IPv4 address with an optional port (`IP` or `IP:PORT`).
    pub server: String,
    /// Queries for this domain and its subdomains also go to `server`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Admin login and API access (decision D10, amendment A7).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Admin {
    /// Argon2id hash of the admin password (PHC string). Empty means that no login is
    /// possible. Set it with `rusthole passwd`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub password_hash: String,
    /// Base32 TOTP secret. Empty turns TOTP off.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub totp_secret: String,
    /// Session lifetime in seconds. Default: 28800 (8 hours).
    pub session_ttl_seconds: u32,
    /// Path to the TLS certificate chain (PEM). This is the older form of `tls.cert_path`.
    /// It stays valid: with both admin paths set and no `tls.mode`, the mode is `file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert_path: Option<String>,
    /// Path to the TLS private key (PEM). This is the older form of `tls.key_path`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key_path: Option<String>,
    /// API tokens. rusthole keeps only a hash of each token.
    pub api_tokens: Vec<ApiToken>,
}

impl Default for Admin {
    fn default() -> Self {
        Self {
            password_hash: String::new(),
            totp_secret: String::new(),
            session_ttl_seconds: 28_800,
            tls_cert_path: None,
            tls_key_path: None,
            api_tokens: Vec::new(),
        }
    }
}

/// Text that `Debug` shows in place of a secret.
const REDACTED: &str = "<redacted>";

fn redact(secret: &str) -> &'static str {
    if secret.is_empty() { "" } else { REDACTED }
}

// Debug must never show a secret: logs and error messages can contain Debug output.
impl fmt::Debug for Admin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admin")
            .field("password_hash", &redact(&self.password_hash))
            .field("totp_secret", &redact(&self.totp_secret))
            .field("session_ttl_seconds", &self.session_ttl_seconds)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &self.tls_key_path)
            .field("api_tokens", &self.api_tokens)
            .finish()
    }
}

/// One API token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiToken {
    /// The stable id of the token (docs/API.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    /// A unique name.
    pub name: String,
    /// The hash of the token: an Argon2id PHC string, or `sha256:` and 64 hex digits.
    pub hash: String,
    /// The first characters of the token (for example `rh_Ab3d`), so that people can see
    /// which token it is. It is not a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// When the API made the token (RFC 3339, UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiToken")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("hash", &redact(&self.hash))
            .field("prefix", &self.prefix)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Where the TLS certificate comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// A certificate chain and a key from PEM files (`tls.cert_path`, `tls.key_path`).
    File,
    /// rusthole makes a self-signed certificate. Browsers show a warning. This mode is for
    /// the admin UI only: DoH clients do not accept it (amendment A6).
    SelfSigned,
    /// rusthole makes a local certificate authority (CA) and a server certificate that the
    /// CA signs. You install the CA certificate on your devices (amendment A6).
    LocalCa,
}

/// TLS settings for the admin listener and the DoH listener. docs/TLS.md has the details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Tls {
    /// `file`, `self-signed` or `local-ca`. Default: `file` when the config gives a
    /// certificate and a key, otherwise `self-signed`. See [`Config::tls_mode`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<TlsMode>,
    /// Certificate chain (PEM) for mode `file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,
    /// Private key (PEM) for mode `file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    /// Host names for a certificate that rusthole makes (modes `self-signed` and
    /// `local-ca`). rusthole also adds `localhost`, `127.0.0.1` and each local IPv4 address.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
}
