//! Config validation. Each check adds a [`ConfigIssue`] with the TOML path of the bad value.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{AUTO, Admin, BlockingMode, CURRENT_VERSION, Config, DEFAULT_GROUP, RuleKind, TlsMode};
use crate::domain::DomainName;
use crate::net::{Cidr, ClientId, Transport, UpstreamHost, UpstreamUrl, parse_socket_addr};
use crate::pattern::compile_rule_regex;

/// Maximum length of a group name.
pub const MAX_GROUP_NAME_LEN: usize = 64;
/// Highest allowed cache size. It keeps memory bounded on a small device.
pub const MAX_CACHE_ENTRIES: u32 = 1_000_000;
/// Highest allowed size of the recent-query ring.
pub const MAX_RECENT_QUERIES: u32 = 1_000_000;
/// Highest allowed upstream timeout, in milliseconds.
pub const MAX_UPSTREAM_TIMEOUT_MS: u32 = 60_000;
/// Highest number of host names in `tls.names`.
pub const MAX_TLS_NAMES: usize = 32;
/// The issue text for an IPv6 transport value (amendment A11).
pub const IPV6_NOT_SUPPORTED: &str = "IPv6 is not supported in v1";

/// One problem in a config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigIssue {
    /// TOML path of the bad value, for example `rules[3].value`.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for ConfigIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Collects issues.
#[derive(Default)]
struct Issues(Vec<ConfigIssue>);

impl Issues {
    fn add(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(ConfigIssue {
            path: path.into(),
            message: message.into(),
        });
    }
}

pub(super) fn validate(config: &Config) -> Vec<ConfigIssue> {
    let mut out = Issues::default();
    if config.config_version != CURRENT_VERSION {
        out.add(
            "config_version",
            format!(
                "version {} is not supported; this rusthole reads version {CURRENT_VERSION}",
                config.config_version
            ),
        );
    }
    check_server(config, &mut out);
    check_upstreams(config, &mut out);
    check_blocking(config, &mut out);
    check_numbers(config, &mut out);
    let groups = check_groups(config, &mut out);
    check_lists(config, &groups, &mut out);
    check_rules(config, &groups, &mut out);
    check_clients(config, &groups, &mut out);
    check_local_dns(config, &mut out);
    check_admin(&config.admin, &mut out);
    check_tls(config, &mut out);
    out.0
}

/// Adds the A11 issue when `ip` is an IPv6 address.
///
/// v1 uses IPv4 transport only (amendment A11). The types stay `IpAddr`, so v2 can add IPv6
/// with no config migration. An IPv4-mapped IPv6 address (`::ffff:192.0.2.1`) is IPv6 here.
/// Do not use this function for DNS content (AAAA records, `blocking.ipv6`).
fn reject_v6(ip: IpAddr, path: impl Into<String>, out: &mut Issues) {
    if ip.is_ipv6() {
        out.add(path, IPV6_NOT_SUPPORTED);
    }
}

fn check_listen(list: &[String], path: &str, out: &mut Issues) {
    if list.is_empty() {
        out.add(
            path,
            "the list is empty; use [\"auto\"] or give IP addresses",
        );
    }
    let has_auto = list.iter().any(|a| a == AUTO);
    if has_auto && list.len() > 1 {
        out.add(path, "\"auto\" cannot be used together with addresses");
    }
    for (i, addr) in list.iter().enumerate() {
        if addr == AUTO {
            continue;
        }
        match addr.parse::<IpAddr>() {
            Ok(ip) => reject_v6(ip, format!("{path}[{i}]"), out),
            Err(_) => out.add(
                format!("{path}[{i}]"),
                format!("{addr:?} is not \"auto\" and not an IP address"),
            ),
        }
    }
}

fn check_port(port: u16, path: &str, out: &mut Issues) {
    if port == 0 {
        out.add(path, "port 0 is not allowed");
    }
}

fn check_server(config: &Config, out: &mut Issues) {
    let s = &config.server;
    check_listen(&s.dns_listen, "server.dns_listen", out);
    check_port(s.dns_port, "server.dns_port", out);
    check_listen(&s.doh.listen, "server.doh.listen", out);
    check_port(s.doh.port, "server.doh.port", out);
    check_listen(&s.admin.listen, "server.admin.listen", out);
    check_port(s.admin.port, "server.admin.port", out);
    // DNS also listens on TCP at dns_port, so an HTTPS listener cannot use that port.
    if s.doh.enabled && s.admin.enabled && s.doh.port == s.admin.port {
        out.add(
            "server.admin.port",
            "the DoH listener and the admin listener use the same port",
        );
    }
    if s.admin.enabled && s.admin.port == s.dns_port {
        out.add(
            "server.admin.port",
            "the admin listener and the DNS listener (TCP) use the same port",
        );
    }
    if s.doh.enabled && s.doh.port == s.dns_port {
        out.add(
            "server.doh.port",
            "the DoH listener and the DNS listener (TCP) use the same port",
        );
    }
}

fn check_upstreams(config: &Config, out: &mut Issues) {
    let u = &config.upstreams;
    if u.servers.is_empty() {
        out.add("upstreams.servers", "give at least one upstream server");
    }
    for (i, server) in u.servers.iter().enumerate() {
        let path = format!("upstreams.servers[{i}]");
        match UpstreamUrl::parse(&server.url) {
            Err(e) => out.add(format!("{path}.url"), e.to_string()),
            Ok(url) => {
                if let UpstreamHost::Ip(ip) = url.host {
                    reject_v6(ip, format!("{path}.url"), out);
                }
                let needs_bootstrap = matches!(url.host, UpstreamHost::Name(_));
                if needs_bootstrap && server.bootstrap.is_empty() {
                    out.add(
                        format!("{path}.bootstrap"),
                        "a DoT or DoH upstream with a host name needs bootstrap IP addresses",
                    );
                }
                if !url.transport.is_encrypted() && !server.bootstrap.is_empty() {
                    out.add(
                        format!("{path}.bootstrap"),
                        "bootstrap addresses are only for tls:// and https:// upstreams",
                    );
                }
            }
        }
        for (j, text) in server.bootstrap.iter().enumerate() {
            match text.parse::<IpAddr>() {
                Ok(ip) => reject_v6(ip, format!("{path}.bootstrap[{j}]"), out),
                Err(_) => out.add(
                    format!("{path}.bootstrap[{j}]"),
                    format!("{text:?} is not an IP address"),
                ),
            }
        }
    }
    for (i, text) in u.fallback_plain.iter().enumerate() {
        let path = format!("upstreams.fallback_plain[{i}]");
        match UpstreamUrl::parse(text) {
            Err(e) => out.add(path, e.to_string()),
            Ok(url) if !matches!(url.transport, Transport::Udp | Transport::Tcp) => {
                out.add(path, "a fallback must be plain DNS (udp:// or tcp://)");
            }
            Ok(url) => {
                if let UpstreamHost::Ip(ip) = url.host {
                    reject_v6(ip, path, out);
                }
            }
        }
    }
    if u.timeout_ms == 0 || u.timeout_ms > MAX_UPSTREAM_TIMEOUT_MS {
        out.add(
            "upstreams.timeout_ms",
            format!("must be 1 to {MAX_UPSTREAM_TIMEOUT_MS}"),
        );
    }
}

fn check_domain(value: &str, path: impl Into<String>, out: &mut Issues) {
    if let Err(e) = DomainName::parse_idn(value) {
        out.add(path, format!("{value:?} is not a valid domain name: {e}"));
    }
}

fn check_blocking(config: &Config, out: &mut Issues) {
    let b = &config.blocking;
    if let Some(v4) = b.ipv4.as_deref().filter(|v| v.parse::<Ipv4Addr>().is_err()) {
        out.add("blocking.ipv4", format!("{v4:?} is not an IPv4 address"));
    }
    if let Some(v6) = b.ipv6.as_deref().filter(|v| v.parse::<Ipv6Addr>().is_err()) {
        out.add("blocking.ipv6", format!("{v6:?} is not an IPv6 address"));
    }
    if b.mode == BlockingMode::Ip && b.ipv4.is_none() && b.ipv6.is_none() {
        out.add(
            "blocking.mode",
            "mode \"ip\" needs blocking.ipv4 or blocking.ipv6",
        );
    }
    for (i, d) in b.special_domains.iter().enumerate() {
        check_domain(d, format!("blocking.special_domains[{i}]"), out);
    }
}

fn check_numbers(config: &Config, out: &mut Issues) {
    let c = &config.cache;
    if c.max_entries > MAX_CACHE_ENTRIES {
        out.add(
            "cache.max_entries",
            format!("must be at most {MAX_CACHE_ENTRIES}"),
        );
    }
    if c.min_ttl > c.max_ttl {
        out.add("cache.min_ttl", "min_ttl is greater than max_ttl");
    }
    for (i, cidr) in config.acl.allow.iter().enumerate() {
        match Cidr::parse(cidr) {
            Ok(c) => reject_v6(c.addr, format!("acl.allow[{i}]"), out),
            Err(e) => out.add(format!("acl.allow[{i}]"), e.to_string()),
        }
    }
    let r = &config.rate_limit;
    if r.queries > 0 && r.interval_seconds == 0 {
        out.add(
            "rate_limit.interval_seconds",
            "must be greater than 0 when rate_limit.queries is set",
        );
    }
    if config.stats.recent_queries > MAX_RECENT_QUERIES {
        out.add(
            "stats.recent_queries",
            format!("must be at most {MAX_RECENT_QUERIES}"),
        );
    }
}

/// True when `name` is a valid group name. See [`super::Group::name`].
pub fn is_valid_group_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name.len() <= MAX_GROUP_NAME_LEN
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c))
}

fn check_groups<'a>(config: &'a Config, out: &mut Issues) -> HashSet<&'a str> {
    let mut seen = HashSet::new();
    for (i, g) in config.groups.iter().enumerate() {
        if !is_valid_group_name(&g.name) {
            out.add(
                format!("groups[{i}].name"),
                format!(
                    "{:?} is not a valid group name (1 to {MAX_GROUP_NAME_LEN} characters: a-z, 0-9, '-', '_', '.')",
                    g.name
                ),
            );
        }
        if !seen.insert(g.name.as_str()) {
            out.add(
                format!("groups[{i}].name"),
                format!("group {:?} is defined twice", g.name),
            );
        }
    }
    if !seen.contains(DEFAULT_GROUP) {
        out.add("groups", "the group \"default\" must exist");
    }
    seen
}

fn check_group_refs(refs: &[String], groups: &HashSet<&str>, path: &str, out: &mut Issues) {
    for (i, name) in refs.iter().enumerate() {
        if !groups.contains(name.as_str()) {
            out.add(
                format!("{path}.groups[{i}]"),
                format!("group {name:?} is not defined in [[groups]]"),
            );
        }
    }
}

fn check_lists(config: &Config, groups: &HashSet<&str>, out: &mut Issues) {
    let mut ids = HashSet::new();
    let mut urls = HashSet::new();
    for (i, list) in config.lists.adlists.iter().enumerate() {
        let path = format!("lists.adlists[{i}]");
        if !ids.insert(list.id) {
            out.add(
                format!("{path}.id"),
                format!("list id {} is used twice", list.id),
            );
        }
        if !urls.insert(list.url.as_str()) {
            out.add(format!("{path}.url"), "this URL is listed twice");
        }
        if let Err(msg) = check_list_url(&list.url) {
            out.add(format!("{path}.url"), msg);
        }
        check_group_refs(&list.groups, groups, &path, out);
    }
}

/// Checks a list URL: it must be `http://` or `https://` with a host (amendment A8).
/// The error text says what is wrong.
pub fn check_list_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .ok_or_else(|| format!("{url:?} is not an http:// or https:// URL"))?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return Err(format!("{url:?} has no valid host"));
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("{url:?} contains a space or a control character"));
    }
    Ok(())
}

fn check_rules(config: &Config, groups: &HashSet<&str>, out: &mut Issues) {
    for (i, rule) in config.rules.iter().enumerate() {
        let path = format!("rules[{i}]");
        match rule.kind {
            RuleKind::Exact => check_domain(&rule.value, format!("{path}.value"), out),
            RuleKind::Regex => {
                if let Err(e) = compile_rule_regex(&rule.value) {
                    out.add(format!("{path}.value"), e.to_string());
                }
            }
        }
        check_group_refs(&rule.groups, groups, &path, out);
    }
}

fn check_clients(config: &Config, groups: &HashSet<&str>, out: &mut Issues) {
    let mut seen: HashMap<ClientId, usize> = HashMap::new();
    for (i, client) in config.clients.iter().enumerate() {
        let path = format!("clients[{i}]");
        match ClientId::parse(&client.id) {
            Err(e) => out.add(format!("{path}.id"), e.to_string()),
            Ok(id) => {
                match &id {
                    ClientId::Ip(ip) => reject_v6(*ip, format!("{path}.id"), out),
                    ClientId::Cidr(c) => reject_v6(c.addr, format!("{path}.id"), out),
                    ClientId::Mac(_) | ClientId::Hostname(_) => {}
                }
                if let Some(first) = seen.insert(id, i) {
                    out.add(
                        format!("{path}.id"),
                        format!("this client is also clients[{first}]"),
                    );
                }
            }
        }
        check_group_refs(&client.groups, groups, &path, out);
    }
}

fn check_local_dns(config: &Config, out: &mut Issues) {
    let l = &config.local_dns;
    for (i, r) in l.records.iter().enumerate() {
        let path = format!("local_dns.records[{i}]");
        check_domain(&r.name, format!("{path}.name"), out);
        let ok = match r.record_type {
            super::RecordType::A => r.value.parse::<Ipv4Addr>().is_ok(),
            super::RecordType::Aaaa => r.value.parse::<Ipv6Addr>().is_ok(),
        };
        if !ok {
            out.add(
                format!("{path}.value"),
                format!("{:?} is not an address of this record type", r.value),
            );
        }
    }
    for (i, c) in l.cnames.iter().enumerate() {
        let path = format!("local_dns.cnames[{i}]");
        check_domain(&c.name, format!("{path}.name"), out);
        check_domain(&c.target, format!("{path}.target"), out);
    }
    for (i, f) in l.conditional_forwarding.iter().enumerate() {
        let path = format!("local_dns.conditional_forwarding[{i}]");
        match Cidr::parse(&f.cidr) {
            Ok(c) => reject_v6(c.addr, format!("{path}.cidr"), out),
            Err(e) => out.add(format!("{path}.cidr"), e.to_string()),
        }
        match parse_socket_addr(&f.server, 53) {
            Ok(addr) => reject_v6(addr.ip(), format!("{path}.server"), out),
            Err(e) => out.add(format!("{path}.server"), e.to_string()),
        }
        if let Some(d) = &f.domain {
            check_domain(d, format!("{path}.domain"), out);
        }
    }
}

/// True for an Argon2id PHC string: `$argon2id$v=19$m=..,t=..,p=..$SALT$HASH`.
pub fn is_argon2id_phc(text: &str) -> bool {
    let parts: Vec<&str> = text.split('$').collect();
    let b64 = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    };
    let params_ok = |s: &str| {
        s.split(',').count() == 3
            && s.split(',').all(|kv| {
                kv.split_once('=').is_some_and(|(k, v)| {
                    ["m", "t", "p"].contains(&k)
                        && !v.is_empty()
                        && v.bytes().all(|b| b.is_ascii_digit())
                })
            })
    };
    match parts.as_slice() {
        ["", "argon2id", version, params, salt, hash] => {
            version
                .strip_prefix("v=")
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                && params_ok(params)
                && b64(salt)
                && b64(hash)
        }
        ["", "argon2id", params, salt, hash] => params_ok(params) && b64(salt) && b64(hash),
        _ => false,
    }
}

fn is_sha256_token_hash(text: &str) -> bool {
    text.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn check_admin(admin: &Admin, out: &mut Issues) {
    // Never put a secret value into an issue message.
    if !admin.password_hash.is_empty() && !is_argon2id_phc(&admin.password_hash) {
        out.add(
            "admin.password_hash",
            "not an Argon2id PHC string; set the password with `rusthole passwd`",
        );
    }
    if !admin.totp_secret.is_empty() {
        let ok = admin.totp_secret.len() >= 16
            && admin
                .totp_secret
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b) || b == b'=');
        if !ok {
            out.add(
                "admin.totp_secret",
                "not a base32 secret of at least 16 characters (A-Z, 2-7)",
            );
        }
    }
    if admin.session_ttl_seconds == 0 {
        out.add("admin.session_ttl_seconds", "must be greater than 0");
    }
    if admin.tls_cert_path.is_some() != admin.tls_key_path.is_some() {
        out.add(
            "admin.tls_cert_path",
            "set both tls_cert_path and tls_key_path, or neither",
        );
    }
    let mut names = HashSet::new();
    for (i, t) in admin.api_tokens.iter().enumerate() {
        let path = format!("admin.api_tokens[{i}]");
        if t.name.trim().is_empty() {
            out.add(format!("{path}.name"), "the name is empty");
        }
        if !names.insert(t.name.as_str()) {
            out.add(format!("{path}.name"), "this name is used twice");
        }
        if !is_argon2id_phc(&t.hash) && !is_sha256_token_hash(&t.hash) {
            out.add(
                format!("{path}.hash"),
                "not an Argon2id PHC string and not sha256:<64 hex digits>",
            );
        }
    }
}

fn check_tls(config: &Config, out: &mut Issues) {
    let data_dir = &config.server.data_dir;
    if data_dir.trim().is_empty() {
        out.add("server.data_dir", "the data directory is empty");
    } else if data_dir.contains('\0') {
        out.add("server.data_dir", "the path contains a NUL character");
    }
    let tls = &config.tls;
    if tls.cert_path.is_some() != tls.key_path.is_some() {
        out.add(
            "tls.cert_path",
            "set both cert_path and key_path, or neither",
        );
    }
    let new_paths = tls.cert_path.is_some() || tls.key_path.is_some();
    let old_paths = config.admin.tls_cert_path.is_some() || config.admin.tls_key_path.is_some();
    if new_paths && old_paths {
        out.add(
            "tls.cert_path",
            "admin.tls_cert_path and tls.cert_path are both set; use only tls.cert_path and \
             tls.key_path",
        );
    }
    let mode = config.tls_mode();
    match mode {
        TlsMode::File if config.tls_files().is_none() => {
            out.add(
                "tls.mode",
                "mode \"file\" needs tls.cert_path and tls.key_path",
            );
        }
        // Without an explicit mode, a half pair of paths gives self-signed. The pair check
        // above reports that pair already.
        TlsMode::SelfSigned | TlsMode::LocalCa
            if config.tls.mode.is_some() && (new_paths || old_paths) =>
        {
            out.add(
                "tls.mode",
                "the certificate and key paths are only for mode \"file\"",
            );
        }
        _ => {}
    }
    // Amendment A6 (DoH needs a trusted certificate) is not checked here: a config_version 1
    // file with DoH on and no TLS setup was valid before the [tls] section, and it must stay
    // valid. The DoH server config builder in rusthole-tls refuses mode "self-signed".
    if tls.names.len() > MAX_TLS_NAMES {
        out.add(
            "tls.names",
            format!("give at most {MAX_TLS_NAMES} host names"),
        );
    }
    let mut seen = HashSet::new();
    for (i, name) in tls.names.iter().enumerate() {
        let path = format!("tls.names[{i}]");
        if let Some(problem) = tls_name_problem(name) {
            out.add(path, problem);
            continue;
        }
        if let Ok(d) = DomainName::parse(name)
            && !seen.insert(d)
        {
            out.add(path, "this name is used twice");
        }
    }
}

/// Tells why `name` cannot be a host name in a TLS certificate, or gives `None` when it can.
///
/// The rules are the webpki rules for a DNS name in a certificate: ASCII letters, digits and
/// '-' only (RFC 952, no '_'), labels of 1 to 63 characters that do not start or end with
/// '-', at most 253 characters, and a last label that is not all digits. One trailing '.' is
/// permitted. A TLS client refuses a certificate with a name that breaks a rule. A local CA
/// with such a name in its name constraints is refused for every name. rusthole-tls also
/// uses this function, for settings that did not go through [`Config::validate`].
pub fn tls_name_problem(name: &str) -> Option<String> {
    if name.parse::<IpAddr>().is_ok() {
        return Some(
            "give a host name, not an IP address; rusthole adds the local IPv4 addresses"
                .to_owned(),
        );
    }
    // DomainName::parse refuses an empty name, an empty label, a label longer than 63
    // characters, a name longer than 253 characters and a character that is not a letter,
    // a digit, '-' or '_'.
    if let Err(e) = DomainName::parse(name) {
        return Some(e.to_string());
    }
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.contains('_') {
        return Some("a host name cannot contain '_'".to_owned());
    }
    if trimmed
        .split('.')
        .any(|label| label.starts_with('-') || label.ends_with('-'))
    {
        return Some("a label of a host name cannot start or end with '-'".to_owned());
    }
    let last = trimmed.rsplit('.').next().unwrap_or(trimmed);
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return Some("the last label of a host name cannot be all digits".to_owned());
    }
    None
}
