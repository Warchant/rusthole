//! Pure mapping from the Pi-hole v6 `pihole.toml` to the rusthole config.
//!
//! The function reads the file as a generic TOML table, so an unknown or a missing key is
//! not an error. docs/IMPORT.md lists each key and what the import does with it.
//!
//! Secrets (`webserver.api.pwhash`, `webserver.api.totp_secret`, `webserver.api.app_pwhash`)
//! are never copied and never printed. The report says only that they exist.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rusthole_core::DomainName;
use rusthole_core::config::{
    BlockingMode, ConditionalForward, Config, IPV6_NOT_SUPPORTED, LocalCname, LocalRecord,
    MAX_CACHE_ENTRIES, RecordType, Upstream, toml_error_text,
};
use rusthole_core::net::Cidr;
use toml::{Table, Value};

use crate::{ImportError, ImportReport};

/// Leaf keys that the mapping reads. Each other leaf key goes to the "ignored" list.
const HANDLED: &[&str] = &[
    "dns.upstreams",
    "dns.hosts",
    "dns.cnameRecords",
    "dns.revServers",
    "dns.blocking.mode",
    "dns.blocking.active",
    "dns.blockTTL",
    "dns.CNAMEdeepInspect",
    "dns.specialDomains.mozillaCanary",
    "dns.specialDomains.iCloudPrivateRelay",
    "dns.reply.blocking.force4",
    "dns.reply.blocking.IPv4",
    "dns.reply.blocking.force6",
    "dns.reply.blocking.IPv6",
    "dns.rateLimit.count",
    "dns.rateLimit.interval",
    "dns.cache.size",
    "dns.dnssec",
    "dns.interface",
    "dns.listeningMode",
    "dns.domainNeeded",
    "dns.bogusPriv",
    "dns.expandHosts",
    "misc.dnsmasq_lines",
    "misc.etc_dnsmasq_d",
    "webserver.port",
    "webserver.headers",
    "webserver.session.timeout",
    "webserver.api.pwhash",
    "webserver.api.totp_secret",
    "webserver.api.app_pwhash",
    "database.maxDBdays",
    "database.DBinterval",
    "dhcp.active",
];

/// Why a top-level section that the mapping does not read is not needed.
fn section_reason(section: &str) -> &'static str {
    match section {
        "dhcp" => "DHCP is out of scope",
        "ntp" => "rusthole has no NTP server",
        "resolver" => "client names come from the neighbor table and conditional forwarding",
        "database" => "the query database has its own settings in [stats]",
        "webserver" => "the admin UI has its own settings in [server.admin] and [admin]",
        "files" => "rusthole uses its own file paths",
        "debug" => "rusthole uses the RUSTHOLE_LOG filter",
        "misc" | "dns" => "not used by rusthole",
        _ => "unknown section; not used by rusthole",
    }
}

/// Gets the value at a dotted path.
fn get<'a>(root: &'a Table, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut value = root.get(parts.next()?)?;
    for part in parts {
        value = value.as_table()?.get(part)?;
    }
    Some(value)
}

fn get_str<'a>(root: &'a Table, path: &str) -> Option<&'a str> {
    get(root, path).and_then(Value::as_str)
}

fn get_bool(root: &Table, path: &str) -> Option<bool> {
    get(root, path).and_then(Value::as_bool)
}

fn get_int(root: &Table, path: &str) -> Option<i64> {
    get(root, path).and_then(Value::as_integer)
}

/// The strings of an array value. Other array items go to the report.
fn get_strings<'a>(root: &'a Table, path: &str, report: &mut ImportReport) -> Vec<&'a str> {
    match get(root, path) {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| {
                let s = v.as_str();
                if s.is_none() {
                    report.report(format!("{path}: an item is not a string; not imported"));
                }
                s
            })
            .collect(),
        Some(_) => {
            report.report(format!("{path}: not an array; not imported"));
            Vec::new()
        }
    }
}

/// Collects all leaf keys as dotted paths.
///
/// The walk uses a work list, not recursion: a long dotted key (`a.b.c...`) makes a deep table,
/// and recursion could then overflow the stack. Each table is visited once, so the walk ends.
fn leaf_keys(root: &Table, out: &mut Vec<String>) {
    let mut work: Vec<(String, &Table)> = vec![(String::new(), root)];
    while let Some((prefix, table)) = work.pop() {
        for (k, v) in table {
            let path = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            match v {
                Value::Table(t) => work.push((path, t)),
                _ => out.push(path),
            }
        }
    }
    out.sort();
}

/// Splits Pi-hole `IP#port` into an IP and a port. A missing port gives 53.
fn split_hash_port(text: &str) -> Option<(IpAddr, u16)> {
    let text = text.trim();
    let (host, port) = match text.rsplit_once('#') {
        Some((h, p)) => (h, p.trim().parse::<u16>().ok()?),
        None => (text, 53),
    };
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    let ip = host.parse::<IpAddr>().ok()?;
    (port != 0).then_some((ip, port))
}

fn socket_text(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Maps `pihole.toml` into `config`. Invalid TOML is an error. A wrong value of one key goes
/// to the report.
pub fn map_pihole_toml(
    text: &str,
    config: &mut Config,
    report: &mut ImportReport,
) -> Result<(), ImportError> {
    let root: Table = text
        .parse()
        .map_err(|e: toml::de::Error| ImportError::PiholeToml(toml_error_text(text, &e)))?;
    map_upstreams(&root, config, report);
    map_hosts_key(&root, config, report);
    map_cnames(&root, config, report);
    map_rev_servers(&root, config, report);
    map_blocking(&root, config, report);
    map_blocking_extras(&root, config, report);
    map_numbers(&root, config, report);
    report_unsupported(&root, report);
    report_ignored(&root, report);
    Ok(())
}

fn map_upstreams(root: &Table, config: &mut Config, report: &mut ImportReport) {
    if get(root, "dns.upstreams").is_none() {
        return;
    }
    let mut servers = Vec::new();
    for item in get_strings(root, "dns.upstreams", report) {
        match split_hash_port(item) {
            // v1 uses IPv4 transport only (amendment A11).
            Some((IpAddr::V6(_), _)) => report.report(format!(
                "dns.upstreams {item:?}: {IPV6_NOT_SUPPORTED}; not imported"
            )),
            Some((ip, port)) => {
                let url = format!("udp://{}", socket_text(ip, port));
                report.translate(format!(
                    "dns.upstreams {item:?} -> upstreams.servers[{}] {url:?}",
                    servers.len()
                ));
                servers.push(Upstream {
                    url,
                    bootstrap: Vec::new(),
                });
            }
            None => report.report(format!(
                "dns.upstreams {item:?}: not an IP address with an optional #port; not imported"
            )),
        }
    }
    if servers.is_empty() {
        report.report("dns.upstreams: no usable upstream; rusthole keeps its default upstreams");
    } else {
        config.upstreams.servers = servers;
    }
}

fn push_record(
    name: &str,
    ip: IpAddr,
    source: &str,
    config: &mut Config,
    report: &mut ImportReport,
) {
    let domain = match DomainName::parse_idn(name) {
        Ok(d) => d,
        Err(e) => {
            report.report(format!(
                "{source}: {name:?} is not a valid name ({e}); not imported"
            ));
            return;
        }
    };
    let record_type = match ip {
        IpAddr::V4(_) => RecordType::A,
        IpAddr::V6(_) => RecordType::Aaaa,
    };
    let record = LocalRecord {
        id: None,
        enabled: true,
        comment: None,
        name: domain.as_str().to_owned(),
        record_type,
        value: ip.to_string(),
    };
    let type_text = match record_type {
        RecordType::A => "A",
        RecordType::Aaaa => "AAAA",
    };
    if config.local_dns.records.contains(&record) {
        report.ignore(format!(
            "{source}: {} {type_text} {ip} is already imported",
            record.name
        ));
        return;
    }
    report.translate(format!(
        "{source}: {} {type_text} {ip} -> local_dns.records[{}]",
        record.name,
        config.local_dns.records.len()
    ));
    config.local_dns.records.push(record);
}

/// Adds the records of one hosts-style line (`IP name [name ...]`).
pub(crate) fn hosts_line(
    line: &str,
    source: &str,
    skip_system: bool,
    config: &mut Config,
    report: &mut ImportReport,
) {
    let content = line.split('#').next().unwrap_or_default().trim();
    if content.is_empty() {
        return;
    }
    let mut parts = content.split_whitespace();
    let Some(ip_text) = parts.next() else {
        return;
    };
    let Ok(ip) = ip_text.parse::<IpAddr>() else {
        report.report(format!(
            "{source}: line {content:?} does not start with an IP address; not imported"
        ));
        return;
    };
    let names: Vec<&str> = parts.collect();
    if names.is_empty() {
        report.report(format!(
            "{source}: line {content:?} has no name; not imported"
        ));
        return;
    }
    for name in names {
        if skip_system && is_system_entry(ip, name) {
            report.ignore(format!(
                "{source}: system entry {name} {ip} is not imported"
            ));
            continue;
        }
        if skip_system && ip.is_unspecified() {
            // dnsmasq serves /etc/hosts, so this line blocks the name in Pi-hole.
            report.report(format!(
                "{source}: {name:?} on {ip} looks like a manual block; not imported; add an exact deny rule for it"
            ));
            continue;
        }
        push_record(name, ip, source, config, report);
    }
}

/// True for the localhost, loopback, broadcast, multicast and `ip6-` entries of a system
/// hosts file. A name on an unspecified address (`0.0.0.0`, `::`) is not a system entry: it is
/// a manual block.
fn is_system_entry(ip: IpAddr, name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let system_ip = match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4 == Ipv4Addr::BROADCAST,
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_multicast(),
    };
    system_ip
        || lower == "localhost"
        || lower.starts_with("localhost.")
        || lower.starts_with("ip6-")
        || lower == "broadcasthost"
}

fn map_hosts_key(root: &Table, config: &mut Config, report: &mut ImportReport) {
    for item in get_strings(root, "dns.hosts", report) {
        hosts_line(item, "dns.hosts", false, config, report);
    }
}

fn map_cnames(root: &Table, config: &mut Config, report: &mut ImportReport) {
    for item in get_strings(root, "dns.cnameRecords", report) {
        // dnsmasq form: cname[,cname...],target[,ttl]
        let mut fields: Vec<&str> = item.split(',').map(str::trim).collect();
        let ttl = match fields.last().map(|f| f.parse::<u32>()) {
            Some(Ok(t)) if fields.len() >= 3 => {
                fields.pop();
                Some(t)
            }
            _ => None,
        };
        let Some((target, names)) = fields.split_last() else {
            continue;
        };
        if names.is_empty() {
            report.report(format!(
                "dns.cnameRecords {item:?}: needs a name and a target; not imported"
            ));
            continue;
        }
        let Ok(target_name) = DomainName::parse_idn(target) else {
            report.report(format!(
                "dns.cnameRecords {item:?}: target {target:?} is not a valid name; not imported"
            ));
            continue;
        };
        for name in names {
            let Ok(alias) = DomainName::parse_idn(name) else {
                report.report(format!(
                    "dns.cnameRecords {item:?}: name {name:?} is not a valid name; not imported"
                ));
                continue;
            };
            report.translate(format!(
                "dns.cnameRecords {alias} -> {target_name} -> local_dns.cnames[{}]",
                config.local_dns.cnames.len()
            ));
            config.local_dns.cnames.push(LocalCname {
                id: None,
                enabled: true,
                comment: None,
                name: alias.as_str().to_owned(),
                target: target_name.as_str().to_owned(),
                ttl,
            });
        }
    }
}

fn map_rev_servers(root: &Table, config: &mut Config, report: &mut ImportReport) {
    for item in get_strings(root, "dns.revServers", report) {
        // Pi-hole form: active,CIDR,server[#port][,domain]
        let fields: Vec<&str> = item.split(',').map(str::trim).collect();
        let (active, cidr, server, domain) = match fields.as_slice() {
            [a, c, s] => (*a, *c, *s, ""),
            [a, c, s, d] => (*a, *c, *s, *d),
            _ => {
                report.report(format!(
                    "dns.revServers {item:?}: expected active,CIDR,server[,domain]; not imported"
                ));
                continue;
            }
        };
        let enabled = match active {
            "true" => true,
            "false" => false,
            _ => {
                report.report(format!(
                    "dns.revServers {item:?}: the first field must be true or false; not imported"
                ));
                continue;
            }
        };
        let Ok(network) = Cidr::parse(cidr) else {
            report.report(format!(
                "dns.revServers {item:?}: {cidr:?} is not a CIDR block; not imported"
            ));
            continue;
        };
        let Some((ip, port)) = split_hash_port(server) else {
            report.report(format!(
                "dns.revServers {item:?}: {server:?} is not an IP address with an optional #port; not imported"
            ));
            continue;
        };
        // v1 uses IPv4 transport only (amendment A11).
        if network.addr.is_ipv6() || ip.is_ipv6() {
            report.report(format!(
                "dns.revServers {item:?}: {IPV6_NOT_SUPPORTED}; not imported"
            ));
            continue;
        }
        let domain = if domain.is_empty() {
            None
        } else if let Ok(d) = DomainName::parse_idn(domain) {
            Some(d.as_str().to_owned())
        } else {
            report.report(format!(
                "dns.revServers {item:?}: {domain:?} is not a valid domain; not imported"
            ));
            continue;
        };
        let server = if port == 53 {
            ip.to_string()
        } else {
            socket_text(ip, port)
        };
        report.translate(format!(
            "dns.revServers {cidr} via {server}{} -> local_dns.conditional_forwarding[{}]",
            domain
                .as_deref()
                .map_or_else(String::new, |d| format!(" ({d})")),
            config.local_dns.conditional_forwarding.len()
        ));
        config
            .local_dns
            .conditional_forwarding
            .push(ConditionalForward {
                id: None,
                comment: None,
                enabled,
                cidr: cidr.to_owned(),
                server,
                domain,
            });
    }
}

fn map_blocking(root: &Table, config: &mut Config, report: &mut ImportReport) {
    if let Some(active) = get_bool(root, "dns.blocking.active") {
        config.blocking.enabled = active;
        report.translate(format!(
            "dns.blocking.active = {active} -> blocking.enabled"
        ));
    }
    if let Some(ttl) = get_int(root, "dns.blockTTL") {
        match u32::try_from(ttl) {
            Ok(t) => {
                config.blocking.blocked_ttl = t;
                report.translate(format!("dns.blockTTL = {t} -> blocking.blocked_ttl"));
            }
            Err(_) => report.report(format!("dns.blockTTL = {ttl}: out of range; not imported")),
        }
    }
    let ipv4 = (get_bool(root, "dns.reply.blocking.force4") == Some(true))
        .then(|| get_str(root, "dns.reply.blocking.IPv4"))
        .flatten()
        .and_then(|s| s.trim().parse::<Ipv4Addr>().ok());
    let ipv6 = (get_bool(root, "dns.reply.blocking.force6") == Some(true))
        .then(|| get_str(root, "dns.reply.blocking.IPv6"))
        .flatten()
        .and_then(|s| s.trim().parse::<Ipv6Addr>().ok());
    let Some(mode) = get_str(root, "dns.blocking.mode") else {
        return;
    };
    let b = &mut config.blocking;
    match mode {
        "NULL" => {
            b.mode = BlockingMode::Null;
            report.translate("dns.blocking.mode NULL -> blocking.mode \"null\"");
        }
        "NXDOMAIN" => {
            b.mode = BlockingMode::Nxdomain;
            report.translate("dns.blocking.mode NXDOMAIN -> blocking.mode \"nxdomain\"");
        }
        "NODATA" => {
            b.mode = BlockingMode::Nodata;
            report.translate("dns.blocking.mode NODATA -> blocking.mode \"nodata\"");
        }
        "IP-NODATA-AAAA" | "IP" => {
            let want_v6 = mode == "IP";
            let v6 = if want_v6 { ipv6 } else { None };
            if ipv4.is_none() && v6.is_none() {
                b.mode = BlockingMode::Null;
                report.report(format!(
                    "dns.blocking.mode {mode}: Pi-hole answers with the address of its interface, which the export does not hold; rusthole uses mode \"null\"; set blocking.mode = \"ip\" with blocking.ipv4/ipv6 to change this"
                ));
                return;
            }
            b.mode = BlockingMode::Ip;
            b.ipv4 = ipv4.map(|a| a.to_string());
            b.ipv6 = v6.map(|a| a.to_string());
            report.translate(format!(
                "dns.blocking.mode {mode} -> blocking.mode \"ip\" (ipv4 {:?}, ipv6 {:?})",
                b.ipv4, b.ipv6
            ));
            if ipv4.is_none() {
                report.report(format!(
                    "dns.blocking.mode {mode}: no fixed IPv4 address; rusthole answers A queries with NODATA"
                ));
            }
            if want_v6 && v6.is_none() {
                report.report(format!(
                    "dns.blocking.mode {mode}: no fixed IPv6 address; rusthole answers AAAA queries with NODATA"
                ));
            }
        }
        other => report.report(format!(
            "dns.blocking.mode {other:?}: unknown mode; rusthole keeps mode \"null\""
        )),
    }
}

/// Reads a bool key. A value of another type goes to the report.
fn bool_key(root: &Table, path: &str, report: &mut ImportReport) -> Option<bool> {
    let value = get(root, path)?;
    let out = value.as_bool();
    if out.is_none() {
        report.report(format!("{path}: not true or false; not imported"));
    }
    out
}

/// Maps the CNAME inspection and the special-domain switches (amendments A3, A4).
fn map_blocking_extras(root: &Table, config: &mut Config, report: &mut ImportReport) {
    if let Some(on) = bool_key(root, "dns.CNAMEdeepInspect", report) {
        config.blocking.deep_cname_check = on;
        report.translate(format!(
            "dns.CNAMEdeepInspect = {on} -> blocking.deep_cname_check"
        ));
    }
    let switches: [(&str, &[&str]); 2] = [
        (
            "dns.specialDomains.mozillaCanary",
            &["use-application-dns.net"],
        ),
        (
            "dns.specialDomains.iCloudPrivateRelay",
            &["mask.icloud.com", "mask-h2.icloud.com"],
        ),
    ];
    for (path, names) in switches {
        let Some(on) = bool_key(root, path, report) else {
            continue;
        };
        let list = &mut config.blocking.special_domains;
        if on {
            for name in names {
                if !list.iter().any(|d| d == name) {
                    list.push((*name).to_owned());
                }
            }
            report.translate(format!(
                "{path} = true -> blocking.special_domains has {}",
                names.join(", ")
            ));
        } else {
            list.retain(|d| !names.contains(&d.as_str()));
            report.translate(format!(
                "{path} = false -> blocking.special_domains without {}",
                names.join(", ")
            ));
        }
    }
}

fn to_u32(root: &Table, path: &str, report: &mut ImportReport) -> Option<u32> {
    let v = get_int(root, path)?;
    let out = u32::try_from(v).ok();
    if out.is_none() {
        report.report(format!("{path} = {v}: out of range; not imported"));
    }
    out
}

fn map_numbers(root: &Table, config: &mut Config, report: &mut ImportReport) {
    if let Some(count) = to_u32(root, "dns.rateLimit.count", report) {
        config.rate_limit.queries = count;
        report.translate(format!(
            "dns.rateLimit.count = {count} -> rate_limit.queries"
        ));
    }
    if let Some(interval) = to_u32(root, "dns.rateLimit.interval", report) {
        if interval == 0 && config.rate_limit.queries > 0 {
            report.report(
                "dns.rateLimit.interval = 0: rusthole needs an interval; it keeps 60 seconds",
            );
        } else {
            config.rate_limit.interval_seconds = interval;
            report.translate(format!(
                "dns.rateLimit.interval = {interval} -> rate_limit.interval_seconds"
            ));
        }
    }
    if let Some(size) = to_u32(root, "dns.cache.size", report) {
        let clamped = size.min(MAX_CACHE_ENTRIES);
        config.cache.max_entries = clamped;
        report.translate(format!("dns.cache.size = {size} -> cache.max_entries"));
        if clamped != size {
            report.report(format!(
                "dns.cache.size = {size}: rusthole allows at most {MAX_CACHE_ENTRIES}; it uses {clamped}"
            ));
        }
    }
    // In Pi-hole, maxDBdays = 0 turns the query database off. rusthole then keeps all data in
    // RAM only, and DBinterval must not turn the disk writes on again.
    let mut database_off = false;
    if let Some(days) = to_u32(root, "database.maxDBdays", report) {
        if days == 0 {
            database_off = true;
            config.stats.flush_interval_seconds = 0;
            report.translate(
                "database.maxDBdays = 0 (database off) -> stats.flush_interval_seconds = 0 (RAM only)",
            );
        } else {
            config.stats.retention_days = days;
            report.translate(format!(
                "database.maxDBdays = {days} -> stats.retention_days"
            ));
        }
    }
    if let Some(secs) = to_u32(root, "database.DBinterval", report) {
        if database_off {
            report.ignore(format!(
                "database.DBinterval = {secs}: the database is off (maxDBdays = 0); rusthole keeps data in RAM only"
            ));
        } else {
            config.stats.flush_interval_seconds = secs;
            report.translate(format!(
                "database.DBinterval = {secs} -> stats.flush_interval_seconds"
            ));
        }
    }
    if let Some(secs) = to_u32(root, "webserver.session.timeout", report) {
        if secs == 0 {
            report.report("webserver.session.timeout = 0: rusthole keeps its default");
        } else {
            config.admin.session_ttl_seconds = secs;
            report.translate(format!(
                "webserver.session.timeout = {secs} -> admin.session_ttl_seconds"
            ));
        }
    }
}

fn non_empty(root: &Table, path: &str) -> bool {
    match get(root, path) {
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Boolean(b)) => *b,
        Some(_) => true,
        None => false,
    }
}

fn report_unsupported(root: &Table, report: &mut ImportReport) {
    if get_bool(root, "dns.dnssec") == Some(true) {
        report.report(
            "dns.dnssec = true: rusthole v1 does not validate DNSSEC; it sets the DO bit and passes the AD bit of the upstream through",
        );
    }
    if non_empty(root, "dns.interface") {
        report.report(
            "dns.interface: rusthole listens on the addresses in server.dns_listen (default: each local address)",
        );
    }
    match get_str(root, "dns.listeningMode") {
        None | Some("LOCAL") => {}
        Some(mode) => report.report(format!(
            "dns.listeningMode = {mode:?}: rusthole answers loopback and local subnets only (acl.auto_local); add other networks to acl.allow"
        )),
    }
    for key in ["dns.domainNeeded", "dns.bogusPriv", "dns.expandHosts"] {
        if get_bool(root, key) == Some(true) {
            report.report(format!("{key} = true: rusthole has no such option"));
        }
    }
    let lines = get(root, "misc.dnsmasq_lines")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if lines > 0 {
        report.report(format!(
            "misc.dnsmasq_lines: {lines} custom dnsmasq lines are not imported; translate them by hand"
        ));
    }
    if get_bool(root, "misc.etc_dnsmasq_d") == Some(true) {
        report.report(
            "misc.etc_dnsmasq_d = true: files in /etc/dnsmasq.d are not in the export and are not imported",
        );
    }
    if let Some(port) = get(root, "webserver.port") {
        report.report(format!(
            "webserver.port = {port}: the rusthole admin UI uses server.admin.port (default 8443, HTTPS)"
        ));
    }
    if non_empty(root, "webserver.headers") {
        report.report(
            "webserver.headers: rusthole sets its own security headers; custom headers are not imported",
        );
    }
    // Never copy or print the values of these keys.
    if non_empty(root, "webserver.api.pwhash") {
        report.report(
            "webserver.api.pwhash: the Pi-hole password cannot be imported; set a new password with `rusthole passwd`",
        );
    }
    if non_empty(root, "webserver.api.totp_secret") {
        report.report(
            "webserver.api.totp_secret: the TOTP secret is not imported; set up TOTP again in rusthole",
        );
    }
    if non_empty(root, "webserver.api.app_pwhash") {
        report.report(
            "webserver.api.app_pwhash: the app password is not imported; make an API token in rusthole",
        );
    }
    if get_bool(root, "dhcp.active") == Some(true) {
        report
            .report("dhcp.active = true: DHCP is out of scope; keep a DHCP server on your network");
    }
}

fn report_ignored(root: &Table, report: &mut ImportReport) {
    let mut keys = Vec::new();
    leaf_keys(root, &mut keys);
    let mut by_section: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for key in keys {
        if HANDLED.contains(&key.as_str()) {
            continue;
        }
        let section = key.split('.').next().unwrap_or_default().to_owned();
        by_section.entry(section).or_default().push(key);
    }
    for (section, keys) in by_section {
        let reason = section_reason(&section);
        if section == "dns" {
            // DNS keys matter most, so list each one.
            for key in keys {
                report.ignore(format!("pihole.toml {key}: {reason}"));
            }
        } else {
            report.ignore(format!(
                "pihole.toml {section}.*: {} keys; {reason}",
                keys.len()
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> (Config, ImportReport) {
        let mut c = Config::default();
        let mut r = ImportReport::default();
        map_pihole_toml(text, &mut c, &mut r).unwrap();
        (c, r)
    }

    #[test]
    fn upstreams_with_ports() {
        let (c, r) = run(r#"
[dns]
upstreams = ["192.0.2.1", "192.0.2.2#5353", "2001:db8::1", "2001:db8::2#54", "bad", "192.0.2.3#0"]
"#);
        let urls: Vec<_> = c.upstreams.servers.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(urls, ["udp://192.0.2.1:53", "udp://192.0.2.2:5353"]);
        assert_eq!(
            r.reported,
            [
                "dns.upstreams \"2001:db8::1\": IPv6 is not supported in v1; not imported",
                "dns.upstreams \"2001:db8::2#54\": IPv6 is not supported in v1; not imported",
                "dns.upstreams \"bad\": not an IP address with an optional #port; not imported",
                "dns.upstreams \"192.0.2.3#0\": not an IP address with an optional #port; not imported",
            ]
        );
        assert_eq!(c.validate(), []);
    }

    #[test]
    fn only_ipv6_upstreams_keep_defaults() {
        let (c, r) = run("[dns]\nupstreams = [\"2001:db8::53\", \"[2001:db8::54]#53\"]\n");
        assert_eq!(c.upstreams, Config::default().upstreams);
        assert_eq!(r.reported.len(), 3, "{:#?}", r.reported);
        assert!(r.reported[2].contains("rusthole keeps its default upstreams"));
        assert_eq!(c.validate(), []);
    }

    #[test]
    fn empty_upstreams_keep_defaults() {
        let (c, r) = run("[dns]\nupstreams = []\n");
        assert_eq!(c.upstreams, Config::default().upstreams);
        assert_eq!(r.reported.len(), 1);
    }

    #[test]
    fn hosts_cnames_and_rev_servers() {
        let (c, r) = run(r#"
[dns]
hosts = ["192.0.2.10 nas.lan media", "2001:db8::10 nas.lan", "junk line", "192.0.2.11"]
cnameRecords = ["www.lan,nas.lan", "a.lan,b.lan,nas.lan,300", "only"]
revServers = [
    "true,192.0.2.0/24,192.0.2.1,lan",
    "false,192.0.2.128/25,192.0.2.129#5353",
    "false,2001:db8::/32,[2001:db8::1]#5353",
    "true,192.0.2.0/24,2001:db8::1",
    "true,2001:db8::/32,192.0.2.1",
    "maybe,1,2,3",
]
"#);
        assert_eq!(c.local_dns.records.len(), 3);
        assert_eq!(c.local_dns.records[1].name, "media");
        assert_eq!(c.local_dns.records[2].record_type, RecordType::Aaaa);
        let cn: Vec<_> = c
            .local_dns
            .cnames
            .iter()
            .map(|x| (x.name.as_str(), x.target.as_str(), x.ttl))
            .collect();
        assert_eq!(
            cn,
            [
                ("www.lan", "nas.lan", None),
                ("a.lan", "nas.lan", Some(300)),
                ("b.lan", "nas.lan", Some(300))
            ]
        );
        let f = &c.local_dns.conditional_forwarding;
        assert_eq!(f.len(), 2);
        assert_eq!(
            (f[0].server.as_str(), f[0].domain.as_deref()),
            ("192.0.2.1", Some("lan"))
        );
        assert_eq!(
            (f[1].enabled, f[1].server.as_str()),
            (false, "192.0.2.129:5353")
        );
        // An IPv6 CIDR or an IPv6 server is reported (A11).
        let v6: Vec<_> = r
            .reported
            .iter()
            .filter(|l| {
                l.starts_with("dns.revServers") && l.contains("IPv6 is not supported in v1")
            })
            .collect();
        assert_eq!(v6.len(), 3, "{:#?}", r.reported);
        assert_eq!(r.reported.len(), 7, "{:#?}", r.reported);
        assert_eq!(c.validate(), [], "{:#?}", c.validate());
    }

    #[test]
    fn blocking_modes() {
        let (c, _) = run("[dns.blocking]\nmode = \"NXDOMAIN\"\nactive = false\n");
        assert_eq!(c.blocking.mode, BlockingMode::Nxdomain);
        assert!(!c.blocking.enabled);
        let (c, r) = run("[dns.blocking]\nmode = \"IP\"\n");
        assert_eq!(c.blocking.mode, BlockingMode::Null);
        assert_eq!(r.reported.len(), 1);
        let (c, r) = run(
            "[dns.blocking]\nmode = \"IP\"\n[dns.reply.blocking]\nforce4 = true\nIPv4 = \"192.0.2.1\"\n",
        );
        assert_eq!(c.blocking.mode, BlockingMode::Ip);
        assert_eq!(c.blocking.ipv4.as_deref(), Some("192.0.2.1"));
        assert_eq!(r.reported.len(), 1, "no IPv6: {:#?}", r.reported);
        assert_eq!(c.validate(), []);
        let (c, r) = run(
            "[dns.blocking]\nmode = \"IP-NODATA-AAAA\"\n[dns.reply.blocking]\nforce4 = true\nIPv4 = \"192.0.2.1\"\nforce6 = true\nIPv6 = \"2001:db8::1\"\n",
        );
        assert_eq!(c.blocking.ipv6, None);
        assert_eq!(r.reported, Vec::<String>::new());
        let (_, r) = run("[dns.blocking]\nmode = \"WEIRD\"\n");
        assert_eq!(r.reported.len(), 1);
    }

    #[test]
    fn secrets_are_reported_but_never_copied() {
        let text = r#"
[webserver]
port = "80o,443os"
[webserver.api]
pwhash = "$BALLOON-SHA256$v=1$s=1024,t=32$c2VjcmV0c2FsdA==$c2VjcmV0aGFzaA=="
totp_secret = "TOTPSECRETVALUE7"
app_pwhash = "$BALLOON-SHA256$v=1$s=1024,t=32$YXBwc2FsdA==$YXBwaGFzaA=="
"#;
        let (c, r) = run(text);
        let all: Vec<&str> = r.all_lines().collect();
        let joined = all.join("\n");
        for secret in ["c2VjcmV0", "TOTPSECRETVALUE7", "YXBw", "BALLOON"] {
            assert!(!joined.contains(secret), "report leaks {secret}");
            assert!(!c.to_toml_string().unwrap().contains(secret));
            assert!(!format!("{c:?}").contains(secret));
        }
        assert_eq!(c.admin.password_hash, "");
        assert!(joined.contains("rusthole passwd"));
    }

    #[test]
    fn reports_unsupported_options() {
        let (_, r) = run(r#"
[dns]
dnssec = true
interface = "eth0"
listeningMode = "ALL"
domainNeeded = true
bogusPriv = true
expandHosts = true
[misc]
dnsmasq_lines = ["address=/x.example/192.0.2.1"]
etc_dnsmasq_d = true
[dhcp]
active = true
"#);
        assert_eq!(r.reported.len(), 9, "{:#?}", r.reported);
    }

    #[test]
    fn unhandled_keys_are_ignored_with_reason() {
        let (_, r) = run(
            "[dns]\nqueryLogging = true\n[ntp.ipv4]\nactive = true\n[ntp.ipv6]\nactive = true\n",
        );
        assert_eq!(
            r.ignored,
            [
                "pihole.toml dns.queryLogging: not used by rusthole",
                "pihole.toml ntp.*: 2 keys; rusthole has no NTP server"
            ]
        );
    }

    #[test]
    fn deep_dotted_key_does_not_overflow() {
        let key = vec!["k"; 5000].join(".");
        let mut c = Config::default();
        let mut r = ImportReport::default();
        // The TOML parser can refuse a very deep key; both results are fine, a crash is not.
        let _ = map_pihole_toml(
            &format!(
                "{key} = 1
"
            ),
            &mut c,
            &mut r,
        );
    }

    #[test]
    fn invalid_toml_is_an_error() {
        let mut c = Config::default();
        let mut r = ImportReport::default();
        assert!(matches!(
            map_pihole_toml("[dns", &mut c, &mut r),
            Err(ImportError::PiholeToml(_))
        ));
    }

    #[test]
    fn parse_error_does_not_quote_a_secret() {
        let text = "[webserver.api]\npwhash = \"$BALLOON-SHA256$SECRETPART\n";
        let mut c = Config::default();
        let mut r = ImportReport::default();
        let err = map_pihole_toml(text, &mut c, &mut r)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("SECRETPART"), "{err}");
        assert!(err.contains("line 2"), "{err}");
    }

    #[test]
    fn max_db_days_zero_turns_disk_writes_off() {
        let (c, r) = run("[database]\nmaxDBdays = 0\nDBinterval = 30\n");
        assert_eq!(c.stats.flush_interval_seconds, 0);
        assert_eq!(
            c.stats.retention_days,
            Config::default().stats.retention_days
        );
        assert_eq!(
            r.translated,
            [
                "database.maxDBdays = 0 (database off) -> stats.flush_interval_seconds = 0 (RAM only)"
            ]
        );
        assert_eq!(r.ignored.len(), 1, "{:#?}", r.ignored);
        assert!(r.ignored[0].starts_with("database.DBinterval = 30: the database is off"));
        assert_eq!(c.validate(), []);

        let (c, _) = run("[database]\nmaxDBdays = 91\nDBinterval = 30\n");
        assert_eq!(
            (c.stats.retention_days, c.stats.flush_interval_seconds),
            (91, 30)
        );
    }

    #[test]
    fn cname_inspection_and_special_domains() {
        let (c, r) = run(
            "[dns]\nCNAMEdeepInspect = false\n[dns.specialDomains]\nmozillaCanary = false\niCloudPrivateRelay = true\n",
        );
        assert!(!c.blocking.deep_cname_check);
        assert_eq!(
            c.blocking.special_domains,
            ["mask.icloud.com", "mask-h2.icloud.com"]
        );
        assert_eq!(r.translated.len(), 3, "{:#?}", r.translated);
        assert_eq!(r.ignored, Vec::<String>::new());
        assert_eq!(c.validate(), []);

        let (c, _) = run("[dns.specialDomains]\niCloudPrivateRelay = false\n");
        assert_eq!(c.blocking.special_domains, ["use-application-dns.net"]);
        assert!(c.blocking.deep_cname_check);

        let (c, r) = run("[dns]\nCNAMEdeepInspect = \"yes\"\n");
        assert!(c.blocking.deep_cname_check);
        assert_eq!(
            r.reported,
            ["dns.CNAMEdeepInspect: not true or false; not imported"]
        );
    }

    #[test]
    fn control_characters_in_keys_are_escaped() {
        let (_, r) = run("[dns]\n\"a\\u001b[2Jb\" = 1\n[\"x\\u001by\"]\nk = 1\n");
        for line in r.all_lines() {
            assert!(!line.chars().any(char::is_control), "{line:?}");
        }
        assert!(
            r.ignored
                .iter()
                .any(|l| l == r"pihole.toml dns.a\u{1b}[2Jb: not used by rusthole"),
            "{:#?}",
            r.ignored
        );
    }

    #[test]
    fn wrong_types_go_to_the_report() {
        let (c, r) = run(
            "[dns]\nupstreams = \"192.0.2.1\"\nhosts = [1, \"192.0.2.9 x\"]\n[dns.cache]\nsize = -5\n",
        );
        assert_eq!(c.upstreams, Config::default().upstreams);
        assert_eq!(c.local_dns.records.len(), 1);
        assert!(r.reported.len() >= 3, "{:#?}", r.reported);
    }
}
