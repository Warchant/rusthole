//! Local DNS (decision D13): local A, AAAA and CNAME records, the reverse map of the local
//! addresses, conditional forwarding, and private reverse zones. Pure: no I/O.
//!
//! [`LocalZone::lookup`] decides, before the policy, the cache and the upstreams:
//!
//! ```mermaid
//! flowchart TD
//!     q[name, type] --> c{local CNAME?}
//!     c -->|yes| cn[CNAME chain + local records of the last target]
//!     c -->|no| r{local A/AAAA name?}
//!     r -->|yes| rr[records of the type, or NODATA]
//!     r -->|no| p{reverse name of a local address?}
//!     p -->|yes| ptr[PTR records, or NODATA]
//!     p -->|no| f{conditional forwarding: domain or reverse zone?}
//!     f -->|yes| fw[Forward to its server]
//!     f -->|no| pr{private reverse zone?}
//!     pr -->|yes| nx[NXDOMAIN: never leak private reverse lookups]
//!     pr -->|no| nl[NotLocal: policy, cache, upstreams]
//! ```
//!
//! docs/CLIENTS.md has the details.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::config::{Config, ConfigIssue, RecordType};
use crate::domain::DomainName;
use crate::net::{Cidr, parse_socket_addr};

/// TTL of a local A, AAAA or PTR record, and of a local CNAME without a `ttl`, in seconds.
pub const DEFAULT_LOCAL_TTL: u32 = 300;
/// CNAME records that one local answer follows, at most.
pub const MAX_CNAME_CHAIN: usize = 8;

/// DNS type numbers that this module uses.
pub mod qtype {
    /// IPv4 address.
    pub const A: u16 = 1;
    /// Alias.
    pub const CNAME: u16 = 5;
    /// Start of authority.
    pub const SOA: u16 = 6;
    /// Reverse pointer.
    pub const PTR: u16 = 12;
    /// IPv6 address.
    pub const AAAA: u16 = 28;
    /// Any type.
    pub const ANY: u16 = 255;
}

/// The data of one local record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalData {
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
    /// An alias: the target name.
    Cname(DomainName),
    /// A reverse pointer: the host name.
    Ptr(DomainName),
}

/// One record of a local answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRr {
    /// The owner name.
    pub name: DomainName,
    /// TTL in seconds.
    pub ttl: u32,
    /// The data.
    pub data: LocalData,
}

/// The result of [`LocalZone::lookup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAnswer {
    /// An authoritative answer (AA bit). Empty records mean NODATA: the name is local, but it
    /// has no record of this type. The policy does not apply to a local name.
    Answer(Vec<LocalRr>),
    /// Send the query to this server, not to the public upstreams. `rule` is the index in
    /// `local_dns.conditional_forwarding` of the config. The policy applies as usual.
    Forward {
        /// The local DNS server.
        server: SocketAddr,
        /// The index of the rule in the config.
        rule: usize,
    },
    /// A name in a private reverse zone that no conditional forwarding rule covers. Answer
    /// NXDOMAIN: a private reverse lookup never goes to the public upstreams.
    PrivateReverse,
    /// Not local: the policy, the cache and the upstreams decide.
    NotLocal,
}

/// A reverse name (`in-addr.arpa` or `ip6.arpa`) as the network that it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReverseName {
    /// The network: an address with the bits of the name and a prefix length of 8 bits per
    /// IPv4 label or 4 bits per IPv6 label. A full name gives a host network (/32, /128).
    pub net: Cidr,
    /// True when the name has more labels in front of the numeric labels of `net` (for
    /// example `lb._dns-sd._udp.0.2.0.192.in-addr.arpa`). Such a name is in the reverse zone
    /// of `net`, but it does not name a host.
    pub extra: bool,
}

impl ReverseName {
    /// The host address, when the name has all labels (4 for IPv4, 32 for IPv6) and no
    /// extra label.
    pub fn host(&self) -> Option<IpAddr> {
        let full = match self.net.addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        (self.net.prefix == full && !self.extra).then_some(self.net.addr)
    }
}

const V4_SUFFIX: &str = "in-addr.arpa";
const V6_SUFFIX: &str = "ip6.arpa";

/// Parses a reverse name. `7.2.0.192.in-addr.arpa` gives `192.0.2.7/32`;
/// `2.0.192.in-addr.arpa` gives `192.0.2.0/24`; `in-addr.arpa` gives `0.0.0.0/0`. See
/// [`parse_reverse_labels`].
pub fn parse_reverse(name: &DomainName) -> Option<ReverseName> {
    let labels: Vec<&[u8]> = name.as_str().split('.').map(str::as_bytes).collect();
    parse_reverse_labels(&labels)
}

/// Parses a reverse name from its labels (the leftmost label first, no root label). The
/// network comes from the longest numeric suffix in front of the zone: the walk starts at
/// the zone and stops at the first label that is not a decimal octet (IPv4, no leading
/// zero, 4 at most) or one hex digit (IPv6, 32 at most). The labels in front of it set
/// [`ReverseName::extra`]. Thus `lb._dns-sd._udp.0.2.0.192.in-addr.arpa` and
/// `0/25.2.0.192.in-addr.arpa` are in the zone of `192.0.2.0/24`. A name that is not in
/// `in-addr.arpa` or `ip6.arpa` gives `None`.
pub fn parse_reverse_labels(labels: &[&[u8]]) -> Option<ReverseName> {
    let (rest, v4) = match labels {
        [rest @ .., zone, arpa] if arpa.eq_ignore_ascii_case(b"arpa") => {
            if zone.eq_ignore_ascii_case(b"in-addr") {
                (rest, true)
            } else if zone.eq_ignore_ascii_case(b"ip6") {
                (rest, false)
            } else {
                return None;
            }
        }
        _ => return None,
    };
    // The labels are in reverse order: the label next to the zone is the first octet or
    // nibble of the address.
    if v4 {
        let mut bytes = [0u8; 4];
        let mut count = 0usize;
        for (slot, label) in bytes.iter_mut().zip(rest.iter().rev()) {
            let Some(octet) = parse_octet(label) else {
                break;
            };
            *slot = octet;
            count += 1;
        }
        let prefix = u8::try_from(count * 8).ok()?;
        return Some(ReverseName {
            net: Cidr {
                addr: IpAddr::V4(Ipv4Addr::from(bytes)),
                prefix,
            },
            extra: count < rest.len(),
        });
    }
    let mut value: u128 = 0;
    let mut count = 0u32;
    for label in rest.iter().rev().take(32) {
        let Some(nibble) = parse_nibble(label) else {
            break;
        };
        value |= u128::from(nibble) << (124 - 4 * count);
        count += 1;
    }
    let prefix = u8::try_from(count * 4).ok()?;
    Some(ReverseName {
        net: Cidr {
            addr: IpAddr::V6(Ipv6Addr::from(value)),
            prefix,
        },
        extra: usize::try_from(count).ok()? < rest.len(),
    })
}

fn parse_octet(label: &[u8]) -> Option<u8> {
    if label.is_empty()
        || label.len() > 3
        || !label.iter().all(u8::is_ascii_digit)
        || (label.len() > 1 && label.first() == Some(&b'0'))
    {
        return None;
    }
    std::str::from_utf8(label).ok()?.parse().ok()
}

fn parse_nibble(label: &[u8]) -> Option<u8> {
    match label {
        [c] => u8::try_from(char::from(*c).to_digit(16)?).ok(),
        _ => None,
    }
}

/// The reverse name of an address: `192.0.2.7` gives `7.2.0.192.in-addr.arpa`.
pub fn reverse_name(ip: IpAddr) -> Option<DomainName> {
    let text = match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.{V4_SUFFIX}")
        }
        IpAddr::V6(v6) => {
            let value = u128::from(v6);
            let mut s = String::with_capacity(72);
            for i in 0..32 {
                let nibble = (value >> (4 * i)) & 0xf;
                // Writing to a String cannot fail.
                let _ = write!(s, "{nibble:x}.");
            }
            s.push_str(V6_SUFFIX);
            s
        }
    };
    DomainName::parse(&text).ok()
}

/// True when the reverse zone of `cidr` holds the reverse name `rev`: the name names `cidr`
/// or a part of it. For a full name this is `cidr.contains(address)`.
pub fn zone_holds(cidr: &Cidr, rev: &ReverseName) -> bool {
    rev.net.prefix >= cidr.prefix && cidr.contains(rev.net.addr)
}

/// The networks whose reverse lookups never go to the public upstreams (like the dnsmasq
/// option `bogus-priv`): private, loopback, link-local, shared (CGNAT), "this network" and
/// documentation ranges. None of them has public reverse data.
pub fn private_networks() -> [Cidr; 14] {
    let v4 = |a: u8, b: u8, c: u8, prefix: u8| Cidr {
        addr: IpAddr::V4(Ipv4Addr::new(a, b, c, 0)),
        prefix,
    };
    let v6 = |first: u16, second: u16, prefix: u8| Cidr {
        addr: IpAddr::V6(Ipv6Addr::new(first, second, 0, 0, 0, 0, 0, 0)),
        prefix,
    };
    [
        v4(0, 0, 0, 8),
        v4(10, 0, 0, 8),
        v4(100, 64, 0, 10),
        v4(127, 0, 0, 8),
        v4(169, 254, 0, 16),
        v4(172, 16, 0, 12),
        v4(192, 168, 0, 16),
        v4(192, 0, 2, 24),
        v4(198, 51, 100, 24),
        v4(203, 0, 113, 24),
        Cidr {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix: 128,
        },
        v6(0xfc00, 0, 7),
        v6(0xfe80, 0, 10),
        v6(0x2001, 0x0db8, 32),
    ]
}

/// True when the reverse name is in a private reverse zone (see [`private_networks`]).
pub fn is_private_reverse(rev: &ReverseName) -> bool {
    private_networks().iter().any(|c| zone_holds(c, rev))
}

/// One enabled conditional forwarding rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    /// The index in `local_dns.conditional_forwarding` of the config.
    pub rule: usize,
    /// Reverse lookups for this network go to `server`.
    pub cidr: Cidr,
    /// The local DNS server.
    pub server: SocketAddr,
    /// Queries for this domain and its subdomains also go to `server`.
    pub domain: Option<DomainName>,
}

/// The local DNS data of a config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalZone {
    a: HashMap<DomainName, Vec<Ipv4Addr>>,
    aaaa: HashMap<DomainName, Vec<Ipv6Addr>>,
    cnames: HashMap<DomainName, (DomainName, u32)>,
    reverse: HashMap<IpAddr, Vec<DomainName>>,
    forwards: Vec<Forward>,
}

impl LocalZone {
    /// Makes the zone from `local_dns` of a config. The config does not need to be valid: a
    /// value that does not parse is skipped and reported.
    pub fn from_config(config: &Config) -> (Self, Vec<ConfigIssue>) {
        let mut issues = Vec::new();
        let mut issue = |path: String, message: String| issues.push(ConfigIssue { path, message });
        let mut zone = Self::default();
        let l = &config.local_dns;
        for (i, r) in l.records.iter().enumerate() {
            let path = format!("local_dns.records[{i}]");
            let Ok(name) = DomainName::parse_idn(&r.name) else {
                issue(
                    format!("{path}.name"),
                    "not a valid domain name; the record is ignored".to_owned(),
                );
                continue;
            };
            let ip = match r.record_type {
                RecordType::A => r.value.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
                RecordType::Aaaa => r.value.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
            };
            let Some(ip) = ip else {
                issue(
                    format!("{path}.value"),
                    "not an address of this record type; the record is ignored".to_owned(),
                );
                continue;
            };
            match ip {
                IpAddr::V4(v4) => push_unique(zone.a.entry(name.clone()).or_default(), v4),
                IpAddr::V6(v6) => push_unique(zone.aaaa.entry(name.clone()).or_default(), v6),
            }
            push_unique(zone.reverse.entry(ip).or_default(), name);
        }
        for (i, c) in l.cnames.iter().enumerate() {
            let path = format!("local_dns.cnames[{i}]");
            let (Ok(name), Ok(target)) = (
                DomainName::parse_idn(&c.name),
                DomainName::parse_idn(&c.target),
            ) else {
                issue(
                    path,
                    "not a valid domain name; the CNAME is ignored".to_owned(),
                );
                continue;
            };
            if zone.cnames.contains_key(&name) {
                issue(
                    format!("{path}.name"),
                    "this alias is defined twice; the first CNAME is used".to_owned(),
                );
                continue;
            }
            if zone.a.contains_key(&name) || zone.aaaa.contains_key(&name) {
                issue(
                    format!("{path}.name"),
                    "this name also has a local record; the CNAME is used".to_owned(),
                );
            }
            zone.cnames
                .insert(name, (target, c.ttl.unwrap_or(DEFAULT_LOCAL_TTL)));
        }
        for (i, f) in l.conditional_forwarding.iter().enumerate() {
            if !f.enabled {
                continue;
            }
            let path = format!("local_dns.conditional_forwarding[{i}]");
            let cidr = match Cidr::parse(&f.cidr) {
                Ok(c) => c,
                Err(e) => {
                    issue(format!("{path}.cidr"), format!("{e}; the rule is ignored"));
                    continue;
                }
            };
            let server = match parse_socket_addr(&f.server, 53) {
                Ok(s) => s,
                Err(e) => {
                    issue(
                        format!("{path}.server"),
                        format!("{e}; the rule is ignored"),
                    );
                    continue;
                }
            };
            let domain = match f.domain.as_deref().map(DomainName::parse_idn) {
                None => None,
                Some(Ok(d)) => Some(d),
                Some(Err(e)) => {
                    issue(
                        format!("{path}.domain"),
                        format!("{e}; the rule is ignored"),
                    );
                    continue;
                }
            };
            zone.forwards.push(Forward {
                rule: i,
                cidr,
                server,
                domain,
            });
        }
        (zone, issues)
    }

    /// The enabled conditional forwarding rules.
    pub fn forwards(&self) -> &[Forward] {
        &self.forwards
    }

    /// The local host names of an address (the reverse map).
    pub fn names_of(&self, ip: IpAddr) -> &[DomainName] {
        self.reverse.get(&ip).map_or(&[], Vec::as_slice)
    }

    /// Decides a query for `name` with type `qtype`. See the module documentation.
    pub fn lookup(&self, name: &DomainName, qtype: u16) -> LocalAnswer {
        if self.cnames.contains_key(name) {
            return LocalAnswer::Answer(self.cname_chain(name, qtype));
        }
        if self.a.contains_key(name) || self.aaaa.contains_key(name) {
            return LocalAnswer::Answer(self.address_records(name, qtype));
        }
        let rev = parse_reverse(name);
        if let Some(host) = rev.as_ref().and_then(ReverseName::host)
            && let Some(names) = self.reverse.get(&host)
        {
            let records = if qtype == qtype::PTR || qtype == qtype::ANY {
                names
                    .iter()
                    .map(|n| LocalRr {
                        name: name.clone(),
                        ttl: DEFAULT_LOCAL_TTL,
                        data: LocalData::Ptr(n.clone()),
                    })
                    .collect()
            } else {
                Vec::new()
            };
            return LocalAnswer::Answer(records);
        }
        if let Some(f) = self.forward_for(name, rev.as_ref()) {
            return LocalAnswer::Forward {
                server: f.server,
                rule: f.rule,
            };
        }
        reverse_zone_answer(rev.as_ref(), None)
    }

    /// Decides a query that [`LocalZone::lookup`] cannot take: a name that is not a valid
    /// [`DomainName`] (for example the RFC 2317 name `0/25.2.0.192.in-addr.arpa`) or a class
    /// that is not IN. `labels` are the labels of the query name, the leftmost label first.
    /// Only the reverse zones apply: a conditional forward by `cidr`, else NXDOMAIN for a
    /// private reverse zone, else [`LocalAnswer::NotLocal`]. Local records do not apply.
    pub fn lookup_reverse_zone(&self, labels: &[&[u8]]) -> LocalAnswer {
        let rev = parse_reverse_labels(labels);
        let forward = rev.as_ref().and_then(|r| self.reverse_forward_for(r));
        reverse_zone_answer(rev.as_ref(), forward)
    }

    /// The conditional forwarding rule for a name: the most specific domain match (on label
    /// boundaries: `lan` matches `a.lan`, not `plan`), else the most specific reverse zone
    /// that holds the name. The first rule wins a tie.
    pub fn forward_for(&self, name: &DomainName, rev: Option<&ReverseName>) -> Option<&Forward> {
        let mut best: Option<(&Forward, usize)> = None;
        for f in &self.forwards {
            if let Some(d) = &f.domain
                && name.is_same_or_subdomain_of(d)
            {
                let len = d.as_str().len();
                if best.is_none_or(|(_, l)| len > l) {
                    best = Some((f, len));
                }
            }
        }
        if let Some((f, _)) = best {
            return Some(f);
        }
        self.reverse_forward_for(rev?)
    }

    /// The conditional forwarding rule with the most specific reverse zone that holds `rev`.
    /// The first rule wins a tie.
    fn reverse_forward_for(&self, rev: &ReverseName) -> Option<&Forward> {
        let mut best: Option<&Forward> = None;
        for f in &self.forwards {
            if zone_holds(&f.cidr, rev) && best.is_none_or(|b| f.cidr.prefix > b.cidr.prefix) {
                best = Some(f);
            }
        }
        best
    }

    /// The A and AAAA records of a local name for `qtype`. Another type gives no record
    /// (NODATA).
    fn address_records(&self, name: &DomainName, qtype: u16) -> Vec<LocalRr> {
        let mut out = Vec::new();
        let rr = |data| LocalRr {
            name: name.clone(),
            ttl: DEFAULT_LOCAL_TTL,
            data,
        };
        if qtype == qtype::A || qtype == qtype::ANY {
            for ip in self.a.get(name).into_iter().flatten() {
                out.push(rr(LocalData::A(*ip)));
            }
        }
        if qtype == qtype::AAAA || qtype == qtype::ANY {
            for ip in self.aaaa.get(name).into_iter().flatten() {
                out.push(rr(LocalData::Aaaa(*ip)));
            }
        }
        out
    }

    /// The CNAME chain from `name`, then the local records of the last target. The walk
    /// stops at [`MAX_CNAME_CHAIN`] CNAME records, at a loop, or at a target that is not local
    /// (the answer then holds the CNAME records only). A chain of exactly
    /// [`MAX_CNAME_CHAIN`] CNAME records still gets the records of its last target. A CNAME
    /// query gets the first record only.
    fn cname_chain(&self, name: &DomainName, qtype: u16) -> Vec<LocalRr> {
        let mut out: Vec<LocalRr> = Vec::new();
        let mut cur = name.clone();
        for _ in 0..MAX_CNAME_CHAIN {
            let Some((target, ttl)) = self.cnames.get(&cur) else {
                out.extend(self.address_records(&cur, qtype));
                return out;
            };
            out.push(LocalRr {
                name: cur.clone(),
                ttl: *ttl,
                data: LocalData::Cname(target.clone()),
            });
            if qtype == qtype::CNAME {
                return out;
            }
            let seen = out.iter().any(|r| r.name == *target);
            if seen || *target == *name {
                return out;
            }
            cur = target.clone();
        }
        // The bound was reached. When the last target is not an alias, the chain is complete:
        // add its records. Else give the records found so far.
        if !self.cnames.contains_key(&cur) {
            out.extend(self.address_records(&cur, qtype));
        }
        out
    }
}

/// The answer for a reverse name that no local record and no domain rule takes: the
/// conditional forward `forward`, else NXDOMAIN for a private reverse zone, else not local.
fn reverse_zone_answer(rev: Option<&ReverseName>, forward: Option<&Forward>) -> LocalAnswer {
    if let Some(f) = forward {
        return LocalAnswer::Forward {
            server: f.server,
            rule: f.rule,
        };
    }
    if rev.is_some_and(is_private_reverse) {
        return LocalAnswer::PrivateReverse;
    }
    LocalAnswer::NotLocal
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

#[cfg(test)]
mod tests;
