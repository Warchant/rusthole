//! Parsers for network values in the config: CIDR blocks, MAC addresses, client IDs,
//! socket addresses and upstream URLs.
//!
//! All parsers are pure. They do not resolve names.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::domain::{DomainError, DomainName};

/// An IP network: an address and a prefix length.
///
/// The address can have host bits set (`192.0.2.7/24`). [`Cidr::contains`] ignores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    /// The address part.
    pub addr: IpAddr,
    /// The prefix length: 0..=32 for IPv4, 0..=128 for IPv6.
    pub prefix: u8,
}

/// Why a string is not a valid network value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("{0:?} is not an IP address")]
    BadIp(String),
    #[error("{0:?} is not a CIDR block (use ADDRESS/PREFIX)")]
    BadCidr(String),
    #[error("prefix length {prefix} is too long for this address family (max {max})")]
    PrefixTooLong { prefix: u8, max: u8 },
    #[error("{0:?} is not a MAC address (use six hex pairs, for example 02:00:00:00:00:01)")]
    BadMac(String),
    #[error("{0:?} is not an address with an optional port")]
    BadSocketAddr(String),
    #[error("port 0 is not allowed")]
    PortZero,
    #[error("{0:?} has no scheme that rusthole knows (use udp://, tcp://, tls:// or https://)")]
    BadScheme(String),
    #[error("{0:?} is not a valid upstream URL")]
    BadUrl(String),
    #[error("the host of a plain DNS upstream must be an IP address, not {0:?}")]
    PlainHostName(String),
    #[error("host name is not valid: {0}")]
    BadHost(#[from] DomainError),
    #[error("{0:?} is a network interface; rusthole does not support clients by interface")]
    Interface(String),
}

impl Cidr {
    /// Parses `ADDRESS/PREFIX`. A plain address gives a host network (/32 or /128).
    pub fn parse(input: &str) -> Result<Self, NetError> {
        let s = input.trim();
        let (addr_text, prefix_text) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_text
            .parse()
            .map_err(|_| NetError::BadCidr(input.to_owned()))?;
        let max = max_prefix(addr);
        let prefix = match prefix_text {
            None => max,
            Some(p) => {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.len() > 3 {
                    return Err(NetError::BadCidr(input.to_owned()));
                }
                p.parse::<u8>()
                    .map_err(|_| NetError::BadCidr(input.to_owned()))?
            }
        };
        if prefix > max {
            return Err(NetError::PrefixTooLong { prefix, max });
        }
        Ok(Self { addr, prefix })
    }

    /// True when `ip` is in this network. An IPv4 address is never in an IPv6 network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let shift = 32 - u32::from(self.prefix);
                let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let shift = 128 - u32::from(self.prefix);
                let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn max_prefix(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// An Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Parses six hex pairs separated by `:` or `-` (for example `02:00:00:00:00:01`).
    pub fn parse(input: &str) -> Result<Self, NetError> {
        let s = input.trim();
        let sep = if s.contains('-') { '-' } else { ':' };
        let mut out = [0u8; 6];
        let mut count = 0usize;
        for part in s.split(sep) {
            let slot = out
                .get_mut(count)
                .ok_or_else(|| NetError::BadMac(input.to_owned()))?;
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(NetError::BadMac(input.to_owned()));
            }
            *slot = u8::from_str_radix(part, 16).map_err(|_| NetError::BadMac(input.to_owned()))?;
            count += 1;
        }
        if count != 6 {
            return Err(NetError::BadMac(input.to_owned()));
        }
        Ok(Self(out))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// How the config identifies a client.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientId {
    /// One IP address.
    Ip(IpAddr),
    /// A network.
    Cidr(Cidr),
    /// A MAC address. rusthole finds it in the kernel neighbor table.
    Mac(MacAddr),
    /// A host name.
    Hostname(DomainName),
}

impl ClientId {
    /// Parses a client ID. The order is: MAC, CIDR, IP, interface (refused), host name.
    ///
    /// The IP forms come before the interface form, because an IPv6 address such as `::1`
    /// also starts with `:`. The Pi-hole interface form is `:` and a name with no other `:`.
    pub fn parse(input: &str) -> Result<Self, NetError> {
        let s = input.trim();
        if let Ok(mac) = MacAddr::parse(s) {
            return Ok(Self::Mac(mac));
        }
        if s.contains('/') {
            return Cidr::parse(s).map(Self::Cidr);
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if let Some(rest) = s.strip_prefix(':') {
            if !rest.is_empty() && !rest.contains(':') {
                return Err(NetError::Interface(input.to_owned()));
            }
            return Err(NetError::BadIp(input.to_owned()));
        }
        Ok(Self::Hostname(DomainName::parse_idn(s)?))
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Cidr(c) => write!(f, "{c}"),
            Self::Mac(m) => write!(f, "{m}"),
            Self::Hostname(h) => write!(f, "{h}"),
        }
    }
}

/// Parses `IP`, `IP:PORT` or `[IPv6]:PORT`. A missing port gives `default_port`.
/// Port 0 is an error.
pub fn parse_socket_addr(input: &str, default_port: u16) -> Result<SocketAddr, NetError> {
    let s = input.trim();
    let addr = if let Ok(ip) = s.parse::<IpAddr>() {
        SocketAddr::new(ip, default_port)
    } else {
        s.parse::<SocketAddr>()
            .map_err(|_| NetError::BadSocketAddr(input.to_owned()))?
    };
    if addr.port() == 0 {
        return Err(NetError::PortZero);
    }
    Ok(addr)
}

/// The transport of an upstream DNS server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Plain DNS over UDP, with TCP retry on truncation.
    Udp,
    /// Plain DNS over TCP.
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    Https,
}

impl Transport {
    /// The default port of the transport.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 53,
            Self::Tls => 853,
            Self::Https => 443,
        }
    }

    /// True for DoT and DoH: these need a TLS certificate check.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Tls | Self::Https)
    }
}

/// The host of an upstream: an IP address or a host name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpstreamHost {
    /// An IP address. rusthole connects to it directly.
    Ip(IpAddr),
    /// A host name. rusthole connects to a bootstrap address and checks the name in TLS.
    Name(DomainName),
}

/// A parsed upstream URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamUrl {
    /// The transport.
    pub transport: Transport,
    /// The host.
    pub host: UpstreamHost,
    /// The port. It is never 0.
    pub port: u16,
    /// The HTTP path for DoH (for example `/dns-query`). Empty for other transports.
    pub path: String,
}

impl UpstreamUrl {
    /// Parses an upstream URL.
    ///
    /// Forms: `8.8.8.8`, `8.8.8.8:53`, `udp://8.8.8.8:53`, `tcp://[2001:db8::1]:53`,
    /// `tls://dns.example:853`, `https://dns.example/dns-query`. A plain DNS upstream
    /// (`udp://`, `tcp://`) must use an IP address. A DoH URL without a path gets `/dns-query`.
    ///
    /// The parser accepts IPv6 hosts, so the type is ready for v2. `Config::validate` refuses
    /// an IPv6 upstream in v1 (amendment A11).
    pub fn parse(input: &str) -> Result<Self, NetError> {
        let s = input.trim();
        let Some((scheme, rest)) = s.split_once("://") else {
            let addr = parse_socket_addr(s, 53)?;
            return Ok(Self {
                transport: Transport::Udp,
                host: UpstreamHost::Ip(addr.ip()),
                port: addr.port(),
                path: String::new(),
            });
        };
        let transport = match scheme.to_ascii_lowercase().as_str() {
            "udp" => Transport::Udp,
            "tcp" => Transport::Tcp,
            "tls" => Transport::Tls,
            "https" => Transport::Https,
            _ => return Err(NetError::BadScheme(input.to_owned())),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (
                rest.get(..i).unwrap_or_default(),
                rest.get(i..).unwrap_or_default(),
            ),
            None => (rest, ""),
        };
        if transport == Transport::Https {
            if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(NetError::BadUrl(input.to_owned()));
            }
        } else if !path.is_empty() && path != "/" {
            return Err(NetError::BadUrl(input.to_owned()));
        }
        if authority.contains('@') || authority.is_empty() {
            return Err(NetError::BadUrl(input.to_owned()));
        }
        let (host_text, port) = split_host_port(authority, transport.default_port())
            .ok_or_else(|| NetError::BadUrl(input.to_owned()))?;
        if port == 0 {
            return Err(NetError::PortZero);
        }
        let host = if let Ok(ip) = host_text.parse::<IpAddr>() {
            UpstreamHost::Ip(ip)
        } else if transport.is_encrypted() {
            UpstreamHost::Name(DomainName::parse_idn(host_text)?)
        } else {
            return Err(NetError::PlainHostName(host_text.to_owned()));
        };
        let path = if transport == Transport::Https {
            if path.is_empty() || path == "/" {
                "/dns-query".to_owned()
            } else {
                path.to_owned()
            }
        } else {
            String::new()
        };
        Ok(Self {
            transport,
            host,
            port,
            path,
        })
    }
}

/// Splits `host`, `host:port`, `[v6]` or `[v6]:port`. Returns `None` on bad syntax.
fn split_host_port(authority: &str, default_port: u16) -> Option<(&str, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after {
            "" => default_port,
            p => parse_port(p.strip_prefix(':')?)?,
        };
        return Some((host, port));
    }
    // One colon separates a port. More colons mean a bare IPv6 address with no port.
    if authority.matches(':').count() == 1 {
        let (host, port) = authority.split_once(':')?;
        return Some((host, parse_port(port)?));
    }
    Some((authority, default_port))
}

fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn cidr_parse_and_contains() {
        let c = Cidr::parse("192.0.2.0/24").unwrap();
        assert!(c.contains("192.0.2.99".parse().unwrap()));
        assert!(!c.contains("192.0.3.1".parse().unwrap()));
        assert!(!c.contains("2001:db8::1".parse().unwrap()));
        let all = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("203.0.113.1".parse().unwrap()));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert_eq!(Cidr::parse("192.0.2.1").unwrap().prefix, 32);
        assert!(matches!(
            Cidr::parse("192.0.2.0/33"),
            Err(NetError::PrefixTooLong { .. })
        ));
        assert!(Cidr::parse("192.0.2.0/").is_err());
        assert!(Cidr::parse("192.0.2.0/+1").is_err());
        assert!(Cidr::parse("host/24").is_err());
    }

    #[test]
    fn mac_parse() {
        let m = MacAddr::parse("02:00:00:00:00:0A").unwrap();
        assert_eq!(m.to_string(), "02:00:00:00:00:0a");
        assert_eq!(MacAddr::parse("02-00-00-00-00-0a").unwrap(), m);
        assert!(MacAddr::parse("02:00:00:00:00").is_err());
        assert!(MacAddr::parse("02:00:00:00:00:00:00").is_err());
        assert!(MacAddr::parse("2:00:00:00:00:00").is_err());
        assert!(MacAddr::parse("zz:00:00:00:00:00").is_err());
    }

    #[test]
    fn client_id_kinds() {
        assert!(matches!(
            ClientId::parse("02:00:00:00:00:01"),
            Ok(ClientId::Mac(_))
        ));
        assert!(matches!(ClientId::parse("192.0.2.5"), Ok(ClientId::Ip(_))));
        assert!(matches!(
            ClientId::parse("2001:db8::5"),
            Ok(ClientId::Ip(_))
        ));
        assert!(matches!(
            ClientId::parse("192.0.2.0/24"),
            Ok(ClientId::Cidr(_))
        ));
        assert!(matches!(
            ClientId::parse("laptop.lan"),
            Ok(ClientId::Hostname(_))
        ));
        assert!(matches!(
            ClientId::parse(":eth0"),
            Err(NetError::Interface(_))
        ));
        assert!(ClientId::parse("bad name").is_err());
    }

    #[test]
    fn client_id_ipv6_that_starts_with_colons_is_not_an_interface() {
        assert!(matches!(ClientId::parse("::1"), Ok(ClientId::Ip(_))));
        assert!(matches!(
            ClientId::parse("::ffff:192.0.2.1"),
            Ok(ClientId::Ip(_))
        ));
        assert!(matches!(ClientId::parse("::"), Ok(ClientId::Ip(_))));
        assert!(matches!(ClientId::parse("::/0"), Ok(ClientId::Cidr(_))));
        assert!(matches!(
            ClientId::parse("::ffff:0:0/96"),
            Ok(ClientId::Cidr(_))
        ));
        assert!(matches!(
            ClientId::parse(":eth0"),
            Err(NetError::Interface(_))
        ));
        assert!(matches!(
            ClientId::parse(" :wlan0 "),
            Err(NetError::Interface(_))
        ));
        assert!(matches!(ClientId::parse(":"), Err(NetError::BadIp(_))));
        assert!(matches!(ClientId::parse(":x:y"), Err(NetError::BadIp(_))));
    }

    #[test]
    fn socket_addr_forms() {
        assert_eq!(
            parse_socket_addr("192.0.2.1", 53).unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53)
        );
        assert_eq!(
            parse_socket_addr("192.0.2.1:5353", 53).unwrap().port(),
            5353
        );
        assert_eq!(
            parse_socket_addr("[2001:db8::1]:54", 53).unwrap(),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                54
            )
        );
        assert_eq!(parse_socket_addr("2001:db8::1", 53).unwrap().port(), 53);
        assert_eq!(
            parse_socket_addr("192.0.2.1:0", 53),
            Err(NetError::PortZero)
        );
        assert!(parse_socket_addr("example.com", 53).is_err());
    }

    #[test]
    fn upstream_forms() {
        let u = UpstreamUrl::parse("8.8.8.8").unwrap();
        assert_eq!((u.transport, u.port), (Transport::Udp, 53));
        let u = UpstreamUrl::parse("udp://192.0.2.1:5353").unwrap();
        assert_eq!((u.transport, u.port), (Transport::Udp, 5353));
        let u = UpstreamUrl::parse("tcp://[2001:db8::1]").unwrap();
        assert_eq!((u.transport, u.port), (Transport::Tcp, 53));
        let u = UpstreamUrl::parse("tls://dns.example").unwrap();
        assert_eq!((u.transport, u.port), (Transport::Tls, 853));
        assert!(matches!(u.host, UpstreamHost::Name(_)));
        let u = UpstreamUrl::parse("https://dns.example/dns-query").unwrap();
        assert_eq!((u.transport, u.port), (Transport::Https, 443));
        assert_eq!(u.path, "/dns-query");
        let u = UpstreamUrl::parse("https://dns.example:8443").unwrap();
        assert_eq!((u.port, u.path.as_str()), (8443, "/dns-query"));
        assert!(matches!(
            UpstreamUrl::parse("ftp://192.0.2.1"),
            Err(NetError::BadScheme(_))
        ));
        assert!(matches!(
            UpstreamUrl::parse("udp://dns.example"),
            Err(NetError::PlainHostName(_))
        ));
        assert_eq!(
            UpstreamUrl::parse("udp://192.0.2.1:0"),
            Err(NetError::PortZero)
        );
        assert!(UpstreamUrl::parse("tls://dns.example/path").is_err());
        assert!(UpstreamUrl::parse("https://user@dns.example/").is_err());
        assert!(UpstreamUrl::parse("https://").is_err());
    }

    proptest! {
        #[test]
        fn cidr_contains_own_address(a in any::<u32>(), p in 0u8..=32) {
            let c = Cidr::parse(&format!("{}/{p}", Ipv4Addr::from(a))).unwrap();
            prop_assert!(c.contains(IpAddr::V4(Ipv4Addr::from(a))));
        }

        #[test]
        fn cidr_v6_contains_own_address(a in any::<u128>(), p in 0u8..=128) {
            let c = Cidr::parse(&format!("{}/{p}", Ipv6Addr::from(a))).unwrap();
            prop_assert!(c.contains(IpAddr::V6(Ipv6Addr::from(a))));
        }

        #[test]
        fn parsers_never_panic(s in ".{0,80}") {
            let _ = Cidr::parse(&s);
            let _ = MacAddr::parse(&s);
            let _ = ClientId::parse(&s);
            let _ = parse_socket_addr(&s, 53);
            let _ = UpstreamUrl::parse(&s);
        }

        #[test]
        fn mac_display_parses_back(b in any::<[u8; 6]>()) {
            let m = MacAddr(b);
            prop_assert_eq!(MacAddr::parse(&m.to_string()).unwrap(), m);
        }
    }
}
