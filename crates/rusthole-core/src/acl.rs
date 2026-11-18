//! Client access control list (decision D7, amendments A8 and A11).
//!
//! The ACL is a list of IPv4 networks. A client is allowed when its address is in one of
//! them. With `acl.auto_local`, the list holds the loopback network and the subnet of each
//! local IPv4 interface. `acl.allow` adds more networks.
//!
//! This module is pure. The DNS crate reads the interfaces and calls [`Acl::build`] again
//! after each interface scan.

use std::net::{IpAddr, Ipv4Addr};

use crate::net::Cidr;

/// The loopback network `127.0.0.0/8`.
pub const LOOPBACK: Cidr = Cidr {
    addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
    prefix: 8,
};

/// One IPv4 address of a local interface, with the prefix length of its subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InterfaceNet {
    /// The interface address.
    pub addr: Ipv4Addr,
    /// The prefix length of the subnet, 0..=32.
    pub prefix: u8,
}

impl InterfaceNet {
    /// The subnet of the interface as a CIDR block, with the host bits set to zero.
    /// A prefix longer than 32 is treated as 32.
    pub fn subnet(&self) -> Cidr {
        let prefix = self.prefix.min(32);
        let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::from(u32::from(self.addr) & mask)),
            prefix,
        }
    }
}

/// Changes a netmask (for example `255.255.255.0`) to a prefix length.
/// Returns `None` when the mask is not contiguous (for example `255.0.255.0`).
pub fn netmask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    // A contiguous mask has only ones, then only zeros.
    if bits.checked_shl(ones).unwrap_or(0) != 0 {
        return None;
    }
    u8::try_from(ones).ok()
}

/// The allowed client networks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Acl {
    nets: Vec<Cidr>,
}

impl Acl {
    /// Makes the ACL.
    ///
    /// With `auto_local`, the ACL holds [`LOOPBACK`] and the subnet of each interface in
    /// `interfaces`. It always holds each network in `allow`. The function removes
    /// duplicates. An IPv6 network in `allow` stays in the list but never matches an IPv4
    /// client (v1 uses IPv4 only; config validation refuses IPv6).
    pub fn build(auto_local: bool, interfaces: &[InterfaceNet], allow: &[Cidr]) -> Self {
        let mut nets = Vec::with_capacity(interfaces.len() + allow.len() + 1);
        if auto_local {
            nets.push(LOOPBACK);
            nets.extend(interfaces.iter().map(InterfaceNet::subnet));
        }
        nets.extend(allow.iter().copied());
        let mut out: Vec<Cidr> = Vec::with_capacity(nets.len());
        for n in nets {
            if !out.contains(&n) {
                out.push(n);
            }
        }
        Self { nets: out }
    }

    /// True when `ip` is in one of the allowed networks.
    ///
    /// v1 uses IPv4 transport only (amendment A11). An IPv4-mapped IPv6 address
    /// (`::ffff:192.0.2.1`) is checked as its IPv4 address. Another IPv6 address matches
    /// only an IPv6 network.
    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        self.nets.iter().any(|n| n.contains(ip))
    }

    /// The allowed networks.
    pub fn networks(&self) -> &[Cidr] {
        &self.nets
    }
}

/// True when the IPv4 network is in a private or local range: RFC 1918 (`10/8`,
/// `172.16/12`, `192.168/16`), CGNAT (`100.64/10`), link-local (`169.254/16`) or loopback
/// (`127/8`). The full network must be in the range: `10.0.0.0/7` is not private.
pub fn is_private_v4(net: &Cidr) -> bool {
    const PRIVATE: [(Ipv4Addr, u8); 6] = [
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(127, 0, 0, 0), 8),
    ];
    let IpAddr::V4(_) = net.addr else {
        return false;
    };
    PRIVATE.iter().any(|(addr, prefix)| {
        let range = Cidr {
            addr: IpAddr::V4(*addr),
            prefix: *prefix,
        };
        net.prefix >= *prefix && range.contains(net.addr)
    })
}

/// The interface subnets that are not private (see [`is_private_v4`]). The DNS crate logs a
/// warning once for each of them (amendment A8): with `auto_local`, rusthole then answers
/// clients from a public network.
pub fn public_subnets(interfaces: &[InterfaceNet]) -> Vec<Cidr> {
    let mut out: Vec<Cidr> = Vec::new();
    for net in interfaces.iter().map(InterfaceNet::subnet) {
        if !is_private_v4(&net) && !out.contains(&net) {
            out.push(net);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn iface(a: &str, prefix: u8) -> InterfaceNet {
        InterfaceNet {
            addr: a.parse().unwrap(),
            prefix,
        }
    }

    #[test]
    fn auto_local_allows_loopback_and_interface_subnets() {
        let acl = Acl::build(true, &[iface("192.0.2.10", 24)], &[]);
        assert!(acl.allows(v4("127.0.0.1")));
        assert!(acl.allows(v4("127.255.0.9")));
        assert!(acl.allows(v4("192.0.2.1")));
        assert!(acl.allows(v4("192.0.2.255")));
        assert!(!acl.allows(v4("192.0.3.1")));
        assert!(!acl.allows(v4("198.51.100.7")));
    }

    #[test]
    fn subnet_edges() {
        let acl = Acl::build(true, &[iface("192.0.2.130", 25)], &[]);
        assert!(acl.allows(v4("192.0.2.128")));
        assert!(acl.allows(v4("192.0.2.255")));
        assert!(!acl.allows(v4("192.0.2.127")));
    }

    #[test]
    fn without_auto_local_only_allow_list() {
        let allow = [Cidr::parse("198.51.100.0/24").unwrap()];
        let acl = Acl::build(false, &[iface("192.0.2.10", 24)], &allow);
        assert!(!acl.allows(v4("127.0.0.1")));
        assert!(!acl.allows(v4("192.0.2.1")));
        assert!(acl.allows(v4("198.51.100.200")));
    }

    #[test]
    fn empty_acl_allows_nothing() {
        let acl = Acl::build(false, &[], &[]);
        assert!(!acl.allows(v4("127.0.0.1")));
        assert_eq!(acl.networks(), &[] as &[Cidr]);
    }

    #[test]
    fn mapped_ipv6_is_checked_as_ipv4() {
        let acl = Acl::build(true, &[], &[]);
        assert!(acl.allows(v4("::ffff:127.0.0.1")));
        assert!(!acl.allows(v4("::1")));
        assert!(!acl.allows(v4("2001:db8::1")));
    }

    #[test]
    fn duplicates_are_removed() {
        let acl = Acl::build(
            true,
            &[iface("192.0.2.10", 24), iface("192.0.2.11", 24)],
            &[Cidr::parse("192.0.2.0/24").unwrap()],
        );
        assert_eq!(acl.networks().len(), 2);
    }

    #[test]
    fn netmask_prefix() {
        assert_eq!(
            netmask_to_prefix("255.255.255.0".parse().unwrap()),
            Some(24)
        );
        assert_eq!(
            netmask_to_prefix("255.255.255.255".parse().unwrap()),
            Some(32)
        );
        assert_eq!(netmask_to_prefix("0.0.0.0".parse().unwrap()), Some(0));
        assert_eq!(
            netmask_to_prefix("255.255.128.0".parse().unwrap()),
            Some(17)
        );
        assert_eq!(netmask_to_prefix("255.0.255.0".parse().unwrap()), None);
        assert_eq!(netmask_to_prefix("0.255.255.255".parse().unwrap()), None);
    }

    #[test]
    fn private_ranges() {
        for p in [
            "10.1.2.0/24",
            "172.16.0.0/12",
            "172.31.255.0/24",
            "192.168.1.0/24",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "127.0.0.0/8",
        ] {
            assert!(is_private_v4(&Cidr::parse(p).unwrap()), "{p}");
        }
        for p in [
            "192.0.2.0/24",
            "172.32.0.0/16",
            "10.0.0.0/7",
            "100.128.0.0/16",
            "8.8.8.0/24",
        ] {
            assert!(!is_private_v4(&Cidr::parse(p).unwrap()), "{p}");
        }
        assert!(!is_private_v4(&Cidr::parse("2001:db8::/32").unwrap()));
    }

    #[test]
    fn public_subnets_are_listed_once() {
        let ifs = [
            iface("192.168.1.2", 24),
            iface("192.0.2.10", 24),
            iface("192.0.2.11", 24),
        ];
        let public = public_subnets(&ifs);
        assert_eq!(public, vec![Cidr::parse("192.0.2.0/24").unwrap()]);
    }

    /// The containment check written another way: compare the top `prefix` bits.
    fn in_net(ip: u32, net: u32, prefix: u8) -> bool {
        if prefix == 0 {
            return true;
        }
        (ip >> (32 - u32::from(prefix))) == (net >> (32 - u32::from(prefix)))
    }

    proptest! {
        /// The ACL decision equals CIDR containment for any address (an independent model).
        #[test]
        fn allow_equals_containment(
            ip in any::<u32>(),
            auto in any::<bool>(),
            ifaces in proptest::collection::vec((any::<u32>(), 0u8..=32), 0..6),
            allow in proptest::collection::vec((any::<u32>(), 0u8..=32), 0..6),
        ) {
            let ifs: Vec<InterfaceNet> = ifaces
                .iter()
                .map(|(a, p)| InterfaceNet { addr: Ipv4Addr::from(*a), prefix: *p })
                .collect();
            let allow_c: Vec<Cidr> = allow
                .iter()
                .map(|(a, p)| Cidr { addr: IpAddr::V4(Ipv4Addr::from(*a)), prefix: *p })
                .collect();
            let acl = Acl::build(auto, &ifs, &allow_c);
            let mut expected = allow.iter().any(|(n, p)| in_net(ip, *n, *p));
            if auto {
                expected |= in_net(ip, 0x7f00_0000, 8);
                expected |= ifaces.iter().any(|(n, p)| in_net(ip, *n, *p));
            }
            prop_assert_eq!(acl.allows(IpAddr::V4(Ipv4Addr::from(ip))), expected);
        }
    }
}
