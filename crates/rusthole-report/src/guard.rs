//! The SSRF guard (docs/PLAN.md R-D10). The report connects only to public IPv4
//! addresses: never to the LAN, the host itself or a special range. Pure.

use std::net::Ipv4Addr;

/// True when `ip` is a public unicast address that the report can connect to.
pub fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let special = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        // 0.0.0.0/8 "this network".
        || a == 0
        // 100.64.0.0/10 shared address space (CGNAT).
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24 IETF protocol assignments.
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15 benchmarking.
        || (a == 198 && (b == 18 || b == 19))
        // 240.0.0.0/4 reserved.
        || a >= 240;
    !special
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)] // Tests: a failure is a test failure.
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn known_addresses() {
        for public in [
            "1.1.1.1",
            "8.8.8.8",
            "9.9.9.9",
            "20.42.65.92",
            "100.63.255.255",
            "100.128.0.1",
        ] {
            assert!(
                is_public_v4(public.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)),
                "{public}"
            );
        }
        for special in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.168.50.150",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                !is_public_v4(special.parse().unwrap_or(Ipv4Addr::LOCALHOST)),
                "{special}"
            );
        }
    }

    proptest! {
        /// No address of a private, loopback, link-local or CGNAT block is public.
        #[test]
        fn special_blocks_are_never_public(x in any::<u32>(), block in 0usize..6) {
            let (net, bits) = [
                (Ipv4Addr::new(10, 0, 0, 0), 8u32),
                (Ipv4Addr::new(127, 0, 0, 0), 8),
                (Ipv4Addr::new(172, 16, 0, 0), 12),
                (Ipv4Addr::new(192, 168, 0, 0), 16),
                (Ipv4Addr::new(169, 254, 0, 0), 16),
                (Ipv4Addr::new(100, 64, 0, 0), 10),
            ][block];
            let host = x & (u32::MAX >> bits);
            let ip = Ipv4Addr::from(u32::from(net) | host);
            prop_assert!(!is_public_v4(ip), "{}", ip);
        }
    }
}
