//! Pure TLS policy: renewal, clock check, names, and the listener rule.
//!
//! The functions here do no I/O and read no clock. `now` is an input.
//!
//! Time in this module is wall-clock time in Unix seconds, not monotonic time. This is the
//! one exception to the monotonic-clock rule (ENGINEERING.md rule 6): a certificate holds its
//! validity as wall-clock dates, and a TLS peer checks it against its own wall clock. A
//! monotonic clock has no relation to those dates.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use rusthole_core::config::TlsMode;

use crate::error::TlsError;

/// One day in seconds.
pub const DAY: i64 = 86_400;
/// rusthole renews a certificate that it made when it has less than this time left.
pub const RENEW_BEFORE: i64 = 30 * DAY;
/// Validity of a self-signed certificate.
pub const SELF_SIGNED_VALIDITY: i64 = 365 * DAY;
/// Validity of a server certificate from the local CA. Apple devices refuse more than
/// 825 days for a TLS server certificate.
pub const LEAF_VALIDITY: i64 = 365 * DAY;
/// Validity of the local CA certificate.
pub const CA_VALIDITY: i64 = 3650 * DAY;
/// A new certificate starts this much before `now`, so that a client with a clock that is a
/// little slow accepts it.
pub const BACKDATE: i64 = 3600;
/// [`clock_plausible`] accepts a clock that is this much before the build time.
pub const CLOCK_MARGIN: i64 = 2 * DAY;

/// Tells if rusthole must make a new certificate.
///
/// The result is true if and only if `now >= not_after - 30 days` or `now < not_before`.
/// All arithmetic saturates, so extreme values do not overflow.
pub fn needs_renewal(not_before: i64, not_after: i64, now: i64) -> bool {
    now < not_before || now >= not_after.saturating_sub(RENEW_BEFORE)
}

/// Tells if the wall clock can be correct.
///
/// A device with no real-time clock (for example a Raspberry Pi) can start with a date in
/// 1970. Certificate checks fail with such a clock. The clock is plausible when `now_unix`
/// is not more than [`CLOCK_MARGIN`] before `build_time_unix`, the build time of the binary.
/// P7 uses this to select the plain DNS fallback (amendment A6).
pub fn clock_plausible(now_unix: i64, build_time_unix: i64) -> bool {
    now_unix >= build_time_unix.saturating_sub(CLOCK_MARGIN)
}

/// A listener that uses TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// The admin UI and REST API. It accepts all three modes.
    Admin,
    /// The DoH listener. It accepts mode `file` and mode `local-ca` only (amendment A6).
    Doh,
}

/// Checks that `listener` can use a certificate from `mode`.
pub fn check_listener_mode(listener: Listener, mode: TlsMode) -> Result<(), TlsError> {
    match (listener, mode) {
        (Listener::Doh, TlsMode::SelfSigned) => Err(TlsError::SelfSignedForDoh),
        _ => Ok(()),
    }
}

/// The subject alternative names (SANs) of a certificate: host names and IP addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SanSet {
    /// Host names in lowercase.
    pub names: BTreeSet<String>,
    /// IP addresses.
    pub ips: BTreeSet<IpAddr>,
}

impl SanSet {
    /// The names that rusthole wants in a certificate that it makes: `localhost`,
    /// `127.0.0.1`, the configured host names and the local IP addresses.
    pub fn wanted(names: &[String], local_ips: &[IpAddr]) -> Self {
        let mut set = Self::default();
        set.names.insert("localhost".to_owned());
        set.ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        set.names.extend(
            names
                .iter()
                .map(|n| n.trim_end_matches('.').to_ascii_lowercase()),
        );
        set.ips.extend(local_ips.iter().copied());
        set
    }

    /// Returns the part of this set that `scope` covers, and the names and addresses that it
    /// does not cover (as text).
    pub fn split_by(&self, scope: &CaScope) -> (SanSet, Vec<String>) {
        let mut covered = SanSet::default();
        let mut uncovered = Vec::new();
        for n in &self.names {
            if scope.covers_name(n) {
                covered.names.insert(n.clone());
            } else {
                uncovered.push(n.clone());
            }
        }
        for ip in &self.ips {
            if scope.covers_ip(*ip) {
                covered.ips.insert(*ip);
            } else {
                uncovered.push(ip.to_string());
            }
        }
        (covered, uncovered)
    }
}

/// An IPv4 network: an address and a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Net4 {
    /// The network address.
    pub addr: Ipv4Addr,
    /// The prefix length, 0 to 32.
    pub prefix: u8,
}

impl Net4 {
    /// Tells if `ip` is in this network.
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = u32::MAX
            .checked_shl(32 - u32::from(self.prefix.min(32)))
            .unwrap_or(0);
        u32::from(ip) & mask == u32::from(self.addr) & mask
    }
}

/// Private and local IPv4 networks. The local CA permits these, so that a new DHCP address
/// in the LAN needs no new CA.
pub const PRIVATE_NETS: [Net4; 6] = [
    Net4 {
        addr: Ipv4Addr::new(10, 0, 0, 0),
        prefix: 8,
    },
    Net4 {
        addr: Ipv4Addr::new(172, 16, 0, 0),
        prefix: 12,
    },
    Net4 {
        addr: Ipv4Addr::new(192, 168, 0, 0),
        prefix: 16,
    },
    Net4 {
        addr: Ipv4Addr::new(127, 0, 0, 0),
        prefix: 8,
    },
    Net4 {
        addr: Ipv4Addr::new(169, 254, 0, 0),
        prefix: 16,
    },
    // Shared address space (RFC 6598). VPNs use it.
    Net4 {
        addr: Ipv4Addr::new(100, 64, 0, 0),
        prefix: 10,
    },
];

/// The names that a local CA can sign: its name constraints (RFC 5280, 4.2.1.10).
///
/// A device that trusts the CA accepts a certificate from it only for these names. Thus a
/// stolen CA key cannot sign a certificate for a public site that the device accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaScope {
    /// Permitted DNS subtrees. A name matches a subtree when it is equal to it or ends with
    /// `.` and the subtree. `None` means that DNS names are not constrained.
    pub dns: Option<BTreeSet<String>>,
    /// Permitted IPv4 networks. `None` means that IP addresses are not constrained.
    pub ipv4: Option<BTreeSet<Net4>>,
}

impl CaScope {
    /// The scope of a new local CA: `localhost` and the configured names, the private
    /// networks, and each local address that is not in a private network (as a /32).
    pub fn for_new_ca(wanted: &SanSet) -> Self {
        let dns = wanted.names.iter().cloned().collect();
        let mut ipv4: BTreeSet<Net4> = PRIVATE_NETS.into_iter().collect();
        for ip in &wanted.ips {
            if let IpAddr::V4(v4) = ip
                && !PRIVATE_NETS.iter().any(|n| n.contains(*v4))
            {
                ipv4.insert(Net4 {
                    addr: *v4,
                    prefix: 32,
                });
            }
        }
        Self {
            dns: Some(dns),
            ipv4: Some(ipv4),
        }
    }

    /// Tells if the scope covers the host name `name` (lowercase).
    pub fn covers_name(&self, name: &str) -> bool {
        let Some(dns) = &self.dns else {
            return true;
        };
        dns.iter().any(|base| {
            name == base
                || name
                    .strip_suffix(base.as_str())
                    .is_some_and(|head| head.ends_with('.'))
        })
    }

    /// Tells if the scope covers `ip`. v1 makes no IPv6 constraint, so a CA with IPv4
    /// constraints does not cover an IPv6 address (amendment A11).
    pub fn covers_ip(&self, ip: IpAddr) -> bool {
        let Some(nets) = &self.ipv4 else {
            return true;
        };
        match ip {
            IpAddr::V4(v4) => nets.iter().any(|n| n.contains(v4)),
            IpAddr::V6(_) => false,
        }
    }
}

/// What rusthole knows about a certificate that it made earlier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertDates {
    /// Start of validity, Unix seconds.
    pub not_before: i64,
    /// End of validity, Unix seconds.
    pub not_after: i64,
}

/// Why rusthole makes a new certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No certificate exists.
    Missing,
    /// The files exist but cannot be used (bad PEM, the key does not match, another issuer).
    Unusable,
    /// The certificate expires in less than 30 days, or it expired.
    Expiring,
    /// The certificate is not valid yet: its start is after `now`.
    NotYetValid,
    /// The names in the certificate are not the names that rusthole wants.
    NamesChanged,
}

/// The decision for a certificate that rusthole makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Use the existing certificate.
    Reuse,
    /// Make a new certificate.
    Generate(Reason),
}

/// Decides if rusthole keeps a generated certificate or makes a new one.
///
/// - `existing` is `None` when no usable certificate exists, with the reason.
/// - `clock_ok` is the result of [`clock_plausible`]. With a clock that is not plausible,
///   rusthole keeps a usable certificate: a new one would have wrong dates.
pub fn plan_cert(
    existing: Result<(&CertDates, &SanSet), Reason>,
    wanted: &SanSet,
    now: i64,
    clock_ok: bool,
) -> Plan {
    let (dates, sans) = match existing {
        Err(reason) => return Plan::Generate(reason),
        Ok(v) => v,
    };
    if sans != wanted {
        return Plan::Generate(Reason::NamesChanged);
    }
    if !clock_ok {
        return Plan::Reuse;
    }
    if now < dates.not_before {
        return Plan::Generate(Reason::NotYetValid);
    }
    if needs_renewal(dates.not_before, dates.not_after, now) {
        return Plan::Generate(Reason::Expiring);
    }
    Plan::Reuse
}

/// Tells if a certificate expired at `now`.
pub fn is_expired(not_after: i64, now: i64) -> bool {
    now > not_after
}

/// Tells if a CA expires in less than 30 days. rusthole never replaces a CA by itself; it
/// only warns.
pub fn ca_expires_soon(not_after: i64, now: i64) -> bool {
    now >= not_after.saturating_sub(RENEW_BEFORE)
}

/// The validity of a new certificate: from `now - BACKDATE` for `validity` seconds.
pub fn new_validity(now: i64, validity: i64) -> CertDates {
    let not_before = now.saturating_sub(BACKDATE);
    CertDates {
        not_before,
        not_after: now.saturating_add(validity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sans(names: &[&str], ips: &[[u8; 4]]) -> SanSet {
        SanSet {
            names: names.iter().map(|s| (*s).to_owned()).collect(),
            ips: ips.iter().map(|b| IpAddr::from(*b)).collect(),
        }
    }

    /// The window is 30 days (the spec). The literal value here does not come from the code.
    const THIRTY_DAYS: i64 = 2_592_000;

    #[test]
    fn renewal_window_edges() {
        assert!(needs_renewal(0, 400 * 86_400, 400 * 86_400 - THIRTY_DAYS));
        assert!(!needs_renewal(
            0,
            400 * 86_400,
            400 * 86_400 - THIRTY_DAYS - 1
        ));
        let nb = 1_000_000;
        let na = nb + 365 * DAY;
        assert!(!needs_renewal(nb, na, nb));
        assert!(needs_renewal(nb, na, nb - 1));
        assert!(!needs_renewal(nb, na, na - RENEW_BEFORE - 1));
        assert!(needs_renewal(nb, na, na - RENEW_BEFORE));
        assert!(needs_renewal(nb, na, na + 1));
        assert!(needs_renewal(i64::MIN, i64::MIN, 0));
        assert!(!needs_renewal(i64::MIN, i64::MAX, 0));
    }

    #[test]
    fn clock_check() {
        let build = 1_793_491_200;
        assert!(clock_plausible(build, build));
        assert!(clock_plausible(build - CLOCK_MARGIN, build));
        assert!(!clock_plausible(build - CLOCK_MARGIN - 1, build));
        assert!(!clock_plausible(0, build));
        assert!(clock_plausible(i64::MIN, i64::MIN));
        assert!(clock_plausible(i64::MAX, i64::MAX));
    }

    #[test]
    fn doh_refuses_self_signed() {
        assert!(matches!(
            check_listener_mode(Listener::Doh, TlsMode::SelfSigned),
            Err(TlsError::SelfSignedForDoh)
        ));
        assert!(check_listener_mode(Listener::Doh, TlsMode::File).is_ok());
        assert!(check_listener_mode(Listener::Doh, TlsMode::LocalCa).is_ok());
        for mode in [TlsMode::File, TlsMode::SelfSigned, TlsMode::LocalCa] {
            assert!(check_listener_mode(Listener::Admin, mode).is_ok());
        }
    }

    #[test]
    fn wanted_adds_loopback_and_normalizes() {
        let s = SanSet::wanted(&["Pi.LAN.".into()], &[IpAddr::from([192, 0, 2, 7])]);
        assert_eq!(
            s,
            sans(&["localhost", "pi.lan"], &[[127, 0, 0, 1], [192, 0, 2, 7]])
        );
    }

    #[test]
    fn scope_of_new_ca() {
        let wanted = SanSet::wanted(
            &["rusthole.lan".into()],
            &[IpAddr::from([192, 168, 1, 2]), IpAddr::from([192, 0, 2, 7])],
        );
        let scope = CaScope::for_new_ca(&wanted);
        assert!(scope.covers_name("rusthole.lan"));
        assert!(scope.covers_name("www.rusthole.lan"));
        assert!(scope.covers_name("localhost"));
        assert!(!scope.covers_name("xrusthole.lan"));
        assert!(!scope.covers_name("example.com"));
        assert!(scope.covers_ip(IpAddr::from([192, 168, 7, 7])));
        assert!(scope.covers_ip(IpAddr::from([10, 1, 2, 3])));
        assert!(scope.covers_ip(IpAddr::from([192, 0, 2, 7])));
        assert!(!scope.covers_ip(IpAddr::from([192, 0, 2, 8])));
        assert!(!scope.covers_ip("2001:db8::1".parse().unwrap()));
        let (covered, uncovered) = wanted.split_by(&scope);
        assert_eq!(covered, wanted);
        assert_eq!(uncovered, Vec::<String>::new());
        let more = SanSet::wanted(
            &["rusthole.lan".into(), "new.example".into()],
            &[IpAddr::from([198, 51, 100, 1])],
        );
        let (covered, uncovered) = more.split_by(&scope);
        assert_eq!(
            covered,
            sans(&["localhost", "rusthole.lan"], &[[127, 0, 0, 1]])
        );
        assert_eq!(uncovered, ["new.example", "198.51.100.1"]);
        // No constraints: everything is covered.
        assert!(CaScope::default().covers_name("example.com"));
        assert!(CaScope::default().covers_ip("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn net_contains() {
        let n = Net4 {
            addr: Ipv4Addr::new(172, 16, 0, 0),
            prefix: 12,
        };
        assert!(n.contains(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!n.contains(Ipv4Addr::new(172, 32, 0, 0)));
        let all = Net4 {
            addr: Ipv4Addr::UNSPECIFIED,
            prefix: 0,
        };
        assert!(all.contains(Ipv4Addr::BROADCAST));
        let host = Net4 {
            addr: Ipv4Addr::new(192, 0, 2, 1),
            prefix: 32,
        };
        assert!(host.contains(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!host.contains(Ipv4Addr::new(192, 0, 2, 2)));
    }

    #[test]
    fn plan_decisions() {
        let wanted = sans(&["localhost"], &[[127, 0, 0, 1]]);
        let dates = new_validity(10_000_000, SELF_SIGNED_VALIDITY);
        let now = 10_000_000;
        assert_eq!(
            plan_cert(Err(Reason::Missing), &wanted, now, true),
            Plan::Generate(Reason::Missing)
        );
        assert_eq!(
            plan_cert(Ok((&dates, &wanted)), &wanted, now, true),
            Plan::Reuse
        );
        let other = sans(&["localhost", "pi.lan"], &[[127, 0, 0, 1]]);
        assert_eq!(
            plan_cert(Ok((&dates, &other)), &wanted, now, true),
            Plan::Generate(Reason::NamesChanged)
        );
        let late = dates.not_after - RENEW_BEFORE;
        assert_eq!(
            plan_cert(Ok((&dates, &wanted)), &wanted, late, true),
            Plan::Generate(Reason::Expiring)
        );
        assert_eq!(
            plan_cert(Ok((&dates, &wanted)), &wanted, late - 1, true),
            Plan::Reuse
        );
        assert_eq!(
            plan_cert(Ok((&dates, &wanted)), &wanted, 0, true),
            Plan::Generate(Reason::NotYetValid)
        );
        // A wrong clock keeps a usable certificate.
        assert_eq!(
            plan_cert(Ok((&dates, &wanted)), &wanted, 0, false),
            Plan::Reuse
        );
        assert_eq!(
            plan_cert(Ok((&dates, &wanted)), &wanted, i64::MAX, false),
            Plan::Reuse
        );
    }

    #[test]
    fn ca_and_expiry_helpers() {
        assert!(!is_expired(100, 100));
        assert!(is_expired(100, 101));
        assert!(ca_expires_soon(100 + RENEW_BEFORE, 100));
        assert!(!ca_expires_soon(101 + RENEW_BEFORE, 100));
        let v = new_validity(i64::MAX, CA_VALIDITY);
        assert_eq!(v.not_after, i64::MAX);
        let v = new_validity(i64::MIN, CA_VALIDITY);
        assert_eq!(v.not_before, i64::MIN);
    }

    proptest! {
        /// The oracle uses i128, so it does not copy the saturating i64 code.
        #[test]
        fn needs_renewal_matches_the_rule(nb in any::<i64>(), na in any::<i64>(), now in any::<i64>()) {
            let expected = i128::from(now) >= i128::from(na) - i128::from(THIRTY_DAYS)
                || now < nb;
            prop_assert_eq!(needs_renewal(nb, na, now), expected);
        }

        #[test]
        fn needs_renewal_near_edges(
            nb in -10_000i64..10_000,
            len in 0i64..(400 * DAY),
            off in -(40 * DAY)..(40 * DAY),
        ) {
            let na = nb + len;
            let now = na - THIRTY_DAYS + off;
            let expected = i128::from(now) >= i128::from(na) - i128::from(THIRTY_DAYS)
                || now < nb;
            prop_assert_eq!(needs_renewal(nb, na, now), expected);
        }

        #[test]
        fn clock_plausible_matches_the_rule(now in any::<i64>(), build in any::<i64>()) {
            let expected = i128::from(now) >= i128::from(build) - i128::from(CLOCK_MARGIN);
            prop_assert_eq!(clock_plausible(now, build), expected);
        }
    }
}
