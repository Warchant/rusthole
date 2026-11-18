//! Local IPv4 interface addresses, behind a trait so that tests can give a fake list.

use std::fmt;
use std::io;
use std::net::IpAddr;

use parking_lot::Mutex;
use rusthole_core::acl::{InterfaceNet, netmask_to_prefix};

use crate::sync::LOCK_TIMEOUT;

/// A source of local interface addresses.
pub trait InterfaceSource: Send + Sync + fmt::Debug {
    /// The IPv4 addresses of the local interfaces, with the prefix length of each subnet.
    /// IPv6 addresses are left out (amendment A11).
    fn scan(&self) -> io::Result<Vec<InterfaceNet>>;
}

/// The real interfaces of the host (crate `if-addrs`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemInterfaces;

impl InterfaceSource for SystemInterfaces {
    fn scan(&self) -> io::Result<Vec<InterfaceNet>> {
        let mut out = Vec::new();
        for iface in if_addrs::get_if_addrs()? {
            let if_addrs::IfAddr::V4(v4) = &iface.addr else {
                continue;
            };
            let Some(prefix) = netmask_to_prefix(v4.netmask) else {
                tracing::warn!(
                    interface = %iface.name,
                    netmask = %v4.netmask,
                    "the netmask is not contiguous; the interface subnet is ignored"
                );
                continue;
            };
            let net = InterfaceNet {
                addr: v4.ip,
                prefix,
            };
            if !out.contains(&net) {
                out.push(net);
            }
        }
        out.sort();
        Ok(out)
    }
}

/// A fixed list that a test can change.
#[derive(Debug, Default)]
pub struct StaticInterfaces {
    nets: Mutex<Vec<InterfaceNet>>,
}

impl StaticInterfaces {
    /// Makes a list.
    pub fn new(nets: Vec<InterfaceNet>) -> Self {
        Self {
            nets: Mutex::new(nets),
        }
    }

    /// Replaces the list. The next scan returns it.
    pub fn set(&self, nets: Vec<InterfaceNet>) {
        if let Some(mut g) = self.nets.try_lock_for(LOCK_TIMEOUT) {
            *g = nets;
        }
    }
}

impl InterfaceSource for StaticInterfaces {
    fn scan(&self) -> io::Result<Vec<InterfaceNet>> {
        self.nets
            .try_lock_for(LOCK_TIMEOUT)
            .map(|g| g.clone())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "interface list lock timed out"))
    }
}

/// The listen addresses for `"auto"`: each IPv4 interface address, without duplicates.
pub fn listen_addrs(nets: &[InterfaceNet]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for n in nets {
        let ip = IpAddr::V4(n.addr);
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_list_changes() {
        let a = InterfaceNet {
            addr: "192.0.2.1".parse().unwrap(),
            prefix: 24,
        };
        let s = StaticInterfaces::new(vec![a]);
        assert_eq!(s.scan().unwrap(), vec![a]);
        s.set(vec![]);
        assert_eq!(s.scan().unwrap(), Vec::<InterfaceNet>::new());
    }

    #[test]
    fn listen_addrs_dedup() {
        let a = InterfaceNet {
            addr: "192.0.2.1".parse().unwrap(),
            prefix: 24,
        };
        let b = InterfaceNet {
            addr: "192.0.2.1".parse().unwrap(),
            prefix: 32,
        };
        assert_eq!(listen_addrs(&[a, b]).len(), 1);
    }

    #[test]
    fn system_scan_works() {
        // The host has at least a loopback interface on all CI systems.
        let nets = SystemInterfaces.scan().unwrap();
        assert!(nets.iter().all(|n| n.prefix <= 32));
    }
}
