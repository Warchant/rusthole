//! The kernel neighbor table: the MAC address of each IPv4 client (amendments A10, A11).
//!
//! On Linux, [`SystemNeighbors`] reads `/proc/net/arp` (IPv4 only, no netlink in v1). On
//! other systems it gives an empty table. A background task reads the source on a period
//! and stores a snapshot in a [`NeighborTable`]. The query path reads the latest snapshot
//! (no lock, no file read).
//!
//! ```mermaid
//! flowchart LR
//!     src[NeighborSource<br/>/proc/net/arp] -->|each 30 s, time limit| task[refresh task]
//!     task -->|swap| snap[NeighborTable<br/>snapshot]
//!     q[query path] -->|load| snap
//! ```

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rusthole_core::net::MacAddr;
use tokio_util::sync::CancellationToken;

use crate::sync::LOCK_TIMEOUT;

/// Entries in one snapshot, at most. More entries are dropped.
pub const MAX_NEIGHBORS: usize = 4096;
/// Bytes of `/proc/net/arp` that rusthole reads, at most.
pub const MAX_ARP_BYTES: usize = 1024 * 1024;
/// Default period of the neighbor table refresh.
pub const NEIGHBOR_REFRESH: Duration = Duration::from_secs(30);
/// Time limit for one read of the neighbor source.
pub const NEIGHBOR_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// The `ATF_COM` flag: the entry is complete (it has a MAC address).
const ATF_COM: u32 = 0x2;

/// One snapshot of the neighbor table.
pub type NeighborSnapshot = HashMap<Ipv4Addr, MacAddr>;

/// Parses the text of `/proc/net/arp`:
///
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.0.2.7        0x1         0x2         02:00:00:00:00:01     *        eth0
/// ```
///
/// The function skips the header, lines that do not parse, incomplete entries (no
/// `ATF_COM` flag) and the all-zero MAC address. It reads at most [`MAX_ARP_BYTES`] bytes
/// and keeps at most [`MAX_NEIGHBORS`] entries. When an address comes twice, the first entry
/// wins. It never panics.
pub fn parse_arp(bytes: &[u8]) -> NeighborSnapshot {
    let data = bytes.get(..MAX_ARP_BYTES).unwrap_or(bytes);
    let mut out = NeighborSnapshot::new();
    // Bounded by the number of lines in `data`.
    for line in data.split(|b| *b == b'\n') {
        if out.len() >= MAX_NEIGHBORS {
            break;
        }
        let Some((ip, mac)) = parse_line(line) else {
            continue;
        };
        out.entry(ip).or_insert(mac);
    }
    out
}

fn parse_line(line: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    let text = std::str::from_utf8(line).ok()?;
    let mut fields = text.split_ascii_whitespace();
    let ip: Ipv4Addr = fields.next()?.parse().ok()?;
    let _hw_type = fields.next()?;
    let flags = parse_hex(fields.next()?)?;
    if flags & ATF_COM == 0 {
        return None;
    }
    let mac = MacAddr::parse(fields.next()?).ok()?;
    if mac.0 == [0; 6] {
        return None;
    }
    Some((ip, mac))
}

fn parse_hex(text: &str) -> Option<u32> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    if digits.is_empty() || digits.len() > 8 {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

/// A source of neighbor table snapshots. Tests use [`StaticNeighbors`].
pub trait NeighborSource: Send + Sync + fmt::Debug {
    /// Reads one snapshot. It must be fast: the refresh task calls it on a blocking thread
    /// with a time limit.
    fn read(&self) -> io::Result<NeighborSnapshot>;
}

/// The neighbor table of the host: `/proc/net/arp` on Linux, an empty table on other systems.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNeighbors;

impl NeighborSource for SystemNeighbors {
    #[cfg(target_os = "linux")]
    fn read(&self) -> io::Result<NeighborSnapshot> {
        use std::io::Read;
        let file = std::fs::File::open("/proc/net/arp")?;
        let mut buf = Vec::new();
        file.take(u64::try_from(MAX_ARP_BYTES).unwrap_or(u64::MAX))
            .read_to_end(&mut buf)?;
        Ok(parse_arp(&buf))
    }

    #[cfg(not(target_os = "linux"))]
    fn read(&self) -> io::Result<NeighborSnapshot> {
        Ok(NeighborSnapshot::new())
    }
}

/// A fixed table that a test can change.
#[derive(Debug, Default)]
pub struct StaticNeighbors {
    map: Mutex<NeighborSnapshot>,
}

impl StaticNeighbors {
    /// Makes a table.
    pub fn new(map: NeighborSnapshot) -> Self {
        Self {
            map: Mutex::new(map),
        }
    }

    /// Replaces the table. The next read returns it.
    pub fn set(&self, map: NeighborSnapshot) {
        if let Some(mut g) = self.map.try_lock_for(LOCK_TIMEOUT) {
            *g = map;
        }
    }
}

impl NeighborSource for StaticNeighbors {
    fn read(&self) -> io::Result<NeighborSnapshot> {
        self.map
            .try_lock_for(LOCK_TIMEOUT)
            .map(|g| g.clone())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "neighbor table lock timed out"))
    }
}

/// The latest neighbor snapshot. Reads take no lock.
#[derive(Debug, Default)]
pub struct NeighborTable {
    snap: ArcSwap<NeighborSnapshot>,
}

impl NeighborTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// The MAC address of an IPv4 address, if the table has it.
    pub fn get(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.snap.load().get(&ip).copied()
    }

    /// The MAC address of a client address. IPv6 gives `None` (amendment A11).
    pub fn get_ip(&self, ip: IpAddr) -> Option<MacAddr> {
        match ip {
            IpAddr::V4(v4) => self.get(v4),
            IpAddr::V6(_) => None,
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.snap.load().len()
    }

    /// True when the table is empty.
    pub fn is_empty(&self) -> bool {
        self.snap.load().is_empty()
    }

    /// Replaces the snapshot. A snapshot with more than [`MAX_NEIGHBORS`] entries keeps only
    /// that many.
    pub fn replace(&self, snap: NeighborSnapshot) {
        let snap = if snap.len() > MAX_NEIGHBORS {
            tracing::warn!(
                entries = snap.len(),
                max = MAX_NEIGHBORS,
                "the neighbor table is too large; entries are dropped"
            );
            snap.into_iter().take(MAX_NEIGHBORS).collect()
        } else {
            snap
        };
        self.snap.store(Arc::new(snap));
    }

    /// Reads `source` once on this thread and stores the snapshot. On an error the old
    /// snapshot stays.
    pub fn refresh_now(&self, source: &dyn NeighborSource) -> io::Result<usize> {
        let snap = source.read()?;
        let n = snap.len();
        self.replace(snap);
        Ok(n)
    }
}

/// Reads `source` each `period` on a blocking thread (time limit
/// [`NEIGHBOR_READ_TIMEOUT`]) and stores each snapshot in `table`.
///
/// Service loop: unbounded on purpose. It runs for the life of the server and ends when
/// `cancel` is cancelled.
pub(crate) async fn refresh_loop(
    source: Arc<dyn NeighborSource>,
    table: Arc<NeighborTable>,
    period: Duration,
    cancel: CancellationToken,
) {
    let mut tick = tokio::time::interval(period.max(Duration::from_millis(10)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failing = false;
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = tick.tick() => {}
        }
        let src = Arc::clone(&source);
        let read = tokio::time::timeout(
            NEIGHBOR_READ_TIMEOUT,
            tokio::task::spawn_blocking(move || src.read()),
        )
        .await;
        let error = match read {
            Ok(Ok(Ok(snap))) => {
                table.replace(snap);
                if failing {
                    tracing::info!("the neighbor table can be read again");
                }
                failing = false;
                continue;
            }
            Ok(Ok(Err(e))) => e.to_string(),
            Ok(Err(e)) => format!("the read task failed: {e}"),
            Err(_) => "the read timed out".to_owned(),
        };
        // Log the first failure only, so a lasting failure does not fill the log.
        if !failing {
            tracing::warn!(
                error,
                "cannot read the neighbor table; the old snapshot stays"
            );
        }
        failing = true;
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    const SAMPLE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.0.2.7        0x1         0x2         02:00:00:00:00:01     *        eth0
192.0.2.8        0x1         0x0         00:00:00:00:00:00     *        eth0
192.0.2.9        0x1         0x6         02:00:00:00:00:02     *        eth0
192.0.2.10       0x1         0x2         00:00:00:00:00:00     *        eth0
192.0.2.7        0x1         0x2         02:00:00:00:00:03     *        eth1
bad line
192.0.2.11 0x1 zz 02:00:00:00:00:04 * eth0
192.0.2.12 0x1 0x2 02:00:00:00:00
";

    fn mac(s: &str) -> MacAddr {
        MacAddr::parse(s).unwrap()
    }

    #[test]
    fn parses_complete_entries_only() {
        let t = parse_arp(SAMPLE.as_bytes());
        assert_eq!(t.len(), 2, "{t:?}");
        assert_eq!(t[&"192.0.2.7".parse().unwrap()], mac("02:00:00:00:00:01"));
        assert_eq!(t[&"192.0.2.9".parse().unwrap()], mac("02:00:00:00:00:02"));
        assert!(parse_arp(b"").is_empty());
        assert!(parse_arp(&[0xff, 0xfe, b'\n', 0]).is_empty());
        // CRLF line ends work too.
        let crlf = "192.0.2.7 0x1 0x2 02:00:00:00:00:01 * eth0\r\n";
        assert_eq!(parse_arp(crlf.as_bytes()).len(), 1);
    }

    #[test]
    fn snapshot_size_is_bounded() {
        let mut text = String::new();
        for i in 0..(MAX_NEIGHBORS + 100) {
            let [_, _, a, b] = u32::try_from(i).unwrap().to_be_bytes();
            let _ = writeln!(
                text,
                "10.0.{a}.{b} 0x1 0x2 02:00:00:00:{a:02x}:{b:02x} * eth0"
            );
        }
        assert_eq!(parse_arp(text.as_bytes()).len(), MAX_NEIGHBORS);
        // A source with too many entries is cut at the table.
        let big: NeighborSnapshot = (0..(MAX_NEIGHBORS + 5))
            .map(|i| {
                let [_, _, a, b] = u32::try_from(i).unwrap().to_be_bytes();
                (Ipv4Addr::new(10, 1, a, b), MacAddr([2, 0, 0, 0, a, b]))
            })
            .collect();
        let table = NeighborTable::new();
        table.replace(big);
        assert_eq!(table.len(), MAX_NEIGHBORS);
    }

    #[test]
    fn only_the_first_bytes_are_read() {
        let mut text = "x".repeat(MAX_ARP_BYTES);
        text.push_str("\n192.0.2.7 0x1 0x2 02:00:00:00:00:01 * eth0\n");
        assert!(parse_arp(text.as_bytes()).is_empty());
    }

    #[test]
    fn table_lookup_and_refresh() {
        let src = StaticNeighbors::new(parse_arp(SAMPLE.as_bytes()));
        let table = NeighborTable::new();
        assert!(table.is_empty());
        assert_eq!(table.refresh_now(&src).unwrap(), 2);
        assert_eq!(
            table.get_ip("192.0.2.7".parse().unwrap()),
            Some(mac("02:00:00:00:00:01"))
        );
        assert_eq!(table.get_ip("2001:db8::7".parse().unwrap()), None);
        src.set(NeighborSnapshot::new());
        table.refresh_now(&src).unwrap();
        assert_eq!(table.get("192.0.2.7".parse().unwrap()), None);
    }

    #[derive(Debug)]
    struct Failing;

    impl NeighborSource for Failing {
        fn read(&self) -> io::Result<NeighborSnapshot> {
            Err(io::Error::other("no table"))
        }
    }

    #[tokio::test]
    async fn refresh_loop_updates_and_stops() {
        let src = Arc::new(StaticNeighbors::default());
        let table = Arc::new(NeighborTable::new());
        let cancel = CancellationToken::new();
        let task = tokio::spawn(refresh_loop(
            src.clone(),
            Arc::clone(&table),
            Duration::from_millis(20),
            cancel.clone(),
        ));
        src.set(parse_arp(SAMPLE.as_bytes()));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while table.len() != 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the table was not refreshed"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // A failing source keeps the old snapshot.
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(refresh_loop(
            Arc::new(Failing),
            Arc::clone(&table),
            Duration::from_millis(10),
            cancel.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(table.len(), 2);
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_table_reads_on_linux() {
        let t = SystemNeighbors.read().unwrap();
        assert!(t.len() <= MAX_NEIGHBORS);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn system_table_is_empty_on_other_systems() {
        assert!(SystemNeighbors.read().unwrap().is_empty());
    }
}
