//! Memory and speed of the compiled block set (decision D6, amendment A10).
//!
//! This test binary counts every heap byte with a counting allocator, so it has its own file.
//! The fast test uses 100 000 names. The slow test uses 1 000 000 names; run it with:
//!
//! ```text
//! cargo test --release -p rusthole-core --test policy_memory -- --ignored --nocapture
//! ```
//!
//! docs/POLICY.md has the measured numbers.

use peak_alloc::PeakAlloc;

#[global_allocator]
static ALLOC: PeakAlloc = PeakAlloc;

#[cfg(test)]
mod memory {
    use std::sync::Mutex;

    use rusthole_core::config::{Adlist, Config, ListKind, Rule, RuleAction, RuleKind};
    use rusthole_core::lists::{EntryAction, MatchKind, ParsedList};
    use rusthole_core::{DomainName, PolicyEngine};

    use super::ALLOC;

    /// The allocator counters are global, so the tests in this file run one at a time.
    static LOCK: Mutex<()> = Mutex::new(());

    /// The memory target of D6: 64 MB for 1 000 000 names, so 64 bytes per name.
    const TARGET_BYTES_PER_NAME: usize = 64;

    const PREFIXES: [&str; 8] = [
        "ads", "trk", "pixel", "metrics", "cdn", "stats", "beacon", "track",
    ];
    const MIDDLES: [&str; 6] = [
        "example",
        "test",
        "sample-host",
        "adnet",
        "media-cdn",
        "invalid",
    ];
    const TLDS: [&str; 5] = ["com", "net", "org", "io", "co.uk"];

    /// A deterministic, unique name of realistic length (about 25 characters) for number `i`.
    fn synthetic_name(i: u64, out: &mut String) {
        use std::fmt::Write;
        let mut h = i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        h ^= h >> 29;
        let pick = |n: usize, shift: u32| usize::try_from((h >> shift) % n as u64).unwrap();
        out.clear();
        write!(
            out,
            "{}-{i:x}.{}.{}",
            PREFIXES[pick(PREFIXES.len(), 3)],
            MIDDLES[pick(MIDDLES.len(), 11)],
            TLDS[pick(TLDS.len(), 19)]
        )
        .unwrap();
    }

    /// A list with names `from..to`. Every tenth entry is a subtree entry, so lookups also
    /// walk the parent names.
    fn make_list(from: u64, to: u64) -> ParsedList {
        let mut list = ParsedList::with_capacity(usize::try_from((to - from) * 27).unwrap());
        let mut s = String::new();
        for i in from..to {
            synthetic_name(i, &mut s);
            let kind = if i % 10 == 0 {
                MatchKind::Subtree
            } else {
                MatchKind::Exact
            };
            list.push(&DomainName::parse(&s).unwrap(), kind, EntryAction::Deny)
                .unwrap();
        }
        list
    }

    fn config(ids: &[u32]) -> Config {
        let mut c = Config::default();
        c.lists.adlists = ids
            .iter()
            .map(|id| Adlist {
                id: *id,
                url: format!("https://lists.example/{id}.txt"),
                kind: ListKind::Block,
                enabled: true,
                groups: vec!["default".into()],
                comment: None,
            })
            .collect();
        // Regex deny rules like those of a typical Pi-hole setup, so that each lookup also
        // runs the regex sets. They match none of the synthetic names.
        c.rules = REGEX_RULES
            .iter()
            .map(|p| Rule {
                kind: RuleKind::Regex,
                action: RuleAction::Deny,
                value: (*p).to_owned(),
                enabled: true,
                groups: vec!["default".into()],
                comment: None,
            })
            .collect();
        c
    }

    const REGEX_RULES: [&str; 9] = [
        r"^ad[0-9]+\.",
        r"(\.|^)telemetry\.invalid$",
        r"^track(ing)?[0-9]*\.",
        r"(\.|^)ads?-[a-z]+\.test$",
        r"^banners?\.",
        r"(\.|^)analytics[0-9]*\.",
        r"^[a-z]{20,}\.example$",
        r"(\.|^)beacon-[0-9]+\.net$",
        r"^pop(up|under)s?\.",
    ];

    #[derive(Debug)]
    struct Measured {
        unique: usize,
        input_bytes: usize,
        peak_bytes: usize,
        steady_bytes: usize,
        estimate_bytes: usize,
        lookups_per_second: f64,
        rehashes: u32,
        max_probe: usize,
    }

    /// Builds an engine from `lists` (given as name ranges, made lazily one at a time), and
    /// measures the heap. The peak includes the list that is being made and added.
    fn measure(ranges: &[(u32, u64, u64)], lookups: usize) -> Measured {
        let _guard = LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ids: Vec<u32> = ranges.iter().map(|r| r.0).collect();
        let cfg = config(&ids);
        let input_bytes = ranges
            .iter()
            .map(|(_, from, to)| make_list(*from, *to).heap_bytes())
            .max()
            .unwrap_or(0);
        let before = ALLOC.current_usage();
        ALLOC.reset_peak_usage();
        let lists = ranges
            .iter()
            .map(|(id, from, to)| (*id, make_list(*from, *to)));
        let (engine, report) = PolicyEngine::build(&cfg, lists);
        let peak_bytes = ALLOC.peak_usage().saturating_sub(before);
        let rehashes = report.set_rehashes;
        let max_probe = report.set_max_probe;
        drop(report);
        let steady_bytes = ALLOC.current_usage().saturating_sub(before);
        let unique = engine.unique_domains();
        let estimate_bytes = engine.memory_bytes();
        let lookups_per_second = lookup_speed(&engine, ranges, lookups);
        Measured {
            unique,
            input_bytes,
            peak_bytes,
            steady_bytes,
            estimate_bytes,
            lookups_per_second,
            rehashes,
            max_probe,
        }
    }

    /// Checks names: one third in the set, one third subdomains of names in the set, one third
    /// not in the set. Returns lookups per second.
    #[allow(clippy::disallowed_methods)] // A speed test needs a clock; it is not core code.
    fn lookup_speed(engine: &PolicyEngine, ranges: &[(u32, u64, u64)], n: usize) -> f64 {
        let max = ranges.iter().map(|r| r.2).max().unwrap_or(1);
        let mut s = String::new();
        let names: Vec<DomainName> = (0..n as u64)
            .map(|k| {
                let i = k.wrapping_mul(7919) % max;
                synthetic_name(i, &mut s);
                match k % 3 {
                    0 => DomainName::parse(&s).unwrap(),
                    1 => DomainName::parse(&format!("www.sub.{s}")).unwrap(),
                    _ => DomainName::parse(&format!("miss-{k}.example")).unwrap(),
                }
            })
            .collect();
        let groups = engine.default_groups();
        let start = std::time::Instant::now();
        let mut blocked = 0usize;
        for name in &names {
            if engine.check(&groups, true, name).is_blocked() {
                blocked += 1;
            }
        }
        let secs = start.elapsed().as_secs_f64().max(1e-9);
        assert!(blocked >= n / 3, "blocked {blocked} of {n}");
        #[allow(clippy::cast_precision_loss)] // A rate for a report; precision loss is fine.
        let rate = n as f64 / secs;
        rate
    }

    fn report(label: &str, m: &Measured) {
        let mb = |b: usize| {
            #[allow(clippy::cast_precision_loss)] // Megabytes for a report.
            let v = b as f64 / 1_000_000.0;
            v
        };
        println!(
            "{label}: unique={} input_list={:.1} MB peak={:.1} MB ({} B/name) steady={:.1} MB \
             ({} B/name) estimate={:.1} MB lookups/s={:.0} rehashes={} max_probe={}",
            m.unique,
            mb(m.input_bytes),
            mb(m.peak_bytes),
            m.peak_bytes / m.unique.max(1),
            mb(m.steady_bytes),
            m.steady_bytes / m.unique.max(1),
            mb(m.estimate_bytes),
            m.lookups_per_second,
            m.rehashes,
            m.max_probe
        );
    }

    fn check_target(m: &Measured) {
        // Random names with a secret key never need a new key, and the probes stay short.
        assert_eq!(m.rehashes, 0);
        assert!(m.max_probe < 1024, "max probe {}", m.max_probe);
        assert!(
            m.peak_bytes <= m.unique * TARGET_BYTES_PER_NAME,
            "peak {} B for {} names is over {TARGET_BYTES_PER_NAME} B per name",
            m.peak_bytes,
            m.unique
        );
        // The estimate from capacities is close to the real heap use.
        assert!(m.estimate_bytes <= m.steady_bytes + m.steady_bytes / 10);
        assert!(m.steady_bytes <= m.estimate_bytes + m.estimate_bytes / 10 + 64 * 1024);
    }

    #[test]
    fn memory_100k_one_list() {
        let m = measure(&[(1, 0, 100_000)], 30_000);
        report("100k, one list", &m);
        assert_eq!(m.unique, 100_000);
        check_target(&m);
    }

    #[test]
    fn memory_100k_overlapping_lists() {
        // 3 lists, 140k entries, 100k unique names.
        let m = measure(
            &[(1, 0, 60_000), (2, 30_000, 80_000), (3, 70_000, 100_000)],
            30_000,
        );
        report("100k, three lists", &m);
        assert_eq!(m.unique, 100_000);
        check_target(&m);
    }

    #[test]
    #[ignore = "slow: run with --release -- --ignored --nocapture"]
    fn memory_1m_one_list() {
        let m = measure(&[(1, 0, 1_000_000)], 1_000_000);
        report("1M, one list", &m);
        assert_eq!(m.unique, 1_000_000);
        check_target(&m);
    }

    #[test]
    #[ignore = "slow: run with --release -- --ignored --nocapture"]
    fn memory_1m_overlapping_lists() {
        // 3 lists, 1.4M entries, 1M unique names, largest list first.
        let m = measure(
            &[
                (1, 0, 600_000),
                (2, 300_000, 800_000),
                (3, 700_000, 1_000_000),
            ],
            1_000_000,
        );
        report("1M, three lists", &m);
        assert_eq!(m.unique, 1_000_000);
        check_target(&m);
    }
}
