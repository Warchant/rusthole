use proptest::prelude::*;

use super::*;
use crate::config::{ConditionalForward, LocalCname, LocalRecord};

fn d(s: &str) -> DomainName {
    DomainName::parse(s).unwrap()
}

fn rec(name: &str, t: RecordType, value: &str) -> LocalRecord {
    LocalRecord {
        name: name.to_owned(),
        record_type: t,
        value: value.to_owned(),
    }
}

fn cname(name: &str, target: &str, ttl: Option<u32>) -> LocalCname {
    LocalCname {
        name: name.to_owned(),
        target: target.to_owned(),
        ttl,
    }
}

fn fwd(cidr: &str, server: &str, domain: Option<&str>) -> ConditionalForward {
    ConditionalForward {
        enabled: true,
        cidr: cidr.to_owned(),
        server: server.to_owned(),
        domain: domain.map(str::to_owned),
    }
}

fn zone(
    records: Vec<LocalRecord>,
    cnames: Vec<LocalCname>,
    forwards: Vec<ConditionalForward>,
) -> LocalZone {
    let mut cfg = Config::default();
    cfg.local_dns.records = records;
    cfg.local_dns.cnames = cnames;
    cfg.local_dns.conditional_forwarding = forwards;
    let (z, issues) = LocalZone::from_config(&cfg);
    assert!(issues.is_empty(), "{issues:?}");
    z
}

fn sample() -> LocalZone {
    zone(
        vec![
            rec("nas.lan", RecordType::A, "192.0.2.10"),
            rec("nas.lan", RecordType::Aaaa, "2001:db8::10"),
            rec("nas.lan", RecordType::A, "192.0.2.11"),
            rec("alias-host.lan", RecordType::A, "192.0.2.10"),
        ],
        vec![
            cname("media.lan", "nas.lan", Some(60)),
            cname("tv.lan", "media.lan", None),
            cname("cdn.lan", "cdn.example", None),
        ],
        vec![
            fwd("192.0.2.0/24", "192.0.2.1", Some("lan")),
            fwd("198.51.100.0/24", "192.0.2.2:5353", None),
            fwd("198.51.100.128/25", "192.0.2.3", Some("sub.corp.lan")),
        ],
    )
}

fn answer(a: LocalAnswer) -> Vec<LocalRr> {
    match a {
        LocalAnswer::Answer(r) => r,
        other => panic!("an answer was expected: {other:?}"),
    }
}

#[test]
fn address_records_by_type() {
    let z = sample();
    let a = answer(z.lookup(&d("nas.lan"), qtype::A));
    assert_eq!(
        a.iter().map(|r| r.data.clone()).collect::<Vec<_>>(),
        vec![
            LocalData::A("192.0.2.10".parse().unwrap()),
            LocalData::A("192.0.2.11".parse().unwrap())
        ]
    );
    assert!(
        a.iter()
            .all(|r| r.ttl == DEFAULT_LOCAL_TTL && r.name == d("nas.lan"))
    );
    let aaaa = answer(z.lookup(&d("nas.lan"), qtype::AAAA));
    assert_eq!(aaaa.len(), 1);
    assert_eq!(answer(z.lookup(&d("nas.lan"), qtype::ANY)).len(), 3);
    // A local name with no record of the type: NODATA, no forward and no upstream.
    assert_eq!(z.lookup(&d("nas.lan"), 16), LocalAnswer::Answer(Vec::new()));
    assert_eq!(
        z.lookup(&d("alias-host.lan"), qtype::AAAA),
        LocalAnswer::Answer(Vec::new())
    );
}

#[test]
fn cname_chains() {
    let z = sample();
    let r = answer(z.lookup(&d("tv.lan"), qtype::A));
    let kinds: Vec<String> = r
        .iter()
        .map(|x| format!("{} {:?} {}", x.name, x.data, x.ttl))
        .collect();
    assert_eq!(r.len(), 4, "{kinds:?}");
    assert_eq!(r[0].data, LocalData::Cname(d("media.lan")));
    assert_eq!(r[0].ttl, DEFAULT_LOCAL_TTL);
    assert_eq!(r[1].data, LocalData::Cname(d("nas.lan")));
    assert_eq!(r[1].ttl, 60);
    assert!(matches!(r[2].data, LocalData::A(_)));
    // A CNAME query gets the CNAME only.
    let r = answer(z.lookup(&d("tv.lan"), qtype::CNAME));
    assert_eq!(r.len(), 1);
    // A target that is not local: the CNAME only.
    let r = answer(z.lookup(&d("cdn.lan"), qtype::A));
    assert_eq!(
        r,
        vec![LocalRr {
            name: d("cdn.lan"),
            ttl: DEFAULT_LOCAL_TTL,
            data: LocalData::Cname(d("cdn.example")),
        }]
    );
}

#[test]
fn cname_loops_and_long_chains_stop() {
    let z = zone(
        Vec::new(),
        vec![cname("a.lan", "b.lan", None), cname("b.lan", "a.lan", None)],
        Vec::new(),
    );
    let r = answer(z.lookup(&d("a.lan"), qtype::A));
    assert_eq!(r.len(), 2);
    let self_loop = zone(Vec::new(), vec![cname("s.lan", "s.lan", None)], Vec::new());
    assert_eq!(answer(self_loop.lookup(&d("s.lan"), qtype::A)).len(), 1);
    let chain: Vec<LocalCname> = (0..20)
        .map(|i| cname(&format!("c{i}.lan"), &format!("c{}.lan", i + 1), None))
        .collect();
    let long = zone(
        vec![rec("c20.lan", RecordType::A, "192.0.2.20")],
        chain,
        Vec::new(),
    );
    assert_eq!(
        answer(long.lookup(&d("c0.lan"), qtype::A)).len(),
        MAX_CNAME_CHAIN
    );
    assert_eq!(answer(long.lookup(&d("c15.lan"), qtype::A)).len(), 6);
    // A chain of exactly MAX_CNAME_CHAIN CNAME records still gets the local A record.
    let start = 20 - MAX_CNAME_CHAIN;
    let r = answer(long.lookup(&d(&format!("c{start}.lan")), qtype::A));
    assert_eq!(r.len(), MAX_CNAME_CHAIN + 1);
    assert!(
        r.iter()
            .take(MAX_CNAME_CHAIN)
            .all(|x| matches!(x.data, LocalData::Cname(_)))
    );
    assert_eq!(
        r.last().map(|x| (&x.name, &x.data)),
        Some((&d("c20.lan"), &LocalData::A("192.0.2.20".parse().unwrap())))
    );
    // One CNAME more than the bound: the CNAME records only.
    let r = answer(long.lookup(&d(&format!("c{}.lan", start - 1)), qtype::A));
    assert_eq!(r.len(), MAX_CNAME_CHAIN);
}

#[test]
fn cname_and_record_on_one_name_is_reported() {
    let mut cfg = Config::default();
    cfg.local_dns.records = vec![rec("x.lan", RecordType::A, "192.0.2.1")];
    cfg.local_dns.cnames = vec![cname("x.lan", "y.lan", None), cname("x.lan", "z.lan", None)];
    let (z, issues) = LocalZone::from_config(&cfg);
    assert_eq!(issues.len(), 2, "{issues:?}");
    assert_eq!(
        answer(z.lookup(&d("x.lan"), qtype::A))[0].data,
        LocalData::Cname(d("y.lan"))
    );
}

#[test]
fn bad_values_are_reported_and_skipped() {
    let mut cfg = Config::default();
    cfg.local_dns.records = vec![
        rec("bad name!", RecordType::A, "192.0.2.1"),
        rec("ok.lan", RecordType::A, "2001:db8::1"),
    ];
    cfg.local_dns.cnames = vec![cname("ok.lan", "bad target!", None)];
    cfg.local_dns.conditional_forwarding = vec![
        fwd("not a cidr", "192.0.2.1", None),
        fwd("192.0.2.0/24", "not a server", None),
        fwd("192.0.2.0/24", "192.0.2.1", Some("bad domain!")),
        ConditionalForward {
            enabled: false,
            ..fwd("192.0.2.0/24", "192.0.2.1", None)
        },
    ];
    let (z, issues) = LocalZone::from_config(&cfg);
    assert_eq!(issues.len(), 6, "{issues:?}");
    assert_eq!(z.forwards(), []);
    assert_eq!(z.lookup(&d("ok.lan"), qtype::A), LocalAnswer::NotLocal);
}

#[test]
fn reverse_map_answers_ptr() {
    let z = sample();
    let r = answer(z.lookup(&d("10.2.0.192.in-addr.arpa"), qtype::PTR));
    let names: Vec<LocalData> = r.into_iter().map(|x| x.data).collect();
    assert_eq!(
        names,
        vec![
            LocalData::Ptr(d("nas.lan")),
            LocalData::Ptr(d("alias-host.lan"))
        ]
    );
    let v6 = reverse_name("2001:db8::10".parse().unwrap()).unwrap();
    assert_eq!(answer(z.lookup(&v6, qtype::PTR)).len(), 1);
    // Another type for a local reverse name: NODATA.
    assert_eq!(
        z.lookup(&d("10.2.0.192.in-addr.arpa"), qtype::A),
        LocalAnswer::Answer(Vec::new())
    );
    assert_eq!(z.names_of("192.0.2.11".parse().unwrap()), &[d("nas.lan")]);
    assert_eq!(z.names_of("192.0.2.99".parse().unwrap()), []);
}

#[test]
fn conditional_forwarding_routes() {
    let z = sample();
    let s = |t: &str| -> SocketAddr { t.parse().unwrap() };
    let fw = |a: LocalAnswer| match a {
        LocalAnswer::Forward { server, rule } => (server, rule),
        other => panic!("a forward was expected: {other:?}"),
    };
    assert_eq!(
        fw(z.lookup(&d("printer.lan"), qtype::A)),
        (s("192.0.2.1:53"), 0)
    );
    assert_eq!(fw(z.lookup(&d("lan"), qtype::SOA)), (s("192.0.2.1:53"), 0));
    // The most specific domain wins.
    assert_eq!(
        fw(z.lookup(&d("x.sub.corp.lan"), qtype::A)),
        (s("192.0.2.3:53"), 2)
    );
    // Label boundaries: `lan` does not match `plan`.
    assert_eq!(z.lookup(&d("plan"), qtype::A), LocalAnswer::NotLocal);
    assert_eq!(z.lookup(&d("www.plan"), qtype::A), LocalAnswer::NotLocal);
    // Reverse zones: the most specific CIDR wins.
    assert_eq!(
        fw(z.lookup(&d("5.2.0.192.in-addr.arpa"), qtype::PTR)),
        (s("192.0.2.1:53"), 0)
    );
    assert_eq!(
        fw(z.lookup(&d("5.100.51.198.in-addr.arpa"), qtype::PTR)),
        (s("192.0.2.2:5353"), 1)
    );
    assert_eq!(
        fw(z.lookup(&d("200.100.51.198.in-addr.arpa"), qtype::PTR)),
        (s("192.0.2.3:53"), 2)
    );
    // The zone name of the CIDR goes to the server too.
    assert_eq!(
        fw(z.lookup(&d("100.51.198.in-addr.arpa"), qtype::SOA)),
        (s("192.0.2.2:5353"), 1)
    );
    // A name with more labels in front of the address is in the zone too (DNS-SD browse).
    assert_eq!(
        fw(z.lookup(&d("b._dns-sd._udp.7.100.51.198.in-addr.arpa"), qtype::PTR)),
        (s("192.0.2.2:5353"), 1)
    );
    // A name that is not a valid domain name (RFC 2317) or a class that is not IN.
    let labels =
        |t: &'static str| -> Vec<&'static [u8]> { t.split('.').map(str::as_bytes).collect() };
    assert_eq!(
        fw(z.lookup_reverse_zone(&labels("0/25.100.51.198.in-addr.arpa"))),
        (s("192.0.2.2:5353"), 1)
    );
    assert_eq!(
        fw(z.lookup_reverse_zone(&labels("x.200.100.51.198.in-addr.arpa"))),
        (s("192.0.2.3:53"), 2)
    );
    // A larger zone than the CIDR is not in it.
    assert_eq!(
        z.lookup(&d("51.198.in-addr.arpa"), qtype::SOA),
        LocalAnswer::NotLocal
    );
}

#[test]
fn private_reverse_is_not_leaked() {
    let z = LocalZone::default();
    for name in [
        "1.0.0.10.in-addr.arpa",
        "5.1.168.192.in-addr.arpa",
        "168.192.in-addr.arpa",
        "1.0.16.172.in-addr.arpa",
        "1.0.0.127.in-addr.arpa",
        "7.2.0.192.in-addr.arpa",
        "1.1.64.100.in-addr.arpa",
        // More labels in front of the address (DNS-SD browse) or a label that is not a number.
        "lb._dns-sd._udp.0.1.168.192.in-addr.arpa",
        "b._dns-sd._udp.0.2.0.192.in-addr.arpa",
        "1.7.2.0.192.in-addr.arpa",
        "256.0.0.10.in-addr.arpa",
        "07.0.0.10.in-addr.arpa",
        "x.10.in-addr.arpa",
    ] {
        assert_eq!(
            z.lookup(&d(name), qtype::PTR),
            LocalAnswer::PrivateReverse,
            "{name}"
        );
    }
    for ip in ["fd00::1", "fe80::1", "::1", "2001:db8::5"] {
        let n = reverse_name(ip.parse().unwrap()).unwrap();
        assert_eq!(
            z.lookup(&n, qtype::PTR),
            LocalAnswer::PrivateReverse,
            "{ip}"
        );
    }
    let deep = format!(
        "{}{}",
        "0.".repeat(3),
        reverse_name("fd00::1".parse().unwrap()).unwrap()
    );
    assert_eq!(z.lookup(&d(&deep), qtype::PTR), LocalAnswer::PrivateReverse);
    // The same with the labels of a name that is not a valid domain name.
    for name in ["0/25.2.0.192.in-addr.arpa", "a b.1.168.192.in-addr.arpa"] {
        let labels: Vec<&[u8]> = name.split('.').map(str::as_bytes).collect();
        assert_eq!(
            z.lookup_reverse_zone(&labels),
            LocalAnswer::PrivateReverse,
            "{name}"
        );
    }
    for name in [
        "0/25.9.9.9.in-addr.arpa",
        "a b.example.com",
        "in-addr.arpa",
        "",
    ] {
        let labels: Vec<&[u8]> = name.split('.').map(str::as_bytes).collect();
        assert_eq!(
            z.lookup_reverse_zone(&labels),
            LocalAnswer::NotLocal,
            "{name}"
        );
    }
    // Public addresses and zones larger than a private range go on.
    for name in [
        "9.9.9.9.in-addr.arpa",
        "1.0.32.172.in-addr.arpa",
        "192.in-addr.arpa",
        "in-addr.arpa",
        "example.com",
        "lb._dns-sd._udp.0.9.9.9.in-addr.arpa",
        "x.192.in-addr.arpa",
        "x.in-addr.arpa",
    ] {
        assert_eq!(
            z.lookup(&d(name), qtype::PTR),
            LocalAnswer::NotLocal,
            "{name}"
        );
    }
}

#[test]
fn reverse_names_parse() {
    let p = |s: &str| parse_reverse(&d(s));
    let c = |s: &str| Cidr::parse(s).unwrap();
    assert_eq!(p("7.2.0.192.in-addr.arpa").unwrap().net, c("192.0.2.7/32"));
    assert_eq!(p("2.0.192.in-addr.arpa").unwrap().net, c("192.0.2.0/24"));
    assert_eq!(p("in-addr.arpa").unwrap().net, c("0.0.0.0/0"));
    assert_eq!(
        p("7.2.0.192.in-addr.arpa").unwrap().host(),
        Some("192.0.2.7".parse().unwrap())
    );
    assert_eq!(p("2.0.192.in-addr.arpa").unwrap().host(), None);
    // More labels: the network of the longest numeric suffix, and no host.
    let extra = |s: &str, net: &str| {
        let r = p(s).unwrap();
        assert_eq!((r.net, r.extra, r.host()), (c(net), true, None), "{s}");
    };
    extra("1.7.2.0.192.in-addr.arpa", "192.0.2.7/32");
    extra("x.7.2.0.192.in-addr.arpa", "192.0.2.7/32");
    extra("256.2.0.192.in-addr.arpa", "192.0.2.0/24");
    extra("07.2.0.192.in-addr.arpa", "192.0.2.0/24");
    extra("x.2.0.192.in-addr.arpa", "192.0.2.0/24");
    extra("lb._dns-sd._udp.0.1.168.192.in-addr.arpa", "192.168.1.0/32");
    extra("x.in-addr.arpa", "0.0.0.0/0");
    assert!(!p("7.2.0.192.in-addr.arpa").unwrap().extra);
    assert_eq!(p("xin-addr.arpa"), None);
    assert_eq!(p("in-addr.arpa.example"), None);
    assert_eq!(p("example.com"), None);
    assert_eq!(
        p("8.b.d.0.1.0.0.2.ip6.arpa").unwrap().net,
        c("2001:db8::/32")
    );
    extra("ab.ip6.arpa", "::/0");
    extra("ab.8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::/32");
    let full = format!("{}ip6.arpa", "0.".repeat(32));
    assert_eq!(p(&full).unwrap().host(), Some("::".parse().unwrap()));
    extra(&format!("0.{full}"), "::/128");
    assert_eq!(
        reverse_name("192.0.2.7".parse().unwrap()).unwrap().as_str(),
        "7.2.0.192.in-addr.arpa"
    );
}

proptest! {
    /// For a full reverse name, the reverse zone of a CIDR holds the name if and only if the
    /// CIDR holds the address.
    #[test]
    fn reverse_zone_match_equals_containment(
        addr in any::<u32>(), net in any::<u32>(), prefix in 0u8..=32,
    ) {
        let ip = IpAddr::V4(Ipv4Addr::from(addr));
        let cidr = Cidr { addr: IpAddr::V4(Ipv4Addr::from(net)), prefix };
        let rev = parse_reverse(&reverse_name(ip).unwrap()).unwrap();
        prop_assert_eq!(rev.host(), Some(ip));
        prop_assert_eq!(zone_holds(&cidr, &rev), cidr.contains(ip));
    }

    /// The same for IPv6.
    #[test]
    fn reverse_zone_match_equals_containment_v6(
        addr in any::<u128>(), net in any::<u128>(), prefix in 0u8..=128,
    ) {
        let ip = IpAddr::V6(Ipv6Addr::from(addr));
        let cidr = Cidr { addr: IpAddr::V6(Ipv6Addr::from(net)), prefix };
        let rev = parse_reverse(&reverse_name(ip).unwrap()).unwrap();
        prop_assert_eq!(rev.host(), Some(ip));
        prop_assert_eq!(zone_holds(&cidr, &rev), cidr.contains(ip));
    }

    /// Labels in front of a full reverse name keep its network, never name a host, and a
    /// private address never goes on to the upstreams.
    #[test]
    fn extra_labels_keep_the_network(
        v4 in any::<u32>(), v6 in any::<u128>(), use_v6 in any::<bool>(),
        junk in proptest::collection::vec("[a-z0-9_-]{1,6}", 1..4),
    ) {
        let ip = if use_v6 { IpAddr::V6(Ipv6Addr::from(v6)) } else { IpAddr::V4(Ipv4Addr::from(v4)) };
        let full = reverse_name(ip).unwrap();
        let name = d(&format!("{}.{}", junk.join("."), full));
        let rev = parse_reverse(&name).unwrap();
        prop_assert_eq!(rev.net, parse_reverse(&full).unwrap().net);
        prop_assert_eq!(rev.host(), None);
        let host = Cidr { addr: ip, prefix: if use_v6 { 128 } else { 32 } };
        let private = private_networks().iter().any(|c| c.contains(ip));
        let got = LocalZone::default().lookup(&name, qtype::PTR);
        prop_assert_eq!(got == LocalAnswer::PrivateReverse, private);
        prop_assert!(zone_holds(&host, &rev));
    }

    /// A conditional forwarding domain matches a name only on label boundaries: the name is
    /// the domain or ends with `.` and the domain.
    #[test]
    fn domain_match_is_on_label_boundaries(
        domain in "[a-z]{1,4}(\\.[a-z]{1,3}){0,2}",
        name in "[a-z]{1,4}(\\.[a-z]{1,3}){0,3}",
    ) {
        let z = zone(Vec::new(), Vec::new(), vec![fwd("192.0.2.0/24", "192.0.2.1", Some(&domain))]);
        let routed = matches!(z.lookup(&d(&name), qtype::A), LocalAnswer::Forward { .. });
        let want = name == domain || name.ends_with(&format!(".{domain}"));
        prop_assert_eq!(routed, want);
    }

    /// A local record always gives an answer, whatever the forwarding rules say.
    #[test]
    fn local_records_beat_forwarding(label in "[a-z]{1,8}", t in prop_oneof![Just(qtype::A), Just(qtype::AAAA), Just(qtype::PTR), Just(16u16)]) {
        let name = format!("{label}.lan");
        let z = zone(
            vec![rec(&name, RecordType::A, "192.0.2.10")],
            Vec::new(),
            vec![fwd("192.0.2.0/24", "192.0.2.1", Some("lan"))],
        );
        let is_answer = matches!(z.lookup(&d(&name), t), LocalAnswer::Answer(_));
        prop_assert!(is_answer);
    }
}
