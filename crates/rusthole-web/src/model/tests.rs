use super::*;

fn cfg() -> Config {
    let mut c = Config::default();
    c.assign_ids();
    c
}

#[test]
fn reverse_zones() {
    let c = Cidr::parse("192.0.2.0/24").unwrap();
    assert_eq!(reverse_zone(&c).as_deref(), Some("2.0.192.in-addr.arpa"));
    assert_eq!(zone_network("2.0.192.in-addr.arpa").unwrap(), Some(c));
    assert_eq!(
        zone_network("10.in-addr.arpa").unwrap(),
        Some(Cidr::parse("10.0.0.0/8").unwrap())
    );
    assert_eq!(zone_network("lan").unwrap(), None);
    assert_eq!(
        zone_network("x.ip6.arpa").unwrap_err().details[0].message,
        IPV6_LATER
    );
    assert!(zone_network("300.in-addr.arpa").is_err());
    assert!(zone_network("01.in-addr.arpa").is_err());
}

#[test]
fn forwarders_map_to_cidr_or_domain() {
    let mut c = cfg();
    create_forwarder(
        &mut c,
        ForwarderCreate {
            domain: "2.0.192.in-addr.arpa".into(),
            servers: vec!["192.0.2.1".into()],
            comment: Some("router".into()),
            enabled: None,
        },
        1,
    )
    .unwrap();
    create_forwarder(
        &mut c,
        ForwarderCreate {
            domain: "LAN".into(),
            servers: vec!["192.0.2.1:5353".into()],
            comment: None,
            enabled: Some(false),
        },
        2,
    )
    .unwrap();
    assert!(c.validate().is_empty(), "{:?}", c.validate());
    let f = &c.local_dns.conditional_forwarding;
    assert_eq!(
        (f[0].cidr.as_str(), f[0].domain.as_deref()),
        ("192.0.2.0/24", None)
    );
    assert_eq!(
        (f[1].cidr.as_str(), f[1].domain.as_deref()),
        ("", Some("lan"))
    );
    assert_eq!(forwarder_out(&f[0]).domain, "2.0.192.in-addr.arpa");
    let two = create_forwarder(
        &mut c,
        ForwarderCreate {
            domain: "x.lan".into(),
            servers: vec!["192.0.2.1".into(), "192.0.2.2".into()],
            comment: None,
            enabled: None,
        },
        3,
    );
    assert_eq!(two.unwrap_err().code, "validation_failed");
    let v6 = create_forwarder(
        &mut c,
        ForwarderCreate {
            domain: "x.lan".into(),
            servers: vec!["[2001:db8::1]:53".into()],
            comment: None,
            enabled: None,
        },
        3,
    );
    assert_eq!(v6.unwrap_err().details[0].message, IPV6_LATER);
}

#[test]
fn groups_rename_and_delete_update_references() {
    let mut c = cfg();
    create_group(
        &mut c,
        GroupCreate {
            name: "kids".into(),
            enabled: None,
            comment: None,
        },
        1,
    )
    .unwrap();
    create_client(
        &mut c,
        ClientCreate {
            match_: "02:00:00:00:00:01".into(),
            groups: Some(vec![0, 1]),
            comment: None,
        },
        1,
    )
    .unwrap();
    patch_group(
        &mut c,
        1,
        GroupPatch {
            name: Some("teens".into()),
            ..GroupPatch::default()
        },
    )
    .unwrap();
    assert_eq!(c.clients[0].groups, ["default", "teens"]);
    assert_eq!(delete_group(&mut c, 0).unwrap_err().code, "conflict");
    delete_group(&mut c, 1).unwrap();
    assert_eq!(c.clients[0].groups, ["default"]);
    assert_eq!(
        create_group(
            &mut c,
            GroupCreate {
                name: "Bad Name".into(),
                enabled: None,
                comment: None
            },
            2
        )
        .unwrap_err()
        .code,
        "validation_failed"
    );
    assert_eq!(
        create_group(
            &mut c,
            GroupCreate {
                name: "default".into(),
                enabled: None,
                comment: None
            },
            2
        )
        .unwrap_err()
        .code,
        "conflict"
    );
}

#[test]
fn clients_rules_and_conflicts() {
    let mut c = cfg();
    let v6 = create_client(
        &mut c,
        ClientCreate {
            match_: "2001:db8::1".into(),
            groups: None,
            comment: None,
        },
        1,
    );
    assert_eq!(v6.unwrap_err().details[0].message, IPV6_LATER);
    create_client(
        &mut c,
        ClientCreate {
            match_: "192.0.2.10".into(),
            groups: None,
            comment: None,
        },
        1,
    )
    .unwrap();
    let dup = create_client(
        &mut c,
        ClientCreate {
            match_: " 192.0.2.10 ".into(),
            groups: None,
            comment: None,
        },
        2,
    );
    assert_eq!(dup.unwrap_err().code, "conflict");
    assert_eq!(client_out(&c, &c.clients[0]).kind, "ip");

    let rule = |p: &str| RuleCreate {
        kind: RuleKind::Exact,
        action: RuleAction::Deny,
        pattern: p.into(),
        enabled: None,
        groups: None,
        comment: None,
    };
    create_rule(&mut c, rule("Ads.Example"), 1, "t").unwrap();
    assert_eq!(c.rules[0].value, "ads.example");
    assert_eq!(
        create_rule(&mut c, rule("ads.example"), 2, "t")
            .unwrap_err()
            .code,
        "conflict"
    );
    let bad = create_rule(
        &mut c,
        RuleCreate {
            kind: RuleKind::Regex,
            pattern: "(".into(),
            ..rule("x")
        },
        2,
        "t",
    );
    assert_eq!(bad.unwrap_err().code, "validation_failed");
    let unknown_group = create_rule(
        &mut c,
        RuleCreate {
            groups: Some(vec![9]),
            ..rule("b.example")
        },
        2,
        "t",
    );
    assert_eq!(unknown_group.unwrap_err().code, "validation_failed");
}

#[test]
fn rule_test_uses_the_engine_regex() {
    let t = |kind, pattern: &str, domain: &str| {
        test_rule(&RuleTest {
            kind,
            pattern: pattern.into(),
            domain: domain.into(),
        })
        .unwrap()
    };
    assert!(t(RuleKind::Regex, "^ADS\\.", "ads.example.net").matches);
    assert!(!t(RuleKind::Regex, "^ads\\.", "x.example.net").matches);
    let bad = t(RuleKind::Regex, "(", "a.example");
    assert!(!bad.valid && !bad.matches && bad.error.is_some());
    assert!(t(RuleKind::Exact, "A.example", "a.example").matches);
}

#[test]
fn records_and_cnames_do_not_share_a_name() {
    let mut c = cfg();
    create_record(
        &mut c,
        RecordCreate {
            name: "nas.lan".into(),
            record_type: RecordType::A,
            address: "192.0.2.20".into(),
            comment: None,
            enabled: None,
        },
        1,
    )
    .unwrap();
    let cname = create_cname(
        &mut c,
        CnameCreate {
            name: "nas.lan".into(),
            target: "x.lan".into(),
            comment: None,
            enabled: None,
        },
        1,
    );
    assert_eq!(cname.unwrap_err().code, "conflict");
    let wrong = create_record(
        &mut c,
        RecordCreate {
            name: "nas6.lan".into(),
            record_type: RecordType::Aaaa,
            address: "192.0.2.20".into(),
            comment: None,
            enabled: None,
        },
        2,
    );
    assert_eq!(wrong.unwrap_err().code, "validation_failed");
}

#[test]
fn blocking_requests() {
    assert!(
        check_blocking(&BlockingReq {
            enabled: true,
            duration_seconds: None
        })
        .is_ok()
    );
    assert!(
        check_blocking(&BlockingReq {
            enabled: true,
            duration_seconds: Some(5)
        })
        .is_err()
    );
    assert!(
        check_blocking(&BlockingReq {
            enabled: false,
            duration_seconds: Some(0)
        })
        .is_err()
    );
    assert!(
        check_blocking(&BlockingReq {
            enabled: false,
            duration_seconds: Some(86_401)
        })
        .is_err()
    );
    assert!(
        check_blocking(&BlockingReq {
            enabled: false,
            duration_seconds: Some(300)
        })
        .is_ok()
    );
}
