// The tests change one field of a default config at a time. That is the clearest form here.
#![allow(clippy::field_reassign_with_default)]

use super::*;
use proptest::prelude::*;

/// Returns the paths of all issues.
fn paths(config: &Config) -> Vec<String> {
    config.validate().into_iter().map(|i| i.path).collect()
}

/// Asserts that the config has exactly one issue, at `path`.
fn assert_one_issue(config: &Config, path: &str) {
    let issues = config.validate();
    assert_eq!(
        issues.iter().map(|i| i.path.as_str()).collect::<Vec<_>>(),
        [path],
        "issues: {issues:#?}"
    );
}

fn rule(kind: RuleKind, value: &str) -> Rule {
    Rule {
        kind,
        action: RuleAction::Deny,
        value: value.to_owned(),
        enabled: true,
        groups: vec![DEFAULT_GROUP.to_owned()],
        comment: None,
    }
}

#[test]
fn default_is_valid_and_round_trips() {
    let c = Config::default();
    assert_eq!(c.validate(), []);
    let text = c.to_toml_string().unwrap();
    assert_eq!(Config::from_toml_str(&text).unwrap(), c);
}

#[test]
fn version_only_file_gives_default() {
    assert_eq!(
        Config::from_toml_str("config_version = 1\n").unwrap(),
        Config::default()
    );
}

#[test]
fn missing_and_unknown_version() {
    assert_eq!(
        Config::from_toml_str("[server]\ndns_port = 53\n"),
        Err(ConfigError::MissingVersion)
    );
    assert_eq!(
        Config::from_toml_str("config_version = \"1\"\n"),
        Err(ConfigError::BadVersionType)
    );
    let err = Config::from_toml_str("config_version = 7\n").unwrap_err();
    assert_eq!(err, ConfigError::UnsupportedVersion { found: 7 });
    assert!(err.to_string().contains("reads version 1"));
    assert_eq!(
        Config::from_toml_str("config_version = 0\n"),
        Err(ConfigError::UnsupportedVersion { found: 0 })
    );
}

#[test]
fn migrate_keeps_current_and_refuses_others() {
    let mut t = toml::Table::new();
    t.insert("config_version".into(), toml::Value::Integer(1));
    assert_eq!(migrate(t.clone(), 1), Ok(t.clone()));
    assert!(migrate(t.clone(), 2).is_err());
    assert!(migrate(t, -1).is_err());
}

#[test]
fn unknown_key_is_an_error() {
    let err = Config::from_toml_str("config_version = 1\n[server]\ndns_prot = 53\n").unwrap_err();
    assert!(err.to_string().contains("dns_prot"), "{err}");
    assert!(Config::from_toml_str("config_version = 1\nextra = true\n").is_err());
}

#[test]
fn deep_dotted_key_does_not_crash() {
    let key = vec!["k"; 5000].join(".");
    assert!(Config::from_toml_str(&format!("config_version = 1\n{key} = 1\n")).is_err());
}

#[test]
fn bad_toml_is_an_error() {
    assert!(matches!(
        Config::from_toml_str("config_version = 1\n[server\n"),
        Err(ConfigError::Toml(_))
    ));
}

#[test]
fn wrong_version_value_is_an_issue() {
    let c = Config {
        config_version: 2,
        ..Config::default()
    };
    assert_one_issue(&c, "config_version");
}

#[test]
fn listen_addresses() {
    let mut c = Config::default();
    c.server.dns_listen = vec!["auto".into(), "192.0.2.1".into()];
    assert_one_issue(&c, "server.dns_listen");
    c.server.dns_listen = vec!["192.0.2.1".into(), "nope".into()];
    assert_one_issue(&c, "server.dns_listen[1]");
    c.server.dns_listen = vec![];
    assert_one_issue(&c, "server.dns_listen");
    c.server.dns_listen = vec!["192.0.2.1".into(), "2001:db8::1".into()];
    assert_eq!(c.validate(), []);
    c.server.doh.listen = vec!["bad".into()];
    assert_one_issue(&c, "server.doh.listen[0]");
}

#[test]
fn port_zero() {
    let mut c = Config::default();
    c.server.dns_port = 0;
    assert_one_issue(&c, "server.dns_port");
    let mut c = Config::default();
    c.server.admin.port = 0;
    assert_one_issue(&c, "server.admin.port");
    let mut c = Config::default();
    c.server.doh.port = 0;
    assert_one_issue(&c, "server.doh.port");
}

#[test]
fn doh_and_admin_port_clash() {
    let mut c = Config::default();
    c.server.doh.enabled = true;
    c.server.doh.port = 8443;
    assert_one_issue(&c, "server.admin.port");
}

#[test]
fn upstream_urls() {
    let mut c = Config::default();
    c.upstreams.servers = vec![Upstream {
        url: "ftp://192.0.2.1".into(),
        bootstrap: vec![],
    }];
    assert_one_issue(&c, "upstreams.servers[0].url");
    c.upstreams.servers[0].url = "udp://192.0.2.1:0".into();
    assert_one_issue(&c, "upstreams.servers[0].url");
    c.upstreams.servers[0].url = "udp://dns.example".into();
    assert_one_issue(&c, "upstreams.servers[0].url");
    c.upstreams.servers[0].url = "8.8.8.8".into();
    assert_eq!(c.validate(), []);
    c.upstreams.servers.clear();
    assert_one_issue(&c, "upstreams.servers");
}

#[test]
fn encrypted_upstream_needs_bootstrap() {
    let mut c = Config::default();
    c.upstreams.servers = vec![Upstream {
        url: "https://dns.example/dns-query".into(),
        bootstrap: vec![],
    }];
    assert_one_issue(&c, "upstreams.servers[0].bootstrap");
    c.upstreams.servers[0].bootstrap = vec!["192.0.2.53".into()];
    assert_eq!(c.validate(), []);
    c.upstreams.servers[0].bootstrap = vec!["dns.example".into()];
    assert_one_issue(&c, "upstreams.servers[0].bootstrap[0]");
    // An IP host needs no bootstrap.
    c.upstreams.servers[0] = Upstream {
        url: "tls://192.0.2.53".into(),
        bootstrap: vec![],
    };
    assert_eq!(c.validate(), []);
    // Bootstrap on a plain upstream is a mistake.
    c.upstreams.servers[0] = Upstream {
        url: "udp://192.0.2.53".into(),
        bootstrap: vec!["192.0.2.53".into()],
    };
    assert_one_issue(&c, "upstreams.servers[0].bootstrap");
}

#[test]
fn fallback_must_be_plain() {
    let mut c = Config::default();
    c.upstreams.fallback_plain = vec!["tls://192.0.2.53".into()];
    assert_one_issue(&c, "upstreams.fallback_plain[0]");
    c.upstreams.fallback_plain = vec!["192.0.2.53".into(), "tcp://192.0.2.54".into()];
    assert_eq!(c.validate(), []);
    c.upstreams.fallback_plain = vec!["junk".into()];
    assert_one_issue(&c, "upstreams.fallback_plain[0]");
}

#[test]
fn upstream_timeout_range() {
    let mut c = Config::default();
    c.upstreams.timeout_ms = 0;
    assert_one_issue(&c, "upstreams.timeout_ms");
    c.upstreams.timeout_ms = MAX_UPSTREAM_TIMEOUT_MS + 1;
    assert_one_issue(&c, "upstreams.timeout_ms");
}

#[test]
fn blocking_ip_mode() {
    let mut c = Config::default();
    c.blocking.mode = BlockingMode::Ip;
    assert_one_issue(&c, "blocking.mode");
    c.blocking.ipv4 = Some("192.0.2.1".into());
    assert_eq!(c.validate(), []);
    c.blocking.ipv4 = Some("2001:db8::1".into());
    assert_one_issue(&c, "blocking.ipv4");
    c.blocking.ipv4 = None;
    c.blocking.ipv6 = Some("192.0.2.1".into());
    assert_one_issue(&c, "blocking.ipv6");
}

#[test]
fn special_domains_are_domains() {
    let mut c = Config::default();
    c.blocking.special_domains.push("not a domain".into());
    assert_one_issue(&c, "blocking.special_domains[3]");
}

#[test]
fn cache_and_numbers() {
    let mut c = Config::default();
    c.cache.min_ttl = 10;
    c.cache.max_ttl = 5;
    assert_one_issue(&c, "cache.min_ttl");
    let mut c = Config::default();
    c.cache.max_entries = MAX_CACHE_ENTRIES + 1;
    assert_one_issue(&c, "cache.max_entries");
    let mut c = Config::default();
    c.rate_limit.interval_seconds = 0;
    assert_one_issue(&c, "rate_limit.interval_seconds");
    c.rate_limit.queries = 0;
    assert_eq!(c.validate(), []);
    let mut c = Config::default();
    c.stats.recent_queries = MAX_RECENT_QUERIES + 1;
    assert_one_issue(&c, "stats.recent_queries");
}

#[test]
fn acl_cidrs() {
    let mut c = Config::default();
    c.acl.allow = vec![
        "192.0.2.0/24".into(),
        "2001:db8::/32".into(),
        "192.0.2.0/40".into(),
    ];
    assert_one_issue(&c, "acl.allow[2]");
}

#[test]
fn groups_default_unique_valid() {
    let mut c = Config::default();
    c.groups = vec![Group {
        name: "kids".into(),
        enabled: true,
        comment: None,
    }];
    assert_one_issue(&c, "groups");
    let mut c = Config::default();
    c.groups.push(c.groups[0].clone());
    assert_one_issue(&c, "groups[1].name");
    let mut c = Config::default();
    for bad in ["Kids", "", "-x", "a b", &"a".repeat(65)] {
        c.groups.truncate(1);
        c.groups.push(Group {
            name: bad.to_owned(),
            enabled: true,
            comment: None,
        });
        assert_one_issue(&c, "groups[1].name");
    }
    assert!(is_valid_group_name("iot-2.lan_x"));
}

#[test]
fn unknown_group_references() {
    let mut c = Config::default();
    c.rules.push(Rule {
        groups: vec!["default".into(), "ghost".into()],
        ..rule(RuleKind::Exact, "ads.example")
    });
    assert_one_issue(&c, "rules[0].groups[1]");
    let mut c = Config::default();
    c.clients.push(Client {
        id: "192.0.2.5".into(),
        groups: vec!["ghost".into()],
        comment: None,
    });
    assert_one_issue(&c, "clients[0].groups[0]");
    let mut c = Config::default();
    c.lists.adlists.push(Adlist {
        id: 1,
        url: "https://lists.example/a.txt".into(),
        kind: ListKind::Block,
        enabled: true,
        groups: vec!["ghost".into()],
        comment: None,
    });
    assert_one_issue(&c, "lists.adlists[0].groups[0]");
}

#[test]
fn adlists_ids_and_urls() {
    let list = |id, url: &str| Adlist {
        id,
        url: url.to_owned(),
        kind: ListKind::Block,
        enabled: true,
        groups: vec![DEFAULT_GROUP.into()],
        comment: None,
    };
    let mut c = Config::default();
    c.lists.adlists = vec![
        list(1, "https://lists.example/a.txt"),
        list(1, "https://lists.example/b.txt"),
    ];
    assert_one_issue(&c, "lists.adlists[1].id");
    c.lists.adlists = vec![
        list(1, "https://lists.example/a.txt"),
        list(2, "https://lists.example/a.txt"),
    ];
    assert_one_issue(&c, "lists.adlists[1].url");
    for bad in [
        "file:///etc/hosts",
        "ftp://lists.example/a",
        "https://",
        "https://u@x/",
        "https://lists.example/a b",
    ] {
        c.lists.adlists = vec![list(1, bad)];
        assert_one_issue(&c, "lists.adlists[0].url");
    }
}

#[test]
fn rule_values() {
    let mut c = Config::default();
    c.rules = vec![
        rule(RuleKind::Exact, "ads.example"),
        rule(RuleKind::Exact, "bad domain"),
        rule(RuleKind::Regex, r"(\.|^)example\.com$"),
        rule(RuleKind::Regex, "(unclosed"),
        rule(RuleKind::Regex, ""),
        rule(RuleKind::Exact, "b\u{fc}cher.example"),
    ];
    assert_eq!(
        paths(&c),
        ["rules[1].value", "rules[3].value", "rules[4].value"]
    );
}

#[test]
fn clients_ids() {
    let client = |id: &str| Client {
        id: id.to_owned(),
        groups: vec![DEFAULT_GROUP.into()],
        comment: None,
    };
    let mut c = Config::default();
    c.clients = vec![
        client("02:00:00:00:00:01"),
        client("192.0.2.5"),
        client("192.0.2.0/24"),
        client("laptop"),
        client(":eth0"),
        client("02:00:00:00:00:01".to_uppercase().as_str()),
        client("192.0.2.0/99"),
    ];
    assert_eq!(
        paths(&c),
        ["clients[4].id", "clients[5].id", "clients[6].id"]
    );
}

#[test]
fn local_dns_values() {
    let mut c = Config::default();
    c.local_dns.records = vec![
        LocalRecord {
            name: "nas.lan".into(),
            record_type: RecordType::A,
            value: "192.0.2.10".into(),
        },
        LocalRecord {
            name: "nas.lan".into(),
            record_type: RecordType::Aaaa,
            value: "192.0.2.10".into(),
        },
        LocalRecord {
            name: "bad name".into(),
            record_type: RecordType::Aaaa,
            value: "2001:db8::10".into(),
        },
    ];
    c.local_dns.cnames = vec![LocalCname {
        name: "media.lan".into(),
        target: "nas..lan".into(),
        ttl: Some(60),
    }];
    c.local_dns.conditional_forwarding = vec![ConditionalForward {
        enabled: true,
        cidr: "192.0.2.0/24".into(),
        server: "192.0.2.1#53".into(),
        domain: Some("lan".into()),
    }];
    assert_eq!(
        paths(&c),
        [
            "local_dns.records[1].value",
            "local_dns.records[2].name",
            "local_dns.cnames[0].target",
            "local_dns.conditional_forwarding[0].server",
        ]
    );
}

const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

#[test]
fn admin_secrets() {
    let mut c = Config::default();
    c.admin.password_hash = PHC.into();
    assert_eq!(c.validate(), []);
    c.admin.password_hash = "$6$plain-crypt".into();
    let issues = c.validate();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].path, "admin.password_hash");
    assert!(!issues[0].message.contains("plain-crypt"));
    c.admin.password_hash = String::new();
    c.admin.totp_secret = "short".into();
    assert_one_issue(&c, "admin.totp_secret");
    c.admin.totp_secret = "JBSWY3DPEHPK3PXP".into();
    assert_eq!(c.validate(), []);
    c.admin.tls_cert_path = Some("/etc/rusthole/cert.pem".into());
    assert_one_issue(&c, "admin.tls_cert_path");
    c.admin.tls_key_path = Some("/etc/rusthole/key.pem".into());
    c.admin.session_ttl_seconds = 0;
    assert_one_issue(&c, "admin.session_ttl_seconds");
}

#[test]
fn api_tokens() {
    let mut c = Config::default();
    c.admin.api_tokens = vec![
        ApiToken {
            name: "ci".into(),
            hash: format!("sha256:{}", "a".repeat(64)),
        },
        ApiToken {
            name: "ci".into(),
            hash: PHC.into(),
        },
        ApiToken {
            name: " ".into(),
            hash: "plain".into(),
        },
    ];
    assert_eq!(
        paths(&c),
        [
            "admin.api_tokens[1].name",
            "admin.api_tokens[2].name",
            "admin.api_tokens[2].hash"
        ]
    );
}

#[test]
fn phc_check() {
    assert!(is_argon2id_phc(PHC));
    assert!(is_argon2id_phc("$argon2id$m=1,t=1,p=1$c2FsdA$aGFzaA"));
    assert!(!is_argon2id_phc("$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA"));
    assert!(!is_argon2id_phc("$argon2id$v=19$m=1,t=1$c2FsdA$aGFzaA"));
    assert!(!is_argon2id_phc("$argon2id$v=19$m=1,t=1,p=1$$aGFzaA"));
    assert!(!is_argon2id_phc(""));
}

#[test]
fn debug_hides_secrets() {
    let mut c = Config::default();
    c.admin.password_hash = PHC.into();
    c.admin.totp_secret = "JBSWY3DPEHPK3PXP".into();
    c.admin.api_tokens.push(ApiToken {
        name: "ci".into(),
        hash: format!("sha256:{}", "b".repeat(64)),
    });
    let text = format!("{c:?}");
    assert!(!text.contains("c29tZXNhbHQ"));
    assert!(!text.contains("JBSWY3DPEHPK3PXP"));
    assert!(!text.contains("bbbbbbbb"));
    assert!(text.contains("<redacted>"));
}

#[test]
fn full_example_in_docs_is_valid() {
    let doc = include_str!("../../../../docs/CONFIG.md");
    let (_, rest) = doc.split_once("```toml\n").unwrap();
    let (text, _) = rest.split_once("```").unwrap();
    let c = Config::from_toml_str(text).unwrap();
    // The example shows each section.
    for section in [
        "[server]",
        "[upstreams]",
        "[blocking]",
        "[cache]",
        "[acl]",
        "[rate_limit]",
        "[stats]",
        "[[lists.adlists]]",
        "[[rules]]",
        "[[groups]]",
        "[[clients]]",
        "[[local_dns.records]]",
        "[[local_dns.cnames]]",
        "[[local_dns.conditional_forwarding]]",
        "[admin]",
    ] {
        assert!(text.contains(section), "example has no {section}");
    }
    assert_eq!(c.validate(), []);
    assert_eq!(
        Config::from_toml_str(&c.to_toml_string().unwrap()).unwrap(),
        c
    );
}

#[test]
fn toml_errors_never_quote_a_secret() {
    let secret = "JBSWY3DPEHPK3PXPSECRET";
    let cases = [
        // An unclosed string: a syntax error on the secret line.
        format!("config_version = 1\n[admin]\ntotp_secret = \"{secret}\n"),
        // A bare value with no quotes.
        format!("config_version = 1\n[admin]\ntotp_secret = {secret}\n"),
        // A typo in the key name.
        format!("config_version = 1\n[admin]\ntotp_secrt = \"{secret}\"\n"),
        // A wrong type: serde quotes a string value in its message.
        format!("config_version = 1\n[admin]\napi_tokens = \"{secret}\"\n"),
        format!("config_version = 1\nadmin = \"{secret}\"\n"),
        format!("config_version = 1\n[admin]\npassword_hash = [\"{secret}\"]\n"),
        format!(
            "config_version = 1\n[[admin.api_tokens]]\nname = \"a\"\nhash = 7\nx = \"{secret}\"\n"
        ),
    ];
    for text in &cases {
        let err = Config::from_toml_str(text).unwrap_err().to_string();
        assert!(!err.contains("SECRET"), "{text:?} gives {err}");
        assert!(err.contains("line "), "{text:?} gives {err}");
    }
}

#[test]
fn toml_error_text_gives_line_and_column() {
    let err = Config::from_toml_str("config_version = 1\n[admin]\ntotp_secret = \"ABC\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("line 3, column "), "{err}");
}

#[test]
fn redact_quoted_parts() {
    assert_eq!(
        redact_quoted(r#"invalid type: string "abc", expected u32"#),
        r#"invalid type: string "<redacted>", expected u32"#
    );
    assert_eq!(
        redact_quoted(r#"string "a\"b" and "c""#),
        r#"string "<redacted>" and "<redacted>""#
    );
    assert_eq!(redact_quoted(r#"open "abc"#), r#"open "<redacted>"#);
    assert_eq!(
        redact_quoted("unknown field `totp_secrt`"),
        "unknown field `totp_secrt`"
    );
}

#[test]
fn unicode_domains_load_as_punycode() {
    let text = "config_version = 1\n\
        [blocking]\nspecial_domains = [\"B\u{fc}cher.example.\"]\n\
        [[rules]]\nkind = \"exact\"\naction = \"deny\"\nvalue = \"b\u{fc}cher.example\"\n\
        [[rules]]\nkind = \"regex\"\naction = \"deny\"\nvalue = \"B\u{fc}cher\"\n\
        [[clients]]\nid = \"K\u{fc}che\"\n\
        [[clients]]\nid = \"02:00:00:00:00:0A\"\n\
        [[local_dns.records]]\nname = \"n\u{e4}s.lan\"\ntype = \"A\"\nvalue = \"192.0.2.10\"\n\
        [[local_dns.cnames]]\nname = \"WWW.lan\"\ntarget = \"n\u{e4}s.lan\"\n\
        [[local_dns.conditional_forwarding]]\ncidr = \"192.0.2.0/24\"\nserver = \"192.0.2.1\"\ndomain = \"Lan.\"\n";
    let c = Config::from_toml_str(text).unwrap();
    assert_eq!(c.validate(), []);
    assert_eq!(c.blocking.special_domains, ["xn--bcher-kva.example"]);
    assert_eq!(c.rules[0].value, "xn--bcher-kva.example");
    // A regex is not a domain: it stays as written.
    assert_eq!(c.rules[1].value, "B\u{fc}cher");
    assert_eq!(c.clients[0].id, "xn--kche-0ra");
    // A MAC address is not a host name: it stays as written.
    assert_eq!(c.clients[1].id, "02:00:00:00:00:0A");
    assert_eq!(c.local_dns.records[0].name, "xn--ns-via.lan");
    assert_eq!(c.local_dns.cnames[0].name, "www.lan");
    assert_eq!(c.local_dns.cnames[0].target, "xn--ns-via.lan");
    assert_eq!(
        c.local_dns.conditional_forwarding[0].domain.as_deref(),
        Some("lan")
    );
    // Each loaded domain value is in the form that DomainName::parse accepts as it is.
    for d in [
        &c.blocking.special_domains[0],
        &c.rules[0].value,
        &c.clients[0].id,
        &c.local_dns.records[0].name,
        &c.local_dns.cnames[0].target,
    ] {
        assert_eq!(crate::DomainName::parse(d).unwrap().as_str(), d.as_str());
    }
    let text = c.to_toml_string().unwrap();
    assert_eq!(Config::from_toml_str(&text).unwrap(), c);
}

#[test]
fn normalize_keeps_invalid_values_for_validate() {
    let mut c = Config::default();
    c.rules.push(rule(RuleKind::Exact, "bad domain"));
    c.normalize();
    assert_eq!(c.rules[0].value, "bad domain");
    assert_one_issue(&c, "rules[0].value");
}

// ---------------------------------------------------------------------------------------------
// Property tests.

fn label() -> impl Strategy<Value = String> {
    "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?"
}

fn domain() -> impl Strategy<Value = String> {
    prop::collection::vec(label(), 1..4).prop_map(|v| v.join("."))
}

fn ipv4() -> impl Strategy<Value = String> {
    any::<[u8; 4]>().prop_map(|b| std::net::Ipv4Addr::from(b).to_string())
}

fn ipv6() -> impl Strategy<Value = String> {
    any::<u128>().prop_map(|b| std::net::Ipv6Addr::from(b).to_string())
}

fn ip() -> impl Strategy<Value = String> {
    prop_oneof![ipv4(), ipv6()]
}

fn cidr() -> impl Strategy<Value = String> {
    prop_oneof![
        (ipv4(), 0u8..=32).prop_map(|(a, p)| format!("{a}/{p}")),
        (ipv6(), 0u8..=128).prop_map(|(a, p)| format!("{a}/{p}")),
    ]
}

/// Any text, with control characters and Unicode, to test TOML string escapes.
fn free_text() -> impl Strategy<Value = Option<String>> {
    prop::option::of(any::<String>())
}

fn group_name() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9_.-]{0,15}"
}

fn upstream() -> impl Strategy<Value = Upstream> {
    prop_oneof![
        ipv4().prop_map(|a| Upstream {
            url: a,
            bootstrap: vec![]
        }),
        (ipv4(), 1u16..).prop_map(|(a, p)| Upstream {
            url: format!("udp://{a}:{p}"),
            bootstrap: vec![]
        }),
        ipv6().prop_map(|a| Upstream {
            url: format!("tcp://[{a}]"),
            bootstrap: vec![]
        }),
        (domain(), prop::collection::vec(ip(), 1..3)).prop_map(|(d, b)| Upstream {
            url: format!("tls://{d}:853"),
            bootstrap: b
        }),
        (domain(), prop::collection::vec(ip(), 1..3)).prop_map(|(d, b)| Upstream {
            url: format!("https://{d}/dns-query"),
            bootstrap: b
        }),
    ]
}

fn regex_value() -> impl Strategy<Value = String> {
    prop_oneof![
        domain().prop_map(|d| format!(r"(\.|^){}$", d.replace('.', r"\."))),
        label().prop_map(|l| format!(r"^{l}\d+\.")),
        Just(r"ads\d+\.example".to_owned()),
    ]
}

fn client_id() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<[u8; 6]>().prop_map(|m| crate::net::MacAddr(m).to_string()),
        ip(),
        cidr(),
        "[a-z][a-z0-9-]{0,10}(\\.lan)?",
    ]
}

prop_compose! {
    fn server()(
        dns_listen in prop_oneof![
            Just(vec![AUTO.to_owned()]),
            prop::collection::vec(ip(), 1..3),
        ],
        dns_port in 1u16..,
        doh_enabled in any::<bool>(),
        doh_port in 1u16..,
        admin_enabled in any::<bool>(),
        admin_port in 1u16..,
    ) -> Server {
        let admin_port = if doh_enabled && admin_enabled && doh_port == admin_port {
            admin_port.checked_add(1).unwrap_or(1)
        } else {
            admin_port
        };
        Server {
            dns_listen,
            dns_port,
            doh: DohListener { enabled: doh_enabled, listen: vec![AUTO.to_owned()], port: doh_port },
            admin: AdminListener { enabled: admin_enabled, listen: vec![AUTO.to_owned()], port: admin_port },
        }
    }
}

prop_compose! {
    fn blocking()(
        enabled in any::<bool>(),
        mode in prop_oneof![
            Just(BlockingMode::Null),
            Just(BlockingMode::Nxdomain),
            Just(BlockingMode::Nodata),
            Just(BlockingMode::Ip),
        ],
        ipv4 in prop::option::of(ipv4()),
        ipv6 in prop::option::of(ipv6()),
        blocked_ttl in any::<u32>(),
        special_domains in prop::collection::vec(domain(), 0..4),
        deep_cname_check in any::<bool>(),
    ) -> Blocking {
        let ipv4 = if mode == BlockingMode::Ip && ipv4.is_none() && ipv6.is_none() {
            Some("192.0.2.1".to_owned())
        } else {
            ipv4
        };
        Blocking { enabled, mode, ipv4, ipv6, blocked_ttl, special_domains, deep_cname_check }
    }
}

prop_compose! {
    fn valid_config()(
        server in server(),
        servers in prop::collection::vec(upstream(), 1..4),
        fallback_plain in prop::collection::vec(ipv4(), 0..3),
        timeout_ms in 1..=MAX_UPSTREAM_TIMEOUT_MS,
        blocking in blocking(),
        max_entries in 0..=MAX_CACHE_ENTRIES,
        ttl_a in any::<u32>(),
        ttl_b in any::<u32>(),
        negative_ttl in any::<u32>(),
        auto_local in any::<bool>(),
        allow in prop::collection::vec(cidr(), 0..3),
        queries in any::<u32>(),
        interval_seconds in 1u32..,
        stats in (any::<u32>(), any::<u32>(), 0..=MAX_RECENT_QUERIES),
        extra_groups in prop::collection::btree_set(group_name(), 0..4),
        group_flags in prop::collection::vec((any::<bool>(), free_text()), 5),
        lists in prop::collection::vec(
            (any::<bool>(), any::<bool>(), free_text(), prop::collection::vec(any::<prop::sample::Index>(), 0..3)),
            0..6,
        ),
        refresh_interval_hours in any::<u32>(),
        rules in prop::collection::vec(
            (any::<bool>(), any::<bool>(), any::<bool>(), domain(), regex_value(), free_text(),
             prop::collection::vec(any::<prop::sample::Index>(), 0..3)),
            0..8,
        ),
        clients in prop::collection::btree_map(client_id(), (free_text(), prop::collection::vec(any::<prop::sample::Index>(), 0..3)), 0..6),
        records in prop::collection::vec((domain(), any::<bool>(), ipv4(), ipv6()), 0..4),
        cnames in prop::collection::vec((domain(), domain(), prop::option::of(any::<u32>())), 0..3),
        forwards in prop::collection::vec((any::<bool>(), cidr(), ip(), prop::option::of(domain())), 0..3),
        admin in (any::<bool>(), any::<bool>(), 1u32.., prop::option::of("[a-z/]{1,20}"),
                  prop::collection::btree_set("[a-z]{1,8}", 0..3)),
    ) -> Config {
        let (min_ttl, max_ttl) = (ttl_a.min(ttl_b), ttl_a.max(ttl_b));
        let mut group_names = vec![DEFAULT_GROUP.to_owned()];
        group_names.extend(extra_groups.into_iter().filter(|g| g != DEFAULT_GROUP));
        let groups = group_names
            .iter()
            .zip(group_flags.into_iter().cycle())
            .map(|(name, (enabled, comment))| Group { name: name.clone(), enabled, comment })
            .collect::<Vec<_>>();
        let pick = |idx: &[prop::sample::Index]| -> Vec<String> {
            idx.iter().map(|i| i.get(&group_names).clone()).collect()
        };
        let adlists = lists
            .iter()
            .enumerate()
            .map(|(i, (allow, enabled, comment, g))| Adlist {
                id: u32::try_from(i).unwrap() * 7 + 1,
                url: format!("https://lists.example/{i}.txt"),
                kind: if *allow { ListKind::Allow } else { ListKind::Block },
                enabled: *enabled,
                groups: pick(g),
                comment: comment.clone(),
            })
            .collect();
        let rules = rules
            .iter()
            .map(|(is_regex, allow, enabled, d, re, comment, g)| Rule {
                kind: if *is_regex { RuleKind::Regex } else { RuleKind::Exact },
                action: if *allow { RuleAction::Allow } else { RuleAction::Deny },
                value: if *is_regex { re.clone() } else { d.clone() },
                enabled: *enabled,
                groups: pick(g),
                comment: comment.clone(),
            })
            .collect();
        // Two text forms of one ID are one client, so keep the first of each.
        let mut seen = std::collections::HashSet::new();
        let clients = clients
            .iter()
            .filter(|(id, _)| seen.insert(crate::net::ClientId::parse(id).unwrap()))
            .map(|(id, (comment, g))| Client { id: id.clone(), groups: pick(g), comment: comment.clone() })
            .collect();
        let (pw, totp, session_ttl_seconds, tls, tokens) = admin;
        Config {
            config_version: CURRENT_VERSION,
            server,
            upstreams: Upstreams {
                servers,
                fallback_plain,
                timeout_ms,
            },
            blocking,
            cache: Cache { max_entries, min_ttl, max_ttl, negative_ttl },
            acl: Acl { auto_local, allow },
            rate_limit: RateLimit { queries, interval_seconds },
            stats: Stats {
                flush_interval_seconds: stats.0,
                retention_days: stats.1,
                recent_queries: stats.2,
            },
            lists: Lists { refresh_interval_hours, adlists },
            rules,
            groups,
            clients,
            local_dns: LocalDns {
                records: records
                    .into_iter()
                    .map(|(name, v6, a, aaaa)| LocalRecord {
                        name,
                        record_type: if v6 { RecordType::Aaaa } else { RecordType::A },
                        value: if v6 { aaaa } else { a },
                    })
                    .collect(),
                cnames: cnames
                    .into_iter()
                    .map(|(name, target, ttl)| LocalCname { name, target, ttl })
                    .collect(),
                conditional_forwarding: forwards
                    .into_iter()
                    .map(|(enabled, cidr, server, domain)| ConditionalForward { enabled, cidr, server, domain })
                    .collect(),
            },
            admin: Admin {
                password_hash: if pw { PHC.to_owned() } else { String::new() },
                totp_secret: if totp { "JBSWY3DPEHPK3PXP".to_owned() } else { String::new() },
                session_ttl_seconds,
                tls_cert_path: tls.as_ref().map(|p| format!("{p}.crt")),
                tls_key_path: tls.map(|p| format!("{p}.key")),
                api_tokens: tokens
                    .into_iter()
                    .map(|name| ApiToken { name, hash: format!("sha256:{}", "0".repeat(64)) })
                    .collect(),
            },
        }
    }
}

/// A config with arbitrary text in each text field. Most of these are not valid.
fn wild_config() -> impl Strategy<Value = Config> {
    let text = || "\\PC{0,24}|.{0,24}";
    (
        valid_config(),
        prop::collection::vec(text(), 12),
        any::<u16>(),
        any::<u32>(),
    )
        .prop_map(|(mut c, t, port, num)| {
            let mut t = t.into_iter().cycle();
            let mut next = || t.next().unwrap_or_default();
            c.config_version = num % 3;
            c.server.dns_listen = vec![next(), AUTO.to_owned()];
            c.server.dns_port = port;
            c.upstreams.servers.push(Upstream {
                url: next(),
                bootstrap: vec![next()],
            });
            c.upstreams.fallback_plain.push(next());
            c.upstreams.timeout_ms = num;
            c.blocking.ipv4 = Some(next());
            c.blocking.special_domains.push(next());
            c.acl.allow.push(next());
            c.groups.push(Group {
                name: next(),
                enabled: true,
                comment: None,
            });
            c.rules.push(Rule {
                kind: RuleKind::Regex,
                action: RuleAction::Deny,
                value: next(),
                enabled: true,
                groups: vec![next()],
                comment: None,
            });
            c.rules.push(Rule {
                kind: RuleKind::Exact,
                action: RuleAction::Allow,
                value: next(),
                enabled: true,
                groups: vec![],
                comment: None,
            });
            c.clients.push(Client {
                id: next(),
                groups: vec![],
                comment: None,
            });
            c.local_dns.conditional_forwarding.push(ConditionalForward {
                enabled: true,
                cidr: next(),
                server: next(),
                domain: Some(next()),
            });
            c.admin.password_hash = next();
            c
        })
}

// The case count comes from PROPTEST_CASES (default 256), so CI can raise it.
proptest! {
    #[test]
    fn valid_strategy_gives_valid_configs(c in valid_config()) {
        let issues = c.validate();
        prop_assert!(issues.is_empty(), "issues: {:#?}", issues);
    }

    #[test]
    fn toml_round_trip(c in valid_config()) {
        let text = c.to_toml_string().unwrap();
        let back = Config::from_toml_str(&text).unwrap();
        prop_assert_eq!(back, c);
    }

    #[test]
    fn validate_never_panics(c in wild_config()) {
        let _ = c.validate();
        // A wild config also writes and reads back (when its version is the current one).
        // The load normalizes domain values, so compare with the normalized config.
        let text = c.to_toml_string().unwrap();
        let mut normalized = c.clone();
        normalized.normalize();
        let mut twice = normalized.clone();
        twice.normalize();
        prop_assert_eq!(&twice, &normalized, "normalize is not idempotent");
        if c.config_version == CURRENT_VERSION {
            prop_assert_eq!(Config::from_toml_str(&text).unwrap(), normalized);
        } else {
            prop_assert!(Config::from_toml_str(&text).is_err());
        }
    }

    #[test]
    fn parse_never_panics(text in "\\PC{0,200}") {
        if let Ok(c) = Config::from_toml_str(&text) {
            let _ = c.validate();
        }
    }

    #[test]
    fn parse_near_valid_text_never_panics(c in valid_config(), cut in any::<prop::sample::Index>()) {
        // Cut a valid file at a random place: a common way that a file becomes bad.
        let text = c.to_toml_string().unwrap();
        let mut end = cut.index(text.len() + 1);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if let Ok(c) = Config::from_toml_str(text.get(..end).unwrap_or_default()) {
            let _ = c.validate();
        }
    }
}
