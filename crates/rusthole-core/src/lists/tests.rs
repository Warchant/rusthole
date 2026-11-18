use super::*;
use proptest::prelude::*;

fn names(list: &ParsedList) -> Vec<(String, MatchKind, EntryAction)> {
    list.entries()
        .map(|e| (e.name.to_owned(), e.kind, e.action))
        .collect()
}

fn exact(name: &str) -> (String, MatchKind, EntryAction) {
    (name.to_owned(), MatchKind::Exact, EntryAction::Deny)
}

fn subtree(name: &str, action: EntryAction) -> (String, MatchKind, EntryAction) {
    (name.to_owned(), MatchKind::Subtree, action)
}

const HOSTS_SAMPLE: &str = "\u{feff}# Synthetic hosts list\r\n\
127.0.0.1 localhost\r\n\
127.0.0.1 localhost.localdomain\r\n\
255.255.255.255 broadcasthost\r\n\
::1 localhost ip6-localhost ip6-loopback\r\n\
0.0.0.0 0.0.0.0\r\n\
\r\n\
0.0.0.0 ads.example.com\r\n\
0.0.0.0\tTracker.Example.NET.   # inline comment\r\n\
127.0.0.1 a.example.org b.example.org c.example.org\r\n\
:: v6.example.com\r\n\
0.0.0.0 bad_name!.example.com\r\n\
0.0.0.0\r\n\
0.0.0.0 B\u{fc}cher.example\r\n";

#[test]
fn hosts_format() {
    let list = parse_default(HOSTS_SAMPLE, ListFormat::Hosts).unwrap();
    assert_eq!(
        names(&list),
        [
            exact("ads.example.com"),
            exact("tracker.example.net"),
            exact("a.example.org"),
            exact("b.example.org"),
            exact("c.example.org"),
            exact("v6.example.com"),
            exact("xn--bcher-kva.example"),
        ]
    );
    let s = &list.stats;
    assert_eq!(s.lines, 14);
    assert_eq!(s.valid, 7);
    assert_eq!(s.comments, 2);
    // localhost x2, localhost.localdomain, broadcasthost, ip6-localhost, ip6-loopback.
    assert_eq!(s.skipped.local_name, 6);
    assert_eq!(s.skipped.ip_address, 1);
    assert_eq!(s.invalid, 2);
    assert_eq!(s.invalid_samples.len(), 2);
    assert_eq!(s.invalid_samples[0].line, 12);
    assert!(matches!(
        s.invalid_samples[0].reason,
        InvalidReason::BadName(DomainError::BadChar { ch: '!' })
    ));
    assert_eq!(s.invalid_samples[1].reason, InvalidReason::NoName);
}

#[test]
fn hosts_strict_refuses_domain_lines() {
    let list = parse_default("ads.example.com\n0.0.0.0 x.example\n", ListFormat::Hosts).unwrap();
    assert_eq!(names(&list), [exact("x.example")]);
    assert_eq!(
        list.stats.invalid_samples[0].reason,
        InvalidReason::NotHosts
    );
}

#[test]
fn domains_format() {
    let text = "# Synthetic domain list\n\
ads.example.com\n\
  tracker.example.net  \n\
cdn.example.org # comment\n\
two words.example\n\
*.wild.example\n\
lan\n\
192.0.2.1\n\
\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.example\n";
    let list = parse_default(text, ListFormat::Domains).unwrap();
    assert_eq!(
        names(&list),
        [
            exact("ads.example.com"),
            exact("tracker.example.net"),
            exact("cdn.example.org"),
            exact("xn--e1afmkfd.example"),
        ]
    );
    assert_eq!(list.stats.invalid, 2);
    assert_eq!(
        list.stats.invalid_samples[0].reason,
        InvalidReason::ExtraText
    );
    assert_eq!(list.stats.skipped.single_label, 1);
    assert_eq!(list.stats.skipped.ip_address, 1);
}

#[test]
fn abp_format() {
    let text = "[Adblock Plus 2.0]\n\
! Title: synthetic list\n\
||ads.example.com^\n\
||Tracker.Example.NET^\n\
@@||good.example.com^\n\
||opt.example.com^$third-party\n\
@@||opt2.example.com^$important\n\
example.com##.banner\n\
/ads[0-9]+/\n\
|https://x.example/path\n\
||wild.*.example^\n\
||nocaret.example\n\
||com^\n\
plain.example.com\n\
||ads2.example.com^ # trailing comment\n";
    let list = parse_default(text, ListFormat::Abp).unwrap();
    assert_eq!(
        names(&list),
        [
            subtree("ads.example.com", EntryAction::Deny),
            subtree("tracker.example.net", EntryAction::Deny),
            subtree("good.example.com", EntryAction::Allow),
            subtree("ads2.example.com", EntryAction::Deny),
        ]
    );
    let s = &list.stats;
    assert_eq!(s.comments, 2);
    assert_eq!(s.skipped.abp_options, 2);
    // cosmetic, regex, URL, wildcard, no caret, plain line.
    assert_eq!(s.skipped.abp_unsupported, 6);
    assert_eq!(s.skipped.single_label, 1);
    assert_eq!(s.invalid, 0);
}

#[test]
fn auto_format_mixes_lines() {
    let text = "# mixed\n\
0.0.0.0 hosts.example.com\n\
domain.example.com\n\
||abp.example.com^\n\
@@||allow.example.com^\n\
example.com##.ad\n\
! comment\n";
    let list = parse_default(text, ListFormat::Auto).unwrap();
    assert_eq!(
        names(&list),
        [
            exact("hosts.example.com"),
            exact("domain.example.com"),
            subtree("abp.example.com", EntryAction::Deny),
            subtree("allow.example.com", EntryAction::Allow),
        ]
    );
    assert_eq!(list.stats.skipped.abp_unsupported, 1);
    assert_eq!(list.stats.comments, 2);
}

#[test]
fn auto_format_keeps_hash_comments() {
    let text = "0.0.0.0 ads.example ## note
ads2.example ### note
||ads3.example^ ## note
ads4.example#@#.x
";
    let list = parse_default(text, ListFormat::Auto).unwrap();
    assert_eq!(
        names(&list),
        [
            exact("ads.example"),
            exact("ads2.example"),
            subtree("ads3.example", EntryAction::Deny),
        ]
    );
    // A cosmetic filter has its marker in the first word.
    assert_eq!(list.stats.skipped.abp_unsupported, 1);
}

#[test]
fn long_lines_are_invalid_not_fatal() {
    let limits = ParseLimits {
        max_line_len: 20,
        ..ParseLimits::default()
    };
    let text = format!("ok.example\n{}.example\nok2.example\n", "a".repeat(30));
    let list = parse(&text, ListFormat::Auto, &limits).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list.stats.invalid, 1);
    assert_eq!(
        list.stats.invalid_samples[0].reason,
        InvalidReason::LineTooLong
    );
}

#[test]
fn entry_limit_is_a_clean_error() {
    let limits = ParseLimits {
        max_entries: 2,
        ..ParseLimits::default()
    };
    let text = "a.example\nb.example\nc.example\n";
    assert_eq!(
        parse(text, ListFormat::Domains, &limits),
        Err(ListError::TooManyEntries { limit: 2 })
    );
    // Exactly at the limit is fine.
    assert_eq!(
        parse("a.example\nb.example\n", ListFormat::Domains, &limits)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn size_limit_is_a_clean_error() {
    let limits = ParseLimits {
        max_bytes: 8,
        ..ParseLimits::default()
    };
    assert_eq!(
        parse("abcdefghij", ListFormat::Domains, &limits),
        Err(ListError::TooLarge { limit: 8 })
    );
}

#[test]
fn samples_are_bounded() {
    let text = "bad name\n".repeat(100);
    let list = parse_default(&text, ListFormat::Domains).unwrap();
    assert_eq!(list.stats.invalid, 100);
    assert_eq!(list.stats.invalid_samples.len(), MAX_INVALID_SAMPLES);
    let long = format!("{} x\n", "\u{e9}".repeat(500));
    let list = parse_default(&long, ListFormat::Domains).unwrap();
    assert_eq!(
        list.stats.invalid_samples[0].text.chars().count(),
        MAX_SAMPLE_CHARS
    );
}

#[test]
fn render_formats() {
    let list = parse_default(
        "a.example\n||b.example^\n@@||c.example^\n",
        ListFormat::Auto,
    )
    .unwrap();
    assert_eq!(
        render(list.entries(), ListFormat::Hosts),
        "0.0.0.0 a.example\n"
    );
    assert_eq!(render(list.entries(), ListFormat::Domains), "a.example\n");
    assert_eq!(
        render(list.entries(), ListFormat::Abp),
        "||b.example^\n@@||c.example^\n"
    );
    let auto = render(list.entries(), ListFormat::Auto);
    assert_eq!(
        names(&parse_default(&auto, ListFormat::Auto).unwrap()),
        names(&list)
    );
}

#[test]
fn push_and_debug() {
    let mut list = ParsedList::new();
    list.push(
        &DomainName::parse("x.example").unwrap(),
        MatchKind::Subtree,
        EntryAction::Allow,
    )
    .unwrap();
    assert_eq!(list.len(), 1);
    assert!(!list.is_empty());
    assert_eq!(names(&list), [subtree("x.example", EntryAction::Allow)]);
    let dbg = format!("{list:?}");
    assert!(dbg.contains("entries: 1"));
    assert!(!dbg.contains("x.example"));
}

fn label() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9_-]{0,20}"
}

/// Valid multi-label names with a letter in the top-level label, so no name is skipped.
fn list_name() -> impl Strategy<Value = String> {
    (prop::collection::vec(label(), 1..4), "[a-z][a-z0-9]{1,8}")
        .prop_map(|(mut v, tld)| {
            v.push(tld);
            v.join(".")
        })
        .prop_filter("not local", |s| {
            !LOCAL_NAMES.contains(&s.as_str()) && !s.starts_with("ip6-")
        })
}

proptest! {
    #[test]
    fn hosts_round_trip(names_in in prop::collection::vec(list_name(), 0..40)) {
        let mut list = ParsedList::new();
        for n in &names_in {
            list.push(&DomainName::parse(n).unwrap(), MatchKind::Exact, EntryAction::Deny).unwrap();
        }
        for format in [ListFormat::Hosts, ListFormat::Domains, ListFormat::Auto] {
            let text = render(list.entries(), format);
            let back = parse_default(&text, format).unwrap();
            prop_assert_eq!(names(&back), names(&list));
            prop_assert_eq!(back.stats.invalid, 0);
        }
    }

    #[test]
    fn abp_round_trip(entries in prop::collection::vec((list_name(), any::<bool>()), 0..40)) {
        let mut list = ParsedList::new();
        for (n, allow) in &entries {
            let action = if *allow { EntryAction::Allow } else { EntryAction::Deny };
            list.push(&DomainName::parse(n).unwrap(), MatchKind::Subtree, action).unwrap();
        }
        let text = render(list.entries(), ListFormat::Abp);
        let back = parse_default(&text, ListFormat::Abp).unwrap();
        prop_assert_eq!(names(&back), names(&list));
    }

    #[test]
    fn parse_never_panics_and_is_bounded(text in "\\PC{0,400}", fmt in 0u8..4) {
        let format = [ListFormat::Auto, ListFormat::Hosts, ListFormat::Domains, ListFormat::Abp][usize::from(fmt)];
        let limits = ParseLimits { max_entries: 5, max_line_len: 64, ..ParseLimits::default() };
        if let Ok(list) = parse(&text, format, &limits) {
            prop_assert!(list.len() <= 5);
            prop_assert!(list.stats.invalid_samples.len() <= MAX_INVALID_SAMPLES);
            prop_assert_eq!(list.entries().count(), list.len());
            for e in list.entries() {
                prop_assert!(DomainName::parse(e.name).is_ok());
                prop_assert!(e.name.contains('.'));
            }
        }
    }
}
