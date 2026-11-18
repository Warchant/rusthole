#![no_main]
//! Fuzz the policy engine: arbitrary rules, lists and names. Build and check must never
//! panic, and some invariants must hold.
//!
//! Input: lines. The first character selects the kind of line:
//! `e`/`E` exact deny/allow rule, `r`/`R` regex deny/allow rule, `0`-`3` a line of list 0-3,
//! `q` a query name, `g` the groups of the next rules (`d` default, `k` kids, `o` off),
//! `a` makes list 3 an allow list. Other lines are ignored.

use libfuzzer_sys::fuzz_target;
use rusthole_core::config::{Adlist, Config, Group, ListKind, Rule, RuleAction, RuleKind};
use rusthole_core::lists::{ListFormat, ParseLimits, parse};
use rusthole_core::policy::Action;
use rusthole_core::{DomainName, PolicyEngine};

const MAX_RULES: usize = 32;
const MAX_QUERIES: usize = 16;

fn groups_from(spec: &str) -> Vec<String> {
    spec.chars()
        .filter_map(|c| match c {
            'd' => Some("default"),
            'k' => Some("kids"),
            'o' => Some("off"),
            _ => None,
        })
        .map(str::to_owned)
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut config = Config::default();
    config.groups = ["default", "kids", "off"]
        .iter()
        .map(|n| Group {
            name: (*n).to_owned(),
            enabled: *n != "off",
            comment: None,
        })
        .collect();
    let mut lists = vec![String::new(); 4];
    let mut queries = Vec::new();
    let mut groups = vec!["default".to_owned()];
    let mut allow_list = false;
    for line in text.lines() {
        let mut chars = line.chars();
        let Some(tag) = chars.next() else { continue };
        let rest = chars.as_str();
        match tag {
            'e' | 'E' | 'r' | 'R' if config.rules.len() < MAX_RULES => config.rules.push(Rule {
                kind: if tag.eq_ignore_ascii_case(&'e') {
                    RuleKind::Exact
                } else {
                    RuleKind::Regex
                },
                action: if tag.is_ascii_uppercase() {
                    RuleAction::Allow
                } else {
                    RuleAction::Deny
                },
                value: rest.to_owned(),
                enabled: true,
                groups: groups.clone(),
                comment: None,
            }),
            '0'..='3' => {
                let i = usize::from(tag as u8 - b'0');
                lists[i].push_str(rest);
                lists[i].push('\n');
            }
            'q' if queries.len() < MAX_QUERIES => queries.push(rest.to_owned()),
            'g' => groups = groups_from(rest),
            'a' => allow_list = true,
            _ => {}
        }
    }
    config.lists.adlists = (0..4u32)
        .map(|id| Adlist {
            id,
            url: format!("https://lists.example/{id}.txt"),
            kind: if id == 3 && allow_list {
                ListKind::Allow
            } else {
                ListKind::Block
            },
            enabled: true,
            groups: if id == 1 {
                vec!["kids".into()]
            } else {
                vec!["default".into()]
            },
            comment: None,
        })
        .collect();
    let limits = ParseLimits {
        max_entries: 256,
        ..ParseLimits::default()
    };
    let parsed = lists.iter().enumerate().filter_map(|(id, t)| {
        let id = u32::try_from(id).ok()?;
        parse(t, ListFormat::Auto, &limits).ok().map(|l| (id, l))
    });
    // A fixed seed, so that a crash input gives the same table again.
    let (engine, _report) = PolicyEngine::build_with_seed(&config, parsed, [1, 2]);
    let default = engine.default_groups();
    let kids = engine.groups_named(["kids"]);
    let none = engine.client_groups::<&str>(Some(&[]));
    let names: Vec<DomainName> = queries
        .iter()
        .filter_map(|q| DomainName::parse_idn(q).ok())
        .collect();
    for name in &names {
        let d = engine.check(&default, true, name);
        // Blocking off always allows.
        assert_eq!(engine.check(&default, false, name).action, Action::Allow);
        // A client with no group is never blocked by a rule or a list.
        let n = engine.check(&none, true, name);
        assert!(!matches!(n.action, Action::Block(_)));
        let _ = engine.check(&kids, true, name);
        // explain lists something when the name is blocked.
        if d.is_blocked() {
            assert!(!engine.explain(Some(&default), name).is_empty());
        }
        let _ = engine.explain(None, name);
    }
    // The chain is blocked if and only if some name in it is blocked.
    let chain = engine.check_chain(&default, true, &names);
    let any = names
        .iter()
        .any(|n| engine.check(&default, true, n).is_blocked());
    assert_eq!(chain.is_blocked(), any);
});
