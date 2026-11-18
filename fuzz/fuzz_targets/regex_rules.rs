#![no_main]
//! Fuzz regex rules: any pattern compiles with the limits or fails cleanly, and a compiled
//! pattern matches names in linear time. The patterns also go through the engine build.

use libfuzzer_sys::fuzz_target;
use rusthole_core::config::{Config, Rule, RuleAction, RuleKind};
use rusthole_core::pattern::{MAX_PATTERN_LEN, compile_rule_regex};
use rusthole_core::{DomainName, PolicyEngine};

/// At most this many patterns go into one engine.
const MAX_PATTERNS: usize = 8;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut config = Config::default();
    for (i, pattern) in text.split('\n').take(MAX_PATTERNS).enumerate() {
        if pattern.len() > MAX_PATTERN_LEN + 16 {
            continue;
        }
        if let Ok(re) = compile_rule_regex(pattern) {
            for name in ["ads.example.com", "A.B.C", "x", "", "xn--bcher-kva.example"] {
                let _ = re.is_match(name);
            }
        }
        config.rules.push(Rule {
            kind: RuleKind::Regex,
            action: if i % 2 == 0 {
                RuleAction::Deny
            } else {
                RuleAction::Allow
            },
            value: pattern.to_owned(),
            enabled: true,
            groups: vec!["default".into()],
            comment: None,
        });
    }
    let (engine, _report) = PolicyEngine::build(&config, std::iter::empty());
    let groups = engine.default_groups();
    for name in ["ads.example.com", "tracker.example.net", "a.b"] {
        let name = DomainName::parse(name).expect("valid name");
        let _ = engine.check(&groups, true, &name);
        let _ = engine.explain(None, &name);
    }
});
