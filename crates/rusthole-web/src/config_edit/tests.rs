use proptest::prelude::*;
use rusthole_core::config::{Group, Rule, RuleAction, RuleKind};

use super::*;

const TEXT: &str = r#"# Header comment: keep me.
config_version = 1

[server]
dns_port = 53 # port comment
admin.port = 8443

[cache]
# cache comment
max_entries = 10000

# rule-a comment
[[rules]]
kind = "exact"
action = "deny"
value = "a.example"

# rule-b comment
[[rules]]
kind = "regex"
action = "deny"
value = '^ads\.' # regex comment

[[groups]]
name = "default"
"#;

fn rule(value: &str) -> Rule {
    Rule {
        id: None,
        kind: RuleKind::Exact,
        action: RuleAction::Deny,
        value: value.to_owned(),
        enabled: true,
        groups: vec!["default".to_owned()],
        comment: None,
        created_at: None,
        updated_at: None,
    }
}

fn loaded(text: &str) -> (Config, Config) {
    let file = Config::from_toml_str(text).unwrap();
    let mut mem = file.clone();
    mem.assign_ids();
    (file, mem)
}

#[test]
fn unchanged_config_keeps_the_text() {
    let (file, mem) = loaded(TEXT);
    let out = render(TEXT, &file, &file, &file).unwrap();
    assert_eq!(out, TEXT);
    // With the ids in memory, the first write adds them and changes nothing else.
    let out = render(TEXT, &file, &mem, &mem).unwrap();
    assert!(out.contains("# rule-a comment"));
    assert!(out.contains("# regex comment"));
    let again = Config::from_toml_str(&out).unwrap();
    assert_eq!(again, mem);
}

#[test]
fn a_change_keeps_comments_and_order() {
    let (file, mem) = loaded(TEXT);
    let mut new = mem.clone();
    new.cache.max_entries = 20_000;
    new.rules.remove(0);
    new.rules.push(Rule {
        id: Some(3),
        ..rule("c.example")
    });
    new.groups.push(Group {
        id: Some(1),
        name: "kids".to_owned(),
        enabled: true,
        comment: Some("Tablets".to_owned()),
    });
    let out = render(TEXT, &file, &mem, &new).unwrap();
    assert!(out.starts_with("# Header comment: keep me.\n"));
    assert!(out.contains("dns_port = 53 # port comment"));
    assert!(out.contains("# cache comment\nmax_entries = 20000"));
    assert!(!out.contains("rule-a comment"));
    assert!(out.contains("# rule-b comment"));
    assert!(out.contains("# regex comment"));
    assert!(out.contains("c.example"));
    let back = Config::from_toml_str(&out).unwrap();
    assert_eq!(back, new);
    // The cache section stays above the rules.
    assert!(out.find("[cache]").unwrap() < out.find("[[rules]]").unwrap());
}

#[test]
fn a_section_that_the_file_does_not_write_gets_only_the_changed_keys() {
    let text = "config_version = 1\n";
    let (file, mem) = loaded(text);
    let mut new = mem.clone();
    new.blocking.blocked_ttl = 10;
    let out = render(text, &file, &mem, &new).unwrap();
    assert!(out.contains("[blocking]\nblocked_ttl = 10\n"), "{out}");
    assert!(!out.contains("special_domains"));
    assert!(!out.contains("[cache]"));
}

#[test]
fn removed_option_and_bad_text() {
    let text = "config_version = 1\n[admin]\npassword_hash = \"$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo\"\n";
    let (file, mem) = loaded(text);
    let mut new = mem.clone();
    new.admin.password_hash.clear();
    let out = render(text, &file, &mem, &new).unwrap();
    assert!(!out.contains("password_hash"));
    // A parse error never quotes the text.
    let bad = "config_version = 1\nsecret = \"hunter2";
    let err = render(bad, &file, &mem, &new).unwrap_err().to_string();
    assert!(!err.contains("hunter2"), "{err}");
}

#[test]
fn edit_file_and_atomic_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, TEXT).unwrap();
    edit_file(&path, |c| c.blocking.blocked_ttl = 7).unwrap();
    let out = std::fs::read_to_string(&path).unwrap();
    assert!(out.contains("# Header comment: keep me."));
    assert!(out.contains("blocked_ttl = 7"));
    // The file has no ids: edit_file does not add them.
    assert!(!out.contains("id = "));
    // An invalid change writes nothing.
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        edit_file(&path, |c| c.groups.clear()),
        Err(EditError::Invalid(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "no temp file stays: {names:?}");
}

#[cfg(unix)]
#[test]
fn written_file_has_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    // Some file systems (for example a Windows drive in WSL) keep no Unix mode. Skip the
    // check there; CI runs it on a real Linux file system.
    let probe = dir.path().join("probe");
    std::fs::write(&probe, b"x").unwrap();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o640)).unwrap();
    if std::fs::metadata(&probe).unwrap().permissions().mode() & 0o777 != 0o640 {
        return;
    }
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, TEXT).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    edit_file(&path, |c| c.blocking.blocked_ttl = 9).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[tokio::test]
async fn store_detects_a_hand_edit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, TEXT).unwrap();
    let (store, cfg) = ConfigStore::open(&path).unwrap();
    assert!(cfg.has_all_ids());
    let w = store
        .update(|c| {
            c.cache.max_entries = 5;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(w.new.cache.max_entries, 5);
    let disk = std::fs::read_to_string(&path).unwrap();
    assert!(disk.contains("# rule-b comment"));
    // The first write wrote all ids.
    assert!(Config::from_toml_str(&disk).unwrap().has_all_ids());

    // A hand edit: the next write is refused, and the store reads the file again.
    std::fs::write(&path, disk.replace("max_entries = 5", "max_entries = 6")).unwrap();
    let err = store
        .update(|c| {
            c.cache.max_entries = 7;
            Ok(())
        })
        .await
        .unwrap_err();
    match err {
        WriteError::Conflict {
            reloaded: Some((old, new)),
        } => {
            assert_eq!(old.cache.max_entries, 5);
            assert_eq!(new.cache.max_entries, 6);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(store.get().cache.max_entries, 6);
    // The retry works.
    store
        .update(|c| {
            c.cache.max_entries = 7;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("max_entries = 7")
    );
}

#[tokio::test]
async fn store_refuses_an_invalid_change() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, TEXT).unwrap();
    let (store, _) = ConfigStore::open(&path).unwrap();
    let err = store
        .update(|c| {
            c.cache.min_ttl = 10;
            c.cache.max_ttl = 1;
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(matches!(err, WriteError::Api(e) if e.code == "validation_failed"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), TEXT);
}

#[derive(Debug, Clone)]
enum Op {
    AddRule(u8),
    RemoveRule(usize),
    ToggleRule(usize),
    SetCache(u32),
    AddGroup(u8),
    RemoveGroup(usize),
    SetComment(usize, Option<u8>),
    SetTtl(u32),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        any::<u8>().prop_map(Op::AddRule),
        (0usize..8).prop_map(Op::RemoveRule),
        (0usize..8).prop_map(Op::ToggleRule),
        (0u32..1_000_000).prop_map(Op::SetCache),
        any::<u8>().prop_map(Op::AddGroup),
        (1usize..5).prop_map(Op::RemoveGroup),
        ((0usize..8), prop::option::of(any::<u8>())).prop_map(|(i, c)| Op::SetComment(i, c)),
        (0u32..3600).prop_map(Op::SetTtl),
    ]
}

/// The next id: one more than every id that was used before (the server never uses an id
/// again, see `AppState::next_id`).
fn fresh_id(high: &mut u32) -> u32 {
    *high += 1;
    *high
}

fn apply(c: &mut Config, op: &Op, high: &mut u32) {
    match op {
        Op::AddRule(n) => {
            let id = Some(fresh_id(high));
            let value = format!("r{n}.example");
            if c.rules.iter().all(|r| r.value != value) {
                c.rules.push(Rule { id, ..rule(&value) });
            }
        }
        Op::RemoveRule(i) => {
            if *i < c.rules.len() {
                c.rules.remove(*i);
            }
        }
        Op::ToggleRule(i) => {
            if let Some(r) = c.rules.get_mut(*i) {
                r.enabled = !r.enabled;
            }
        }
        Op::SetCache(n) => c.cache.max_entries = *n,
        Op::AddGroup(n) => {
            let name = format!("g{n}");
            if c.groups.iter().all(|g| g.name != name) {
                let id = Some(fresh_id(high));
                c.groups.push(Group {
                    id,
                    name,
                    enabled: true,
                    comment: None,
                });
            }
        }
        Op::RemoveGroup(i) => {
            if *i < c.groups.len() && c.groups[*i].name != "default" {
                let name = c.groups.remove(*i).name;
                for r in &mut c.rules {
                    r.groups.retain(|g| *g != name);
                }
            }
        }
        Op::SetComment(i, v) => {
            if let Some(r) = c.rules.get_mut(*i) {
                r.comment = v.map(|n| format!("note {n}"));
            }
        }
        Op::SetTtl(t) => c.blocking.blocked_ttl = *t,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).map_or(128, |env: u32| env.max(128))
    ))]

    /// For any chain of edits, each written text parses to the wanted config, and the
    /// comments of items that still exist stay in the text.
    #[test]
    fn edits_round_trip_and_keep_comments(ops in prop::collection::vec(prop::collection::vec(op(), 1..4), 1..6)) {
        let mut text = TEXT.to_owned();
        let (mut file, mut mem) = loaded(&text);
        // Ids of rules and groups share one counter here; that is enough for the test.
        let mut high = 100;
        for batch in ops {
            let mut new = mem.clone();
            for o in &batch {
                apply(&mut new, o, &mut high);
            }
            new.assign_ids();
            prop_assume!(new.validate().is_empty());
            let out = render(&text, &file, &mem, &new).unwrap();
            let back = Config::from_toml_str(&out).unwrap();
            prop_assert_eq!(&back, &new);
            prop_assert!(out.starts_with("# Header comment: keep me.\n"));
            prop_assert!(out.contains("# cache comment"));
            let b_alive = new.rules.iter().any(|r| r.value == "^ads\\.");
            prop_assert_eq!(out.contains("# rule-b comment"), b_alive);
            text = out;
            file = back;
            mem = new;
        }
    }
}

/// An edit through the API model (the functions that the handlers run).
#[derive(Debug, Clone)]
enum ApiOp {
    CreateRule(u8, bool),
    PatchRule(usize, bool),
    DeleteRule(usize),
    CreateGroup(u8),
    DeleteGroup(usize),
    CreateClient(u8),
    CreateRecord(u8),
    Settings(u32, u32),
}

fn api_op() -> impl Strategy<Value = ApiOp> {
    prop_oneof![
        (any::<u8>(), any::<bool>()).prop_map(|(n, r)| ApiOp::CreateRule(n, r)),
        ((0usize..6), any::<bool>()).prop_map(|(i, e)| ApiOp::PatchRule(i, e)),
        (0usize..6).prop_map(ApiOp::DeleteRule),
        any::<u8>().prop_map(ApiOp::CreateGroup),
        (0usize..4).prop_map(ApiOp::DeleteGroup),
        any::<u8>().prop_map(ApiOp::CreateClient),
        any::<u8>().prop_map(ApiOp::CreateRecord),
        ((0u32..50_000), (0u32..100)).prop_map(|(c, q)| ApiOp::Settings(c, q)),
    ]
}

fn apply_api(c: &mut Config, op: &ApiOp, high: &mut u32) -> Result<(), crate::error::ApiError> {
    use crate::model;
    let now = "2026-11-17T08:30:00Z";
    match op {
        ApiOp::CreateRule(n, regex) => {
            let req = model::RuleCreate {
                kind: if *regex {
                    RuleKind::Regex
                } else {
                    RuleKind::Exact
                },
                action: RuleAction::Deny,
                pattern: if *regex {
                    format!("^r{n}\\.")
                } else {
                    format!("r{n}.example")
                },
                enabled: None,
                groups: None,
                comment: Some(format!("api {n}")),
            };
            model::create_rule(c, req, fresh_id(high), now)
        }
        ApiOp::PatchRule(i, enabled) => match c.rules.get(*i).and_then(|r| r.id) {
            Some(id) => model::patch_rule(
                c,
                id,
                model::RulePatch {
                    enabled: Some(*enabled),
                    ..model::RulePatch::default()
                },
                now,
            ),
            None => Ok(()),
        },
        ApiOp::DeleteRule(i) => {
            if *i < c.rules.len() {
                c.rules.remove(*i);
            }
            Ok(())
        }
        ApiOp::CreateGroup(n) => model::create_group(
            c,
            model::GroupCreate {
                name: format!("g{n}"),
                enabled: None,
                comment: None,
            },
            fresh_id(high),
        ),
        ApiOp::DeleteGroup(i) => match c.groups.get(*i).and_then(|g| g.id) {
            Some(id) => model::delete_group(c, id),
            None => Ok(()),
        },
        ApiOp::CreateClient(n) => model::create_client(
            c,
            model::ClientCreate {
                match_: format!("192.0.2.{n}"),
                groups: None,
                comment: None,
            },
            fresh_id(high),
        ),
        ApiOp::CreateRecord(n) => model::create_record(
            c,
            model::RecordCreate {
                name: format!("h{n}.lan"),
                record_type: rusthole_core::config::RecordType::A,
                address: format!("192.0.2.{n}"),
                comment: None,
                enabled: None,
            },
            fresh_id(high),
        ),
        ApiOp::Settings(cache, qps) => crate::settings::apply_patch(
            c,
            crate::settings::SettingsPatch {
                cache: Some(crate::settings::CacheS {
                    enabled: *cache > 0,
                    max_entries: *cache,
                    min_ttl: 0,
                    max_ttl: 86_400,
                    negative_ttl: 300,
                }),
                rate_limit: Some(crate::settings::RateLimitS {
                    queries_per_second: *qps,
                    burst: 500,
                }),
                ..crate::settings::SettingsPatch::default()
            },
        ),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).map_or(96, |env: u32| env.max(96))
    ))]

    /// For any chain of edits through the API model, each written text parses to the same
    /// config, and the comments that are not part of an edited item stay.
    #[test]
    fn api_model_edits_round_trip_and_keep_comments(ops in prop::collection::vec(api_op(), 1..12)) {
        let mut text = TEXT.to_owned();
        let (mut file, mut mem) = loaded(&text);
        let mut high = 100;
        for op in ops {
            let mut new = mem.clone();
            if apply_api(&mut new, &op, &mut high).is_err() {
                // The API refuses the edit (for example a duplicate): nothing is written.
                continue;
            }
            new.normalize();
            new.assign_ids();
            if !new.validate().is_empty() {
                continue;
            }
            let out = render(&text, &file, &mem, &new).unwrap();
            let back = Config::from_toml_str(&out).unwrap();
            prop_assert_eq!(&back, &new);
            prop_assert!(out.starts_with("# Header comment: keep me.\n"));
            prop_assert!(out.contains("dns_port = 53 # port comment"));
            prop_assert!(out.contains("# cache comment"));
            let b_alive = new.rules.iter().any(|r| r.value == "^ads\\.");
            prop_assert_eq!(out.contains("# rule-b comment"), b_alive);
            text = out;
            file = back;
            mem = new;
        }
    }
}
