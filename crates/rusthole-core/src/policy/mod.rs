//! The policy engine: it decides if a name is blocked for a client.
//!
//! The engine is pure and immutable. [`PolicyEngine::build`] makes it from the config and the
//! parsed lists. The DNS path can then share it between threads and swap it as one unit when
//! the lists or the config change.
//!
//! The decision order follows Pi-hole v6. docs/POLICY.md has the full description:
//!
//! 1. Blocking is off (the toggle) → allow.
//! 2. Exact allow rule, then regex allow rule → allow.
//! 3. Special domain (amendment A3) → its fixed answer (NXDOMAIN).
//! 4. Exact deny rule → block.
//! 5. Allow-kind list → allow.
//! 6. Block list entry → block.
//! 7. Regex deny rule → block.
//! 8. Else → allow.
//!
//! In a CNAME chain, the first name with an allow match (steps 2 and 5) or a block decides
//! the full answer (the Pi-hole rule, see [`PolicyEngine::check_chain`]).
//!
//! A rule or a list applies to a client only through a shared, enabled group.

mod set;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use regex::{Regex, RegexSet, RegexSetBuilder};

use crate::config::{
    Blocking, BlockingMode, Config, ConfigIssue, DEFAULT_GROUP, ListKind, RuleAction, RuleKind,
};
use crate::domain::DomainName;
use crate::lists::{MatchKind, ParsedList};
use crate::pattern::compile_rule_regex;
use set::{DomainSet, DomainSetBuilder, Elem, HashKey, MAX_LISTS};
pub use set::{MAX_PROBE, MAX_REHASH};

/// Size limit of the compiled program of all regex rules of one action, in bytes. When the
/// set goes over it, the engine matches each regex alone (slower, same result).
pub const REGEX_SET_SIZE_LIMIT: usize = 16 * 1024 * 1024;
/// Size limit of the lazy DFA cache of one regex set, in bytes.
pub const REGEX_SET_DFA_SIZE_LIMIT: usize = 4 * 1024 * 1024;
/// Maximum number of lists in one engine.
pub const MAX_ENGINE_LISTS: usize = MAX_LISTS;

/// The groups of one client, resolved for one engine.
///
/// Make it with [`PolicyEngine::client_groups`] (or [`PolicyEngine::groups_named`]). It is
/// valid only for the engine that made it: make it again after each rebuild. It holds only
/// enabled groups.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupSet {
    words: Vec<u64>,
}

impl GroupSet {
    /// No group: no list and no rule applies.
    pub fn none() -> Self {
        Self::default()
    }

    /// True when the set holds no group.
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    fn insert(&mut self, group: usize) {
        let word = group / 64;
        if self.words.len() <= word {
            self.words.resize(word + 1, 0);
        }
        if let Some(w) = self.words.get_mut(word) {
            *w |= 1u64 << (group % 64);
        }
    }
}

/// True when the group mask `mask` and the client groups share a group.
fn intersects(mask: &[u64], groups: &GroupSet) -> bool {
    mask.iter().zip(&groups.words).any(|(a, b)| a & b != 0)
}

/// How rusthole answers a blocked name. It comes from `blocking.mode`. The DNS layer makes the
/// records: a blocked name is blocked for all query types (amendment A3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReply {
    /// `0.0.0.0` for A, `::` for AAAA, NODATA for other types.
    Null,
    /// NXDOMAIN.
    Nxdomain,
    /// NODATA.
    Nodata,
    /// The given address for A or AAAA. A missing address gives NODATA for its type.
    Ip {
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    },
}

/// The fixed answer of a special domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialReply {
    /// NXDOMAIN (Firefox DoH canary, iCloud Private Relay).
    Nxdomain,
}

/// What to do with a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Forward or answer as usual.
    Allow,
    /// Answer with the block reply.
    Block(BlockReply),
    /// Answer with the fixed answer of a special domain.
    Special(SpecialReply),
}

/// The ids of the lists that matched: the first four, and a flag when more matched.
/// It does not allocate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListIds {
    ids: [u32; 4],
    len: u8,
    more: bool,
}

impl ListIds {
    /// The list ids (at most four).
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.ids.iter().take(usize::from(self.len)).copied()
    }

    /// The first list id.
    pub fn first(&self) -> Option<u32> {
        self.iter().next()
    }

    /// True when no list matched.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when more than four lists matched. [`PolicyEngine::explain`] gives all.
    pub fn has_more(&self) -> bool {
        self.more
    }

    fn push(&mut self, id: u32) {
        if self.iter().any(|x| x == id) {
            return;
        }
        if let Some(slot) = self.ids.get_mut(usize::from(self.len)) {
            *slot = id;
            self.len += 1;
        } else {
            self.more = true;
        }
    }
}

/// Why the engine gave its action. A rule is named by its index in `rules` of the config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Nothing matched.
    NoMatch,
    /// Blocking is off.
    BlockingDisabled,
    /// The name is in `blocking.special_domains`.
    SpecialDomain,
    /// An exact allow rule matched.
    ExactAllow { rule: usize },
    /// A regex allow rule matched.
    RegexAllow { rule: usize },
    /// An allow-kind list matched.
    AllowList { lists: ListIds },
    /// An exact deny rule matched.
    ExactDeny { rule: usize },
    /// A block list matched.
    BlockList { lists: ListIds },
    /// A regex deny rule matched.
    RegexDeny { rule: usize },
}

impl Reason {
    /// True for an allow match: an exact allow rule, a regex allow rule or an allow-kind
    /// list. In a CNAME chain, such a match allows the full answer (the Pi-hole rule).
    /// [`Reason::NoMatch`] and [`Reason::BlockingDisabled`] are not allow matches.
    pub fn is_allow_match(&self) -> bool {
        matches!(
            self,
            Self::ExactAllow { .. } | Self::RegexAllow { .. } | Self::AllowList { .. }
        )
    }
}

/// The result of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// What to do.
    pub action: Action,
    /// Why.
    pub reason: Reason,
    /// The index of the name that decided, in the chain given to
    /// [`PolicyEngine::check_chain`]. 0 is the query name; a higher value is a CNAME target.
    pub name_index: usize,
}

impl Decision {
    /// True when the action is not [`Action::Allow`].
    pub fn is_blocked(&self) -> bool {
        !matches!(self.action, Action::Allow)
    }
}

/// What a match in [`PolicyEngine::explain`] comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchSource {
    /// `blocking.special_domains`.
    SpecialDomain,
    /// An exact rule (index in `rules` of the config).
    ExactRule { rule: usize },
    /// A regex rule (index in `rules` of the config).
    RegexRule { rule: usize },
    /// A list entry.
    List { id: u32, kind: MatchKind },
}

/// The effect of one match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchEffect {
    Allow,
    Deny,
    Special,
}

/// One match of [`PolicyEngine::explain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The rule or list.
    pub source: MatchSource,
    /// Allow, deny or special.
    pub effect: MatchEffect,
    /// The name that matched: the query name, or a parent for a subtree entry.
    pub matched: String,
    /// The enabled groups of the rule or list. Empty for a special domain (all clients).
    pub groups: Vec<String>,
}

/// What the build did with one list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListStatus {
    /// The list is in the engine.
    Used,
    /// The list is disabled in the config. Its data was dropped.
    Disabled,
    /// No list in the config has this id. Its data was dropped.
    NotInConfig,
    /// The id came a second time. The second data was dropped.
    Duplicate,
    /// More than [`MAX_ENGINE_LISTS`] lists.
    TooManyLists,
    /// The set is full (too many names). The list is in the engine only in part.
    SetFull,
}

/// One list in a [`BuildReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListBuildInfo {
    /// The list id.
    pub id: u32,
    /// Entries in the parsed list.
    pub entries: usize,
    /// Names that this list added to the set (names that no earlier list had).
    pub new_domains: usize,
    /// `@@` allow entries of a block-kind list. The engine does not use them: only an
    /// allow-kind list can allow a name.
    pub ignored_allow_entries: usize,
    /// What the build did.
    pub status: ListStatus,
}

/// The result of a build.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildReport {
    /// One item for each list that the iterator gave, in order.
    pub lists: Vec<ListBuildInfo>,
    /// Enabled lists of the config that the iterator did not give.
    pub missing_lists: Vec<u32>,
    /// Config values that the engine could not use. The build skipped them.
    pub issues: Vec<ConfigIssue>,
    /// Unique names in the compiled set.
    pub unique_domains: usize,
    /// Entries of all used lists.
    pub entries: usize,
    /// Heap bytes of the engine after the build (an estimate from capacities).
    pub memory_bytes: usize,
    /// Highest heap use of the set during the build, including the list buffer that was being
    /// added (an estimate from capacities).
    pub peak_build_bytes: usize,
    /// New hash keys that the compiled set took, because a name probed more than
    /// [`MAX_PROBE`] table entries. Not zero means very bad luck or a list with names that
    /// were made to collide. At [`MAX_REHASH`], the set has no probe limit.
    pub set_rehashes: u32,
    /// The longest probe in the hash table of the compiled set. A lookup probes at most
    /// this plus one entries for each name.
    pub set_max_probe: usize,
}

impl BuildReport {
    fn issue(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.issues.push(ConfigIssue {
            path: path.into(),
            message: message.into(),
        });
    }
}

#[derive(Debug, Clone)]
struct GroupInfo {
    name: String,
    enabled: bool,
}

#[derive(Debug, Clone, Copy)]
struct ListInfo {
    id: u32,
}

#[derive(Debug, Clone, Copy)]
struct RuleInfo {
    /// Index in `rules` of the config.
    index: usize,
}

enum Matcher {
    Empty,
    Set(RegexSet),
    Each(Vec<Regex>),
}

/// The regex rules of one action.
struct RegexRules {
    matcher: Matcher,
    /// The compiled rule id of each pattern.
    rules: Vec<u32>,
}

impl fmt::Debug for RegexRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.matcher {
            Matcher::Empty => "empty",
            Matcher::Set(_) => "set",
            Matcher::Each(_) => "each",
        };
        f.debug_struct("RegexRules")
            .field("matcher", &kind)
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl RegexRules {
    fn new(compiled: Vec<(u32, Regex)>, path: &str, report: &mut BuildReport) -> Self {
        Self::with_limit(compiled, REGEX_SET_SIZE_LIMIT, path, report)
    }

    fn with_limit(
        compiled: Vec<(u32, Regex)>,
        size_limit: usize,
        path: &str,
        report: &mut BuildReport,
    ) -> Self {
        if compiled.is_empty() {
            return Self {
                matcher: Matcher::Empty,
                rules: Vec::new(),
            };
        }
        let rules = compiled.iter().map(|(id, _)| *id).collect();
        let built = RegexSetBuilder::new(compiled.iter().map(|(_, r)| r.as_str()))
            .case_insensitive(true)
            .size_limit(size_limit)
            .dfa_size_limit(REGEX_SET_DFA_SIZE_LIMIT)
            .build();
        let matcher = if let Ok(set) = built {
            Matcher::Set(set)
        } else {
            report.issue(
                path,
                "the regex rules together go over the set size limit; \
                 each regex is matched alone (slower)",
            );
            Matcher::Each(compiled.into_iter().map(|(_, r)| r).collect())
        };
        Self { matcher, rules }
    }

    fn is_match(&self, name: &str) -> bool {
        match &self.matcher {
            Matcher::Empty => false,
            Matcher::Set(set) => set.is_match(name),
            Matcher::Each(all) => all.iter().any(|r| r.is_match(name)),
        }
    }

    /// Calls `f` with the compiled rule id of each matching pattern, in pattern order.
    /// Stops when `f` returns true.
    fn find_match(&self, name: &str, mut f: impl FnMut(u32) -> bool) {
        if !self.is_match(name) {
            return;
        }
        match &self.matcher {
            Matcher::Empty => {}
            Matcher::Set(set) => {
                for i in &set.matches(name) {
                    if self.rules.get(i).is_some_and(|id| f(*id)) {
                        return;
                    }
                }
            }
            Matcher::Each(all) => {
                for (i, r) in all.iter().enumerate() {
                    if r.is_match(name) && self.rules.get(i).is_some_and(|id| f(*id)) {
                        return;
                    }
                }
            }
        }
    }
}

/// The compiled policy. See the module documentation.
pub struct PolicyEngine {
    groups: Vec<GroupInfo>,
    group_index: HashMap<String, usize>,
    /// Number of u64 words in one group mask.
    words: usize,
    lists: Vec<ListInfo>,
    /// One group mask per list.
    list_masks: Vec<u64>,
    rules: Vec<RuleInfo>,
    /// One group mask per compiled rule.
    rule_masks: Vec<u64>,
    exact_allow: HashMap<Box<str>, Vec<u32>>,
    exact_deny: HashMap<Box<str>, Vec<u32>>,
    regex_allow: RegexRules,
    regex_deny: RegexRules,
    special: HashSet<Box<str>>,
    reply: BlockReply,
    blocked_ttl: u32,
    deep_cname_check: bool,
    set: DomainSet,
}

impl fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("groups", &self.groups.len())
            .field("lists", &self.lists.len())
            .field("rules", &self.rules.len())
            .field("unique_domains", &self.set.len())
            .field("regex_allow", &self.regex_allow)
            .field("regex_deny", &self.regex_deny)
            .field("reply", &self.reply)
            .finish_non_exhaustive()
    }
}

impl Default for PolicyEngine {
    /// An engine with the default config and no list.
    fn default() -> Self {
        Self::build(&Config::default(), std::iter::empty()).0
    }
}

/// Mask helper for the build: makes group masks from group names.
struct MaskMaker<'a> {
    groups: &'a [GroupInfo],
    index: &'a HashMap<String, usize>,
    words: usize,
}

impl MaskMaker<'_> {
    /// Appends the mask of `names` (enabled groups only) to `out`.
    fn push(&self, names: &[String], path: &str, out: &mut Vec<u64>, report: &mut BuildReport) {
        let start = out.len();
        out.resize(start + self.words, 0);
        for (i, name) in names.iter().enumerate() {
            let Some(&g) = self.index.get(name) else {
                report.issue(
                    format!("{path}.groups[{i}]"),
                    format!("group {name:?} is not defined; it is ignored"),
                );
                continue;
            };
            if !self.groups.get(g).is_some_and(|info| info.enabled) {
                continue;
            }
            if let Some(w) = out.get_mut(start + g / 64) {
                *w |= 1u64 << (g % 64);
            }
        }
    }
}

impl PolicyEngine {
    /// Builds an engine from a config and parsed lists.
    ///
    /// The config does not need to be valid. The build skips each value that it cannot use
    /// and reports it in [`BuildReport::issues`]. The iterator gives `(list id, list)`; the
    /// build reads one list at a time and drops or takes over its buffer. Give the largest
    /// list first for the lowest peak memory.
    ///
    /// The hash key of the compiled set comes from [`std::hash::RandomState`] (the OS random
    /// source), so two builds can have different tables but always give the same decisions.
    /// Use [`PolicyEngine::build_with_seed`] for a repeatable build.
    pub fn build(
        config: &Config,
        lists: impl IntoIterator<Item = (u32, ParsedList)>,
    ) -> (Self, BuildReport) {
        Self::build_with_seed(config, lists, random_seed())
    }

    /// Builds an engine like [`PolicyEngine::build`], with a given seed for the hash key of
    /// the compiled set. The list text comes from the network, so the seed must be secret:
    /// get it from the OS random source. A list author who knows the seed can make names
    /// that collide in the table and make the build and the lookups slow. The same seed and
    /// input give the same engine.
    pub fn build_with_seed(
        config: &Config,
        lists: impl IntoIterator<Item = (u32, ParsedList)>,
        seed: [u64; 2],
    ) -> (Self, BuildReport) {
        let mut report = BuildReport::default();

        let mut groups: Vec<GroupInfo> = Vec::new();
        let mut group_index: HashMap<String, usize> = HashMap::new();
        for (i, g) in config.groups.iter().enumerate() {
            if group_index.contains_key(&g.name) {
                report.issue(
                    format!("groups[{i}].name"),
                    "the group is defined twice; the first one is used",
                );
                continue;
            }
            group_index.insert(g.name.clone(), groups.len());
            groups.push(GroupInfo {
                name: g.name.clone(),
                enabled: g.enabled,
            });
        }
        let words = groups.len().div_ceil(64).max(1);
        let masks = MaskMaker {
            groups: &groups,
            index: &group_index,
            words,
        };

        let (engine_lists, list_masks, set) =
            build_lists(config, lists, &masks, HashKey::new(seed), &mut report);
        let (rules, rule_masks, exact_allow, exact_deny, regex_allow, regex_deny) =
            build_rules(config, &masks, &mut report);

        let mut special = HashSet::new();
        for (i, d) in config.blocking.special_domains.iter().enumerate() {
            match DomainName::parse_idn(d) {
                Ok(name) => {
                    special.insert(Box::from(name.as_str()));
                }
                Err(e) => report.issue(format!("blocking.special_domains[{i}]"), e.to_string()),
            }
        }
        let reply = block_reply(&config.blocking, &mut report);

        let engine = Self {
            groups,
            group_index,
            words,
            lists: engine_lists,
            list_masks,
            rules,
            rule_masks,
            exact_allow,
            exact_deny,
            regex_allow,
            regex_deny,
            special,
            reply,
            blocked_ttl: config.blocking.blocked_ttl,
            deep_cname_check: config.blocking.deep_cname_check,
            set,
        };
        report.unique_domains = engine.set.len();
        report.memory_bytes = engine.memory_bytes();
        report.peak_build_bytes = engine.set.peak_build_bytes();
        report.set_rehashes = engine.set.rehashes();
        report.set_max_probe = engine.set.max_probe();
        (engine, report)
    }

    /// The groups of a client. `None` (a client with no `[[clients]]` entry) gives the group
    /// `default`. `Some(&[])` (a client with `groups = []`) gives no group. Unknown and
    /// disabled groups are left out.
    pub fn client_groups<S: AsRef<str>>(&self, groups: Option<&[S]>) -> GroupSet {
        match groups {
            None => self.default_groups(),
            Some(names) => self.groups_named(names.iter().map(AsRef::as_ref)),
        }
    }

    /// The group `default` (if it is enabled).
    pub fn default_groups(&self) -> GroupSet {
        self.groups_named([DEFAULT_GROUP])
    }

    /// The enabled groups with these names. Unknown names are left out.
    pub fn groups_named<'a>(&self, names: impl IntoIterator<Item = &'a str>) -> GroupSet {
        let mut set = GroupSet::none();
        for name in names {
            if let Some(&g) = self.group_index.get(name)
                && self.groups.get(g).is_some_and(|info| info.enabled)
            {
                set.insert(g);
            }
        }
        set
    }

    /// Checks one name. `blocking` is the state of the blocking toggle
    /// ([`BlockingToggle::is_blocking`](crate::blocking_state::BlockingToggle::is_blocking)).
    ///
    /// The function does not allocate, except for a small set when a regex rule matches.
    pub fn check(&self, groups: &GroupSet, blocking: bool, name: &DomainName) -> Decision {
        self.decide(groups, blocking, name, 0)
    }

    /// Checks a CNAME chain: the query name first, then each CNAME target in chain order
    /// (amendment A4).
    ///
    /// This is the Pi-hole rule. The walk stops at the first name that has an allow match
    /// ([`Reason::is_allow_match`]) or that is blocked, and that decision is the decision of
    /// the full answer. Thus an allow on the query name, or on a CNAME target before the
    /// blocked target, allows the full answer. [`Decision::name_index`] tells which name
    /// decided. When no name decides, the answer is allowed with the decision of the query
    /// name. When `blocking.deep_cname_check` is false, only the query name is checked. An
    /// empty chain is allowed.
    pub fn check_chain(&self, groups: &GroupSet, blocking: bool, chain: &[DomainName]) -> Decision {
        let Some(first) = chain.first() else {
            return Decision {
                action: Action::Allow,
                reason: Reason::NoMatch,
                name_index: 0,
            };
        };
        let d0 = self.decide(groups, blocking, first, 0);
        if d0.is_blocked() || d0.reason.is_allow_match() || !blocking || !self.deep_cname_check {
            return d0;
        }
        // Bounded by the length of the chain.
        for (i, name) in chain.iter().enumerate().skip(1) {
            let d = self.decide(groups, blocking, name, i);
            if d.is_blocked() || d.reason.is_allow_match() {
                return d;
            }
        }
        d0
    }

    fn decide(
        &self,
        groups: &GroupSet,
        blocking: bool,
        name: &DomainName,
        index: usize,
    ) -> Decision {
        let d = |action, reason| Decision {
            action,
            reason,
            name_index: index,
        };
        if !blocking {
            return d(Action::Allow, Reason::BlockingDisabled);
        }
        let s = name.as_str();
        // Pi-hole v6: the exact and regex allow rules come before the special domains.
        if let Some(rule) = self.exact_hit(&self.exact_allow, groups, s) {
            return d(Action::Allow, Reason::ExactAllow { rule });
        }
        if let Some(rule) = self.regex_hit(&self.regex_allow, groups, s) {
            return d(Action::Allow, Reason::RegexAllow { rule });
        }
        if self.special.contains(s) {
            return d(
                Action::Special(SpecialReply::Nxdomain),
                Reason::SpecialDomain,
            );
        }
        let block = Action::Block(self.reply);
        // Pi-hole v6: an exact deny rule wins over an allow-kind list.
        if let Some(rule) = self.exact_hit(&self.exact_deny, groups, s) {
            return d(block, Reason::ExactDeny { rule });
        }
        let (allow_lists, block_lists) = self.list_hits(groups, name);
        if !allow_lists.is_empty() {
            return d(Action::Allow, Reason::AllowList { lists: allow_lists });
        }
        if !block_lists.is_empty() {
            return d(block, Reason::BlockList { lists: block_lists });
        }
        if let Some(rule) = self.regex_hit(&self.regex_deny, groups, s) {
            return d(block, Reason::RegexDeny { rule });
        }
        d(Action::Allow, Reason::NoMatch)
    }

    fn rule_mask(&self, rule: u32) -> &[u64] {
        let Ok(r) = usize::try_from(rule) else {
            return &[];
        };
        self.rule_masks
            .get(r * self.words..(r + 1) * self.words)
            .unwrap_or_default()
    }

    fn list_mask(&self, list: usize) -> &[u64] {
        self.list_masks
            .get(list * self.words..(list + 1) * self.words)
            .unwrap_or_default()
    }

    fn rule_index(&self, rule: u32) -> Option<usize> {
        let r = usize::try_from(rule).ok()?;
        self.rules.get(r).map(|info| info.index)
    }

    fn exact_hit(
        &self,
        map: &HashMap<Box<str>, Vec<u32>>,
        groups: &GroupSet,
        name: &str,
    ) -> Option<usize> {
        map.get(name)?
            .iter()
            .find(|r| intersects(self.rule_mask(**r), groups))
            .and_then(|r| self.rule_index(*r))
    }

    fn regex_hit(&self, rules: &RegexRules, groups: &GroupSet, name: &str) -> Option<usize> {
        let mut hit = None;
        rules.find_match(name, |r| {
            if intersects(self.rule_mask(r), groups) {
                hit = Some(r);
                true
            } else {
                false
            }
        });
        hit.and_then(|r| self.rule_index(r))
    }

    /// Calls `f(element, matched name)` for each list element that matches `name`:
    /// exact and subtree elements of the name, and subtree elements of each parent.
    fn for_each_list_hit<'n>(&self, name: &'n DomainName, mut f: impl FnMut(Elem, &'n str)) {
        // Bounded: a name has at most 127 labels.
        for (depth, parent) in name.self_and_parents().enumerate() {
            if depth > 0 && !self.set.has_subtree() {
                break;
            }
            let Some(elems) = self.set.get(parent) else {
                continue;
            };
            for e in elems {
                if depth == 0 || e.subtree() {
                    f(e, parent);
                }
            }
        }
    }

    fn list_hits(&self, groups: &GroupSet, name: &DomainName) -> (ListIds, ListIds) {
        let mut allow = ListIds::default();
        let mut block = ListIds::default();
        self.for_each_list_hit(name, |e, _| {
            let list = e.list();
            let Some(info) = self.lists.get(list) else {
                return;
            };
            if !intersects(self.list_mask(list), groups) {
                return;
            }
            if e.allow() {
                allow.push(info.id);
            } else {
                block.push(info.id);
            }
        });
        (allow, block)
    }

    /// Lists every rule and list that matches `name` (A9: "which list blocks this domain").
    ///
    /// With `Some(groups)`, only rules and lists of these groups are listed. With `None`,
    /// all enabled rules and lists are listed, also those that apply to no group. Special
    /// domains are always listed. The blocking toggle has no effect here.
    pub fn explain(&self, groups: Option<&GroupSet>, name: &DomainName) -> Vec<Match> {
        let applies = |mask: &[u64]| groups.is_none_or(|g| intersects(mask, g));
        let mut out = Vec::new();
        let s = name.as_str();
        if self.special.contains(s) {
            out.push(Match {
                source: MatchSource::SpecialDomain,
                effect: MatchEffect::Special,
                matched: s.to_owned(),
                groups: Vec::new(),
            });
        }
        let mut rule_hits: Vec<(u32, MatchEffect, bool)> = Vec::new();
        for (map, effect) in [
            (&self.exact_allow, MatchEffect::Allow),
            (&self.exact_deny, MatchEffect::Deny),
        ] {
            for r in map.get(s).into_iter().flatten() {
                rule_hits.push((*r, effect, false));
            }
        }
        for (rules, effect) in [
            (&self.regex_allow, MatchEffect::Allow),
            (&self.regex_deny, MatchEffect::Deny),
        ] {
            rules.find_match(s, |r| {
                rule_hits.push((r, effect, true));
                false
            });
        }
        rule_hits.sort_unstable_by_key(|(r, _, _)| *r);
        for (r, effect, regex) in rule_hits {
            let mask = self.rule_mask(r);
            let Some(rule) = self.rule_index(r) else {
                continue;
            };
            if !applies(mask) {
                continue;
            }
            out.push(Match {
                source: if regex {
                    MatchSource::RegexRule { rule }
                } else {
                    MatchSource::ExactRule { rule }
                },
                effect,
                matched: s.to_owned(),
                groups: self.group_names(mask),
            });
        }
        self.for_each_list_hit(name, |e, matched| {
            let list = e.list();
            let Some(info) = self.lists.get(list) else {
                return;
            };
            let mask = self.list_mask(list);
            if !applies(mask) {
                return;
            }
            out.push(Match {
                source: MatchSource::List {
                    id: info.id,
                    kind: if e.subtree() {
                        MatchKind::Subtree
                    } else {
                        MatchKind::Exact
                    },
                },
                effect: if e.allow() {
                    MatchEffect::Allow
                } else {
                    MatchEffect::Deny
                },
                matched: matched.to_owned(),
                groups: self.group_names(mask),
            });
        });
        out
    }

    fn group_names(&self, mask: &[u64]) -> Vec<String> {
        self.groups
            .iter()
            .enumerate()
            .filter(|(g, _)| {
                mask.get(g / 64)
                    .is_some_and(|w| w & (1u64 << (g % 64)) != 0)
            })
            .map(|(_, info)| info.name.clone())
            .collect()
    }

    /// The block reply from `blocking.mode`.
    pub fn block_reply(&self) -> BlockReply {
        self.reply
    }

    /// TTL of a blocked answer, in seconds (`blocking.blocked_ttl`).
    pub fn blocked_ttl(&self) -> u32 {
        self.blocked_ttl
    }

    /// Number of unique names in the compiled set.
    pub fn unique_domains(&self) -> usize {
        self.set.len()
    }

    /// Number of lists in the engine.
    pub fn list_count(&self) -> usize {
        self.lists.len()
    }

    /// Heap bytes of the engine (an estimate from capacities). The compiled regex programs
    /// are not counted.
    pub fn memory_bytes(&self) -> usize {
        let map_bytes = |m: &HashMap<Box<str>, Vec<u32>>| {
            m.iter()
                .map(|(k, v)| k.len() + v.capacity() * 4 + 48)
                .sum::<usize>()
        };
        self.set.heap_bytes()
            + self.list_masks.capacity() * 8
            + self.rule_masks.capacity() * 8
            + self.lists.capacity() * std::mem::size_of::<ListInfo>()
            + self.rules.capacity() * std::mem::size_of::<RuleInfo>()
            + map_bytes(&self.exact_allow)
            + map_bytes(&self.exact_deny)
            + self.special.iter().map(|s| s.len() + 32).sum::<usize>()
    }
}

/// A seed for the hash key from [`std::hash::RandomState`]. Std gets its keys from the OS
/// random source, and each `RandomState` has different keys.
fn random_seed() -> [u64; 2] {
    use std::hash::BuildHasher;
    let state = std::hash::RandomState::new();
    [state.hash_one(0u8), state.hash_one(1u8)]
}

/// Builds the compiled set from the parsed lists.
fn build_lists(
    config: &Config,
    lists: impl IntoIterator<Item = (u32, ParsedList)>,
    masks: &MaskMaker<'_>,
    key: HashKey,
    report: &mut BuildReport,
) -> (Vec<ListInfo>, Vec<u64>, DomainSet) {
    let mut by_id: HashMap<u32, usize> = HashMap::new();
    for (i, l) in config.lists.adlists.iter().enumerate() {
        if by_id.contains_key(&l.id) {
            report.issue(
                format!("lists.adlists[{i}].id"),
                format!("list id {} is used twice; the first list is used", l.id),
            );
            continue;
        }
        by_id.insert(l.id, i);
    }
    let mut builder = DomainSetBuilder::new(key);
    let mut infos: Vec<ListInfo> = Vec::new();
    let mut list_masks: Vec<u64> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();
    for (id, parsed) in lists {
        let entries = parsed.len();
        let mut new_domains = 0;
        let mut ignored_allow_entries = 0;
        let cfg = by_id
            .get(&id)
            .and_then(|i| config.lists.adlists.get(*i).map(|l| (*i, l)));
        let status = match cfg {
            None => ListStatus::NotInConfig,
            Some((_, l)) if !l.enabled => ListStatus::Disabled,
            Some(_) if seen.contains(&id) => ListStatus::Duplicate,
            Some((i, l)) => match u16::try_from(infos.len()) {
                Err(_) => ListStatus::TooManyLists,
                Ok(idx) => {
                    seen.insert(id);
                    infos.push(ListInfo { id });
                    masks.push(
                        &l.groups,
                        &format!("lists.adlists[{i}]"),
                        &mut list_masks,
                        report,
                    );
                    match builder.add_list(idx, l.kind == ListKind::Allow, parsed) {
                        Ok(stats) => {
                            new_domains = stats.new_names;
                            ignored_allow_entries = stats.ignored_allow;
                            report.entries += stats.entries;
                            ListStatus::Used
                        }
                        Err(_) => ListStatus::SetFull,
                    }
                }
            },
        };
        report.lists.push(ListBuildInfo {
            id,
            entries,
            new_domains,
            ignored_allow_entries,
            status,
        });
    }
    for l in &config.lists.adlists {
        if l.enabled && !seen.contains(&l.id) && !report.missing_lists.contains(&l.id) {
            report.missing_lists.push(l.id);
        }
    }
    (infos, list_masks, builder.finish())
}

type Rules = (
    Vec<RuleInfo>,
    Vec<u64>,
    HashMap<Box<str>, Vec<u32>>,
    HashMap<Box<str>, Vec<u32>>,
    RegexRules,
    RegexRules,
);

/// Compiles the exact and regex rules. Disabled rules are left out.
fn build_rules(config: &Config, masks: &MaskMaker<'_>, report: &mut BuildReport) -> Rules {
    let mut rules: Vec<RuleInfo> = Vec::new();
    let mut rule_masks: Vec<u64> = Vec::new();
    let mut exact_allow: HashMap<Box<str>, Vec<u32>> = HashMap::new();
    let mut exact_deny: HashMap<Box<str>, Vec<u32>> = HashMap::new();
    let mut regex_allow: Vec<(u32, Regex)> = Vec::new();
    let mut regex_deny: Vec<(u32, Regex)> = Vec::new();
    for (i, rule) in config.rules.iter().enumerate() {
        if !rule.enabled {
            continue;
        }
        let path = format!("rules[{i}]");
        let Ok(id) = u32::try_from(rules.len()) else {
            report.issue(&path, "too many rules; the rule is ignored");
            continue;
        };
        match rule.kind {
            RuleKind::Exact => {
                let name = match DomainName::parse_idn(&rule.value) {
                    Ok(n) => n,
                    Err(e) => {
                        report.issue(format!("{path}.value"), e.to_string());
                        continue;
                    }
                };
                let map = match rule.action {
                    RuleAction::Allow => &mut exact_allow,
                    RuleAction::Deny => &mut exact_deny,
                };
                map.entry(Box::from(name.as_str())).or_default().push(id);
            }
            RuleKind::Regex => {
                let re = match compile_rule_regex(&rule.value) {
                    Ok(r) => r,
                    Err(e) => {
                        report.issue(format!("{path}.value"), e.to_string());
                        continue;
                    }
                };
                match rule.action {
                    RuleAction::Allow => regex_allow.push((id, re)),
                    RuleAction::Deny => regex_deny.push((id, re)),
                }
            }
        }
        rules.push(RuleInfo { index: i });
        masks.push(&rule.groups, &path, &mut rule_masks, report);
    }
    let regex_allow = RegexRules::new(regex_allow, "rules (regex allow)", report);
    let regex_deny = RegexRules::new(regex_deny, "rules (regex deny)", report);
    (
        rules,
        rule_masks,
        exact_allow,
        exact_deny,
        regex_allow,
        regex_deny,
    )
}

fn block_reply(b: &Blocking, report: &mut BuildReport) -> BlockReply {
    match b.mode {
        BlockingMode::Null => BlockReply::Null,
        BlockingMode::Nxdomain => BlockReply::Nxdomain,
        BlockingMode::Nodata => BlockReply::Nodata,
        BlockingMode::Ip => {
            let ipv4 = b.ipv4.as_deref().and_then(|v| {
                v.parse().ok().or_else(|| {
                    report.issue("blocking.ipv4", "not an IPv4 address; NODATA is used");
                    None
                })
            });
            let ipv6 = b.ipv6.as_deref().and_then(|v| {
                v.parse().ok().or_else(|| {
                    report.issue("blocking.ipv6", "not an IPv6 address; NODATA is used");
                    None
                })
            });
            BlockReply::Ip { ipv4, ipv6 }
        }
    }
}
