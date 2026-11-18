//! `GET /settings` and `PATCH /settings` (docs/API.md section 12): the mapping between the
//! API sections and the config.
//!
//! Some API fields have no field of their own in the config:
//!
//! | API | Config |
//! |---|---|
//! | `blocking.mode` `custom_ip` | `blocking.mode = "ip"` |
//! | `blocking.special_domains` (bool) | `blocking.special_domains` (list): true keeps the list (or sets the default list), false empties it |
//! | `cache.enabled` | `cache.max_entries > 0`; false writes `max_entries = 0` |
//! | `rate_limit.burst` | `rate_limit.queries` (the bucket size) |
//! | `rate_limit.queries_per_second` | `queries / interval_seconds`, rounded; a change sets `interval_seconds = round(burst / queries_per_second)` |
//! | `acl.extra_cidrs` | `acl.allow` |
//! | `stats.recent_queries_size` | `stats.recent_queries` |

use std::net::{Ipv4Addr, Ipv6Addr};

use rusthole_core::Config;
use rusthole_core::config::{BlockingMode, SPECIAL_DOMAINS, Upstream};
use rusthole_core::net::{Cidr, UpstreamHost, UpstreamUrl};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult, FieldError};
use crate::model::IPV6_LATER;

/// `upstreams`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamsS {
    pub servers: Vec<String>,
    pub timeout_ms: u32,
}

/// `blocking`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockingS {
    pub mode: String,
    pub custom_ipv4: Option<String>,
    pub custom_ipv6: Option<String>,
    pub blocked_ttl: u32,
    pub special_domains: bool,
    pub cname_check: bool,
}

/// `cache`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheS {
    pub enabled: bool,
    pub max_entries: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub negative_ttl: u32,
}

/// `rate_limit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitS {
    pub queries_per_second: u32,
    pub burst: u32,
}

/// `acl` in a response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AclOut {
    pub extra_cidrs: Vec<String>,
    pub local_subnets: Vec<String>,
}

/// `acl` in a request (`local_subnets` is read-only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclIn {
    pub extra_cidrs: Vec<String>,
}

/// `stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsS {
    pub flush_interval_seconds: u32,
    pub retention_days: u32,
    pub recent_queries_size: u32,
}

/// `lists`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListsS {
    pub refresh_interval_hours: u32,
}

/// The `GET /settings` body.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SettingsOut {
    pub upstreams: UpstreamsS,
    pub blocking: BlockingS,
    pub cache: CacheS,
    pub rate_limit: RateLimitS,
    pub acl: AclOut,
    pub stats: StatsS,
    pub lists: ListsS,
    /// True when a change since the start needs a restart (listeners, upstreams, statistics
    /// settings). An additive field.
    pub restart_required: bool,
}

/// The `PATCH /settings` body. Each section replaces the old one as a whole.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsPatch {
    pub upstreams: Option<UpstreamsS>,
    pub blocking: Option<BlockingS>,
    pub cache: Option<CacheS>,
    pub rate_limit: Option<RateLimitS>,
    pub acl: Option<AclIn>,
    pub stats: Option<StatsS>,
    pub lists: Option<ListsS>,
}

fn mode_str(m: BlockingMode) -> &'static str {
    match m {
        BlockingMode::Null => "null",
        BlockingMode::Nxdomain => "nxdomain",
        BlockingMode::Nodata => "nodata",
        BlockingMode::Ip => "custom_ip",
    }
}

/// The `rate_limit` section of a config.
pub fn rate_limit_of(cfg: &Config) -> RateLimitS {
    let q = cfg.rate_limit.queries;
    let i = cfg.rate_limit.interval_seconds.max(1);
    RateLimitS {
        queries_per_second: if q == 0 {
            0
        } else {
            u32::try_from((u64::from(q) + u64::from(i) / 2) / u64::from(i))
                .unwrap_or(u32::MAX)
                .max(1)
        },
        burst: q,
    }
}

/// The settings of a config.
pub fn settings_of(cfg: &Config, local_subnets: &[Cidr], restart_required: bool) -> SettingsOut {
    SettingsOut {
        upstreams: UpstreamsS {
            servers: cfg
                .upstreams
                .servers
                .iter()
                .map(|u| u.url.clone())
                .collect(),
            timeout_ms: cfg.upstreams.timeout_ms,
        },
        blocking: BlockingS {
            mode: mode_str(cfg.blocking.mode).to_owned(),
            custom_ipv4: cfg.blocking.ipv4.clone(),
            custom_ipv6: cfg.blocking.ipv6.clone(),
            blocked_ttl: cfg.blocking.blocked_ttl,
            special_domains: !cfg.blocking.special_domains.is_empty(),
            cname_check: cfg.blocking.deep_cname_check,
        },
        cache: CacheS {
            enabled: cfg.cache.max_entries > 0,
            max_entries: cfg.cache.max_entries,
            min_ttl: cfg.cache.min_ttl,
            max_ttl: cfg.cache.max_ttl,
            negative_ttl: cfg.cache.negative_ttl,
        },
        rate_limit: rate_limit_of(cfg),
        acl: AclOut {
            extra_cidrs: cfg.acl.allow.clone(),
            local_subnets: local_subnets.iter().map(ToString::to_string).collect(),
        },
        stats: StatsS {
            flush_interval_seconds: cfg.stats.flush_interval_seconds,
            retention_days: cfg.stats.retention_days,
            recent_queries_size: cfg.stats.recent_queries,
        },
        lists: ListsS {
            refresh_interval_hours: cfg.lists.refresh_interval_hours,
        },
        restart_required,
    }
}

#[derive(Default)]
struct Errs(Vec<FieldError>);

impl Errs {
    fn add(&mut self, field: &str, message: impl Into<String>) {
        self.0.push(FieldError {
            field: field.to_owned(),
            message: message.into(),
        });
    }

    fn range(&mut self, field: &str, v: u32, lo: u32, hi: u32) {
        if v < lo || v > hi {
            self.add(field, format!("Use {lo} to {hi}."));
        }
    }
}

/// Applies a settings patch to a config. All field errors come in one 422 response.
pub fn apply_patch(cfg: &mut Config, p: SettingsPatch) -> ApiResult<()> {
    let mut e = Errs::default();
    if let Some(u) = p.upstreams {
        patch_upstreams(cfg, &u, &mut e);
    }
    if let Some(b) = p.blocking {
        patch_blocking(cfg, b, &mut e);
    }
    if let Some(c) = p.cache {
        patch_cache(cfg, &c, &mut e);
    }
    if let Some(r) = p.rate_limit {
        patch_rate_limit(cfg, &r);
    }
    if let Some(a) = p.acl {
        patch_acl(cfg, &a, &mut e);
    }
    if let Some(s) = p.stats {
        if s.flush_interval_seconds != 0 && !(10..=3600).contains(&s.flush_interval_seconds) {
            e.add("stats.flush_interval_seconds", "Use 0, or 10 to 3600.");
        }
        e.range("stats.retention_days", s.retention_days, 1, 365);
        e.range(
            "stats.recent_queries_size",
            s.recent_queries_size,
            100,
            100_000,
        );
        cfg.stats.flush_interval_seconds = s.flush_interval_seconds;
        cfg.stats.retention_days = s.retention_days;
        cfg.stats.recent_queries = s.recent_queries_size;
    }
    if let Some(l) = p.lists {
        if l.refresh_interval_hours > 168 {
            e.add("lists.refresh_interval_hours", "Use 0, or 1 to 168.");
        }
        cfg.lists.refresh_interval_hours = l.refresh_interval_hours;
    }
    if e.0.is_empty() {
        Ok(())
    } else {
        Err(ApiError::invalid_many(e.0))
    }
}

fn patch_upstreams(cfg: &mut Config, u: &UpstreamsS, e: &mut Errs) {
    if u.servers.is_empty() || u.servers.len() > 8 {
        e.add("upstreams.servers", "Give 1 to 8 servers.");
    }
    for (i, s) in u.servers.iter().enumerate() {
        match UpstreamUrl::parse(s.trim()) {
            Ok(url) => {
                if matches!(url.host, UpstreamHost::Ip(ip) if ip.is_ipv6()) {
                    e.add(&format!("upstreams.servers[{i}]"), IPV6_LATER);
                }
            }
            Err(err) => e.add(&format!("upstreams.servers[{i}]"), err.to_string()),
        }
    }
    e.range("upstreams.timeout_ms", u.timeout_ms, 100, 10_000);
    let old = std::mem::take(&mut cfg.upstreams.servers);
    cfg.upstreams.servers = u
        .servers
        .iter()
        .map(|s| {
            let url = s.trim().to_owned();
            // Keep the bootstrap addresses of a server that stays.
            let bootstrap = old
                .iter()
                .find(|o| o.url == url)
                .map_or_else(Vec::new, |o| o.bootstrap.clone());
            Upstream { url, bootstrap }
        })
        .collect();
    cfg.upstreams.timeout_ms = u.timeout_ms;
}

fn patch_blocking(cfg: &mut Config, b: BlockingS, e: &mut Errs) {
    cfg.blocking.mode = match b.mode.as_str() {
        "null" => BlockingMode::Null,
        "nxdomain" => BlockingMode::Nxdomain,
        "nodata" => BlockingMode::Nodata,
        "custom_ip" => BlockingMode::Ip,
        _ => {
            e.add("blocking.mode", "Use null, nxdomain, nodata or custom_ip.");
            cfg.blocking.mode
        }
    };
    let custom = cfg.blocking.mode == BlockingMode::Ip;
    if custom
        && b.custom_ipv4
            .as_ref()
            .is_some_and(|v4| v4.parse::<Ipv4Addr>().is_err())
    {
        e.add("blocking.custom_ipv4", "Not an IPv4 address.");
    }
    if custom
        && b.custom_ipv6
            .as_ref()
            .is_some_and(|v6| v6.parse::<Ipv6Addr>().is_err())
    {
        e.add("blocking.custom_ipv6", "Not an IPv6 address.");
    }
    if custom && b.custom_ipv4.is_none() && b.custom_ipv6.is_none() {
        e.add("blocking.custom_ipv4", "Mode custom_ip needs an address.");
    }
    cfg.blocking.ipv4 = if custom { b.custom_ipv4 } else { None };
    cfg.blocking.ipv6 = if custom { b.custom_ipv6 } else { None };
    e.range("blocking.blocked_ttl", b.blocked_ttl, 0, 3600);
    cfg.blocking.blocked_ttl = b.blocked_ttl;
    if !b.special_domains {
        cfg.blocking.special_domains.clear();
    } else if cfg.blocking.special_domains.is_empty() {
        cfg.blocking.special_domains = SPECIAL_DOMAINS.iter().map(|s| (*s).to_owned()).collect();
    }
    cfg.blocking.deep_cname_check = b.cname_check;
}

fn patch_cache(cfg: &mut Config, c: &CacheS, e: &mut Errs) {
    e.range("cache.max_entries", c.max_entries, 0, 1_000_000);
    if c.enabled && c.max_entries == 0 {
        e.add(
            "cache.max_entries",
            "Set more than 0, or turn the cache off.",
        );
    }
    if c.min_ttl > c.max_ttl {
        e.add("cache.min_ttl", "min_ttl must not be more than max_ttl.");
    }
    cfg.cache.max_entries = if c.enabled { c.max_entries } else { 0 };
    cfg.cache.min_ttl = c.min_ttl;
    cfg.cache.max_ttl = c.max_ttl;
    cfg.cache.negative_ttl = c.negative_ttl;
}

/// A rate limit section equal to the current one changes nothing (the mapping rounds).
fn patch_rate_limit(cfg: &mut Config, r: &RateLimitS) {
    if *r == rate_limit_of(cfg) {
        return;
    }
    if r.queries_per_second == 0 {
        cfg.rate_limit.queries = 0;
    } else {
        let burst = r.burst.max(r.queries_per_second);
        cfg.rate_limit.queries = burst;
        let qps = u64::from(r.queries_per_second);
        let interval = (u64::from(burst) + qps / 2) / qps;
        cfg.rate_limit.interval_seconds = u32::try_from(interval.max(1)).unwrap_or(u32::MAX);
    }
}

fn patch_acl(cfg: &mut Config, a: &AclIn, e: &mut Errs) {
    if a.extra_cidrs.len() > 64 {
        e.add("acl.extra_cidrs", "Give at most 64 CIDRs.");
    }
    let mut out = Vec::new();
    for (i, s) in a.extra_cidrs.iter().enumerate() {
        match Cidr::parse(s.trim()) {
            Ok(c) if c.addr.is_ipv6() => e.add(&format!("acl.extra_cidrs[{i}]"), IPV6_LATER),
            Ok(c) => out.push(c.to_string()),
            Err(err) => e.add(&format!("acl.extra_cidrs[{i}]"), err.to_string()),
        }
    }
    cfg.acl.allow = out;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_then_patch_back_changes_nothing() {
        let cfg = Config::default();
        let s = settings_of(&cfg, &[], false);
        let mut c2 = cfg.clone();
        apply_patch(
            &mut c2,
            SettingsPatch {
                upstreams: Some(s.upstreams.clone()),
                blocking: Some(s.blocking.clone()),
                cache: Some(s.cache.clone()),
                rate_limit: Some(s.rate_limit.clone()),
                acl: Some(AclIn {
                    extra_cidrs: s.acl.extra_cidrs.clone(),
                }),
                stats: Some(s.stats.clone()),
                lists: Some(s.lists.clone()),
            },
        )
        .unwrap();
        assert_eq!(c2, cfg);
    }

    #[test]
    fn mapped_fields() {
        let mut cfg = Config::default();
        apply_patch(
            &mut cfg,
            SettingsPatch {
                cache: Some(CacheS {
                    enabled: false,
                    max_entries: 500,
                    min_ttl: 0,
                    max_ttl: 10,
                    negative_ttl: 5,
                }),
                rate_limit: Some(RateLimitS {
                    queries_per_second: 50,
                    burst: 200,
                }),
                ..SettingsPatch::default()
            },
        )
        .unwrap();
        assert_eq!(cfg.cache.max_entries, 0);
        assert_eq!(
            (cfg.rate_limit.queries, cfg.rate_limit.interval_seconds),
            (200, 4)
        );
        let s = settings_of(&cfg, &[], false);
        assert!(!s.cache.enabled);
        assert_eq!(
            s.rate_limit,
            RateLimitS {
                queries_per_second: 50,
                burst: 200
            }
        );
    }

    #[test]
    fn errors_have_api_field_names() {
        let mut cfg = Config::default();
        let err = apply_patch(
            &mut cfg,
            SettingsPatch {
                upstreams: Some(UpstreamsS {
                    servers: vec!["[2001:db8::1]:53".into()],
                    timeout_ms: 50,
                }),
                acl: Some(AclIn {
                    extra_cidrs: vec!["2001:db8::/32".into()],
                }),
                ..SettingsPatch::default()
            },
        )
        .unwrap_err();
        let fields: Vec<_> = err.details.iter().map(|d| d.field.as_str()).collect();
        assert!(fields.contains(&"upstreams.servers[0]"), "{fields:?}");
        assert!(fields.contains(&"upstreams.timeout_ms"));
        assert!(fields.contains(&"acl.extra_cidrs[0]"));
    }
}
