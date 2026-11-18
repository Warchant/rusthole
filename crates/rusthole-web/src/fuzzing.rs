//! Entry points for the fuzz targets `api_json` and `host_header` (`fuzz/`). They are
//! public so that the fuzz crate can call them; the server does not use them.

use std::net::Ipv4Addr;
use std::sync::OnceLock;

use rusthole_core::Config;

use crate::host::{HostAllow, host_allowed};
use crate::model::{
    self, BlockingReq, ClientCreate, ClientPatch, CnameCreate, CnamePatch, CodeReq, DisableTotpReq,
    ForwarderCreate, ForwarderPatch, GroupCreate, GroupPatch, ListCreate, ListPatch, LoginReq,
    PasswordReq, RecordCreate, RecordPatch, RuleCreate, RulePatch, RuleTest, TokenCreate,
};
use crate::routes::parse_json;
use crate::settings::{SettingsPatch, apply_patch};

fn base_config() -> &'static Config {
    static CFG: OnceLock<Config> = OnceLock::new();
    CFG.get_or_init(|| {
        let text = r#"
config_version = 1
[[groups]]
name = "default"
[[groups]]
id = 1
name = "kids"
[[lists.adlists]]
id = 1
url = "https://lists.example/hosts.txt"
kind = "block"
[[rules]]
id = 1
kind = "exact"
action = "deny"
value = "ads.example"
[[clients]]
uid = 1
id = "192.0.2.10"
[[local_dns.records]]
id = 1
name = "nas.lan"
type = "A"
value = "192.0.2.20"
[[local_dns.cnames]]
id = 1
name = "files.lan"
target = "nas.lan"
[[local_dns.conditional_forwarding]]
id = 1
cidr = "192.0.2.0/24"
server = "192.0.2.1"
"#;
        let mut c = Config::from_toml_str(text).unwrap_or_default();
        c.assign_ids();
        c
    })
}

/// Parses `body` as the request body of one write endpoint (the first byte picks the
/// endpoint), applies it to a sample config and validates the result. It must never
/// panic.
pub fn api_json(data: &[u8]) {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let mut c = base_config().clone();
    let now = "2026-11-17T08:30:00Z";
    let applied = match sel % 22 {
        0 => parse_json::<ListCreate>(body).and_then(|r| model::create_list(&mut c, r, 99)),
        1 => parse_json::<ListPatch>(body).and_then(|r| model::patch_list(&mut c, 1, r)),
        2 => parse_json::<RuleCreate>(body).and_then(|r| model::create_rule(&mut c, r, 99, now)),
        3 => parse_json::<RulePatch>(body).and_then(|r| model::patch_rule(&mut c, 1, r, now)),
        4 => parse_json::<RuleTest>(body).and_then(|r| model::test_rule(&r).map(|_| ())),
        5 => parse_json::<GroupCreate>(body).and_then(|r| model::create_group(&mut c, r, 99)),
        6 => parse_json::<GroupPatch>(body).and_then(|r| model::patch_group(&mut c, 1, r)),
        7 => parse_json::<ClientCreate>(body).and_then(|r| model::create_client(&mut c, r, 99)),
        8 => parse_json::<ClientPatch>(body).and_then(|r| model::patch_client(&mut c, 1, r)),
        9 => parse_json::<RecordCreate>(body).and_then(|r| model::create_record(&mut c, r, 99)),
        10 => parse_json::<RecordPatch>(body).and_then(|r| model::patch_record(&mut c, 1, r)),
        11 => parse_json::<CnameCreate>(body).and_then(|r| model::create_cname(&mut c, r, 99)),
        12 => parse_json::<CnamePatch>(body).and_then(|r| model::patch_cname(&mut c, 1, r)),
        13 => {
            parse_json::<ForwarderCreate>(body).and_then(|r| model::create_forwarder(&mut c, r, 99))
        }
        14 => parse_json::<ForwarderPatch>(body).and_then(|r| model::patch_forwarder(&mut c, 1, r)),
        15 => parse_json::<SettingsPatch>(body).and_then(|r| apply_patch(&mut c, r)),
        16 => parse_json::<BlockingReq>(body).and_then(|r| model::check_blocking(&r)),
        17 => parse_json::<TokenCreate>(body)
            .and_then(|r| model::create_token(&mut c, &r.name, 99, "rh_fuzz", now)),
        18 => parse_json::<LoginReq>(body).map(|_| ()),
        19 => parse_json::<DisableTotpReq>(body).map(|_| ()),
        20 => parse_json::<PasswordReq>(body).map(|_| ()),
        _ => parse_json::<CodeReq>(body).map(|_| ()),
    };
    if applied.is_ok() {
        c.normalize();
        let _ = c.validate();
        let _ = crate::settings::settings_of(&c, &[], false);
    }
}

/// Runs the `Host` check on arbitrary bytes. It must never panic.
pub fn host_header(data: &[u8]) {
    static ALLOW: OnceLock<HostAllow> = OnceLock::new();
    let allow =
        ALLOW.get_or_init(|| HostAllow::new(8443, ["rusthole.lan"], [Ipv4Addr::new(192, 0, 2, 2)]));
    let text = String::from_utf8_lossy(data);
    let _ = host_allowed(&text, allow);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        api_json(b"");
        for sel in 0u8..22 {
            let mut d = vec![sel];
            d.extend_from_slice(br#"{"url":"https://x.example/a","name":"g1","match":"192.0.2.5","kind":"exact","action":"deny","pattern":"a.example","domain":"a.example","type":"A","address":"192.0.2.9","target":"nas.lan","servers":["192.0.2.1"],"enabled":false,"password":"x","code":"1"}"#);
            api_json(&d);
        }
        host_header(b"localhost:8443");
        host_header(&[0xff, 0xfe]);
    }
}
