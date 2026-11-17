#![no_main]
//! Fuzz the `pihole.toml` mapping: any UTF-8 text goes through `map_pihole_toml`. It may not
//! panic, and the config that it makes must be valid.

use libfuzzer_sys::fuzz_target;
use rusthole_core::Config;
use rusthole_import::{ImportReport, map_pihole_toml};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut config = Config::default();
    let mut report = ImportReport::default();
    if map_pihole_toml(text, &mut config, &mut report).is_ok() {
        assert_eq!(config.validate(), vec![]);
    }
});
