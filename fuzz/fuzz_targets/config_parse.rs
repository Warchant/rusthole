#![no_main]
//! Fuzz the config parser: any UTF-8 text goes through `Config::from_toml_str` and
//! `Config::validate`. Neither may panic. A parsed config must write and read back.

use libfuzzer_sys::fuzz_target;
use rusthole_core::Config;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(config) = Config::from_toml_str(text) {
        let _ = config.validate();
        let again = config.to_toml_string().expect("a parsed config must serialize");
        let back = Config::from_toml_str(&again).expect("a written config must parse");
        assert_eq!(back, config);
    }
});
