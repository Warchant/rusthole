#![no_main]
//! Fuzz `DomainName::parse`: it must never panic, and a parsed name must parse to itself.

use libfuzzer_sys::fuzz_target;
use rusthole_core::DomainName;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(name) = DomainName::parse(text) {
        let again = DomainName::parse(name.as_str()).expect("a parsed name must parse again");
        assert_eq!(name, again);
    }
});
