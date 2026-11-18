#![no_main]
//! Fuzz the list parsers: any UTF-8 text through each format. No panic, and the output obeys
//! the limits: entry count, sample count, and each entry is a valid multi-label name.

use libfuzzer_sys::fuzz_target;
use rusthole_core::DomainName;
use rusthole_core::lists::{
    ListError, ListFormat, MAX_INVALID_SAMPLES, MAX_SAMPLE_CHARS, ParseLimits, parse, render,
};

const MAX_ENTRIES: usize = 64;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let limits = ParseLimits {
        max_line_len: 512,
        max_entries: MAX_ENTRIES,
        max_bytes: 64 * 1024,
    };
    for format in [
        ListFormat::Auto,
        ListFormat::Hosts,
        ListFormat::Domains,
        ListFormat::Abp,
    ] {
        match parse(text, format, &limits) {
            Ok(list) => {
                assert!(list.len() <= MAX_ENTRIES);
                assert_eq!(list.entries().count(), list.len());
                assert_eq!(list.stats.valid, list.len());
                assert!(list.stats.invalid_samples.len() <= MAX_INVALID_SAMPLES);
                for s in &list.stats.invalid_samples {
                    assert!(s.text.chars().count() <= MAX_SAMPLE_CHARS);
                }
                for e in list.entries() {
                    let name = DomainName::parse(e.name).expect("an entry is a valid name");
                    assert_eq!(name.as_str(), e.name, "an entry is canonical");
                    assert!(e.name.contains('.'));
                }
                // The rendered text parses back to the entries that the format can hold.
                let again = render(list.entries(), ListFormat::Auto);
                let back = parse(&again, ListFormat::Auto, &ParseLimits::default())
                    .expect("rendered text parses");
                assert!(back.len() <= list.len());
                assert_eq!(back.stats.invalid, 0);
            }
            Err(ListError::TooManyEntries { limit }) => assert_eq!(limit, MAX_ENTRIES),
            Err(ListError::TooLarge { .. }) => assert!(text.len() > limits.max_bytes),
        }
    }
});
