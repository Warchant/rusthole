//! Fuzz target: the metadata file of the list disk cache (part P3b). Any bytes must give a
//! value or an error, never a panic. A value must render and parse to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rusthole_core::refresh::{parse_meta, render_meta};

fuzz_target!(|data: &[u8]| {
    if let Ok(meta) = parse_meta(data) {
        let again = parse_meta(&render_meta(&meta));
        assert_eq!(again.as_ref(), Ok(&meta));
        // The merge rules keep a valid file.
        let failed = meta.after_failure(0, &String::from_utf8_lossy(data));
        assert!(parse_meta(&render_meta(&failed)).is_ok());
    }
});
