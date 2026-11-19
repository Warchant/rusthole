//! Fuzz target: arbitrary bytes as an IANA RDAP bootstrap file or an RDAP domain answer
//! (the first byte picks the parser). No input may panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rusthole_report::fuzzing::rdap_json(data);
});
