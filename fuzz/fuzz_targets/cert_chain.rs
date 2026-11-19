//! Fuzz target: arbitrary bytes as one DER certificate of a TLS chain that a server sent.
//! No input may panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rusthole_report::fuzzing::cert_chain(data);
});
