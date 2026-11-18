//! Fuzz target: arbitrary bytes as the `Host` header of the admin API. No input may panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rusthole_web::fuzzing::host_header(data);
});
