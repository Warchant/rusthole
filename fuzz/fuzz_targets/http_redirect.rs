//! Fuzz target: arbitrary bytes as a plain HTTP request head on the admin port. No input
//! may panic, and a redirect never points to a host that the host check refuses.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rusthole_web::fuzzing::http_redirect(data);
});
