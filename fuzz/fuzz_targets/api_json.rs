//! Fuzz target: arbitrary bytes as the JSON body of each write endpoint of the admin API
//! (parse, apply to a sample config, validate). No input may panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rusthole_web::fuzzing::api_json(data);
});
