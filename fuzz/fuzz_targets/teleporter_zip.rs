#![no_main]
//! Fuzz the Teleporter import: any bytes go through the zip reader, the SQLite reader and the
//! mapping. Nothing may panic. A successful import must give a valid config.

use libfuzzer_sys::fuzz_target;
use rusthole_import::{Limits, import_teleporter};

/// Small limits, so that one input cannot use much memory.
const LIMITS: Limits = Limits {
    max_entries: 64,
    max_entry_size: 4 * 1024 * 1024,
    max_total_size: 8 * 1024 * 1024,
    max_rows: 10_000,
    max_sqlite_ksteps: 200_000,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(imported) = import_teleporter(data, &LIMITS) {
        assert_eq!(imported.config.validate(), vec![]);
    }
});
