#![no_main]
//! Fuzz the TOML profile loader.
//!
//! Profile-parse is the largest piece of attacker-controlled-shaped
//! input the binary handles: a user (or a malicious template author)
//! can hand us arbitrary UTF-8 and we must round-trip it through
//! TOML deserialise → finalise without panicking. A panic here would
//! be a denial-of-service against `sandkasten verify`, `explain`,
//! `render`, etc.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return; };
    // Parse step. Any error is fine — we just want to surface panics.
    let Ok(raw) = sandkasten::config::Profile::from_toml_str(text) else { return; };
    // Finalise step (variable expansion, defaults, validation). This
    // is the second half of the load pipeline and the panic-prone one.
    let ctx = sandkasten::config::ExpandContext {
        cwd: std::path::PathBuf::from("/"),
        exe_dir: Some(std::path::PathBuf::from("/bin")),
        home: Some(std::path::PathBuf::from("/tmp")),
    };
    let _ = sandkasten::config::finalize(raw, &ctx);
});
