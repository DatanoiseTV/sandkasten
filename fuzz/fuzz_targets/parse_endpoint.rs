#![no_main]
//! Fuzz the endpoint parser. `parse_endpoint` ingests a string like
//! `host:443`, `[::1]:443`, `0.0.0.0:80`, `127.0.0.1:9090`, etc. It's
//! called for every entry under `network.outbound_tcp`, `inbound_tcp`,
//! `inbound_udp`, and is reachable from any user-supplied profile.
//! A panic here would crash `render` / `explain` / `verify`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return; };
    let _ = sandkasten::config::parse_endpoint(text);
});
