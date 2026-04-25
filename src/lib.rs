//! Library facade so fuzz harnesses (and future embedders) can reach
//! the parse-prone surfaces without going through the bin.
//!
//! The bin (`src/main.rs`) does NOT depend on this lib — it declares
//! the same modules itself via `mod foo;`. That means each module is
//! compiled twice, once into the binary and once into the library.
//! Cargo handles this transparently; the cost is a slightly slower
//! cold build, the benefit is no source restructure for an already
//! shipped CLI.
//!
//! Only modules a fuzz target or external consumer would reasonably
//! want are re-exposed. Sandbox application (`macos`, `linux`,
//! `mocks`, `signing` etc.) stays bin-private.

#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

#[macro_use]
pub mod log;

pub mod config;
pub mod events;
pub mod hardware;
pub mod presets;
pub mod templates;
