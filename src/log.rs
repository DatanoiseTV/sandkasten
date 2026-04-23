//! Tiered, low-noise logging.
//!
//! Levels:
//!   * `Quiet`   — only hard errors via anyhow (printed by `main`).
//!   * `Normal`  — default. Almost silent; prints only when sandkasten itself
//!                 warns about something (e.g. profile widening).
//!   * `Info`    — `-v`. Lifecycle one-liners: profile loaded, sandbox applied,
//!                 child PID, exit code.
//!   * `Debug`   — `-vv`. Adds a compact rule summary.
//!   * `Trace`   — `-vvv`. Adds full generated policy and post-hoc kernel
//!                 denial capture (macOS only, via `log show`).

use crate::config::Profile;
use std::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(Level::Normal as u8);

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Quiet = 0,
    Normal = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

pub fn set(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn level() -> Level {
    match LEVEL.load(Ordering::Relaxed) {
        0 => Level::Quiet,
        1 => Level::Normal,
        2 => Level::Info,
        3 => Level::Debug,
        _ => Level::Trace,
    }
}

pub fn from_flags(verbose: u8, quiet: bool) -> Level {
    if quiet {
        return Level::Quiet;
    }
    match verbose {
        0 => Level::Normal,
        1 => Level::Info,
        2 => Level::Debug,
        _ => Level::Trace,
    }
}

macro_rules! at {
    ($lvl:expr) => {
        crate::log::level() >= $lvl
    };
}
pub(crate) use at;

pub fn info(fmt: std::fmt::Arguments<'_>) {
    if level() >= Level::Info {
        eprintln!("sandkasten │ {fmt}");
    }
}

#[allow(dead_code)]
pub fn warn(fmt: std::fmt::Arguments<'_>) {
    if level() >= Level::Normal {
        eprintln!("sandkasten ⚠ {fmt}");
    }
}

#[allow(dead_code)]
pub fn debug(fmt: std::fmt::Arguments<'_>) {
    if level() >= Level::Debug {
        eprintln!("sandkasten ∙ {fmt}");
    }
}

#[allow(dead_code)]
pub fn trace(fmt: std::fmt::Arguments<'_>) {
    if level() >= Level::Trace {
        eprintln!("sandkasten ⋯ {fmt}");
    }
}

/// One-line summary of the profile's effective rules. Printed at Debug.
pub fn print_summary(p: &Profile) {
    if level() < Level::Debug {
        return;
    }
    let fs = &p.filesystem;
    let net = &p.network;
    let sys = &p.system;
    let proc_ = &p.process;

    let net_mode = if !net.outbound_tcp.is_empty() || !net.outbound_udp.is_empty() {
        "specific"
    } else if net.allow_localhost {
        "localhost"
    } else if net.allow_dns {
        "dns-only"
    } else {
        "none"
    };

    eprintln!(
        "sandkasten ∙ rules: {r_sub} read-subpaths, {rw_sub} rw-subpaths, \
         {r_lit} read-files, {rw_lit} rw-files, {deny} denies",
        r_sub = fs.read.len(),
        rw_sub = fs.read_write.len(),
        r_lit = fs.read_files.len(),
        rw_lit = fs.read_write_files.len(),
        deny = fs.deny.len(),
    );
    eprintln!(
        "sandkasten ∙ network: {net_mode} | outbound: {otcp} tcp / {oudp} udp{icmp}{raw} \
         | inbound: {itcp} tcp / {iudp} udp",
        otcp = net.outbound_tcp.len(),
        oudp = net.outbound_udp.len(),
        icmp = if net.allow_icmp { " | icmp" } else { "" },
        raw = if net.allow_raw_sockets {
            " | raw-sockets"
        } else {
            ""
        },
        itcp = net.inbound_tcp.len(),
        iudp = net.inbound_udp.len(),
    );
    eprintln!(
        "sandkasten ∙ process: fork={f}, exec={x} | system: sysctl={sy}, iokit={io}, ipc={ip}, mach={m}",
        f = proc_.allow_fork,
        x = proc_.allow_exec,
        sy = sys.allow_sysctl_read,
        io = sys.allow_iokit,
        ip = sys.allow_ipc,
        m = sys.mach_services.len(),
    );
}
