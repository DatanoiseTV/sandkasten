//! Plain-English summaries + structural diffs of profiles. No AI, no LLM —
//! deterministic rendering from the profile data model so the output is
//! reviewable, auditable, and stable across runs.

use crate::config::{Profile, Network};
use std::fmt::Write as _;

/// Produce a multi-paragraph human summary of what the profile grants and
/// denies. Intentionally verbose and readable; favour clarity over brevity.
pub fn explain(p: &Profile) -> String {
    let mut s = String::new();
    let name = p.name.as_deref().unwrap_or("(unnamed)");
    let _ = writeln!(s, "Profile: {name}");
    if let Some(d) = &p.description {
        let _ = writeln!(s, "  “{d}”");
    }
    if let Some(parent) = &p.extends {
        let _ = writeln!(s, "  extends template: {parent}");
    }
    s.push('\n');

    // ── Filesystem ───────────────────────────────────────
    s.push_str("Filesystem\n");
    let fs = &p.filesystem;
    if fs.read.is_empty()
        && fs.read_write.is_empty()
        && fs.read_files.is_empty()
        && fs.read_write_files.is_empty()
    {
        s.push_str("  • nothing readable. The sandbox cannot even open dynamic libraries.\n");
    } else {
        if !fs.read.is_empty() {
            let _ = writeln!(s, "  • read under: {}", fs.read.join(", "));
        }
        if !fs.read_write.is_empty() {
            let _ = writeln!(s, "  • read + write under: {}", fs.read_write.join(", "));
        }
        if !fs.read_files.is_empty() {
            let _ = writeln!(s, "  • read these specific files: {}", fs.read_files.join(", "));
        }
        if !fs.read_write_files.is_empty() {
            let _ = writeln!(s, "  • read+write these files: {}", fs.read_write_files.join(", "));
        }
    }
    if !fs.deny.is_empty() {
        let _ = writeln!(s, "  • explicitly denied (overrides any allow): {}", fs.deny.join(", "));
    }
    if !fs.rules.is_empty() {
        let _ = writeln!(s, "  • fine-grained rules:");
        for r in &fs.rules {
            let kind = if r.literal { "file" } else { "subtree" };
            let allows = if r.allow.is_empty() { "nothing".to_string() } else { r.allow.join(", ") };
            let denies = if r.deny.is_empty() { String::new() } else { format!(", denies: {}", r.deny.join(", ")) };
            let _ = writeln!(s, "      {kind} {} → allows: {allows}{denies}", r.path);
        }
    }
    s.push('\n');

    // ── Network ──────────────────────────────────────────
    s.push_str("Network\n");
    s.push_str(&explain_network(&p.network));
    s.push('\n');

    // ── Process ──────────────────────────────────────────
    s.push_str("Process\n");
    let _ = writeln!(s, "  • may fork:       {}", yn(p.process.allow_fork));
    let _ = writeln!(s, "  • may exec:       {}", yn(p.process.allow_exec));
    let _ = writeln!(s, "  • signal itself:  {}", yn(p.process.allow_signal_self));
    s.push('\n');

    // ── System ───────────────────────────────────────────
    s.push_str("System\n");
    let _ = writeln!(s, "  • sysctl reads:   {}", yn(p.system.allow_sysctl_read));
    let _ = writeln!(s, "  • IOKit:          {}", yn(p.system.allow_iokit));
    let _ = writeln!(s, "  • POSIX IPC:      {}", yn(p.system.allow_ipc));
    if p.system.allow_mach_all {
        s.push_str("  • Mach services:  ALL (macOS — broad; needed by browsers/Electron)\n");
    } else if !p.system.mach_services.is_empty() {
        let _ = writeln!(
            s,
            "  • Mach services:  {} listed",
            p.system.mach_services.len()
        );
    } else {
        s.push_str("  • Mach services:  none\n");
    }
    s.push('\n');

    // ── Environment ──────────────────────────────────────
    s.push_str("Environment\n");
    if p.env.pass_all {
        s.push_str("  • passes ALL parent environment variables to the sandbox.\n");
    } else if !p.env.pass.is_empty() {
        let _ = writeln!(
            s,
            "  • forwards only these env vars from the parent: {}",
            p.env.pass.join(", ")
        );
    } else {
        s.push_str("  • no env vars forwarded (scrubbed entirely).\n");
    }
    if !p.env.set.is_empty() {
        let _ = writeln!(
            s,
            "  • sets explicit env vars: {}",
            p.env.set.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    s.push('\n');

    // ── Limits ───────────────────────────────────────────
    let l = &p.limits;
    let any_limit = l.cpu_seconds.is_some()
        || l.memory_mb.is_some()
        || l.file_size_mb.is_some()
        || l.open_files.is_some()
        || l.processes.is_some()
        || l.stack_mb.is_some()
        || l.wall_timeout_seconds.is_some()
        || !l.core_dumps;
    if any_limit {
        s.push_str("Limits\n");
        if let Some(v) = l.cpu_seconds           { let _ = writeln!(s, "  • CPU seconds:      {v}"); }
        if let Some(v) = l.memory_mb             { let _ = writeln!(s, "  • Max memory:       {v} MiB"); }
        if let Some(v) = l.file_size_mb          { let _ = writeln!(s, "  • Max file size:    {v} MiB"); }
        if let Some(v) = l.open_files            { let _ = writeln!(s, "  • Max open FDs:     {v}"); }
        if let Some(v) = l.processes             { let _ = writeln!(s, "  • Max processes:    {v} (fork-bomb guard)"); }
        if let Some(v) = l.stack_mb              { let _ = writeln!(s, "  • Max stack:        {v} MiB"); }
        if let Some(v) = l.wall_timeout_seconds  { let _ = writeln!(s, "  • Wall-clock limit: {v} seconds (SIGTERM → SIGKILL +3s)"); }
        if !l.core_dumps                          { s.push_str("  • Core dumps disabled (crash can't spill memory to disk).\n"); }
        s.push('\n');
    }

    // ── Workspace / overlay / mocks ──────────────────────
    if p.workspace.path.is_some() || p.overlay.lower.is_some() || !p.mocks.files.is_empty() {
        s.push_str("Workspace / overlay / mocks\n");
        if let Some(w) = &p.workspace.path {
            let cd = if p.workspace.chdir { ", initial CWD" } else { "" };
            let _ = writeln!(s, "  • persistent workspace: {w}{cd}");
        }
        if let (Some(l), Some(u)) = (&p.overlay.lower, &p.overlay.upper) {
            let _ = writeln!(s, "  • Linux overlayfs: reads from {l}; writes land in {u}");
        }
        if !p.mocks.files.is_empty() {
            let names: Vec<_> = p.mocks.files.keys().cloned().collect();
            let _ = writeln!(s, "  • mock files via $SANDKASTEN_MOCKS: {}", names.join(", "));
        }
        s.push('\n');
    }

    s
}

fn explain_network(n: &Network) -> String {
    let mut s = String::new();
    let has_any = n.allow_localhost
        || n.allow_dns
        || n.allow_inbound
        || n.allow_icmp
        || n.allow_icmpv6
        || n.allow_sctp
        || n.allow_dccp
        || n.allow_udplite
        || n.allow_raw_sockets
        || n.allow_unix_sockets
        || !n.outbound_tcp.is_empty()
        || !n.outbound_udp.is_empty()
        || !n.inbound_tcp.is_empty()
        || !n.inbound_udp.is_empty()
        || !n.extra_protocols.is_empty()
        || !n.presets.is_empty()
        || !n.redirects.is_empty()
        || !n.blocks.is_empty()
        || !n.hosts_entries.is_empty()
        || !n.dns.servers.is_empty();
    if !has_any {
        s.push_str("  • fully isolated — no network at all.\n");
        return s;
    }
    if n.allow_localhost { s.push_str("  • loopback (127.0.0.1 / ::1) permitted\n"); }
    if n.allow_dns       { s.push_str("  • DNS resolution permitted\n"); }
    if n.allow_inbound   { s.push_str("  • may bind inbound listeners\n"); }
    if n.allow_icmp      { s.push_str("  • ICMP (ping)\n"); }
    if n.allow_icmpv6    { s.push_str("  • ICMPv6\n"); }
    if n.allow_sctp      { s.push_str("  • SCTP\n"); }
    if n.allow_dccp      { s.push_str("  • DCCP\n"); }
    if n.allow_udplite   { s.push_str("  • UDP-Lite\n"); }
    if n.allow_raw_sockets { s.push_str("  • RAW sockets (packet-crafting ability — privileged)\n"); }
    if n.allow_unix_sockets { s.push_str("  • UNIX-domain sockets\n"); }
    if !n.outbound_tcp.is_empty() {
        let _ = writeln!(s, "  • outbound TCP to: {}", n.outbound_tcp.join(", "));
    }
    if !n.outbound_udp.is_empty() {
        let _ = writeln!(s, "  • outbound UDP to: {}", n.outbound_udp.join(", "));
    }
    if !n.inbound_tcp.is_empty() {
        let _ = writeln!(s, "  • inbound TCP binds: {}", n.inbound_tcp.join(", "));
    }
    if !n.inbound_udp.is_empty() {
        let _ = writeln!(s, "  • inbound UDP binds: {}", n.inbound_udp.join(", "));
    }
    if !n.extra_protocols.is_empty() {
        let _ = writeln!(s, "  • extra L4 protocols: {}", n.extra_protocols.join(", "));
    }
    if !n.presets.is_empty() {
        let _ = writeln!(s, "  • protocol presets: {}", n.presets.join(", "));
    }
    if !n.redirects.is_empty() {
        s.push_str("  • Linux DNAT redirects:\n");
        for r in &n.redirects {
            let _ = writeln!(s, "      {} → {} ({})", r.from, r.to, r.protocol.as_deref().unwrap_or("tcp"));
        }
    }
    if !n.blocks.is_empty() {
        s.push_str("  • blocked outbound:\n");
        for b in &n.blocks {
            let p = b.port.as_deref().unwrap_or("*");
            let pr = b.protocol.as_deref().unwrap_or("tcp");
            let _ = writeln!(s, "      {} {}:{p}", pr, b.host);
        }
    }
    if !n.hosts_entries.is_empty() {
        s.push_str("  • /etc/hosts rewrites:\n");
        for (h, ip) in &n.hosts_entries {
            let _ = writeln!(s, "      {h} → {ip}");
        }
    }
    if !n.dns.servers.is_empty() {
        let _ = writeln!(
            s,
            "  • DNS servers overridden to: {}",
            n.dns.servers.join(", ")
        );
    }
    s
}

fn yn(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

// ── diff ─────────────────────────────────────────────────────────────────

pub fn diff(left: &Profile, right: &Profile) -> String {
    let mut s = String::new();
    let l_name = left.name.as_deref().unwrap_or("left");
    let r_name = right.name.as_deref().unwrap_or("right");

    let _ = writeln!(s, "--- {}", l_name);
    let _ = writeln!(s, "+++ {}", r_name);
    s.push('\n');

    // List diffs.
    macro_rules! list_diff {
        ($title:expr, $left:expr, $right:expr) => {{
            let l: std::collections::BTreeSet<_> = $left.iter().collect();
            let r: std::collections::BTreeSet<_> = $right.iter().collect();
            let only_l: Vec<_> = l.difference(&r).collect();
            let only_r: Vec<_> = r.difference(&l).collect();
            if !only_l.is_empty() || !only_r.is_empty() {
                let _ = writeln!(s, "{}:", $title);
                for x in only_l { let _ = writeln!(s, "  − {x}"); }
                for x in only_r { let _ = writeln!(s, "  + {x}"); }
                s.push('\n');
            }
        }};
    }
    macro_rules! bool_diff {
        ($title:expr, $l:expr, $r:expr) => {{
            if $l != $r {
                let _ = writeln!(s, "{}:  {} → {}", $title, $l, $r);
            }
        }};
    }

    list_diff!("filesystem.read",             left.filesystem.read,             right.filesystem.read);
    list_diff!("filesystem.read_write",       left.filesystem.read_write,       right.filesystem.read_write);
    list_diff!("filesystem.read_files",       left.filesystem.read_files,       right.filesystem.read_files);
    list_diff!("filesystem.read_write_files", left.filesystem.read_write_files, right.filesystem.read_write_files);
    list_diff!("filesystem.deny",             left.filesystem.deny,             right.filesystem.deny);

    list_diff!("network.outbound_tcp", left.network.outbound_tcp, right.network.outbound_tcp);
    list_diff!("network.outbound_udp", left.network.outbound_udp, right.network.outbound_udp);
    list_diff!("network.inbound_tcp",  left.network.inbound_tcp,  right.network.inbound_tcp);
    list_diff!("network.inbound_udp",  left.network.inbound_udp,  right.network.inbound_udp);
    list_diff!("network.presets",      left.network.presets,      right.network.presets);

    bool_diff!("network.allow_localhost",    left.network.allow_localhost,    right.network.allow_localhost);
    bool_diff!("network.allow_dns",          left.network.allow_dns,          right.network.allow_dns);
    bool_diff!("network.allow_inbound",      left.network.allow_inbound,      right.network.allow_inbound);
    bool_diff!("network.allow_icmp",         left.network.allow_icmp,         right.network.allow_icmp);
    bool_diff!("network.allow_icmpv6",       left.network.allow_icmpv6,       right.network.allow_icmpv6);
    bool_diff!("network.allow_sctp",         left.network.allow_sctp,         right.network.allow_sctp);
    bool_diff!("network.allow_dccp",         left.network.allow_dccp,         right.network.allow_dccp);
    bool_diff!("network.allow_udplite",      left.network.allow_udplite,      right.network.allow_udplite);
    bool_diff!("network.allow_raw_sockets",  left.network.allow_raw_sockets,  right.network.allow_raw_sockets);
    bool_diff!("network.allow_unix_sockets", left.network.allow_unix_sockets, right.network.allow_unix_sockets);

    bool_diff!("process.allow_fork",        left.process.allow_fork,        right.process.allow_fork);
    bool_diff!("process.allow_exec",        left.process.allow_exec,        right.process.allow_exec);
    bool_diff!("process.allow_signal_self", left.process.allow_signal_self, right.process.allow_signal_self);

    bool_diff!("system.allow_sysctl_read", left.system.allow_sysctl_read, right.system.allow_sysctl_read);
    bool_diff!("system.allow_iokit",       left.system.allow_iokit,       right.system.allow_iokit);
    bool_diff!("system.allow_ipc",         left.system.allow_ipc,         right.system.allow_ipc);
    bool_diff!("system.allow_mach_all",    left.system.allow_mach_all,    right.system.allow_mach_all);
    list_diff!("system.mach_services",     left.system.mach_services,     right.system.mach_services);

    bool_diff!("env.pass_all", left.env.pass_all, right.env.pass_all);
    list_diff!("env.pass",     left.env.pass,     right.env.pass);

    if s.lines().count() == 3 {
        s.push_str("(no structural differences)\n");
    }
    s
}
