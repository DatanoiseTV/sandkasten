//! Generate a Seatbelt Profile Language (SBPL) source string from a Profile.
//!
//! SBPL is a TinyScheme-dialect DSL whose rules are evaluated top-to-bottom
//! with last-match-wins semantics. We emit:
//!   1. `(version 1)` header
//!   2. `(deny default)` — fail-closed
//!   3. base allowances that every Mach-O binary needs to even start
//!   4. Mach service lookups
//!   5. File read / read-write allows (broad → narrow)
//!   6. File single-file allows (literals)
//!   7. Network allows
//!   8. Deny overrides (evaluated last → they win)

use crate::config::{Endpoint, HostSpec, PortSpec, Profile};
use std::fmt::Write;

pub fn generate(p: &Profile) -> String {
    generate_for_target(p, None)
}

/// Like [`generate`], but if `target` is set, unconditionally allow
/// `process-exec` on that one literal path so the initial `execve` that
/// sandkasten itself calls after `sandbox_init` always succeeds. Without
/// this, a profile with `allow_exec = false` blocks its own entry point
/// on macOS: the policy takes effect *before* the `execve` that launches
/// argv[0], so there is no way to ever reach the sandboxed binary.
/// `file-map-executable` is also granted for the target so dyld can mmap
/// the binary itself (separate permission from `file-read*`).
pub fn generate_for_target(p: &Profile, target: Option<&str>) -> String {
    let mut s = String::with_capacity(4096);
    let _ = writeln!(s, ";; sandkasten generated profile");
    if let Some(n) = &p.name {
        let _ = writeln!(s, ";; name: {n}");
    }
    if let Some(d) = &p.description {
        let _ = writeln!(s, ";; description: {d}");
    }
    s.push_str("(version 1)\n");
    s.push_str("(deny default)\n");
    // Suppress deny-log spam on Normal/Info. At Trace (`-vvv`), leave denies
    // logged so our post-hoc unified-log capture can show them.
    if !crate::log::at!(crate::log::Level::Trace) {
        s.push_str("(deny default (with no-log))\n");
    }
    s.push('\n');

    // --- base allowances ---------------------------------------------------
    s.push_str(";; --- base ---\n");
    // Every Mach-O binary needs this to look up its own pid info.
    s.push_str("(allow process-info-pidinfo (target self))\n");
    s.push_str("(allow process-info-setcontrol (target self))\n");
    if p.process.allow_signal_self {
        s.push_str("(allow signal (target self))\n");
    }
    if p.process.allow_fork {
        s.push_str("(allow process-fork)\n");
    }
    if p.process.allow_exec {
        // Children inherit the sandbox by default — no `(with no-sandbox)`.
        s.push_str("(allow process-exec)\n");
        s.push_str("(allow process-exec-interpreter)\n");
    } else if let Some(t) = target {
        // One-shot grant for the initial execve sandkasten itself performs.
        // Children still can't exec new programs.
        let _ = writeln!(s, "(allow process-exec (literal {}))", quote(t));
        let _ = writeln!(s, "(allow process-exec-interpreter (literal {}))", quote(t));
    }
    // dyld bootstrap — see Apple's /System/Library/Sandbox/Profiles/dyld-support.sb.
    //
    // On macOS 14+, every dynamic Mach-O binary loads dylibs from the
    // shared cache stored in cryptex graft points:
    //   /System/Cryptexes/OS        (symlink on snapshot boots)
    //   /System/Volumes/Preboot/Cryptexes/OS (the actual cryptex mount)
    // Without access to these, even `/usr/bin/true` SIGABRTs during
    // startup before main() runs. We also have to grant `file-read*
    // file-test-existence` on every ancestor directory (libignition in
    // dyld opens "/" as an openat(2) root and fstatats the graft dirs),
    // and `file-map-executable` (separate permission from file-read*)
    // for dyld to mmap the cache pages executable.
    //
    // These grants are unconditional when any exec is allowed: they are
    // the bare minimum for a dynamic binary to even reach main(). The
    // actual read scope is still constrained by the profile's read list.
    if p.process.allow_exec || target.is_some() {
        s.push_str("(allow file-map-executable)\n");
        s.push_str(";; dyld cryptex + root-directory bootstrap\n");
        s.push_str("(allow file-read* file-test-existence (literal \"/\"))\n");
        s.push_str(
            "(allow file-read* file-test-existence file-map-executable \
             (subpath \"/System/Cryptexes/OS\") \
             (subpath \"/System/Volumes/Preboot/Cryptexes/OS\"))\n",
        );
        s.push_str(
            "(allow file-read* file-test-existence \
             (literal \"/System/Volumes\") \
             (literal \"/System/Volumes/Preboot\") \
             (literal \"/System/Volumes/Preboot/Cryptexes\") \
             (literal \"/System/Cryptexes\"))\n",
        );
    }
    if p.system.allow_sysctl_read {
        s.push_str("(allow sysctl-read)\n");
    }
    if p.filesystem.allow_metadata_read {
        // Reading stat-like metadata is nearly always safe and breaks fewer binaries.
        s.push_str("(allow file-read-metadata)\n");
    }
    if p.system.allow_ipc {
        s.push_str("(allow ipc-posix-shm)\n");
        s.push_str("(allow ipc-posix-sem)\n");
    }
    if p.system.allow_iokit {
        s.push_str("(allow iokit-open)\n");
    }
    s.push('\n');

    // --- Mach services -----------------------------------------------------
    if p.system.allow_mach_all {
        s.push_str(";; --- mach services (ALL — allow_mach_all = true) ---\n");
        s.push_str("(allow mach-lookup)\n");
        s.push_str("(allow mach-register)\n");
        s.push_str("(allow mach-cross-domain-lookup)\n\n");
    } else if !p.system.mach_services.is_empty() {
        s.push_str(";; --- mach services ---\n");
        for svc in &p.system.mach_services {
            let _ = writeln!(s, "(allow mach-lookup (global-name {}))", quote(svc));
        }
        s.push('\n');
    }

    // --- filesystem reads --------------------------------------------------
    if !p.filesystem.read.is_empty() || !p.filesystem.read_files.is_empty() {
        s.push_str(";; --- filesystem: read ---\n");
        for path in &p.filesystem.read {
            for p in firmlink_variants(path) {
                let _ = writeln!(s, "(allow file-read* (subpath {}))", quote(&p));
            }
        }
        for path in &p.filesystem.read_files {
            for p in firmlink_variants(path) {
                let _ = writeln!(s, "(allow file-read* (literal {}))", quote(&p));
            }
        }
        s.push('\n');
    }

    // --- filesystem read+write --------------------------------------------
    if !p.filesystem.read_write.is_empty() || !p.filesystem.read_write_files.is_empty() {
        s.push_str(";; --- filesystem: read+write ---\n");
        for path in &p.filesystem.read_write {
            for p in firmlink_variants(path) {
                let _ = writeln!(s, "(allow file-read* file-write* (subpath {}))", quote(&p));
            }
        }
        for path in &p.filesystem.read_write_files {
            for p in firmlink_variants(path) {
                let _ = writeln!(s, "(allow file-read* file-write* (literal {}))", quote(&p));
            }
        }
        s.push('\n');
    }

    // --- network -----------------------------------------------------------
    let has_net = p.network.allow_localhost
        || p.network.allow_dns
        || p.network.allow_inbound
        || !p.network.outbound_tcp.is_empty()
        || !p.network.outbound_udp.is_empty()
        || !p.network.inbound_tcp.is_empty()
        || !p.network.inbound_udp.is_empty();
    if has_net {
        s.push_str(";; --- network ---\n");

        if p.network.allow_localhost {
            // Modern macOS sandbox grammar accepts only `localhost` or `*`
            // as host — IP literals and specific hostnames are rejected.
            s.push_str("(allow network-outbound (remote tcp \"localhost:*\"))\n");
            s.push_str("(allow network-outbound (remote udp \"localhost:*\"))\n");
        }

        if p.network.allow_dns {
            // DNS is UDP:53 (and TCP:53 for large responses) on any host.
            s.push_str("(allow network-outbound (remote udp \"*:53\"))\n");
            s.push_str("(allow network-outbound (remote tcp \"*:53\"))\n");
            // Resolver helpers sometimes also use a UNIX-domain socket to mDNSResponder;
            // granted via mach service `com.apple.dnssd.service` if caller wants full DNS.
        }

        let mut widened = false;
        for ep in &p.network.outbound_tcp {
            let e = crate::config::parse_endpoint(ep).expect("validated earlier");
            s.push_str(&emit_net("network-outbound", "tcp", &e, &mut widened));
        }
        for ep in &p.network.outbound_udp {
            let e = crate::config::parse_endpoint(ep).expect("validated earlier");
            s.push_str(&emit_net("network-outbound", "udp", &e, &mut widened));
        }
        if widened {
            s.push_str(
                ";; NOTE: macOS's Seatbelt grammar rejects specific hostnames/IPs\n\
                 ;; in network filters — entries have been widened to `*:PORT`.\n\
                 ;; Per-host outbound filtering on macOS requires a userspace proxy.\n",
            );
        }

        if p.network.allow_icmp {
            s.push_str("(allow network-outbound (remote icmp \"*:*\"))\n");
        }
        if p.network.allow_icmpv6 {
            s.push_str("(allow network-outbound (remote icmp6 \"*:*\"))\n");
        }
        if p.network.allow_unix_sockets {
            // AF_UNIX bind and connect. Chromium, Electron, VS Code,
            // Docker-for-Mac, gpg-agent etc. all need this. The precise
            // Seatbelt filter for unix sockets varies by macOS version, so
            // we grant the socket() syscall itself and broad local bind;
            // the filesystem layer still gates which paths the socket
            // file may be created at.
            s.push_str("(allow system-socket)\n");
            s.push_str("(allow network-bind)\n");
        }

        // SCTP / DCCP / UDPLite: Seatbelt's per-protocol filter syntax is
        // undocumented for these, and support varies. Grant at the broad
        // `remote ip` level — destination port is not filterable here.
        let has_exotic_proto = p.network.allow_sctp
            || p.network.allow_dccp
            || p.network.allow_udplite
            || !p.network.extra_protocols.is_empty();
        if has_exotic_proto {
            s.push_str("(allow network-outbound (remote ip \"*:*\"))\n");
            s.push_str(
                ";; NOTE: SCTP/DCCP/UDPLite/extra_protocols on macOS widen to\n\
                 ;; `remote ip *:*` — port-level filtering for these is Linux-only.\n",
            );
        }
        if p.network.allow_raw_sockets {
            // SBPL has no direct raw-socket filter — this broad grant lets
            // the process open AF_INET/SOCK_RAW. Highly privileged: avoid.
            s.push_str(";; WARNING: raw sockets grant packet-crafting ability.\n");
            s.push_str("(allow network-outbound)\n");
        }
        for proto in &p.network.extra_protocols {
            match proto.as_str() {
                "icmp" => s.push_str("(allow network-outbound (remote icmp \"*:*\"))\n"),
                "icmp6" | "icmpv6" => {
                    s.push_str("(allow network-outbound (remote icmp6 \"*:*\"))\n");
                }
                "ip" | "ip4" | "ip6" => {
                    let _ = writeln!(s, "(allow network-outbound (remote {proto} \"*:*\"))");
                }
                other => {
                    let _ = writeln!(
                        s,
                        ";; extra_protocol {other:?} has no SBPL mapping on macOS — ignored"
                    );
                }
            }
        }

        if p.network.allow_inbound
            || !p.network.inbound_tcp.is_empty()
            || !p.network.inbound_udp.is_empty()
        {
            if p.network.allow_inbound
                && p.network.inbound_tcp.is_empty()
                && p.network.inbound_udp.is_empty()
            {
                // Shortcut: allow_inbound with no specific endpoints = wildcard bind+accept.
                s.push_str("(allow network-bind (local tcp \"*:*\"))\n");
                s.push_str("(allow network-bind (local udp \"*:*\"))\n");
                s.push_str("(allow network-inbound (local tcp \"*:*\"))\n");
                s.push_str("(allow network-inbound (local udp \"*:*\"))\n");
            } else {
                let mut iw = false;
                for ep in &p.network.inbound_tcp {
                    let e = crate::config::parse_endpoint(ep).expect("validated earlier");
                    let local = local_sbpl(&e, &mut iw);
                    let _ = writeln!(s, "(allow network-bind (local tcp {local}))");
                    let _ = writeln!(s, "(allow network-inbound (local tcp {local}))");
                }
                for ep in &p.network.inbound_udp {
                    let e = crate::config::parse_endpoint(ep).expect("validated earlier");
                    let local = local_sbpl(&e, &mut iw);
                    let _ = writeln!(s, "(allow network-bind (local udp {local}))");
                    let _ = writeln!(s, "(allow network-inbound (local udp {local}))");
                }
                if iw {
                    s.push_str(";; NOTE: inbound entries widened to `*:PORT` (see above).\n");
                }
            }
        }
        s.push('\n');
    }

    // --- fine-grained per-path rules (evaluated before blanket denies) -----
    if !p.filesystem.rules.is_empty() {
        s.push_str(";; --- fine-grained rules ---\n");
        for rule in &p.filesystem.rules {
            let filter = if rule.literal {
                format!("(literal {})", quote(&rule.path))
            } else {
                format!("(subpath {})", quote(&rule.path))
            };
            for op in &rule.allow {
                for sbpl_op in map_op(op) {
                    let _ = writeln!(s, "(allow {sbpl_op} {filter})");
                }
            }
            for op in &rule.deny {
                for sbpl_op in map_op(op) {
                    let _ = writeln!(s, "(deny {sbpl_op} {filter})");
                }
            }
        }
        s.push('\n');
    }

    // --- blanket deny overrides (evaluated last = winning) -----------------
    if !p.filesystem.deny.is_empty() {
        s.push_str(";; --- deny overrides (last match wins) ---\n");
        for path in &p.filesystem.deny {
            let _ = writeln!(s, "(deny file-read* file-write* (subpath {}))", quote(path));
        }
    }
    if !p.filesystem.hide.is_empty() {
        s.push_str(";; --- hide paths (macOS best-effort — returns EPERM, not ENOENT) ---\n");
        for path in &p.filesystem.hide {
            let _ = writeln!(s, "(deny file-read* file-write* (subpath {}))", quote(path));
        }
        s.push_str(
            ";; NOTE: macOS cannot make denied paths look like ENOENT without a\n\
             ;; DYLD_INSERT_LIBRARIES interposer. The sandbox returns EPERM instead.\n",
        );
    }
    if !p.filesystem.rewire.is_empty() {
        s.push_str(
            ";; NOTE: [[filesystem.rewire]] is Linux-only (mount-namespace bind).\n\
             ;; On macOS, prefer symlinks on disk under the sandbox's writable area.\n",
        );
    }

    // --- network blocks (best-effort on macOS — grammar limits us) --------
    if !p.network.blocks.is_empty() {
        s.push_str(";; --- network blocks ---\n");
        for b in &p.network.blocks {
            let host = match b.host.as_str() {
                "localhost" | "*" => b.host.clone(),
                _ => "*".to_string(),
            };
            let port = b.port.as_deref().unwrap_or("*");
            let proto = b.protocol.as_deref().unwrap_or("tcp");
            if proto == "tcp" || proto == "udp" {
                let _ = writeln!(
                    s,
                    "(deny network-outbound (remote {proto} \"{host}:{port}\"))"
                );
            }
        }
        if p.network
            .blocks
            .iter()
            .any(|b| !matches!(b.host.as_str(), "localhost" | "*"))
        {
            s.push_str(
                ";; NOTE: macOS Seatbelt grammar rejects per-host network denies;\n\
                 ;; specific hostnames/IPs were widened to `*:PORT`. For precise\n\
                 ;; per-IP blocking on macOS, use a PF-based or proxy-based approach.\n",
            );
        }
    }

    if !p.network.redirects.is_empty() {
        s.push_str(
            ";; NOTE: [[network.redirects]] is Linux-only (nftables DNAT).\n\
             ;; On macOS, prefer [network.hosts_entries] for hostname-based redirects.\n",
        );
    }

    s
}

/// Map user-facing op names to SBPL operation tokens. Unknown ops map to
/// nothing (silently ignored — callers should validate via `validate_ops`).
fn map_op(op: &str) -> &'static [&'static str] {
    match op.to_ascii_lowercase().as_str() {
        "read" => &["file-read*"],
        "write" => &["file-write-data"],
        "create" => &["file-write-create"],
        "delete" => &["file-write-unlink"],
        // Rename is modelled as create + unlink.
        "rename" => &["file-write-create", "file-write-unlink"],
        "chmod" => &["file-write-mode"],
        "chown" => &["file-write-owner"],
        "xattr" => &["file-write-xattr"],
        "ioctl" => &["file-ioctl"],
        "exec" => &["process-exec"],
        // Convenience aggregates.
        "all" => &["file-read*", "file-write*", "file-ioctl"],
        "write-all" => &["file-write*"],
        _ => &[],
    }
}

fn local_sbpl(e: &Endpoint, widened: &mut bool) -> String {
    let host_str = match &e.host {
        HostSpec::Any => "*".to_string(),
        HostSpec::Name(n) if n == "localhost" => "localhost".to_string(),
        HostSpec::Ipv4(v4) if v4.is_loopback() => "localhost".to_string(),
        HostSpec::Ipv6(v6) if v6.is_loopback() => "localhost".to_string(),
        _ => {
            *widened = true;
            "*".to_string()
        }
    };
    let port_str = match e.port {
        PortSpec::Any => "*".to_string(),
        PortSpec::Num(n) => n.to_string(),
        PortSpec::Range(_, _) => {
            *widened = true;
            "*".to_string()
        }
    };
    format!("\"{host_str}:{port_str}\"")
}

/// Emit an SBPL network filter. Modern macOS's Seatbelt grammar accepts only
/// `localhost` or `*` as hostname in `remote tcp`/`remote udp` — IP literals
/// and specific hostnames are rejected by `sandbox_init`. We therefore
/// normalize the user's host to `localhost` (for loopback) or `*` (anything
/// else) and preserve port-level filtering. A warning is emitted once if we
/// had to widen.
fn emit_net(kind: &str, proto: &str, e: &Endpoint, widened: &mut bool) -> String {
    let (host_str, had_to_widen) = match &e.host {
        HostSpec::Any => ("*".to_string(), false),
        HostSpec::Name(n) if n == "localhost" => ("localhost".to_string(), false),
        HostSpec::Ipv4(v4) if v4.is_loopback() => ("localhost".to_string(), false),
        HostSpec::Ipv6(v6) if v6.is_loopback() => ("localhost".to_string(), false),
        HostSpec::Name(_)
        | HostSpec::Ipv4(_)
        | HostSpec::Ipv6(_)
        | HostSpec::Ipv4Cidr(_, _)
        | HostSpec::Ipv6Cidr(_, _) => ("*".to_string(), true),
    };
    if had_to_widen {
        *widened = true;
    }
    let (port_str, port_widened) = match e.port {
        PortSpec::Any => ("*".to_string(), false),
        PortSpec::Num(n) => (n.to_string(), false),
        // Seatbelt grammar has no port-range — widen to `*`.
        PortSpec::Range(_, _) => ("*".to_string(), true),
    };
    if port_widened {
        *widened = true;
    }
    format!("(allow {kind} (remote {proto} \"{host_str}:{port_str}\"))\n")
}

/// On macOS, `/etc`, `/tmp`, and `/var` are symlinks into `/private/*`.
/// Seatbelt resolves symlinks before checking `literal` / `subpath` rules,
/// so a rule on `/etc/hosts` will not match when a process opens
/// `/private/etc/hosts` — which is what every open of `/etc/hosts` really
/// becomes. Emit both forms so the user doesn't need to know the trick.
fn firmlink_variants(path: &str) -> Vec<String> {
    let prefixes = ["/etc/", "/tmp/", "/var/"];
    let literals = ["/etc", "/tmp", "/var"];
    let mut out = vec![path.to_string()];
    for pfx in prefixes {
        if let Some(rest) = path.strip_prefix(pfx) {
            out.push(format!("/private{pfx}{rest}"));
            return out;
        }
    }
    for lit in literals {
        if path == lit {
            out.push(format!("/private{lit}"));
            return out;
        }
    }
    out
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Filesystem, Network, Process, Profile, System};

    #[test]
    fn renders_header_and_default_deny() {
        let p = Profile::default();
        let s = generate(&p);
        assert!(s.contains("(version 1)"));
        assert!(s.contains("(deny default)"));
    }

    #[test]
    fn quote_escapes_backslash_and_quote() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn widens_specific_hosts_to_wildcard_on_macos_grammar() {
        let mut p = Profile::default();
        p.network.outbound_tcp = vec!["192.168.1.5:443".into(), "[::1]:8080".into()];
        p.validate().unwrap();
        let s = generate(&p);
        // loopback → localhost
        assert!(s.contains("(remote tcp \"localhost:8080\")"));
        // non-loopback IP → widened to *
        assert!(s.contains("(remote tcp \"*:443\")"));
        // user-facing warning
        assert!(s.contains("widened"));
    }

    #[test]
    fn deny_overrides_come_after_allows() {
        let mut p = Profile::default();
        p.filesystem.read = vec!["/".into()];
        p.filesystem.deny = vec!["/Users/alice/.ssh".into()];
        let s = generate(&p);
        let allow_pos = s.find("(allow file-read* (subpath \"/\"))").unwrap();
        let deny_pos = s
            .find("(deny file-read* file-write* (subpath \"/Users/alice/.ssh\"))")
            .unwrap();
        assert!(deny_pos > allow_pos);
    }

    #[test]
    fn strict_template_parses_and_renders() {
        let mut p = Profile::from_toml_str(crate::templates::STRICT).unwrap();
        let ctx = crate::config::ExpandContext {
            cwd: std::path::PathBuf::from("/tmp"),
            exe_dir: None,
            home: Some(std::path::PathBuf::from("/tmp")),
        };
        p.expand_paths(&ctx).unwrap();
        p.validate().unwrap();
        let s = generate(&p);
        assert!(s.contains("(allow mach-lookup (global-name \"com.apple.system.logger\"))"));
        assert!(s.contains("(allow file-read* (subpath \"/usr/lib\"))"));
    }

    #[test]
    fn firmlink_variants_alias_etc_tmp_var_into_private() {
        let mut p = Profile::default();
        p.filesystem.read_files = vec!["/etc/hosts".into(), "/var/run/resolv.conf".into()];
        let s = generate(&p);
        assert!(s.contains("(allow file-read* (literal \"/etc/hosts\"))"));
        assert!(s.contains("(allow file-read* (literal \"/private/etc/hosts\"))"));
        assert!(s.contains("(allow file-read* (literal \"/var/run/resolv.conf\"))"));
        assert!(s.contains("(allow file-read* (literal \"/private/var/run/resolv.conf\"))"));
    }

    #[test]
    fn target_grants_initial_exec_when_allow_exec_is_false() {
        let p = Profile::default();
        // allow_exec defaults to false.
        let without = generate(&p);
        assert!(!without.contains("process-exec"));

        let with = generate_for_target(&p, Some("/usr/bin/true"));
        assert!(with.contains("(allow process-exec (literal \"/usr/bin/true\"))"));
        // dyld bootstrap must also be present so the initial execve can load.
        assert!(with.contains("(allow file-map-executable)"));
        assert!(with.contains("(literal \"/System/Volumes/Preboot/Cryptexes\")"));
    }

    // Keep the imports used in tests reachable.
    #[allow(dead_code)]
    fn _force_use(_: Filesystem, _: Network, _: Process, _: System) {}
}
