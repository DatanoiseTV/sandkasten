//! Per-IP outbound filtering via nftables, applied inside the netns.
//!
//! Invariants assumed by the caller:
//!
//! * This function runs **inside the forked child**, after `unshare` has
//!   placed the process in a private netns but before Landlock + seccomp.
//! * `/sbin/nft` or `/usr/sbin/nft` (or `nft` on `$PATH`) exists. When it
//!   doesn't, we print a warning and return `Ok(())` — the netns by itself
//!   is already a hard outbound barrier.
//! * The process holds `CAP_NET_ADMIN` in the current user namespace
//!   (granted by our `CLONE_NEWUSER`).
//!
//! Rule shape:
//!
//! ```text
//! table inet sandkasten {
//!   chain output {
//!     type filter hook output priority 0; policy drop;
//!     oif lo accept
//!     ct state established,related accept
//!     # allow_dns
//!     udp dport 53 accept
//!     tcp dport 53 accept
//!     # allow_icmp
//!     ip protocol icmp accept
//!     # outbound_tcp entries
//!     ip  daddr 1.2.3.4 tcp dport 443 accept
//!     ip6 daddr 2001:db8::/128 tcp dport 443 accept
//!   }
//! }
//! ```
//!
//! External connectivity into the netns is a separate concern —
//! sandkasten does not create veth / set up pasta. Users wanting real
//! outbound traffic with per-IP filtering run the sandbox inside an
//! already-plumbed netns (pasta, slirp4netns, rootless network providers),
//! and these rules then enforce the policy.

use crate::config::{HostSpec, Network, PortSpec};
use anyhow::{anyhow, Context, Result};
use std::io::Write as _;
use std::process::{Command, Stdio};

pub fn apply_if_relevant(net: &Network) -> Result<()> {
    let has_allowlist = !net.outbound_tcp.is_empty()
        || !net.outbound_udp.is_empty()
        || net.allow_dns
        || net.allow_icmp
        || net.allow_icmpv6;
    let has_rewrites = !net.redirects.is_empty() || !net.blocks.is_empty();
    if !has_allowlist && !has_rewrites {
        // Nothing to enforce beyond what the netns already denies.
        return Ok(());
    }

    let Some(nft) = which("nft") else {
        eprintln!(
            "sandkasten ⚠ nftables: `nft` not found on $PATH — per-IP outbound \
             rules are not applied. (The private netns still blocks all outbound \
             traffic unless you've set up pasta/slirp4netns.)"
        );
        return Ok(());
    };

    let ruleset = render_ruleset(net)?;
    let mut child = Command::new(&nft)
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", nft.display()))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("nft stdin not captured"))?;
        stdin.write_all(ruleset.as_bytes())?;
    }
    let out = child.wait_with_output().context("waiting for nft")?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft load failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

fn render_ruleset(net: &Network) -> Result<String> {
    let mut rules = String::new();
    rules.push_str("table inet sandkasten {\n");

    // NAT hook for DNAT redirects — must come before the filter chain so
    // rewritten packets are then evaluated by the allowlist.
    if !net.redirects.is_empty() {
        rules.push_str("    chain nat_output {\n");
        rules.push_str("        type nat hook output priority -100;\n");
        for r in &net.redirects {
            emit_redirect(&mut rules, r)?;
        }
        rules.push_str("    }\n");
    }

    rules.push_str("    chain output {\n");
    rules.push_str("        type filter hook output priority 0; policy drop;\n");
    rules.push_str("        oif lo accept\n");
    rules.push_str("        ct state established,related accept\n");

    // Explicit blocks first — evaluated before any accept rules below.
    for b in &net.blocks {
        emit_block(&mut rules, b)?;
    }

    if net.allow_dns {
        rules.push_str("        udp dport 53 accept\n");
        rules.push_str("        tcp dport 53 accept\n");
    }
    if net.allow_icmp {
        rules.push_str("        ip protocol icmp accept\n");
    }
    if net.allow_icmpv6 {
        rules.push_str("        ip6 nexthdr icmpv6 accept\n");
    }
    if net.allow_sctp {
        rules.push_str("        meta l4proto sctp accept\n");
    }
    if net.allow_dccp {
        rules.push_str("        meta l4proto dccp accept\n");
    }
    if net.allow_udplite {
        rules.push_str("        meta l4proto udplite accept\n");
    }
    for extra in &net.extra_protocols {
        rules.push_str(&format!(
            "        meta l4proto {} accept  # via extra_protocols\n",
            extra.to_ascii_lowercase()
        ));
    }
    for ep in &net.outbound_tcp {
        emit_host_port(&mut rules, "tcp", ep)?;
    }
    for ep in &net.outbound_udp {
        emit_host_port(&mut rules, "udp", ep)?;
    }

    rules.push_str("    }\n");
    rules.push_str("}\n");
    Ok(rules)
}

fn emit_redirect(rules: &mut String, r: &crate::config::Redirect) -> Result<()> {
    let from = crate::config::parse_endpoint(&r.from)
        .with_context(|| format!("redirect from {:?}", r.from))?;
    let to =
        crate::config::parse_endpoint(&r.to).with_context(|| format!("redirect to {:?}", r.to))?;
    let proto = r.protocol.as_deref().unwrap_or("tcp");
    if proto != "tcp" && proto != "udp" {
        return Err(anyhow!(
            "redirect protocol must be tcp or udp, got {proto:?}"
        ));
    }
    // Destination (from) matcher.
    let (daddr_fam, daddr_val) = match &from.host {
        crate::config::HostSpec::Ipv4(v) => ("ip", v.to_string()),
        crate::config::HostSpec::Ipv6(v) => ("ip6", v.to_string()),
        crate::config::HostSpec::Ipv4Cidr(v, mask) => ("ip", format!("{v}/{mask}")),
        crate::config::HostSpec::Ipv6Cidr(v, mask) => ("ip6", format!("{v}/{mask}")),
        crate::config::HostSpec::Name(_) | crate::config::HostSpec::Any => {
            return Err(anyhow!(
                "redirect `from` must be an IP or CIDR literal; got {:?} — use hosts_entries for hostnames",
                r.from
            ))
        }
    };
    let dport_clause = match from.port {
        crate::config::PortSpec::Any => String::new(),
        crate::config::PortSpec::Num(n) => format!(" {proto} dport {n}"),
        crate::config::PortSpec::Range(lo, hi) => format!(" {proto} dport {lo}-{hi}"),
    };
    // Target (to).
    let to_str = match (&to.host, to.port) {
        (crate::config::HostSpec::Ipv4(v), crate::config::PortSpec::Num(p)) => format!("{v}:{p}"),
        (crate::config::HostSpec::Ipv4(v), crate::config::PortSpec::Any) => v.to_string(),
        (crate::config::HostSpec::Ipv6(v), crate::config::PortSpec::Num(p)) => format!("[{v}]:{p}"),
        (crate::config::HostSpec::Ipv6(v), crate::config::PortSpec::Any) => format!("[{v}]"),
        (_, crate::config::PortSpec::Range(_, _)) => {
            return Err(anyhow!(
                "redirect `to` cannot be a port range — pick a single target port"
            ))
        }
        (
            crate::config::HostSpec::Name(_)
            | crate::config::HostSpec::Any
            | crate::config::HostSpec::Ipv4Cidr(_, _)
            | crate::config::HostSpec::Ipv6Cidr(_, _),
            _,
        ) => {
            return Err(anyhow!(
                "redirect `to` must be a single IP[:port] — CIDR / hostname / wildcard not allowed; got {:?}",
                r.to
            ))
        }
    };
    rules.push_str(&format!(
        "        {daddr_fam} daddr {daddr_val}{dport_clause} dnat to {to_str}\n"
    ));
    Ok(())
}

fn emit_block(rules: &mut String, b: &crate::config::Block) -> Result<()> {
    let proto = b.protocol.as_deref().unwrap_or("tcp");
    let port_clause = match b.port.as_deref() {
        None | Some("") | Some("*") => String::new(),
        Some(p) => format!(" {proto} dport {p}"),
    };
    // Resolve host: IP literal or hostname → A/AAAA at rule-load time.
    if let Ok(v4) = b.host.parse::<std::net::Ipv4Addr>() {
        rules.push_str(&format!("        ip daddr {v4}{port_clause} reject\n"));
    } else if let Ok(v6) = b.host.parse::<std::net::Ipv6Addr>() {
        rules.push_str(&format!("        ip6 daddr {v6}{port_clause} reject\n"));
    } else {
        match std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:0", b.host)) {
            Ok(addrs) => {
                for a in addrs {
                    match a {
                        std::net::SocketAddr::V4(v) => rules.push_str(&format!(
                            "        ip daddr {}{port_clause} reject  # {}\n",
                            v.ip(),
                            b.host
                        )),
                        std::net::SocketAddr::V6(v) => rules.push_str(&format!(
                            "        ip6 daddr {}{port_clause} reject  # {}\n",
                            v.ip(),
                            b.host
                        )),
                    }
                }
            }
            Err(_) => rules.push_str(&format!(
                "        # could not resolve {} — block skipped\n",
                b.host
            )),
        }
    }
    Ok(())
}

fn emit_host_port(rules: &mut String, proto: &str, endpoint: &str) -> Result<()> {
    let e = crate::config::parse_endpoint(endpoint)
        .with_context(|| format!("parse endpoint {endpoint}"))?;
    // Separate proto/port clause from the host/daddr clause so we don't emit
    // double `{proto}` tokens when there is no explicit daddr match.
    let port_match = match e.port {
        PortSpec::Any => String::new(),
        PortSpec::Num(n) => format!("dport {n}"),
        PortSpec::Range(lo, hi) => format!("dport {lo}-{hi}"),
    };
    // Renders "<proto> <port_match>" when both are present, just one when not.
    let proto_port = if port_match.is_empty() {
        format!("meta l4proto {proto}")
    } else {
        format!("{proto} {port_match}")
    };

    match e.host {
        HostSpec::Any => {
            rules.push_str(&format!("        {proto_port} accept\n"));
        }
        HostSpec::Ipv4(v4) => {
            rules.push_str(&format!("        ip daddr {v4} {proto_port} accept\n"));
        }
        HostSpec::Ipv6(v6) => {
            rules.push_str(&format!("        ip6 daddr {v6} {proto_port} accept\n"));
        }
        HostSpec::Ipv4Cidr(v4, mask) => {
            rules.push_str(&format!(
                "        ip daddr {v4}/{mask} {proto_port} accept\n"
            ));
        }
        HostSpec::Ipv6Cidr(v6, mask) => {
            rules.push_str(&format!(
                "        ip6 daddr {v6}/{mask} {proto_port} accept\n"
            ));
        }
        HostSpec::Name(n) => {
            // nftables does not resolve hostnames at rule-load time.
            // Best-effort: resolve to every A/AAAA record and emit rules for
            // all of them. If resolution fails, emit a comment noting the
            // skip — the caller still sees deny-by-default for that host.
            match std::net::ToSocketAddrs::to_socket_addrs(&format!("{n}:0")) {
                Ok(addrs) => {
                    for a in addrs {
                        match a {
                            std::net::SocketAddr::V4(v) => rules.push_str(&format!(
                                "        ip daddr {} {proto_port} accept  # {n}\n",
                                v.ip()
                            )),
                            std::net::SocketAddr::V6(v) => rules.push_str(&format!(
                                "        ip6 daddr {} {proto_port} accept  # {n}\n",
                                v.ip()
                            )),
                        }
                    }
                }
                Err(_) => {
                    rules.push_str(&format!("        # could not resolve {n} — rule skipped\n"));
                }
            }
        }
    }
    Ok(())
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    // Search PATH first, then fall back to canonical sbin locations —
    // `nft` typically lives in /sbin (Debian/Arch) or /usr/sbin (older
    // layouts), neither of which is in a regular user's $PATH.
    if let Some(path_env) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_env) {
            let p = dir.join(bin);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    for fallback in ["/sbin", "/usr/sbin", "/usr/local/sbin"] {
        let p = std::path::Path::new(fallback).join(bin);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}
