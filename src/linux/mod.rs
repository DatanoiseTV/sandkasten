//! Linux backend: user/mount/pid/ipc/uts + optional net namespace, Landlock
//! filesystem LSM, and a seccomp-BPF deny-list for obviously dangerous syscalls.
//!
//! Design notes and limits (documented in README too):
//!
//! * Filesystem: Landlock is allow-list only. The `deny` list in a profile is
//!   enforced by **omission** — a path in `deny` is pruned from any enclosing
//!   `read` / `read_write` subtree before the Landlock ruleset is built.
//!   (macOS supports true deny-overrides via SBPL last-match-wins.)
//!
//! * Network: an unprivileged user namespace lets us create a private netns with
//!   only `lo`. We support three effective modes:
//!     - no network (default)
//!     - localhost-only (`allow_localhost = true`)
//!     - host network (if neither of the above nor any explicit rule is set
//!       AND `allow_inbound` or any outbound rule is present — we inherit
//!       the parent netns rather than isolate. v1 does not implement
//!       per-IP outbound filtering on Linux; it's kernel-enforced on macOS.)
//!
//! * Seccomp: deny-list of kernel-admin and introspection syscalls
//!   (ptrace, bpf, kexec, module ops, mount, pivot_root, etc.). Process
//!   isolation remains primarily a namespace property.

mod isolate;
pub(crate) mod landlock_fs;
pub mod learn;
pub(crate) mod nftables;
pub(crate) mod seccomp_filter;

use crate::config::Profile;
use anyhow::{anyhow, Context, Result};
use std::ffi::CString;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

pub(crate) fn build_envp(env: &crate::config::Env) -> Result<Vec<CString>> {
    let mut out: Vec<CString> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    fn push_kv(
        out: &mut Vec<CString>,
        seen: &mut std::collections::BTreeSet<String>,
        k: &str,
        v: &str,
    ) -> Result<()> {
        if seen.insert(k.to_string()) {
            out.push(CString::new(format!("{k}={v}")).context("env NUL")?);
        }
        Ok(())
    }
    for (k, v) in &env.set {
        push_kv(&mut out, &mut seen, k, v)?;
    }
    if env.pass_all {
        for (k, v) in std::env::vars() {
            push_kv(&mut out, &mut seen, &k, &v)?;
        }
    } else {
        for key in &env.pass {
            if let Ok(v) = std::env::var(key) {
                push_kv(&mut out, &mut seen, key, &v)?;
            }
        }
    }
    Ok(out)
}

extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill with a valid pid + signal.
        unsafe { libc::kill(pid, sig) };
    }
}

/// Wall-clock watchdog state for the SIGALRM-based timeout. We can't pass
/// state to a signal handler directly, so hold it in an atomic + static.
static WATCHDOG_PID: AtomicI32 = AtomicI32::new(0);
static WATCHDOG_STAGE: AtomicI32 = AtomicI32::new(0); // 0 → TERM next, 1 → KILL next

extern "C" fn alarm_handler(_sig: libc::c_int) {
    let pid = WATCHDOG_PID.load(Ordering::SeqCst);
    if pid <= 0 {
        return;
    }
    let stage = WATCHDOG_STAGE.fetch_add(1, Ordering::SeqCst);
    // SAFETY: kill + alarm are both async-signal-safe.
    unsafe {
        if stage == 0 {
            libc::kill(pid, libc::SIGTERM);
            libc::alarm(3);
        } else {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

/// Install a SIGALRM-based wall-clock watchdog for the given child pid.
/// Fires SIGTERM after `secs`, then SIGKILL 3 s later if the child is still
/// alive. Used instead of a std::thread because pthread_create sometimes
/// fails with EINVAL after CLONE_NEWUSER (seen in LXC).
pub(crate) fn install_alarm_watchdog(child: nix::unistd::Pid, secs: u64) {
    WATCHDOG_PID.store(child.as_raw(), Ordering::SeqCst);
    WATCHDOG_STAGE.store(0, Ordering::SeqCst);
    // SAFETY: sigaction with a fresh zeroed struct + fn pointer is standard.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = alarm_handler as *const () as usize;
        libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut());
        let clipped = secs.min(i32::MAX as u64 / 2) as libc::c_uint;
        libc::alarm(clipped);
    }
}

pub(crate) fn install_signal_forwarders(child: nix::unistd::Pid) {
    CHILD_PID.store(child.as_raw(), Ordering::SeqCst);
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        // SAFETY: sigaction is a C-repr POD; all-zero is the documented
        // "default handler" representation.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = forward_signal as *const () as usize;
        // SAFETY: &action is a valid sigaction pointer; forward_signal has
        // the signature expected by sa_sigaction (extern "C" fn).
        unsafe {
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

pub fn run(profile: &Profile, cwd: Option<&Path>, argv: &[String]) -> Result<i32> {
    if argv.is_empty() {
        return Err(anyhow!("no command to run"));
    }
    isolate::run(profile, cwd, argv)
}

/// Human-readable policy summary used by the `render` command.
pub fn render(p: &Profile) -> String {
    let mut s = String::new();
    s.push_str("# sandkasten Linux policy\n");
    if let Some(n) = &p.name {
        s.push_str(&format!("# profile: {n}\n"));
    }
    s.push_str("\n[namespaces]\n");
    s.push_str("  user, mount, pid, ipc, uts");
    let net_mode = net_mode(p);
    s.push_str(&format!(
        "{}\n",
        if net_mode.unshare_net { ", net" } else { "" }
    ));

    s.push_str("\n[filesystem — Landlock ruleset]\n");
    for p in &p.filesystem.read {
        s.push_str(&format!("  read       {p}\n"));
    }
    for p in &p.filesystem.read_write {
        s.push_str(&format!("  read+write {p}\n"));
    }
    if !p.filesystem.deny.is_empty() {
        s.push_str("  (deny: Linux enforces by subtree omission — see README)\n");
        for d in &p.filesystem.deny {
            s.push_str(&format!("  deny       {d}\n"));
        }
    }

    s.push_str("\n[network]\n");
    s.push_str(&format!("  mode: {}\n", net_mode.label));
    if !p.network.outbound_tcp.is_empty() || !p.network.outbound_udp.is_empty() {
        if net_mode.unshare_net {
            s.push_str("  per-IP filtering: nftables allow-list inside the private netns.\n");
        } else {
            s.push_str(
                "  per-IP filtering: NOT enforced (host netns mode — kernel-level\n\
                 \x20                    nftables rules would affect the host globally).\n\
                 \x20                    Use [network.netns_path] to plumb your own\n\
                 \x20                    isolated netns if filtering matters.\n",
            );
        }
        for ep in &p.network.outbound_tcp {
            s.push_str(&format!("    tcp → {ep}\n"));
        }
        for ep in &p.network.outbound_udp {
            s.push_str(&format!("    udp → {ep}\n"));
        }
    }

    s.push_str("\n[seccomp]\n");
    s.push_str("  deny-list for: ptrace, bpf, kexec_load, module ops,\n");
    s.push_str("                 mount/umount2, pivot_root, chroot, setns,\n");
    s.push_str("                 unshare, reboot, iopl/ioperm, swapon/off,\n");
    s.push_str("                 keyctl, perf_event_open, syslog, delete_module\n");

    s
}

pub(super) struct NetMode {
    pub unshare_net: bool,
    pub bring_up_lo: bool,
    pub label: &'static str,
}

pub(super) fn net_mode(p: &Profile) -> NetMode {
    // Explicit user choice wins.
    if p.network.external.as_deref() == Some("host") {
        return NetMode {
            unshare_net: false,
            bring_up_lo: false,
            label: "host (shares host netns; Landlock + seccomp still apply)",
        };
    }
    if p.network.netns_path.is_some() {
        return NetMode {
            unshare_net: false, // we setns() into an existing one instead
            bring_up_lo: false,
            label: "setns into provided netns_path",
        };
    }

    let has_outbound = !p.network.outbound_tcp.is_empty() || !p.network.outbound_udp.is_empty();
    let has_inbound = p.network.allow_inbound
        || !p.network.inbound_tcp.is_empty()
        || !p.network.inbound_udp.is_empty();
    let wants_external = p.network.allow_dns || has_outbound;
    let all_off = !p.network.allow_localhost
        && !wants_external
        && !has_inbound
        && !p.network.allow_icmp
        && !p.network.allow_icmpv6;

    if all_off {
        return NetMode {
            unshare_net: true,
            bring_up_lo: false,
            label: "none (private netns, no interfaces)",
        };
    }
    // Outbound-only or outbound+localhost with no inbound. Without a
    // pasta/slirp4netns bridge a private Linux netns has no interface
    // to reach the internet, so everything dies at getaddrinfo. Match
    // macOS's out-of-the-box behaviour by sharing the host netns; the
    // sandboxed process can still be constrained by Landlock, seccomp,
    // and the namespace barriers on /mnt, /proc, etc. Users who want
    // per-IP filtering should point `[network.netns_path]` at a
    // pre-plumbed namespace or set `external = "isolated"` (reserved
    // for future pasta integration).
    if !has_inbound && wants_external {
        return NetMode {
            unshare_net: false,
            bring_up_lo: false,
            label: "host netns (outbound+localhost; set [network.netns_path] for per-IP isolation)",
        };
    }
    if !has_inbound {
        return NetMode {
            unshare_net: true,
            bring_up_lo: p.network.allow_localhost,
            label: "private netns (localhost only)",
        };
    }
    NetMode {
        unshare_net: false,
        bring_up_lo: false,
        label: "host (inherits parent netns — inbound requires this)",
    }
}
