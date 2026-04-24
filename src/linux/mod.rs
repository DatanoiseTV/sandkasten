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
//! * Network: an unprivileged user namespace lets us create a private netns.
//!   The effective mode is picked in [`net_mode`] based on profile intent +
//!   what's installed on the host:
//!     - `NetKind::PrivateNetns` — no network, or localhost-only if
//!       `allow_localhost = true`.
//!     - `NetKind::PastaWrap` — outbound-only profile, pasta (from passt)
//!       is installed and not AppArmor-confined. Re-exec under
//!       `pasta --config-net -- sandkasten …`. Per-IP `nftables`
//!       filtering is enforced inside pasta's netns where kernel-wide
//!       rules don't affect the host.
//!     - `NetKind::Slirp4netnsWrap` — outbound-only profile, pasta unusable
//!       (Debian/Ubuntu's AppArmor profile blocks our re-exec pattern)
//!       but `slirp4netns` is installed. Fork-before-unshare flow: parent
//!       writes the child's uid/gid maps from outside the userns, spawns
//!       `slirp4netns -c <pid> tap0 --disable-host-loopback`, child
//!       continues the normal post-ns setup. `nftables` applies inside
//!       the plumbed netns, same guarantee as pasta.
//!     - `NetKind::ExternalNetns` — `setns()` into an existing netns (e.g.
//!       one set up by the user with `ip netns add vpn; ip netns exec vpn
//!       wg-quick up wg0`; pointed at via `[network.netns_path]`).
//!     - `NetKind::HostShared` — fallback when neither pasta nor
//!       slirp4netns is available, or `external = "host"`, or an inbound
//!       listener is configured. In this mode nftables rules are NOT
//!       applied (they'd affect the host globally); `render` flags the
//!       degradation explicitly.
//!
//! * Seccomp: deny-list of kernel-admin and introspection syscalls
//!   (ptrace, bpf, kexec, module ops, mount, pivot_root, etc.), plus the
//!   conditional TIOCSTI-via-ioctl block. Optional `process.block_setid_syscalls`
//!   denies the full setuid/setgid family. Process isolation remains
//!   primarily a namespace property.

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
    pub kind: NetKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // other variants are carried for render/debug output
pub(super) enum NetKind {
    /// Fully private netns (no external connectivity, optional `lo`).
    /// Covers both the "no network at all" case and the
    /// "localhost only" case — behaviour-wise they're identical at
    /// the ruleset level, only `bring_up_lo` changes.
    PrivateNetns,
    /// Private netns + pasta (from passt) provides external connectivity.
    /// nftables applies safely inside pasta's netns.
    PastaWrap,
    /// Private netns + slirp4netns attached from outside. Used when
    /// pasta is restricted by AppArmor (Debian/Ubuntu) but
    /// slirp4netns is installed. Requires the fork-before-unshare
    /// dance — see `isolate::run_slirp4netns`.
    Slirp4netnsWrap,
    /// Host netns (fallback when neither pasta nor slirp4netns is
    /// available, or `external = "host"`, or an inbound listener is
    /// configured).
    HostShared,
    /// `setns()` into an existing netns (user-plumbed via
    /// `[network.netns_path]`).
    ExternalNetns,
}

/// Env var we set on the outer process before `exec pasta -- sandkasten …`
/// so the inner sandkasten invocation knows it's already in a pasta
/// netns and shouldn't try to `CLONE_NEWNET` again.
const PASTA_ENV_MARKER: &str = "SANDKASTEN_PASTA_WRAPPED";

/// Env var set by the slirp4netns-flow parent before the child
/// continues its in-process sandbox setup, signalling "the namespace
/// has already been unshared and the uid/gid maps have already been
/// written from outside".
pub(super) const SLIRP_ENV_MARKER: &str = "SANDKASTEN_SLIRP_PLUMBED";

pub(super) fn already_in_pasta() -> bool {
    std::env::var_os(PASTA_ENV_MARKER).is_some()
}

pub(super) fn already_slirp_plumbed() -> bool {
    std::env::var_os(SLIRP_ENV_MARKER).is_some()
}

pub(super) fn find_slirp4netns() -> Option<std::path::PathBuf> {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let p = std::path::Path::new(dir).join("slirp4netns");
        if p.is_file() {
            return Some(p);
        }
    }
    for p in [
        "/usr/bin/slirp4netns",
        "/usr/local/bin/slirp4netns",
        "/usr/sbin/slirp4netns",
    ] {
        if std::path::Path::new(p).is_file() {
            return Some(std::path::PathBuf::from(p));
        }
    }
    None
}

fn find_pasta() -> Option<std::path::PathBuf> {
    // Debian/Ubuntu ship passt with an AppArmor profile that restricts
    // pasta's exec targets to `passt.avx2` only — blocking our
    // re-exec-sandkasten approach. Detect and skip if the profile is
    // enforced, since attempting pasta would fail with a confusing
    // "Failed to start command or shell: Permission denied" error and
    // leave the user stuck.
    if apparmor_restricts_passt() {
        crate::log::info(format_args!(
            "pasta found but AppArmor `passt` profile is enforced — skipping \
             pasta (would fail to exec our re-exec). Falling back to host netns."
        ));
        return None;
    }
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let p = std::path::Path::new(dir).join("pasta");
        if p.is_file() {
            return Some(p);
        }
    }
    for p in ["/usr/bin/pasta", "/usr/local/bin/pasta", "/usr/sbin/pasta"] {
        if std::path::Path::new(p).is_file() {
            return Some(std::path::PathBuf::from(p));
        }
    }
    None
}

fn apparmor_restricts_passt() -> bool {
    // The kernel-facing `/sys/kernel/security/apparmor/profiles` is
    // root-only on modern Debian/Ubuntu, so we can't peek at it as
    // the invoking user. Use the on-disk profile file as a proxy: on
    // Debian the passt package ships `/etc/apparmor.d/usr.bin.passt`
    // and the profile is automatically enforced at boot. Absence of
    // the file means no restriction; presence means the restriction
    // very likely applies. False positives cost us an unnecessary
    // host-netns fallback; false negatives cost us a cryptic
    // "Permission denied" at runtime — so err on the side of the
    // false positive.
    std::path::Path::new("/etc/apparmor.d/usr.bin.passt").exists()
        || std::path::Path::new("/etc/apparmor.d/passt").exists()
}

/// Re-exec sandkasten under pasta so the sandboxed process runs inside
/// pasta's userspace-plumbed netns. Never returns on success.
pub(super) fn exec_under_pasta(_net: &NetMode, argv: &[String], cwd: Option<&Path>) -> Result<i32> {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;

    let pasta =
        find_pasta().ok_or_else(|| anyhow!("pasta binary disappeared between check and exec"))?;
    let self_exe = std::fs::read_link("/proc/self/exe").context("reading /proc/self/exe")?;

    // Rebuild the invocation: `pasta --config-net -- <self_exe> <orig argv 0..>`
    // where argv 0.. is the original CLI the user passed us. Reconstruct
    // from std::env::args() which still holds the parent's argv.
    // pasta's default `--runas` is "nobody" (unprivileged), which means
    // the command it exec's can't open our binary (owned by the invoking
    // user, mode 0755, but ownership still matters for some paths). Pass
    // the current user's uid:gid explicitly so the inner sandkasten
    // inherits the same credentials as the outer.
    let uid_gid = format!("{}:{}", nix::unistd::geteuid(), nix::unistd::getegid());
    let mut outer_argv: Vec<CString> = vec![
        CString::new(pasta.as_os_str().as_bytes()).context("pasta path NUL")?,
        // --config-net: plumb networking and exec the command in it.
        // --quiet keeps pasta's banner off stderr so the sandboxed
        // process's output stays the headline.
        CString::new("--config-net").unwrap(),
        CString::new("--quiet").unwrap(),
        CString::new("--runas").unwrap(),
        CString::new(uid_gid).unwrap(),
        CString::new("--").unwrap(),
        CString::new(self_exe.as_os_str().as_bytes()).context("self exe NUL")?,
    ];
    for arg in std::env::args().skip(1) {
        outer_argv.push(CString::new(arg.as_bytes()).context("argv NUL")?);
    }
    let _ = argv; // argv is reconstructed from std::env::args above
    let _ = cwd; // pasta inherits CWD; our inner invocation will --cwd again
    let c_outer: Vec<&CStr> = outer_argv.iter().map(|c| c.as_c_str()).collect();

    // Propagate the parent environment and add our marker.
    let mut env_pairs: Vec<CString> = std::env::vars()
        .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
        .collect();
    env_pairs.push(CString::new(format!("{PASTA_ENV_MARKER}=1")).unwrap());
    let c_env: Vec<&CStr> = env_pairs.iter().map(|c| c.as_c_str()).collect();
    crate::log::info(format_args!(
        "wrapping in pasta: {}",
        outer_argv
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    nix::unistd::execve(&outer_argv[0], &c_outer, &c_env)
        .with_context(|| format!("execve {}", pasta.display()))?;
    unreachable!()
}

pub(super) fn net_mode(p: &Profile) -> NetMode {
    // Explicit user choice wins.
    if p.network.external.as_deref() == Some("host") {
        return NetMode {
            unshare_net: false,
            bring_up_lo: false,
            label: "host (shares host netns; Landlock + seccomp still apply)",
            kind: NetKind::HostShared,
        };
    }
    if p.network.netns_path.is_some() {
        return NetMode {
            unshare_net: false, // we setns() into an existing one instead
            bring_up_lo: false,
            label: "setns into provided netns_path",
            kind: NetKind::ExternalNetns,
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
            kind: NetKind::PrivateNetns,
        };
    }
    // Outbound-only or outbound+localhost with no inbound. Prefer pasta
    // (from passt) if installed — it creates a userspace-plumbed netns so
    // our private netns actually reaches the internet, AND nftables
    // rules applied inside that netns don't affect the host. If pasta
    // isn't installed, fall back to sharing the host netns: per-IP
    // filtering isn't enforced (kernel rules would hit host globally)
    // but at least the internet works OOB. Users can override both
    // paths with `[network.netns_path]`.
    if !has_inbound && wants_external {
        if find_pasta().is_some() {
            return NetMode {
                unshare_net: true,
                bring_up_lo: p.network.allow_localhost,
                label: "private netns + pasta (external connectivity plumbed; nftables applies)",
                kind: NetKind::PastaWrap,
            };
        }
        // Pasta blocked or missing. slirp4netns is the second-best
        // choice — uses the same userspace TAP model, attaches via
        // PID instead of execing, and isn't confined by Debian's
        // AppArmor profile.
        if find_slirp4netns().is_some() {
            return NetMode {
                unshare_net: true,
                bring_up_lo: p.network.allow_localhost,
                label:
                    "private netns + slirp4netns (external connectivity plumbed; nftables applies)",
                kind: NetKind::Slirp4netnsWrap,
            };
        }
        let label = if apparmor_restricts_passt() {
            "host netns fallback (AppArmor `passt` profile blocks pasta; install \
             `slirp4netns` for per-IP isolation or use [network.netns_path])"
        } else {
            "host netns fallback (install `passt` or `slirp4netns` for per-IP isolation)"
        };
        return NetMode {
            unshare_net: false,
            bring_up_lo: false,
            label,
            kind: NetKind::HostShared,
        };
    }
    if !has_inbound {
        return NetMode {
            unshare_net: true,
            bring_up_lo: p.network.allow_localhost,
            label: "private netns (localhost only)",
            kind: NetKind::PrivateNetns,
        };
    }
    NetMode {
        unshare_net: false,
        bring_up_lo: false,
        label: "host (inherits parent netns — inbound requires this)",
        kind: NetKind::HostShared,
    }
}
