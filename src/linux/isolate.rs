//! Namespace setup, fork into PID namespace, and exec.

use crate::config::Profile;
use anyhow::{anyhow, Context, Result};
use nix::sched::{unshare, CloneFlags};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execve, fork, ForkResult, Pid};
use std::ffi::CString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub fn run(profile: &Profile, cwd: Option<&Path>, argv: &[String]) -> Result<i32> {
    let net = super::net_mode(profile);

    // Stage 1: enter user namespace. Other namespaces unshared together so
    // uid_map writes happen exactly once.
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();

    let mut flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS;
    if net.unshare_net {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    unshare(flags).context("unshare (is unprivileged_userns_clone enabled?)")?;

    // Map our uid/gid to 0 inside the new user namespace.
    write_map("/proc/self/setgroups", b"deny\n").context("setgroups deny")?;
    write_map("/proc/self/uid_map", format!("0 {uid} 1\n").as_bytes()).context("uid_map")?;
    write_map("/proc/self/gid_map", format!("0 {gid} 1\n").as_bytes()).context("gid_map")?;

    // Set a neutral hostname inside the UTS namespace.
    let _ = nix::unistd::sethostname("sandkasten");

    // Build argv/env before fork.
    let prog = CString::new(argv[0].as_bytes()).context("argv[0] NUL")?;
    let c_args: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_bytes()).context("argv NUL"))
        .collect::<Result<_>>()?;
    let envp_vec = crate::linux::build_envp(&profile.env)?;

    // Resolve program via PATH using scrubbed envp (before fork so we surface
    // errors to the parent).
    let resolved = resolve_program(&prog, &envp_vec)?;

    // Prepare Landlock ruleset inputs (PathFds must be opened before seccomp
    // and before we chdir into possibly restricted locations).
    let lock = crate::linux::landlock_fs::Prepared::from(profile)?;

    let cwd_c = match cwd {
        Some(p) => Some(CString::new(p.as_os_str().as_bytes()).context("cwd NUL")?),
        None => None,
    };

    // Fork — child becomes PID 1 in the new PID namespace.
    match unsafe { fork() }.context("fork")? {
        ForkResult::Child => {
            let rc = child_main(
                profile,
                &net,
                cwd_c.as_deref(),
                &resolved,
                &c_args,
                &envp_vec,
                lock,
            );
            // Unreached on success (execve); on error print + _exit.
            let msg = match rc {
                Ok(()) => "sandkasten: execve returned Ok unexpectedly\n".to_string(),
                Err(e) => format!("sandkasten: child setup failed: {e:#}\n"),
            };
            let _ = nix::unistd::write(std::io::stderr(), msg.as_bytes());
            // SAFETY: _exit terminates the child without running destructors.
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => parent_wait(child, &profile.limits),
    }
}

fn child_main(
    profile: &Profile,
    net: &super::NetMode,
    cwd: Option<&std::ffi::CStr>,
    prog: &CString,
    argv: &[CString],
    envp: &[CString],
    lock: crate::linux::landlock_fs::Prepared,
) -> Result<()> {
    if net.bring_up_lo {
        bring_up_loopback().context("bringing up lo")?;
    }

    // Apply nftables allowlist inside the netns (if we actually created
    // one and the profile has per-host rules). Does nothing silently when
    // nft isn't installed.
    if net.unshare_net {
        crate::linux::nftables::apply_if_relevant(&profile.network)
            .context("applying nftables rules")?;
    }

    // DNS / hosts bind-mount overlays. Silent no-op if neither is configured.
    // Runs inside our mount namespace so it doesn't affect the host.
    bind_overlay_netfiles(profile).context("bind-mounting dns/hosts overlays")?;

    // True copy-on-write overlayfs, if the profile asks for it.
    apply_overlayfs(profile).context("setting up overlayfs")?;

    if let Some(c) = cwd {
        if unsafe { libc::chdir(c.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("chdir");
        }
    }

    // Apply POSIX resource limits.
    if let Err(lbl) = crate::limits::apply(&profile.limits) {
        return Err(anyhow!("setrlimit failed: {lbl}"));
    }

    // Drop ambient privileges — any future setuid binary still inside our
    // user namespace can't gain real privileges. Defense-in-depth for the
    // seccomp filter below (otherwise sudoable binaries could try to
    // widen; here they simply can't).
    no_new_privs().context("prctl PR_SET_NO_NEW_PRIVS")?;

    // Apply Landlock filesystem restrictions.
    lock.apply().context("landlock restrict_self")?;

    // Apply seccomp filter. Must be after any syscalls the filter would reject.
    crate::linux::seccomp_filter::install(profile).context("seccomp install")?;

    // Note: we can't use crate::log from inside the child (post-fork /
    // pre-exec restrictions); lifecycle info is logged from the parent.

    // execve with scrubbed envp.
    let argv_ref: Vec<&std::ffi::CStr> = argv.iter().map(|c| c.as_c_str()).collect();
    let envp_ref: Vec<&std::ffi::CStr> = envp.iter().map(|c| c.as_c_str()).collect();
    execve(prog, &argv_ref, &envp_ref).context("execve")?;
    unreachable!()
}

fn parent_wait(child: Pid, limits: &crate::config::Limits) -> Result<i32> {
    crate::linux::install_signal_forwarders(child);
    // Wall-clock watchdog via SIGALRM rather than a thread — pthread_create
    // fails with EINVAL on some kernels after CLONE_NEWUSER (seen inside
    // LXC, and occasionally on bare-metal 6.x after user namespace entry).
    if let Some(secs) = limits.wall_timeout_seconds {
        crate::linux::install_alarm_watchdog(child, secs);
    }
    loop {
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
            Ok(_) => continue,
            Err(nix::Error::EINTR) => continue,
            Err(e) => return Err(anyhow!(e).context("waitpid")),
        }
    }
}

fn write_map(path: &str, data: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("open {path}"))?;
    f.write_all(data).with_context(|| format!("write {path}"))?;
    Ok(())
}

/// Set the no_new_privs bit on the current process. Any future exec of a
/// setuid binary will NOT grant additional privileges, and this bit is
/// preserved across exec. Required for unprivileged seccomp filtering and
/// valuable as a defense-in-depth switch even when it isn't strictly needed.
fn no_new_privs() -> Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes fixed integer args.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("prctl");
    }
    Ok(())
}

/// Bind-mount synth DNS and hosts files over `/etc/resolv.conf` and
/// `/etc/hosts`, respectively. Reads content from our mock tempdir (which
/// the main-thread materialiser wrote just before fork) via the
/// `SANDKASTEN_MOCKS` env var. Inside the mount namespace, so the host's
/// files are untouched.
fn bind_overlay_netfiles(profile: &crate::config::Profile) -> Result<()> {
    let needs_resolv = crate::net_files::resolv_conf(&profile.network).is_some();
    let needs_hosts = crate::net_files::hosts_extra(&profile.network).is_some();
    if !needs_resolv && !needs_hosts {
        return Ok(());
    }

    let mock_dir = std::env::var_os("SANDKASTEN_MOCKS")
        .ok_or_else(|| anyhow!("SANDKASTEN_MOCKS unset — mocks::materialise didn't run"))?;
    let mock_dir = std::path::PathBuf::from(mock_dir);

    if needs_resolv {
        let src = mock_dir.join("resolv.conf");
        bind_over(&src, std::path::Path::new("/etc/resolv.conf"))
            .context("bind-mount /etc/resolv.conf")?;
    }
    if needs_hosts {
        let src = mock_dir.join("hosts");
        bind_over(&src, std::path::Path::new("/etc/hosts"))
            .context("bind-mount /etc/hosts")?;
    }
    Ok(())
}

fn bind_over(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    use nix::mount::{mount, MsFlags};
    // Read-only bind: mount(src, dst, MS_BIND), then remount with MS_REMOUNT|MS_RDONLY.
    mount(
        Some(src),
        dst,
        Option::<&str>::None,
        MsFlags::MS_BIND,
        Option::<&str>::None,
    )
    .with_context(|| format!("bind-mount {} -> {}", src.display(), dst.display()))?;
    mount(
        Option::<&std::path::Path>::None,
        dst,
        Option::<&str>::None,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        Option::<&str>::None,
    )
    .with_context(|| format!("remount-ro {}", dst.display()))?;
    Ok(())
}

/// Set up an overlayfs on top of `overlay.lower` so writes land in
/// `overlay.upper` instead of the real filesystem. The merged view appears
/// at `overlay.mount` (defaults to `overlay.lower`, i.e. an in-place
/// replacement).
///
/// Requires Linux 5.11+ for unprivileged-userns overlayfs mounts.
fn apply_overlayfs(profile: &crate::config::Profile) -> Result<()> {
    let (Some(lower), Some(upper)) = (
        profile.overlay.lower.as_ref(),
        profile.overlay.upper.as_ref(),
    ) else {
        return Ok(());
    };
    let mount_at = profile
        .overlay
        .mount
        .as_deref()
        .unwrap_or(lower)
        .to_string();

    // Both upper and work must live on the same filesystem; we stash work/
    // as a sibling of upper.
    std::fs::create_dir_all(upper).with_context(|| format!("mkdir {upper}"))?;
    let work = std::path::Path::new(upper)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/tmp"))
        .join(format!(
            ".sandkasten-ovl-work-{}",
            std::process::id()
        ));
    std::fs::create_dir_all(&work)
        .with_context(|| format!("mkdir {}", work.display()))?;

    let opts = format!(
        "lowerdir={lower},upperdir={upper},workdir={}",
        work.display()
    );

    use nix::mount::{mount, MsFlags};
    mount(
        Some("overlay"),
        std::path::Path::new(&mount_at),
        Some("overlay"),
        MsFlags::empty(),
        Some(opts.as_str()),
    )
    .with_context(|| format!("overlayfs mount at {mount_at} ({opts})"))?;
    Ok(())
}

fn bring_up_loopback() -> Result<()> {
    // ioctl(SIOCSIFFLAGS) on AF_INET dgram socket. Small enough to inline.
    use std::os::fd::AsRawFd;
    let sock = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Inet,
        nix::sys::socket::SockType::Datagram,
        nix::sys::socket::SockFlag::empty(),
        None,
    )
    .context("socket for SIOCSIFFLAGS")?;

    #[repr(C)]
    struct Ifreq {
        ifr_name: [u8; 16],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }
    let mut req: Ifreq = unsafe { std::mem::zeroed() };
    let name = b"lo\0";
    req.ifr_name[..name.len()].copy_from_slice(name);
    req.ifr_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;

    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &req) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("ioctl SIOCSIFFLAGS lo");
    }
    Ok(())
}

fn resolve_program(prog: &CString, envp: &[CString]) -> Result<CString> {
    let bytes = prog.to_bytes();
    if bytes.contains(&b'/') {
        return Ok(prog.clone());
    }
    let path = envp
        .iter()
        .find_map(|c| {
            let b = c.to_bytes();
            b.strip_prefix(b"PATH=").map(|p| p.to_vec())
        })
        .unwrap_or_else(|| b"/usr/bin:/bin".to_vec());

    for dir in path.split(|&b| b == b':') {
        if dir.is_empty() {
            continue;
        }
        let mut candidate: Vec<u8> = Vec::with_capacity(dir.len() + 1 + bytes.len());
        candidate.extend_from_slice(dir);
        if dir.last() != Some(&b'/') {
            candidate.push(b'/');
        }
        candidate.extend_from_slice(bytes);
        let p = Path::new(std::ffi::OsStr::from_bytes(&candidate));
        if p.is_file() {
            return CString::new(candidate).context("resolved path NUL");
        }
    }
    Err(anyhow!("{} not found in PATH", String::from_utf8_lossy(bytes)))
}
