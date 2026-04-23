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
            let msg = format!("sandkasten: child setup failed: {rc:#}\n");
            let _ = nix::unistd::write(std::io::stderr(), msg.as_bytes());
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => parent_wait(child),
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

    if let Some(c) = cwd {
        if unsafe { libc::chdir(c.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("chdir");
        }
    }

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

fn parent_wait(child: Pid) -> Result<i32> {
    crate::linux::install_signal_forwarders(child);
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
