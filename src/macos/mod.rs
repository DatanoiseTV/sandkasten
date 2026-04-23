//! macOS backend: kernel-enforced Seatbelt sandbox via the `sandbox_init` SPI.
//!
//! Flow:
//!   parent:
//!     - build SBPL source from Profile
//!     - fork
//!   child:
//!     - `sandbox_init(sbpl)`  — process is now locked down
//!     - scrub env per profile
//!     - `chdir` if requested (must be allowed by FS policy)
//!     - `execvp` the target
//!   parent:
//!     - install SIGINT/SIGTERM forwarders
//!     - `waitpid`, return the child's exit status
//!
//! # Safety
//!
//! This module wraps POSIX + libSystem FFI. All `unsafe` calls follow the
//! standard fork/exec contract:
//!
//! * The parent calls `libc::fork()`. The child runs only async-signal-safe
//!   libc calls (`chdir`, `sandbox_init`, `execve`, `_exit`, `write`) before
//!   exec; no Rust destructors run in the child between fork and exec.
//! * `CString` pointers handed to libc are valid NUL-terminated strings that
//!   live on the caller's stack for the duration of the call.
//! * `envp` slices end with a sentinel null, satisfying `execve`'s contract.
//! * `waitpid`, `kill`, and `sigaction` take process IDs and integer signals;
//!   the `sigaction` struct is constructed via `mem::zeroed` which is valid
//!   for plain FFI POD types.
//! * `__error()` returns libc's per-thread errno pointer — always valid.

#![allow(clippy::undocumented_unsafe_blocks)] // see module-level safety doc

pub mod denials;
pub mod ffi;
pub mod learn;
pub mod sbpl;

use crate::config::Profile;
use anyhow::{anyhow, Context, Result};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// Most-recent child PID (for post-run denial capture). Zero before first run.
pub fn last_child_pid() -> Option<i32> {
    let p = CHILD_PID.load(Ordering::SeqCst);
    if p > 0 {
        Some(p)
    } else {
        None
    }
}

pub fn run(profile: &Profile, cwd: Option<&Path>, argv: &[String]) -> Result<i32> {
    let policy = sbpl::generate(profile);
    if crate::log::at!(crate::log::Level::Trace) {
        eprintln!("─── generated SBPL ───");
        for line in policy.lines() {
            eprintln!("  {line}");
        }
        eprintln!("─── end SBPL ─────────");
    }
    crate::log::info(format_args!("applying sandbox ({} bytes SBPL)", policy.len()));
    let envp = build_envp(&profile.env)?;
    run_with_sbpl(&policy, argv, cwd, envp, &profile.limits)
}

/// Lower-level entry: fork, apply the given SBPL in the child, exec argv with
/// the supplied envp. Used by both `run` and `learn`.
pub fn run_with_sbpl(
    policy: &str,
    argv: &[String],
    cwd: Option<&Path>,
    envp: Vec<CString>,
    limits: &crate::config::Limits,
) -> Result<i32> {
    if argv.is_empty() {
        return Err(anyhow!("no command to run"));
    }

    let prog = CString::new(argv[0].as_bytes()).context("argv[0] contains NUL")?;
    let c_args: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_bytes()).context("argv contains NUL"))
        .collect::<Result<_>>()?;
    let argv_ptrs: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp_ptrs: Vec<*const libc::c_char> = envp
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let cwd_c = match cwd {
        Some(p) => Some(CString::new(p.as_os_str().as_bytes()).context("cwd contains NUL")?),
        None => None,
    };

    // SAFETY: fork() is an unsafe POSIX call; the child path below restricts
    // itself to async-signal-safe operations until execve.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error()).context("fork");
    }
    if pid == 0 {
        child_exec(policy, cwd_c.as_deref(), &prog, &argv_ptrs, &envp_ptrs, limits);
    }

    CHILD_PID.store(pid, Ordering::SeqCst);
    install_signal_forwarders();
    crate::log::info(format_args!("forked pid {pid}"));

    // Wall-clock watchdog: if the profile sets `wall_timeout_seconds`, spawn
    // a thread that SIGTERMs after that window and escalates to SIGKILL 3 s
    // later if the child is still running.
    if let Some(secs) = limits.wall_timeout_seconds {
        let child = pid;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            // Best-effort TERM then KILL. We race with natural exit; EINVAL
            // / ESRCH from a reaped pid is fine.
            eprintln!("sandkasten │ timeout reached ({secs}s) — sending SIGTERM to pid {child}");
            // SAFETY: kill() with a valid signal and the recorded pid.
            unsafe { libc::kill(child, libc::SIGTERM) };
            std::thread::sleep(std::time::Duration::from_secs(3));
            eprintln!("sandkasten │ child didn't exit within 3 s of SIGTERM — SIGKILL");
            unsafe { libc::kill(child, libc::SIGKILL) };
        });
    }

    wait_for(pid)
}

fn child_exec(
    policy: &str,
    cwd: Option<&std::ffi::CStr>,
    prog: &std::ffi::CStr,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
    limits: &crate::config::Limits,
) -> ! {
    // Apply POSIX resource limits *before* the sandbox. setrlimit itself is
    // unrestricted by Seatbelt, so order doesn't matter for correctness;
    // doing it first keeps behaviour identical if sandbox ever got tighter
    // around setrlimit in the future.
    if let Err(lbl) = crate::limits::apply(limits) {
        let _ = write_stderr(b"sandkasten: setrlimit failed: ");
        let _ = write_stderr(lbl.as_bytes());
        let _ = write_stderr(b"\n");
        unsafe { libc::_exit(127) };
    }

    // Apply the sandbox.
    if let Err(e) = ffi::apply(policy) {
        // stderr write is best-effort; we're still pre-sandbox-exec but mid-fork.
        let _ = write_stderr(b"sandkasten: sandbox apply failed: ");
        let _ = write_stderr(e.as_bytes());
        let _ = write_stderr(b"\n");
        unsafe { libc::_exit(127) };
    }

    if let Some(c) = cwd {
        // SAFETY: `c` is a valid NUL-terminated C string owned by the caller.
        if unsafe { libc::chdir(c.as_ptr()) } != 0 {
            let _ = write_stderr(b"sandkasten: chdir failed (is the path in the FS allowlist?)\n");
            // SAFETY: _exit terminates without running destructors; required
            // in a forked child before execve.
            unsafe { libc::_exit(127) };
        }
    }

    // execvpe isn't on macOS — emulate with execve + PATH search, or use execvp
    // which does PATH lookup but uses the current environ. We want the scrubbed
    // environ to apply to the child, so we do the PATH search ourselves.
    exec_with_path(prog, argv, envp);
}

/// Resolve `prog` via PATH (if it has no `/`), then execve with the given envp.
fn exec_with_path(prog: &std::ffi::CStr, argv: &[*const libc::c_char], envp: &[*const libc::c_char]) -> ! {
    let prog_bytes = prog.to_bytes();
    if prog_bytes.contains(&b'/') {
        unsafe { libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        let err = unsafe { *libc::__error() };
        let _ = write_stderr(b"sandkasten: execve failed: ");
        let _ = write_stderr(prog_bytes);
        let _ = write_stderr(b" errno=");
        let mut buf = [0u8; 8];
        let n = itoa(err, &mut buf);
        let _ = write_stderr(&buf[..n]);
        let _ = write_stderr(b"\n");
        unsafe { libc::_exit(127) };
    }

    // PATH lookup. We read PATH from envp so the child's PATH (after env scrub)
    // is authoritative.
    let path = envp_get(envp, b"PATH").unwrap_or(b"/usr/bin:/bin:/usr/sbin:/sbin");
    for dir in path.split(|&b| b == b':') {
        if dir.is_empty() {
            continue;
        }
        let mut candidate: Vec<u8> = Vec::with_capacity(dir.len() + 1 + prog_bytes.len() + 1);
        candidate.extend_from_slice(dir);
        if dir.last() != Some(&b'/') {
            candidate.push(b'/');
        }
        candidate.extend_from_slice(prog_bytes);
        candidate.push(0);
        unsafe { libc::execve(candidate.as_ptr() as *const _, argv.as_ptr(), envp.as_ptr()) };
        // ENOENT / EACCES → try next. Any other errno and we bail.
        let err = unsafe { *libc::__error() };
        if err != libc::ENOENT && err != libc::EACCES && err != libc::ENOTDIR {
            break;
        }
    }
    let _ = write_stderr(b"sandkasten: exec failed (not found or not allowed by sandbox)\n");
    unsafe { libc::_exit(127) };
}

fn envp_get<'a>(envp: &'a [*const libc::c_char], key: &[u8]) -> Option<&'a [u8]> {
    for &p in envp {
        if p.is_null() {
            break;
        }
        let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
        if s.len() > key.len() && s.starts_with(key) && s[key.len()] == b'=' {
            // SAFETY: we return a slice into the CStr's bytes, which live as long
            // as envp (which is held on the stack by the caller).
            return Some(unsafe { std::slice::from_raw_parts(s.as_ptr().add(key.len() + 1), s.len() - key.len() - 1) });
        }
    }
    None
}

fn itoa(mut n: i32, buf: &mut [u8; 8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let mut tmp = [0u8; 8];
    let mut i = 0;
    while n > 0 && i < tmp.len() {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut j = 0;
    if neg && j < buf.len() {
        buf[j] = b'-';
        j += 1;
    }
    while i > 0 && j < buf.len() {
        i -= 1;
        buf[j] = tmp[i];
        j += 1;
    }
    j
}

fn write_stderr(b: &[u8]) -> std::io::Result<()> {
    let n = unsafe { libc::write(2, b.as_ptr() as *const _, b.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn build_envp(env: &crate::config::Env) -> Result<Vec<CString>> {
    let mut out: Vec<CString> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    let add = |out: &mut Vec<CString>, seen: &mut std::collections::BTreeSet<String>, k: &str, v: &str| -> Result<()> {
        if seen.insert(k.to_string()) {
            out.push(CString::new(format!("{k}={v}")).context("env contains NUL")?);
        }
        Ok(())
    };

    // Explicit `set` entries win.
    for (k, v) in &env.set {
        add(&mut out, &mut seen, k, v)?;
    }

    if env.pass_all {
        for (k, v) in std::env::vars() {
            add(&mut out, &mut seen, &k, &v)?;
        }
    } else {
        for key in &env.pass {
            if let Ok(v) = std::env::var(key) {
                add(&mut out, &mut seen, key, &v)?;
            }
        }
    }

    Ok(out)
}

fn wait_for(pid: libc::pid_t) -> Result<i32> {
    let mut status: libc::c_int = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err).context("waitpid");
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(1)
    }
}

extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe { libc::kill(pid, sig) };
    }
}

fn install_signal_forwarders() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = forward_signal as *const () as usize;
        unsafe {
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}
