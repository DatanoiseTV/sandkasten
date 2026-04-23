//! POSIX resource-limits (`setrlimit`) applier, shared by macOS and Linux.
//!
//! Called from inside the forked child, *before* sandbox application and
//! exec — these are per-process limits that survive exec and are enforced
//! by the kernel scheduler / allocator, independent of the MACF/Landlock
//! layer.

use crate::config::Limits;

const MB: u64 = 1024 * 1024;

/// Apply all non-None limits from the profile. Failures are reported via
/// a string return (the child prints + `_exit`s); we don't stop on a
/// single setrlimit failure to avoid making the sandbox a brittleness trap.
pub fn apply(limits: &Limits) -> Result<(), &'static str> {
    // Helper that sets both soft and hard to the same value. Setting only
    // soft leaves room for the process to raise itself back up; setting
    // hard ensures it cannot.
    //
    // libc's `RLIMIT_*` constants are `i32` on macOS and `u32` on Linux,
    // so we take the resource id as the platform-native type
    // (`__rlimit_resource_t` / `c_int`) via a tiny wrapper.
    fn set_one(resource: RlimResource, val: u64, label: &'static str) -> Result<(), &'static str> {
        let rl = libc::rlimit {
            rlim_cur: val as libc::rlim_t,
            rlim_max: val as libc::rlim_t,
        };
        // SAFETY: `rl` is a valid, fully initialised rlimit struct.
        let rc = unsafe { libc::setrlimit(resource, &rl) };
        if rc != 0 {
            return Err(label);
        }
        Ok(())
    }

    if let Some(s) = limits.cpu_seconds {
        set_one(libc::RLIMIT_CPU, s, "RLIMIT_CPU")?;
    }
    if let Some(m) = limits.memory_mb {
        // On macOS RLIMIT_AS exists but is often loose; RLIMIT_DATA is the
        // more reliable gate for most allocators. We set both on Linux.
        let _ = set_one(libc::RLIMIT_AS, m.saturating_mul(MB), "RLIMIT_AS");
        #[cfg(target_os = "linux")]
        {
            set_one(libc::RLIMIT_DATA, m.saturating_mul(MB), "RLIMIT_DATA")?;
        }
    }
    if let Some(s) = limits.file_size_mb {
        set_one(libc::RLIMIT_FSIZE, s.saturating_mul(MB), "RLIMIT_FSIZE")?;
    }
    if let Some(n) = limits.open_files {
        set_one(libc::RLIMIT_NOFILE, n, "RLIMIT_NOFILE")?;
    }
    if let Some(n) = limits.processes {
        set_one(libc::RLIMIT_NPROC, n, "RLIMIT_NPROC")?;
    }
    if let Some(s) = limits.stack_mb {
        set_one(libc::RLIMIT_STACK, s.saturating_mul(MB), "RLIMIT_STACK")?;
    }
    if !limits.core_dumps {
        // Zero the core-dump limit so a crash can't spill memory to disk.
        set_one(libc::RLIMIT_CORE, 0, "RLIMIT_CORE")?;
    }

    Ok(())
}

// Native type for libc::setrlimit's resource id: i32 on macOS, u32 on Linux.
#[cfg(target_os = "linux")]
type RlimResource = libc::__rlimit_resource_t;
#[cfg(not(target_os = "linux"))]
type RlimResource = libc::c_int;
