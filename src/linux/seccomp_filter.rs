//! seccomp-BPF deny-list.
//!
//! This filter is defence-in-depth, not the primary isolation mechanism.
//! Namespaces already make most of these syscalls useless from inside the
//! sandbox; seccomp ensures the kernel doesn't even start to process them.

use crate::config::Profile;
use anyhow::{Context, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use std::collections::BTreeMap;

pub fn install(profile: &Profile) -> Result<()> {
    let arch = if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        // seccompiler supports these two; other archs pass through.
        return Ok(());
    };

    let blocked: &[i64] = &[
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_reboot,
        libc::SYS_keyctl,
        libc::SYS_syslog,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_add_key,
        libc::SYS_request_key,
        // Hardlink / symlink creation is a classic sandbox-escape primitive:
        // with write access to any path + read access to system paths, an
        // attacker can pull a sensitive file into their writable dir by
        // linkat(), sidestepping Landlock's path-based rules. Blocking link
        // creation is a cheap, broad mitigation. Note: SYS_link and
        // SYS_symlink only exist on legacy archs (x86_64); aarch64 kernels
        // only provide the *at variants, which we block unconditionally.
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        // Filesystem-by-handle syscalls that let the caller reopen a file
        // by a handle obtained in another mount namespace — classic
        // mount-ns-escape technique. Deny regardless.
        libc::SYS_name_to_handle_at,
        libc::SYS_open_by_handle_at,
        // io_uring: large, fast-evolving attack surface. Recent CVEs have
        // repeatedly found privilege escalations in this subsystem. Deny
        // unless you need it (and if you do, patch this list).
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // userfaultfd: used in kernel-exploit primitives to stall on page
        // faults. Almost no legit sandboxed-app use.
        libc::SYS_userfaultfd,
        // Time manipulation — prevent the sandbox from smearing the clock.
        libc::SYS_settimeofday,
        libc::SYS_adjtimex,
        libc::SYS_clock_adjtime,
        libc::SYS_clock_settime,
        // Process-mode & comparison primitives often used in exploit chains.
        libc::SYS_personality,
        libc::SYS_kcmp,
        libc::SYS_vhangup,
        libc::SYS_quotactl,
        // fanotify — filesystem event capture (can see metadata across mount ns).
        libc::SYS_fanotify_init,
        libc::SYS_fanotify_mark,
        // Deprecated but still present on x86_64 kernels, frequently exploited.
        libc::SYS_remap_file_pages,
        // NUMA / memory movement: rarely needed, sometimes abused in races.
        libc::SYS_move_pages,
        libc::SYS_migrate_pages,
        libc::SYS_mbind,
        libc::SYS_set_mempolicy,
        libc::SYS_get_mempolicy,
        // Process accounting — lets a root-in-userns attacker turn on
        // accounting and enumerate host process execs via the syscall.
        libc::SYS_acct,
        // Deprecated / legacy that should never be called by a modern
        // sandboxed binary and are thin wrappers for long-ago semantics.
        libc::SYS_lookup_dcookie,
    ];

    // Syscalls only present on legacy archs (x86_64). aarch64 never
    // exposed SYS_link, SYS_symlink, SYS_uselib, SYS_iopl or SYS_ioperm.
    #[cfg(target_arch = "x86_64")]
    let extra_blocked: &[i64] = &[
        libc::SYS_link,
        libc::SYS_symlink,
        // Legacy library loader — deprecated, occasionally abused for
        // ELF parsing tricks.
        libc::SYS_uselib,
        libc::SYS_iopl,
        libc::SYS_ioperm,
    ];
    #[cfg(not(target_arch = "x86_64"))]
    let extra_blocked: &[i64] = &[];

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in blocked.iter().chain(extra_blocked.iter()) {
        rules.insert(nr, vec![]);
    }

    // Optional: block the setuid-family syscalls. Enabled either directly
    // via `process.block_setid_syscalls` or transitively via
    // `process.block_privilege_elevation` (which implies it). The userns
    // boundary already makes these calls only affect the inner UID/GID
    // mapping (not the host), but denying them outright is defense-in-
    // depth — and importantly, makes sudo/su fail loudly instead of
    // succeeding in the userns and leaving confused callers running with
    // "root-looking" inner credentials.
    if profile.process.blocks_setid() {
        let setid: &[i64] = &[
            libc::SYS_setuid,
            libc::SYS_setgid,
            libc::SYS_setreuid,
            libc::SYS_setregid,
            libc::SYS_setresuid,
            libc::SYS_setresgid,
            libc::SYS_setfsuid,
            libc::SYS_setfsgid,
            libc::SYS_setgroups,
        ];
        for &nr in setid {
            rules.insert(nr, vec![]);
        }
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                     // default: allow
        SeccompAction::Errno(libc::EPERM as u32), // blocked: EPERM
        arch,
    )
    .context("build seccomp filter")?;

    let prog: BpfProgram = filter.try_into().context("compile seccomp BPF")?;
    seccompiler::apply_filter(&prog).context("apply seccomp BPF")?;
    Ok(())
}
