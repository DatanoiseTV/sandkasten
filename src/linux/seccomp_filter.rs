//! seccomp-BPF deny-list.
//!
//! This filter is defence-in-depth, not the primary isolation mechanism.
//! Namespaces already make most of these syscalls useless from inside the
//! sandbox; seccomp ensures the kernel doesn't even start to process them.

use crate::config::Profile;
use anyhow::{Context, Result};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

pub fn install(_profile: &Profile) -> Result<()> {
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
    ];

    #[cfg(target_arch = "x86_64")]
    let extra_blocked: &[i64] = &[libc::SYS_iopl, libc::SYS_ioperm];
    #[cfg(not(target_arch = "x86_64"))]
    let extra_blocked: &[i64] = &[];

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in blocked.iter().chain(extra_blocked.iter()) {
        rules.insert(nr, vec![]);
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,           // default: allow
        SeccompAction::Errno(libc::EPERM as u32), // blocked: EPERM
        arch,
    )
    .context("build seccomp filter")?;

    let prog: BpfProgram = filter.try_into().context("compile seccomp BPF")?;
    seccompiler::apply_filter(&prog).context("apply seccomp BPF")?;
    Ok(())
}
