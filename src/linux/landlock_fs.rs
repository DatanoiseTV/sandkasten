//! Landlock filesystem ruleset.
//!
//! Landlock is an LSM available from Linux 5.13+ (ABI v1), 5.19+ (ABI v2),
//! 6.2+ (ABI v3). It lets an unprivileged process restrict itself (and its
//! descendants) to an allow-list of filesystem subtrees. We open all path fds
//! in the parent (before the mount-ns / chdir possibly makes them unreachable)
//! and apply `restrict_self` in the child after any final setup.

use crate::config::Profile;
use anyhow::{Context, Result};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetStatus, ABI,
};

pub struct Prepared {
    created: Option<RulesetCreated>,
}

impl Prepared {
    pub fn from(p: &Profile) -> Result<Self> {
        let abi = ABI::V3;
        let access_all = AccessFs::from_all(abi);
        let access_read = AccessFs::from_read(abi);

        // Compute effective read/read_write lists with `deny` enforcement by
        // subtree-pruning: any allow-path that is an ancestor of a deny-path is
        // dropped. We do NOT attempt to split a parent into its non-denied
        // children — users should specify narrower allows instead.
        let (reads, writes) = prune(&p.filesystem);

        if reads.is_empty() && writes.is_empty() {
            return Ok(Self { created: None });
        }

        let mut created = Ruleset::default()
            .handle_access(access_all)
            .context("landlock handle_access")?
            .create()
            .context("landlock create (kernel >= 5.13?)")?;

        for path in &reads {
            match PathFd::new(path) {
                Ok(fd) => {
                    created = created
                        .add_rule(PathBeneath::new(fd, access_read))
                        .with_context(|| format!("landlock add_rule read {path}"))?;
                }
                Err(e) => {
                    // Paths that don't exist on this platform are silently
                    // skipped at default verbosity — cross-platform templates
                    // naturally include macOS-only entries on Linux and vice
                    // versa. Debug level surfaces them for diagnostics.
                    crate::log::debug(format_args!(
                        "landlock: skipping read path {path:?}: {e}"
                    ));
                }
            }
        }
        for path in &writes {
            match PathFd::new(path) {
                Ok(fd) => {
                    created = created
                        .add_rule(PathBeneath::new(fd, access_all))
                        .with_context(|| format!("landlock add_rule rw {path}"))?;
                }
                Err(e) => {
                    crate::log::debug(format_args!(
                        "landlock: skipping rw path {path:?}: {e}"
                    ));
                }
            }
        }

        Ok(Self { created: Some(created) })
    }

    pub fn apply(self) -> Result<()> {
        let Some(created) = self.created else {
            return Ok(());
        };
        let status = created.restrict_self().context("landlock restrict_self")?;
        if let RulesetStatus::NotEnforced = status.ruleset {
            eprintln!(
                "sandkasten: WARNING — Landlock not enforced (kernel/feature unavailable). \
                 Filesystem isolation will rely on mount namespace only."
            );
        }
        Ok(())
    }
}

fn prune(fs: &crate::config::Filesystem) -> (Vec<String>, Vec<String>) {
    use std::path::Path;
    let is_ancestor = |anc: &str, desc: &str| -> bool {
        let a = Path::new(anc);
        let d = Path::new(desc);
        d.starts_with(a) && a != d
    };
    let covered_by_deny = |p: &str| fs.deny.iter().any(|d| is_ancestor(d, p) || p == d);
    let has_deny_inside = |p: &str| fs.deny.iter().any(|d| is_ancestor(p, d));

    let mut reads = Vec::new();
    let mut writes = Vec::new();

    for p in &fs.read {
        if covered_by_deny(p) {
            continue;
        }
        if has_deny_inside(p) {
            eprintln!(
                "sandkasten: WARNING — Linux cannot deny {:?} inside allowed read subtree {:?}; \
                 use narrower allow paths instead.",
                fs.deny.iter().find(|d| p.starts_with(p)).unwrap_or(&String::new()),
                p
            );
        }
        reads.push(p.clone());
    }
    for p in &fs.read_write {
        if covered_by_deny(p) {
            continue;
        }
        writes.push(p.clone());
    }
    // read_files/read_write_files treated as literal parents for Landlock
    // (Landlock has no file-literal form — PathBeneath on the file itself works
    // for single files, too).
    for p in &fs.read_files {
        reads.push(p.clone());
    }
    for p in &fs.read_write_files {
        writes.push(p.clone());
    }
    (reads, writes)
}
