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
    /// Build the Landlock ruleset for the given profile. When `target`
    /// is provided, the parent directory of the target binary is
    /// implicitly added to the allow-list with read + execute — this
    /// mirrors the macOS side: sandkasten's own `execve()` of `argv[0]`
    /// must always succeed regardless of how sparse the profile is,
    /// otherwise a minimal template ("strict") bricks itself before it
    /// can reach the sandboxed program's `main()`.
    pub fn for_target(p: &Profile, target: Option<&str>) -> Result<Self> {
        let abi = ABI::V3;
        let access_all = AccessFs::from_all(abi);
        // `from_read` covers ReadFile + ReadDir but — importantly — does NOT
        // include Execute. Without this, Landlock refuses every execve into
        // a binary whose directory is only on `read` (e.g. `/usr/bin/true`
        // under the `strict` template), and the very first `execve()` that
        // sandkasten itself performs returns EACCES. `Execute` + read is
        // the shape users expect of "read-only path": you can read it, you
        // can list it, you can run a binary from it, but you can't write.
        let access_read = AccessFs::from_read(abi) | AccessFs::Execute;

        // Compute effective read/read_write lists with `deny` enforcement by
        // subtree-pruning: any allow-path that is an ancestor of a deny-path is
        // dropped. We do NOT attempt to split a parent into its non-denied
        // children — users should specify narrower allows instead.
        let (mut reads, writes) = prune(&p.filesystem);

        // Implicit read+exec grant for the target binary's parent
        // directory (and the binary itself in case the parent is denied).
        // Matches the macOS `(allow process-exec (literal "<target>"))`.
        if let Some(t) = target {
            let path = std::path::Path::new(t);
            if let Some(parent) = path.parent() {
                let parent_s = parent.to_string_lossy().into_owned();
                if !reads.iter().any(|r| r == &parent_s) {
                    reads.push(parent_s);
                }
            }
        }

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
                    crate::log::debug(format_args!("landlock: skipping read path {path:?}: {e}"));
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
                    crate::log::debug(format_args!("landlock: skipping rw path {path:?}: {e}"));
                }
            }
        }

        Ok(Self {
            created: Some(created),
        })
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

    let mut reads = Vec::new();
    let mut writes = Vec::new();

    // Collect deny paths that are masked by an ancestor allow — they are
    // the ones Landlock can't enforce. Emit a single consolidated warning
    // at the end rather than once per read path (templates like `self`
    // with `read = ["/"]` would otherwise spam 10+ lines per invocation).
    let mut unenforceable_denies: Vec<String> = Vec::new();
    for p in &fs.read {
        if covered_by_deny(p) {
            continue;
        }
        for d in &fs.deny {
            if is_ancestor(p, d) && !unenforceable_denies.iter().any(|x| x == d) {
                unenforceable_denies.push(d.clone());
            }
        }
        reads.push(p.clone());
    }
    if !unenforceable_denies.is_empty() {
        // Shown only at `-v` (Info) and above. A default run of a template
        // like `self` would otherwise spam a 15-line paragraph on every
        // invocation for information the user can't act on during a one-
        // off execution.
        crate::log::info(format_args!(
            "Landlock is allow-list only, so these deny paths sit inside a \
             broader allow and are NOT enforced on Linux (they ARE enforced \
             on macOS): {}. Narrow the matching allow entry to exclude them \
             if that matters.",
            unenforceable_denies.join(", ")
        ));
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
