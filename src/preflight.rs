//! Runtime dependency check. Runs lazily from `sandkasten doctor` and
//! automatically on the first `run`/`shell` if `sandkasten` detects a
//! missing soft dependency that the user's profile actually needs.
//!
//! The output is a short table: check, status, remediation command tailored
//! to the detected distribution.

use std::fmt::Write as _;

pub struct Finding {
    pub check: &'static str,
    pub status: Status,
    pub hint: String,
}

pub enum Status {
    Ok,
    Missing,
    #[allow(dead_code)]
    NotApplicable,
}

pub fn run_all() -> Vec<Finding> {
    let mut out = Vec::new();

    #[cfg(target_os = "macos")]
    {
        out.push(check_sandbox_exec());
    }

    #[cfg(target_os = "linux")]
    {
        out.push(check_proc("/proc/sys/kernel/unprivileged_userns_clone"));
        out.push(check_tool(
            "nft",
            "per-IP outbound filtering",
            install_hint_nft(),
        ));
        out.push(check_tool(
            "strace",
            "`sandkasten learn` on Linux",
            install_hint_strace(),
        ));
        out.push(check_landlock());
    }

    out
}

pub fn render(findings: &[Finding]) -> String {
    let mut s = String::new();
    s.push_str("sandkasten pre-flight\n");
    s.push_str("─────────────────────\n");
    for f in findings {
        let symbol = match f.status {
            Status::Ok => "✓",
            Status::Missing => "✗",
            Status::NotApplicable => "·",
        };
        let _ = writeln!(s, " {symbol}  {:<32}  {}", f.check, f.hint);
    }
    s
}

pub fn has_problems(findings: &[Finding]) -> bool {
    findings.iter().any(|f| matches!(f.status, Status::Missing))
}

// ─── individual checks ───────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn check_sandbox_exec() -> Finding {
    let ok = std::path::Path::new("/usr/bin/sandbox-exec").exists();
    Finding {
        check: "sandbox-exec (reference)",
        status: if ok { Status::Ok } else { Status::Missing },
        hint: if ok {
            "present (for manual SBPL tests)".into()
        } else {
            "not found — sandkasten still works, but `sandbox-exec -f` testing won't".into()
        },
    }
}

#[cfg(target_os = "linux")]
fn check_proc(path: &str) -> Finding {
    let v = std::fs::read_to_string(path).unwrap_or_default();
    let v = v.trim();
    let label = "unprivileged user namespaces";
    if v == "1" {
        return Finding {
            check: label.leak_static(),
            status: Status::Ok,
            hint: format!("{path} = 1"),
        };
    }
    if v.is_empty() {
        // File doesn't exist — modern kernels don't always expose it.
        return Finding {
            check: label.leak_static(),
            status: Status::Ok,
            hint: format!("(sysctl not present — default-on kernel)"),
        };
    }
    Finding {
        check: label.leak_static(),
        status: Status::Missing,
        hint: format!(
            "{path} = {v}  — enable with `sudo sysctl -w kernel.unprivileged_userns_clone=1` \
             (persist via /etc/sysctl.d/99-userns.conf)"
        ),
    }
}

#[cfg(target_os = "linux")]
fn check_tool(bin: &str, reason: &'static str, install: String) -> Finding {
    let found = which_static(bin);
    if found.is_some() {
        Finding {
            check: bin_static(bin),
            status: Status::Ok,
            hint: format!("{}", found.unwrap().display()),
        }
    } else {
        Finding {
            check: bin_static(bin),
            status: Status::Missing,
            hint: format!("needed for {reason}. Install:  {install}"),
        }
    }
}

#[cfg(target_os = "linux")]
fn check_landlock() -> Finding {
    // Landlock ABI probe — syscall 445 (landlock_create_ruleset) with a
    // NULL attr + size=0 returns the supported ABI level, or -ENOSYS if
    // Landlock isn't compiled in.
    // SAFETY: linux-syscall with well-defined args.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_VERSION
        )
    };
    if rc < 0 {
        Finding {
            check: "Landlock LSM",
            status: Status::Missing,
            hint: format!(
                "syscall returned errno={} — kernel is older than 5.13 or Landlock not compiled in",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            ),
        }
    } else {
        Finding {
            check: "Landlock LSM",
            status: Status::Ok,
            hint: format!("ABI version {rc}"),
        }
    }
}

#[cfg(target_os = "linux")]
fn which_static(bin: &str) -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&path) {
            let p = d.join(bin);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    for fallback in ["/sbin", "/usr/sbin", "/usr/local/sbin"] {
        let p = std::path::Path::new(fallback).join(bin);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn distro_family() -> &'static str {
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    if os.contains("ID=debian") || os.contains("ID_LIKE=debian") || os.contains("ubuntu") {
        "debian"
    } else if os.contains("fedora") || os.contains("rhel") || os.contains("centos") {
        "rhel"
    } else if os.contains("arch") {
        "arch"
    } else if os.contains("alpine") {
        "alpine"
    } else if os.contains("opensuse") || os.contains("suse") {
        "suse"
    } else {
        "unknown"
    }
}

#[cfg(target_os = "linux")]
fn install_hint_nft() -> String {
    match distro_family() {
        "debian" => "sudo apt-get install nftables".into(),
        "rhel" => "sudo dnf install nftables".into(),
        "arch" => "sudo pacman -S nftables".into(),
        "alpine" => "sudo apk add nftables".into(),
        "suse" => "sudo zypper install nftables".into(),
        _ => "install the `nftables` package for your distro".into(),
    }
}

#[cfg(target_os = "linux")]
fn install_hint_strace() -> String {
    match distro_family() {
        "debian" => "sudo apt-get install strace".into(),
        "rhel" => "sudo dnf install strace".into(),
        "arch" => "sudo pacman -S strace".into(),
        "alpine" => "sudo apk add strace".into(),
        "suse" => "sudo zypper install strace".into(),
        _ => "install the `strace` package for your distro".into(),
    }
}

// Tiny helper — `&'static str` is needed for the `check` field; we leak
// short distro strings since the set is small and bounded.
#[cfg(target_os = "linux")]
fn bin_static(s: &str) -> &'static str {
    Box::leak(Box::<str>::from(s)) as _
}

#[cfg(target_os = "linux")]
trait LeakStr {
    fn leak_static(&self) -> &'static str;
}
#[cfg(target_os = "linux")]
impl LeakStr for &str {
    fn leak_static(&self) -> &'static str {
        Box::leak(Box::<str>::from(*self)) as _
    }
}
