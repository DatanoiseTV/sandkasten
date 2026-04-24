//! Platform-agnostic parts of `learn` mode: operation vocabulary, heuristics,
//! interactive prompting, and TOML emission. Each platform produces a
//! `BTreeSet<Op>` (macOS via SBPL `(trace ...)`, Linux via strace parsing) and
//! passes it to `process`.

use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct Options {
    pub base: String,
    pub output: Option<PathBuf>,
    pub auto_system: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Op {
    FileRead(PathBuf),
    FileReadMeta(PathBuf),
    FileWrite(PathBuf),
    MachLookup(String),
    NetOutbound { proto: String, endpoint: String },
    NetBind { proto: String, endpoint: String },
    ProcessExec(PathBuf),
    SysctlRead(String),
    IokitOpen(String),
    IpcShm(String),
    Other(String),
}

pub fn process(ops: BTreeSet<Op>, cwd: &Path, opts: &Options) -> Result<i32> {
    eprintln!("sandkasten: captured {} unique operations", ops.len());

    let home = dirs::home_dir();
    let analysis = analyze(&ops, cwd, home.as_deref());
    let decisions = prompt_decisions(&analysis, opts)?;
    let toml = emit_toml(&opts.base, &analysis, &decisions)?;

    let out_path = opts
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("learned.toml"));
    std::fs::write(&out_path, &toml).with_context(|| format!("writing {}", out_path.display()))?;
    eprintln!("\nsandkasten: wrote profile to {}", out_path.display());
    eprintln!(
        "            try it with:  sandkasten run {} -- <your-cmd>",
        out_path.display()
    );
    Ok(0)
}

// ─── heuristics ──────────────────────────────────────────────────────────────

const SYSTEM_SUBTREES_MACOS: &[&str] = &[
    "/usr/lib",
    "/usr/share",
    "/usr/libexec",
    "/System/Library",
    "/Library/Apple/System",
    "/private/var/db/dyld",
    "/private/var/db/timezone",
    "/private/etc/localtime",
    "/private/var/db/mds",
];

const SYSTEM_SUBTREES_LINUX: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib32",
    "/usr/lib64",
    "/usr/share",
    "/usr/include",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf.d",
    "/etc/localtime",
    "/etc/alternatives",
    "/proc/self",
    "/sys/devices/system/cpu",
];

const SYSTEM_BIN_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];

#[cfg(target_os = "macos")]
const TMP_SUBTREES: &[&str] = &["/private/var/folders", "/tmp", "/private/tmp"];
#[cfg(not(target_os = "macos"))]
const TMP_SUBTREES: &[&str] = &["/tmp", "/var/tmp", "/run/user"];

fn sensitive_relative() -> &'static [&'static str] {
    &[
        ".ssh",
        ".aws",
        ".gnupg",
        ".config/gcloud",
        ".docker",
        ".kube",
        ".netrc",
        ".pgpass",
        "Library/Keychains",
        "Library/Application Support/com.apple.TCC",
        "Library/Cookies",
        "Library/Mail",
        "Library/Messages",
        ".bash_history",
        ".zsh_history",
        ".password-store",
        ".mozilla",
    ]
}

const SAFE_MACH_SERVICES: &[&str] = &[
    "com.apple.system.logger",
    "com.apple.system.notification_center",
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.CoreServices.coreservicesd",
    "com.apple.lsd.mapdb",
    "com.apple.lsd.modifydb",
    "com.apple.SystemConfiguration.configd",
    "com.apple.dnssd.service",
    "com.apple.logd",
];

pub struct Analysis {
    pub cwd: PathBuf,
    pub home: Option<PathBuf>,
    pub system_reads: Vec<String>,
    pub system_bins: Vec<String>,
    pub cwd_reads: bool,
    pub cwd_writes: bool,
    pub tmp_used: bool,
    pub home_literals_read: Vec<PathBuf>,
    pub home_literals_write: Vec<PathBuf>,
    pub other_reads: Vec<PathBuf>,
    pub other_writes: Vec<PathBuf>,
    pub rolled_up_subpaths_read: Vec<PathBuf>,
    pub rolled_up_subpaths_write: Vec<PathBuf>,
    pub sensitive_hits: Vec<PathBuf>,
    pub mach_safe: Vec<String>,
    pub mach_other: Vec<String>,
    pub outbound: Vec<(String, String)>,
    pub outbound_by_port: BTreeMap<u16, BTreeSet<String>>,
    pub outbound_has_dns: bool,
    pub inbound: Vec<(String, String)>,
    pub sysctls: Vec<String>,
    pub iokit: Vec<String>,
    pub ipc: Vec<String>,
    pub process_execs: Vec<PathBuf>,
}

fn system_subtrees() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        SYSTEM_SUBTREES_MACOS
    } else {
        SYSTEM_SUBTREES_LINUX
    }
}

fn analyze(ops: &BTreeSet<Op>, cwd: &Path, home: Option<&Path>) -> Analysis {
    let mut a = Analysis {
        cwd: cwd.to_path_buf(),
        home: home.map(|h| h.to_path_buf()),
        system_reads: Vec::new(),
        system_bins: Vec::new(),
        cwd_reads: false,
        cwd_writes: false,
        tmp_used: false,
        home_literals_read: Vec::new(),
        home_literals_write: Vec::new(),
        other_reads: Vec::new(),
        other_writes: Vec::new(),
        rolled_up_subpaths_read: Vec::new(),
        rolled_up_subpaths_write: Vec::new(),
        sensitive_hits: Vec::new(),
        mach_safe: Vec::new(),
        mach_other: Vec::new(),
        outbound: Vec::new(),
        outbound_by_port: BTreeMap::new(),
        outbound_has_dns: false,
        inbound: Vec::new(),
        sysctls: Vec::new(),
        iokit: Vec::new(),
        ipc: Vec::new(),
        process_execs: Vec::new(),
    };

    let mut used_system: BTreeSet<String> = BTreeSet::new();
    let mut used_bins: BTreeSet<String> = BTreeSet::new();
    let mut unclassified_reads: Vec<PathBuf> = Vec::new();
    let mut unclassified_writes: Vec<PathBuf> = Vec::new();

    let ctx = ClassifyCtx { cwd, home };
    for op in ops {
        match op {
            Op::FileRead(p) | Op::FileReadMeta(p) | Op::ProcessExec(p) => {
                classify_path(
                    p,
                    &ctx,
                    &mut ClassifySinks {
                        used_system: &mut used_system,
                        used_bins: &mut used_bins,
                        sensitive: &mut a.sensitive_hits,
                        tmp_flag: &mut a.tmp_used,
                        cwd_flag: &mut a.cwd_reads,
                        home_literals: &mut a.home_literals_read,
                        other_literals: &mut unclassified_reads,
                    },
                );
                if matches!(op, Op::ProcessExec(_)) {
                    a.process_execs.push(p.clone());
                }
            }
            Op::FileWrite(p) => {
                classify_path(
                    p,
                    &ctx,
                    &mut ClassifySinks {
                        used_system: &mut used_system,
                        used_bins: &mut used_bins,
                        sensitive: &mut a.sensitive_hits,
                        tmp_flag: &mut a.tmp_used,
                        cwd_flag: &mut a.cwd_writes,
                        home_literals: &mut a.home_literals_write,
                        other_literals: &mut unclassified_writes,
                    },
                );
            }
            Op::MachLookup(name) => {
                if SAFE_MACH_SERVICES.contains(&name.as_str()) {
                    if !a.mach_safe.contains(name) {
                        a.mach_safe.push(name.clone());
                    }
                } else if !a.mach_other.contains(name) {
                    a.mach_other.push(name.clone());
                }
            }
            Op::NetOutbound { proto, endpoint } => {
                let ep = (proto.clone(), endpoint.clone());
                if !a.outbound.contains(&ep) {
                    a.outbound.push(ep);
                }
                if let Some((host, port)) = split_endpoint(endpoint) {
                    if port == 53 {
                        a.outbound_has_dns = true;
                    } else {
                        a.outbound_by_port.entry(port).or_default().insert(host);
                    }
                }
            }
            Op::NetBind { proto, endpoint } => {
                let ep = (proto.clone(), endpoint.clone());
                if !a.inbound.contains(&ep) {
                    a.inbound.push(ep);
                }
            }
            Op::SysctlRead(s) => {
                if !a.sysctls.contains(s) {
                    a.sysctls.push(s.clone());
                }
            }
            Op::IokitOpen(s) => {
                if !a.iokit.contains(s) {
                    a.iokit.push(s.clone());
                }
            }
            Op::IpcShm(s) => {
                if !a.ipc.contains(s) {
                    a.ipc.push(s.clone());
                }
            }
            Op::Other(_) => {}
        }
    }

    a.system_reads = used_system.into_iter().collect();
    a.system_bins = used_bins.into_iter().collect();

    let (read_rolls, read_leftovers) = rollup_by_parent(unclassified_reads, 3);
    let (write_rolls, write_leftovers) = rollup_by_parent(unclassified_writes, 3);
    a.rolled_up_subpaths_read = read_rolls;
    a.rolled_up_subpaths_write = write_rolls;
    a.other_reads = read_leftovers;
    a.other_writes = write_leftovers;

    a
}

struct ClassifyCtx<'a> {
    cwd: &'a Path,
    home: Option<&'a Path>,
}

struct ClassifySinks<'a> {
    used_system: &'a mut BTreeSet<String>,
    used_bins: &'a mut BTreeSet<String>,
    sensitive: &'a mut Vec<PathBuf>,
    tmp_flag: &'a mut bool,
    cwd_flag: &'a mut bool,
    home_literals: &'a mut Vec<PathBuf>,
    other_literals: &'a mut Vec<PathBuf>,
}

fn classify_path(p: &Path, ctx: &ClassifyCtx<'_>, out: &mut ClassifySinks<'_>) {
    let cwd = ctx.cwd;
    let home = ctx.home;
    let used_system = &mut *out.used_system;
    let used_bins = &mut *out.used_bins;
    let sensitive = &mut *out.sensitive;
    let tmp_flag = &mut *out.tmp_flag;
    let cwd_flag = &mut *out.cwd_flag;
    let home_literals = &mut *out.home_literals;
    let other_literals = &mut *out.other_literals;
    if let Some(h) = home {
        for rel in sensitive_relative() {
            let s = h.join(rel);
            if p.starts_with(&s) {
                if !sensitive.contains(&p.to_path_buf()) {
                    sensitive.push(p.to_path_buf());
                }
                return;
            }
        }
    }
    for sub in system_subtrees() {
        if p.starts_with(sub) {
            used_system.insert((*sub).to_string());
            return;
        }
    }
    for bin in SYSTEM_BIN_DIRS {
        if p.starts_with(bin) {
            used_bins.insert((*bin).to_string());
            return;
        }
    }
    for tmp in TMP_SUBTREES {
        if p.starts_with(tmp) {
            *tmp_flag = true;
            return;
        }
    }
    if p.starts_with(cwd) {
        *cwd_flag = true;
        return;
    }
    if let Some(h) = home {
        if p.starts_with(h) {
            if !home_literals.contains(&p.to_path_buf()) {
                home_literals.push(p.to_path_buf());
            }
            return;
        }
    }
    if !other_literals.contains(&p.to_path_buf()) {
        other_literals.push(p.to_path_buf());
    }
}

fn rollup_by_parent(paths: Vec<PathBuf>, min: usize) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut by_parent: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for p in paths {
        if let Some(par) = p.parent() {
            by_parent.entry(par.to_path_buf()).or_default().push(p);
        }
    }
    let mut rolls = Vec::new();
    let mut leftovers = Vec::new();
    for (par, kids) in by_parent {
        if kids.len() >= min && par != Path::new("/") && !par.as_os_str().is_empty() {
            rolls.push(par);
        } else {
            leftovers.extend(kids);
        }
    }
    (rolls, leftovers)
}

fn split_endpoint(ep: &str) -> Option<(String, u16)> {
    if let Some(rest) = ep.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let port_s = rest[close + 1..].strip_prefix(':')?;
        let port = port_s.parse().ok()?;
        return Some((format!("[{host}]"), port));
    }
    let i = ep.rfind(':')?;
    let host = &ep[..i];
    let port: u16 = ep[i + 1..].parse().ok()?;
    Some((host.to_string(), port))
}

// ─── prompting ───────────────────────────────────────────────────────────────

#[derive(Default, Debug)]
pub struct Decisions {
    pub allow_system_reads: bool,
    pub allow_system_bins: bool,
    pub allow_tmp: bool,
    pub allow_cwd_rw: bool,
    pub allow_home_literals: bool,
    pub allow_rolled_reads: bool,
    pub allow_rolled_writes: bool,
    pub allow_other_reads: bool,
    pub allow_other_writes: bool,
    pub allow_sensitive: bool,
    pub allow_mach_safe: bool,
    pub allow_mach_other: bool,
    pub outbound_mode: OutboundMode,
    pub allow_inbound: bool,
    pub allow_sysctls: bool,
    pub allow_iokit: bool,
    pub allow_ipc: bool,
    pub allow_dns: bool,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundMode {
    #[default]
    Deny,
    Specific,
    WildcardByPort,
}

fn prompt_decisions(a: &Analysis, opts: &Options) -> Result<Decisions> {
    let mut d = Decisions::default();
    let mut n = 1;

    eprintln!("\n── review observed behaviour ────────────────────────────────────");

    if !a.system_reads.is_empty() {
        d.allow_system_reads = bucket_prompt(
            &mut n,
            "System library reads",
            a.system_reads.iter().map(|s| s.as_str()),
            "read-only, known-safe subtrees (libc, runtime, timezone, etc.)",
            DefaultAnswer::Yes,
            opts.auto_system,
        )?;
    }
    if !a.system_bins.is_empty() {
        d.allow_system_bins = bucket_prompt(
            &mut n,
            "System binary dirs (read)",
            a.system_bins.iter().map(|s| s.as_str()),
            "lets the sandboxed process launch stock utilities",
            DefaultAnswer::Yes,
            opts.auto_system,
        )?;
    }
    if a.tmp_used {
        d.allow_tmp = bucket_prompt(
            &mut n,
            "Temp directories",
            TMP_SUBTREES.iter().copied(),
            "per-user tmp (read+write) — libc and frameworks often need this",
            DefaultAnswer::Yes,
            opts.auto_system,
        )?;
    }
    if a.cwd_reads || a.cwd_writes {
        let mode = if a.cwd_writes { "read+write" } else { "read" };
        d.allow_cwd_rw = bucket_prompt(
            &mut n,
            &format!("Working directory ${{CWD}} ({mode})"),
            [a.cwd.to_string_lossy().as_ref()].iter().copied(),
            "the app's \"own folder\" — emitted portably as ${CWD}",
            DefaultAnswer::Yes,
            false,
        )?;
    }
    if !a.rolled_up_subpaths_read.is_empty() {
        let lines: Vec<String> = a
            .rolled_up_subpaths_read
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        d.allow_rolled_reads = bucket_prompt(
            &mut n,
            "Parent-dir rollups (read)",
            lines.iter().map(|s| s.as_str()),
            "3+ siblings observed; collapsed to the parent subpath",
            DefaultAnswer::Maybe,
            false,
        )?;
    }
    if !a.rolled_up_subpaths_write.is_empty() {
        let lines: Vec<String> = a
            .rolled_up_subpaths_write
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        d.allow_rolled_writes = bucket_prompt(
            &mut n,
            "Parent-dir rollups (write)",
            lines.iter().map(|s| s.as_str()),
            "writes observed across multiple siblings of a parent dir",
            DefaultAnswer::Maybe,
            false,
        )?;
    }
    if !a.home_literals_read.is_empty() {
        let lines: Vec<String> = a
            .home_literals_read
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        d.allow_home_literals = bucket_prompt(
            &mut n,
            "Home-directory reads (narrow literals)",
            lines.iter().map(|s| s.as_str()),
            "single-file reads under your home that are NOT sensitive",
            DefaultAnswer::Maybe,
            false,
        )?;
    }
    if !a.other_reads.is_empty() {
        let lines: Vec<String> = a
            .other_reads
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        d.allow_other_reads = bucket_prompt(
            &mut n,
            "Other reads",
            lines.iter().map(|s| s.as_str()),
            "paths outside system / CWD / home",
            DefaultAnswer::Maybe,
            false,
        )?;
    }
    if !a.other_writes.is_empty() {
        let lines: Vec<String> = a
            .other_writes
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        d.allow_other_writes = bucket_prompt(
            &mut n,
            "Other writes",
            lines.iter().map(|s| s.as_str()),
            "writes outside system / CWD / home — scrutinize carefully",
            DefaultAnswer::No,
            false,
        )?;
    }
    if !a.sensitive_hits.is_empty() {
        eprintln!("\n ⚠  SENSITIVE path access observed:");
        for p in &a.sensitive_hits {
            eprintln!("      {}", p.display());
        }
        eprintln!("    These are default-DENIED. Emitted as explicit `deny` entries");
        eprintln!("    in the generated profile. Override only if you understand the risk.");
        d.allow_sensitive = yes_no("    Override and ALLOW access to these paths?", false)?;
    }

    if !a.mach_safe.is_empty() {
        d.allow_mach_safe = bucket_prompt(
            &mut n,
            "Mach services (known-safe)",
            a.mach_safe.iter().map(|s| s.as_str()),
            "standard system bus endpoints",
            DefaultAnswer::Yes,
            opts.auto_system,
        )?;
    }
    if !a.mach_other.is_empty() {
        d.allow_mach_other = bucket_prompt(
            &mut n,
            "Mach services (other)",
            a.mach_other.iter().map(|s| s.as_str()),
            "unusual endpoints — scrutinize",
            DefaultAnswer::Maybe,
            false,
        )?;
    }

    if !a.outbound.is_empty() || a.outbound_has_dns {
        eprintln!("\n [{n}] Outbound network");
        n += 1;
        if a.outbound_has_dns {
            eprintln!("     DNS (UDP:53) observed.");
        }
        if !a.outbound.is_empty() {
            let mut list: Vec<&(String, String)> = a.outbound.iter().collect();
            list.sort();
            for (proto, ep) in list.iter().take(20) {
                eprintln!("     {proto:3} {ep}");
            }
            if a.outbound.len() > 20 {
                eprintln!("     ... and {} more", a.outbound.len() - 20);
            }
        }
        let wildcardable: Vec<u16> = a
            .outbound_by_port
            .iter()
            .filter(|(_, hosts)| hosts.len() >= 3)
            .map(|(p, _)| *p)
            .collect();
        if !wildcardable.is_empty() {
            eprintln!(
                "     hint: {} hit by ≥3 distinct hosts — wildcard `*:PORT` is a natural fit.",
                wildcardable
                    .iter()
                    .map(|p| format!(":{p}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let choice = choose(
            "     mode? [d]eny / [s]pecific hosts / [w]ildcard by port",
            &["d", "s", "w"],
            "d",
        )?;
        d.outbound_mode = match choice.as_str() {
            "s" => OutboundMode::Specific,
            "w" => OutboundMode::WildcardByPort,
            _ => OutboundMode::Deny,
        };
        if a.outbound_has_dns {
            d.allow_dns = yes_no("     allow DNS (UDP:53 / TCP:53)?", true)?;
        }
    }

    if !a.inbound.is_empty() {
        eprintln!("\n [{n}] Inbound listeners");
        n += 1;
        for (proto, ep) in &a.inbound {
            eprintln!("     {proto:3} {ep}");
        }
        d.allow_inbound = yes_no("     allow these inbound binds?", false)?;
    }

    if !a.sysctls.is_empty() {
        d.allow_sysctls = bucket_prompt(
            &mut n,
            "Sysctl reads",
            a.sysctls.iter().map(|s| s.as_str()),
            "kernel state reads — commonly safe",
            DefaultAnswer::Yes,
            opts.auto_system,
        )?;
    }
    if !a.iokit.is_empty() {
        d.allow_iokit = bucket_prompt(
            &mut n,
            "IOKit opens",
            a.iokit.iter().map(|s| s.as_str()),
            "hardware/device access",
            DefaultAnswer::Maybe,
            false,
        )?;
    }
    if !a.ipc.is_empty() {
        d.allow_ipc = bucket_prompt(
            &mut n,
            "POSIX IPC",
            a.ipc.iter().map(|s| s.as_str()),
            "shared memory / semaphores",
            DefaultAnswer::Maybe,
            false,
        )?;
    }

    eprintln!("─────────────────────────────────────────────────────────────────");
    Ok(d)
}

enum DefaultAnswer {
    Yes,
    No,
    Maybe,
}

fn bucket_prompt<'a>(
    n: &mut usize,
    title: &str,
    items: impl IntoIterator<Item = &'a str>,
    note: &str,
    default: DefaultAnswer,
    auto_accept: bool,
) -> Result<bool> {
    let items: Vec<&str> = items.into_iter().collect();
    eprintln!(
        "\n [{}] {title}  ({} item{})",
        n,
        items.len(),
        if items.len() == 1 { "" } else { "s" }
    );
    *n += 1;
    eprintln!("     {note}");
    for line in items.iter().take(8) {
        eprintln!("       • {line}");
    }
    if items.len() > 8 {
        eprintln!("       ... and {} more", items.len() - 8);
    }
    if auto_accept {
        eprintln!("     (auto-accepted via --auto-system)");
        return Ok(true);
    }
    let default_bool = match default {
        DefaultAnswer::Yes => true,
        DefaultAnswer::No => false,
        DefaultAnswer::Maybe => false,
    };
    yes_no("     include in profile?", default_bool)
}

fn yes_no(prompt: &str, default: bool) -> Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    eprint!("{prompt} {hint} ");
    std::io::stderr().flush().ok();
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    let t = buf.trim().to_lowercase();
    Ok(match t.as_str() {
        "" => default,
        "y" | "yes" => true,
        _ => false,
    })
}

fn choose(prompt: &str, choices: &[&str], default: &str) -> Result<String> {
    eprint!("{prompt} (default {default}) ");
    std::io::stderr().flush().ok();
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    let t = buf.trim().to_lowercase();
    if t.is_empty() {
        return Ok(default.to_string());
    }
    for c in choices {
        if *c == t {
            return Ok(t);
        }
    }
    Ok(default.to_string())
}

// ─── emit ────────────────────────────────────────────────────────────────────

fn emit_toml(base: &str, a: &Analysis, d: &Decisions) -> Result<String> {
    let mut s = String::new();
    s.push_str("# generated by `sandkasten learn`\n");
    s.push_str("name = \"learned\"\n");
    s.push_str("description = \"Auto-generated from observed behaviour.\"\n");
    s.push_str(&format!("extends = \"{}\"\n\n", toml_escape(base)));

    let mut reads: Vec<String> = Vec::new();
    let mut read_writes: Vec<String> = Vec::new();
    let mut deny: Vec<String> = Vec::new();
    let mut read_files: Vec<String> = Vec::new();
    let mut rw_files: Vec<String> = Vec::new();

    if d.allow_system_reads {
        reads.extend(a.system_reads.iter().cloned());
    }
    if d.allow_system_bins {
        reads.extend(a.system_bins.iter().cloned());
    }
    if d.allow_tmp {
        for t in TMP_SUBTREES {
            read_writes.push((*t).to_string());
        }
    }
    if d.allow_cwd_rw {
        read_writes.push("${CWD}".into());
    }
    if d.allow_rolled_reads {
        for p in &a.rolled_up_subpaths_read {
            reads.push(p.to_string_lossy().into_owned());
        }
    }
    if d.allow_rolled_writes {
        for p in &a.rolled_up_subpaths_write {
            read_writes.push(p.to_string_lossy().into_owned());
        }
    }
    if d.allow_home_literals {
        for p in &a.home_literals_read {
            read_files.push(portable_home_path(p, a.home.as_deref()));
        }
    }
    if d.allow_other_reads {
        for p in &a.other_reads {
            read_files.push(p.to_string_lossy().into_owned());
        }
    }
    if d.allow_other_writes {
        for p in &a.other_writes {
            rw_files.push(p.to_string_lossy().into_owned());
        }
    }
    if !a.sensitive_hits.is_empty() && !d.allow_sensitive {
        for p in &a.sensitive_hits {
            deny.push(portable_home_path(p, a.home.as_deref()));
        }
    } else if d.allow_sensitive {
        for p in &a.sensitive_hits {
            read_files.push(portable_home_path(p, a.home.as_deref()));
        }
    }

    if !(reads.is_empty()
        && read_writes.is_empty()
        && deny.is_empty()
        && read_files.is_empty()
        && rw_files.is_empty())
    {
        s.push_str("[filesystem]\n");
        emit_list(&mut s, "read", &reads);
        emit_list(&mut s, "read_write", &read_writes);
        emit_list(&mut s, "read_files", &read_files);
        emit_list(&mut s, "read_write_files", &rw_files);
        emit_list(&mut s, "deny", &deny);
        s.push('\n');
    }

    let any_net = d.allow_dns || d.outbound_mode != OutboundMode::Deny || d.allow_inbound;
    if any_net {
        s.push_str("[network]\n");
        if d.allow_dns {
            s.push_str("allow_dns = true\n");
        }
        match d.outbound_mode {
            OutboundMode::Deny => {}
            OutboundMode::Specific => {
                let tcp: Vec<String> = a
                    .outbound
                    .iter()
                    .filter(|(p, _)| p == "tcp")
                    .map(|(_, e)| e.clone())
                    .collect();
                let udp: Vec<String> = a
                    .outbound
                    .iter()
                    .filter(|(p, _)| p == "udp")
                    .map(|(_, e)| e.clone())
                    .collect();
                emit_list(&mut s, "outbound_tcp", &tcp);
                emit_list(&mut s, "outbound_udp", &udp);
            }
            OutboundMode::WildcardByPort => {
                let ports: BTreeSet<u16> = a.outbound_by_port.keys().copied().collect();
                let tcp: Vec<String> = ports.iter().map(|p| format!("*:{p}")).collect();
                emit_list(&mut s, "outbound_tcp", &tcp);
            }
        }
        if d.allow_inbound {
            s.push_str("allow_inbound = true\n");
        }
        s.push('\n');
    }

    if !a.process_execs.is_empty() {
        s.push_str("[process]\n");
        s.push_str("allow_fork = true\n");
        s.push_str("allow_exec = true\n\n");
    }

    let any_sys =
        d.allow_mach_safe || d.allow_mach_other || d.allow_sysctls || d.allow_iokit || d.allow_ipc;
    if any_sys {
        s.push_str("[system]\n");
        if d.allow_sysctls {
            s.push_str("allow_sysctl_read = true\n");
        }
        if d.allow_iokit {
            s.push_str("allow_iokit = true\n");
        }
        if d.allow_ipc {
            s.push_str("allow_ipc = true\n");
        }
        let mut mach = Vec::new();
        if d.allow_mach_safe {
            mach.extend(a.mach_safe.iter().cloned());
        }
        if d.allow_mach_other {
            mach.extend(a.mach_other.iter().cloned());
        }
        emit_list(&mut s, "mach_services", &mach);
        s.push('\n');
    }

    Ok(s)
}

fn emit_list(s: &mut String, key: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    s.push_str(key);
    s.push_str(" = [\n");
    for it in items {
        s.push_str("  \"");
        s.push_str(&toml_escape(it));
        s.push_str("\",\n");
    }
    s.push_str("]\n");
}

fn toml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn portable_home_path(p: &Path, home: Option<&Path>) -> String {
    if let Some(h) = home {
        if let Ok(rest) = p.strip_prefix(h) {
            return format!("${{HOME}}/{}", rest.display());
        }
    }
    p.to_string_lossy().into_owned()
}
