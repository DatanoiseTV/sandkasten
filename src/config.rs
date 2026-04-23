use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Known per-op tokens, cross-checked from the macOS SBPL mapper so form UIs
/// and the validator agree on the vocabulary.
pub const KNOWN_OPS: &[&str] = &[
    "read", "write", "create", "delete", "rename", "chmod", "chown",
    "xattr", "ioctl", "exec", "all", "write-all",
];

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: Option<String>,
    pub description: Option<String>,
    pub extends: Option<String>,

    #[serde(default)]
    pub filesystem: Filesystem,
    #[serde(default)]
    pub network: Network,
    #[serde(default)]
    pub process: Process,
    #[serde(default)]
    pub system: System,
    #[serde(default)]
    pub env: Env,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub mocks: Mocks,

    /// Simple cross-platform workspace — a persistent directory the sandbox
    /// sees as read+write, can `chdir` into on start, and that the user may
    /// pre-populate or inspect afterwards.
    #[serde(default)]
    pub workspace: Workspace,

    /// Linux-only: true overlayfs (copy-on-write). `lower` is the read-only
    /// base; writes land in `upper`; the merged view is mounted at `mount`.
    /// Requires an unprivileged-userns-capable kernel (5.11+).
    #[serde(default)]
    pub overlay: Overlay,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    /// Filesystem path for the workspace. Supports `~`, `${CWD}`, `${HOME}`
    /// etc. Auto-created if missing. Automatically added to `filesystem.read_write`.
    pub path: Option<String>,

    /// If true, the sandbox's initial working directory is set to the
    /// workspace path. `--cwd` on the CLI still wins.
    #[serde(default)]
    pub chdir: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Overlay {
    /// Read-only lower layer (typically the real directory to present).
    pub lower: Option<String>,
    /// Persistent writable upper layer — where writes land.
    pub upper: Option<String>,
    /// Mount point inside the sandbox's view. Defaults to `lower`, so the
    /// sandbox sees the merged union in place of the real directory.
    pub mount: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Mocks {
    /// Virtual file-name → file content map. Each entry is materialized to a
    /// private tempdir before the sandbox is applied. The tempdir's absolute
    /// path is exposed to the sandboxed process via the `SANDKASTEN_MOCKS`
    /// environment variable, so mock-aware callers (test harnesses, shims,
    /// anything that can consult an env var) can read fake content without
    /// touching the real filesystem.
    ///
    /// NOTE: this is a v1 content-sidecar mechanism. True transparent
    /// path-interposition (so a program opening `/etc/hostname` reads the
    /// mock) requires a DYLD_INSERT_LIBRARIES / LD_PRELOAD shim or a
    /// bind-mount overlay, both planned but not yet implemented.
    #[serde(default)]
    pub files: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    /// Allow stat/metadata reads on any path. Most binaries need this to function.
    #[serde(default = "default_true")]
    pub allow_metadata_read: bool,

    /// Paths the sandbox may read from (recursive).
    #[serde(default)]
    pub read: Vec<String>,

    /// Paths the sandbox may read and write (recursive).
    #[serde(default)]
    pub read_write: Vec<String>,

    /// Paths explicitly denied — evaluated after allows so they win.
    #[serde(default)]
    pub deny: Vec<String>,

    /// Single-file literals. Use for narrow allowances like `/etc/hosts`.
    #[serde(default)]
    pub read_files: Vec<String>,

    #[serde(default)]
    pub read_write_files: Vec<String>,

    /// Fine-grained per-path rules. Each rule names a path and lists the
    /// file operations to allow or deny. Operations are written last in
    /// generated SBPL, so rule denies win over broad subpath allows.
    ///
    /// Recognised ops: `read`, `write`, `create`, `delete`, `rename`, `chmod`,
    /// `chown`, `xattr`, `ioctl`, `exec`, `all`.
    #[serde(default)]
    pub rules: Vec<FileRule>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileRule {
    /// Path the rule applies to.
    pub path: String,

    /// If true, match the exact path (SBPL literal / Landlock file). If
    /// false (default), match the subtree rooted at `path`.
    #[serde(default)]
    pub literal: bool,

    /// Operations explicitly allowed on this path/subtree.
    #[serde(default)]
    pub allow: Vec<String>,

    /// Operations explicitly denied on this path/subtree. Evaluated after
    /// allows — per SBPL last-match-wins — so denies win for the same op.
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Allow outbound connections to localhost/loopback (any port unless restricted).
    #[serde(default)]
    pub allow_localhost: bool,

    /// Allow binding local ports for inbound listeners.
    #[serde(default)]
    pub allow_inbound: bool,

    /// Allow DNS resolution (UDP:53 to any host). Usually required for outbound by hostname.
    #[serde(default)]
    pub allow_dns: bool,

    /// Outbound TCP allowlist. Entries are `host:port`, `ip:port`, `*:port`, `host:*`, or `*:*`.
    /// Hosts may be hostnames or IPv4/IPv6 literals.
    #[serde(default)]
    pub outbound_tcp: Vec<String>,

    /// Outbound UDP allowlist. Same grammar as `outbound_tcp`.
    #[serde(default)]
    pub outbound_udp: Vec<String>,

    /// Inbound TCP bind allowlist. `*:port` means bind any interface on that port.
    #[serde(default)]
    pub inbound_tcp: Vec<String>,

    #[serde(default)]
    pub inbound_udp: Vec<String>,

    /// Allow ICMP (v4) — needed for ping/traceroute. On macOS, unprivileged
    /// ICMP uses SOCK_DGRAM+IPPROTO_ICMP and works without root; raw ICMP
    /// needs root. Inside a Linux user namespace the process has CAP_NET_RAW
    /// so raw ICMP is usable.
    #[serde(default)]
    pub allow_icmp: bool,

    /// Allow ICMPv6.
    #[serde(default)]
    pub allow_icmpv6: bool,

    /// Allow raw/packet sockets (AF_INET/SOCK_RAW, AF_PACKET). Highly
    /// privileged — grants packet-crafting capabilities. Default-deny.
    #[serde(default)]
    pub allow_raw_sockets: bool,

    /// Additional outbound L4 protocols to allow (e.g. "sctp"). Not every
    /// protocol is expressible in macOS's Seatbelt grammar; unsupported
    /// entries widen to a broad grant with a warning.
    #[serde(default)]
    pub extra_protocols: Vec<String>,

    /// Allow UNIX domain socket bind/connect. Many modern apps (Chromium,
    /// Electron, browsers) use UNIX sockets for inter-process coordination
    /// and fail to start without this.
    #[serde(default)]
    pub allow_unix_sockets: bool,

    /// DNS server override. On Linux the synthetic resolv.conf is bind-
    /// mounted over `/etc/resolv.conf` in the sandbox's mount namespace,
    /// so every resolver inside the sandbox uses these servers. On macOS
    /// the synthetic file is materialised into `$SANDKASTEN_MOCKS/resolv.conf`
    /// — transparent DNS swap there needs a DYLD interposer and is planned.
    #[serde(default)]
    pub dns: Dns,

    /// Additional /etc/hosts entries visible to the sandbox. Keys are
    /// hostnames, values are IPs. Applied via the same bind-mount
    /// mechanism as `dns` on Linux; materialised to
    /// `$SANDKASTEN_MOCKS/hosts` on macOS.
    #[serde(default)]
    pub hosts_entries: std::collections::BTreeMap<String, String>,

    /// Outbound IP/port redirects (Linux only). Traffic to `from` is DNAT'd
    /// to `to` inside the netns via nftables. For hostname-based redirects
    /// prefer `hosts_entries` — those work on both platforms and survive
    /// TLS SNI routing. Each entry: `from = "1.2.3.4:443"`, `to =
    /// "127.0.0.1:8443"`, optional `protocol = "tcp"|"udp"`.
    #[serde(default)]
    pub redirects: Vec<Redirect>,

    /// Outbound block list — refuse connections to matching destinations.
    /// Linux applies via nftables REJECT; macOS via SBPL `(deny …)`
    /// (limited to `localhost`/`*` hosts by the Seatbelt grammar).
    #[serde(default)]
    pub blocks: Vec<Block>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub host: String,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// Nameserver IPs, in order. Overrides host `/etc/resolv.conf` entirely.
    #[serde(default)]
    pub servers: Vec<String>,

    /// Search domains.
    #[serde(default)]
    pub search: Vec<String>,

    /// Verbatim `options` line values (e.g. `edns0`, `rotate`, `timeout:1`).
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    /// Allow `fork`/`vfork`.
    #[serde(default)]
    pub allow_fork: bool,

    /// Allow `exec` of new binaries. Children inherit the sandbox.
    #[serde(default)]
    pub allow_exec: bool,

    /// Allow signalling of sandboxed siblings/children. Signalling outside is always denied.
    #[serde(default = "default_true")]
    pub allow_signal_self: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct System {
    /// Allow reading kernel state via sysctl. Many runtimes (libc, Go, JVM) need this.
    #[serde(default = "default_true")]
    pub allow_sysctl_read: bool,

    /// macOS-only: Mach service names the sandbox may look up.
    #[serde(default)]
    pub mach_services: Vec<String>,

    /// macOS-only: allow looking up ANY Mach service. Much more compatible
    /// with complex GUI apps (browsers, Electron, Blender), but gives the
    /// sandbox access to the full Mach bus — prefer a narrow `mach_services`
    /// allowlist when you know what the target needs.
    #[serde(default)]
    pub allow_mach_all: bool,

    /// Allow the IOKit framework / /dev access (needed for GPU, terminals).
    #[serde(default)]
    pub allow_iokit: bool,

    /// Allow POSIX IPC (shared memory, semaphores).
    #[serde(default)]
    pub allow_ipc: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Maximum CPU seconds (RLIMIT_CPU). `None` = inherit.
    pub cpu_seconds: Option<u64>,

    /// Maximum address-space / virtual memory size in megabytes (RLIMIT_AS).
    /// Approximates "max resident memory" for most apps.
    pub memory_mb: Option<u64>,

    /// Maximum single-file size the sandbox may create in megabytes
    /// (RLIMIT_FSIZE).
    pub file_size_mb: Option<u64>,

    /// Maximum open file descriptors (RLIMIT_NOFILE).
    pub open_files: Option<u64>,

    /// Maximum number of processes / threads for the sandboxed user
    /// (RLIMIT_NPROC). A fork-bomb guard.
    pub processes: Option<u64>,

    /// Max stack size per thread in megabytes (RLIMIT_STACK).
    pub stack_mb: Option<u64>,

    /// Allow core dumps? Default false — set RLIMIT_CORE to 0 so the
    /// sandboxed process can't spill memory to disk on crash.
    #[serde(default)]
    pub core_dumps: bool,

    /// Wall-clock timeout in seconds. Parent process SIGTERMs the child
    /// after this; if the child doesn't exit within 3 s it is SIGKILLed.
    /// Takes effect even if the CLI `--timeout` isn't passed.
    pub wall_timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Env {
    /// If true, all parent environment variables are passed through.
    /// If false (default), only variables listed in `pass` are passed.
    #[serde(default)]
    pub pass_all: bool,

    /// Environment variable names to pass through from the parent.
    #[serde(default)]
    pub pass: Vec<String>,

    /// Environment variables set explicitly (override parent).
    #[serde(default)]
    pub set: std::collections::BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

impl Profile {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        toml::from_str(s).context("parsing profile TOML")
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("reading profile {}", path.display()))?;
        let mut p: Self = Self::from_toml_str(&s)?;
        if p.name.is_none() {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                p.name = Some(stem.to_string());
            }
        }
        Ok(p)
    }

    /// Expand `~`, `${CWD}`, `${EXE_DIR}`, `${HOME}`, and any other
    /// environment variables in every user-supplied path.
    pub fn expand_paths(&mut self, ctx: &ExpandContext) -> Result<()> {
        for v in [
            &mut self.filesystem.read,
            &mut self.filesystem.read_write,
            &mut self.filesystem.deny,
            &mut self.filesystem.read_files,
            &mut self.filesystem.read_write_files,
        ] {
            for p in v.iter_mut() {
                *p = ctx.expand(p)?;
            }
        }
        for r in &mut self.filesystem.rules {
            r.path = ctx.expand(&r.path)?;
        }
        if let Some(p) = self.workspace.path.as_deref() {
            self.workspace.path = Some(ctx.expand(p)?);
        }
        if let Some(p) = self.overlay.lower.as_deref() {
            self.overlay.lower = Some(ctx.expand(p)?);
        }
        if let Some(p) = self.overlay.upper.as_deref() {
            self.overlay.upper = Some(ctx.expand(p)?);
        }
        if let Some(p) = self.overlay.mount.as_deref() {
            self.overlay.mount = Some(ctx.expand(p)?);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(n) = &self.name {
            if n.is_empty() {
                return Err(anyhow!("profile name cannot be empty"));
            }
        }
        for p in self
            .filesystem
            .read
            .iter()
            .chain(&self.filesystem.read_write)
            .chain(&self.filesystem.deny)
        {
            if !Path::new(p).is_absolute() {
                return Err(anyhow!("filesystem paths must be absolute, got: {p}"));
            }
        }
        for rule in &self.filesystem.rules {
            if !Path::new(&rule.path).is_absolute() {
                return Err(anyhow!(
                    "filesystem.rules[].path must be absolute, got: {}",
                    rule.path
                ));
            }
            for op in rule.allow.iter().chain(rule.deny.iter()) {
                if !KNOWN_OPS.contains(&op.to_ascii_lowercase().as_str()) {
                    return Err(anyhow!(
                        "unknown file operation {op:?} in rule for {}; known ops: {}",
                        rule.path,
                        KNOWN_OPS.join(", ")
                    ));
                }
            }
        }
        for endpoint in self
            .network
            .outbound_tcp
            .iter()
            .chain(&self.network.outbound_udp)
            .chain(&self.network.inbound_tcp)
            .chain(&self.network.inbound_udp)
        {
            parse_endpoint(endpoint)
                .with_context(|| format!("invalid network endpoint: {endpoint}"))?;
        }
        Ok(())
    }

    /// Merge a child profile over a parent (child wins on scalars, lists concatenate).
    pub fn merge_over(mut self, parent: Profile) -> Profile {
        let mut out = parent;
        out.name = self.name.take().or(out.name);
        out.description = self.description.take().or(out.description);
        out.extends = None;

        // Filesystem — concat lists, child scalars win
        out.filesystem.allow_metadata_read = self.filesystem.allow_metadata_read
            || out.filesystem.allow_metadata_read;
        extend(&mut out.filesystem.read, self.filesystem.read);
        extend(&mut out.filesystem.read_write, self.filesystem.read_write);
        extend(&mut out.filesystem.deny, self.filesystem.deny);
        extend(&mut out.filesystem.read_files, self.filesystem.read_files);
        extend(
            &mut out.filesystem.read_write_files,
            self.filesystem.read_write_files,
        );
        // Child rules go AFTER parent rules so that their last-match-wins
        // behaviour in SBPL still applies correctly.
        out.filesystem.rules.extend(self.filesystem.rules);

        // Network
        out.network.allow_localhost |= self.network.allow_localhost;
        out.network.allow_inbound |= self.network.allow_inbound;
        out.network.allow_dns |= self.network.allow_dns;
        extend(&mut out.network.outbound_tcp, self.network.outbound_tcp);
        extend(&mut out.network.outbound_udp, self.network.outbound_udp);
        extend(&mut out.network.inbound_tcp, self.network.inbound_tcp);
        extend(&mut out.network.inbound_udp, self.network.inbound_udp);
        out.network.allow_icmp |= self.network.allow_icmp;
        out.network.allow_icmpv6 |= self.network.allow_icmpv6;
        out.network.allow_raw_sockets |= self.network.allow_raw_sockets;
        out.network.allow_unix_sockets |= self.network.allow_unix_sockets;
        extend(&mut out.network.extra_protocols, self.network.extra_protocols);
        // DNS & hosts: child wins on any set value, otherwise inherit.
        if !self.network.dns.servers.is_empty() {
            out.network.dns.servers = self.network.dns.servers;
        }
        if !self.network.dns.search.is_empty() {
            out.network.dns.search = self.network.dns.search;
        }
        if !self.network.dns.options.is_empty() {
            out.network.dns.options = self.network.dns.options;
        }
        for (k, v) in self.network.hosts_entries {
            out.network.hosts_entries.insert(k, v);
        }
        out.network.redirects.extend(self.network.redirects);
        out.network.blocks.extend(self.network.blocks);

        // Process: allows are additive — either parent or child granting
        // the permission results in it being granted. Templates can only
        // loosen, never silently tighten, their parents.
        out.process.allow_fork |= self.process.allow_fork;
        out.process.allow_exec |= self.process.allow_exec;
        out.process.allow_signal_self |= self.process.allow_signal_self;

        // System
        out.system.allow_sysctl_read |= self.system.allow_sysctl_read;
        extend(&mut out.system.mach_services, self.system.mach_services);
        out.system.allow_mach_all |= self.system.allow_mach_all;
        out.system.allow_iokit |= self.system.allow_iokit;
        out.system.allow_ipc |= self.system.allow_ipc;

        // Env
        out.env.pass_all |= self.env.pass_all;
        extend(&mut out.env.pass, self.env.pass);
        out.env.set.extend(self.env.set);

        // Mocks: child overrides parent on key collision.
        for (k, v) in self.mocks.files {
            out.mocks.files.insert(k, v);
        }

        // Workspace & overlay: child scalars win when set.
        if self.workspace.path.is_some() {
            out.workspace.path = self.workspace.path;
        }
        if self.workspace.chdir {
            out.workspace.chdir = true;
        }
        if self.overlay.lower.is_some() {
            out.overlay.lower = self.overlay.lower;
        }
        if self.overlay.upper.is_some() {
            out.overlay.upper = self.overlay.upper;
        }
        if self.overlay.mount.is_some() {
            out.overlay.mount = self.overlay.mount;
        }

        // Limits — child's scalar wins for each field. `min` semantics
        // would be safer, but users explicitly extending a parent usually
        // want to raise limits, and they can always narrow manually.
        out.limits.cpu_seconds = self.limits.cpu_seconds.or(out.limits.cpu_seconds);
        out.limits.memory_mb = self.limits.memory_mb.or(out.limits.memory_mb);
        out.limits.file_size_mb = self.limits.file_size_mb.or(out.limits.file_size_mb);
        out.limits.open_files = self.limits.open_files.or(out.limits.open_files);
        out.limits.processes = self.limits.processes.or(out.limits.processes);
        out.limits.stack_mb = self.limits.stack_mb.or(out.limits.stack_mb);
        out.limits.core_dumps |= self.limits.core_dumps;
        out.limits.wall_timeout_seconds = self
            .limits
            .wall_timeout_seconds
            .or(out.limits.wall_timeout_seconds);

        out
    }
}

fn extend<T: PartialEq>(dst: &mut Vec<T>, src: Vec<T>) {
    for v in src {
        if !dst.contains(&v) {
            dst.push(v);
        }
    }
}

/// Runtime context for expanding `${CWD}`, `${EXE_DIR}`, `${HOME}`, `~`, and
/// other environment variables in user-supplied path strings.
pub struct ExpandContext {
    pub cwd: PathBuf,
    pub exe_dir: Option<PathBuf>,
    pub home: Option<PathBuf>,
}

impl ExpandContext {
    pub fn detect(argv0: Option<&str>) -> Result<Self> {
        let cwd = std::env::current_dir().context("getting current working directory")?;
        let home = dirs::home_dir();
        let exe_dir = argv0.and_then(Self::resolve_exe_dir);
        Ok(Self { cwd, exe_dir, home })
    }

    fn resolve_exe_dir(prog: &str) -> Option<PathBuf> {
        let p = Path::new(prog);
        let abs = if p.is_absolute() {
            p.to_path_buf()
        } else if prog.contains('/') {
            std::env::current_dir().ok()?.join(p)
        } else {
            // PATH lookup
            let path_env = std::env::var_os("PATH")?;
            let mut found = None;
            for dir in std::env::split_paths(&path_env) {
                let candidate = dir.join(p);
                if candidate.is_file() {
                    found = Some(candidate);
                    break;
                }
            }
            found?
        };
        let canonical = std::fs::canonicalize(&abs).unwrap_or(abs);
        canonical.parent().map(|x| x.to_path_buf())
    }

    fn lookup(&self, var: &str) -> Option<String> {
        match var {
            "CWD" => Some(self.cwd.to_string_lossy().into_owned()),
            "EXE_DIR" => self
                .exe_dir
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            "HOME" => self.home.as_ref().map(|p| p.to_string_lossy().into_owned()),
            other => std::env::var(other).ok(),
        }
    }

    pub fn expand(&self, s: &str) -> Result<String> {
        // Tilde at start → HOME.
        let s = if let Some(rest) = s.strip_prefix('~') {
            if rest.is_empty() || rest.starts_with('/') {
                let home = self
                    .home
                    .as_ref()
                    .ok_or_else(|| anyhow!("~ used but HOME is unknown"))?;
                format!("{}{}", home.display(), rest)
            } else {
                // `~user` — not supported; pass through literally.
                s.to_string()
            }
        } else {
            s.to_string()
        };

        // ${VAR} and $VAR substitution.
        let mut out = String::with_capacity(s.len());
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'$' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                    let end = bytes[i + 2..]
                        .iter()
                        .position(|&b| b == b'}')
                        .ok_or_else(|| anyhow!("unterminated ${{...}} in {s:?}"))?;
                    let name = &s[i + 2..i + 2 + end];
                    let val = self
                        .lookup(name)
                        .ok_or_else(|| anyhow!("undefined variable ${{{name}}} in path"))?;
                    out.push_str(&val);
                    i += 2 + end + 1;
                    continue;
                } else if i + 1 < bytes.len() && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_') {
                    let mut j = i + 1;
                    while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                        j += 1;
                    }
                    let name = &s[i + 1..j];
                    let val = self
                        .lookup(name)
                        .ok_or_else(|| anyhow!("undefined variable ${name} in path"))?;
                    out.push_str(&val);
                    i = j;
                    continue;
                }
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        Ok(out)
    }
}

/// A parsed host:port. Host is "*" for wildcard, otherwise a hostname or IP literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: HostSpec,
    pub port: PortSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSpec {
    Any,
    Name(String),
    Ipv4(std::net::Ipv4Addr),
    Ipv6(std::net::Ipv6Addr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSpec {
    Any,
    Num(u16),
}

pub fn parse_endpoint(s: &str) -> Result<Endpoint> {
    // Handle IPv6 bracketed form `[::1]:443`
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| anyhow!("missing ']' in {s}"))?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("missing port in {s}"))?;
        (host, port)
    } else {
        let i = s
            .rfind(':')
            .ok_or_else(|| anyhow!("endpoint must be host:port, got {s}"))?;
        (&s[..i], &s[i + 1..])
    };

    let host = if host == "*" {
        HostSpec::Any
    } else if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        HostSpec::Ipv4(v4)
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        HostSpec::Ipv6(v6)
    } else {
        // Reject obviously invalid hostnames.
        if host.is_empty() || host.contains(char::is_whitespace) {
            return Err(anyhow!("invalid hostname: {host:?}"));
        }
        HostSpec::Name(host.to_string())
    };

    let port = if port == "*" {
        PortSpec::Any
    } else {
        PortSpec::Num(port.parse().context("invalid port number")?)
    };

    Ok(Endpoint { host, port })
}

/// Resolve a profile reference into a path:
///   1. exact path if contains `/` or ends in `.toml`
///   2. `$PWD/<name>.toml`
///   3. `$XDG_CONFIG_HOME/sandkasten/profiles/<name>.toml`
pub fn resolve_profile_path(name: &str) -> Result<PathBuf> {
    if name.contains('/') || name.ends_with(".toml") {
        let p = PathBuf::from(name);
        if p.exists() {
            return Ok(p);
        }
        return Err(anyhow!("profile file not found: {}", p.display()));
    }

    let here = PathBuf::from(format!("{name}.toml"));
    if here.exists() {
        return Ok(here);
    }

    if let Some(conf) = dirs::config_dir() {
        let p = conf.join("sandkasten").join("profiles").join(format!("{name}.toml"));
        if p.exists() {
            return Ok(p);
        }
    }

    Err(anyhow!(
        "profile {name:?} not found (looked in ./, $XDG_CONFIG_HOME/sandkasten/profiles/). \
         Use `sandkasten templates` to see built-ins."
    ))
}

/// Load a profile by name, applying template inheritance. Paths are NOT yet
/// expanded; caller must apply `expand_paths(&ctx)` with a runtime context
/// before validating.
pub fn load(name: &str) -> Result<Profile> {
    if let Some(tpl) = crate::templates::builtin(name) {
        let mut p = Profile::from_toml_str(tpl)?;
        if p.name.is_none() {
            p.name = Some(name.to_string());
        }
        return merge_parents(p);
    }

    let path = resolve_profile_path(name)?;
    let p = Profile::from_file(&path)?;
    merge_parents(p)
}

fn merge_parents(mut p: Profile) -> Result<Profile> {
    if let Some(parent_name) = p.extends.clone() {
        let parent = load(&parent_name)?;
        p = p.merge_over(parent);
    }
    Ok(p)
}

/// Finalize a profile: expand path variables using `ctx`, then validate.
pub fn finalize(mut p: Profile, ctx: &ExpandContext) -> Result<Profile> {
    p.expand_paths(ctx)?;
    p.validate()?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ExpandContext {
        ExpandContext {
            cwd: PathBuf::from("/work/project"),
            exe_dir: Some(PathBuf::from("/opt/tool/bin")),
            home: Some(PathBuf::from("/home/alice")),
        }
    }

    #[test]
    fn expand_cwd_exe_home() {
        let c = ctx();
        assert_eq!(c.expand("${CWD}/data").unwrap(), "/work/project/data");
        assert_eq!(c.expand("${EXE_DIR}").unwrap(), "/opt/tool/bin");
        assert_eq!(c.expand("${HOME}/.cache").unwrap(), "/home/alice/.cache");
        assert_eq!(c.expand("~/logs").unwrap(), "/home/alice/logs");
    }

    #[test]
    fn undefined_var_errors() {
        assert!(ctx().expand("${NOPE_DOES_NOT_EXIST}").is_err());
    }

    #[test]
    fn parse_endpoint_ipv4_ipv6_wildcard() {
        let e = parse_endpoint("192.168.0.1:443").unwrap();
        assert!(matches!(e.host, HostSpec::Ipv4(_)));
        assert_eq!(e.port, PortSpec::Num(443));

        let e = parse_endpoint("[::1]:8080").unwrap();
        assert!(matches!(e.host, HostSpec::Ipv6(_)));
        assert_eq!(e.port, PortSpec::Num(8080));

        let e = parse_endpoint("*:443").unwrap();
        assert_eq!(e.host, HostSpec::Any);
        assert_eq!(e.port, PortSpec::Num(443));

        let e = parse_endpoint("example.com:*").unwrap();
        assert_eq!(e.host, HostSpec::Name("example.com".into()));
        assert_eq!(e.port, PortSpec::Any);
    }

    #[test]
    fn rejects_non_absolute_fs_paths() {
        let mut p = Profile::default();
        p.filesystem.read = vec!["relative/path".into()];
        assert!(p.validate().is_err());
    }

    #[test]
    fn merge_over_concatenates_lists_preserving_uniqueness() {
        let parent = Profile {
            filesystem: Filesystem {
                read: vec!["/a".into(), "/b".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let child = Profile {
            filesystem: Filesystem {
                read: vec!["/b".into(), "/c".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = child.merge_over(parent);
        assert_eq!(merged.filesystem.read, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn self_template_expands_cwd_at_runtime() {
        let raw = Profile::from_toml_str(crate::templates::SELF).unwrap();
        let raw = merge_parents(raw).unwrap();
        let p = finalize(raw, &ctx()).unwrap();
        assert!(p
            .filesystem
            .read_write
            .iter()
            .any(|s| s == "/work/project"));
    }
}
