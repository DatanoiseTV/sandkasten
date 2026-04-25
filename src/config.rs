use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Known per-op tokens, cross-checked from the macOS SBPL mapper so form UIs
/// and the validator agree on the vocabulary.
pub const KNOWN_OPS: &[&str] = &[
    "read",
    "write",
    "create",
    "delete",
    "rename",
    "chmod",
    "chown",
    "xattr",
    "ioctl",
    "exec",
    "all",
    "write-all",
];

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: Option<String>,
    pub description: Option<String>,
    pub extends: Option<String>,

    /// Reset specific parent-inherited fields before merging this
    /// child on top. By default, `extends` UNIONs lists and ORs
    /// boolean allow-flags, so a child can only widen — never narrow
    /// — its parent. `clear` lets a child say "throw out the parent's
    /// value of this field, treat it as if I'm starting from default
    /// for this one knob".
    ///
    /// Field paths are dotted, e.g.:
    /// ```toml
    /// clear = [
    ///   "network.outbound_tcp",
    ///   "network.allow_dns",
    ///   "filesystem.read",
    /// ]
    /// ```
    ///
    /// Listing a path that doesn't match a known field is a hard
    /// error so typos surface at load time, not at run time.
    ///
    /// See `KNOWN_CLEAR_PATHS` for the supported set.
    #[serde(default)]
    pub clear: Vec<String>,

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

    /// Hardware access: USB, serial, PTY, audio, GPU. Auto-expands into the
    /// right FS paths and Mach services at profile-load time.
    #[serde(default)]
    pub hardware: Hardware,

    /// Hardware identity spoofing: CPU count, /proc/cpuinfo, DMI fields,
    /// machine-id, hostname. Linux implements via sched_setaffinity +
    /// bind-mounted synthetic files; macOS implements what the kernel
    /// permits (hostname via UTS-equivalent) and documents the rest.
    #[serde(default)]
    pub spoof: Spoof,

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
pub struct Spoof {
    /// Limit the sandbox to N logical cores via `sched_setaffinity` (Linux).
    /// `sysconf(_SC_NPROCESSORS_ONLN)` and everything derived from it (Go's
    /// GOMAXPROCS default, Rust's `num_cpus`, most thread pools) will see
    /// this count. `/proc/cpuinfo` still shows all cores — use
    /// `cpuinfo_synth = true` to also bind-mount a synthetic file.
    pub cpu_count: Option<u32>,

    /// If true, generate a synthetic `/proc/cpuinfo` reflecting
    /// `cpu_count` + the `cpuinfo_*` fields, and bind-mount it in the
    /// sandbox's mount namespace. Linux only.
    #[serde(default)]
    pub cpuinfo_synth: bool,

    /// Override the CPU model string in the synthetic /proc/cpuinfo.
    pub cpuinfo_model: Option<String>,

    /// Override the reported MHz per core.
    pub cpuinfo_mhz: Option<u32>,

    /// Hostname the sandbox sees. Linux: set via sethostname in our UTS
    /// namespace (overrides the default `sandkasten`). macOS: set via the
    /// `HOSTNAME` env var only — `hostname` syscall spoofing requires root.
    pub hostname: Option<String>,

    /// Spoof `/etc/machine-id` (32 hex chars, conventionally without dashes).
    pub machine_id: Option<String>,

    /// Linux DMI overrides — each field maps to a file under
    /// `/sys/class/dmi/id/`. Common keys: `product_name`, `product_serial`,
    /// `product_uuid`, `sys_vendor`, `board_name`, `board_serial`,
    /// `bios_vendor`, `bios_version`, `chassis_serial`.
    #[serde(default)]
    pub dmi: std::collections::BTreeMap<String, String>,

    /// Arbitrary synthetic file mounts (Linux). Each entry names an absolute
    /// target path (must already exist in the sandbox's view) and inline
    /// content. Used for UEFI variables, thermal zones, battery state,
    /// anything surfaced through `/sys` or `/proc`.
    #[serde(default)]
    pub files: Vec<SpoofFile>,

    /// Convenience: set every `/sys/class/thermal/thermal_zone*/temp` and
    /// `/sys/class/hwmon/hwmon*/temp*_input` entry the sandbox's host
    /// exposes to this value (degrees Celsius ×1000 is written into the
    /// sysfs format). Linux only.
    pub temperature_c: Option<i32>,

    /// Convenience: override UEFI firmware platform size (32/64).
    pub efi_platform_size: Option<u32>,

    /// Convenience: say whether the firmware is EFI at all (true/false).
    /// When false, /sys/firmware/efi is hidden via an empty bind-mount.
    pub efi_enabled: Option<bool>,

    /// Override the contents of `/proc/version` (kernel version string
    /// reported by `uname -v` implementations that read this file, and
    /// by any tool that opens it).
    pub kernel_version: Option<String>,

    /// Override `/proc/sys/kernel/osrelease` (the release version string).
    pub kernel_release: Option<String>,

    /// Override the contents of `/etc/os-release` — distribution identity.
    pub os_release: Option<String>,

    /// Override `/etc/issue` (pre-login banner).
    pub issue: Option<String>,

    /// Override `/etc/hostid` (8-byte binary file). Value is parsed as a
    /// 32-bit hex integer and written as little-endian bytes.
    pub hostid_hex: Option<String>,

    /// Override `/etc/timezone` (Debian-family zone file).
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpoofFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hardware {
    /// libusb / raw USB: reads+writes on `/dev/bus/usb/*` (Linux) or IOKit +
    /// USB Mach services (macOS).
    #[serde(default)]
    pub usb: bool,
    /// Serial ports (`/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/tty.usbserial*`, etc.).
    #[serde(default)]
    pub serial: bool,
    /// Audio: ALSA/PulseAudio on Linux, CoreAudio Mach services on macOS.
    #[serde(default)]
    pub audio: bool,
    /// GPU / DRM / Metal. Still requires platform-specific sandbox settings.
    #[serde(default)]
    pub gpu: bool,
    /// Camera / webcam / V4L2.
    #[serde(default)]
    pub camera: bool,

    /// Screen capture / recording. macOS: adds ScreenCaptureKit and
    /// CoreGraphics Mach services + TCC grant path. Linux: adds /dev/dri
    /// for GPU-accelerated capture (PipeWire screencast works with
    /// [hardware].audio + gpu + camera together).
    #[serde(default)]
    pub screen_capture: bool,

    /// Fine-grained video-device controls. Expands into `[[filesystem.rewire]]`
    /// + `[[filesystem.hide]]` entries at profile-load time.
    #[serde(default)]
    pub video: Video,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Video {
    /// Allowlist of video device nodes visible to the sandbox. Any
    /// `/dev/video*` / `/dev/media*` NOT in this list is hidden via
    /// `filesystem.hide`. Empty → no whitelisting.
    #[serde(default)]
    pub devices: Vec<String>,

    /// Camera redirects: map of "path the sandbox sees" → "path on host".
    /// E.g. `{ "/dev/video0" = "/dev/video5" }` makes /dev/video0 inside
    /// the sandbox resolve to the host's /dev/video5 (a v4l2loopback
    /// device fed by another process, for instance). Linux only.
    #[serde(default)]
    pub redirect: std::collections::BTreeMap<String, String>,
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

    /// Rewire paths so that inside the sandbox, `from` actually points to
    /// `to`. Linux: bind-mount `to` over `from` inside the mount namespace.
    /// macOS: not supported without an interposer — the rewire list is
    /// ignored with a warning.
    #[serde(default)]
    pub rewire: Vec<Rewire>,

    /// Hide paths so callers see them as empty / non-existent rather than
    /// getting EPERM on access. Useful when a target app probes for config
    /// files and crashes on "permission denied" but handles "not found".
    /// Linux: bind-mounts an empty tmpfs over directories and `/dev/null`
    /// over files. macOS: emits SBPL denies (still returns EPERM) and
    /// warns.
    #[serde(default)]
    pub hide: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rewire {
    pub from: String,
    pub to: String,
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

    /// Allow SCTP (Stream Control Transmission Protocol).
    #[serde(default)]
    pub allow_sctp: bool,

    /// Allow DCCP (Datagram Congestion Control Protocol).
    #[serde(default)]
    pub allow_dccp: bool,

    /// Allow UDP-Lite.
    #[serde(default)]
    pub allow_udplite: bool,

    /// Escape hatch for additional outbound L4 protocols by name. Not every
    /// protocol is expressible in macOS's Seatbelt grammar; unsupported
    /// entries widen to a broad `remote ip` grant with a warning.
    #[serde(default)]
    pub extra_protocols: Vec<String>,

    /// Allow UNIX domain socket bind/connect. Many modern apps (Chromium,
    /// Electron, browsers) use UNIX sockets for inter-process coordination
    /// and fail to start without this.
    #[serde(default)]
    pub allow_unix_sockets: bool,

    /// Named protocol/service presets that expand into concrete TCP/UDP
    /// rules at profile-load time. Known tokens:
    ///   http, https, quic, ssh, ntp, mdns, rtp, sip, stun, webrtc, ldap,
    ///   ldaps, smtp, smtps, imap, imaps, pop3, pop3s, ftp, ftps, irc,
    ///   ircs, mysql, postgres, redis, memcached, mongodb, git.
    #[serde(default)]
    pub presets: Vec<String>,

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

    /// External network integration (Linux only). Values:
    ///   * `none` (default) — sandkasten unshares a private netns; outbound
    ///     requires bringing your own plumbing.
    ///   * `host` — skip the netns unshare entirely; the sandbox shares the
    ///     host's network stack. Landlock + seccomp still apply.
    ///   * `pasta` — sentinel; same effect as `none` today but enables a
    ///     documented wrapper pattern where the user invokes sandkasten
    ///     via `pasta --config-net --ns-user <sk-bin> …`.
    pub external: Option<String>,

    /// Join an existing network namespace instead of creating a new one.
    /// Path must be a netns file descriptor — typically
    /// `/run/netns/<name>` created by `ip netns add <name>`, or
    /// `/proc/<pid>/ns/net` for an existing process's netns. Linux only.
    ///
    /// Pattern for routing sandboxed traffic through a VPN:
    ///   `ip netns add vpn`
    ///   `ip netns exec vpn wg-quick up wg0`    # or openvpn, etc.
    ///   Then set `netns_path = "/run/netns/vpn"` in the profile.
    /// Every outbound connection from the sandbox follows the VPN's routes.
    pub netns_path: Option<String>,

    /// Force the sandbox through an outbound HTTP(S) proxy. Sets
    /// `HTTP_PROXY` / `HTTPS_PROXY` / `http_proxy` / `https_proxy` /
    /// `ALL_PROXY` / `NO_PROXY` env vars, and optionally restricts
    /// `outbound_tcp` to only the proxy's `host:port` when the existing
    /// list is empty. Use with a user-provided MITM proxy
    /// (mitmproxy / squid / custom) to enforce HTTP method + URL rules.
    /// Kernel-level L7 filtering is out of scope for a sandbox.
    #[serde(default)]
    pub proxy: Proxy,

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
pub struct Proxy {
    /// Proxy URL — e.g. `http://127.0.0.1:8080` or
    /// `socks5://127.0.0.1:1080`. Empty = disabled.
    pub url: Option<String>,

    /// Hosts / CIDRs the sandbox is allowed to reach directly (not via
    /// the proxy). Rendered into `NO_PROXY`.
    #[serde(default)]
    pub bypass: Vec<String>,

    /// If true (default), automatically extract host:port from `url`
    /// and add it to `outbound_tcp` — so no other destinations can be
    /// reached without going through the proxy.
    #[serde(default = "default_true")]
    pub restrict_outbound: bool,
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

    /// Block exec of classic privilege-elevation binaries (sudo, su, doas,
    /// pkexec, etc.) from inside the sandbox. Useful as a guardrail against
    /// users who have `NOPASSWD: ALL` sudoers entries or similar: even a
    /// compromised tool running in the sandbox can't re-exec through sudo
    /// to regain root on the host. Defense-in-depth; namespaces on Linux
    /// already neuter privilege elevation for the sandboxed process, but
    /// denying the exec outright prevents social-engineering-style abuse
    /// (e.g. a script that calls sudo and expects the host's cached creds).
    /// Implies `block_setid_syscalls`.
    #[serde(default)]
    pub block_privilege_elevation: bool,

    /// Block the setuid-family syscalls (`setuid`, `setgid`, `setreuid`,
    /// `setregid`, `setresuid`, `setresgid`, `setfsuid`, `setfsgid`,
    /// `setgroups`) via seccomp on Linux. Defense against shellcode that
    /// tries to drop or gain privileges directly without going through a
    /// named elevation binary.
    ///
    /// On Linux the `CLONE_NEWUSER` boundary already prevents real host
    /// privilege changes, but blocking these outright also stops tools
    /// from silently "succeeding" into an inner-namespace root mapping
    /// that confuses downstream callers (e.g. `sudo` printing
    /// `root@...#` and giving a root-looking shell inside the userns).
    ///
    /// macOS: no direct Seatbelt equivalent, so this flag is a Linux-only
    /// defence. The SBPL policy on macOS already refuses to honour setuid
    /// bits for sandboxed processes at the kernel MAC layer.
    #[serde(default)]
    pub block_setid_syscalls: bool,

    /// Memory W^X: forbid mprotect(..., PROT_EXEC) on any page that was
    /// ever writable, via `prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN)`
    /// (Linux 6.3+). Blocks the entire "write shellcode, flip to
    /// executable, jump to it" class of memory corruption exploits.
    ///
    /// **Breaks legitimate JIT compilers** (V8, SpiderMonkey, LuaJIT,
    /// Java HotSpot, PHP JIT, many Pythons with Cython-JIT) — so it's
    /// opt-in. Safe for shells, CLI utilities, compiled static binaries,
    /// and anything that doesn't call `mprotect(...PROT_EXEC)` on its
    /// own anonymous mappings.
    #[serde(default)]
    pub no_w_x: bool,

    /// Disable indirect branch speculation and speculative store bypass
    /// for the sandboxed process only, via
    /// `prctl(PR_SET_SPECULATION_CTRL, ..., PR_SPEC_FORCE_DISABLE)` for
    /// both `PR_SPEC_INDIRECT_BRANCH` (Spectre v2) and
    /// `PR_SPEC_STORE_BYPASS` (Spectre v4 / SSBD). Mitigates speculative
    /// execution side-channel attacks reachable from inside the sandbox.
    ///
    /// Costs ~2-5% CPU on branch-heavy workloads, so it's opt-in. No
    /// functional breakage — just slower.
    #[serde(default)]
    pub mitigate_spectre: bool,
}

impl Process {
    /// Whether the setid-family seccomp filter should be installed.
    /// Either a direct request or an implication of
    /// [`Process::block_privilege_elevation`]. Currently only consulted
    /// by the Linux seccomp backend; macOS has no direct Seatbelt
    /// equivalent.
    #[allow(dead_code)] // used only by src/linux/seccomp_filter.rs
    pub fn blocks_setid(&self) -> bool {
        self.block_setid_syscalls || self.block_privilege_elevation
    }
}

/// Canonical path list for [`Process::block_privilege_elevation`].
///
/// Includes both macOS system locations (`/usr/bin/...`) and the common
/// extra-install paths: Homebrew on macOS/arm, Intel Homebrew, user-local
/// builds, Linux package-manager paths, Snap, and Linuxbrew. Expand with
/// care — every entry here becomes a `deny process-exec` on macOS (and
/// matters only if the binary exists, so extras are free defense).
#[allow(dead_code)] // consumed only by the macOS SBPL generator today
pub const PRIVILEGE_ELEVATION_BINARIES: &[&str] = &[
    // Standard *nix system paths — present on both macOS (as Apple
    // binaries) and on every Linux distro.
    "/usr/bin/sudo",
    "/usr/bin/sudoedit",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/doas",
    "/usr/bin/pkexec",
    "/usr/bin/runuser",
    "/usr/sbin/visudo",
    "/usr/libexec/doas",
    // Locally-compiled installs on both platforms.
    "/usr/local/bin/sudo",
    "/usr/local/bin/doas",
    "/usr/local/bin/su",
    // Package-manager installs.
    "/opt/homebrew/bin/sudo", // Homebrew on Apple Silicon
    "/opt/homebrew/bin/doas",
    "/home/linuxbrew/.linuxbrew/bin/sudo", // Linuxbrew on Linux
    "/home/linuxbrew/.linuxbrew/bin/doas",
    "/snap/bin/sudo", // Ubuntu Snap
];

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
            expand_globs_in_place(v);
        }
        for r in &mut self.filesystem.rules {
            r.path = ctx.expand(&r.path)?;
        }
        for r in &mut self.filesystem.rewire {
            r.from = ctx.expand(&r.from)?;
            r.to = ctx.expand(&r.to)?;
        }
        for p in &mut self.filesystem.hide {
            *p = ctx.expand(p)?;
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
    ///
    /// If the child specifies any paths in its `clear` list, those
    /// fields on the parent are reset to default BEFORE the child's
    /// values are merged in. That's the only way a child can narrow
    /// a parent's allow-set; without it, every list and bool flag
    /// on the parent stays sticky.
    pub fn merge_over(mut self, parent: Profile) -> Profile {
        let mut out = parent;
        for path in &self.clear {
            clear_field(&mut out, path);
        }
        out.name = self.name.take().or(out.name);
        out.description = self.description.take().or(out.description);
        out.extends = None;
        out.clear = Vec::new();

        // Filesystem — concat lists, child scalars win
        out.filesystem.allow_metadata_read =
            self.filesystem.allow_metadata_read || out.filesystem.allow_metadata_read;
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
        out.filesystem.rewire.extend(self.filesystem.rewire);
        extend(&mut out.filesystem.hide, self.filesystem.hide);

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
        out.network.allow_sctp |= self.network.allow_sctp;
        out.network.allow_dccp |= self.network.allow_dccp;
        out.network.allow_udplite |= self.network.allow_udplite;
        out.network.allow_raw_sockets |= self.network.allow_raw_sockets;
        out.network.allow_unix_sockets |= self.network.allow_unix_sockets;
        extend(
            &mut out.network.extra_protocols,
            self.network.extra_protocols,
        );
        extend(&mut out.network.presets, self.network.presets);
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
        // External / netns integration.
        if self.network.external.is_some() {
            out.network.external = self.network.external;
        }
        if self.network.netns_path.is_some() {
            out.network.netns_path = self.network.netns_path;
        }

        // Proxy settings: child scalars win.
        if self.network.proxy.url.is_some() {
            out.network.proxy.url = self.network.proxy.url;
        }
        extend(&mut out.network.proxy.bypass, self.network.proxy.bypass);
        // Child wins unconditionally — the parent's Default::default() for
        // Proxy gives `false` for restrict_outbound regardless of serde's
        // `default_true` attribute, so AND-merging would defeat the user's
        // explicit value.
        out.network.proxy.restrict_outbound = self.network.proxy.restrict_outbound;

        // Process: allows are additive — either parent or child granting
        // the permission results in it being granted. Templates can only
        // loosen, never silently tighten, their parents.
        out.process.allow_fork |= self.process.allow_fork;
        out.process.allow_exec |= self.process.allow_exec;
        out.process.allow_signal_self |= self.process.allow_signal_self;
        // block_* fields OR together so once any layer blocks it, the merged
        // result blocks it (more-restrictive wins for security toggles).
        out.process.block_privilege_elevation |= self.process.block_privilege_elevation;
        out.process.block_setid_syscalls |= self.process.block_setid_syscalls;
        out.process.no_w_x |= self.process.no_w_x;
        out.process.mitigate_spectre |= self.process.mitigate_spectre;

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

        // Hardware flags: additive.
        out.hardware.usb |= self.hardware.usb;
        out.hardware.serial |= self.hardware.serial;
        out.hardware.audio |= self.hardware.audio;
        out.hardware.gpu |= self.hardware.gpu;
        out.hardware.camera |= self.hardware.camera;
        out.hardware.screen_capture |= self.hardware.screen_capture;
        extend(&mut out.hardware.video.devices, self.hardware.video.devices);
        for (k, v) in self.hardware.video.redirect {
            out.hardware.video.redirect.insert(k, v);
        }

        // Spoof: child scalar wins where set.
        out.spoof.cpu_count = self.spoof.cpu_count.or(out.spoof.cpu_count);
        out.spoof.cpuinfo_synth |= self.spoof.cpuinfo_synth;
        out.spoof.cpuinfo_model = self.spoof.cpuinfo_model.or(out.spoof.cpuinfo_model);
        out.spoof.cpuinfo_mhz = self.spoof.cpuinfo_mhz.or(out.spoof.cpuinfo_mhz);
        out.spoof.hostname = self.spoof.hostname.or(out.spoof.hostname);
        out.spoof.machine_id = self.spoof.machine_id.or(out.spoof.machine_id);
        for (k, v) in self.spoof.dmi {
            out.spoof.dmi.insert(k, v);
        }
        out.spoof.files.extend(self.spoof.files);
        out.spoof.temperature_c = self.spoof.temperature_c.or(out.spoof.temperature_c);
        out.spoof.efi_platform_size = self.spoof.efi_platform_size.or(out.spoof.efi_platform_size);
        out.spoof.efi_enabled = self.spoof.efi_enabled.or(out.spoof.efi_enabled);
        out.spoof.kernel_version = self.spoof.kernel_version.or(out.spoof.kernel_version);
        out.spoof.kernel_release = self.spoof.kernel_release.or(out.spoof.kernel_release);
        out.spoof.os_release = self.spoof.os_release.or(out.spoof.os_release);
        out.spoof.issue = self.spoof.issue.or(out.spoof.issue);
        out.spoof.hostid_hex = self.spoof.hostid_hex.or(out.spoof.hostid_hex);
        out.spoof.timezone = self.spoof.timezone.or(out.spoof.timezone);

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

/// Reset one field on `p` to the type's default. Called from
/// `merge_over` for each entry in the child's `clear` list, BEFORE
/// the child's own values are folded in. Unknown paths are a no-op
/// at this layer — typo-validation runs earlier in `validate_clear`.
fn clear_field(p: &mut Profile, path: &str) {
    match path {
        // ── filesystem ──
        "filesystem.read"             => p.filesystem.read.clear(),
        "filesystem.read_write"       => p.filesystem.read_write.clear(),
        "filesystem.deny"             => p.filesystem.deny.clear(),
        "filesystem.read_files"       => p.filesystem.read_files.clear(),
        "filesystem.read_write_files" => p.filesystem.read_write_files.clear(),
        "filesystem.hide"             => p.filesystem.hide.clear(),
        "filesystem.rules"            => p.filesystem.rules.clear(),
        "filesystem.allow_metadata_read" => p.filesystem.allow_metadata_read = false,
        // ── network ──
        "network.outbound_tcp"      => p.network.outbound_tcp.clear(),
        "network.outbound_udp"      => p.network.outbound_udp.clear(),
        "network.inbound_tcp"       => p.network.inbound_tcp.clear(),
        "network.inbound_udp"       => p.network.inbound_udp.clear(),
        "network.allow_localhost"   => p.network.allow_localhost = false,
        "network.allow_inbound"     => p.network.allow_inbound = false,
        "network.allow_dns"         => p.network.allow_dns = false,
        "network.allow_unix_sockets" => p.network.allow_unix_sockets = false,
        "network.allow_icmp"        => p.network.allow_icmp = false,
        "network.allow_icmpv6"      => p.network.allow_icmpv6 = false,
        "network.allow_sctp"        => p.network.allow_sctp = false,
        "network.allow_dccp"        => p.network.allow_dccp = false,
        "network.allow_udplite"     => p.network.allow_udplite = false,
        "network.allow_raw_sockets" => p.network.allow_raw_sockets = false,
        "network.extra_protocols"   => p.network.extra_protocols.clear(),
        "network.presets"           => p.network.presets.clear(),
        // ── process ──
        "process.allow_fork"   => p.process.allow_fork = false,
        "process.allow_exec"   => p.process.allow_exec = false,
        "process.allow_signal_self" => p.process.allow_signal_self = false,
        // ── system ──
        "system.mach_services"    => p.system.mach_services.clear(),
        "system.allow_mach_all"   => p.system.allow_mach_all = false,
        "system.allow_iokit"      => p.system.allow_iokit = false,
        "system.allow_ipc"        => p.system.allow_ipc = false,
        "system.allow_sysctl_read" => p.system.allow_sysctl_read = false,
        // ── env ──
        "env.pass"     => p.env.pass.clear(),
        "env.pass_all" => p.env.pass_all = false,
        // ── hardware ──
        "hardware.usb"    => p.hardware.usb = false,
        "hardware.serial" => p.hardware.serial = false,
        "hardware.audio"  => p.hardware.audio = false,
        "hardware.gpu"    => p.hardware.gpu = false,
        "hardware.camera" => p.hardware.camera = false,
        "hardware.screen_capture" => p.hardware.screen_capture = false,
        // Unknown paths are caught earlier in validate_clear and
        // turned into a load-time error. If we get here it means the
        // caller skipped validation; do nothing rather than panic.
        _ => {}
    }
}

/// The full set of dotted field paths that `clear = [...]` accepts.
/// Sorted for `sandkasten explain` / error-message stability.
const KNOWN_CLEAR_PATHS: &[&str] = &[
    "env.pass",
    "env.pass_all",
    "filesystem.allow_metadata_read",
    "filesystem.deny",
    "filesystem.hide",
    "filesystem.read",
    "filesystem.read_files",
    "filesystem.read_write",
    "filesystem.read_write_files",
    "filesystem.rules",
    "hardware.audio",
    "hardware.camera",
    "hardware.gpu",
    "hardware.screen_capture",
    "hardware.serial",
    "hardware.usb",
    "network.allow_dccp",
    "network.allow_dns",
    "network.allow_icmp",
    "network.allow_icmpv6",
    "network.allow_inbound",
    "network.allow_localhost",
    "network.allow_raw_sockets",
    "network.allow_sctp",
    "network.allow_udplite",
    "network.allow_unix_sockets",
    "network.extra_protocols",
    "network.inbound_tcp",
    "network.inbound_udp",
    "network.outbound_tcp",
    "network.outbound_udp",
    "network.presets",
    "process.allow_exec",
    "process.allow_fork",
    "process.allow_signal_self",
    "system.allow_iokit",
    "system.allow_ipc",
    "system.allow_mach_all",
    "system.allow_sysctl_read",
    "system.mach_services",
];

/// Validate the `clear` list of a profile (called once per file at
/// load time). Returns Err on the first unknown path so typos are
/// caught before they silently no-op a security tightening.
fn validate_clear(p: &Profile) -> Result<()> {
    for path in &p.clear {
        if !KNOWN_CLEAR_PATHS.contains(&path.as_str()) {
            return Err(anyhow!(
                "unknown field path in `clear`: {path:?}\n\
                 known paths: {}",
                KNOWN_CLEAR_PATHS.join(", ")
            ));
        }
    }
    Ok(())
}

/// Expand entries that look like shell globs (contain any of `*`, `?`, `[`)
/// into the concrete paths they match on the host filesystem. Non-glob
/// entries are left untouched. De-duplicates.
fn expand_globs_in_place(v: &mut Vec<String>) {
    let mut out: Vec<String> = Vec::with_capacity(v.len());
    for p in v.drain(..) {
        if p.contains('*') || p.contains('?') || p.contains('[') {
            match glob::glob(&p) {
                Ok(iter) => {
                    let before = out.len();
                    for entry in iter.flatten() {
                        let s = entry.to_string_lossy().into_owned();
                        if !out.contains(&s) {
                            out.push(s);
                        }
                    }
                    if out.len() == before {
                        eprintln!(
                            "sandkasten ⚠ glob {p:?} matched nothing on this host — kept literally"
                        );
                        out.push(p);
                    }
                }
                Err(e) => {
                    eprintln!("sandkasten ⚠ invalid glob {p:?}: {e} — kept literally");
                    out.push(p);
                }
            }
        } else if !out.contains(&p) {
            out.push(p);
        }
    }
    *v = out;
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
                } else if i + 1 < bytes.len()
                    && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_')
                {
                    let mut j = i + 1;
                    while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_')
                    {
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
    /// CIDR block — `192.168.1.0/24`. Linux nftables emits this natively;
    /// macOS Seatbelt has no CIDR form and widens to `*` with a warning.
    Ipv4Cidr(std::net::Ipv4Addr, u8),
    Ipv6Cidr(std::net::Ipv6Addr, u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSpec {
    Any,
    Num(u16),
    /// Inclusive range `lo..=hi`.
    Range(u16, u16),
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
    } else if let Some((addr, mask)) = host.split_once('/') {
        // CIDR form.
        let mask: u8 = mask
            .parse()
            .map_err(|_| anyhow!("invalid CIDR mask in {host:?}"))?;
        if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
            if mask > 32 {
                return Err(anyhow!("IPv4 CIDR mask must be 0..=32, got {mask}"));
            }
            HostSpec::Ipv4Cidr(v4, mask)
        } else if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
            if mask > 128 {
                return Err(anyhow!("IPv6 CIDR mask must be 0..=128, got {mask}"));
            }
            HostSpec::Ipv6Cidr(v6, mask)
        } else {
            return Err(anyhow!(
                "CIDR form {host:?} must start with an IP address (v4 or v6)"
            ));
        }
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
    } else if let Some((a, b)) = port.split_once('-') {
        let lo: u16 = a.parse().context("invalid port range lower bound")?;
        let hi: u16 = b.parse().context("invalid port range upper bound")?;
        if hi < lo {
            return Err(anyhow!("port range {lo}-{hi} is inverted"));
        }
        PortSpec::Range(lo, hi)
    } else {
        PortSpec::Num(port.parse().context("invalid port number")?)
    };

    Ok(Endpoint { host, port })
}

/// Per-user profile directory. Linux: `$XDG_CONFIG_HOME/sandkasten/profiles/`.
/// macOS: `~/Library/Application Support/sandkasten/profiles/`.
pub fn user_profile_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("sandkasten").join("profiles"))
}

/// System-wide profile search path. Returns the directories we look
/// in when a name isn't in PWD or the user dir, in order. Admin
/// overrides (`/etc`, `/Library/Application Support`) come before
/// package-managed defaults (Homebrew share dirs, `/usr/share`) so a
/// site customisation wins over the distro/package copy.
pub fn system_profile_dirs() -> Vec<PathBuf> {
    [
        // Linux: admin / sysadmin overrides under /etc.
        "/etc/sandkasten/profiles",
        // macOS: system-wide config (admin-managed).
        "/Library/Application Support/sandkasten/profiles",
        // Homebrew prefixes — Apple Silicon, Intel, Linuxbrew.
        "/opt/homebrew/share/sandkasten/profiles",
        "/usr/local/share/sandkasten/profiles",
        "/home/linuxbrew/.linuxbrew/share/sandkasten/profiles",
        // Linux distro packaging convention.
        "/usr/share/sandkasten/profiles",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

/// The single canonical install destination for `--system`. This is
/// where `sandkasten install-profiles --system` writes; the search
/// order above also picks this dir up first.
pub fn system_install_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/sandkasten/profiles")
    } else {
        PathBuf::from("/etc/sandkasten/profiles")
    }
}

/// Resolve a profile reference into a path. Two regimes:
///
/// 1. **Path-shaped** — anything containing `/` (i.e. an actual path,
///    relative or absolute) is read literally.  No search path consult
///    even on a "file not found" error: paths are unambiguous.
///
/// 2. **Bare name** — a plain `ai-agent` or `ai-agent.toml` (no slash)
///    is treated as a name to look up. The trailing `.toml` is
///    stripped if the user typed one — a common natural mistake — so
///    `ai-agent`, `ai-agent.toml`, and `./ai-agent.toml` all work
///    consistently. The lookup walks:
///
///       - `./<name>.toml`
///       - user dir: `$XDG_CONFIG_HOME/sandkasten/profiles/<name>.toml`
///         (macOS: `~/Library/Application Support/sandkasten/profiles/`)
///       - system dirs: `/etc/sandkasten/profiles/`,
///         `/Library/Application Support/sandkasten/profiles/`,
///         `$(brew --prefix)/share/sandkasten/profiles/`,
///         `/usr/share/sandkasten/profiles/`
///
///    Earlier entries shadow later ones, so a user copy of
///    `ai-agent.toml` wins over a system one and a `/etc` override
///    wins over a package-shipped default.
pub fn resolve_profile_path(name: &str) -> Result<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        if p.exists() {
            return Ok(p);
        }
        return Err(anyhow!("profile file not found: {}", p.display()));
    }

    // Bare name. Strip a trailing `.toml` if present — `ai-agent` and
    // `ai-agent.toml` should both resolve through the search path.
    let bare = name.strip_suffix(".toml").unwrap_or(name);
    let filename = format!("{bare}.toml");

    let here = PathBuf::from(&filename);
    if here.exists() {
        return Ok(here);
    }

    if let Some(user) = user_profile_dir() {
        let p = user.join(&filename);
        if p.exists() {
            return Ok(p);
        }
    }

    for dir in system_profile_dirs() {
        let p = dir.join(&filename);
        if p.exists() {
            return Ok(p);
        }
    }

    Err(anyhow!(
        "profile {name:?} not found. Searched (in order): ./, \
         {user_path}, {sys_paths}. Run `sandkasten templates` for the \
         built-in template list, or `sandkasten install-profiles` to \
         drop the bundled examples (e.g. `ai-agent.toml`) into the \
         user profile dir.",
        user_path = user_profile_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<no user config dir>".to_string()),
        sys_paths = system_profile_dirs()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
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
    // Catch typos in `clear = [...]` paths at load time, before they
    // silently no-op and leave a parent's wide allow rule in place.
    validate_clear(&p)?;
    if let Some(parent_name) = p.extends.clone() {
        let parent = load(&parent_name)?;
        p = p.merge_over(parent);
    }
    Ok(p)
}

/// Finalize a profile: expand path variables using `ctx`, expand named
/// protocol/service presets and hardware-access flags, propagate spoof
/// conveniences, then validate.
pub fn finalize(mut p: Profile, ctx: &ExpandContext) -> Result<Profile> {
    p.expand_paths(ctx)?;
    crate::presets::expand(&mut p);
    crate::hardware::expand(&mut p);

    // efi_enabled = false → hide /sys/firmware/efi entirely.
    if p.spoof.efi_enabled == Some(false) {
        let efi = "/sys/firmware/efi".to_string();
        if !p.filesystem.hide.iter().any(|x| x == &efi) {
            p.filesystem.hide.push(efi);
        }
    }

    // Overlayfs: writes to the merged mount land on the upper dir, so
    // both the mount point (what the sandboxed process sees) and the
    // upper dir (what Landlock actually checks) must be in the
    // filesystem.read_write list. Auto-add them — users don't have to
    // think about this and it can't be wrong.
    for path in [
        p.overlay.upper.clone(),
        p.overlay.mount.clone(),
        // lower stays read-only on purpose.
    ]
    .into_iter()
    .flatten()
    {
        if !p.filesystem.read_write.iter().any(|x| x == &path) {
            p.filesystem.read_write.push(path);
        }
    }

    // Network proxy: set env vars + optionally narrow outbound_tcp.
    apply_proxy(&mut p);

    p.validate()?;
    Ok(p)
}

fn apply_proxy(p: &mut Profile) {
    let Some(url) = p.network.proxy.url.clone() else {
        return;
    };
    for var in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        p.env.set.entry(var.into()).or_insert_with(|| url.clone());
    }
    if !p.network.proxy.bypass.is_empty() {
        let joined = p.network.proxy.bypass.join(",");
        p.env
            .set
            .entry("NO_PROXY".into())
            .or_insert_with(|| joined.clone());
        p.env.set.entry("no_proxy".into()).or_insert(joined);
    }
    // Restrict outbound to the proxy's host:port (and DNS + the explicit
    // proxy bypass entries) when the user hasn't listed other destinations.
    if p.network.proxy.restrict_outbound && p.network.outbound_tcp.is_empty() {
        if let Some(hostport) = host_port_from_url(&url) {
            p.network.outbound_tcp.push(hostport);
        }
        for b in p.network.proxy.bypass.clone() {
            p.network.outbound_tcp.push(format!("{b}:*"));
        }
    }
}

fn host_port_from_url(u: &str) -> Option<String> {
    // Cheap parser — no url crate dep.
    //  scheme://host[:port][/...]
    let after = u.split_once("://")?.1;
    let host_part = after.split(['/', '?', '#']).next()?;
    if host_part.contains(':') {
        Some(host_part.to_string())
    } else {
        // Default ports per scheme.
        let port = match u.split("://").next().unwrap_or("") {
            "http" => 80,
            "https" => 443,
            "socks5" | "socks5h" => 1080,
            _ => return None,
        };
        Some(format!("{host_part}:{port}"))
    }
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
    fn resolve_profile_walks_search_path_for_bare_name_with_toml_suffix() {
        // Regression for: `sandkasten run ai-agent.toml -- claude`
        // failing with "profile file not found" even though
        // ai-agent.toml is installed in the user dir. Before the fix
        // a `.toml` extension shortcut to the literal-path branch
        // and bypassed the search path entirely.
        let tmp =
            std::env::temp_dir().join(format!("sandkasten-resolve-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let target = tmp.join("foo.toml");
        std::fs::write(&target, "name = \"foo\"\n").unwrap();

        // Simulate "user dir" by leaning on the actual lookup with
        // a path argument. We can't override user_profile_dir from
        // a unit test without significant refactor, so probe the
        // path branch directly: a `/`-shaped reference still works.
        let by_path = resolve_profile_path(target.to_str().unwrap()).unwrap();
        assert_eq!(by_path, target);

        // Bare `foo.toml` (no slash, has extension) should NOT take
        // the literal-path shortcut — it walks the search list. We
        // can't insert into the user dir from tests, but we CAN
        // confirm the not-found error mentions the search path,
        // which proves we passed through the new branch.
        let err = resolve_profile_path("definitely-not-installed-xyz.toml").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Searched (in order)"),
            "expected search-path enumeration, got: {msg}"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn blocks_setid_tracks_both_flags() {
        let mut p = Process::default();
        assert!(!p.blocks_setid());
        p.block_setid_syscalls = true;
        assert!(p.blocks_setid());
        p.block_setid_syscalls = false;
        p.block_privilege_elevation = true;
        assert!(p.blocks_setid(), "privilege-elevation must imply setid");
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
    fn clear_resets_parent_field_before_merge() {
        // Parent grants wide outbound + DNS.
        let parent = Profile {
            network: Network {
                allow_dns: true,
                outbound_tcp: vec!["a:443".into(), "b:443".into()],
                allow_localhost: true,
                ..Default::default()
            },
            ..Default::default()
        };
        // Child wants NONE of that, even though `extends` would
        // normally union/OR everything additively.
        let child = Profile {
            clear: vec![
                "network.outbound_tcp".into(),
                "network.allow_dns".into(),
                "network.allow_localhost".into(),
            ],
            network: Network {
                allow_dns: false,
                outbound_tcp: vec![],
                allow_localhost: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = child.merge_over(parent);
        assert!(merged.network.outbound_tcp.is_empty());
        assert!(!merged.network.allow_dns);
        assert!(!merged.network.allow_localhost);
        assert!(merged.clear.is_empty(), "clear list shouldn't survive merge");
    }

    #[test]
    fn unknown_clear_path_is_a_load_time_error() {
        let p = Profile {
            clear: vec!["network.no_such_field".into()],
            ..Default::default()
        };
        let err = validate_clear(&p).unwrap_err().to_string();
        assert!(err.contains("network.no_such_field"));
    }

    #[test]
    fn self_template_expands_cwd_at_runtime() {
        let raw = Profile::from_toml_str(crate::templates::SELF).unwrap();
        let raw = merge_parents(raw).unwrap();
        let p = finalize(raw, &ctx()).unwrap();
        assert!(p.filesystem.read_write.iter().any(|s| s == "/work/project"));
    }
}
