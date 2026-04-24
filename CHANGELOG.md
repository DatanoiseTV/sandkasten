# Changelog

## v0.2.0 — 2026-04-24

A very large release on top of the initial tag. The short version: sandkasten
is now a comprehensive sandboxing + profile-authoring toolkit with a native
macOS app alongside the Linux-friendly web UI and CLI.

### Kernel policy

- **Resource limits** via `setrlimit` — cpu_seconds, memory_mb,
  file_size_mb, open_files, processes, stack_mb, core_dumps,
  wall_timeout_seconds. CLI `--timeout` honours the same watchdog.
- **`PR_SET_NO_NEW_PRIVS`** + **`PR_SET_DUMPABLE=0`** +
  **`PR_SET_KEEPCAPS=0`** + **`PR_SET_PTRACER(-1)`** on Linux.
- **Capability bounding-set drops** for 20 capabilities (SYS_ADMIN /
  BOOT / NICE / RESOURCE / TIME / TTY_CONFIG / MKNOD / LEASE / AUDIT_* /
  SETFCAP / MAC_* / SYSLOG / WAKE_ALARM / BLOCK_SUSPEND / PERFMON /
  BPF / CHECKPOINT_RESTORE).
- **seccomp-BPF** deny-list grown to cover hardlink / symlink, handle-
  based file reopen (`name_to_handle_at` / `open_by_handle_at`),
  io_uring_*, userfaultfd, clock manipulation, personality / kcmp /
  vhangup / quotactl, fanotify, remap_file_pages, NUMA movement, acct,
  uselib, lookup_dcookie, and all the kernel-admin syscalls.
- **Protocol coverage**: SCTP / DCCP / UDPLite flags on Linux; 35+
  named service presets (http / https / quic / webrtc / rtp / sip /
  stun / ssh / rdp / vnc / mail / file-transfer / auth / databases /
  chat / ntp / mdns / ping / wireguard / openvpn / tailscale / ipsec /
  minecraft / steam / source-engine / quake3 / teamspeak /
  discord-voice / riot-games / tcpdump / pcap / nmap).
- **Per-IP outbound filtering** on Linux via nftables inside the
  sandbox's netns, with CIDR + hostname → A/AAAA resolution.
- **Traffic hooks**: `[[network.redirects]]` DNAT on Linux,
  `[[network.blocks]]` nftables REJECT (Linux) / SBPL deny (macOS).
- **`[network.proxy]`** — HTTP(S)/SOCKS5 proxy integration: sets the
  six standard `*_PROXY` env vars and (optionally) narrows
  outbound_tcp to only the proxy's host:port, guaranteeing the
  sandbox can't route around it. Integrates with mitmproxy / squid
  for L7 rules.
- **`[network.netns_path]`** — `setns()` into an existing netns.
  Route sandboxed traffic through a VPN that you set up once via
  `ip netns add vpn; ip netns exec vpn wg-quick up wg0`.
- **DNS / `/etc/hosts` override** — `[network.dns]` +
  `[network.hosts_entries]`. Transparent on Linux via bind-mount,
  sidecar on macOS.
- **Hardware preset flags**: USB / serial / audio / GPU / camera /
  screen-capture. Linux expands into the right `/dev/*`, `/sys/*`,
  `/run/user/*` paths; macOS grants IOKit + the right Mach service
  families.
- **`[hardware.video]`** — camera allowlist + `from → to` redirect
  map (v4l2loopback pattern).
- **`[spoof]`** — hardware identity spoofing: `cpu_count`
  (sched_setaffinity), `cpuinfo_synth`, hostname, machine_id,
  kernel_version / kernel_release, os_release, issue, hostid_hex,
  timezone, DMI fields, thermal / hwmon temperatures, EFI platform
  size + enablement, arbitrary `[[spoof.files]]` bind-mounts.

### Filesystem

- **Glob expansion** in `read` / `read_write` / `deny` /
  `read_files` / `read_write_files` (`/etc/*.conf`).
- **Path template variables**: `${CWD}` / `${HOME}` / `${EXE_DIR}` /
  any env var / `~`, evaluated at run time.
- **Fine-grained per-path rules** with per-op allow + deny
  (read, write, create, delete, rename, chmod, chown, xattr, ioctl,
  exec, all, write-all).
- **`[[filesystem.rewire]]`** — Linux bind-mount path substitution.
- **`[[filesystem.hide]]`** — hides paths by bind-mounting an empty
  tmpfs / `/dev/null`, so ls/stat see "empty" rather than EPERM.

### Workspace / overlay / mocks / snapshots

- **`[workspace]`** — persistent directory per profile, auto-created,
  exposed as `$SANDKASTEN_WORKSPACE`, optionally set as CWD.
- **`[overlay]`** — true overlayfs on Linux 5.11+.
- **`sandkasten snap save|load|list`** — named snapshots of the
  overlay upperdir for time-travel.
- **`[mocks.files]`** — content sidecar materialised to a per-run
  tempdir exposed via `$SANDKASTEN_MOCKS`.

### CLI

- `sandkasten run / shell / sshd / init / check / render / list /
  templates / explain / diff / doctor / info / snap / ui / wrap /
  verify / learn / completions`.
- **`sshd`** — ready-made `ForceCommand` for sshd_config.
- **`wrap`** — transparent-prepend shortcut (`sandkasten wrap --
  npm install`).
- **Profile signing** via minisign — trusted keys from
  `~/.config/sandkasten/trusted_keys/*.pub`, `verify` + `run
  --verify` commands.
- **`doctor`** — environment pre-flight with OS-specific install
  commands for missing tools (nft, strace).
- **Tiered verbose logging** (`-v` / `-vv` / `-vvv`) with post-run
  kernel-denial capture (macOS).
- **`--timeout`** flag with SIGTERM → SIGKILL escalation.
- **Policy fingerprint** — `render` emits `;; policy-hash: …`.
- **Shell completions** (bash / zsh / fish / powershell / elvish).

### Built-in templates

New: `browser`, `electron`. Existing (`self`, `strict`, `minimal-cli`,
`network-client`, `dev`) refined — secure defaults enabled
(`allow_unix_sockets` on by default where appropriate; TLS Mach
services baked into `strict`).

### Web UI

- Local-only on `127.0.0.1`, 128-bit bearer token, CSRF guard via
  `Origin` header on mutating requests, tight CSP, 64 KB body cap.
- Structured form editor with client-side validation (paths,
  endpoints, env names, Mach services).
- Fine-grained rule editor with allow/deny chip toggles.
- Duplicate / save-as flow for built-in templates.
- Non-system modal dialogs, toast notifications.

### Native macOS app (new)

- `swift-ui/` — SwiftUI + TOMLKit. Three tabs: **Editor** (structured
  form for every profile section — toggles, steppers, string-list
  editors, KV pair editors, preset chip pickers, op chip matrices),
  **Policy** (plain-English explanation), **TOML** (raw source).
- Self-contained .app bundle with embedded CLI.
- Ad-hoc signed, custom AppIcon.icns generated via Core Graphics.
- Resilient decoder — per-section parse errors don't blank the form,
  they surface in an inline banner.
- Debug log at `/tmp/sandkasten-ui.log` for field debugging.

### Packaging

- **Homebrew tap** published at `DatanoiseTV/sandkasten`.
  `brew tap DatanoiseTV/sandkasten && brew install sandkasten`.

## v0.1.0

Initial tagged release — core macOS + Linux kernel sandbox, first
round of profile templates, initial web UI, minisign signing,
learn mode on both platforms.
