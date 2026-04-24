# Changelog

## v0.3.1 — 2026-04-24

Parity pass: the Linux backend now reaches the same "works out of the
box" state the macOS backend has. Four distinct bugs were surfaced by
dogfooding a fresh install on Debian trixie (kernel 6.12, Landlock ABI v6)
against the same matrix that was passing on macOS.

### Landlock

- **Execute bit was missing from the `read` access set.** `AccessFs::from_read`
  covers `ReadFile` + `ReadDir` only — it does NOT include `Execute`. Every
  invocation of a binary whose directory was only on `read` (e.g.
  `/usr/bin/true` under `strict`) therefore died with `EACCES` at the
  initial `execve()`. Fixed by unioning `AccessFs::Execute` into the read
  access mask.
- **Initial `execve` wasn't guaranteed reachable.** Matched the macOS
  one-shot `process-exec` literal grant by implicitly adding the target
  binary's parent directory to the Landlock allow-list. Without this, any
  template that doesn't explicitly list the target's bin directory
  (`strict` on Linux) bricks its own entry point.
- **"Deny cannot be enforced" warning was spammed 15 times per run.**
  Templates like `self` with `read = ["/"]` triggered the warning once per
  read path × once per deny path intersection. Consolidated to a single
  informational line and downgraded from default to `-v` (Info) so a
  normal invocation stays silent.

### Network

- **Private-netns+nftables with no external plumbing was the default for
  `network-client` and `dev`.** A private Linux netns has no route to the
  internet without `pasta`/`slirp4netns`/a prepared veth pair, so every
  outbound lookup failed with `EAI_AGAIN` or `network unreachable`.
  Matched the macOS behaviour (shared host network stack) by defaulting to
  the host netns for outbound-only profiles. Per-IP nftables filtering is
  therefore not enforced in that mode (kernel-wide rules would hit the
  host globally) — the `render` output says so explicitly and points users
  at `[network.netns_path]` for bring-your-own-isolation.

### Templates

- `dev`: add `${CWD}` to `read_write`. `git clone`, `npm install`,
  `cargo build`, and every other "work in this directory" flow needs it
  and the template was previously only granting `/tmp` + `~/.cache`.

### Verified end-to-end on Linux

`self`/`strict`/`minimal-cli`/`network-client`/`dev` each run the matrix
that was passing on macOS: `cat`, `ls`, `wc`, `awk`, `python -c`, `bash`,
`curl https://ipinfo.io/ip`, `dig ipinfo.io`, `git clone https://...`.
`process.block_privilege_elevation` correctly makes `sudo`/`su` fail in
both platforms (on Linux by way of the userns UID remap + seccomp setid
denies).

## v0.3.0 — 2026-04-24

### New: privilege-elevation + setuid/setgid guardrails

Two new cross-platform profile flags under `[process]`:

- `block_privilege_elevation = true` — denies exec of the classic
  escalation binaries on both macOS and Linux. The binary list covers
  the standard *nix system paths (`/usr/bin/sudo`, `/usr/bin/su`,
  `/bin/su`, `/usr/bin/doas`, `/usr/bin/pkexec`, `/usr/bin/runuser`,
  `/usr/sbin/visudo`, `/usr/libexec/doas`), the common package-manager
  installs (Homebrew, Linuxbrew, Snap), and `/usr/local/bin/...` for
  locally-compiled builds. Useful specifically when the host user has
  `NOPASSWD: ALL` in sudoers or cached credentials — without it, a
  compromised sandboxed tool could re-exec through `sudo` and end up
  running as host-root before the user notices. Implies
  `block_setid_syscalls`.

- `block_setid_syscalls = true` — seccomp-denies the setuid-family
  syscalls (`setuid`, `setgid`, `setreuid`, `setregid`, `setresuid`,
  `setresgid`, `setfsuid`, `setfsgid`, `setgroups`) on Linux, so even
  shellcode that skips the elevation binary and calls the syscall
  directly gets `EPERM`. Linux-only; macOS already prevents the
  sandboxed process from honouring setuid bits at the kernel MAC
  layer.

Under the hood:
- **macOS:** emits `(deny process-exec (literal "/usr/bin/sudo"))` and
  friends in the generated SBPL. Seatbelt already refuses to honour
  setuid inside the sandbox, but the explicit deny makes the policy
  discoverable instead of hidden in kernel-level MAC behaviour.
- **Linux:** binary-level denial follows naturally from the Landlock
  allow-list (the elevation binaries aren't normally on it); the new
  seccomp filter is the real enforcement, and fires even on profiles
  that *do* grant a broad exec subtree.

Both flags default to `false` (no behaviour change in existing
profiles). Turn them on in any profile that runs user-supplied code.

### Template fixes (from continued dogfood pass)

- `strict`: allow read on `/Library/Developer/CommandLineTools` and
  `/Applications/Xcode.app` so Apple's xcrun-shim binaries
  (`/usr/bin/git`, `/usr/bin/python3`, `/usr/bin/clang`, …) can find
  and re-exec the real tool.
- `minimal-cli`: grant read on `${CWD}` so the advertised use case
  (`awk` / `sed` / `sort` / `wc` / `grep <file-in-cwd>`) actually
  works. Writes stay denied.
- `network-client`: grant `read_write` on `/private/var/folders`
  (macOS `$TMPDIR`) and `/tmp` so xcrun can cache its database —
  without this every xcrun-shim binary fails with "couldn't create
  cache file" before it ever reaches the network.
- `dev`: add the `web` + `ssh` presets so `git clone`, `npm install`,
  `pip install`, `cargo fetch` etc. can actually reach the network
  without the user having to hand-extend the profile. The description
  previously claimed "localhost network" which was literally true
  and quietly catastrophic.

## v0.2.2 — 2026-04-24

One-line follow-up to v0.2.1: `allow_unix_sockets` now also grants
`network-outbound` on the Unix-domain socket paths
(`/var/run`, `/private/var/run`, `/tmp`, `/private/tmp`), not just
`system-socket` + `network-bind`. Without that outbound grant,
`getaddrinfo(3)` on macOS silently returns EAI_NONAME — which made
`curl https://x.example` fail under `network-client` even though
everything else (UDP:53, mDNSResponder mach services, filesystem
reads) was in place. `dig` and `host` were unaffected because they
use libresolv directly rather than going through mDNSResponder's
Unix socket.

## v0.2.1 — 2026-04-24

Dogfood pass on macOS surfaced three template-level bugs. All fixed here
without changing any public API.

### macOS SBPL generator

- **Initial `execve` always granted.** Templates with `allow_exec = false`
  (notably `strict`) previously made their own entry point unreachable:
  Seatbelt applies before the `execve` sandkasten itself issues, so a
  blanket `(deny process-exec)` kills the launch. Now we always emit
  `(allow process-exec (literal "<argv[0]>"))` — one-shot grant for the
  target binary only; children still inherit whatever `allow_exec` says.
- **dyld bootstrap baked in.** On macOS 14+ every dynamic Mach-O binary
  loads its dylibs from the shared cache stored in cryptex graft points
  (`/System/Cryptexes/OS`, `/System/Volumes/Preboot/Cryptexes/OS`, plus
  each ancestor). Without these grants, even `/usr/bin/true` SIGABRTed
  during dyld startup. We now emit the full graft-point + ancestor
  allowance set (mirrored from Apple's own `dyld-support.sb`) whenever
  any exec is allowed.
- **`/etc`, `/tmp`, `/var` firmlink aliasing.** Seatbelt matches paths
  post-symlink-resolution, so a rule on `/etc/hosts` never fires because
  the real path is `/private/etc/hosts`. The SBPL generator now emits
  both forms automatically for any read/read_files/read_write/
  read_write_files entry whose path begins with `/etc`, `/tmp`, or `/var`.

### Templates

- **`strict`:** added `/System/Volumes/Preboot/Cryptexes` to `read` so
  dyld can actually find the shared cache on live-fs boots. (The dyld
  bootstrap set granted by the generator is the minimum; the template
  still controls everything else.)
- **`network-client`:** added `/etc/ssl` + `/var/run/resolv.conf` so
  libressl/curl find their TLS config and DNS resolver file, plus a
  handful more mach services (`com.apple.mDNSResponder`, `ocspd`,
  `cfnetworkagent`, `networkd`, `symptomsd`) needed for outbound TLS.

### Tests

Two new generator tests: `firmlink_variants_alias_etc_tmp_var_into_private`
and `target_grants_initial_exec_when_allow_exec_is_false`. 13 total,
all green on macOS + Linux.

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
