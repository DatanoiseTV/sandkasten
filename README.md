# sandkasten

A fast, kernel-enforced application sandbox for **macOS** and **Linux**, written in
Rust. Describe what a program may touch in TOML; sandkasten enforces it at the
kernel level.

```
─┐
 │  profile.toml  ──▶  sandkasten  ──▶  fork ─▶ sandbox_init()  ──▶  execve(target)
─┘                                                ▲
                                                  │
                                    macOS: Seatbelt (MACF)
                                    Linux: user+mount+pid+ipc+uts[+net] ns
                                           + Landlock LSM
                                           + seccomp-BPF
                                           + PR_SET_NO_NEW_PRIVS
```

- **Native enforcement.** We call the kernel directly — no userspace
  interposition — so overhead is effectively zero once policy is applied.
- **Default deny.** Filesystem, network, Mach, sysctl, IOKit and IPC are all
  off unless the profile opts in.
- **Portable profiles.** One TOML file works on both platforms; backend-specific
  details are handled by the generator.
- **Tight dependencies.** Small crate list, short build times, the produced
  binary is a single ~3 MB release binary.

## Status

Experimental — usable, but Apple's Seatbelt is technically SPI (used
unchanged by Chrome/Firefox for 15+ years; stable in practice). See the
[Limits](#limits) section before relying on this for a production security
boundary.

## Quickstart

```sh
cargo install --path .          # or: cargo build --release
sandkasten templates            # list built-ins
sandkasten init                 # writes ./sandkasten.toml (from the `self` template)
sandkasten run self -- /bin/cat myfile.txt
```

The default **`self`** template lets the target see only its own working
directory (`${CWD}`) plus the minimal system paths a dynamically-linked binary
needs to load. No network, no home directory, no writes outside CWD.

## Commands

```
sandkasten run <profile> [-C <cwd>] [--timeout 30s] [--verify] -- <cmd> [args...]
  Launches the command under the named profile. --timeout accepts s/m/h/d.
  --verify refuses to run unless the profile's .minisig signature validates
  against a trusted key (see "Profile signing" below).
  Profile name resolution: ./foo.toml  →  ~/.config/sandkasten/profiles/foo.toml
                           →  built-in templates.

sandkasten init [--template <name>] [-o <path>]
  Writes a starter profile. Default template: self.

sandkasten check <profile>
  Parses + validates without running.

sandkasten render <profile>
  Prints the generated policy (SBPL on macOS, a summary on Linux) for audit.

sandkasten verify <profile>
  Verifies the profile's sidecar minisign signature against trusted keys.

sandkasten list
  Lists user profiles and built-in templates.

sandkasten templates
  Lists built-in templates with descriptions.

sandkasten learn [--base <tpl>] [-o <out.toml>] [--auto-system] -- <cmd> [args...]
  Runs the target with full permissions while capturing every operation it
  performs. Applies heuristics (subtree collapsing, sensitive-path flagging,
  wildcard-by-port detection, CWD folding) and interactively proposes a
  tightened profile. macOS uses SBPL (trace ...); Linux uses strace -f.

sandkasten ui [--port 4173]
  Opens a local web UI for browsing and editing profiles (see UI section).

sandkasten shell <profile> [--shell /bin/zsh] [-C <cwd>]
  Drop into an interactive sandboxed shell. `$SANDKASTEN_PROFILE` is set
  so you can customise `PS1`, e.g.
    PS1='[sandkasten:$SANDKASTEN_PROFILE] \w \$ '

sandkasten diff <left> <right>
  Structural diff between two profiles — what each grants that the other
  does not. Built-in names, paths, and user profiles all work.

sandkasten explain <profile>
  Plain-English summary of what a profile allows, denies, and limits.
  Deterministic; no AI. Great for reviewing an unfamiliar profile before
  running untrusted code through it.
```

`render` also emits a trailing `;; policy-hash: <16-hex>` fingerprint
(64-bit FNV-1a over the full rendered policy). Stash it in CI to detect
policy drift — if the hash of a regenerated policy differs from a pinned
one, something changed.

Verbosity:

- default / `-q` — silent except errors
- `-v` — lifecycle one-liners (profile, applied policy, pid, exit)
- `-vv` — adds a compact rule summary
- `-vvv` — adds the full generated policy and, on macOS, a post-run
  kernel-denial capture (deduped, PID-filtered, top 30)

## Profile format

```toml
name = "my-profile"
description = "What this profile is for"
extends = "strict"              # inherit from a built-in

[filesystem]
allow_metadata_read = true      # stat/readdir on any path
read = ["/usr/lib", "/System"]  # subtrees readable
read_write = ["${CWD}", "/tmp"] # subtrees readable + writable
read_files = ["/etc/hosts"]     # single-file reads
read_write_files = []
deny = ["${HOME}/.ssh"]         # blanket deny (overrides allows)

# Fine-grained per-path rules. Ops: read, write, create, delete, rename,
# chmod, chown, xattr, ioctl, exec, all, write-all.
[[filesystem.rules]]
path = "${CWD}/important.log"
literal = true                  # match the exact file only
allow = ["read", "write"]
deny  = ["delete", "chmod"]

[network]
allow_localhost = true
allow_dns = true
allow_inbound = false
allow_icmp = false              # ICMP (ping)
allow_icmpv6 = false
allow_raw_sockets = false       # AF_INET/SOCK_RAW — privileged
allow_sctp = false              # Stream Control Transmission Protocol
allow_dccp = false              # Datagram Congestion Control Protocol
allow_udplite = false           # UDP-Lite
outbound_tcp = ["*:443", "*:80", "10.0.0.5:22", "example.com:8080"]
outbound_udp = []
inbound_tcp  = []
inbound_udp  = []
extra_protocols = []            # additional `meta l4proto X` on Linux
# Named protocol/service presets that expand into concrete TCP/UDP rules
# at profile-load time. See the full list below.
presets = ["https", "webrtc", "ssh", "postgres"]

[process]
allow_fork = false              # default-deny; templates opt-in
allow_exec = false
allow_signal_self = true

[system]
allow_sysctl_read = true
allow_iokit = false
allow_ipc = false
allow_mach_all = false          # macOS: very broad; needed for GUI apps
mach_services = ["com.apple.system.logger"]

[env]
pass_all = false
pass = ["PATH", "HOME", "LANG"] # only these vars are forwarded
set  = { }                      # { KEY = "value" } to override

[limits]                        # POSIX resource limits (all optional)
cpu_seconds = 60                # RLIMIT_CPU — kills if exceeded
memory_mb = 1024                # RLIMIT_AS (+ RLIMIT_DATA on Linux)
file_size_mb = 100              # RLIMIT_FSIZE — max single-file size
open_files = 512                # RLIMIT_NOFILE
processes = 64                  # RLIMIT_NPROC — fork-bomb guard
stack_mb = 8                    # RLIMIT_STACK
core_dumps = false              # RLIMIT_CORE = 0 blocks memory-dump on crash
wall_timeout_seconds = 300      # parent SIGTERMs after N seconds, then SIGKILL +3s

[mocks]                         # v1: content sidecar
files = { "config.json" = '{"api":"https://example/"}' }
# Materialised to a private tempdir; the path lands in $SANDKASTEN_MOCKS
# inside the sandbox. Transparent path-interposition (LD_PRELOAD /
# bind-mount) is planned — until then, mock-aware apps consult the env var.

# DNS / hosts rewrite — transparent on Linux (bind-mounts in the sandbox's
# mount namespace over /etc/resolv.conf and /etc/hosts). On macOS the
# synthesised files appear under $SANDKASTEN_MOCKS as resolv.conf and hosts;
# transparent application needs the DYLD interposer, planned.
[network.dns]
servers = ["1.1.1.1", "9.9.9.9"]
search  = ["example.com"]
options = ["edns0", "rotate"]

[network.hosts_entries]
"api.example.com" = "127.0.0.1"
"corp.internal"   = "10.0.0.42"

# Outbound IP redirect (Linux only, nftables DNAT). Hooks an app that dials
# a hardcoded IP to a local service. For hostname-based hooking use
# `hosts_entries` — works on both platforms and survives TLS SNI routing.
[[network.redirects]]
from = "1.2.3.4:443"
to   = "127.0.0.1:8443"
protocol = "tcp"              # tcp | udp

# Outbound blocks. Linux emits nftables REJECT rules; macOS emits SBPL
# denies (hostname / IP denies are widened to `*:PORT` by Seatbelt's
# grammar — document the limit).
[[network.blocks]]
host = "tracking.example.com"
port = "*"                    # omit or "*" for all ports
protocol = "tcp"

# Persistent workspace: cross-platform. Directory is auto-created, added
# to read_write, exposed to the sandbox as $SANDKASTEN_WORKSPACE, and
# optionally set as the initial CWD. Pre-populate it or inspect it
# yourself afterwards — writes persist there.
[workspace]
path  = "~/.sandkasten/work/${NAME}"
chdir = true

# True copy-on-write overlay (Linux only, kernel 5.11+).
#   lower   = read-only base the sandbox sees through
#   upper   = writes land here persistently; inspect at any time
#   mount   = where the merged view is exposed (defaults to lower,
#             so the overlay transparently replaces the real path)
[overlay]
lower = "/opt/myapp"
upper = "~/.sandkasten/overlay/myapp"
# mount = "/opt/myapp"   # default
```

### Path template variables

Expanded at `sandkasten run` time:

| variable     | resolves to                                         |
|--------------|-----------------------------------------------------|
| `${CWD}`     | absolute working directory                          |
| `${EXE_DIR}` | directory of the resolved target binary             |
| `${HOME}`    | user's home directory                               |
| `${ANY_ENV}` | any other env var from the parent shell             |
| `~`          | shorthand for `${HOME}`                             |

### Built-in templates

| template         | what it gives you                                                          |
|------------------|----------------------------------------------------------------------------|
| `self`           | **Default.** Read+write on `${CWD}` only. No rest of filesystem. No net.   |
| `strict`         | Near-zero permissions. Minimal base every dynamically-linked binary needs. |
| `minimal-cli`    | `strict` + read on `/usr/bin /bin /sbin /usr/local /opt`. No net.          |
| `network-client` | `minimal-cli` + outbound TCP 80/443 + DNS. Read-only FS.                   |
| `dev`            | Permissive. Read `/`, write CWD/TMP, localhost. Denies secrets.            |
| `browser`        | Chromium-family browsers (Brave, Chrome, Edge). Use `--no-sandbox`.        |
| `electron`       | Electron apps (VS Code, Slack, Discord, Obsidian, …).                      |

**Running a Chromium-based browser.** Chromium has its own internal sandbox
that calls `sandbox_init` from helper processes; that fails inside an outer
sandbox. Pass `--no-sandbox` so the outer (sandkasten) sandbox is the only
enforcement layer. Optionally also pass `--password-store=basic` to silence
the "Encryption is not available" warning — saved passwords then live
plaintext in the profile directory, appropriate for a disposable session.

```sh
sandkasten run browser -- \
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
  --no-sandbox --password-store=basic
```

The browser inherits the sandbox across its ~10 helper processes. Keychain,
`~/.ssh`, `~/.aws`, TCC database, shell history and other browsers' profile
dirs are all explicitly denied.

## Web UI

```sh
sandkasten ui
# ╭─ sandkasten UI ─────────────────────────────────────────
# │  http://127.0.0.1:46513/?t=<random-token>
# │  profiles directory: ~/.config/sandkasten/profiles
# │  Ctrl-C to stop.
# ╰─────────────────────────────────────────────────────────
```

The UI is local-only and minimalistic. Features:

- Structured form per profile section (filesystem, network, process, system, env)
- TOML tab for raw editing with live server-side validation on save
- Fine-grained rule editor with allow/deny toggles per operation (read, write,
  create, delete, rename, chmod, chown, xattr, ioctl, exec)
- Client-side validators for paths (absolute / template vars), network
  endpoints (`host:port`, IPv4/IPv6, rejects CIDR with an explanatory message),
  env var names and Mach service names; bad lines are flagged inline
- Duplicate / Save-As flow for built-in templates and existing profiles
- Non-system modal dialogs; toast notifications for save/delete

### Web UI security

- Binds **only** to `127.0.0.1` — never the network.
- **128-bit random bearer token** required on every `/api/*` request; printed
  once on startup.
- **CSRF guard**: mutating requests (PUT, DELETE) require an `Origin` header
  matching the bound `host:port` — a token leaked via URL alone isn't enough
  to trigger writes cross-origin.
- **Tight CSP** (`default-src 'none'`), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy` disabling camera/mic/geolocation, `Cache-Control: no-store`.
- **Body size cap** of 64 KB on PUT (profiles are tiny; anything larger is
  refused with 413 before being read into memory).
- **Path traversal blocked**: profile names must match `[a-zA-Z0-9_-]+`;
  writes are confined to `~/.config/sandkasten/profiles/`.
- **No `run` endpoint**: the UI edits profiles only. You launch profiles
  yourself via `sandkasten run`. This keeps the attack surface small.

### Network-protocol presets

`presets` gives short ergonomic names for common port/protocol bundles.
Every preset only adds to the outbound allowlist — nothing permissive is
implicit. Kernel sandboxes see L3/L4 traffic; an application-layer name
like `"rtp"` resolves to the UDP port range that protocol customarily
uses. On Linux, port ranges reach `nftables` natively; on macOS the
Seatbelt grammar has no range form and we widen to `*:PORT` (noted in
the rendered policy).

| group       | presets                                                                   |
|-------------|---------------------------------------------------------------------------|
| Web         | `http`, `https`, `quic`, `web`                                            |
| Realtime    | `rtp`, `sip`, `stun`, `webrtc`                                            |
| Remote      | `ssh`, `rdp`, `vnc`                                                       |
| Mail        | `smtp`, `smtps`, `imap`, `imaps`, `pop3`, `pop3s`                         |
| Files       | `ftp`, `ftps`, `sftp`, `git`                                              |
| Auth        | `ldap`, `ldaps`, `kerberos`                                               |
| Databases   | `mysql`, `postgres`, `redis`, `memcached`, `mongodb`, `cassandra`, `elastic` |
| Chat        | `irc`, `ircs`, `xmpp`, `matrix`, `mqtt`, `mqtts`                          |
| Time / disc | `ntp`, `mdns`, `dhcp`, `dns`                                              |
| Diagnostics | `ping` (ICMP + ICMPv6)                                                    |

## Profile signing

sandkasten verifies **minisign** ed25519 signatures — same format as Jedisct1's
`minisign` CLI (Homebrew: `brew install minisign`).

Generate a key pair and sign profiles outside sandkasten:

```sh
minisign -G -p sandkasten.pub -s sandkasten.key      # one-off: create key pair
minisign -Sm my-profile.toml -s sandkasten.key       # sign; produces my-profile.toml.minisig
```

Install the public key as trusted, then run with verification:

```sh
mkdir -p ~/.config/sandkasten/trusted_keys
cp sandkasten.pub ~/.config/sandkasten/trusted_keys/
# or:  export SANDKASTEN_TRUSTED_KEY="$(cat sandkasten.pub)"

sandkasten verify my-profile.toml
# → ok: my-profile.toml verified against key ~/.config/sandkasten/trusted_keys/sandkasten.pub

sandkasten run --verify my-profile.toml -- my-cmd
# refuses to launch if the signature doesn't validate against any trusted key
```

Built-in templates ship inside the signed sandkasten binary — they don't need
a sidecar signature and `--verify` ignores them.

## Security model

### What sandkasten enforces, and where

| layer          | macOS                                     | Linux                                                  |
|----------------|-------------------------------------------|--------------------------------------------------------|
| filesystem     | Seatbelt/MACF (kernel)                    | Landlock LSM (5.13+)                                   |
| network (L4)   | Seatbelt `network-outbound/inbound`       | private netns (unshare)                                |
| mach services  | Seatbelt `mach-lookup`                    | —                                                      |
| syscalls       | —                                         | seccomp-BPF deny-list                                  |
| process isol.  | fork inherits sandbox                     | user+pid+ipc+uts namespaces                            |
| privilege      | inherited                                 | `PR_SET_NO_NEW_PRIVS` (planned)                        |

### Threat model

sandkasten is designed to contain:

- **Untrusted code** (from strangers, the internet, build artifacts) running
  as your user.
- **Accidentally malicious tools** — over-eager build scripts, scripts that
  `rm -rf ~` with an unset variable, etc.
- **Reading credential files** — `~/.ssh`, `~/.aws`, keychains, browser
  cookies, `.bash_history`, `.netrc` etc. are flagged and denied in the
  default profiles.

sandkasten is **not** designed to contain:

- **Kernel exploits.** Anything that breaks out of MACF/Landlock/seccomp bypasses us too.
- **Physical access or root escalation attempts** — if the target somehow gains root, the sandbox is gone.
- **Side-channel leakage** — timing attacks, cache covert channels, etc.
- **Apps intentionally wanting to self-sandbox against themselves** — this is
  for sandboxing *other* code.

### Safety posture of the tool itself

- No `unsafe_op_in_unsafe_fn`; FFI-heavy modules have module-level safety
  rationale.
- `clippy` clean at default level + `clippy::undocumented_unsafe_blocks` + `rust_2018_idioms`.
- No destructive filesystem operations in `sandkasten run` — it only `fork` /
  `exec`s. No creating, moving, or deleting files of yours.
- Profile validator rejects non-absolute paths and unknown file-op names.

## Limits

Shipping honestly so nobody gets surprised:

1. **macOS `sandbox_init` is SPI.** It is undocumented by Apple, but has
   been used unchanged since Mac OS X 10.5, sits at the MACF layer, and is
   how every sandboxed macOS browser works. There is no supported
   replacement for third-party binaries.
2. **Modern macOS Seatbelt grammar** rejects IP literals and specific
   hostnames in `remote tcp`/`remote udp` — only `localhost` and `*` are
   accepted. sandkasten widens any user-specified per-IP rule to `*:PORT`
   with an explicit warning. True per-IP outbound filtering on macOS
   requires a userspace proxy.
3. **macOS learn mode (`(trace ...)`)** no longer materializes a trace file
   reliably on modern macOS. The heuristics and profile emitter still work;
   capture quality is best-effort.
4. **macOS kernel-denial capture** only surfaces *default-deny fallthroughs* —
   explicit `(deny ...)` rules match silently by design.
5. **Landlock is allow-list only.** The profile's `deny` list is enforced on
   Linux by *subtree omission*: a path in `deny` under an allowed subtree will
   produce a warning telling you to narrow the allow.
6. **Linux per-IP outbound filtering** is implemented via nftables rules
   applied inside the private netns. Hostnames are resolved at rule-load
   time into A/AAAA records. The child process has `CAP_NET_ADMIN` in the
   user namespace, so rule installation is unprivileged.

   **External connectivity into the netns is not set up by sandkasten**
   — a fresh netns has no interfaces beyond `lo`. Users wanting real
   outbound traffic combine sandkasten with an unprivileged network
   provider (`pasta` from passt-linux, `slirp4netns`, or rootless-podman's
   network stack) that plumbs a veth-like interface into the netns before
   sandkasten applies the policy. The nftables rules then enforce the
   allowlist over whichever connectivity exists.

   Without `nft` on `$PATH`, the netns itself is already a full outbound
   barrier; sandkasten logs a warning and proceeds.

7. **Mock mode (v1)** is a simple content sidecar — `[mocks.files]` entries
   are written to a private tempdir and exposed via `$SANDKASTEN_MOCKS` to
   the sandboxed process. Transparent path interposition (so a program
   opening `/etc/hostname` reads the mock without any app cooperation)
   requires an LD_PRELOAD / DYLD_INSERT_LIBRARIES shim or a Linux
   bind-mount overlay — both on the roadmap.

## Roadmap

- [x] Resource limits (`[limits]` section — cpu, memory, FDs, nproc, file size)
- [x] `--timeout` flag for wall-clock kills
- [x] `PR_SET_NO_NEW_PRIVS` on Linux (defense-in-depth for seccomp)
- [x] Profile signing (minisign verify before apply)
- [x] Mock mode v1 (content sidecar via `$SANDKASTEN_MOCKS`)
- [x] End-to-end sandbox smoke test on Linux CI
- [x] Linux per-IP outbound via nftables inside the netns
- [x] DNS server override + /etc/hosts pinning (transparent on Linux via
      bind-mount; sidecar-exposed on macOS pending interposer)
- [x] Persistent workspace directory (`[workspace]`) — cross-platform
- [x] Linux overlayfs copy-on-write (`[overlay]`)
- [x] Outbound redirects (Linux nftables DNAT) + outbound blocks (cross-platform)
- [x] Protocol coverage: SCTP / DCCP / UDPLite flags + `presets` for
      HTTP(S) / QUIC / RTP / SIP / STUN / WebRTC / SSH / databases /
      mail / chat / NTP / mDNS — ~35 named presets that expand into
      concrete TCP/UDP rules
- [x] `sandkasten shell / diff / explain` — interactive sandboxed shell,
      structural profile diffs, plain-English policy explanations
- [x] Reproducibility fingerprint in `render` output
- [ ] Bundled `pasta` / `slirp4netns` integration for turnkey outbound
- [ ] Transparent mock interposition via LD_PRELOAD / DYLD_INSERT_LIBRARIES
- [ ] Snapshot / restore of the overlayfs upper layer (Linux "time travel")
- [ ] Live policy tightening (SIGHUP reloads; sandbox_init only narrows)
- [ ] Homebrew tap

## License

MIT OR Apache-2.0 at your option.
