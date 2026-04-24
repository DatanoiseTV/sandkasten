# sandkasten

> A fast, kernel-enforced application sandbox for macOS and Linux.
> Describe what a program may touch in TOML; sandkasten enforces it in the kernel.

```
profile.toml ──▶ sandkasten ──▶ fork ─▶ sandbox_init() ─▶ execve(target)
                                          │
                                          ├─ macOS: Seatbelt (MACF, kernel)
                                          └─ Linux: user+mount+pid+ipc+uts[+net] namespaces
                                                    + Landlock LSM
                                                    + seccomp-BPF
                                                    + PR_SET_NO_NEW_PRIVS
                                                    + resource limits (setrlimit)
```

Written in Rust. Single ~2 MB release binary. No daemon, no service, no setuid.
Unprivileged — sandkasten itself never requires root.

## At a glance

- **Kernel enforcement.** macOS calls `sandbox_init`, Linux unshares namespaces
  and installs Landlock + seccomp. All decisions happen in the kernel; zero
  userspace interposition overhead after policy is applied.
- **Portable profiles.** One TOML file works on both platforms. The generators
  pick the right primitive per OS and warn when something's unexpressible.
- **Default deny.** Filesystem, network, Mach services, sysctl, IOKit, IPC —
  all off unless the profile opts in. Templates (`strict`, `minimal-cli`,
  `self`, `dev`, `browser`, `electron`, `network-client`) provide sane starts.
- **Privilege-elevation guardrails.** `process.block_privilege_elevation = true`
  denies exec of `sudo` / `su` / `doas` / `pkexec` / `runuser` / `visudo`
  across macOS and Linux (incl. Homebrew, Linuxbrew, Snap, and
  `/usr/local/bin/...` installs). `process.block_setid_syscalls = true`
  seccomp-denies every setuid/setgid-family syscall on Linux so shellcode
  that skips the named binary can't gain creds either.
- **Interactive OR scripted learning.** `sandkasten learn -- <cmd>` runs the
  target with full permissions while capturing every operation it performs,
  applies heuristics (subtree collapsing, sensitive-path flagging, preset
  detection), and interactively proposes a tight profile. Use `--yes` for
  a non-interactive mode that accepts every bucket (except sensitive paths,
  which always stay default-deny).
- **Honest limits.** Failure modes and platform asymmetries are documented
  inline in the generated policy and in this README. See *Limits*, below.

## Install

### Homebrew (macOS + Linuxbrew)

```sh
brew tap DatanoiseTV/sandkasten
brew install sandkasten
```

The formula installs from prebuilt per-arch tarballs from the GitHub
release — ~2 s wall-clock, no Rust toolchain required. Shell completions
for bash/zsh/fish are installed automatically on the native triples
(arm64-macos, x86_64-linux).

### Direct download

Each release ships tarballs for every `{aarch64,x86_64}-{apple-darwin,
unknown-linux-gnu}` combo plus a versionless alias so generic URLs
work across version bumps. Grab the one for your platform from
<https://github.com/DatanoiseTV/sandkasten/releases/latest> or one-liner it:

```sh
# Linux x86_64 — latest release, auto-resolved server-side, no version pin:
curl -sSL https://github.com/DatanoiseTV/sandkasten/releases/latest/download/sandkasten-x86_64-unknown-linux-gnu.tar.gz \
  | tar -xz && sudo install sandkasten-*/sandkasten /usr/local/bin/

# macOS Apple Silicon:
curl -sSL https://github.com/DatanoiseTV/sandkasten/releases/latest/download/sandkasten-aarch64-apple-darwin.tar.gz \
  | tar -xz && sudo install sandkasten-*/sandkasten /usr/local/bin/
```

Swap the triple for `aarch64-unknown-linux-gnu` (Linux arm64) or
`x86_64-apple-darwin` (Intel Macs). Pin a specific release by
replacing `latest/download/` with `download/<tag>/` and adding the
`<tag>-` prefix to the filename.

### From source

```sh
cargo install --path .
# or
cargo build --release   # → target/release/sandkasten
```

Runtime dependencies: none on either platform — the prebuilt binary
is statically self-contained. Linux optionally *benefits* from `pasta`
(from the `passt` package) or `slirp4netns` for external network
connectivity under a private netns with per-IP `nftables` filtering,
and `strace` for `sandkasten learn`. `sandkasten doctor` prints
distro-tailored install commands for anything missing.

## 60-second tour

```sh
# See what's available
sandkasten templates
sandkasten doctor

# Run /bin/cat sandboxed — only the current directory is writable
sandkasten run self -- /bin/cat README.md

# Write a tight profile interactively by observing what an app does
sandkasten learn --auto-system -o my-tool.toml -- ./my-tool --help

# Pre-flight review before running: explain in plain English
sandkasten explain my-tool.toml

# Structural diff between two profiles
sandkasten diff self dev

# Launch a Chromium-based browser in a throwaway sandbox
sandkasten run browser -- \
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
  --no-sandbox --password-store=basic

# Web UI for editing profiles (local, token-gated)
sandkasten ui
```

## Example use cases

### Run untrusted code from the internet

You just cloned a repo and want to `npm install` without letting it read
`~/.ssh` or exfiltrate your cloud credentials.

```toml
# untrusted.toml
name = "untrusted-npm"
extends = "self"
[filesystem]
read_write = ["${CWD}"]
[network]
allow_dns = true
presets = ["https"]         # TCP 443 outbound for registry
[process]
allow_fork = true
allow_exec = true
[env]
pass = ["PATH", "HOME", "NODE_PATH", "NPM_CONFIG_REGISTRY"]
[limits]
wall_timeout_seconds = 600   # cap install at 10 minutes
memory_mb = 4096
```

```sh
sandkasten run ./untrusted.toml -- npm install
```

`~/.ssh`, `~/.aws`, `~/.gnupg`, keychains, shell history, TCC database are
all inherited-denied from the `self` template. The package script can't
reach them even if it tries — sandbox returns EPERM.

### Block re-exec through sudo / su (defense against cached creds)

```toml
# harder.toml — most hosts have NOPASSWD: ALL sudoers entries for the
# user account at some point. A compromised sandboxed tool could call
# `sudo sh -c 'curl ... | sh'` and escalate to host-root before the
# user notices. This flag denies exec of every named elevation binary
# and, on Linux, also seccomp-denies the setuid-family syscalls so
# shellcode that skips the binary still can't flip creds.
extends = "dev"
[process]
block_privilege_elevation = true   # implies block_setid_syscalls
```

```sh
sandkasten run harder.toml -- ./untrusted-tool
# Inside: `sudo whoami` → sandkasten: execve failed: /usr/bin/sudo errno=1
# `/usr/bin/python3 -c 'import os; os.setuid(0)'` → OSError: EPERM
```

Works symmetrically on macOS (Seatbelt `(deny process-exec ...)`) and
Linux (Landlock exclusion + seccomp). The binary list covers standard
`/usr/bin/`, Homebrew on Apple Silicon, Linuxbrew, Snap, and
`/usr/local/bin/...` for locally compiled installs — not just the
macOS paths.

### Sandbox a Chromium-family browser for a one-off session

```sh
sandkasten run browser -- \
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
  --no-sandbox --password-store=basic
```

The `browser` template grants a broad FS read (so rendering, extensions,
file pickers work), narrow writes (only caches, preferences, Downloads,
Desktop, Documents), every Mach service the browser needs, and **hard
denies** Keychains, SSH keys, cookies, shell history, Mail/Messages
stores, and other browsers' profile directories.

`--no-sandbox` is how you disable Chromium's own inner sandbox — our
outer sandbox is the enforcement layer. `--password-store=basic`
silences the "Encryption is not available" warning that appears when a
browser can't reach the keychain (because we intentionally denied it).

### Jail SSH logins

In `/etc/ssh/sshd_config`:

```
Match User sandboxed
    ForceCommand /usr/local/bin/sandkasten sshd dev
```

Every interactive login by `sandboxed` runs `$SHELL -l` under the `dev`
profile. `ssh sandboxed@host 'some command'` runs the command through
`/bin/sh -c` under the same sandbox — `$SSH_ORIGINAL_COMMAND` is picked
up by `sandkasten sshd`.

### Hook an app that dials hard-coded IPs onto a local service (Linux)

The app pings `1.2.3.4:443` and you want it to hit your local development
server without modifying the binary:

```toml
[[network.redirects]]
from = "1.2.3.4:443"
to   = "127.0.0.1:8443"
protocol = "tcp"

[network]
allow_localhost = true
```

Applied via nftables DNAT inside the sandbox's private netns. The host's
network stack is untouched. For hostname-based apps, prefer
`[network.hosts_entries]` — it works cross-platform and survives TLS SNI.

### Route sandboxed traffic through a VPN (Linux)

sandkasten can **join an existing network namespace** instead of creating
its own. If you've set up WireGuard (or OpenVPN, or any tunnel) in a
named netns, point the profile at it and every byte the sandbox sends
rides the tunnel:

```sh
# one-off setup (root, host)
ip netns add vpn
ip link add wg0 type wireguard
ip link set wg0 netns vpn
ip netns exec vpn wg setconf wg0 /etc/wireguard/wg0.conf
ip netns exec vpn ip addr add 10.0.0.2/24 dev wg0
ip netns exec vpn ip link set wg0 up
ip netns exec vpn ip route add default dev wg0
```

```toml
# profile.toml
[network]
netns_path = "/run/netns/vpn"
allow_dns = true
outbound_tcp = ["*:443"]
```

```sh
sandkasten run profile.toml -- curl https://ifconfig.me
# → reports the VPN endpoint's IP, not yours
```

Sandbox applies as usual on top — Landlock, seccomp, resource limits —
but the kernel routes `connect()` through the VPN. No LD_PRELOAD, no
userspace proxy. Per-IP nftables rules inside this netns still work.

### Controlled hardware identity for testing

A compatibility test suite wants to see a specific CPU, machine-id, DMI
serial, and kernel version:

```toml
[spoof]
cpu_count       = 4                 # sched_setaffinity pins to 4 cores
cpuinfo_synth   = true
cpuinfo_model   = "Intel(R) Xeon(R) E5-2697 v4 @ 2.30GHz"
hostname        = "test-rig-07"
machine_id      = "deadbeefcafebabe0123456789abcdef"
kernel_version  = "Linux version 6.12.0-stable #1 SMP"
kernel_release  = "6.12.0-stable"
os_release      = """
NAME="FleetOS"
VERSION="2025.10"
ID=fleetos
"""

[spoof.dmi]
product_serial = "FLEET-00042"
sys_vendor     = "AcmeCo"
board_name     = "Fleetboard R7"

[[spoof.files]]
path = "/sys/class/net/lo/address"
content = "00:de:ad:be:ef:01"
```

Verified: `nproc` returns 4, `/etc/machine-id` reads the spoofed value,
`/proc/cpuinfo` shows "Sandkasten CPU" (or your override), host files
untouched. See *Limits* for what the kernel syscall `uname` will and
won't let us spoof.

### USB / libusb in a sandbox

```toml
[hardware]
usb    = true
serial = true   # also /dev/ttyUSB* /dev/ttyACM*
```

Linux: grants read+write on `/dev/bus/usb` and read on the udev bits
libusb consults. macOS: grants IOKit + the USB driver family Mach
services.

### Camera / video-device control

```toml
[hardware]
camera = true             # V4L2 (Linux) / AVFoundation (macOS)
screen_capture = true     # PipeWire screencast (Linux) / ScreenCaptureKit (macOS)

[hardware.video]
# Only /dev/video0 is visible; every other /dev/video*, /dev/media*,
# /dev/v4l-subdev* is hidden via an empty bind-mount so enumeration
# returns nothing rather than EPERM.
devices = ["/dev/video0"]

# Redirect: inside the sandbox /dev/video0 actually resolves to the
# host's /dev/video5. Useful for v4l2loopback pipes (feed a fake camera
# stream from a file or another process into /dev/video5, the sandbox
# sees /dev/video0).
redirect = { "/dev/video0" = "/dev/video5" }
```

Linux implements both via the same mount-namespace bind-mount primitive
used by DNS overrides; see `[[filesystem.rewire]]` / `[[filesystem.hide]]`
if you want the raw form. macOS uses the CoreMediaIO + ScreenCaptureKit
Mach services — AVFoundation doesn't route through device nodes, so the
allowlist/redirect is Linux-only there (documented in the emitted
policy).

### Isolated packet capture / port scanning

```toml
extends = "minimal-cli"
[network]
presets = ["nmap"]            # allow_raw_sockets + ICMP + DNS
allow_localhost = true
```

Inside a private netns with `CAP_NET_RAW` you can run `tcpdump` or
`nmap` against loopback or any veth you've plumbed in, without that
activity being visible on the host's interfaces.

### Isolate a CI/CD step (GitHub Actions example)

Dependency installs (`npm install`, `pip install`, `cargo fetch`, …),
untrusted PR test code, and build steps that execute scripts from
third-party packages are the classic supply-chain attack surface on a
CI runner. Wrapping them in sandkasten keeps them off the runner's
credentials, the tokens in `~/.aws` / `~/.docker`, and the rest of the
workspace.

```yaml
# .github/workflows/sandboxed-install.yml
name: sandboxed-install
on: [push]

jobs:
  build:
    runs-on: ubuntu-22.04    # 24.04 ships an AppArmor profile that
                             # blocks unprivileged userns — either use
                             # 22.04, or add `sudo aa-teardown`.
    steps:
      - uses: actions/checkout@v6

      - name: Install sandkasten (prebuilt binary, ~2s — tracks latest)
        run: |
          # Versionless alias resolved server-side → this step stays
          # green across version bumps with no CI edits. Pin a
          # specific release by swapping `latest/download/` for
          # `download/v0.4.0/` and prefixing the filename with the
          # tag, if you want reproducible runs.
          curl -sSL \
            https://github.com/DatanoiseTV/sandkasten/releases/latest/download/sandkasten-x86_64-unknown-linux-gnu.tar.gz \
            | tar -xz
          sudo install sandkasten-*/sandkasten /usr/local/bin/
          # slirp4netns → real outbound + per-IP nftables filtering
          # inside the sandbox. Without it, network-client falls back
          # to host netns (still works, just loses per-IP enforcement).
          sudo apt-get update -qq && sudo apt-get install -y -qq slirp4netns

      - name: `npm install` under a hardened sandbox
        run: |
          # Fresh profile in the workspace dir — no access to host HOME,
          # no ~/.ssh / ~/.aws / ~/.npmrc leakage, only outbound to the
          # npm registry.
          cat > ci.toml <<'EOF'
          name = "ci-npm"
          extends = "network-client"
          [filesystem]
          read_write = [ "${CWD}" ]
          [network]
          outbound_tcp = [
            "*:443",             # registry.npmjs.org et al.
          ]
          [process]
          block_privilege_elevation = true
          block_setid_syscalls      = true
          no_w_x                    = true   # Linux 6.3+; safe for npm
          EOF
          sandkasten run ci.toml -- npm ci --no-audit --no-fund

      - name: Run tests under the same profile
        run: sandkasten run ci.toml -- npm test
```

What this gives you on a standard GitHub hosted runner:

- `package.json` post-install scripts can't reach `~/.npmrc` / `~/.aws` /
  the `GITHUB_TOKEN` env var the runner auto-exports (it's not
  in the profile's `env.pass`).
- Outbound is restricted to TCP 443 — a compromised install can't
  exfiltrate to `curl http://attacker:8080/` or SSH tunnel out.
- `process.block_privilege_elevation` neuters `sudo` even if the
  runner has a passwordless sudoers entry (GitHub's does).
- `no_w_x` blocks the classic "write shellcode into an RW page,
  mprotect it executable, jump to it" pattern.

Self-hosted runners get the same guarantees plus full per-IP
outbound filtering (pasta or slirp4netns plumbs the private netns).
On hosted runners the `network-client` base falls back to host netns
when pasta/slirp4netns isn't installed — network is still reachable,
but per-IP filtering isn't kernel-enforced.

### Isolate a CI/CD step (GitLab CI example)

```yaml
sandboxed-tests:
  image: ubuntu:22.04
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl slirp4netns ca-certificates
    # Versionless alias auto-resolved to the current release — no
    # pipeline bumps needed when sandkasten updates.
    - curl -sSL https://github.com/DatanoiseTV/sandkasten/releases/latest/download/sandkasten-x86_64-unknown-linux-gnu.tar.gz | tar -xz
    - install sandkasten-*/sandkasten /usr/local/bin/
  script:
    - |
      cat > ci.toml <<'EOF'
      extends = "network-client"
      [filesystem]
      read_write = [ "${CWD}" ]
      [process]
      block_privilege_elevation = true
      block_setid_syscalls      = true
      EOF
    - sandkasten run ci.toml -- ./run-untrusted-tests.sh
```

Note on GitLab/self-hosted runners: the `unprivileged_userns_clone`
sysctl must be set to 1 (default on most recent distros). `sandkasten
doctor` reports the value and the distro-specific one-liner to enable
it.

### Drop a throwaway overlay for ephemeral experiments (Linux)

```toml
[overlay]
lower = "/opt/bigapp"                          # read-only base
upper = "~/.sandkasten/overlay/bigapp"         # writes land here
# mount = "/opt/bigapp"  ← default, in-place

[workspace]
path  = "~/.sandkasten/work/bigapp"
chdir = true
```

Writes to `/opt/bigapp/*` don't touch the real base — they land in
`upper`. Snapshot any time:

```sh
sandkasten snap save bigapp before-experiment
# ... do dangerous things inside the sandbox ...
sandkasten snap load bigapp before-experiment  # instant rewind
sandkasten snap list bigapp
```

Previous state is moved aside to `<upper>.bak-<ts>` — nothing is
ever deleted silently.

### HTTP method / URL filtering, header rewrites

sandkasten's enforcement is **L3/L4** — the kernel sees addresses and
ports, not HTTP. For L7 rules (block `DELETE`, rewrite the `Host`
header, add `X-Forwarded-For`, return a synthetic 403 on
`/api/admin/*`) pair sandkasten with a userland proxy. Pattern:

```toml
[network]
allow_dns = true

[network.proxy]
url    = "http://127.0.0.1:8080"     # your mitmproxy / squid / caddy
bypass = ["127.0.0.1", "localhost"]
# restrict_outbound = true           # default — sandbox can ONLY talk
                                     # to the proxy + bypass hosts
```

With `restrict_outbound` on, `outbound_tcp` is auto-narrowed to just
the proxy's `host:port` plus each `bypass` entry. `HTTP_PROXY` /
`HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` (and their lowercase forms)
are set in the sandbox's env. Every URL library the app uses — curl,
libcurl, Go's `net/http`, Python's `requests`, Node's `http` — honours
those env vars.

Then on the proxy side (example mitmproxy addon):

```python
# save as rewrite.py; run: mitmproxy -s rewrite.py --listen-port 8080
from mitmproxy import http

class Rewrite:
    def request(self, flow: http.HTTPFlow) -> None:
        # Block dangerous HTTP verbs.
        if flow.request.method in ("DELETE", "PUT"):
            flow.response = http.Response.make(403, b"blocked by sandkasten+mitmproxy")
            return
        # Rewrite Host + add X-Forwarded-For.
        if "api.prod.example.com" in flow.request.pretty_host:
            flow.request.host = "api.staging.example.com"
        flow.request.headers["X-Forwarded-For"] = "10.0.0.1"

addons = [Rewrite()]
```

The kernel sandbox guarantees the app can't route around the proxy;
the proxy enforces the application-layer policy.

## Command reference

```
sandkasten run <profile> [--timeout 30s] [--verify] [-C <cwd>] -- <cmd> [args...]
sandkasten shell <profile>                 # interactive sandboxed shell, $SANDKASTEN_PROFILE set
sandkasten sshd <profile>                  # for sshd ForceCommand — see Use cases
sandkasten init [--template <name>] [-o <path>]
sandkasten learn [--base <tpl>] [-o <out.toml>] [--auto-system] [--yes|-y] -- <cmd>
sandkasten check <profile>                 # validate without running
sandkasten render <profile>                # print generated policy (+ policy-hash trailer)
sandkasten explain <profile>               # plain-English summary
sandkasten diff <profile> <profile>        # structural diff between two profiles
sandkasten verify <profile>                # minisign signature check
sandkasten snap save|load|list <profile> <name>   # overlay upperdir snapshots
sandkasten list                            # user profiles + built-in templates
sandkasten templates                       # built-in templates + descriptions
sandkasten doctor                          # environment / dependency check
sandkasten ui [--port 4173]                # local web UI
```

Verbosity: default is silent, `-v` adds lifecycle, `-vv` adds a compact
rule summary, `-vvv` adds the full generated policy plus post-run
kernel denial capture (macOS).

## Profile schema

A profile is TOML. Everything is optional. `extends` inherits from a
built-in template; list-valued fields concatenate, scalars prefer the
child, and path variables (`${CWD}`, `${HOME}`, `${EXE_DIR}`, `~`, any
env var) are expanded at run time.

```toml
name        = "my-profile"
description = "What this profile is for"
extends     = "self"

# ── FILESYSTEM ──────────────────────────────────────────────────────────
[filesystem]
allow_metadata_read = true
read             = ["/usr/lib", "/System"]
read_write       = ["${CWD}", "/tmp"]
read_files       = ["/etc/hosts"]
read_write_files = ["/dev/null", "/dev/tty"]
deny             = ["${HOME}/.ssh"]
hide             = ["/etc/shadow"]      # Linux: tmpfs/dev-null bind-mount
                                         # macOS: emits SBPL deny

# Fine-grained ops per path. Tokens: read, write, create, delete, rename,
# chmod, chown, xattr, ioctl, exec, all, write-all.
[[filesystem.rules]]
path    = "${CWD}/important.log"
literal = true
allow   = ["read", "write"]
deny    = ["delete", "chmod"]

# Linux: symbolic-path substitution via bind-mount in the mount namespace.
[[filesystem.rewire]]
from = "/etc/resolv.conf"
to   = "${CWD}/my-resolv.conf"

# ── NETWORK ─────────────────────────────────────────────────────────────
[network]
allow_localhost    = true
allow_dns          = true
allow_inbound      = false
allow_icmp         = false
allow_icmpv6       = false
allow_sctp         = false
allow_dccp         = false
allow_udplite      = false
allow_raw_sockets  = false     # AF_INET/SOCK_RAW — packet-crafting
allow_unix_sockets = true      # AF_UNIX — Chromium/Electron/docker need this
outbound_tcp       = ["*:443", "example.com:8080", "10.0.0.5:22"]
outbound_udp       = []
inbound_tcp        = []
inbound_udp        = []
extra_protocols    = []        # additional `meta l4proto X` on Linux
presets            = ["https", "ssh", "postgres"]   # see table below

[network.dns]
servers = ["1.1.1.1", "9.9.9.9"]
search  = ["corp.internal"]
options = ["edns0", "rotate"]

[network.hosts_entries]
"api.test.lan" = "127.0.0.1"

# Linux-only DNAT
[[network.redirects]]
from = "1.2.3.4:443"
to   = "127.0.0.1:8443"
protocol = "tcp"

# Outbound blocks. Linux: nftables REJECT. macOS: SBPL deny (Seatbelt
# grammar widens specific hosts to `*:PORT` — documented in the render).
[[network.blocks]]
host = "tracking.example.com"
port = "*"

# ── PROCESS / SYSTEM / ENV ──────────────────────────────────────────────
[process]
allow_fork                 = true
allow_exec                 = true
allow_signal_self          = true
# Block exec of sudo/su/doas/pkexec/runuser/visudo/sudoedit from inside
# the sandbox. Useful when the host user has `NOPASSWD: ALL` sudoers or
# cached credentials — without this, a compromised tool inside the
# sandbox could re-exec through sudo and escape back to host-root. The
# binary list covers the standard *nix paths (`/usr/bin/sudo`,
# `/usr/sbin/visudo`, `/usr/libexec/doas`, …) and the common extras:
# Homebrew (macOS), Linuxbrew and Snap (Linux), and `/usr/local/bin/…`
# for locally-compiled installs. Implies `block_setid_syscalls`.
block_privilege_elevation  = false
# Block the setuid-family syscalls (setuid/setgid/setreuid/setregid/
# setresuid/setresgid/setfsuid/setfsgid/setgroups) via seccomp on Linux.
# Defense against shellcode that tries to change credentials directly
# without invoking a named elevation binary. Linux-only; macOS is
# already prevented from honouring setuid bits inside the sandbox at
# the kernel MAC layer.
block_setid_syscalls       = false
# Memory W^X: forbid mprotect(..., PROT_EXEC) on any page that was
# ever writable (Linux 6.3+, PR_SET_MDWE). Blocks the entire "write
# shellcode, flip to executable, jump to it" exploit class. Breaks
# JITs (V8, LuaJIT, Java HotSpot, PHP JIT, ...) — opt-in.
no_w_x                     = false
# Force-disable indirect branch speculation (Spectre v2) and
# speculative store bypass (Spectre v4 / SSBD) for the sandboxed
# process via PR_SET_SPECULATION_CTRL. Mitigates speculative side
# channels reachable from inside the sandbox. Costs ~2-5% CPU. Opt-in.
mitigate_spectre           = false

[system]
allow_sysctl_read = true
allow_iokit       = false
allow_ipc         = false
allow_mach_all    = false     # macOS: broad; needed by browsers/Electron
mach_services     = ["com.apple.system.logger"]

[env]
pass_all = false
pass     = ["PATH", "HOME", "LANG"]
set      = { }                # { KEY = "value" } to override

# ── RESOURCE LIMITS (POSIX setrlimit + wall-clock watchdog) ─────────────
[limits]
cpu_seconds          = 60
memory_mb            = 1024
file_size_mb         = 100
open_files           = 512
processes            = 64
stack_mb             = 8
core_dumps           = false
wall_timeout_seconds = 300

# ── HARDWARE ACCESS ─────────────────────────────────────────────────────
[hardware]
usb    = true     # /dev/bus/usb + udev (Linux) / USB Mach services (macOS)
serial = true     # /dev/tty* nodes
audio  = true     # ALSA / PulseAudio (Linux), CoreAudio (macOS)
gpu    = true     # /dev/dri (Linux), Metal (macOS)
camera = true     # V4L2 (Linux), AVFoundation (macOS)

# ── IDENTITY SPOOFING (Linux fully, macOS limited) ──────────────────────
[spoof]
cpu_count        = 4
cpuinfo_synth    = true
cpuinfo_model    = "CustomCPU 2.0"
cpuinfo_mhz      = 3200
hostname         = "rig-42"
machine_id       = "deadbeefcafe1234deadbeefcafe5678"
kernel_version   = "Linux version 6.12.0-stable #1 SMP"
kernel_release   = "6.12.0-stable"
os_release       = """NAME="FleetOS"\nVERSION="2025.10"\nID=fleetos\n"""
issue            = "Welcome to FleetOS\n"
hostid_hex       = "deadbeef"
timezone         = "Etc/UTC"
efi_platform_size = 64
efi_enabled       = false   # hide /sys/firmware/efi entirely
temperature_c     = 42      # bind-mount millicelsius over all thermal/hwmon temps

[spoof.dmi]
product_serial = "ABC123"
sys_vendor     = "AcmeCo"
board_name     = "Fleetboard R7"

[[spoof.files]]
path    = "/sys/class/net/lo/address"
content = "00:de:ad:be:ef:01"

# ── OVERLAY / WORKSPACE / MOCKS ─────────────────────────────────────────
[workspace]
path  = "~/.sandkasten/work/${NAME}"   # auto-created, added to rw,
                                        # exposed as $SANDKASTEN_WORKSPACE
chdir = true

[overlay]                # Linux kernel ≥5.11 (unprivileged overlayfs)
lower = "/opt/myapp"
upper = "~/.sandkasten/overlay/myapp"
# mount = "/opt/myapp"   ← default

[mocks]                  # v1: content sidecar via $SANDKASTEN_MOCKS
files = { "config.json" = '{"api":"local"}' }
```

### Built-in templates

| template         | what it gives you                                                         |
|------------------|---------------------------------------------------------------------------|
| `self`           | **Default.** Read across `/`, read+write only `${CWD}`, hard-deny secrets |
| `strict`         | Near-zero permissions — minimal base every dynamically-linked binary needs|
| `minimal-cli`    | `strict` + `/usr/bin /bin /sbin /usr/local /opt` + CWD readable           |
| `network-client` | `minimal-cli` + outbound TCP 80/443 + DNS + `$TMPDIR` + `/var/run/resolv.conf`. |
| `dev`            | Permissive. Read `/`, write CWD/TMP, HTTPS/SSH/DNS + localhost. Denies user secrets. |
| `browser`        | Chromium-family browsers (macOS + Linux). Pair with `--no-sandbox`.       |
| `electron`       | Electron apps (VS Code, Slack, Discord, Obsidian, …). Grants write on `~/Library/Application Support` (macOS). |

### Network presets

Named protocol/service bundles. Expand into concrete TCP/UDP outbound
rules at profile-load time.

| group     | presets                                                          |
|-----------|------------------------------------------------------------------|
| Web       | `http`, `https`, `quic`, `web`                                   |
| Realtime  | `rtp`, `sip`, `stun`, `webrtc`                                   |
| VPN       | `wireguard`, `wireguard-all-udp`, `openvpn`, `tailscale`, `ipsec`|
| Remote    | `ssh`, `rdp`, `vnc`                                              |
| Mail      | `smtp`, `smtps`, `imap`, `imaps`, `pop3`, `pop3s`                |
| Files     | `ftp`, `ftps`, `sftp`, `git`                                     |
| Auth      | `ldap`, `ldaps`, `kerberos`                                      |
| Databases | `mysql`, `postgres`, `redis`, `memcached`, `mongodb`, `cassandra`, `elastic` |
| Chat      | `irc`, `ircs`, `xmpp`, `matrix`, `mqtt`, `mqtts`                 |
| Time      | `ntp`, `mdns`, `dhcp`, `dns`                                     |
| Games     | `minecraft`, `minecraft-bedrock`, `steam`, `source-engine`, `quake3`, `teamspeak`, `discord-voice`, `riot-games` |
| Diag      | `ping`, `tcpdump`, `pcap`, `wireshark`, `nmap`                   |

## Web UI

```
sandkasten ui
╭─ sandkasten UI ─────────────────────────────────────────
│  http://127.0.0.1:46513/?t=<random-token>
│  profiles directory: ~/.config/sandkasten/profiles
│  Ctrl-C to stop.
╰─────────────────────────────────────────────────────────
```

Binds only to `127.0.0.1`. 128-bit random bearer token required on every
`/api/*` request. Mutating requests (PUT/DELETE) additionally require the
`Origin` header to match the bound host — belt-and-braces CSRF guard on
top of the token. Body size capped at 64 KB; path names restricted to
`[a-zA-Z0-9_-]+`; writes confined to `~/.config/sandkasten/profiles/`.
Tight CSP, `X-Frame-Options: DENY`, `no-sniff`, `no-referrer`,
`Permissions-Policy` disabling camera/mic/geo.

Features: structured form per profile section, TOML tab for raw edit,
fine-grained rule editor, client-side validation (paths, endpoints,
env names, Mach services), duplicate / save-as flow for built-in
templates, non-system modal dialogs, toast notifications.

**No `run` endpoint.** The UI edits profiles only — you launch them
from your shell. Keeps the attack surface small.

## Profile signing

sandkasten verifies minisign ed25519 signatures — same format as
Jedisct1's `minisign` CLI (`brew install minisign`, `apt install
minisign`).

```sh
minisign -G -p sandkasten.pub -s sandkasten.key    # one-off key pair
minisign -Sm my.toml -s sandkasten.key             # sign → my.toml.minisig

# Install trusted key:
mkdir -p ~/.config/sandkasten/trusted_keys
cp sandkasten.pub ~/.config/sandkasten/trusted_keys/

sandkasten verify my.toml
# → ok: my.toml verified against key ~/.config/sandkasten/trusted_keys/sandkasten.pub

sandkasten run --verify my.toml -- my-cmd
# refuses to launch if the signature doesn't validate
```

Built-in templates ship inside the signed binary — they skip `--verify`.

## Security model

### What sandkasten enforces

| layer          | macOS                              | Linux                                          |
|----------------|------------------------------------|------------------------------------------------|
| Filesystem     | Seatbelt / MACF (kernel)           | Landlock LSM (5.13+) + mount-ns bind-mounts    |
| Network (L4)   | Seatbelt `network-outbound/inbound`| private netns (unshare) + nftables in-netns    |
| Mach services  | `mach-lookup` predicate            | — (not applicable)                             |
| Syscalls       | —                                  | seccomp-BPF deny-list                          |
| Process        | fork inherits sandbox              | user+pid+ipc+uts namespaces                    |
| Privilege      | inherited                          | `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE=0`     |
| Resources      | `setrlimit`                        | `setrlimit`                                    |

### Threat model — what it's for

- **Untrusted code** (from strangers, the internet, third-party build
  scripts, CI jobs) running as your user.
- **Over-eager tools** — build systems, package managers, test runners
  that might glob-delete or exfiltrate by accident.
- **Credential hygiene.** Templates default-deny `~/.ssh`, `~/.aws`,
  `~/.gnupg`, `~/.docker`, `~/.kube`, `~/.netrc`, `~/.password-store`,
  macOS Keychains, the TCC database, shell history, mail, messages,
  cookies, other browsers' profile dirs.

### Threat model — what it is **not** for

- **Kernel exploits.** Anything that breaks out of MACF / Landlock /
  seccomp bypasses us too.
- **Root escalation.** If the target finds a way to root, the sandbox
  ends. `PR_SET_NO_NEW_PRIVS` rules out setuid escalation; kernel
  vulns are not in scope.
- **Side-channel leakage.** Timing attacks, cache-based covert
  channels, Meltdown/Spectre class bugs.
- **Airtight hardware-identity hiding.** `[spoof]` replaces user-space
  views of `/proc`, `/sys`, `/etc/*` — it does not patch the `CPUID`
  instruction, `uname(2)` syscall fields the kernel fills,
  `_SC_NPROCESSORS_ONLN` (which reads `/sys/devices/system/cpu/online`
  unless Go/Rust/num_cpus honours affinity, which most do), or
  userland that reads `/dev/kmsg`. It's a faithful view for most
  tools; it's not a VM.

### Anti-breakout measures

- **`PR_SET_NO_NEW_PRIVS`** blocks setuid-elevation from within the sandbox.
- **`PR_SET_DUMPABLE=0`** disables core dumps (no memory spill on
  crash) and makes the process non-ptrace-attachable from peers.
- Seccomp deny-list includes `link`/`linkat`/`symlink`/`symlinkat`
  (hardlink-into-writable-area escape), `name_to_handle_at` /
  `open_by_handle_at` (reopen via handle across mount ns), `io_uring_*`
  (high-churn attack surface), `userfaultfd`, clock-manipulation
  syscalls, kernel-admin syscalls (mount / pivot_root / chroot /
  unshare / setns / reboot / module ops), `ptrace` and process-memory
  introspection, `keyctl` / `add_key` / `request_key`,
  `perf_event_open`, `bpf`, NUMA memory-move primitives.
- Landlock writes are path-based; hardlink creation is blocked so an
  attacker can't pull a denied file into the writable area.

## Limits

Shipped honestly — nothing hidden.

1. **macOS `sandbox_init` is SPI.** Undocumented by Apple but stable in
   practice — the mechanism every sandboxed macOS browser uses.
2. **Modern macOS Seatbelt grammar** rejects IP literals and specific
   hostnames in `remote tcp/udp` — only `localhost` and `*` are
   accepted. sandkasten widens specific-host rules to `*:PORT` with an
   explicit NOTE in the rendered policy. Per-IP outbound filtering on
   macOS needs a userspace proxy.
3. **macOS kernel denial capture** (the `-vvv` post-run summary) only
   surfaces default-deny fallthroughs — explicit `(deny …)` rules are
   silent by design in Seatbelt.
4. **Landlock is allow-list only.** A `deny` inside a broader allow
   emits a warning and is not enforced on Linux; narrow the allow
   instead.
5. **Linux network plumbing.** A fresh netns has no interfaces beyond
   `lo`, so for outbound profiles sandkasten auto-detects and uses
   `pasta` (from the `passt` package) or `slirp4netns` to bridge the
   private netns to the host network. `nftables` rules then enforce
   per-IP policy inside the plumbed netns without touching the host.
   If neither tool is installed (or `pasta` is AppArmor-confined on
   Debian/Ubuntu, which we detect), sandkasten falls back to sharing
   the host netns — internet still works, but per-IP filtering is
   not kernel-enforced. `sandkasten render <profile>` names the
   active mode explicitly.
6. **Mock mode v1 is a content sidecar.** `[mocks.files]` materialises
   to `$SANDKASTEN_MOCKS`. Transparent path interposition (so a
   program opening `/etc/hostname` reads the mock without
   cooperation) requires an LD_PRELOAD / DYLD_INSERT_LIBRARIES shim —
   planned.
7. **FreeBSD support is not shipped.** Unprivileged full-kernel
   sandboxing on FreeBSD really does require jail(2) + root.
8. **Overlay + Landlock interaction.** Overlayfs mounts cleanly in a
   user namespace, but Landlock's pre-opened PathFds may target
   the lower-layer inode rather than the merged inode on some
   kernels. Auto-adding the mount-point path to `read_write` works on
   recent 6.x kernels; on older ones writes may still see EACCES.

## Disclaimer

**sandkasten is provided AS-IS, without warranty of any kind,** express
or implied, including but not limited to merchantability, fitness for a
particular purpose, and non-infringement. In no event shall the authors
be liable for any claim, damages, or other liability, whether in an
action of contract, tort, or otherwise, arising from, out of, or in
connection with the software or its use.

**Use on systems and against data you are authorised to operate on.** The
network-filtering, redirection, packet-capture, identity-spoofing, and
tracing features are offered for legitimate use — sandboxing untrusted
code on your own machines, testing compatibility with custom identities
in environments you control, hardening SSH sessions on hosts you
administer, and similar. Deploying them against systems without
authorisation, circumventing licence enforcement, impersonating
customers or users, or concealing the provenance of network traffic for
the purpose of abuse is explicitly not supported and may violate local
law. The authors accept no responsibility for misuse.

**sandkasten is not a substitute for a formally reviewed security
product.** Kernel vulnerabilities bypass MACF, Landlock and seccomp.
Side channels are not addressed. `[spoof]` presents a plausible
user-space view, not a virtualised environment; determined
fingerprinting will still identify the real host via unspoofed
channels (CPUID instruction, TSC behaviour, unspoofed `/proc`/`/sys`
entries, GPU capabilities, network RTT, etc.).

## License

Dual-licensed under **MIT** or **Apache-2.0** at your option.

- [`LICENSE-MIT`](LICENSE-MIT)
- [`LICENSE-APACHE`](LICENSE-APACHE)

## Roadmap

- [x] Resource limits, `--timeout`, `PR_SET_NO_NEW_PRIVS`
- [x] Profile signing (minisign verify before apply)
- [x] Per-IP outbound on Linux via nftables inside the netns
- [x] DNS override + `/etc/hosts` pinning (transparent on Linux via
      bind-mount; sidecar on macOS)
- [x] Persistent `[workspace]` + Linux `[overlay]` + `sandkasten snap`
- [x] `[spoof]` — CPU, DMI, machine-id, kernel identity, thermal, EFI,
      arbitrary `[[spoof.files]]` bind-mounts
- [x] `[hardware]` — USB / serial / audio / GPU / camera presets
- [x] `[[filesystem.rewire]]`, `[[filesystem.hide]]`
- [x] Protocol coverage: SCTP / DCCP / UDPLite + 35 service presets
      including WireGuard, Tailscale, Steam, Minecraft, Riot, etc.
- [x] `sandkasten shell / sshd / diff / explain / doctor / snap`
- [x] Reproducibility fingerprint in `render`
- [x] End-to-end Linux smoke test in CI
- [x] Bundled `pasta` / `slirp4netns` auto-integration for turnkey
      Linux outbound, with per-IP nftables filtering enforced inside
      the plumbed netns; AppArmor-aware fallback to host netns.
- [x] Homebrew tap published at `DatanoiseTV/sandkasten`; prebuilt
      per-arch binaries (~2 s install, no Rust build-dep).
- [x] Always-on TIOCSTI seccomp block (ioctl-arg conditional deny).
- [x] Opt-in `process.no_w_x` (PR_SET_MDWE memory W^X) and
      `process.mitigate_spectre` (PR_SET_SPECULATION_CTRL for
      Spectre v2 + SSBD) on Linux.
- [x] `process.block_privilege_elevation` + `process.block_setid_syscalls`
      (sudo/su/doas/pkexec exec deny across macOS + Linux + Homebrew +
      Linuxbrew + Snap; seccomp setid-family deny).
- [x] `sandkasten learn --yes` non-interactive capture for scripts / CI.
- [x] Weekly Dependabot-grouped dependency updates (cargo + swift +
      github-actions).
- [ ] Transparent mock interposition via `LD_PRELOAD` /
      `DYLD_INSERT_LIBRARIES`.
- [ ] Live policy reload (SIGHUP → re-apply; sandbox_init only narrows).
