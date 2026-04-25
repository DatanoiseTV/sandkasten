# sandkasten — Quick Start

This is the "I just heard about this tool, how do I actually use it"
guide. If you want the full reference, see [the README](../README.md).

## 1. Install

One of:

```sh
# macOS or Linux (Linuxbrew) — prebuilt binary, ~2 s install, no Rust needed:
brew tap DatanoiseTV/sandkasten
brew install sandkasten

# Or bare curl, any system (swap the triple):
curl -sSL \
  https://github.com/DatanoiseTV/sandkasten/releases/latest/download/sandkasten-x86_64-unknown-linux-gnu.tar.gz \
  | tar -xz && sudo install sandkasten-*/sandkasten /usr/local/bin/
```

Available triples: `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`.

Confirm:

```sh
sandkasten --version
sandkasten doctor   # pre-flight — reports anything missing for full functionality
```

On Linux `sandkasten doctor` will tell you to `apt install slirp4netns`
or similar if you want real per-IP outbound filtering under a private
netns. Not required for the sandbox to run; just nicer.

## 2. Your first sandboxed command

```sh
# Run /bin/ls inside the sandbox. The `self` template is the default:
# read the whole filesystem, write only the current directory, no network,
# hard-deny ~/.ssh / ~/.aws / ~/Library/Keychains / shell history / …
sandkasten run self -- /bin/ls
```

Swap `/bin/ls` for anything: `cat`, `python3 script.py`, `node`,
`rg`, your own binary. Arguments after `--` are passed through verbatim.

A few more starter invocations:

```sh
# Same, but using the one-flag shortcut (`wrap` defaults to self):
sandkasten wrap -- /usr/bin/env

# Read-only filesystem, no network, for CLI utilities:
sandkasten run minimal-cli -- awk '{print $1}' data.txt

# Read-only FS + outbound HTTPS/DNS — a typical "download and inspect":
sandkasten run network-client -- curl -sSf https://ipinfo.io/ip

# Permissive dev sandbox — read /, write CWD+TMP, web+ssh+localhost:
sandkasten run dev -- npm install

# Browser, pairs with --no-sandbox so Chromium doesn't nest:
sandkasten run browser -- "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --no-sandbox
```

## 3. Templates at a glance

| template         | read-scope                                              | write-scope    | network                       |
|------------------|----------------------------------------------------------|----------------|--------------------------------|
| `self`           | `/`, minus `~/.ssh` / `~/.aws` / keychains / history    | `${CWD}` only  | none                           |
| `strict`         | minimum to boot a dynamic binary (libc, dyld, …)        | nothing        | none                           |
| `minimal-cli`    | `strict` + `/usr/bin /bin /sbin /usr/local /opt` + CWD  | nothing        | none                           |
| `network-client` | `minimal-cli` + `/etc/ssl` + `$TMPDIR` + DNS resolver   | `$TMPDIR`      | outbound TCP 80/443 + DNS      |
| `dev`            | `/` minus secrets                                        | CWD + TMP + `~/.cache` | HTTPS/SSH/DNS + localhost |
| `browser`        | `/`                                                      | caches + profile dirs | outbound 80/443 + localhost |
| `electron`       | `/`                                                      | Application Support + caches | 80/443 + localhost |

`sandkasten templates` prints the same with the full text descriptions.

## 4. Writing your own profile

Profiles are TOML files. Start from a built-in with `extends`:

```toml
# myprofile.toml
name = "myprofile"
extends = "network-client"

[filesystem]
# ${CWD} and ~ are expanded at run time.
read_write = ["${CWD}"]

# Add per-host outbound on top of what network-client gives you.
[network]
outbound_tcp = ["api.example.com:443"]

# Harden against supply-chain compromise (see step 6):
[process]
block_privilege_elevation = true   # deny exec of sudo / su / doas / pkexec / …
block_setid_syscalls      = true   # also deny setuid/setgid syscalls on Linux
no_w_x                    = false  # enable if target isn't a JIT (V8, LuaJIT, …)
```

Then:

```sh
sandkasten run ./myprofile.toml -- my-command arg1 arg2

# See what the profile actually does in kernel-talk, before running:
sandkasten render ./myprofile.toml

# Plain-English explanation:
sandkasten explain ./myprofile.toml

# Diff two profiles:
sandkasten diff a.toml b.toml
```

## 5. When a run fails

Sandbox denials present as ENOENT, EPERM, or EACCES to the target
program. To see what's actually denied:

```sh
sandkasten -vv run myprofile -- my-command
```

`-vv` emits a rule summary. `-vvv` additionally captures kernel
denial events after the run (on macOS; on Linux, check `journalctl`
or `dmesg`). Common fixes:

- Missing read path — add to `filesystem.read = [...]` or the literal
  file to `filesystem.read_files`.
- Missing outbound — add to `network.outbound_tcp = [...]`.
- Missing Mach service (macOS) — add to `system.mach_services`. If
  you're sandboxing a GUI app and enumerating services is painful,
  set `system.allow_mach_all = true`.
- Something that looks like it should work but doesn't — run
  `sandkasten learn` (see next section).

## 6. `sandkasten learn`: auto-generate a profile

Watch the target do its thing with full permissions, then synthesise
a tight profile from what it actually did:

```sh
# Interactive (Linux; macOS currently can't capture trace under modern
# kernels — see CHANGELOG):
sandkasten learn --base strict -o myapp.toml -- ./myapp --flags

# Non-interactive, accept every observed bucket (except sensitive paths,
# which always stay default-deny):
sandkasten learn --base strict --yes -o myapp.toml -- ./myapp --flags

# Then run with the generated profile:
sandkasten run ./myapp.toml -- ./myapp --flags
```

The generator collapses read-sibling rollups into subpaths, flags
accesses to `~/.ssh` / keychains / etc. as sensitive, and recognises
common protocol presets (e.g. "saw UDP:53 and TCP:443" → emits the
`web` preset).

## 7. Hardening knobs worth knowing

Add to `[process]` in any profile:

```toml
[process]
# Block exec of sudo/su/doas/pkexec/runuser/visudo — useful on hosts
# where the current user has `NOPASSWD: ALL` in sudoers or recently
# entered their password (cached creds). Covers Homebrew, Linuxbrew,
# Snap, /usr/local/bin paths too.
block_privilege_elevation = true

# Seccomp-block setuid/setgid/setreuid/setregid/setresuid/setresgid/
# setfsuid/setfsgid/setgroups. Defense against shellcode that skips
# the named elevation binary. Implied by block_privilege_elevation.
block_setid_syscalls = true

# Memory W^X — forbid mprotect PROT_EXEC on any page that was ever
# writable (Linux 6.3+). Blocks classic shellcode patterns.
# Breaks JITs (V8, LuaJIT, Java HotSpot, PHP JIT), so leave off for
# Node/Python-with-JIT/Java workloads.
no_w_x = true

# Force-disable indirect branch speculation + speculative store
# bypass for this process only (Spectre v2 + v4 mitigations).
# Costs ~2–5 % CPU on branch-heavy code. Opt-in.
mitigate_spectre = true
```

And always-on (no flag): sandkasten unconditionally blocks
`ioctl(_, TIOCSTI, …)` — the classic "inject characters into parent's
controlling terminal" container-escape primitive.

## 8. Wrapping an AI coding agent

Agentic CLI tools (Claude Code, opencode, aider, Continue, Cursor
Agent, …) inherit your full shell environment by default — `~/.ssh`,
`~/.aws`, `GITHUB_TOKEN`, cached sudo creds. A ready-made profile
lives at [`examples/ai-agent.toml`](../examples/ai-agent.toml).

If you installed sandkasten via Homebrew, the example is already on
the search path under `<HOMEBREW_PREFIX>/share/sandkasten/profiles/`,
so:

```sh
# Auth: the profile hard-denies ~/Library/Keychains, so OAuth-tokens-
# stored-in-Keychain agents (Claude Code, Cursor Agent, …) need the
# model API key in the outer env. The profile's env.pass list
# whitelists the major ones (ANTHROPIC_API_KEY, OPENAI_API_KEY, …).
export ANTHROPIC_API_KEY="sk-ant-..."

sandkasten run ai-agent -- claude        # ← bare name, no path needed
sandkasten run ai-agent -- opencode

# Alias so the original name "just works":
alias claude='sandkasten run ai-agent -- claude'
```

> If `claude` hangs at startup with no TUI, it's the Keychain gate —
> set `ANTHROPIC_API_KEY` in the parent shell.

For non-Homebrew installs, drop the bundled examples in once:

```sh
sandkasten install-profiles            # writes to user profile dir
# or, host-wide:
sudo sandkasten install-profiles --system
```

After that, `sandkasten run ai-agent -- claude` resolves the bare
name from the user / `/etc/sandkasten/profiles/` / Homebrew share
path. `sandkasten list` enumerates everything visible.

The profile gives the agent: read-anywhere, write-only-project +
agent-state, outbound to model APIs + GitHub + package registries
only, hard-denied `~/.ssh`/`~/.aws`/keychains/shell-history,
`block_privilege_elevation` + `block_setid_syscalls` so even
prompt-injected tool calls can't `sudo`, `env.pass` whitelisted to
model API keys only (no `GITHUB_TOKEN` / `AWS_*` leakage). Every
shell command the agent fork-execs inherits the same sandbox.

See the README's [matching example](../README.md#sandbox-an-ai-coding-agent-claude-code-opencode-aider-) for the full breakdown of what the profile blocks
and how to tighten it further (stricter outbound, narrower read scope).

## 9. Using it in CI/CD

See the [GitHub Actions and GitLab examples in the README](../README.md#isolate-a-cicd-step-github-actions-example)
for a full wrap of `npm ci` / test runs under a hardened profile. TL;DR:

```yaml
- run: |
    curl -sSL https://github.com/DatanoiseTV/sandkasten/releases/latest/download/sandkasten-x86_64-unknown-linux-gnu.tar.gz \
      | tar -xz
    sudo install sandkasten-*/sandkasten /usr/local/bin/
    cat > ci.toml <<'EOF'
    extends = "network-client"
    [filesystem]
    read_write = [ "${CWD}" ]
    [process]
    block_privilege_elevation = true
    no_w_x                    = true   # if target isn't a JIT
    EOF
    sandkasten run ci.toml -- npm ci && sandkasten run ci.toml -- npm test
```

Gotchas on hosted runners:
- **Use `ubuntu-22.04`, not `ubuntu-latest`.** The 24.04 image ships an
  AppArmor profile that blocks unprivileged user namespaces, which
  sandkasten needs. On 22.04 or self-hosted it works out of the box.
- Optionally `sudo apt-get install -y -qq slirp4netns` for real
  per-IP outbound filtering; without it, outbound profiles fall back
  to sharing the host netns (still secure for FS/syscalls, just no
  per-IP network enforcement).

## 10. Other useful subcommands

```sh
sandkasten templates             # list built-ins
sandkasten init                  # emit a skeleton profile
sandkasten info                  # runtime + capability info
sandkasten shell <profile>       # interactive shell inside the sandbox
sandkasten sshd <profile>        # jail SSH logins; see README
sandkasten snap save|load|list   # time-travel the overlay upperdir
sandkasten verify <profile>      # check the minisign signature
sandkasten completions <shell>   # emit shell completion script
```

That's the whole surface. Everything else — `[spoof]`, `[[filesystem.rewire]]`,
`[hardware]`, `[network.proxy]`, `[workspace]`, `[overlay]` — is in
the [README](../README.md) under *Example use cases* and *Profile schema*.
