# Submitting sandkasten to homebrew-core

This file is a checklist + template for when sandkasten is eligible to
be contributed to [Homebrew/homebrew-core](https://github.com/Homebrew/homebrew-core).
Until then, the tap at `DatanoiseTV/homebrew-sandkasten` is the primary
distribution channel and is kept in sync with every tagged release.

## Eligibility — the notability gate

Homebrew-core's [Acceptable Formulae](https://docs.brew.sh/Acceptable-Formulae)
policy requires the software to be *notable*. Confirmed thresholds (from
the maintainer feedback on PR #279268):

- **Third-party submission** (someone other than the project author):
  ≥30 forks **and** ≥30 watchers **and** ≥75 stars
- **Self-submission** (by the project author — this is us):
  ≥90 forks **and** ≥90 watchers **and** ≥225 stars

All three counts must be met; "any one of" is not enough. Check the
current numbers with:

```sh
gh api repos/DatanoiseTV/sandkasten \
  --jq '{stars: .stargazers_count, forks: .forks_count, watchers: .subscribers_count}'
```

**Do not open the PR before all three thresholds are met.** The first
attempt (PR #279268, v0.2.0) was closed within an hour with a polite
"doesn't currently meet the applicable thresholds" comment — no drama,
but a closed PR is still a closed PR. Wait until the counts clear.

## Pre-flight audit

The formula in this directory is already audit-clean. Re-run the audit
against the live tap before submitting to catch anything that drifted:

```sh
brew tap DatanoiseTV/sandkasten
brew audit --strict --online DatanoiseTV/sandkasten/sandkasten
brew test --verbose DatanoiseTV/sandkasten/sandkasten
```

Both commands must exit 0 with no warnings.

## Steps to submit

1. Fork <https://github.com/Homebrew/homebrew-core>.
2. `brew tap --force homebrew/core` (creates a local writable checkout).
3. Copy `packaging/homebrew/sandkasten.rb` into
   `$(brew --repository homebrew/core)/Formula/s/sandkasten.rb`.
4. `brew audit --new --strict --online --git sandkasten` — must pass clean.
5. `brew install --build-from-source sandkasten` — must build on both
   macOS arm64 and x86_64. Use a CI matrix or a cloud runner if you
   don't have both architectures locally.
6. `brew test sandkasten` — must pass.
7. Commit with the message format Homebrew requires:
   ```
   sandkasten <version> (new formula)
   ```
8. Open a PR from your fork. Title: `sandkasten <version> (new formula)`.

## PR description template

Copy this into the PR body, replacing the `<placeholders>`:

```markdown
# sandkasten <version> (new formula)

## What is it

Fast, kernel-enforced application sandbox for macOS and Linux. Uses the
native isolation primitives on each platform (Seatbelt on macOS;
user/mount/pid/net namespaces + Landlock + seccomp-BPF on Linux), so
there is no VM or container runtime dependency.

- Upstream: https://github.com/DatanoiseTV/sandkasten
- License: MIT OR Apache-2.0
- Language: Rust (stable toolchain)

## Notability

- GitHub stars: <N>
- GitHub forks: <N>
- GitHub watchers: <N>

## Checklist

- [x] `brew audit --new --strict --online --git sandkasten` passes
- [x] `brew install --build-from-source sandkasten` succeeds on macOS arm64
- [x] `brew install --build-from-source sandkasten` succeeds on macOS x86_64
- [x] `brew test sandkasten` exercises both `templates` and `doctor`
- [x] Shell completions (bash, zsh, fish) install via
      `generate_completions_from_executable`
- [x] Stable release tagged (current: v<version>)
```

## After merge

- Keep the tap (`DatanoiseTV/homebrew-sandkasten`) in sync for a while —
  users who tapped it already will keep getting updates from there.
- Subsequent version bumps go through the usual `brew bump-formula-pr`
  flow against `Homebrew/homebrew-core`, not the tap.
