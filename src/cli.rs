use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum SnapCmd {
    /// Save the profile's overlay upperdir under a named snapshot.
    Save(SnapArgs),
    /// Restore the profile's overlay upperdir from a named snapshot.
    /// Existing upperdir contents are moved aside (to `<upper>.bak-<ts>`).
    Load(SnapArgs),
    /// List snapshots for a profile.
    List { profile: String },
}

#[derive(Args, Debug)]
pub struct SnapArgs {
    pub profile: String,
    pub name: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "sandkasten",
    version,
    about = "Kernel-enforced application sandbox for macOS and Linux",
    long_about = "Run untrusted binaries under a kernel-enforced sandbox.\n\
                  macOS: Seatbelt (sandbox_init SPI).\n\
                  Linux: user+mount+net namespaces, Landlock, seccomp-BPF."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Verbosity. `-v` lifecycle events, `-vv` rule summary, `-vvv` full
    /// generated policy plus kernel denial capture (macOS) after the run.
    #[arg(long, short = 'v', global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress all non-error output (overrides `-v`).
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Emit machine-readable structured events alongside (or instead
    /// of) the human-readable log. Format is newline-delimited JSON:
    /// one event per line, each line a self-contained JSON object
    /// with at minimum `{"event":"...","ts":"<ISO-8601>"}`. Useful
    /// for SIEM / auditd ingest.
    ///
    /// Currently emits `run_start` and `run_end` for each sandbox
    /// invocation (`run`, `wrap`, `shell`, `sshd`); future work
    /// will add `denial` events from kernel-log capture.
    ///
    /// Defaults to `none` (no structured output). `json` writes to
    /// the path given by `--events-file`, or to stderr alongside
    /// the regular log if no file is given.
    #[arg(long, value_name = "FORMAT", value_parser = ["none", "json"], default_value = "none", global = true)]
    pub events: String,

    /// File to write structured events to (only with `--events=json`).
    /// `-` writes to stdout, omitting writes to stderr (default for
    /// `--events=json` without this flag). Append-mode; rotated by
    /// the user / external tooling.
    #[arg(long, value_name = "PATH", global = true)]
    pub events_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run a command under a profile. Use `--` to separate sandkasten args from the command.
    Run {
        /// Profile name (built-in or `~/.config/sandkasten/profiles/<name>.toml`) or path.
        profile: String,

        /// Override the working directory inside the sandbox. Must be allowed by the profile.
        #[arg(long, short = 'C')]
        cwd: Option<PathBuf>,

        /// Wall-clock timeout. Accepts `30s`, `5m`, `2h`. The parent sends
        /// SIGTERM; if the child is still alive 3 s later, SIGKILL. Overrides
        /// the profile's `[limits].wall_timeout_seconds` if set.
        #[arg(long)]
        timeout: Option<String>,

        /// Refuse to run unless the profile's sidecar `.minisig` signature
        /// validates against one of the trusted keys. Ignored for built-in
        /// templates (those ship inside the sandkasten binary).
        #[arg(long)]
        verify: bool,

        /// Command and arguments to run.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },

    /// Verify a profile's minisign signature against the configured trusted keys.
    Verify {
        /// Path or profile name to verify.
        profile: String,
    },

    /// Transparent wrapper: sandbox a command with sensible defaults.
    /// Equivalent to `run self -- <cmd>` unless `--profile` is given.
    ///
    /// Prepend `sandkasten wrap --` in aliases, scripts, CI steps:
    ///     alias npm='sandkasten wrap --profile dev -- npm'
    ///     sandkasten wrap -- ./untrusted-build.sh
    Wrap {
        /// Profile to apply. Defaults to `self`.
        #[arg(long, short = 'p', default_value = "self")]
        profile: String,

        /// Wall-clock timeout.
        #[arg(long)]
        timeout: Option<String>,

        /// Override the working directory inside the sandbox.
        #[arg(long, short = 'C')]
        cwd: Option<PathBuf>,

        /// Command and arguments to run.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },

    /// Drop into an interactive shell inside the sandbox. The child sees
    /// `$SANDKASTEN_PROFILE` set to the active profile name so you can
    /// reference it from `PS1`.
    Shell {
        /// Profile to apply.
        profile: String,
        /// Override the shell (default: `$SHELL`, falling back to `/bin/bash`).
        #[arg(long)]
        shell: Option<String>,
        /// Override working directory.
        #[arg(long, short = 'C')]
        cwd: Option<PathBuf>,
    },

    /// Intended for use as sshd's `ForceCommand`. If `$SSH_ORIGINAL_COMMAND`
    /// is set (the user ran `ssh host some-cmd`) it is executed via
    /// `/bin/sh -c` inside the sandbox; otherwise an interactive shell
    /// is launched.
    ///
    /// Example sshd_config:
    ///     Match User sandboxed
    ///         ForceCommand /usr/local/bin/sandkasten sshd dev
    Sshd {
        /// Profile to apply to every SSH login.
        profile: String,
    },

    /// Structural diff between two profiles — what each grants that the other
    /// does not. Works with built-in names, paths, and user profiles.
    Diff { left: String, right: String },

    /// Plain-English explanation of what a profile allows and denies. Great
    /// for reviewing an unfamiliar profile before running untrusted code.
    Explain { profile: String },

    /// Pre-flight environment check: kernel features, supporting tools,
    /// and OS-specific install commands for anything missing.
    Doctor,

    /// Print summary info about this sandkasten install — version,
    /// config dirs, trusted keys, available templates.
    Info,

    /// Print shell-completion script to stdout.
    /// Usage: `sandkasten completions bash > /etc/bash_completion.d/sandkasten`
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Save or restore the writable state of a profile's overlay upper
    /// layer. Useful for "time-travel" over a sandbox that uses [overlay].
    #[command(subcommand)]
    Snap(SnapCmd),

    /// Write a starter profile to disk.
    Init {
        /// Template to start from.
        #[arg(long, short = 't', default_value = "self")]
        template: String,

        /// Output path. Defaults to ./sandkasten.toml.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Validate a profile without running anything.
    Check { profile: String },

    /// Render a profile to the native policy format (SBPL on macOS) for audit.
    Render { profile: String },

    /// List profiles discoverable on this machine.
    List,

    /// List built-in templates.
    Templates,

    /// Launch the local web UI for browsing / editing profiles.
    Ui {
        /// Port to bind on 127.0.0.1. 0 = pick a free port.
        #[arg(long, default_value_t = 0)]
        port: u16,

        /// Don't auto-open a browser window.
        #[arg(long)]
        no_open: bool,
    },

    /// Run the target with full permissions in trace mode, then interactively
    /// generate a tight profile from what the app actually did. Fully
    /// functional on Linux (strace). macOS 14+ silently disables the
    /// Seatbelt `(trace ...)` directive unless the caller has the
    /// `com.apple.security.sandbox.trace` entitlement (sandbox-exec does
    /// not); this command will emit a clear error rather than produce an
    /// empty profile. Generated TOML is cross-platform — learn on Linux
    /// and run on either.
    Learn {
        /// Base template the generated profile will extend.
        #[arg(long, default_value = "strict")]
        base: String,

        /// Output path for the generated profile. Defaults to ./learned.toml.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Accept system-path reads, /tmp, and known-safe Mach services without prompting.
        #[arg(long)]
        auto_system: bool,

        /// Skip every interactive prompt and auto-accept the widest profile
        /// that captures the observed behaviour. Sensitive paths
        /// (~/.ssh / Keychains / ~/.aws etc.) are still default-denied —
        /// that bucket intentionally stays opt-in. Intended for scripted
        /// / CI use where no tty is available.
        #[arg(long, short = 'y')]
        yes: bool,

        /// Working directory override.
        #[arg(long, short = 'C')]
        cwd: Option<PathBuf>,

        /// Command and arguments to observe.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
}
