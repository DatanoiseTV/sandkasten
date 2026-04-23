use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    Check {
        profile: String,
    },

    /// Render a profile to the native policy format (SBPL on macOS) for audit.
    Render {
        profile: String,
    },

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
    /// generate a tight profile from what the app actually did. macOS only.
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

        /// Working directory override.
        #[arg(long, short = 'C')]
        cwd: Option<PathBuf>,

        /// Command and arguments to observe.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
}
