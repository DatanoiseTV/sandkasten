#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(
    clippy::all,
    clippy::undocumented_unsafe_blocks,
    clippy::semicolon_if_nothing_returned,
    rust_2018_idioms
)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

mod cli;
mod config;
mod explain;
mod hardware;
mod learn_core;
mod limits;
#[macro_use]
mod log;
mod mocks;
mod net_files;
mod preflight;
mod presets;
mod signing;
mod snapshot;
mod spoofing;
mod templates;
mod ui;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

fn main() -> ExitCode {
    let args = cli::Cli::parse();
    log::set(log::from_flags(args.verbose, args.quiet));
    match run(args) {
        Ok(code) =>
        {
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            ExitCode::from(code.clamp(0, 255) as u8)
        }
        Err(e) => {
            eprintln!("sandkasten: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(args: cli::Cli) -> Result<i32> {
    match args.command {
        cli::Command::Run {
            profile,
            cwd,
            timeout,
            verify,
            argv,
        } => {
            if verify {
                // Verify only applies to on-disk profiles; built-ins ship inside
                // the signed binary itself so are implicitly trusted.
                if templates::builtin(&profile).is_none() {
                    let path = config::resolve_profile_path(&profile)?;
                    let rep = signing::verify(&path)?;
                    log::info(format_args!(
                        "signature ok for {} (key source: {})",
                        rep.profile.display(),
                        rep.key_source
                    ));
                }
            }
            let raw = config::load(&profile)?;
            let ctx = config::ExpandContext::detect(argv.first().map(String::as_str))?;
            let mut prof = config::finalize(raw, &ctx)?;
            // CLI --timeout overrides the profile's value.
            if let Some(t) = timeout.as_deref() {
                prof.limits.wall_timeout_seconds = Some(parse_duration_seconds(t)?);
            }

            // Materialise any [mocks.files] into a tempdir. Also adds that
            // dir to the profile's read set so the sandbox permits reads.
            let mock_handle = mocks::materialise(&mut prof)?;
            if let Some(m) = &mock_handle {
                prof.env
                    .set
                    .insert(m.env_var.0.clone(), m.env_var.1.clone());
                // Also expose it to the *current* process env. Linux child
                // setup (bind-mount of /etc/resolv.conf, /etc/hosts) runs
                // pre-exec and reads this via std::env::var before the
                // new envp is installed by execve.
                // SAFETY: set_var on the current process is safe before any
                // threads are spawned by the main program.
                unsafe {
                    std::env::set_var(&m.env_var.0, &m.env_var.1);
                }
                log::info(format_args!(
                    "mocks materialised at {} ({} files)",
                    m.dir.display(),
                    prof.mocks.files.len()
                ));
            }

            // If the profile defines an overlay, auto-grant Landlock write
            // on both the mount point (so VFS opens are approved) and the
            // upperdir (so overlayfs's kernel-side redirect path is covered).
            if let (Some(lower), Some(upper)) =
                (prof.overlay.lower.clone(), prof.overlay.upper.clone())
            {
                let mount_at = prof.overlay.mount.clone().unwrap_or(lower);
                for p in [mount_at, upper] {
                    if !prof.filesystem.read_write.iter().any(|x| x == &p) {
                        prof.filesystem.read_write.push(p);
                    }
                }
            }

            // Materialise [workspace]: create dir, add to rw, expose via env,
            // optionally chdir.
            let mut effective_cwd = cwd.clone();
            if let Some(ws_path) = prof.workspace.path.clone() {
                let ws = PathBuf::from(&ws_path);
                std::fs::create_dir_all(&ws)
                    .with_context(|| format!("creating workspace {}", ws.display()))?;
                if !prof.filesystem.read_write.iter().any(|p| p == &ws_path) {
                    prof.filesystem.read_write.push(ws_path.clone());
                }
                prof.env
                    .set
                    .insert("SANDKASTEN_WORKSPACE".to_string(), ws_path.clone());
                if prof.workspace.chdir && effective_cwd.is_none() {
                    effective_cwd = Some(ws.clone());
                }
                log::info(format_args!(
                    "workspace: {} (chdir={})",
                    ws.display(),
                    prof.workspace.chdir
                ));
            }

            log::info(format_args!(
                "profile={:?} cwd={} target={}",
                prof.name.as_deref().unwrap_or("?"),
                ctx.cwd.display(),
                argv.first().map_or("?", String::as_str),
            ));
            log::print_summary(&prof);
            let rc = run_sandboxed(&prof, effective_cwd.as_deref(), &argv);
            if let Some(m) = mock_handle {
                let _ = std::fs::remove_dir_all(&m.dir);
            }
            rc
        }
        cli::Command::Init { template, output } => {
            let body = templates::builtin(&template)
                .ok_or_else(|| anyhow!("unknown template: {template}"))?;
            let path = output.unwrap_or_else(|| PathBuf::from("sandkasten.toml"));
            if path.exists() {
                return Err(anyhow!("refusing to overwrite {}", path.display()));
            }
            std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("wrote {} (template: {template})", path.display());
            Ok(0)
        }
        cli::Command::Check { profile } => {
            let raw = config::load(&profile)?;
            let ctx = config::ExpandContext::detect(None)?;
            let p = config::finalize(raw, &ctx)?;
            println!("profile {:?} ok", p.name.as_deref().unwrap_or("?"));
            Ok(0)
        }
        cli::Command::Render { profile } => {
            let raw = config::load(&profile)?;
            let ctx = config::ExpandContext::detect(None)?;
            let p = config::finalize(raw, &ctx)?;
            let rendered = render_policy(&p)?;
            print!("{rendered}");
            // Reproducibility hash: first-12 hex of FNV-1a over the rendered
            // bytes, printed as a trailing line so diffs of policy drift are
            // visible. (FNV-1a keeps our dep list short; swap for SHA-256
            // later if users ask for collision resistance.)
            let h = fnv1a(rendered.as_bytes());
            println!(";; policy-hash: {:016x}", h);
            Ok(0)
        }
        cli::Command::List => {
            list_profiles();
            Ok(0)
        }
        cli::Command::Templates => {
            for (name, desc) in templates::LIST {
                println!("  {name:<16}  {desc}");
            }
            Ok(0)
        }
        cli::Command::Learn {
            base,
            output,
            auto_system,
            cwd,
            argv,
        } => run_learn(&base, output, auto_system, cwd.as_deref(), &argv),
        cli::Command::Ui { port, no_open } => {
            ui::run(port, !no_open)?;
            Ok(0)
        }
        cli::Command::Wrap {
            profile,
            timeout,
            cwd,
            argv,
        } => {
            // Delegate to the Run path with the chosen profile (defaulting
            // to `self`).
            run(cli::Cli {
                command: cli::Command::Run {
                    profile,
                    cwd,
                    timeout,
                    verify: false,
                    argv,
                },
                verbose: args.verbose,
                quiet: args.quiet,
            })
        }
        cli::Command::Shell {
            profile,
            shell,
            cwd,
        } => {
            let raw = config::load(&profile)?;
            let ctx = config::ExpandContext::detect(None)?;
            let mut prof = config::finalize(raw, &ctx)?;
            let sh = shell
                .or_else(|| std::env::var("SHELL").ok())
                .unwrap_or_else(|| "/bin/bash".to_string());
            // Tell the shell which sandbox it's in so users can customise PS1.
            prof.env.set.insert(
                "SANDKASTEN_PROFILE".into(),
                prof.name.clone().unwrap_or_else(|| profile.clone()),
            );
            // Materialise mocks + workspace like `run` does.
            let mock_handle = mocks::materialise(&mut prof)?;
            if let Some(m) = &mock_handle {
                prof.env
                    .set
                    .insert(m.env_var.0.clone(), m.env_var.1.clone());
            }
            let mut effective_cwd = cwd;
            if let Some(ws_path) = prof.workspace.path.clone() {
                let ws = PathBuf::from(&ws_path);
                std::fs::create_dir_all(&ws)
                    .with_context(|| format!("creating workspace {}", ws.display()))?;
                if !prof.filesystem.read_write.iter().any(|p| p == &ws_path) {
                    prof.filesystem.read_write.push(ws_path.clone());
                }
                prof.env.set.insert("SANDKASTEN_WORKSPACE".into(), ws_path);
                if prof.workspace.chdir && effective_cwd.is_none() {
                    effective_cwd = Some(ws);
                }
            }
            log::info(format_args!(
                "profile={:?} shell={} cwd={}",
                prof.name.as_deref().unwrap_or("?"),
                sh,
                effective_cwd
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| ctx.cwd.display().to_string())
            ));
            log::print_summary(&prof);
            let rc = run_sandboxed(&prof, effective_cwd.as_deref(), &[sh]);
            if let Some(m) = mock_handle {
                let _ = std::fs::remove_dir_all(&m.dir);
            }
            rc
        }
        cli::Command::Sshd { profile } => {
            let raw = config::load(&profile)?;
            let ctx = config::ExpandContext::detect(None)?;
            let mut prof = config::finalize(raw, &ctx)?;

            // Materialise mocks + workspace identically to `run`/`shell`.
            let mock_handle = mocks::materialise(&mut prof)?;
            if let Some(m) = &mock_handle {
                prof.env
                    .set
                    .insert(m.env_var.0.clone(), m.env_var.1.clone());
                // SAFETY: pre-fork, single-threaded.
                unsafe {
                    std::env::set_var(&m.env_var.0, &m.env_var.1);
                }
            }
            prof.env.set.insert(
                "SANDKASTEN_PROFILE".into(),
                prof.name.clone().unwrap_or_else(|| profile.clone()),
            );

            // Workspace chdir honoured exactly as in shell/run.
            let mut effective_cwd: Option<PathBuf> = None;
            if let Some(ws_path) = prof.workspace.path.clone() {
                let ws = PathBuf::from(&ws_path);
                std::fs::create_dir_all(&ws).ok();
                if !prof.filesystem.read_write.iter().any(|p| p == &ws_path) {
                    prof.filesystem.read_write.push(ws_path.clone());
                }
                prof.env.set.insert("SANDKASTEN_WORKSPACE".into(), ws_path);
                if prof.workspace.chdir {
                    effective_cwd = Some(ws);
                }
            }

            // sshd sets `$SSH_ORIGINAL_COMMAND` when the user ran
            // `ssh host some-command` — in that case we run it via sh -c.
            // Otherwise the user got an interactive login; spawn their shell.
            let argv: Vec<String> = match std::env::var("SSH_ORIGINAL_COMMAND") {
                Ok(cmd) if !cmd.trim().is_empty() => {
                    log::info(format_args!(
                        "sshd: running forced command under profile {profile:?}"
                    ));
                    vec!["/bin/sh".into(), "-c".into(), cmd]
                }
                _ => {
                    let sh = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
                    log::info(format_args!(
                        "sshd: interactive shell {sh} under profile {profile:?}"
                    ));
                    vec![sh, "-l".into()]
                }
            };
            let rc = run_sandboxed(&prof, effective_cwd.as_deref(), &argv);
            if let Some(m) = mock_handle {
                let _ = std::fs::remove_dir_all(&m.dir);
            }
            rc
        }
        cli::Command::Diff { left, right } => {
            let ctx = config::ExpandContext::detect(None)?;
            let lp = config::finalize(config::load(&left)?, &ctx)?;
            let rp = config::finalize(config::load(&right)?, &ctx)?;
            print!("{}", explain::diff(&lp, &rp));
            Ok(0)
        }
        cli::Command::Snap(sub) => {
            let ctx = config::ExpandContext::detect(None)?;
            // A snapshot is keyed by a short identifier, not a TOML file
            // path. When the user passes the same argument they'd use for
            // `sandkasten run` (which can be a path), derive the key from
            // the profile's `name = ...` field, falling back to the file
            // stem. Keeps the `snap` CLI consistent with `run`.
            let snap_key = |arg: &str, prof: &config::Profile| -> String {
                if let Some(n) = prof.name.as_deref().filter(|n| !n.is_empty()) {
                    return n.to_string();
                }
                std::path::Path::new(arg)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(arg)
                    .to_string()
            };
            match sub {
                cli::SnapCmd::Save(a) => {
                    let prof = config::finalize(config::load(&a.profile)?, &ctx)?;
                    let key = snap_key(&a.profile, &prof);
                    let path = snapshot::save(&prof, &key, &a.name)?;
                    println!("saved to {}", path.display());
                    Ok(0)
                }
                cli::SnapCmd::Load(a) => {
                    let prof = config::finalize(config::load(&a.profile)?, &ctx)?;
                    let key = snap_key(&a.profile, &prof);
                    snapshot::load(&prof, &key, &a.name)?;
                    println!("restored {} for {}", a.name, key);
                    Ok(0)
                }
                cli::SnapCmd::List { profile } => {
                    // Best-effort key resolution — if `profile` parses as a
                    // TOML file we use its `name`, otherwise treat it as the
                    // key directly (same as before).
                    let key = if std::path::Path::new(&profile).exists() {
                        match config::load(&profile).and_then(|p| config::finalize(p, &ctx)) {
                            Ok(p) => snap_key(&profile, &p),
                            Err(_) => profile.clone(),
                        }
                    } else {
                        profile.clone()
                    };
                    for name in snapshot::list(&key)? {
                        println!("{name}");
                    }
                    Ok(0)
                }
            }
        }
        cli::Command::Info => {
            print_info();
            Ok(0)
        }
        cli::Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = cli::Cli::command();
            clap_complete::generate(shell, &mut cmd, "sandkasten", &mut std::io::stdout());
            Ok(0)
        }
        cli::Command::Doctor => {
            let f = preflight::run_all();
            print!("{}", preflight::render(&f));
            if preflight::has_problems(&f) {
                Ok(1)
            } else {
                Ok(0)
            }
        }
        cli::Command::Explain { profile } => {
            let ctx = config::ExpandContext::detect(None)?;
            let p = config::finalize(config::load(&profile)?, &ctx)?;
            print!("{}", explain::explain(&p));
            Ok(0)
        }
        cli::Command::Verify { profile } => {
            if templates::builtin(&profile).is_some() {
                println!("{profile:?} is a built-in template (ships inside the signed sandkasten binary — no separate signature needed)");
                return Ok(0);
            }
            let path = config::resolve_profile_path(&profile)?;
            let rep = signing::verify(&path)?;
            println!(
                "ok: {} verified against key {}",
                rep.profile.display(),
                rep.key_source
            );
            Ok(0)
        }
    }
}

fn run_learn(
    base: &str,
    output: Option<PathBuf>,
    auto_system: bool,
    cwd: Option<&std::path::Path>,
    argv: &[String],
) -> Result<i32> {
    if templates::builtin(base).is_none() {
        let _ = config::resolve_profile_path(base)?;
    }
    let opts = learn_core::Options {
        base: base.to_string(),
        output,
        auto_system,
    };
    #[cfg(target_os = "macos")]
    {
        macos::learn::run(argv, cwd, opts)
    }
    #[cfg(target_os = "linux")]
    {
        linux::learn::run(argv, cwd, opts)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (argv, cwd, opts);
        Err(anyhow!("learn mode not supported on this platform"))
    }
}

#[cfg(target_os = "macos")]
fn run_sandboxed(
    profile: &config::Profile,
    cwd: Option<&std::path::Path>,
    argv: &[String],
) -> Result<i32> {
    let start = std::time::Instant::now();
    let rc = macos::run(profile, cwd, argv)?;
    log::info(format_args!("child exited with code {rc}"));
    if log::at!(log::Level::Trace) {
        // Give the unified log a moment to flush; widen the query window
        // generously so short-lived children are covered.
        std::thread::sleep(std::time::Duration::from_millis(600));
        let window = start.elapsed() + std::time::Duration::from_secs(2);
        let child_pid = macos::last_child_pid();
        macos::denials::show_since(window, child_pid);
    }
    Ok(rc)
}

#[cfg(target_os = "linux")]
fn run_sandboxed(
    profile: &config::Profile,
    cwd: Option<&std::path::Path>,
    argv: &[String],
) -> Result<i32> {
    let rc = linux::run(profile, cwd, argv)?;
    log::info(format_args!("child exited with code {rc}"));
    // On Linux, Landlock denials are not routinely logged. seccomp EPERMs
    // show up in the child's stderr as normal syscall errors. We surface a
    // one-line hint at Trace.
    if log::at!(log::Level::Trace) {
        eprintln!(
            "sandkasten │ Linux: kernel denial logs not captured (Landlock is silent; \
             check journalctl/dmesg for seccomp/audit entries if needed)"
        );
    }
    Ok(rc)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn run_sandboxed(
    _profile: &config::Profile,
    _cwd: Option<&std::path::Path>,
    _argv: &[String],
) -> Result<i32> {
    Err(anyhow!("sandkasten only supports macOS and Linux"))
}

#[cfg(target_os = "macos")]
fn render_policy(p: &config::Profile) -> Result<String> {
    Ok(macos::sbpl::generate(p))
}

#[cfg(target_os = "linux")]
fn render_policy(p: &config::Profile) -> Result<String> {
    Ok(linux::render(p))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn render_policy(_p: &config::Profile) -> Result<String> {
    Err(anyhow!("render not supported on this platform"))
}

/// Parse a simple duration like `30s`, `5m`, `2h`, `150` (seconds) into seconds.
fn parse_duration_seconds(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("empty duration"));
    }
    // Trailing unit: s/m/h/d
    let (num, mult) = if let Some(stripped) = s.strip_suffix('s') {
        (stripped, 1u64)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 60)
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 3600)
    } else if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 86_400)
    } else {
        (s, 1)
    };
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow!("invalid duration {s:?} (expected e.g. 30s, 5m, 2h)"))?;
    n.checked_mul(mult)
        .ok_or_else(|| anyhow!("duration overflow: {s}"))
}

fn print_info() {
    println!("sandkasten {}", env!("CARGO_PKG_VERSION"));
    println!(
        "  platform: {}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let conf = dirs::config_dir().map(|p| p.join("sandkasten"));
    if let Some(c) = &conf {
        println!("  config dir:    {}", c.display());
        println!("  profiles dir:  {}", c.join("profiles").display());
        println!("  trusted keys:  {}", c.join("trusted_keys").display());
        println!("  snapshots dir: {}", c.join("snapshots").display());
    }
    println!();
    println!("built-in templates:");
    for (name, desc) in templates::LIST {
        println!("  {name:<16}  {desc}");
    }
    if let Some(c) = conf {
        let profdir = c.join("profiles");
        if let Ok(rd) = std::fs::read_dir(&profdir) {
            let count = rd
                .flatten()
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("toml"))
                .count();
            println!("\n  user profiles installed: {count}");
        }
        let trusted = c.join("trusted_keys");
        if let Ok(rd) = std::fs::read_dir(&trusted) {
            let count = rd
                .flatten()
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("pub"))
                .count();
            println!("  trusted signing keys:    {count}");
        }
    }
}

/// 64-bit FNV-1a hash. Cheap, no-deps, stable. We use it for the policy-hash
/// fingerprint printed by `render` so users can store the expected hash in
/// their profile or CI config and detect drift.
fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut h = OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

fn list_profiles() {
    println!("built-in templates:");
    for (name, desc) in templates::LIST {
        println!("  {name:<16}  {desc}");
    }
    if let Some(conf) = dirs::config_dir() {
        let dir = conf.join("sandkasten").join("profiles");
        if let Ok(entries) = std::fs::read_dir(&dir) {
            println!("\nuser profiles in {}:", dir.display());
            for e in entries.flatten() {
                let path = e.path();
                if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        println!("  {stem}");
                    }
                }
            }
        }
    }
}
