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
mod events;
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

    // Auto-route events into a per-run NDJSON file under
    // $SANDKASTEN_EVENTS_DIR if the env var is set and the user hasn't
    // already asked for an explicit --events / --events-file. This is
    // how the optional macOS menu-bar UI subscribes to denial events:
    // it sets the env var in its launch environment, and every
    // sandkasten run from that shell drops events into the directory
    // it's watching. Server / headless users never set the var and see
    // exactly the v0.4.2 behaviour.
    let resolved_events_file: Option<std::path::PathBuf> = args.events_file.clone().or_else(|| {
        if args.events != "none" {
            return None; // user already asked for stderr/stdout — respect it
        }
        let dir = std::env::var_os("SANDKASTEN_EVENTS_DIR")?;
        let dir = std::path::PathBuf::from(dir);
        if dir.as_os_str().is_empty() {
            return None;
        }
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!(
                "sandkasten: SANDKASTEN_EVENTS_DIR={} unusable: {e}",
                dir.display()
            );
            return None; // soft-fail — never break the run for events
        }
        let pid = std::process::id();
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        Some(dir.join(format!("run-{ts_ms}-{pid}.ndjson")))
    });
    // If we synthesised a file from the env var, also flip the format
    // from `none` to `json` so events actually get written.
    let events_format = if resolved_events_file.is_some() && args.events == "none" {
        "json"
    } else {
        args.events.as_str()
    };
    if let Err(e) = events::init(events_format, resolved_events_file.as_deref()) {
        eprintln!("sandkasten: {e:#}");
        return ExitCode::from(2);
    }
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

            // Structured run_start event for SIEM-style consumers
            // (no-op when --events=none, which is the default). The
            // policy hash is the same fingerprint that `render` emits
            // — handy for "did this exact policy run?" auditing.
            let policy_hash = render_policy(&prof)
                .ok()
                .map(|r| format!("{:016x}", fnv1a(r.as_bytes())));
            events::run_start(
                prof.name.as_deref().unwrap_or("(unnamed)"),
                argv.first().map_or("", String::as_str),
                &argv,
                policy_hash.as_deref(),
            );
            let started = std::time::Instant::now();
            let rc = run_sandboxed(&prof, effective_cwd.as_deref(), &argv);
            let wall_ms = started.elapsed().as_millis();
            // Always emit run_end so a downstream pipeline can pair
            // start/end records by pid even on errors.
            let exit_code = rc.as_ref().copied().unwrap_or(127);
            events::run_end(exit_code, wall_ms);

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
        cli::Command::InstallProfiles {
            system,
            user,
            force,
            source,
        } => install_profiles(system, user, force, source.as_deref()),

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
            for (name, desc) in &templates::list() {
                println!("  {name:<16}  {desc}");
            }
            Ok(0)
        }
        cli::Command::Learn {
            base,
            output,
            auto_system,
            yes,
            cwd,
            argv,
        } => run_learn(&base, output, auto_system, yes, cwd.as_deref(), &argv),
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
                events: args.events,
                events_file: args.events_file,
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
    yes: bool,
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
        yes,
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
    // Capture denials when the user asked (-vvv) OR when structured
    // events are enabled — the optional menu-bar UI subscribes to them
    // through the events sink and can't react to anything we don't
    // emit. Always-on capture would be too chatty for plain runs.
    if log::at!(log::Level::Trace) || events::enabled() {
        // Give the unified log a moment to flush; widen the query window
        // generously so short-lived children are covered.
        std::thread::sleep(std::time::Duration::from_millis(600));
        let window = start.elapsed() + std::time::Duration::from_secs(2);
        let child_pid = macos::last_child_pid();
        let print_summary = log::at!(log::Level::Trace);
        let profile_name = profile.name.as_deref().unwrap_or("<inline>");
        macos::denials::show_since(window, child_pid, print_summary, profile_name);
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
    for (name, desc) in &templates::list() {
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
    for (name, desc) in &templates::list() {
        println!("  {name:<16}  {desc}");
    }
    let mut dirs_to_show: Vec<PathBuf> = Vec::new();
    if let Some(d) = config::user_profile_dir() {
        dirs_to_show.push(d);
    }
    dirs_to_show.extend(config::system_profile_dirs());
    for dir in dirs_to_show {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let path = e.path();
                if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                    return None;
                }
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(str::to_string)
            })
            .collect();
        if names.is_empty() {
            continue;
        }
        names.sort();
        println!("\nprofiles in {}:", dir.display());
        for n in names {
            println!("  {n}");
        }
    }
}

/// `sandkasten install-profiles [--system|--user] [--force] [-s <dir>]`.
/// Copies the bundled example profiles (and optionally additional
/// `.toml` files from a source dir) into the chosen profile dir so
/// they can be referenced by bare name.
fn install_profiles(
    system: bool,
    _user: bool, // explicit --user is the default; flag is just for scriptable clarity
    force: bool,
    source: Option<&std::path::Path>,
) -> Result<i32> {
    let dest = if system {
        config::system_install_dir()
    } else {
        config::user_profile_dir()
            .ok_or_else(|| anyhow!("can't determine per-user config dir on this system"))?
    };
    std::fs::create_dir_all(&dest).with_context(|| format!("creating {}", dest.display()))?;

    // Bundled examples are compiled into the binary so install works
    // even on a host that has only the prebuilt tarball, no source tree.
    let mut planned: Vec<(String, Vec<u8>)> = templates::BUNDLED_EXAMPLES
        .iter()
        .map(|(name, body)| (format!("{name}.toml"), body.as_bytes().to_vec()))
        .collect();

    // Optional caller-supplied dir layered on top — files there with
    // the same name override the bundled copy. Useful for organisations
    // that ship a custom profile bundle.
    if let Some(src) = source {
        for entry in std::fs::read_dir(src)
            .with_context(|| format!("reading source dir {}", src.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow!("non-utf8 filename in {}", src.display()))?
                .to_string();
            let body =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            planned.retain(|(n, _)| n != &name);
            planned.push((name, body));
        }
    }

    if planned.is_empty() {
        eprintln!("nothing to install");
        return Ok(0);
    }

    let mut installed = 0usize;
    let mut skipped = 0usize;
    for (name, body) in &planned {
        let target = dest.join(name);
        if target.exists() && !force {
            eprintln!(
                "  skip   {} (already exists; pass --force to overwrite)",
                target.display()
            );
            skipped += 1;
            continue;
        }
        std::fs::write(&target, body).with_context(|| format!("writing {}", target.display()))?;
        eprintln!("  write  {}", target.display());
        installed += 1;
    }

    eprintln!(
        "\ninstalled {installed} profile(s) to {}{}",
        dest.display(),
        if skipped > 0 {
            format!(" ({skipped} skipped)")
        } else {
            String::new()
        }
    );
    if system {
        eprintln!(
            "(system scope — readable by every user on this host; \
             requires `sudo` if you ran into a permission error.)"
        );
    } else {
        eprintln!(
            "next step:  sandkasten run <profile-name> -- <command>\n\
             e.g.        sandkasten run ai-agent -- claude"
        );
    }
    Ok(0)
}
