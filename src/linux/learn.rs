//! Linux capture driver for `learn` mode.
//!
//! Linux has no direct analogue of SBPL's `(trace ...)` — the closest
//! unprivileged option is strace with `-f -e trace=%file,%network`. We spawn
//! the target under strace, tee its own stdout/stderr through, and parse the
//! strace log from the tempfile afterwards.
//!
//! Limits:
//!   * strace adds ~10-30× overhead. Don't use this for perf benchmarks.
//!   * Binaries that detect ptrace and refuse to run (some DRM / anti-debug)
//!     will not cooperate. Run them under `sandkasten run <profile>` instead.
//!   * Requires /proc/sys/kernel/yama/ptrace_scope ≤ 1.

use crate::learn_core::{self, Op, Options};
use anyhow::{anyhow, Context, Result};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run(argv: &[String], cwd: Option<&Path>, opts: Options) -> Result<i32> {
    if argv.is_empty() {
        return Err(anyhow!("no command to observe"));
    }
    if which("strace").is_none() {
        return Err(anyhow!(
            "learn mode on Linux requires `strace` — install with \
             `apt install strace` / `dnf install strace` / `pacman -S strace`"
        ));
    }

    let log_path = temp_path("sandkasten-strace", "log")?;

    eprintln!("── sandkasten learn ─────────────────────────────────────────────");
    eprintln!(" recording operations via strace to  {}", log_path.display());
    eprintln!(" the target runs WITH FULL PERMISSIONS during this capture.");
    eprintln!("─────────────────────────────────────────────────────────────────\n");

    let mut cmd = Command::new("strace");
    cmd.args([
        "-f",
        "-o",
        log_path.to_string_lossy().as_ref(),
        "-e",
        "trace=%file,%network,execve,fork,clone,clone3",
        "-y", // print fd paths
        "-s",
        "512", // longer strings
        "--",
    ]);
    cmd.args(argv);
    if let Some(c) = cwd {
        cmd.current_dir(c);
    }

    let status = cmd.status().context("spawning strace")?;
    let exit = status.code().unwrap_or(128 + status.signal().unwrap_or(0));
    eprintln!("\nsandkasten: target exited with code {exit}");

    let ops = parse_strace(&log_path)
        .with_context(|| format!("parsing strace log {}", log_path.display()))?;
    let _ = std::fs::remove_file(&log_path);

    let cwd_abs = cwd
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    learn_core::process(ops, &cwd_abs, &opts)
}

/// Parse an `strace -f -y -e trace=%file,%network` log into `Op`s.
fn parse_strace(path: &Path) -> Result<BTreeSet<Op>> {
    let f = std::fs::File::open(path)?;
    let mut out = BTreeSet::new();
    for line in BufReader::new(f).lines() {
        let Ok(line) = line else { continue };
        if let Some(op) = parse_strace_line(&line) {
            out.insert(op);
        }
    }
    Ok(out)
}

/// Single strace line parser. We look for known syscalls and extract their
/// first path or sockaddr argument. Lines from `strace -f` are prefixed with a
/// PID; we strip it. Lines continuing from a previous interruption
/// (`<unfinished ...>`, `<... foo resumed>`) are skipped or re-joined.
fn parse_strace_line(raw: &str) -> Option<Op> {
    // Strip "[pid NNNN] " or "NNNN " prefix from -f output.
    let line = raw
        .trim_start()
        .trim_start_matches(|c: char| c == '[')
        .trim_start_matches("pid ")
        .trim_start();
    let line = match line.find(']') {
        Some(i) if line.starts_with(char::is_numeric) || line.starts_with("pid") => &line[i + 1..],
        _ => line,
    };
    let line = line.trim_start();
    let first_digit_nondigit = line
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| i)
        .unwrap_or(0);
    let line = if first_digit_nondigit > 0 && line.as_bytes().get(first_digit_nondigit) == Some(&b' ') {
        &line[first_digit_nondigit + 1..]
    } else {
        line
    };

    // skip continuation/resume markers
    if line.contains("<unfinished ...>") || line.contains("resumed>") {
        return None;
    }

    let paren = line.find('(')?;
    let sys = line[..paren].trim();
    let args = &line[paren + 1..];

    // Cheap check: only process lines that ended with " = <result>" — i.e.
    // completed syscalls. Skip signal lines etc.
    if !line.contains(" = ") {
        return None;
    }

    // Detect "= -1 ENOENT" and skip — we only record successful ops.
    if let Some(eq) = line.rfind(" = ") {
        let tail = &line[eq + 3..];
        if tail.trim_start().starts_with('-') && tail.contains(' ') {
            return None;
        }
    }

    match sys {
        // File reads
        "openat" | "open" | "access" | "faccessat" | "faccessat2" | "stat"
        | "lstat" | "fstatat" | "newfstatat" | "readlink" | "readlinkat"
        | "getxattr" | "lgetxattr" | "statx" => {
            first_quoted_arg(args).map(|p| {
                let is_write = sys == "openat" && args.contains("O_WRONLY")
                    || sys == "openat" && args.contains("O_RDWR")
                    || sys == "openat" && args.contains("O_CREAT")
                    || sys == "open" && args.contains("O_WRONLY")
                    || sys == "open" && args.contains("O_RDWR")
                    || sys == "open" && args.contains("O_CREAT");
                if is_write {
                    Op::FileWrite(PathBuf::from(p))
                } else if matches!(
                    sys,
                    "stat" | "lstat" | "fstatat" | "newfstatat" | "statx" | "access" | "faccessat" | "faccessat2"
                ) {
                    Op::FileReadMeta(PathBuf::from(p))
                } else {
                    Op::FileRead(PathBuf::from(p))
                }
            })
        }

        // File writes / mutations
        "creat" | "mkdir" | "mkdirat" | "unlink" | "unlinkat" | "rename"
        | "renameat" | "renameat2" | "chmod" | "fchmodat" | "chown"
        | "lchown" | "fchownat" | "utime" | "utimes" | "utimensat"
        | "setxattr" | "lsetxattr" | "removexattr" | "lremovexattr"
        | "truncate" | "link" | "linkat" | "symlink" | "symlinkat" => {
            first_quoted_arg(args).map(|p| Op::FileWrite(PathBuf::from(p)))
        }

        // Network — extract sockaddr string from connect/bind
        "connect" => parse_sockaddr(args).map(|(p, e)| Op::NetOutbound {
            proto: p,
            endpoint: e,
        }),
        "bind" => parse_sockaddr(args).map(|(p, e)| Op::NetBind {
            proto: p,
            endpoint: e,
        }),

        // exec
        "execve" | "execveat" => first_quoted_arg(args).map(|p| Op::ProcessExec(PathBuf::from(p))),

        _ => None,
    }
}

fn first_quoted_arg(args: &str) -> Option<String> {
    let q = args.find('"')?;
    let bytes = args.as_bytes();
    let mut i = q + 1;
    let mut out = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 1;
                if i < bytes.len() {
                    // Handle \t, \n, \" etc. For path purposes, treat as literal char.
                    out.push(bytes[i] as char);
                    i += 1;
                }
            }
            b'"' => return Some(out),
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    None
}

/// Parse strace's sockaddr rendering:
///   `{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}`
///   `{sa_family=AF_INET6, sin6_port=htons(80), sin6_addr=inet_pton("2001:db8::1"), ...}`
/// We don't parse AF_UNIX/AF_NETLINK.
fn parse_sockaddr(args: &str) -> Option<(String, String)> {
    let (proto_hint, is_v6) = if args.contains("AF_INET6") {
        (None, true)
    } else if args.contains("AF_INET") {
        (None, false)
    } else {
        return None;
    };
    let _ = proto_hint;

    // Port
    let port_marker = if is_v6 { "sin6_port=htons(" } else { "sin_port=htons(" };
    let p_idx = args.find(port_marker)?;
    let after = &args[p_idx + port_marker.len()..];
    let end = after.find(')')?;
    let port: u16 = after[..end].parse().ok()?;

    // Addr
    let addr_marker = if is_v6 { "inet_pton(\"" } else { "inet_addr(\"" };
    let a_idx = args.find(addr_marker)?;
    let after = &args[a_idx + addr_marker.len()..];
    let aend = after.find('"')?;
    let addr = &after[..aend];

    // strace's dump doesn't tell us tcp vs udp directly — infer tcp as default
    // (connect() is overwhelmingly tcp; udp uses sendto mostly). Users can
    // still opt into wildcard-by-port in the prompt.
    let ep = if is_v6 {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    };
    Some(("tcp".to_string(), ep))
}

fn which(prog: &str) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let p = dir.join(prog);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn temp_path(prefix: &str, ext: &str) -> Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    Ok(std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos:x}.{ext}")))
}

// Required for status.signal() on Unix
use std::os::unix::process::ExitStatusExt;
