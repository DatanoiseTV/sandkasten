//! macOS capture driver for `learn` mode.
//!
//! Runs the target under `(allow default) (trace "<file>")`. The kernel writes
//! one candidate allow-rule per operation to the trace file. We parse it and
//! hand the resulting op set to `learn_core::process`.

use crate::learn_core::{self, Op, Options};
use anyhow::{anyhow, Context, Result};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

pub fn run(argv: &[String], cwd: Option<&Path>, opts: Options) -> Result<i32> {
    if argv.is_empty() {
        return Err(anyhow!("no command to observe"));
    }

    let trace_path = temp_path("sandkasten-trace", "sb")?;
    let trace = trace_path.to_string_lossy().into_owned();
    let policy = format!(
        ";; sandkasten learn mode\n\
         (version 1)\n\
         (allow default)\n\
         (trace {})\n",
        quote_sbpl(&trace)
    );

    eprintln!("── sandkasten learn ─────────────────────────────────────────────");
    eprintln!(" recording operations to  {}", trace_path.display());
    eprintln!(" the target runs WITH FULL PERMISSIONS during this capture.");
    eprintln!("─────────────────────────────────────────────────────────────────\n");

    // Pass the full parent environment so the target can actually run.
    let envp: Vec<std::ffi::CString> = std::env::vars()
        .filter_map(|(k, v)| std::ffi::CString::new(format!("{k}={v}")).ok())
        .collect();

    let exit = super::run_with_sbpl(&policy, argv, cwd, envp)?;
    eprintln!("\nsandkasten: target exited with code {exit}");

    let ops = parse_trace(&trace_path)
        .with_context(|| format!("parsing trace {}", trace_path.display()))?;
    let _ = std::fs::remove_file(&trace_path);

    let cwd_abs = cwd
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    learn_core::process(ops, &cwd_abs, &opts)
}

fn parse_trace(path: &Path) -> Result<BTreeSet<Op>> {
    let f = std::fs::File::open(path)?;
    let mut out = BTreeSet::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if let Some(op) = parse_line(&line) {
            out.insert(op);
        }
    }
    Ok(out)
}

fn parse_line(line: &str) -> Option<Op> {
    let l = line.trim();
    let rest = l.strip_prefix("(allow ")?;
    let (opname, rest) = split_token(rest);
    match opname {
        "file-read*" | "file-read-data" | "file-read-xattr" => {
            first_quoted(rest).map(|p| Op::FileRead(PathBuf::from(p)))
        }
        "file-read-metadata" => first_quoted(rest).map(|p| Op::FileReadMeta(PathBuf::from(p))),
        "file-write*"
        | "file-write-data"
        | "file-write-create"
        | "file-write-unlink"
        | "file-write-mode"
        | "file-write-owner"
        | "file-write-setugid"
        | "file-write-times"
        | "file-write-xattr" => first_quoted(rest).map(|p| Op::FileWrite(PathBuf::from(p))),
        "mach-lookup" => first_quoted(rest).map(Op::MachLookup),
        "network-outbound" => {
            parse_network(rest).map(|(p, e)| Op::NetOutbound { proto: p, endpoint: e })
        }
        "network-bind" | "network-inbound" => {
            parse_network(rest).map(|(p, e)| Op::NetBind { proto: p, endpoint: e })
        }
        "process-exec" | "process-exec*" => {
            first_quoted(rest).map(|p| Op::ProcessExec(PathBuf::from(p)))
        }
        "sysctl-read" => first_quoted(rest).map(Op::SysctlRead),
        "iokit-open" => first_quoted(rest).map(Op::IokitOpen),
        "ipc-posix-shm" | "ipc-posix-sem" => first_quoted(rest).map(Op::IpcShm),
        _ => Some(Op::Other(format!("{opname} {rest}"))),
    }
}

fn split_token(s: &str) -> (&str, &str) {
    match s.find([' ', '\t']) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

fn first_quoted(s: &str) -> Option<String> {
    let q = s.find('"')?;
    let bytes = s.as_bytes();
    let mut i = q + 1;
    let mut out = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 1;
                if i < bytes.len() {
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

fn parse_network(s: &str) -> Option<(String, String)> {
    let r = s.find("(remote ")?;
    let after = &s[r + 8..];
    let (proto, rest) = split_token(after);
    let ep = first_quoted(rest)?;
    Some((proto.to_string(), ep))
}

fn quote_sbpl(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn temp_path(prefix: &str, ext: &str) -> Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    Ok(std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos:x}.{ext}")))
}
