//! Post-hoc denial capture via `log show`.
//!
//! After the sandboxed child exits, we query the unified log for sandbox
//! events from the last N seconds, dedupe by (operation, target) and print a
//! compact summary. Intentionally rate-limited (runs once, bounded window) so
//! even apps that hit thousands of denials produce a small digest.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

pub fn show_since(window: Duration, child_pid: Option<i32>) {
    let seconds = window.as_secs().max(1);
    // Sandbox denial events are emitted by the kernel (sender="kernel",
    // category="Sandbox") with the denied process's PID embedded in the
    // message text, not in the event's processIdentifier. So we filter by
    // eventMessage shape and post-filter by PID.
    let predicate = "eventMessage CONTAINS \"Sandbox\" AND eventMessage CONTAINS \"deny(\"";
    let output = Command::new("/usr/bin/log")
        .args([
            "show",
            "--style",
            "compact",
            "--last",
            &format!("{seconds}s"),
            "--predicate",
            predicate,
        ])
        .output();

    let stdout = match output {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            eprintln!(
                "sandkasten ⚠ denial capture: log show failed (exit={:?}) — {}",
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return;
        }
        Err(e) => {
            eprintln!("sandkasten ⚠ denial capture: could not spawn `log`: {e}");
            return;
        }
    };

    let text = String::from_utf8_lossy(&stdout);
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();

    for line in text.lines() {
        // Lines look like:
        //   2026-04-24 00:21:03.123 Error ... kernel: (Sandbox) Sandbox: cat(50334) deny(1) file-read-data /foo
        let Some(deny_idx) = line.find("deny(") else {
            continue;
        };

        // Extract PID: the token before "Sandbox: " then after "name(PID)".
        if let Some(pid) = extract_denied_pid(line) {
            if let Some(filter) = child_pid {
                if pid != filter && pid != filter as u32 as i32 {
                    continue;
                }
            }
        } else if child_pid.is_some() {
            // Couldn't extract — if user asked for PID filter, skip ambiguous rows.
            continue;
        }

        let after = &line[deny_idx..];
        let Some(op_start) = after.find(' ') else {
            continue;
        };
        let rest = after[op_start + 1..].trim();
        let (op, target) = match rest.split_once(char::is_whitespace) {
            Some((o, t)) => (o.to_string(), t.trim().to_string()),
            None => (rest.to_string(), String::new()),
        };
        *counts.entry((op, target)).or_insert(0) += 1;
    }

    if counts.is_empty() {
        eprintln!(
            "sandkasten │ no kernel denial events in the capture window.\n\
             sandkasten │ note: macOS only logs default-deny fallthroughs — explicit\n\
             sandkasten │       `deny` rules that match a specific path are silent by design."
        );
        return;
    }

    eprintln!("sandkasten │ kernel denials ({} unique):", counts.len());
    // Sort by frequency (descending) then op+target.
    let mut entries: Vec<_> = counts.into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    const MAX_ROWS: usize = 30;
    for ((op, target), count) in entries.iter().take(MAX_ROWS) {
        let target_trunc = truncate(target, 80);
        eprintln!("    {count:>5}× {op:<24} {target_trunc}");
    }
    if entries.len() > MAX_ROWS {
        eprintln!(
            "    … {} more unique denial rows suppressed",
            entries.len() - MAX_ROWS
        );
    }
}

/// Extract the denied-process PID from a sandbox deny log line.
/// Format: `... Sandbox: <name>(<pid>) deny(<n>) ...`
fn extract_denied_pid(line: &str) -> Option<i32> {
    let sb = line.rfind("Sandbox: ")?;
    let rest = &line[sb + 9..];
    // rest starts with "name(pid) deny(...)"
    let deny_at = rest.find(" deny(")?;
    let name_pid = &rest[..deny_at];
    let open = name_pid.rfind('(')?;
    let close = name_pid.rfind(')')?;
    if close <= open {
        return None;
    }
    name_pid[open + 1..close].parse().ok()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let keep = max.saturating_sub(1);
        let mut out: String = s.chars().take(keep).collect();
        out.push('…');
        out
    }
}
