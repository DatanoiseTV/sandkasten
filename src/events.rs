//! Structured (machine-readable) event sink.
//!
//! Two output modes selected at startup via `--events`:
//!   * `none` — disabled, [`emit`] is a no-op.
//!   * `json` — newline-delimited JSON to a file, stdout (`-`),
//!     or stderr (default if no file is given). One self-contained
//!     JSON object per line; downstream is expected to parse line-
//!     at-a-time with no continuation across lines.
//!
//! The intended consumer is a SIEM / auditd / log-aggregator pipeline,
//! not a human terminal. Human-readable logging via [`crate::log`] is
//! independent and can be enabled simultaneously.
//!
//! All events carry at least:
//!   * `event` — discriminant (`run_start` / `run_end` / `warning` /
//!     future `denial`)
//!   * `ts` — RFC 3339 / ISO 8601 with **millisecond** precision, UTC
//!     (e.g. `2026-04-25T23:44:20.198Z`). Sub-second is required for
//!     ordering: a sandboxed `cat` finishes in ~7 ms, so run_start and
//!     run_end land in the same wall-clock second on practically every
//!     invocation.
//!   * `ts_ms` — same instant as a Unix epoch in milliseconds. Provided
//!     redundantly so consumers that don't want to parse the RFC 3339
//!     string can use it directly.
//!   * `pid` — sandkasten's own PID (the supervisor)
//!
//! Per-event fields are stable once added — never rename a key, only
//! add new optional ones; downstream parsers should ignore unknown
//! fields.

use std::io::Write;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    None,
    Json,
}

enum Sink {
    Stderr,
    Stdout,
    File(std::fs::File),
}

struct State {
    format: Format,
    sink: Sink,
}

impl State {
    fn write_line(&mut self, line: &str) {
        let res = match &mut self.sink {
            Sink::Stderr => writeln!(std::io::stderr(), "{line}"),
            Sink::Stdout => writeln!(std::io::stdout(), "{line}"),
            Sink::File(f) => writeln!(f, "{line}"),
        };
        // We deliberately don't propagate write errors from the events
        // sink — events are advisory; if SIEM ingest is broken, we
        // shouldn't fail the user's actual sandboxed command. Just
        // continue silently. The main log surface still complains
        // visibly if something's wrong.
        let _ = res;
    }
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

/// Initialise the event sink for the lifetime of this process. Called
/// once from `main()` after parsing CLI args. Safe to skip — the
/// default (uninitialised) state is "no events emitted".
pub fn init(format: &str, file: Option<&std::path::Path>) -> anyhow::Result<()> {
    let format = match format {
        "none" => Format::None,
        "json" => Format::Json,
        other => anyhow::bail!("unknown --events format {other:?}; expected none|json"),
    };
    if format == Format::None {
        return Ok(());
    }
    let sink = match file {
        None => Sink::Stderr,
        Some(p) if p == std::path::Path::new("-") => Sink::Stdout,
        Some(p) => {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .map_err(|e| anyhow::anyhow!("opening --events-file {}: {e}", p.display()))?;
            Sink::File(f)
        }
    };
    *STATE.lock().expect("events::STATE poisoned") = Some(State { format, sink });
    Ok(())
}

/// Whether structured events are turned on. Cheap check — internal
/// callers can skip building the JSON payload when this is false.
pub fn enabled() -> bool {
    STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.format != Format::None))
        .unwrap_or(false)
}

/// One-shot RFC 3339 UTC timestamp with millisecond precision, no
/// chrono dep. Format: `YYYY-MM-DDTHH:MM:SS.mmmZ`. Returned alongside
/// the same instant as a Unix-epoch ms, used both as the event's
/// `ts_ms` field and (here) as the source-of-truth the string is
/// formatted from — guarantees `ts` and `ts_ms` always agree.
fn now_iso8601() -> (String, u128) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_ms = now.as_millis();
    let secs = (total_ms / 1000) as i64;
    let frac_ms = (total_ms % 1000) as u32;
    // Inline date math so we don't pull in chrono.
    let (y, mo, d, h, mi, s) = epoch_to_ymdhms(secs);
    (
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{frac_ms:03}Z"),
        total_ms,
    )
}

fn epoch_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let s = secs as u64;
    let h = (s / 3600) % 24;
    let mi = (s / 60) % 60;
    let sec = s % 60;
    let mut days = (s / 86_400) as i64;
    let mut y = 1970i32;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let in_year = if leap { 366 } else { 365 };
        if days < in_year {
            break;
        }
        days -= in_year;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mo: u32 = 1;
    for &d in &dim {
        if (days as i32) < d {
            break;
        }
        days -= d as i64;
        mo += 1;
    }
    let d = (days as u32) + 1;
    (y, mo, d, h as u32, mi as u32, sec as u32)
}

// ── public emitters ───────────────────────────────────────────────

/// Sandbox starting. Called from the run path right before fork.
pub fn run_start(profile: &str, target: &str, argv: &[String], policy_hash: Option<&str>) {
    if !enabled() {
        return;
    }
    let (ts, ts_ms) = now_iso8601();
    let mut s = String::with_capacity(256);
    s.push('{');
    push_field(&mut s, "event", "run_start", true);
    push_field(&mut s, "ts", &ts, false);
    push_field_raw(&mut s, "ts_ms", &ts_ms.to_string(), false);
    push_field_raw(&mut s, "pid", &std::process::id().to_string(), false);
    push_field(&mut s, "profile", profile, false);
    push_field(&mut s, "target", target, false);
    s.push_str(",\"argv\":[");
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&json_string(a));
    }
    s.push(']');
    if let Some(h) = policy_hash {
        push_field(&mut s, "policy_hash", h, false);
    }
    s.push('}');
    write_line(&s);
}

/// Sandbox ended. Called once `parent_wait` returns.
pub fn run_end(exit_code: i32, wall_ms: u128) {
    if !enabled() {
        return;
    }
    let (ts, ts_ms) = now_iso8601();
    let mut s = String::with_capacity(192);
    s.push('{');
    push_field(&mut s, "event", "run_end", true);
    push_field(&mut s, "ts", &ts, false);
    push_field_raw(&mut s, "ts_ms", &ts_ms.to_string(), false);
    push_field_raw(&mut s, "pid", &std::process::id().to_string(), false);
    push_field_raw(&mut s, "exit_code", &exit_code.to_string(), false);
    // Linux convention: rc 128+N == process killed by signal N.
    if (128..192).contains(&exit_code) {
        push_field_raw(&mut s, "signal", &(exit_code - 128).to_string(), false);
    }
    push_field_raw(&mut s, "wall_ms", &wall_ms.to_string(), false);
    s.push('}');
    write_line(&s);
}

/// Non-fatal warning sandkasten itself emits (e.g. "Landlock can't
/// enforce deny path X inside allow Y").
#[allow(dead_code)]
pub fn warning(message: &str) {
    if !enabled() {
        return;
    }
    let (ts, ts_ms) = now_iso8601();
    let mut s = String::with_capacity(128 + message.len());
    s.push('{');
    push_field(&mut s, "event", "warning", true);
    push_field(&mut s, "ts", &ts, false);
    push_field_raw(&mut s, "ts_ms", &ts_ms.to_string(), false);
    push_field_raw(&mut s, "pid", &std::process::id().to_string(), false);
    push_field(&mut s, "message", message, false);
    s.push('}');
    write_line(&s);
}

// ── internal helpers ──────────────────────────────────────────────

fn write_line(s: &str) {
    if let Ok(mut g) = STATE.lock() {
        if let Some(state) = g.as_mut() {
            state.write_line(s);
        }
    }
}

fn push_field(buf: &mut String, key: &str, val: &str, first: bool) {
    if !first {
        buf.push(',');
    }
    buf.push('"');
    buf.push_str(key);
    buf.push_str("\":");
    buf.push_str(&json_string(val));
}

fn push_field_raw(buf: &mut String, key: &str, raw: &str, first: bool) {
    if !first {
        buf.push(',');
    }
    buf.push('"');
    buf.push_str(key);
    buf.push_str("\":");
    buf.push_str(raw);
}

/// Minimal RFC 8259 string escaper.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_escapes() {
        assert_eq!(json_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
        assert_eq!(json_string("plain"), "\"plain\"");
        assert_eq!(json_string("\x01"), "\"\\u0001\"");
    }

    #[test]
    fn epoch_conversion_is_sane() {
        // 2026-04-25T00:00:00Z = 1777075200 (verified with `date -u -r`).
        let (y, mo, d, h, mi, s) = epoch_to_ymdhms(1_777_075_200);
        assert_eq!((y, mo, d, h, mi, s), (2026, 4, 25, 0, 0, 0));
        // 2024-02-29T12:34:56Z = 1709210096 (leap year).
        let (y, mo, d, h, mi, s) = epoch_to_ymdhms(1_709_210_096);
        assert_eq!((y, mo, d), (2024, 2, 29));
        assert_eq!((h, mi, s), (12, 34, 56));
        // Year boundary on a non-leap year: 2025-12-31T23:59:59Z = 1767225599.
        let (y, mo, d, h, mi, s) = epoch_to_ymdhms(1_767_225_599);
        assert_eq!((y, mo, d, h, mi, s), (2025, 12, 31, 23, 59, 59));
        // Day after: 2026-01-01T00:00:00Z = 1767225600.
        let (y, mo, d, h, mi, s) = epoch_to_ymdhms(1_767_225_600);
        assert_eq!((y, mo, d, h, mi, s), (2026, 1, 1, 0, 0, 0));
    }
}
