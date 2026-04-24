//! Synthetic hardware-identity file generation.
//!
//! Generates the file contents declared by `[spoof]` — CPUID/DMI/machine-id.
//! Callers (per-platform runners) decide how to expose them: Linux bind-
//! mounts them in the mount namespace; macOS has no comparable primitive
//! and documents the limit.

use crate::config::Spoof;

/// A file that should appear at `target_path` inside the sandbox, with the
/// given content. Keep the set small — these are all bind-mounted, and
/// bind-mounts must have an existing target file/directory.
pub struct SynthFile {
    pub target_path: String,
    pub content: String,
}

pub fn plan(spoof: &Spoof) -> Vec<SynthFile> {
    let mut out = Vec::new();

    if spoof.cpuinfo_synth {
        out.push(SynthFile {
            target_path: "/proc/cpuinfo".into(),
            content: render_cpuinfo(spoof),
        });
    }

    if let Some(mid) = &spoof.machine_id {
        let sanitized = mid.trim().to_string();
        out.push(SynthFile {
            target_path: "/etc/machine-id".into(),
            content: format!("{sanitized}\n"),
        });
    }

    for (key, val) in &spoof.dmi {
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            continue;
        }
        out.push(SynthFile {
            target_path: format!("/sys/class/dmi/id/{key}"),
            content: format!("{val}\n"),
        });
    }

    out
}

fn render_cpuinfo(spoof: &Spoof) -> String {
    let cores = spoof.cpu_count.unwrap_or(1).max(1);
    let model = spoof
        .cpuinfo_model
        .clone()
        .unwrap_or_else(|| "Sandkasten CPU".into());
    let mhz = spoof.cpuinfo_mhz.unwrap_or(3000);
    let mut s = String::new();
    for id in 0..cores {
        use std::fmt::Write as _;
        let _ = writeln!(s, "processor\t: {id}");
        s.push_str("vendor_id\t: Sandkasten\n");
        s.push_str("cpu family\t: 6\n");
        s.push_str("model\t\t: 62\n");
        let _ = writeln!(s, "model name\t: {model}");
        s.push_str("stepping\t: 0\n");
        let _ = writeln!(s, "cpu MHz\t\t: {mhz}");
        s.push_str("cache size\t: 8192 KB\n");
        s.push_str("physical id\t: 0\n");
        let _ = writeln!(s, "siblings\t: {cores}");
        let _ = writeln!(s, "core id\t\t: {id}");
        let _ = writeln!(s, "cpu cores\t: {cores}");
        s.push_str("fpu\t\t: yes\n");
        s.push_str("flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe\n");
        s.push_str("\n");
    }
    s
}
