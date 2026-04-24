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

    // User-provided arbitrary bind-mount files. Absolute paths only; we
    // silently drop anything relative to avoid confusion.
    for f in &spoof.files {
        if !f.path.starts_with('/') {
            continue;
        }
        out.push(SynthFile {
            target_path: f.path.clone(),
            content: f.content.clone(),
        });
    }

    // Convenience: uniform temperature across every thermal zone / hwmon
    // input we can enumerate on the HOST at plan time. (Enumeration is
    // done on the launching side — these paths won't exist on macOS, so
    // the loop is Linux-only.)
    #[cfg(target_os = "linux")]
    if let Some(c) = spoof.temperature_c {
        let millic = (c as i64) * 1000;
        let body = format!("{millic}\n");
        for base in ["/sys/class/thermal", "/sys/class/hwmon"] {
            if let Ok(rd) = std::fs::read_dir(base) {
                for e in rd.flatten() {
                    let dir = e.path();
                    // thermal_zone*/temp or hwmon*/temp*_input
                    let candidates = if base.ends_with("thermal") {
                        vec![dir.join("temp")]
                    } else {
                        // hwmon directories contain several tempN_input files.
                        if let Ok(inner) = std::fs::read_dir(&dir) {
                            inner
                                .flatten()
                                .filter_map(|x| {
                                    let p = x.path();
                                    let name = p.file_name()?.to_str()?.to_string();
                                    if name.starts_with("temp") && name.ends_with("_input") {
                                        Some(p)
                                    } else {
                                        None
                                    }
                                })
                                .collect()
                        } else {
                            Vec::new()
                        }
                    };
                    for c in candidates {
                        if c.exists() {
                            out.push(SynthFile {
                                target_path: c.to_string_lossy().into_owned(),
                                content: body.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    // UEFI platform size override.
    if let Some(sz) = spoof.efi_platform_size {
        out.push(SynthFile {
            target_path: "/sys/firmware/efi/fw_platform_size".into(),
            content: format!("{sz}\n"),
        });
    }

    // System enumeration.
    if let Some(v) = &spoof.kernel_version {
        out.push(SynthFile {
            target_path: "/proc/version".into(),
            content: format!("{v}\n"),
        });
    }
    if let Some(v) = &spoof.kernel_release {
        out.push(SynthFile {
            target_path: "/proc/sys/kernel/osrelease".into(),
            content: format!("{v}\n"),
        });
    }
    if let Some(v) = &spoof.os_release {
        out.push(SynthFile {
            target_path: "/etc/os-release".into(),
            content: if v.ends_with('\n') { v.clone() } else { format!("{v}\n") },
        });
        out.push(SynthFile {
            target_path: "/usr/lib/os-release".into(),
            content: if v.ends_with('\n') { v.clone() } else { format!("{v}\n") },
        });
    }
    if let Some(v) = &spoof.issue {
        out.push(SynthFile {
            target_path: "/etc/issue".into(),
            content: if v.ends_with('\n') { v.clone() } else { format!("{v}\n") },
        });
    }
    if let Some(hex) = &spoof.hostid_hex {
        // /etc/hostid is 4 bytes, little-endian, typically written as the
        // raw u32 from `sethostid(2)`. We also write a newline-terminated
        // hex form for tools that read the file as text.
        if let Ok(n) = u32::from_str_radix(hex.trim_start_matches("0x"), 16) {
            let mut bytes = n.to_le_bytes().to_vec();
            // Not newline terminated — binary file.
            out.push(SynthFile {
                target_path: "/etc/hostid".into(),
                content: String::from_utf8_lossy(&std::mem::take(&mut bytes)).into_owned(),
            });
        }
    }
    if let Some(tz) = &spoof.timezone {
        out.push(SynthFile {
            target_path: "/etc/timezone".into(),
            content: format!("{tz}\n"),
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
