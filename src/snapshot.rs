//! Named snapshots of a profile's overlay upperdir. Plain directory copies —
//! no compression, no format — stored under
//! `~/.config/sandkasten/snapshots/<profile>/<name>/`.

use crate::config::Profile;
use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;

fn root() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("no config dir"))?;
    Ok(base.join("sandkasten").join("snapshots"))
}

fn profile_dir(name: &str) -> Result<PathBuf> {
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "profile name for snapshots must be [a-zA-Z0-9_-]+, got {name:?}"
        ));
    }
    Ok(root()?.join(name))
}

fn require_upper(p: &Profile) -> Result<PathBuf> {
    let upper = p
        .overlay
        .upper
        .as_ref()
        .ok_or_else(|| anyhow!("profile has no [overlay].upper — nothing to snapshot"))?;
    Ok(PathBuf::from(upper))
}

pub fn save(profile: &Profile, profile_name: &str, snap_name: &str) -> Result<PathBuf> {
    let upper = require_upper(profile)?;
    if !upper.exists() {
        return Err(anyhow!(
            "upperdir {} does not exist yet — run the profile once first",
            upper.display()
        ));
    }
    let dst = profile_dir(profile_name)?.join(snap_name);
    if dst.exists() {
        return Err(anyhow!(
            "snapshot {} already exists — pick a different name or remove it",
            dst.display()
        ));
    }
    std::fs::create_dir_all(dst.parent().unwrap())
        .with_context(|| format!("creating parent of {}", dst.display()))?;
    copy_tree(&upper, &dst)
        .with_context(|| format!("copying {} → {}", upper.display(), dst.display()))?;
    Ok(dst)
}

pub fn load(profile: &Profile, profile_name: &str, snap_name: &str) -> Result<()> {
    let upper = require_upper(profile)?;
    let src = profile_dir(profile_name)?.join(snap_name);
    if !src.exists() {
        return Err(anyhow!("snapshot {} not found", src.display()));
    }
    // Move current upper out of the way rather than deleting it.
    if upper.exists() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut bak = upper.clone();
        let name = upper
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("upper");
        bak.set_file_name(format!("{name}.bak-{ts}"));
        std::fs::rename(&upper, &bak)
            .with_context(|| format!("renaming {} → {}", upper.display(), bak.display()))?;
        eprintln!("sandkasten │ previous upper moved to {}", bak.display());
    }
    std::fs::create_dir_all(upper.parent().unwrap_or(std::path::Path::new("/")))?;
    copy_tree(&src, &upper)
        .with_context(|| format!("restoring {} → {}", src.display(), upper.display()))?;
    Ok(())
}

pub fn list(profile_name: &str) -> Result<Vec<String>> {
    let dir = match profile_dir(profile_name) {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut out: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    out.sort();
    Ok(out)
}

/// Recursive directory copy. Preserves file modes; uses hardlink-style
/// metadata where possible. We intentionally don't chase symlinks, to avoid
/// copying arbitrary files the upperdir happens to link to.
fn copy_tree(from: &std::path::Path, to: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if ft.is_dir() {
            copy_tree(&src, &dst)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&src)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}
