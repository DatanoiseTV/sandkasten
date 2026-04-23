//! Minimal mock files (v1).
//!
//! Materialize every `[mocks.files]` entry into a private per-run tempdir.
//! The sandboxed process sees the tempdir's path in `$SANDKASTEN_MOCKS` and
//! can read any mock file by name. The tempdir is added to the profile's
//! `read` list automatically so the sandbox permits the reads.
//!
//! Keys in `[mocks.files]` are used as file *names* inside the tempdir —
//! path separators are rejected so a mock can't escape via `../`.

use crate::config::Profile;
use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;

/// Result of materialisation — the directory we wrote to and the env var
/// the caller must forward into the child.
pub struct Materialised {
    pub dir: PathBuf,
    pub env_var: (String, String),
}

pub fn materialise(profile: &mut Profile) -> Result<Option<Materialised>> {
    if profile.mocks.files.is_empty() {
        return Ok(None);
    }

    // Validate names first so we never write partial state.
    for name in profile.mocks.files.keys() {
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name.starts_with('.')
            || name.len() > 255
        {
            return Err(anyhow!(
                "mock file name {name:?} is invalid — use a simple basename"
            ));
        }
    }

    let dir = temp_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating mock dir {}", dir.display()))?;

    for (name, content) in &profile.mocks.files {
        let path = dir.join(name);
        std::fs::write(&path, content)
            .with_context(|| format!("writing mock {}", path.display()))?;
    }

    // Expose the tempdir to the sandboxed process AND make it readable by
    // the sandbox policy.
    let dir_str = dir.to_string_lossy().into_owned();
    profile.filesystem.read.push(dir_str.clone());

    Ok(Some(Materialised {
        dir,
        env_var: ("SANDKASTEN_MOCKS".to_string(), dir_str),
    }))
}

fn temp_dir() -> Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    Ok(std::env::temp_dir().join(format!("sandkasten-mocks-{pid}-{nanos:x}")))
}
