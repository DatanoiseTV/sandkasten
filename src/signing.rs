//! Profile signature verification.
//!
//! We use the `minisign` format, produced by the `minisign` CLI tool
//! (available via Homebrew, apt, etc.) — ed25519 signatures over the
//! exact profile bytes. A profile `foo.toml` gets a sidecar `foo.toml.minisig`.
//!
//! # Generating and sharing a key pair (outside sandkasten)
//!
//! ```sh
//! minisign -G -p sandkasten.pub -s sandkasten.key          # create key pair
//! minisign -Sm my-profile.toml -s sandkasten.key           # sign, writes my-profile.toml.minisig
//! ```
//!
//! # Trusted keys
//!
//! sandkasten reads trusted public keys from:
//!   1. `$SANDKASTEN_TRUSTED_KEY` (single key, raw minisign-pubkey format)
//!   2. `~/.config/sandkasten/trusted_keys/*.pub`
//!
//! Every trusted key is tried in turn; a valid signature from *any* of them
//! accepts the profile. This mirrors `known_hosts` semantics — add keys you
//! trust, omit the ones you don't.

use anyhow::{anyhow, Context, Result};
use minisign_verify::{PublicKey, Signature};
use std::path::{Path, PathBuf};

pub struct VerifyReport {
    pub profile: PathBuf,
    #[allow(dead_code)] // surfaced in human-facing output, retained for callers
    pub signature: PathBuf,
    pub key_source: String,
}

pub fn sig_path_for(profile: &Path) -> PathBuf {
    let mut p = profile.as_os_str().to_os_string();
    p.push(".minisig");
    PathBuf::from(p)
}

/// Attempt verification against every trusted key. Returns `Ok(report)`
/// on the first key that accepts the signature; `Err` if none do or the
/// signature/profile can't be read.
pub fn verify(profile: &Path) -> Result<VerifyReport> {
    let sig_path = sig_path_for(profile);
    if !sig_path.exists() {
        return Err(anyhow!(
            "no signature file at {} — generate one with `minisign -Sm {}`",
            sig_path.display(),
            profile.display()
        ));
    }
    let content =
        std::fs::read(profile).with_context(|| format!("reading {}", profile.display()))?;
    let sig_text = std::fs::read_to_string(&sig_path)
        .with_context(|| format!("reading {}", sig_path.display()))?;
    let signature = Signature::decode(&sig_text)
        .map_err(|e| anyhow!("invalid minisign signature in {}: {e}", sig_path.display()))?;

    let keys = trusted_keys()?;
    if keys.is_empty() {
        return Err(anyhow!(
            "no trusted keys configured — set $SANDKASTEN_TRUSTED_KEY \
             or add *.pub files to ~/.config/sandkasten/trusted_keys/"
        ));
    }

    for (source, key_text) in &keys {
        let Ok(pk) = PublicKey::decode(key_text) else {
            continue;
        };
        if pk.verify(&content, &signature, false).is_ok() {
            return Ok(VerifyReport {
                profile: profile.to_path_buf(),
                signature: sig_path,
                key_source: source.clone(),
            });
        }
    }
    Err(anyhow!(
        "signature rejected by every trusted key ({} tried)",
        keys.len()
    ))
}

fn trusted_keys() -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    if let Ok(val) = std::env::var("SANDKASTEN_TRUSTED_KEY") {
        if !val.trim().is_empty() {
            out.push(("$SANDKASTEN_TRUSTED_KEY".into(), val));
        }
    }
    if let Some(conf) = dirs::config_dir() {
        let dir = conf.join("sandkasten").join("trusted_keys");
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) != Some("pub") {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(&p) {
                    out.push((p.display().to_string(), text));
                }
            }
        }
    }
    Ok(out)
}
