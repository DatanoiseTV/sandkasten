//! Built-in profile templates. These are compiled into the binary so the tool
//! works with no configuration. Users can `extends = "strict"` to build on top.

pub const STRICT: &str = include_str!("../templates/strict.toml");
pub const SELF: &str = include_str!("../templates/self.toml");
pub const DEV: &str = include_str!("../templates/dev.toml");
pub const NETWORK_CLIENT: &str = include_str!("../templates/network-client.toml");
pub const MINIMAL_CLI: &str = include_str!("../templates/minimal-cli.toml");
pub const BROWSER: &str = include_str!("../templates/browser.toml");
pub const ELECTRON: &str = include_str!("../templates/electron.toml");

/// Bundled example profiles — TOML bodies compiled into the binary so
/// `sandkasten install-profiles` can drop them onto disk without
/// needing the source tree. Distinct from `builtin()` above: those
/// are *templates* you can `extends = "..."`; these are
/// *example profiles* you can run as-is or copy and edit.
pub const BUNDLED_EXAMPLES: &[(&str, &str)] =
    &[("ai-agent", include_str!("../examples/ai-agent.toml"))];

/// Names of the built-in templates, in the order they appear in the
/// CLI / web-UI listings.
const NAMES: &[&str] = &[
    "self",
    "strict",
    "minimal-cli",
    "network-client",
    "dev",
    "browser",
    "electron",
];

/// `(name, short_description)` for each built-in. The description is
/// derived from the embedded TOML's `description = "..."` line at run
/// time so the CLI / web UI / `templates` listing can never drift out
/// of sync with the actual TOML — they share a single source of truth.
pub fn list() -> Vec<(&'static str, &'static str)> {
    NAMES
        .iter()
        .filter_map(|n| builtin(n).map(|toml| (*n, extract_description(toml))))
        .collect()
}

/// Pull the first `description = "..."` value out of a TOML body.
/// Cheap line scan rather than full TOML parse — these files are
/// authored by hand, the description is always on its own line near
/// the top, and we'd rather not pay an allocation/parse round here
/// just to fill a CLI table.
fn extract_description(toml: &'static str) -> &'static str {
    for line in toml.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("description") {
            // Match `description = "..."` (any spaces, double-quoted).
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('"') {
                    if let Some(end) = rest.find('"') {
                        return &rest[..end];
                    }
                }
            }
        }
    }
    "(no description)"
}

pub fn builtin(name: &str) -> Option<&'static str> {
    match name {
        "self" => Some(SELF),
        "strict" => Some(STRICT),
        "dev" => Some(DEV),
        "network-client" => Some(NETWORK_CLIENT),
        "minimal-cli" => Some(MINIMAL_CLI),
        "browser" => Some(BROWSER),
        "electron" => Some(ELECTRON),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_matches_toml_for_every_template() {
        // No template should still be carrying a placeholder. Equally,
        // the description has to actually render to non-empty so the
        // CLI table doesn't grow blank rows.
        for (name, desc) in list() {
            assert!(!desc.is_empty(), "template {name} has empty description");
            assert_ne!(
                desc, "(no description)",
                "template {name} missing `description = ...`"
            );
        }
    }

    #[test]
    fn extract_description_handles_typical_toml() {
        let toml = "name = \"x\"\ndescription = \"hello world\"\nextends = \"y\"\n";
        assert_eq!(extract_description(toml), "hello world");
    }

    #[test]
    fn extract_description_skips_first_unrelated_line() {
        let toml = "# comment\nname = \"x\"\n# another comment\ndescription = \"good\"\n";
        assert_eq!(extract_description(toml), "good");
    }
}
