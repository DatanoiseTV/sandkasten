//! Built-in profile templates. These are compiled into the binary so the tool
//! works with no configuration. Users can `extends = "strict"` to build on top.

pub const STRICT: &str = include_str!("../templates/strict.toml");
pub const SELF: &str = include_str!("../templates/self.toml");
pub const DEV: &str = include_str!("../templates/dev.toml");
pub const NETWORK_CLIENT: &str = include_str!("../templates/network-client.toml");
pub const MINIMAL_CLI: &str = include_str!("../templates/minimal-cli.toml");

pub const LIST: &[(&str, &str)] = &[
    ("self", "Default. Sandbox sees only its own working directory (${CWD}). No network."),
    ("strict", "Near-zero permissions. Minimal base every CLI needs to start."),
    ("minimal-cli", "Read /usr /System + /etc/hosts. No network, no writes."),
    ("dev", "Permissive development sandbox. Writes to CWD + TMPDIR, localhost."),
    ("network-client", "Outbound HTTPS + DNS only. Read-only filesystem."),
];

pub fn builtin(name: &str) -> Option<&'static str> {
    match name {
        "self" => Some(SELF),
        "strict" => Some(STRICT),
        "dev" => Some(DEV),
        "network-client" => Some(NETWORK_CLIENT),
        "minimal-cli" => Some(MINIMAL_CLI),
        _ => None,
    }
}
