//! Local web UI for browsing and editing profiles.
//!
//! # Security model
//!
//! * Binds only on `127.0.0.1` — never the network.
//! * Issues a random bearer token at startup. All `/api/*` requests require
//!   the token; `/` serves the shell which embeds the token for fetches.
//! * Never executes code. The UI edits TOML profiles only — no "run" endpoint.
//!   Users launch profiles from their shell via `sandkasten run`.
//! * Writes only to `~/.config/sandkasten/profiles/` (created if absent).
//!   Refuses file names that escape the directory via `/` or `..`.
//! * Does not expose built-in templates for editing — they are read-only.

use crate::config;
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tiny_http::{Header, Method, Response, Server, StatusCode};

const INDEX_HTML: &str = include_str!("index.html");

pub fn run(port: u16, open_browser: bool) -> Result<()> {
    let dir = profiles_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let token = random_token();
    let addr = format!("127.0.0.1:{port}");
    let server = Server::http(&addr).map_err(|e| anyhow!("binding {addr}: {e}"))?;
    let actual = server.server_addr();
    let bound = actual.to_string();
    let url = format!("http://{bound}/?t={token}");

    eprintln!("╭─ sandkasten UI ──────────────────────────────────────────");
    eprintln!("│  {url}");
    eprintln!("│  profiles directory: {}", dir.display());
    eprintln!("│  Ctrl-C to stop.");
    eprintln!("╰──────────────────────────────────────────────────────────");

    if open_browser {
        let _ = std::process::Command::new("open").arg(&url).status();
    }

    let state = Arc::new(AppState { dir, token, bound });

    for request in server.incoming_requests() {
        let state = state.clone();
        let _ = handle(&state, request);
    }
    Ok(())
}

struct AppState {
    dir: PathBuf,
    token: String,
    bound: String,
}

fn handle(state: &AppState, mut req: tiny_http::Request) -> Result<()> {
    let method = req.method().clone();
    let url = req.url().to_string();
    let (path, query) = split_query(&url);
    let path = path.to_string();
    let query = query.to_string();

    // Collect header/token upfront so we don't need to borrow `req` again.
    let provided_token = extract_token(&req, &query);

    let check_auth = |req: tiny_http::Request| -> Result<tiny_http::Request, ()> {
        if provided_token.as_deref() == Some(state.token.as_str()) {
            Ok(req)
        } else {
            let _ = req.respond(json_response(401, b"{\"error\":\"unauthorized\"}"));
            Err(())
        }
    };

    let result: Result<()> = match (&method, path.as_str()) {
        (Method::Get, "/") => {
            let html = INDEX_HTML.replace("{{TOKEN}}", &json_string(&state.token));
            req.respond(html_response(200, html.as_bytes()))?;
            Ok(())
        }
        (Method::Get, "/api/profiles") => {
            let req = match check_auth(req) {
                Ok(r) => r,
                Err(()) => return Ok(()),
            };
            let body = list_profiles_json(&state.dir);
            req.respond(json_response(200, body.as_bytes()))?;
            Ok(())
        }
        (Method::Get, "/api/templates") => {
            let req = match check_auth(req) {
                Ok(r) => r,
                Err(()) => return Ok(()),
            };
            let mut body = String::from("[");
            for (i, (name, desc)) in crate::templates::LIST.iter().enumerate() {
                if i > 0 {
                    body.push(',');
                }
                body.push_str(&format!(
                    "{{\"name\":{},\"description\":{},\"raw\":{}}}",
                    json_string(name),
                    json_string(desc),
                    json_string(crate::templates::builtin(name).unwrap_or("")),
                ));
            }
            body.push(']');
            req.respond(json_response(200, body.as_bytes()))?;
            Ok(())
        }
        (Method::Get, p) if p.starts_with("/api/profiles/") => {
            let req = match check_auth(req) {
                Ok(r) => r,
                Err(()) => return Ok(()),
            };
            let name = &p["/api/profiles/".len()..];
            match read_profile(&state.dir, name) {
                Ok(raw) => {
                    let body = format!(
                        "{{\"name\":{},\"raw\":{}}}",
                        json_string(name),
                        json_string(&raw)
                    );
                    req.respond(json_response(200, body.as_bytes()))?;
                }
                Err(e) => {
                    req.respond(json_response(
                        404,
                        format!("{{\"error\":{}}}", json_string(&e.to_string())).as_bytes(),
                    ))?;
                }
            }
            Ok(())
        }
        (Method::Put, p) if p.starts_with("/api/profiles/") => {
            if provided_token.as_deref() != Some(state.token.as_str()) {
                req.respond(json_response(401, b"{\"error\":\"unauthorized\"}"))?;
                return Ok(());
            }
            if !origin_allowed(&req, &state.bound) {
                req.respond(json_response(
                    403,
                    b"{\"error\":\"origin not allowed (CSRF guard)\"}",
                ))?;
                return Ok(());
            }
            // Content-Length gate — refuse oversized bodies before reading them.
            let clen = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("Content-Length"))
                .and_then(|h| h.value.as_str().parse::<usize>().ok())
                .unwrap_or(0);
            if clen > MAX_BODY_BYTES {
                req.respond(json_response(413, b"{\"error\":\"body too large\"}"))?;
                return Ok(());
            }
            let name = p["/api/profiles/".len()..].to_string();
            let mut body = Vec::with_capacity(clen.min(MAX_BODY_BYTES));
            // Read in 4KB chunks up to the cap; refuse if exceeded.
            let mut buf = [0u8; 4096];
            loop {
                let n = std::io::Read::read(req.as_reader(), &mut buf)?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
                if body.len() > MAX_BODY_BYTES {
                    req.respond(json_response(413, b"{\"error\":\"body too large\"}"))?;
                    return Ok(());
                }
            }
            let body_str = String::from_utf8(body).unwrap_or_default();
            match write_profile(&state.dir, &name, &body_str) {
                Ok(()) => req.respond(json_response(200, b"{\"ok\":true}"))?,
                Err(e) => req.respond(json_response(
                    400,
                    format!("{{\"error\":{}}}", json_string(&e.to_string())).as_bytes(),
                ))?,
            }
            Ok(())
        }
        (Method::Delete, p) if p.starts_with("/api/profiles/") => {
            let req = match check_auth(req) {
                Ok(r) => r,
                Err(()) => return Ok(()),
            };
            if !origin_allowed(&req, &state.bound) {
                req.respond(json_response(
                    403,
                    b"{\"error\":\"origin not allowed (CSRF guard)\"}",
                ))?;
                return Ok(());
            }
            let name = &p["/api/profiles/".len()..];
            match delete_profile(&state.dir, name) {
                Ok(()) => req.respond(json_response(200, b"{\"ok\":true}"))?,
                Err(e) => req.respond(json_response(
                    400,
                    format!("{{\"error\":{}}}", json_string(&e.to_string())).as_bytes(),
                ))?,
            }
            Ok(())
        }
        _ => {
            req.respond(Response::from_string("not found").with_status_code(StatusCode(404)))?;
            Ok(())
        }
    };
    result
}

fn extract_token(req: &tiny_http::Request, query: &str) -> Option<String> {
    let header_token = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .and_then(|h| h.value.as_str().strip_prefix("Bearer ").map(str::to_string));
    if header_token.is_some() {
        return header_token;
    }
    parse_query(query)
        .into_iter()
        .find_map(|(k, v)| if k == "t" { Some(v) } else { None })
}

#[allow(dead_code)]
fn require_auth(state: &AppState, req: &tiny_http::Request, query: &str) -> Result<()> {
    // Bearer header takes precedence.
    let header_token = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .map(|h| h.value.as_str().to_string())
        .and_then(|v| v.strip_prefix("Bearer ").map(str::to_string));

    let query_token =
        parse_query(query)
            .into_iter()
            .find_map(|(k, v)| if k == "t" { Some(v) } else { None });

    let given = header_token.or(query_token).unwrap_or_default();
    if given == state.token {
        Ok(())
    } else {
        Err(anyhow!("unauthorized"))
    }
}

fn list_profiles_json(dir: &Path) -> String {
    let mut entries: Vec<(String, String)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let desc = std::fs::read_to_string(&p)
                .ok()
                .and_then(|s| parse_description(&s))
                .unwrap_or_default();
            entries.push((stem.to_string(), desc));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::from("[");
    for (i, (name, desc)) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"name\":{},\"description\":{}}}",
            json_string(name),
            json_string(desc)
        ));
    }
    out.push(']');
    out
}

fn parse_description(toml_src: &str) -> Option<String> {
    toml::from_str::<config::Profile>(toml_src)
        .ok()
        .and_then(|p| p.description)
}

fn read_profile(dir: &Path, name: &str) -> Result<String> {
    if let Some(builtin) = crate::templates::builtin(name) {
        return Ok(builtin.to_string());
    }
    let p = resolve(dir, name)?;
    std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))
}

fn write_profile(dir: &Path, name: &str, raw: &str) -> Result<()> {
    // Validate parseability first — refuse to write broken TOML.
    let prof: config::Profile = toml::from_str(raw).context("TOML parse error")?;
    let _ = prof; // we're just checking

    let p = resolve(dir, name)?;
    std::fs::write(&p, raw).with_context(|| format!("writing {}", p.display()))?;
    Ok(())
}

fn delete_profile(dir: &Path, name: &str) -> Result<()> {
    let p = resolve(dir, name)?;
    std::fs::remove_file(&p).with_context(|| format!("deleting {}", p.display()))?;
    Ok(())
}

/// Resolve a profile name to a path, rejecting anything that looks like an
/// attempt to escape the profiles directory.
fn resolve(dir: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.starts_with('.')
        || name.len() > 128
    {
        return Err(anyhow!("invalid profile name: {name:?}"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "profile names must be [a-zA-Z0-9_-] only, got {name:?}"
        ));
    }
    Ok(dir.join(format!("{name}.toml")))
}

fn profiles_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("no config directory"))?;
    Ok(base.join("sandkasten").join("profiles"))
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn random_token() -> String {
    // 128 bits of entropy from /dev/urandom.
    let mut buf = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut buf);
    } else {
        // Fallback: pid + nanos. Weaker but still unguessable in practice
        // for a local-only UI.
        let pid = std::process::id() as u64;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        buf[..8].copy_from_slice(&pid.to_le_bytes());
        buf[8..].copy_from_slice(&nanos.to_le_bytes());
    }
    let mut hex = String::with_capacity(32);
    for b in buf {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

fn split_query(url: &str) -> (&str, &str) {
    match url.find('?') {
        Some(i) => (&url[..i], &url[i + 1..]),
        None => (url, ""),
    }
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((percent_decode(k), percent_decode(v)))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(a), Some(b)) = (hi, lo) {
                out.push((a << 4) | b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

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
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn security_headers(r: Response<std::io::Cursor<Vec<u8>>>) -> Response<std::io::Cursor<Vec<u8>>> {
    // Tight CSP for an app that only talks to itself. `'unsafe-inline'` on
    // script/style is required because the whole SPA ships as inline in
    // `index.html`; mitigated by default-src 'none' and strict form-action.
    r.with_header(
        Header::from_bytes(
            &b"Content-Security-Policy"[..],
            &b"default-src 'none'; script-src 'self' 'unsafe-inline'; \
               style-src 'self' 'unsafe-inline'; connect-src 'self'; \
               img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; \
               form-action 'none'; base-uri 'none'"[..],
        )
        .unwrap(),
    )
    .with_header(Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap())
    .with_header(Header::from_bytes(&b"X-Frame-Options"[..], &b"DENY"[..]).unwrap())
    .with_header(Header::from_bytes(&b"Referrer-Policy"[..], &b"no-referrer"[..]).unwrap())
    .with_header(
        Header::from_bytes(
            &b"Permissions-Policy"[..],
            &b"camera=(), microphone=(), geolocation=(), interest-cohort=()"[..],
        )
        .unwrap(),
    )
    .with_header(Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).unwrap())
}

fn json_response(status: u16, body: &[u8]) -> Response<std::io::Cursor<Vec<u8>>> {
    security_headers(
        Response::from_data(body.to_vec())
            .with_status_code(StatusCode(status))
            .with_header(
                Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"application/json; charset=utf-8"[..],
                )
                .unwrap(),
            ),
    )
}

fn html_response(status: u16, body: &[u8]) -> Response<std::io::Cursor<Vec<u8>>> {
    security_headers(
        Response::from_data(body.to_vec())
            .with_status_code(StatusCode(status))
            .with_header(
                Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap(),
            ),
    )
}

/// Hardened origin allowlist for mutating requests. The UI is local-only; we
/// only accept requests whose `Origin` header matches our bound `host:port`.
/// This stops a malicious page in your browser from submitting writes via the
/// bearer token in a URL someone tricked you into clicking (defense-in-depth
/// on top of the token).
fn origin_allowed(req: &tiny_http::Request, bound_addr: &str) -> bool {
    let want_http = format!("http://{bound_addr}");
    let origin = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Origin"))
        .map(|h| h.value.as_str().to_string());
    match origin {
        Some(o) => o == want_http,
        // Same-origin `fetch` from our own page sometimes omits Origin on
        // same-scheme GETs. For mutations we REQUIRE Origin.
        None => false,
    }
}

/// Max body length (in bytes) we'll accept on PUT. Profiles should be tiny;
/// anything larger is almost certainly a bug or attack.
const MAX_BODY_BYTES: usize = 64 * 1024;
