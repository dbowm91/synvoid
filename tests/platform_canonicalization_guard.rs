//! Root-test ownership: STATIC_POLICY
//! Rationale: validates Phase 32 platform canonicalization (crate owns OS
//! primitives, root stays a thin facade)
//!
//! Guard test preventing `src/platform/` from regrowing duplicate generic
//! implementations. Canonical platform traits/types/backends have one source
//! owner under `crates/synvoid-platform`; the root module may only re-export
//! them (module aliases and `pub use` of historical top-level names).
//!
//! Fails if any `.rs` file under `src/platform/`:
//! - defines (not merely re-exports) a canonical platform item
//!   (`Signal`, `ProcessControl`, `IpcTransport`, socket ownership wrappers,
//!   service-control traits, OS backends, `Platform`/`PlatformError`, …), or
//! - contains a non-`pub use` item (modules, structs, enums, traits, fns,
//!   statics, impl blocks, macros, `extern` blocks).
//!
//! See `architecture/platform.md` §2 (disposition matrix) for ownership.

use std::path::{Path, PathBuf};

/// Canonical platform items owned by `synvoid-platform`. Redefining any of
/// these under `src/platform/` recreates the duplicate-source hazard.
const CANONICAL_ITEMS: &[&str] = &[
    // Detection / errors / paths.
    "Platform",
    "PlatformError",
    "PlatformPaths",
    "SecureDir",
    // IPC.
    "IpcTransport",
    "IpcListener",
    "IpcStream",
    "PlatformIpcListener",
    "PlatformIpcStream",
    // Process / signals.
    "Signal",
    "ProcessControl",
    "SignalHandler",
    "PlatformProcessControl",
    "PlatformSignalHandler",
    // Sockets.
    "SocketType",
    "SocketInfo",
    "OwnedTcpListener",
    "OwnedTcpStream",
    "SocketHandoffError",
    "SocketHandle",
    "SocketFDPassing",
    "PlatformSocketFDPassing",
    "PlatformSocketHandle",
    // Sandbox.
    "SandboxError",
    "SandboxLevel",
    "SandboxCapabilities",
    "SandboxBackend",
    "SandboxPaths",
    "ProcessSandbox",
    "StubSandbox",
    // Services.
    "ServiceState",
    "ServiceConfig",
    "ServiceControl",
];

fn walk_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            walk_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Strip `//` line comments and `/* … */` block comments so the scanner only
/// sees code. String literals are left intact; definition keywords cannot
/// appear inside string literals in a way that matches the anchored patterns
/// below (`pub struct "…"`, …), so this is sufficient for a tripwire.
fn strip_comments(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '/' if chars.peek() == Some(&'/') => {
                while let Some(&next) = chars.peek() {
                    if next == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut depth = 1;
                while depth > 0 {
                    match chars.next() {
                        Some('/') if chars.peek() == Some(&'*') => {
                            chars.next();
                            depth += 1;
                        }
                        Some('*') if chars.peek() == Some(&'/') => {
                            chars.next();
                            depth -= 1;
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            _ => result.push(ch),
        }
    }
    result
}

fn is_definition_of(line: &str, name: &str) -> bool {
    // Matches `pub struct Name`, `pub(crate) enum Name`, `trait Name`,
    // `pub fn name(`, `pub type Name`, etc. Re-exports (`pub use …::Name;`)
    // intentionally do not match: they contain `use`, not a definition kw.
    let quals: &[&str] = &[
        &format!("struct {name}"),
        &format!("enum {name}"),
        &format!("trait {name}"),
        &format!("fn {name}"),
        &format!("type {name}"),
        &format!("mod {name}"),
    ];
    let line = line.trim();
    let line = line.strip_prefix("pub").unwrap_or(line).trim();
    let line = line
        .strip_prefix("(crate)")
        .or_else(|| line.strip_prefix("(super)"))
        .or_else(|| line.strip_prefix("(self)"))
        .unwrap_or(line)
        .trim();
    let line = line.strip_prefix("unsafe").unwrap_or(line).trim();
    // `pub use` lines are re-exports, never definitions.
    if line.starts_with("use ") {
        return false;
    }
    quals.iter().any(|q| line.starts_with(q))
}

#[test]
fn platform_facade_contains_no_canonical_definitions() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let platform_dir = repo.join("src").join("platform");
    let mut files = Vec::new();
    walk_rs_files(&platform_dir, &mut files);
    assert!(
        !files.is_empty(),
        "src/platform/ should exist with at least mod.rs"
    );

    let mut offenders = Vec::new();
    for path in &files {
        let relative = path.strip_prefix(&repo).unwrap().display().to_string();
        let text = std::fs::read_to_string(path).expect("read Rust source");
        let code = strip_comments(&text);
        for (line_num, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            for name in CANONICAL_ITEMS {
                if is_definition_of(trimmed, name) {
                    offenders.push(format!(
                        "  {}:{}: redefines canonical `synvoid-platform` item `{}`: {}",
                        relative,
                        line_num + 1,
                        name,
                        trimmed
                    ));
                    break;
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "src/platform/ must not redefine canonical synvoid-platform items \
         (implement in crates/synvoid-platform, re-export from the facade):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn platform_facade_contains_only_reexports() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let platform_dir = repo.join("src").join("platform");
    let mut files = Vec::new();
    walk_rs_files(&platform_dir, &mut files);

    // Item keywords that prove a file carries implementation, not aliasing.
    // `pub use` lines are filtered before this check; anything left starting
    // with these keywords (or `impl`/`extern`/`macro_rules!`) is a violation.
    const BANNED_LEADS: &[&str] = &[
        "pub mod ",
        "pub struct ",
        "pub enum ",
        "pub trait ",
        "pub fn ",
        "pub type ",
        "pub static ",
        "pub const ",
        "mod ",
        "struct ",
        "enum ",
        "trait ",
        "fn ",
        "type ",
        "static ",
        "const ",
        "impl ",
        "impl<",
        "extern ",
        "macro_rules!",
    ];

    let mut offenders = Vec::new();
    for path in &files {
        let relative = path.strip_prefix(&repo).unwrap().display().to_string();
        let text = std::fs::read_to_string(path).expect("read Rust source");
        let code = strip_comments(&text);
        for (line_num, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with("pub use ")
                || trimmed.starts_with("use ")
            {
                continue;
            }
            // `pub(crate) use` / `pub use` with visibility qualifier.
            if trimmed.starts_with("pub") && trimmed.contains(" use ") {
                continue;
            }
            // Closing braces and attributes on their own line are structural.
            if trimmed == "}" || trimmed == "};" {
                continue;
            }
            if BANNED_LEADS.iter().any(|lead| trimmed.starts_with(lead)) {
                offenders.push(format!(
                    "  {}:{}: facade must only re-export: {}",
                    relative,
                    line_num + 1,
                    trimmed
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "src/platform/ files must contain only `pub use` re-exports \
         (plus comments/attributes):\n{}",
        offenders.join("\n")
    );
}
