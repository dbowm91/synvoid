//! Root-test ownership: STATIC_POLICY
//! Rationale: validates Phase 03 compatibility-facade disposition (removed paths stay
//! removed, retained pure facades stay thin, adapters stay documented)
//!
//! Guard for `architecture/facade_disposition_matrix.md` (Phase 03).
//! Static, fast, no codegen:
//! - removed facades must not be redeclared in `src/lib.rs`, must not exist on disk,
//!   and must be recorded as removed in the ledger + disposition matrix;
//! - retained pure facades must stay thin (re-exports only, no local items);
//! - documented adapters (`config`, `proxy`, `http_client`, `metrics`) are exempt
//!   from thinness but must be documented in the matrix + ledger.
//!
//! NOTE: several facade directories contain pre-existing orphan `.rs` files that are
//! not reachable from `src/lib.rs` (e.g. `src/process/ipc.rs`, sibling files under
//! `src/honeypot_port/` / `src/serverless/`). Those orphans are not compiled and are
//! out of scope for this guard; it inspects only the compiled entry file
//! (`src/<name>/mod.rs`, `src/<name>.rs`, or the inline block in `src/lib.rs`).

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Phase 03 `remove_now` set. Canonical replacements live in
/// `architecture/facade_disposition_matrix.md` §4.
const REMOVED_FACADES: &[&str] = &[
    "auth",
    "cgi",
    "challenge",
    "filter",
    "integrity",
    "php",
    "proxy_cache",
    "upload",
];

/// Retained pure facades (must stay thin). Entry file locations:
/// `<name>/mod.rs`, `<name>.rs`, or `inline:<symbol>` for `src/lib.rs` blocks.
const PURE_FACADES: &[&str] = &[
    "app_server",
    "block_store",
    "fastcgi",
    "geoip:inline",
    "honeypot_port",
    "http3",
    "listener",
    "location_matcher",
    "mesh",
    "mime",
    "process",
    "protocol",
    "router",
    "router_adapter",
    "serialization:inline",
    "serverless",
    "spin",
    "static_files",
    "streaming",
    "theme",
    "tunnel",
    "upstream:inline",
    "vpn_client",
    "buffer:inline",
    "dns",
];

/// Documented adapters exempt from thinness (must be documented, not thin).
const DOCUMENTED_ADAPTERS: &[&str] = &["config", "proxy", "http_client", "metrics"];

fn entry_source(repo: &std::path::Path, facade: &str) -> Option<String> {
    if let Some(inline) = facade.strip_suffix(":inline") {
        let lib = std::fs::read_to_string(repo.join("src/lib.rs")).unwrap_or_default();
        return Some(extract_inline_block(&lib, inline));
    }
    let mod_rs = repo.join(format!("src/{facade}/mod.rs"));
    if mod_rs.exists() {
        return std::fs::read_to_string(mod_rs).ok();
    }
    let flat_rs = repo.join(format!("src/{facade}.rs"));
    if flat_rs.exists() {
        return std::fs::read_to_string(flat_rs).ok();
    }
    None
}

/// Extract the inline `pub mod <name> { ... }` / `pub use ... as <name>;` region
/// from `src/lib.rs` for thinness scanning. Falls back to the full lib source
/// filtered to lines mentioning the symbol (conservative: thin inline blocks only
/// mention the symbol on re-export lines).
fn extract_inline_block(lib: &str, name: &str) -> String {
    let lines: Vec<&str> = lib.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();
        let opens_block = trimmed.starts_with(&format!("pub mod {name}"))
            || trimmed.starts_with(&format!("pub mod {name} "));
        if opens_block && trimmed.contains('{') {
            let mut depth = 0;
            while i < lines.len() {
                let l = lines[i];
                depth += l.matches('{').count() as i32 - l.matches('}').count() as i32;
                out.push_str(l);
                out.push('\n');
                i += 1;
                if depth <= 0 {
                    break;
                }
            }
            continue;
        }
        if trimmed.contains(name)
            && (trimmed.starts_with("pub use") || trimmed.starts_with("pub mod"))
        {
            out.push_str(line);
            out.push('\n');
        }
        i += 1;
    }
    out
}

fn code_lines(src: &str) -> Vec<String> {
    src.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| {
            !(l.is_empty()
                || l.starts_with("//")
                || l.starts_with("//!")
                || l.starts_with("/*")
                || l.starts_with('*'))
        })
        .collect()
}

#[test]
fn removed_facades_stay_removed() {
    let repo = workspace_root();
    let lib = std::fs::read_to_string(repo.join("src/lib.rs")).expect("read src/lib.rs");
    let ledger = std::fs::read_to_string(repo.join("architecture/root_module_ledger.md"))
        .expect("read ledger");
    let matrix = std::fs::read_to_string(repo.join("architecture/facade_disposition_matrix.md"))
        .expect("read disposition matrix");

    let mut violations = Vec::new();

    for facade in REMOVED_FACADES {
        // 1. Not redeclared in lib.rs (mod declaration or `as <name>` re-export).
        for line in lib.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            if trimmed == format!("pub mod {facade};")
                || trimmed.starts_with(&format!("pub mod {facade} "))
                || trimmed.starts_with(&format!("pub mod {facade}{{"))
            {
                violations.push(format!(
                    "src/lib.rs redeclares removed facade `pub mod {facade}`"
                ));
            }
            if trimmed.starts_with("pub use")
                && (trimmed.ends_with(&format!(" as {facade};"))
                    || trimmed.contains(&format!(" as {facade} ")))
            {
                violations.push(format!(
                    "src/lib.rs re-exports removed facade `as {facade}`"
                ));
            }
        }

        // 2. Entry files do not exist on disk.
        if repo.join(format!("src/{facade}/mod.rs")).exists() {
            violations.push(format!("removed facade still on disk: src/{facade}/mod.rs"));
        }
        if repo.join(format!("src/{facade}.rs")).exists()
            && !matches!(*facade, "integrity" | "proxy_cache")
        {
            // integrity/proxy_cache never had flat files; any other flat file is a reintroduction.
            violations.push(format!("removed facade still on disk: src/{facade}.rs"));
        }
        // The removed auth override must not come back either.
        if repo
            .join(format!("src/{facade}/AGENTS.override.md"))
            .exists()
        {
            violations.push(format!(
                "removed facade override still on disk: src/{facade}/AGENTS.override.md"
            ));
        }

        // 3. Ledger records the removal (prevents silent reintroduction without update).
        if !ledger.contains(&format!("| {facade} ")) || !ledger.contains("removed (Phase 03") {
            violations.push(format!(
                "ledger missing Phase 03 removal record for `{facade}`"
            ));
        }

        // 4. Disposition matrix governs the removal.
        if !matrix.contains(facade) || !matrix.contains("remove_now") {
            violations.push(format!(
                "disposition matrix missing `remove_now` record for `{facade}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "removed facades must stay removed (update facade_disposition_matrix.md + ledger to change):\n{}",
        violations.join("\n")
    );
}

#[test]
fn retained_pure_facades_stay_thin() {
    let repo = workspace_root();
    let mut violations = Vec::new();

    // Tokens that indicate substantive local implementation (word-boundary match).
    let forbidden = [
        "fn ", "struct ", "enum ", "trait ", "impl ", "type ", "const ", "static ",
    ];

    for facade in PURE_FACADES {
        let short = facade.split(':').next().unwrap_or(facade);
        let Some(src) = entry_source(&repo, facade) else {
            violations.push(format!("pure facade `{short}` entry file missing"));
            continue;
        };
        if code_lines(&src).is_empty() {
            violations.push(format!("pure facade `{short}` entry file is empty"));
            continue;
        }
        // Must contain at least one re-export.
        if !src.contains("pub use") {
            violations.push(format!(
                "pure facade `{short}` contains no `pub use` re-export"
            ));
        }
        for (idx, line) in code_lines(&src).iter().enumerate() {
            // Allow attributes, cfg gates, module plumbing, re-exports, braces.
            if line.starts_with('#')
                || line.starts_with("pub use")
                || line.starts_with("use ")
                || line.starts_with("pub mod")
                || line == "{"
                || line == "}"
            {
                continue;
            }
            let padded = format!(" {line} ");
            for token in forbidden {
                // `type` appears in legitimate `pub use foo::type` paths? No — but
                // guard against false positives by requiring the token at item position.
                let hit = if *token == *"type " {
                    line.starts_with("pub type ") || line.starts_with("type ")
                } else {
                    padded.contains(token)
                };
                if hit {
                    violations.push(format!(
                        "`{short}` gained implementation at code line {}: {line}",
                        idx + 1
                    ));
                    break;
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "pure facades must stay thin re-exports (document adapters in the matrix instead):\n{}",
        violations.join("\n")
    );
}

#[test]
fn documented_adapters_stay_documented() {
    let repo = workspace_root();
    let lib = std::fs::read_to_string(repo.join("src/lib.rs")).expect("read src/lib.rs");
    let ledger = std::fs::read_to_string(repo.join("architecture/root_module_ledger.md"))
        .expect("read ledger");
    let matrix = std::fs::read_to_string(repo.join("architecture/facade_disposition_matrix.md"))
        .expect("read disposition matrix");

    let mut violations = Vec::new();

    for adapter in DOCUMENTED_ADAPTERS {
        // Still declared (adapters are permitted implementation).
        let declared = lib.contains(&format!("pub mod {adapter}"))
            || lib.contains(&format!("pub mod {adapter};"))
            || lib.contains(adapter);
        if !declared {
            violations.push(format!(
                "documented adapter `{adapter}` missing from src/lib.rs"
            ));
        }
        // Documented in both the matrix and the ledger.
        if !matrix.contains(adapter) {
            violations.push(format!(
                "adapter `{adapter}` missing from disposition matrix"
            ));
        }
        if !ledger.contains(&format!("| {adapter} ")) {
            violations.push(format!("adapter `{adapter}` missing from ledger"));
        }
    }

    // The three known root-only adapter surfaces must keep their documentation.
    for anchor in ["ProxyServer", "quic_tunnel_dispatch", "compat submodules"] {
        if !matrix.contains(anchor) {
            violations.push(format!("matrix missing adapter anchor `{anchor}`"));
        }
    }

    assert!(
        violations.is_empty(),
        "documented adapters must stay declared and documented:\n{}",
        violations.join("\n")
    );
}
