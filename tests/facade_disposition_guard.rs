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
//! NOTE (Phase 25): the pre-existing orphan `.rs` files that used to sit beside
//! these facades (e.g. `src/process/ipc.rs`, sibling files under
//! `src/honeypot_port/` / `src/serverless/`) were dead source — not reachable
//! from `src/lib.rs` (no `mod` declaration, no `#[path]`, no `include!`) and
//! therefore never compiled. Phase 25 deleted them and this guard now prohibits
//! their return via `pure_facade_dirs_contain_no_orphan_sources` below.

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
    "icmp_filter",
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

/// Declared child modules of a module file: `mod <name>;` / `pub mod <name>;`
/// (attributes such as `#[cfg]` on preceding lines do not matter) plus explicit
/// `#[path = "..."]` file mappings.
fn declared_children(src: &str) -> (Vec<String>, Vec<String>) {
    let mut mods = Vec::new();
    for line in src.lines() {
        let trimmed = line.trim();
        // Strip a leading `pub(...)` qualifier if present.
        let rest = if let Some(after_pub) = trimmed.strip_prefix("pub") {
            let after_pub = after_pub.trim_start();
            if let Some(paren_end) = after_pub.strip_prefix('(').and_then(|s| s.find(')')) {
                after_pub[paren_end + 1..].trim_start()
            } else {
                after_pub
            }
        } else {
            trimmed
        };
        if let Some(after_mod) = rest.strip_prefix("mod ") {
            let name: String = after_mod
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                mods.push(name);
            }
        }
    }
    let mut paths = Vec::new();
    let mut search = src;
    while let Some(idx) = search.find("#[path") {
        let rest = &search[idx..];
        if let Some(q1) = rest.find('"') {
            if let Some(q2) = rest[q1 + 1..].find('"') {
                paths.push(rest[q1 + 1..q1 + 1 + q2].to_string());
            }
        }
        search = &rest[1..];
    }
    (mods, paths)
}

fn collect_rs_files_recursive(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|_| panic!("read {}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files_recursive(&path, out);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

#[test]
fn pure_facade_dirs_contain_no_orphan_sources() {
    // Phase 25: every `.rs` file under a pure-facade directory must be the entry
    // `mod.rs` or a file reachable through `mod` declarations (including
    // `#[path]` mappings). Undeclared files are never compiled; they rot, confuse
    // audits, and must be deleted — not left beside the facade.
    let repo = workspace_root();
    let mut violations = Vec::new();

    for facade in PURE_FACADES {
        let short = facade.split(':').next().unwrap_or(facade);
        if facade.contains(':') {
            continue; // inline/file facades have no directory to audit
        }
        let dir = repo.join(format!("src/{short}"));
        if !dir.is_dir() {
            continue; // flat `src/<name>.rs` facades: nothing to audit
        }
        let mut files = Vec::new();
        collect_rs_files_recursive(&dir, &mut files);
        // Expected set: each dir's mod.rs plus declared children.
        let mut expected = std::collections::BTreeSet::new();
        // Seed with every mod.rs (each directory level needs its entry file).
        for f in &files {
            if f.file_name().map(|n| n == "mod.rs").unwrap_or(false) {
                expected.insert(f.clone());
            }
        }
        // Expand declared children relative to the declaring file's directory.
        // Iterate to a fixed point for nested declarations.
        loop {
            let mut added = false;
            let snapshot: Vec<std::path::PathBuf> = expected.iter().cloned().collect();
            for f in &snapshot {
                let src = std::fs::read_to_string(f).unwrap_or_default();
                let parent = f.parent().unwrap_or(&dir);
                let (mods, paths) = declared_children(&src);
                for m in mods {
                    for candidate in [
                        parent.join(format!("{m}.rs")),
                        parent.join(&m).join("mod.rs"),
                    ] {
                        if candidate.is_file() && expected.insert(candidate) {
                            added = true;
                        }
                    }
                }
                for p in paths {
                    let candidate = parent.join(&p);
                    if candidate.is_file() && expected.insert(candidate) {
                        added = true;
                    }
                }
            }
            if !added {
                break;
            }
        }
        for f in &files {
            if !expected.contains(f) {
                violations.push(format!(
                    "orphan source under pure facade `src/{short}/`: {} is not declared by any `mod`/`#[path]` (delete it — undeclared files are never compiled)",
                    f.strip_prefix(&repo).unwrap_or(f).display()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "pure-facade directories must not contain undeclared `.rs` files:\n{}",
        violations.join("\n")
    );
}
