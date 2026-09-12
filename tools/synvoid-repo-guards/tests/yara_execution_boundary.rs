//! Phase 26 YARA execution-boundary guards.
//!
//! Pins the consolidation: one canonical `yara-x` owner (`synvoid-yara`),
//! no compilation in mesh, jail uses the generic engine directly.

use std::fs;
use synvoid_repo_guards::{prepare_for_scanning, workspace_root, Violations};

fn read_repo(rel: &str) -> String {
    let repo = workspace_root();
    fs::read_to_string(repo.join(rel)).unwrap_or_else(|_| panic!("read {rel}"))
}

fn manifest_declares_yara_x(manifest: &str) -> bool {
    // Only match real dependency declarations, not comments explaining absence.
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        // Strip inline comments.
        let code = t.split('#').next().unwrap_or("").trim();
        if code.contains("yara-x") && code.contains('=') {
            return true;
        }
    }
    false
}

#[test]
fn only_approved_crates_declare_yara_x() {
    let repo = workspace_root();
    let mut violations = Violations::new();
    let approved = ["crates/synvoid-yara/Cargo.toml"];
    // Walk all crate manifests.
    let crates_dir = repo.join("crates");
    if let Ok(entries) = fs::read_dir(&crates_dir) {
        for entry in entries.flatten() {
            let manifest_path = entry.path().join("Cargo.toml");
            if !manifest_path.exists() {
                continue;
            }
            let content = fs::read_to_string(&manifest_path).unwrap_or_default();
            if manifest_declares_yara_x(&content) {
                let rel = manifest_path
                    .strip_prefix(&repo)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                if !approved.contains(&rel.as_str()) {
                    violations.push(format!(
                        "{rel} declares yara-x; only synvoid-yara may (Phase 26 single owner)"
                    ));
                }
            }
        }
    }
    // Root must never declare yara-x directly.
    let root_manifest = read_repo("Cargo.toml");
    // Check workspace-level + root package deps (ignore the workspace.members list
    // which legitimately names crates/synvoid-yara).
    for line in root_manifest.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.starts_with("members") || t.contains("crates/synvoid-yara") {
            continue;
        }
        let code = t.split('#').next().unwrap_or("").trim();
        if code.contains("yara-x") && code.contains('=') {
            violations.push(format!("root Cargo.toml declares yara-x: {t}"));
        }
    }
    violations.assert_ok("yara-x ownership violations");
}

#[test]
fn mesh_contains_no_yara_x_production_reference() {
    let repo = workspace_root();
    let mesh_src = repo.join("crates/synvoid-mesh/src");
    let mut violations = Violations::new();
    let mut stack = vec![mesh_src];
    while let Some(dir) = stack.pop() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                    let content = fs::read_to_string(&path).unwrap_or_default();
                    let code = prepare_for_scanning(&content);
                    if code.contains("yara_x::") || code.contains("yara_x ") {
                        violations.push(format!(
                            "{} references yara_x in production code (mesh must use injected validator)",
                            path.strip_prefix(&repo).unwrap_or(&path).display()
                        ));
                    }
                }
            }
        }
    }
    violations.assert_ok("mesh yara_x references");
}

#[test]
fn synvoid_yara_has_no_forbidden_reverse_deps() {
    let manifest = read_repo("crates/synvoid-yara/Cargo.toml");
    let forbidden = [
        "synvoid-mesh",
        "synvoid-upload",
        "synvoid-http",
        "synvoid-admin",
        "synvoid-waf",
    ];
    let mut violations = Violations::new();
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let code = t.split('#').next().unwrap_or("");
        for dep in &forbidden {
            // Match `dep =` / `dep=` dependency declarations.
            if code.contains(dep) && code.contains('=') {
                violations.push(format!("synvoid-yara must not depend on {dep}: {t}"));
            }
        }
    }
    // Root crate dep is `path = "."` or `name = "synvoid"`; forbid both.
    if manifest.contains("path = \".\"") || manifest.contains("name = \"synvoid\"") {
        violations.push("synvoid-yara must not depend on the root crate".to_string());
    }
    violations.assert_ok("synvoid-yara reverse dependencies");
}

#[test]
fn yara_jail_uses_generic_engine_directly() {
    let service = read_repo("src/sandbox/yara_service.rs");
    let code = prepare_for_scanning(&service);
    assert!(
        code.contains("synvoid_yara"),
        "yara_service.rs must import the generic synvoid-yara engine (Phase 26 Part E)"
    );
    assert!(
        !code.contains("synvoid_upload"),
        "yara_service.rs must not couple to the upload domain (use synvoid-yara directly)"
    );
}

#[test]
fn upload_does_not_link_yara_x_directly() {
    let manifest = read_repo("crates/synvoid-upload/Cargo.toml");
    assert!(
        !manifest_declares_yara_x(&manifest),
        "synvoid-upload must consume synvoid-yara contracts, not yara-x directly"
    );
    let scanner = read_repo("crates/synvoid-upload/src/yara_scanner.rs");
    let code = prepare_for_scanning(&scanner);
    assert!(
        !code.contains("yara_x::"),
        "synvoid-upload/src/yara_scanner.rs must not reference yara_x (facade over synvoid-yara)"
    );
}
