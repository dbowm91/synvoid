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
    // which legitimately names crates/synvoid-yara). `[patch.*]` sections are
    // skipped: path overrides are not dependency declarations and are governed
    // by the fork-temporariness guards (`*_fork_is_temporary_guard`) instead.
    let mut in_patch = false;
    for line in root_manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_patch = t.starts_with("[patch");
            continue;
        }
        if in_patch {
            continue;
        }
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
    // Phase 29: canonical YARA jail service lives in `synvoid-jail-runtime`;
    // the root path is a pure facade. Both layers must use the generic engine
    // directly, never the upload domain.
    let service = read_repo("crates/synvoid-jail-runtime/src/yara_service.rs");
    let code = prepare_for_scanning(&service);
    assert!(
        code.contains("synvoid_yara"),
        "jail-runtime yara_service.rs must import the generic synvoid-yara engine (Phase 26 Part E)"
    );
    assert!(
        !code.contains("synvoid_upload"),
        "jail-runtime yara_service.rs must not couple to the upload domain (use synvoid-yara directly)"
    );
    let facade = prepare_for_scanning(&read_repo("src/sandbox/yara_service.rs"));
    assert!(
        facade.contains("synvoid_jail_runtime::YaraJailService"),
        "root yara_service.rs must remain a facade over synvoid-jail-runtime (Phase 29)"
    );
    assert!(
        !facade.contains("synvoid_upload"),
        "root yara facade must not couple to the upload domain"
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

// ---------------------------------------------------------------------------
// Phase 38 Part D: compiled-byte boundary guards
//
// GHSA-2jx3-ff3v-j7jj: `yara_x::Rules::deserialize` on malformed serialized
// bytes can cause memory corruption. Phase 36 removed every remote-bytes
// path; these guards fail if one is reintroduced.
// ---------------------------------------------------------------------------

/// True if production code (comments/strings/tests stripped) calls the
/// dangerous YARA deserializer. Narrow: matches only `Rules::deserialize`
/// (the yara-x executable path), not benign serde/toml/postcard deserializes.
fn calls_rules_deserialize(code: &str) -> bool {
    code.contains("Rules::deserialize")
}

fn collect_production_rs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(entries) = fs::read_dir(&d) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                    out.push(path);
                }
            }
        }
    }
    out
}

#[test]
fn mesh_must_not_call_rules_deserialize() {
    let repo = workspace_root();
    let mut violations = Violations::new();
    for path in collect_production_rs(&repo.join("crates/synvoid-mesh/src")) {
        let content = fs::read_to_string(&path).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        if calls_rules_deserialize(&code) {
            violations.push(format!(
                "{} calls Rules::deserialize (mesh must never deserialize compiled YARA; recompile approved source via synvoid-yara)",
                path.strip_prefix(&repo).unwrap_or(&path).display()
            ));
        }
    }
    violations.assert_ok("mesh Rules::deserialize violations");
}

#[test]
fn upload_must_not_call_rules_deserialize() {
    let repo = workspace_root();
    let mut violations = Violations::new();
    for path in collect_production_rs(&repo.join("crates/synvoid-upload/src")) {
        let content = fs::read_to_string(&path).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        if calls_rules_deserialize(&code) {
            violations.push(format!(
                "{} calls Rules::deserialize (upload must recompile approved source via synvoid-yara, never deserialize remote bytes)",
                path.strip_prefix(&repo).unwrap_or(&path).display()
            ));
        }
    }
    violations.assert_ok("upload Rules::deserialize violations");
}

#[test]
fn synvoid_yara_has_no_remote_deserialize_path() {
    // Phase 36 removed `reload_with_compiled_rules`,
    // `CompiledArtifact::{deserialize_verified, from_bytes_with_binding}`, and
    // every other remote-bytes constructor. If a local verified-artifact path
    // is ever re-added, this guard forces an explicit allowlist update here —
    // it must not silently reappear.
    let repo = workspace_root();
    let mut violations = Violations::new();
    for path in collect_production_rs(&repo.join("crates/synvoid-yara/src")) {
        let content = fs::read_to_string(&path).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        if calls_rules_deserialize(&code) {
            violations.push(format!(
                "{} calls Rules::deserialize (no remote deserialize path may exist in synvoid-yara without an explicit guard allowlist update)",
                path.strip_prefix(&repo).unwrap_or(&path).display()
            ));
        }
    }
    violations.assert_ok("synvoid-yara Rules::deserialize violations");
}

#[test]
fn mesh_must_not_prefer_compiled_bytes_over_source() {
    // Removed Phase 36 APIs must not return under new names. Production mesh
    // code must never select compiled bytes as the executable input.
    let repo = workspace_root();
    let forbidden = [
        "reload_with_compiled_rules",
        "deserialize_verified",
        "from_bytes_with_binding",
        "local_compiled_rules",
        "apply_compiled_rules",
        "get_current_compiled_rules",
        "CompiledBundle",
    ];
    let mut violations = Violations::new();
    for path in collect_production_rs(&repo.join("crates/synvoid-mesh/src")) {
        let content = fs::read_to_string(&path).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        for token in &forbidden {
            if code.contains(token) {
                violations.push(format!(
                    "{} contains removed compiled-byte API `{token}` (source text is the only executable input since Phase 36)",
                    path.strip_prefix(&repo).unwrap_or(&path).display()
                ));
            }
        }
    }
    // Same tokens must not reappear as an executable input in synvoid-yara.
    // (Doc comments explaining the Phase 36 removal are stripped by
    // `prepare_for_scanning`, so any remaining hit is real code.)
    for path in collect_production_rs(&repo.join("crates/synvoid-yara/src")) {
        let content = fs::read_to_string(&path).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        for token in [
            "reload_with_compiled_rules",
            "deserialize_verified",
            "from_bytes_with_binding",
            "CompiledBundle",
        ] {
            if code.contains(token) {
                violations.push(format!(
                    "{} contains removed compiled-byte API `{token}`",
                    path.strip_prefix(&repo).unwrap_or(&path).display()
                ));
            }
        }
    }
    violations.assert_ok("compiled-byte preference violations");
}

fn declared_yara_x_minor(manifest: &str) -> Option<String> {
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let code = t.split('#').next().unwrap_or("").trim();
        if code.contains("yara-x") && code.contains("version") {
            // Extract `version = "1.20"` (major.minor prefix; patch floats).
            if let Some(pos) = code.find("version") {
                let rest = &code[pos..];
                if let Some(q1) = rest.find('"') {
                    if let Some(q2) = rest[q1 + 1..].find('"') {
                        let v = rest[q1 + 1..q1 + 1 + q2].to_string();
                        let mut parts = v.split('.');
                        if let (Some(maj), Some(min)) = (parts.next(), parts.next()) {
                            return Some(format!("{maj}.{min}"));
                        }
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

fn engine_version_tag(lib: &str) -> Option<String> {
    for line in lib.lines() {
        let t = line.trim();
        if t.starts_with("pub const YARA_ENGINE_VERSION") {
            if let Some(q1) = t.find('"') {
                if let Some(q2) = t[q1 + 1..].find('"') {
                    return Some(t[q1 + 1..q1 + 1 + q2].to_string());
                }
            }
        }
    }
    None
}

#[test]
fn yara_engine_version_matches_manifest() {
    // `YARA_ENGINE_VERSION` must track the declared yara-x major.minor line so
    // old-engine artifacts reject deterministically after an upgrade.
    let manifest = read_repo("crates/synvoid-yara/Cargo.toml");
    let minor = declared_yara_x_minor(&manifest)
        .expect("synvoid-yara manifest must declare yara-x version");
    let artifact = read_repo("crates/synvoid-yara/src/artifact.rs");
    let tag = engine_version_tag(&artifact).expect("artifact.rs must define YARA_ENGINE_VERSION");
    let expected_prefix = format!("yara-x/{minor}");
    assert!(
        tag.starts_with(&expected_prefix),
        "YARA_ENGINE_VERSION {tag:?} must match declared yara-x line {minor:?} (expected prefix {expected_prefix:?}); bump both together"
    );
}
