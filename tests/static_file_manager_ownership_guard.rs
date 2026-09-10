//! Root-test ownership: STATIC_POLICY
//! Rationale: validates Phase 02 static file-manager ownership closure
//! (canonical `synvoid-static-files` implementation vs root facade)
//!
//! Guards the ownership model recorded in
//! `architecture/root_module_ledger.md` and
//! `architecture/root_module_burndown_report.md` (Phase 02):
//!
//! 1. Exactly one canonical `FileManager` implementation exists.
//! 2. All consumers reference it directly or through a pure re-export.
//! 3. The no-op YARA refresh surface stays removed.
//! 4. `synvoid-static-files` never imports the root `synvoid` crate.
//! 5. The root facade stays thin and the ledger records the final decision.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_to_string(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn is_comment_or_blank(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with("//")
}

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

fn code_contains(path: &Path, needle: &str) -> bool {
    read_to_string(path)
        .lines()
        .any(|line| !is_comment_or_blank(line) && line.contains(needle))
}

/// 1. Exactly one canonical `FileManager` implementation exists.
#[test]
fn single_canonical_file_manager_implementation() {
    let root = workspace_root();
    let canonical = root.join("crates/synvoid-static-files/src/file_manager.rs");
    assert!(
        canonical.exists(),
        "canonical implementation missing: crates/synvoid-static-files/src/file_manager.rs"
    );
    assert!(
        code_contains(&canonical, "pub struct FileManager"),
        "canonical file_manager.rs must define `pub struct FileManager`"
    );

    // The old root implementation must stay deleted.
    let removed = root.join("src/static_files/file_manager.rs");
    assert!(
        !removed.exists(),
        "root duplicate must stay deleted: src/static_files/file_manager.rs"
    );

    // No second `struct FileManager` may appear under the root facade.
    let facade_dir = root.join("src/static_files");
    let mut files = Vec::new();
    walk_rs_files(&facade_dir, &mut files);
    let mut offenders = Vec::new();
    for path in &files {
        if code_contains(path, "pub struct FileManager") {
            offenders.push(path.strip_prefix(&root).unwrap().display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "root static_files facade must not define a second FileManager: {offenders:?}"
    );

    // The crate must declare the module.
    assert!(
        code_contains(
            &root.join("crates/synvoid-static-files/src/lib.rs"),
            "pub mod file_manager"
        ),
        "synvoid-static-files/src/lib.rs must declare `pub mod file_manager`"
    );
}

/// 2. Consumers reference the canonical implementation.
#[test]
fn consumers_use_canonical_imports() {
    let root = workspace_root();
    for rel in ["src/http/file_manager.rs", "src/http/webdav.rs"] {
        let path = root.join(rel);
        assert!(path.exists(), "consumer missing: {rel}");
        let text = read_to_string(&path);
        assert!(
            text.contains("synvoid_static_files::file_manager"),
            "{rel} must import the canonical `synvoid_static_files::file_manager` path"
        );
        assert!(
            !text.contains("crate::static_files::file_manager"),
            "{rel} must not import the legacy `crate::static_files::file_manager` path"
        );
    }
}

/// 3. The no-op YARA refresh surface stays removed.
///
/// Phase 02 deleted `reload_yara_rules_if_needed` (no-op `Ok(())` under both
/// mesh and non-mesh), `new_with_periodic_refresh`, and
/// `start_periodic_yara_refresh`. None may reappear in the canonical module
/// or the root facade/adapters.
#[test]
fn noop_refresh_surface_stays_removed() {
    let root = workspace_root();
    let paths = [
        "crates/synvoid-static-files/src/file_manager.rs",
        "src/static_files/mod.rs",
        "src/http/file_manager.rs",
        "src/http/webdav.rs",
    ];
    for needle in [
        "reload_yara_rules_if_needed",
        "new_with_periodic_refresh",
        "start_periodic_yara_refresh",
    ] {
        let mut offenders = Vec::new();
        for rel in paths {
            let path = root.join(rel);
            if path.exists() && code_contains(&path, needle) {
                offenders.push(rel.to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "removed refresh surface `{needle}` must not reappear in: {offenders:?}"
        );
    }

    // The honest rule-update lifecycle must remain documented: observable
    // version accessor plus injected backend trait.
    let canonical = root.join("crates/synvoid-static-files/src/file_manager.rs");
    for required in [
        "FileManagerSecurityBackend",
        "yara_rule_version",
        "scan_upload_bytes",
        "check_upload_rate_allowed",
        "detect_content_mime_types",
    ] {
        assert!(
            code_contains(&canonical, required),
            "canonical file_manager.rs must contain `{required}` (injected backend contract)"
        );
    }
}

/// 4. The domain crate must not depend on the root crate.
#[test]
fn static_files_crate_never_imports_root() {
    let root = workspace_root();
    let crate_dir = root.join("crates").join("synvoid-static-files");
    let mut files = Vec::new();
    walk_rs_files(&crate_dir, &mut files);
    assert!(!files.is_empty(), "expected synvoid-static-files sources");

    let mut offenders = Vec::new();
    for path in &files {
        for (line_num, line) in read_to_string(path).lines().enumerate() {
            if is_comment_or_blank(line) {
                continue;
            }
            // `crate::` inside the crate refers to synvoid-static-files itself.
            // `synvoid::` would be the root application crate and is forbidden.
            // `synvoid_*` crate paths (with underscore suffix) are fine.
            if line.contains("use synvoid::") || line.contains(" synvoid::") {
                offenders.push(format!(
                    "{}:{}: {line}",
                    path.strip_prefix(&root).unwrap().display(),
                    line_num + 1
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "synvoid-static-files must not import the root synvoid crate:\n{}",
        offenders.join("\n")
    );
}

/// 5. The root facade stays a pure re-export and the ledger records it.
#[test]
fn root_facade_stays_pure_and_ledger_agrees() {
    let root = workspace_root();
    let facade = root.join("src/static_files/mod.rs");
    assert!(facade.exists(), "facade missing: src/static_files/mod.rs");
    let text = read_to_string(&facade);
    assert!(
        text.contains("pub use synvoid_static_files::file_manager"),
        "facade must re-export the canonical file_manager module"
    );
    assert!(
        !text.contains("pub mod file_manager"),
        "facade must not declare a local `file_manager` implementation module"
    );
    assert!(
        text.lines().count() <= 20,
        "facade must stay thin (<=20 lines), got {}",
        text.lines().count()
    );

    let ledger = read_to_string(&root.join("architecture/root_module_ledger.md"));
    assert!(
        !ledger.contains("local `file_manager` needs investigation"),
        "ledger must no longer say file_manager \"needs investigation\""
    );
    assert!(
        ledger.contains("pure re-export facade"),
        "ledger must record static_files as a pure re-export facade"
    );
}
