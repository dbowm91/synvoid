//! Root-test ownership: STATIC_POLICY
//! Rationale: validates Phase 21 admin/plugin root-boundary closure
//!
//! Guards the Phase 21 ownership audit (`architecture/admin_root_ownership.md`):
//! - root `plugin` must not duplicate crate-owned runtime/manifest/trust types;
//! - `synvoid-plugin-runtime` must not import the root `synvoid` facade;
//! - root admin `common` must re-export crate DTOs instead of redefining them;
//! - the root module ledger, burn-down report, and final surface audit must
//!   agree on the remaining `split_required` set.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_source(path: &PathBuf) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e))
}

/// Strip line comments (`//`), block comments (`/* */`), and string literals
/// so structural scans do not match prose or example code.
fn strip_comments_and_strings(content: &str) -> String {
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
            '"' => loop {
                match chars.next() {
                    Some('\\') => {
                        chars.next();
                    }
                    Some('"') => break,
                    Some(_) => {}
                    None => break,
                }
            },
            _ => result.push(ch),
        }
    }
    result
}

fn rust_files_under(dir: &PathBuf) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !dir.is_dir() {
        return files;
    }
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            files.extend(rust_files_under(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    files
}

/// Root `plugin` must be a lifecycle/composition facade over the canonical
/// `synvoid-plugin-runtime` manager, not a second runtime implementation.
#[test]
fn root_plugin_defines_no_runtime_types() {
    let repo = repo_root();
    let file = repo.join("src").join("plugin").join("mod.rs");
    let cleaned = strip_comments_and_strings(&read_source(&file));

    let forbidden = [
        "pub struct PluginManager",
        "pub struct PluginManagerLifecycle",
        "struct UnsafeNativeExtensionWrapper",
        "pub struct PluginManifest",
        "pub enum PluginTrustTier",
        "pub struct PluginCapabilities",
        "pub enum PluginCapability",
        "pub struct WasmRuntime",
        "pub struct WasmPluginManager",
        "pub struct WasmResourceLimits",
        "runtimes.write",
        "fn enforce_plugin_load_policy",
        "fn verify_plugin_signature",
        "fn limits_from_manifest",
    ];
    let mut violations = Vec::new();
    for pattern in &forbidden {
        if cleaned.contains(pattern) {
            violations.push(pattern.to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "src/plugin/mod.rs duplicates crate-owned runtime types (Phase 21):\n{}",
        violations.join("\n")
    );

    assert!(
        cleaned.contains("pub use synvoid_plugin_runtime::plugin_manager::")
            && cleaned.contains("PluginManager"),
        "src/plugin/mod.rs must re-export the canonical crate PluginManager"
    );
}

/// `synvoid-plugin-runtime` must not import the root `synvoid::` facade.
/// (Scoped counterpart of `root_facade_boundary_guard` for the Phase 21
/// crate-purity invariant.)
#[test]
fn plugin_runtime_crate_does_not_import_root() {
    let repo = repo_root();
    let crate_root = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src");
    let mut offenders = Vec::new();
    for path in rust_files_under(&crate_root) {
        let text = read_source(&path);
        let cleaned = strip_comments_and_strings(&text);
        for (line_num, line) in cleaned.lines().enumerate() {
            if line.contains("use synvoid::") || line.contains(" synvoid::") {
                let relative = path
                    .strip_prefix(&repo)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                offenders.push(format!("{}:{}: {}", relative, line_num + 1, line.trim()));
                break;
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "synvoid-plugin-runtime must not import root synvoid paths:\n{}",
        offenders.join("\n")
    );
}

/// Root admin `common` must re-export crate DTOs, not redefine them.
#[test]
fn root_admin_common_reexports_crate_dtos() {
    let repo = repo_root();
    let file = repo
        .join("src")
        .join("admin")
        .join("handlers")
        .join("common.rs");
    let cleaned = strip_comments_and_strings(&read_source(&file));

    for pattern in [
        "pub struct PaginationQuery",
        "pub struct PaginatedResponse",
        "pub struct StatusResponse",
        "pub struct ErrorPage",
        "pub const ERROR_PAGES",
        "pub struct PaginationLimits",
        "pub const PAGINATION_LIMITS_DEFAULT",
        "pub enum RequiredRole",
        "pub struct AuthenticatedUser",
        "fn parse_ip(",
    ] {
        assert!(
            !cleaned.contains(pattern),
            "src/admin/handlers/common.rs redefines crate-owned item '{pattern}' \
             (Phase 21: re-export synvoid_admin::handlers::common instead)"
        );
    }
    assert!(
        cleaned.contains("pub use synvoid_admin::handlers::common::"),
        "src/admin/handlers/common.rs must re-export the canonical crate DTOs"
    );
}

/// Extract module names whose ledger row classifies them `split_required`.
/// Rows look like `| admin | ... | split_required | ... |` (ledger, possibly
/// backticked in the audit doc); the first cell is the module name.
fn split_required_modules(text: &str) -> Vec<String> {
    let mut modules = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') || !trimmed.ends_with('|') {
            continue;
        }
        if trimmed.contains("---") {
            continue;
        }
        let cells: Vec<String> = trimmed[1..trimmed.len() - 1]
            .split('|')
            .map(|c| c.trim().trim_matches('`').trim_matches('"').to_string())
            .collect();
        if cells.iter().any(|c| c == "split_required") && !cells.is_empty() {
            let name = cells[0].trim_matches('`').to_string();
            if !name.is_empty() && name != "Module" {
                modules.push(name);
            }
        }
    }
    modules.sort();
    modules.dedup();
    modules
}

/// Ledger, burn-down report, and final surface audit must agree on the
/// remaining `split_required` set (Phase 21 Part G reconciliation).
#[test]
fn ledger_burndown_surface_audit_agree_on_split_required() {
    let repo = repo_root();
    let ledger = read_source(&repo.join("architecture/root_module_ledger.md"));
    let burndown = read_source(&repo.join("architecture/root_module_burndown_report.md"));
    let audit = read_source(&repo.join("architecture/final_surface_audit.md"));

    let ledger_modules = split_required_modules(&ledger);
    let audit_modules = split_required_modules(&audit);

    // Burn-down "Remaining `split_required` Modules" section lists rows as
    // `| `module` | LOC | Blocker |`; every row in that section is remaining.
    let mut burndown_modules = Vec::new();
    let mut in_remaining = false;
    for line in burndown.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## ") {
            in_remaining = trimmed.contains("Remaining") && trimmed.contains("split_required");
        } else if in_remaining
            && trimmed.starts_with('|')
            && trimmed.ends_with('|')
            && !trimmed.contains("---")
            && !trimmed.contains("Module")
        {
            let first = trimmed[1..trimmed.len() - 1]
                .split('|')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('`')
                .to_string();
            if !first.is_empty() {
                burndown_modules.push(first);
            }
        }
    }
    burndown_modules.sort();
    burndown_modules.dedup();

    assert_eq!(
        ledger_modules, burndown_modules,
        "root_module_ledger.md and root_module_burndown_report.md disagree on \
         remaining split_required modules"
    );
    assert_eq!(
        ledger_modules, audit_modules,
        "root_module_ledger.md and final_surface_audit.md disagree on \
         remaining split_required modules"
    );
}
