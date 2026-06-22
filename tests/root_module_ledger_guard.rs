//! Guard test ensuring every public root module in `src/lib.rs` is recorded
//! in the ownership ledger at `architecture/root_module_ledger.md`.
//!
//! This prevents the ledger from drifting when new root modules are added
//! without updating the documentation.

use std::path::PathBuf;

#[test]
fn root_exports_are_recorded_in_ownership_ledger() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lib = std::fs::read_to_string(repo.join("src/lib.rs")).unwrap();
    let ledger = std::fs::read_to_string(repo.join("architecture/root_module_ledger.md")).unwrap();

    let mut missing = Vec::new();
    for line in lib.lines() {
        let trimmed = line.trim();

        // Skip comments and blank lines
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#") {
            continue;
        }

        // Extract module names from `pub mod foo;` declarations
        if let Some(rest) = trimmed.strip_prefix("pub mod ") {
            let name = rest
                .split(|c: char| c == ';' || c == '{' || c.is_whitespace())
                .next()
                .unwrap_or("");
            if name.is_empty() || name == "test_utils" {
                continue;
            }
            let needle = format!("| {} ", name);
            if !ledger.contains(&needle) {
                missing.push(name.to_string());
            }
        }

        // Extract re-export names from `pub use synvoid_foo as bar;`
        if let Some(rest) = trimmed.strip_prefix("pub use synvoid_") {
            if let Some(as_pos) = rest.find(" as ") {
                let name = rest[as_pos + 4..]
                    .split(|c: char| c == ';' || c.is_whitespace())
                    .next()
                    .unwrap_or("");
                if !name.is_empty() {
                    let needle = format!("| {} ", name);
                    if !ledger.contains(&needle) {
                        missing.push(name.to_string());
                    }
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "root modules missing from architecture/root_module_ledger.md: {}",
        missing.join(", ")
    );
}
