//! Static guards for root module ledger, facade boundary, and dependency ownership.
//!
//! These guards ensure:
//! - Every public root module in `src/lib.rs` is recorded in the ownership ledger
//! - Domain crates (`crates/`) do not import root `synvoid::` paths
//! - Root dependencies have ownership ledger entries

use std::collections::BTreeSet;
use std::fs;
use synvoid_repo_guards::{collect_source_files, workspace_root, Violations};

// ---------------------------------------------------------------------------
// root_module_ledger_guard
// ---------------------------------------------------------------------------

#[test]
fn root_exports_are_recorded_in_ownership_ledger() {
    let repo = workspace_root();
    let lib = fs::read_to_string(repo.join("src/lib.rs")).unwrap();
    let ledger = fs::read_to_string(repo.join("architecture/root_module_ledger.md")).unwrap();

    let mut missing = Vec::new();
    for line in lib.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#") {
            continue;
        }
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

// ---------------------------------------------------------------------------
// root_facade_boundary_guard
// ---------------------------------------------------------------------------

/// Files in `crates/` that are exempt from the facade boundary because they
/// are the legacy root re-export facade itself or test utilities.
const FACADE_EXEMPT: &[&str] = &["crates/synvoid-testkit/"];

#[test]
fn domain_crates_do_not_import_root_facade() {
    let repo = workspace_root();
    let _crates_dir = repo.join("crates");
    let files = collect_source_files(&repo);
    let mut violations = Violations::new();

    for file in &files {
        let rel = file.strip_prefix(&repo).unwrap_or(file);
        let rel_str = rel.to_string_lossy();

        // Only scan crates/ files (not src/)
        if !rel_str.starts_with("crates/") {
            continue;
        }

        // Skip exempt files
        if FACADE_EXEMPT.iter().any(|e| rel_str.starts_with(e)) {
            continue;
        }

        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = synvoid_repo_guards::prepare_for_scanning(&content);

        for (line_no, line) in scanned.lines().enumerate() {
            let trimmed = line.trim();
            // Check for `use synvoid::` imports
            if trimmed.contains("use synvoid::") {
                violations.push(format!(
                    "{}:{}: imports from root synvoid:: facade (domain crates must use narrow traits)",
                    rel_str,
                    line_no + 1
                ));
            }
        }
    }

    violations.assert_ok("root_facade_boundary_guard: domain crates must not import root facade");
}

// ---------------------------------------------------------------------------
// root_dependency_ownership_guard
// ---------------------------------------------------------------------------

fn root_manifest_dependencies(manifest: &str) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let mut in_root_deps = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_root_deps = trimmed == "[dependencies]"
                || (trimmed.starts_with("[target.") && trimmed.ends_with(".dependencies]"));
            continue;
        }
        if !in_root_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once('=') {
            let name = name.trim();
            if !name.is_empty() {
                deps.insert(name.to_string());
            }
        }
    }
    deps
}

fn root_build_dependencies(manifest: &str) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let mut in_build_deps = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_build_deps = trimmed == "[build-dependencies]";
            continue;
        }
        if !in_build_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once('=') {
            let name = name.trim();
            if !name.is_empty() {
                deps.insert(name.to_string());
            }
        }
    }
    deps
}

const VALID_CLASSIFICATIONS: &[&str] = &[
    "composition_runtime",
    "compat_facade",
    "migration_blocker",
    "test_or_tooling",
    "remove_candidate",
];

fn parse_ledger_entries(ledger: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for line in ledger.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("| ") || !trimmed.ends_with(" |") {
            continue;
        }
        if trimmed.contains("---") || trimmed.contains("Dependency") {
            continue;
        }
        let cells: Vec<&str> = trimmed[2..trimmed.len() - 2]
            .split(" | ")
            .map(|s| s.trim())
            .collect();
        if cells.len() >= 3 {
            let dep_name = cells[0].to_string();
            let classification = cells[2].to_string();
            if !dep_name.starts_with('#') && !dep_name.is_empty() {
                entries.push((dep_name, classification));
            }
        }
    }
    entries
}

#[test]
fn root_dependencies_have_ownership_entries() {
    let repo = workspace_root();
    let manifest = fs::read_to_string(repo.join("Cargo.toml")).expect("read Cargo.toml");
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");

    let deps = root_manifest_dependencies(&manifest);
    let mut missing = Vec::new();
    for dep in &deps {
        let needle = format!("| {} |", dep);
        if !ledger.contains(&needle) {
            missing.push(dep.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "root dependencies missing ownership ledger entries:\n{}",
        missing.join("\n")
    );
    for forbidden in ["TBD", "unknown", "fill me in"] {
        assert!(
            !ledger.contains(forbidden),
            "root dependency ledger contains placeholder: {forbidden}"
        );
    }
}

#[test]
fn ledger_entries_are_live() {
    let repo = workspace_root();
    let manifest = fs::read_to_string(repo.join("Cargo.toml")).expect("read Cargo.toml");
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");

    let mut all_deps = root_manifest_dependencies(&manifest);
    all_deps.extend(root_build_dependencies(&manifest));

    let entries = parse_ledger_entries(&ledger);
    let mut stale = Vec::new();
    for (dep_name, classification) in &entries {
        if classification == "remove_candidate" {
            continue;
        }
        if !all_deps.contains(dep_name.as_str()) {
            stale.push(dep_name.clone());
        }
    }
    assert!(
        stale.is_empty(),
        "ledger entries for dependencies not in Cargo.toml (stale entries):\n{}",
        stale.join("\n")
    );
}

#[test]
fn ledger_classifications_are_valid() {
    let repo = workspace_root();
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");

    let entries = parse_ledger_entries(&ledger);
    let mut invalid = Vec::new();
    for (dep_name, classification) in &entries {
        if !VALID_CLASSIFICATIONS.contains(&classification.as_str()) {
            invalid.push(format!(
                "{}: unknown classification '{}'",
                dep_name, classification
            ));
        }
    }
    assert!(
        invalid.is_empty(),
        "ledger entries with invalid classifications:\n{}",
        invalid.join("\n")
    );
}

// ---------------------------------------------------------------------------
// root_dependency_entitlement_guard (Phase 25)
//
// Inventory-only ledger rows permit entitlement drift: a dependency keeps its
// row forever while its consumers move to crates. This guard maps `use` /
// qualified-path references in compiled root source back to manifest
// dependencies and enforces the `Allowed root paths` ledger column:
// - composition_runtime / compat_facade: >=1 production (src/) consumer, and
//   every consumer top-level path must be allowlisted.
// - migration_blocker / remove_candidate with no allowed paths: fail-closed,
//   zero production consumers (a new `use` must reclassify first).
// - test_or_tooling: >=1 tests/benches consumer; no visible production consumer
//   outside unit tests (prepare_for_scanning strips cfg(test) modules).
// Macro-generated / proc-macro / build-script-only dependencies that cannot be
// mechanically attributed must be listed in ENTITLEMENT_EXCEPTIONS with a reason;
// the list is currently empty because no manifest dependency needs it.
// ---------------------------------------------------------------------------

/// Narrow exceptions for dependencies that cannot be mechanically attributed.
/// Each entry is (manifest dependency name, reason). Adding an entry requires a
/// ledger row justifying it; the guard fails on unknown names.
// Phase 31: prost + tonic-prost are codegen runtimes for the supervisor gRPC
// control API (OUT_DIR/synvoid.control.rs references `::prost::Message` and
// ProstCodec); no direct `prost::`/`tonic_prost::` in src/ to attribute.
const ENTITLEMENT_EXCEPTIONS: &[(&str, &str)] = &[
    (
        "prost",
        "tonic codegen runtime (::prost::Message in OUT_DIR, not src/)",
    ),
    (
        "tonic-prost",
        "tonic gRPC Codec runtime (generated ProstCodec, not src/)",
    ),
];

fn parse_entitlement_rows(ledger: &str) -> Vec<(String, String, Vec<String>, bool)> {
    // Returns (dep, classification, allowed_paths, is_build_table).
    let mut rows = Vec::new();
    let mut in_build = false;
    for line in ledger.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## ") {
            in_build = trimmed.contains("Build Dependencies");
            continue;
        }
        if !trimmed.starts_with("| ") || !trimmed.ends_with(" |") {
            continue;
        }
        if trimmed.contains("---") || trimmed.contains("Dependency") {
            continue;
        }
        let cells: Vec<&str> = trimmed[2..trimmed.len() - 2]
            .split(" | ")
            .map(|s| s.trim())
            .collect();
        if cells.len() >= 7 {
            let dep = cells[0].to_string();
            let classification = cells[2].to_string();
            let allowed: Vec<String> = cells[6]
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s != "\u{2014}" && s != "—")
                .collect();
            if !dep.starts_with('#') && !dep.is_empty() {
                rows.push((dep, classification, allowed, in_build));
            }
        }
    }
    rows
}

/// True if `pos` (byte index) inside `line` is within a `"..."` string literal.
/// Guards encode forbidden paths as string literals (e.g. `"openraft::"`); those
/// must not count as entitlement.
fn inside_string_literal(line: &str, pos: usize) -> bool {
    let mut quotes = 0u32;
    let mut escaped = false;
    for b in line.as_bytes().iter().take(pos) {
        if escaped {
            escaped = false;
            continue;
        }
        if *b == b'\\' {
            escaped = true;
            continue;
        }
        if *b == b'"' {
            quotes += 1;
        }
    }
    quotes % 2 == 1
}

fn top_level_for(src_root: &std::path::Path, file: &std::path::Path) -> String {
    let rel = file.strip_prefix(src_root).unwrap_or(file);
    let mut parts = rel.components();
    let first = parts
        .next()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .unwrap_or_default();
    if first == "bin" {
        return "bin".to_string();
    }
    if first.ends_with(".rs") {
        return first.trim_end_matches(".rs").to_string();
    }
    first
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Code reference to `IDENT::` outside string literals and not as part of a
/// longer identifier (`http_body_util::` must not entitle `http_body`).
fn has_path_ref(scanned: &str, ident: &str) -> bool {
    let needle = format!("{ident}::");
    for (i, _) in scanned.match_indices(&needle) {
        if i > 0 && is_ident_byte(scanned.as_bytes()[i - 1]) {
            continue;
        }
        let line_start = scanned[..i].rfind('\n').map(|x| x + 1).unwrap_or(0);
        let line_end = scanned[i..]
            .find('\n')
            .map(|x| i + x)
            .unwrap_or(scanned.len());
        if !inside_string_literal(&scanned[line_start..line_end], i - line_start) {
            return true;
        }
    }
    false
}

/// `use IDENT...` import (covers `use IDENT::x`, `use IDENT as y`).
fn has_use_ref(scanned: &str, ident: &str) -> bool {
    for (i, _) in scanned.match_indices("use ") {
        if i > 0 && is_ident_byte(scanned.as_bytes()[i - 1]) {
            continue;
        }
        let rest = &scanned[i + 4..];
        if rest == ident
            || rest.starts_with(&format!("{ident}::"))
            || rest.starts_with(&format!("{ident} "))
            || rest.starts_with(&format!("{ident};"))
            || rest.starts_with(&format!("{ident}\n"))
        {
            return true;
        }
    }
    false
}

/// Serde helper attribute: `#[serde(with = "IDENT")]`.
fn has_with_attr(scanned: &str, ident: &str) -> bool {
    scanned.contains(&format!("with = \"{ident}\""))
}

fn has_code_ref(scanned: &str, ident: &str) -> bool {
    has_path_ref(scanned, ident) || has_use_ref(scanned, ident) || has_with_attr(scanned, ident)
}

fn collect_production_consumers(
    repo: &std::path::Path,
    idents: &[String],
) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let src_root = repo.join("src");
    let files = synvoid_repo_guards::collect_rs_files(&src_root);
    for file in &files {
        let content = std::fs::read_to_string(file).unwrap_or_default();
        let scanned = synvoid_repo_guards::prepare_for_scanning(&content);
        let top = top_level_for(&src_root, file);
        for ident in idents {
            if has_code_ref(&scanned, ident) {
                out.entry(ident.clone()).or_default().insert(top.clone());
            }
        }
    }
    out
}

fn collect_test_consumers(
    repo: &std::path::Path,
    idents: &[String],
) -> std::collections::BTreeSet<String> {
    use std::collections::BTreeSet;
    let mut out = BTreeSet::new();
    for dir in ["tests", "benches"] {
        for file in synvoid_repo_guards::collect_rs_files(&repo.join(dir)) {
            let content = std::fs::read_to_string(&file).unwrap_or_default();
            for ident in idents {
                if has_code_ref(&content, ident) {
                    out.insert(ident.clone());
                }
            }
        }
    }
    out
}

/// Unstripped src/ consumers (includes `#[cfg(test)]` unit-test modules).
/// Only used to credit test_or_tooling fixtures; production entitlement always
/// uses the stripped view.
fn collect_unstripped_src_consumers(
    repo: &std::path::Path,
    idents: &[String],
) -> std::collections::BTreeSet<String> {
    use std::collections::BTreeSet;
    let mut out = BTreeSet::new();
    for file in synvoid_repo_guards::collect_rs_files(&repo.join("src")) {
        let content = std::fs::read_to_string(&file).unwrap_or_default();
        for ident in idents {
            if has_code_ref(&content, ident) {
                out.insert(ident.clone());
            }
        }
    }
    out
}

#[test]
fn build_dependencies_are_used_by_build_script() {
    let repo = workspace_root();
    let manifest = fs::read_to_string(repo.join("Cargo.toml")).expect("read Cargo.toml");
    let build_rs = fs::read_to_string(repo.join("build.rs")).unwrap_or_default();
    let deps = root_build_dependencies(&manifest);
    let mut violations = Violations::new();
    for dep in &deps {
        let ident = dep.replace('-', "_");
        if !has_code_ref(&build_rs, &ident) {
            violations.push(format!(
                "{dep}: build-dependency with no reference in build.rs"
            ));
        }
    }
    violations.assert_ok("build_dependencies_are_used_by_build_script");
}

#[test]
fn root_dependencies_have_path_entitlement() {
    let repo = workspace_root();
    let manifest = fs::read_to_string(repo.join("Cargo.toml")).expect("read Cargo.toml");
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");

    let mut deps = root_manifest_dependencies(&manifest);
    // `syslog` is a remove_candidate row without a manifest entry; drop any
    // manifest dep that has no ledger row here — missing rows are already a
    // failure in root_dependencies_have_ownership_entries.
    let rows = parse_entitlement_rows(&ledger);
    // Main-table rows govern manifest [dependencies]; build-table rows govern
    // [build-dependencies] (e.g. chrono appears in both with different scopes).
    let by_dep: std::collections::BTreeMap<&str, (&str, &[String])> = rows
        .iter()
        .filter(|(_, _, _, is_build)| !is_build)
        .map(|(d, c, a, _)| (d.as_str(), (c.as_str(), a.as_slice())))
        .collect();

    // Exception names must reference real ledger rows.
    for (name, _reason) in ENTITLEMENT_EXCEPTIONS {
        assert!(
            by_dep.contains_key(name),
            "entitlement exception for unknown dependency: {name}"
        );
        deps.remove(&name.to_string());
    }

    let idents: Vec<String> = deps.iter().map(|d| d.replace('-', "_")).collect();
    let prod = collect_production_consumers(&repo, &idents);
    let test_only = collect_test_consumers(&repo, &idents);
    // test_or_tooling deps may live only in src/ unit tests, which
    // prepare_for_scanning strips. Scan unstripped src/ so unit-test fixtures
    // (e.g. flate2 in src/worker/mod.rs tests) count as tooling consumers.
    let unit_test = collect_unstripped_src_consumers(&repo, &idents);

    let mut violations = Violations::new();
    for dep in &deps {
        let ident = dep.replace('-', "_");
        let Some((classification, allowed)) = by_dep.get(dep.as_str()) else {
            continue; // missing ledger row: owned by root_dependencies_have_ownership_entries
        };
        let consumers = prod.get(&ident);
        let has_test = test_only.contains(&ident);
        match *classification {
            "composition_runtime" | "compat_facade" => {
                let Some(set) = consumers else {
                    violations.push(format!(
                        "{dep}: no production (src/) consumer but classified {classification} \
                         — move use to a crate, reclassify, or except with reason"
                    ));
                    continue;
                };
                for top in set {
                    if !allowed.iter().any(|a| a == top) {
                        violations.push(format!(
                            "{dep}: consumed from src/{top} outside ledger allowlist [{}]",
                            allowed.join(", ")
                        ));
                    }
                }
            }
            "migration_blocker" | "remove_candidate" => {
                if allowed.is_empty() {
                    if let Some(set) = consumers {
                        violations.push(format!(
                            "{dep}: fail-closed {classification} row gained production consumer(s) \
                             [{}] — reclassify with a reason first",
                            set.iter().cloned().collect::<Vec<_>>().join(", ")
                        ));
                    }
                } else if let Some(set) = consumers {
                    for top in set {
                        if !allowed.iter().any(|a| a == top) {
                            violations.push(format!(
                                "{dep}: consumed from src/{top} outside ledger allowlist [{}]",
                                allowed.join(", ")
                            ));
                        }
                    }
                }
            }
            "test_or_tooling" => {
                if !has_test && consumers.is_none() && !unit_test.contains(&ident) {
                    violations.push(format!(
                        "{dep}: test_or_tooling with no tests/benches or unit-test consumer"
                    ));
                }
                if let Some(set) = consumers {
                    // Visible production references (outside stripped unit tests)
                    // are not entitled for tooling-only dependencies.
                    violations.push(format!(
                        "{dep}: test_or_tooling consumed from production src/ paths [{}] \
                         — move to unit tests or reclassify",
                        set.iter().cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
            }
            _ => {}
        }
    }

    violations.assert_ok(
        "root_dependency_entitlement_guard: manifest dependencies must have ledger-entitled root consumers",
    );
}

#[test]
fn ledger_allowed_paths_are_wellformed() {
    let repo = workspace_root();
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");
    let rows = parse_entitlement_rows(&ledger);
    assert!(
        !rows.is_empty(),
        "entitlement ledger parse returned no rows — column layout changed?"
    );
    // Every composition_runtime / compat_facade row must entitle at least one path.
    let mut empty = Vec::new();
    for (dep, classification, allowed, _) in &rows {
        if (classification == "composition_runtime" || classification == "compat_facade")
            && allowed.is_empty()
        {
            empty.push(dep.clone());
        }
    }
    assert!(
        empty.is_empty(),
        "ledger rows entitled to no root path but classified as live:\n{}",
        empty.join("\n")
    );
}
