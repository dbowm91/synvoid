//! Root-test ownership: STATIC_POLICY
//! Rationale: validates Phase 41 fail-closed config capability preflight.
//!
//! Guard for `architecture/config_feature_contract.md`:
//! - every `#[cfg(feature = ...)]` config field in `synvoid-config` must be
//!   covered by the raw-TOML preflight + capability matrix;
//! - the preflight helper, capability struct, and matrix must stay in sync.
//!
//! Static, fast, no codegen.

use std::fs;

fn read_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Collect `#[cfg(feature = "...")]` field owners in synvoid-config/src.
/// Returns (file, feature, field-name) for struct fields directly under a
/// cfg attribute. Heuristic: a `#[cfg(feature = "...")]` line followed
/// within 3 lines by `pub <name>:`.
fn gated_fields() -> Vec<(String, String, String)> {
    let dir = "crates/synvoid-config/src";
    let mut out = Vec::new();
    let entries = fs::read_dir(dir).expect("synvoid-config/src must exist");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        // Recurse into dns/ subdir files as well.
        if path.is_dir() {
            continue;
        }
        let content = fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if t.starts_with("#[cfg(feature") && t.contains("feature") {
                let feature = t.split('"').nth(1).unwrap_or("unknown").to_string();
                for next in lines.iter().skip(i + 1).take(3) {
                    let nt = next.trim();
                    // Skip re-exports and functions: only struct fields (`pub
                    // <name>:` without `::`, `use`, or `fn`).
                    if nt.starts_with("pub fn")
                        || nt.starts_with("pub struct")
                        || nt.starts_with("pub use")
                    {
                        break;
                    }
                    if nt.starts_with("pub ") && nt.contains(':') {
                        let name = nt
                            .trim_start_matches("pub ")
                            .split([':', ' '])
                            .next()
                            .unwrap_or("?")
                            .to_string();
                        // Skip re-export remnants (`use` caught above);
                        // struct fields never equal `use`/`fn`.
                        if name == "use" || name == "fn" {
                            break;
                        }
                        out.push((
                            path.file_name().unwrap().to_str().unwrap().to_string(),
                            feature.clone(),
                            name,
                        ));
                        break;
                    }
                }
            }
        }
    }
    // Include dns/ subdir.
    if let Ok(entries) = fs::read_dir("crates/synvoid-config/src/dns") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let content = fs::read_to_string(&path).unwrap_or_default();
            let lines: Vec<&str> = content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim();
                if t.starts_with("#[cfg(feature") {
                    let feature = t.split('"').nth(1).unwrap_or("unknown").to_string();
                    for next in lines.iter().skip(i + 1).take(3) {
                        let nt = next.trim();
                        if nt.starts_with("pub fn")
                            || nt.starts_with("pub struct")
                            || nt.starts_with("pub use")
                        {
                            break;
                        }
                        if nt.starts_with("pub ") && nt.contains(':') {
                            let name = nt
                                .trim_start_matches("pub ")
                                .split([':', ' '])
                                .next()
                                .unwrap_or("?")
                                .to_string();
                            if name == "use" || name == "fn" {
                                break;
                            }
                            out.push((
                                format!("dns/{}", path.file_name().unwrap().to_str().unwrap()),
                                feature.clone(),
                                name,
                            ));
                            break;
                        }
                    }
                }
            }
        }
    }
    out
}

#[test]
fn capability_preflight_covers_gated_fields() {
    let main = read_file("crates/synvoid-config/src/main_config.rs");
    assert!(
        main.contains("fn validate_config_capability_presence"),
        "preflight helper must exist in main_config.rs"
    );
    assert!(
        main.contains("struct CompiledCapabilities"),
        "CompiledCapabilities must exist in main_config.rs"
    );
    assert!(
        main.contains("from_toml_str"),
        "from_toml_str seam must exist"
    );

    // Expected capability-bearing TOML paths (Phase 41 matrix).
    for key in ["\"dns\"", "\"mesh\"", "\"tunnel\"", "\"icmp_filter\""] {
        assert!(
            main.contains(key),
            "preflight must inspect capability key {key}"
        );
    }

    let fields = gated_fields();
    // Known capability-bearing (field, feature) pairs that must be covered.
    let expected = [
        ("main_config.rs", "dns", "dns"),
        ("main_config.rs", "mesh", "mesh"),
        ("tunnel.rs", "mesh", "mesh"),
        ("main_config.rs", "icmp-filter", "icmp_filter"),
    ];
    for (file, feature, field) in expected {
        assert!(
            fields
                .iter()
                .any(|(f, feat, name)| f == file && feat == feature && name == field),
            "expected gated field {field} (feature {feature}) in {file}; found: {fields:?}"
        );
    }

    // No new gated field may appear without updating the preflight + matrix.
    // Allowlist: capability fields above + known compile-only details.
    let allowlist = [
        ("main_config.rs", "dns", "dns"),
        ("main_config.rs", "mesh", "mesh"),
        ("tunnel.rs", "mesh", "mesh"),
        ("main_config.rs", "icmp-filter", "icmp_filter"),
        // Compile-only: methods/accessors, not TOML keys.
        ("mesh.rs", "mesh", "load_node_identity"),
        ("tunnel.rs", "mesh", "has_mesh"),
        ("tunnel.rs", "mesh", "is_global_node"),
    ];
    let mut uncovered = Vec::new();
    for (file, feat, name) in &fields {
        // Skip function-gated items (heuristic may catch `pub fn` if within
        // 3 lines; those are compile-only and allowed).
        if name == "fn" {
            continue;
        }
        if !allowlist
            .iter()
            .any(|(f, fe, n)| f == file && fe == feat && n == name)
        {
            uncovered.push(format!("{file}:{name} (feature {feat})"));
        }
    }
    assert!(
        uncovered.is_empty(),
        "New feature-gated config field(s) must be added to the capability matrix + preflight: {uncovered:?}. \
         See architecture/config_feature_contract.md."
    );
}

#[test]
fn capability_matrix_documents_preflight() {
    let matrix = read_file("architecture/config_feature_contract.md");
    for key in ["[dns]", "[mesh]", "[tunnel.mesh]", "[icmp_filter]"] {
        assert!(
            matrix.contains(key),
            "capability matrix must document TOML path {key}"
        );
    }
    for sym in [
        "validate_config_capability_presence",
        "CompiledCapabilities",
        "from_toml_str",
    ] {
        assert!(matrix.contains(sym), "capability matrix must mention {sym}");
    }
}

#[test]
fn checked_arithmetic_present_at_runtime_derivations() {
    // Config validation is the first barrier; runtime constructors must
    // still use checked arithmetic (Phase 41 Workstream D).
    let supervisor = read_file("src/supervisor/process.rs");
    assert!(
        supervisor.contains("checked_add"),
        "supervisor derived capacities must use checked_add"
    );
    let shared = read_file("crates/synvoid-upstream/src/shared_state.rs");
    assert!(
        shared.contains("checked_mul") && shared.contains("checked_add"),
        "shared-memory constructors must use checked arithmetic"
    );
    let ipc = read_file("crates/synvoid-ipc/src/manager.rs");
    assert!(
        ipc.contains("worker_port_for_id") && ipc.contains("checked_restart_backoff"),
        "IPC port/backoff derivations must use checked helpers"
    );
}

#[test]
fn mesh_restart_truthful_at_config_validation() {
    let mesh = read_file("crates/synvoid-config/src/mesh.rs");
    assert!(
        mesh.contains("fn validate(")
            && mesh.contains("restart_enabled")
            && mesh.contains("not supported"),
        "MeshSupervisionConfig::validate must reject restart_enabled"
    );
    let main = read_file("crates/synvoid-config/src/main_config.rs");
    assert!(
        main.contains("process_manager.validate()") || main.contains("process_manager.validate("),
        "MainConfig::validate must invoke process validation"
    );
    assert!(
        main.contains("supervisor.validate("),
        "MainConfig::validate must invoke supervisor validation"
    );
}
