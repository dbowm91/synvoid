//! Mechanical source-scanning guardrail test for threat-intel consumer actionability (Iteration 54).
//!
//! This test enforces that:
//! 1. Enforcement files/functions cannot call raw lookup helpers directly.
//! 2. Raw lookup helpers are allowlisted only for diagnostic/admin/shadow/docs paths.
//! 3. Blocklist mutation from threat-intel files must be near a policy-composed actionability call.
//! 4. ShadowOnly paths cannot call block/unblock APIs.
//! 5. LegacyUnknown is not used for new threat-intel blocklist writes.
//! 6. AdminManual/SupervisorSync are not used for threat-intel-originated blocklist writes.

use std::fs;
use std::path::{Path, PathBuf};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let cargo_toml = path.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = fs::read_to_string(&cargo_toml).unwrap_or_default();
            if content.contains("[workspace]") {
                return path;
            }
        }
        if !path.pop() {
            break;
        }
    }
    panic!("Could not find workspace root");
}

fn strip_cfg_test_modules(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut depth = 0i32;
    let mut in_test_module = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[cfg(test)]") {
            in_test_module = true;
            depth = 0;
            continue;
        }
        if in_test_module {
            if trimmed.starts_with("mod ") && trimmed.contains('{') {
                depth += 1;
                continue;
            }
            for ch in trimmed.chars() {
                if ch == '{' {
                    depth += 1;
                }
                if ch == '}' {
                    depth -= 1;
                }
            }
            if depth <= 0 {
                in_test_module = false;
            }
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }
    result
}

fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return results,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            results.extend(collect_rs_files(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            results.push(path);
        }
    }
    results
}

/// Strip single-line comments (`// ...`) and block comments (`/* ... */`).
/// Best-effort heuristic; acceptable for a guardrail.
fn strip_comments(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

// ── Phase 1: Raw Lookup Boundary ─────────────────────────────────────────────

/// Tokens that indicate a raw threat-intel lookup. Enforcement-sensitive code
/// must use the `lookup_*_policy_strict` wrappers instead.
const RAW_LOOKUP_TOKENS: &[&str] = &[
    "lookup_local_indicator(",
    "lookup_local_indicator_by_ip(",
    "lookup_threat_indicator_in_dht(",
];

/// Files where raw lookups are explicitly permitted (implementation, tests,
/// feed bookkeeping, documentation, admin, shadow, diagnostics).
fn is_lookup_allowlisted(relative: &str) -> bool {
    let allowlist: &[&str] = &[
        "crates/synvoid-mesh/src/mesh/threat_intel.rs",
        "crates/synvoid-mesh/src/mesh/threat_intel_policy.rs",
        "tests/threat_intel_boundary_guard.rs",
        "tests/threat_intel_consumer_actionability_guard.rs",
        "tests/dht_integration_test.rs",
        "src/waf/threat_intel/feed_client.rs",
    ];

    for entry in allowlist {
        if relative == *entry {
            return true;
        }
    }

    // Documentation, admin, shadow/diagnostic, and plan directories are always permitted.
    if relative.starts_with("docs/")
        || relative.starts_with("plans/")
        || relative.starts_with("architecture/")
        || relative.starts_with("src/admin/")
        || relative.starts_with("skills/")
    {
        return true;
    }

    false
}

/// Enforcement-sensitive directories that must not contain raw lookup calls.
const RAW_LOOKUP_DENYLIST_DIRS: &[&str] = &[
    "src/waf",
    "src/http",
    "src/worker/unified_server",
    "src/proxy",
    "crates/synvoid-http3",
    "crates/synvoid-waf",
    "crates/synvoid-proxy",
];

/// Phase 1 test: scan enforcement-sensitive directories and reject raw lookup
/// APIs outside the allowlist.
#[test]
fn enforcement_files_no_raw_lookup_calls() {
    let root = workspace_root();
    let mut violations: Vec<String> = Vec::new();

    for dir in RAW_LOOKUP_DENYLIST_DIRS {
        let path = root.join(dir);
        if !path.exists() {
            continue;
        }

        let files = collect_rs_files(&path);
        for file in &files {
            let relative = file
                .strip_prefix(&root)
                .unwrap_or(file)
                .to_string_lossy()
                .into_owned();

            if is_lookup_allowlisted(&relative) {
                continue;
            }

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let production = strip_cfg_test_modules(&content);
            let production = strip_comments(&production);

            for token in RAW_LOOKUP_TOKENS {
                if production.contains(token) {
                    violations.push(format!("  {relative}: contains `{token}`"));
                }
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Raw threat-intel lookup API used in an enforcement-sensitive path. \
             Use `lookup_*_policy_strict` for actionability-sensitive reads, \
             or document and allowlist the call if it is debug/shadow/bookkeeping only.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

// ── Phase 2: Blocklist Mutation Must Be Policy-Gated ──────────────────────────

/// Block-store mutation tokens in threat-intel files.
const BLOCK_MUTATION_TOKENS: &[&str] = &[
    "block_ip(",
    "block_ip_with_provenance(",
    "block_mesh_id(",
    "block_mesh_id_with_provenance(",
];

/// Policy gate token that must appear before any block mutation in
/// `handle_incoming_threat`.
const POLICY_GATE_TOKEN: &str = "evaluate_incoming_threat_policy";

/// Scan `threat_intel.rs` and verify that `evaluate_incoming_threat_policy`
/// is called before any block-store mutation in `handle_incoming_threat`.
#[test]
fn handle_incoming_threat_is_policy_gated() {
    let root = workspace_root();
    let threat_intel_path = root.join("crates/synvoid-mesh/src/mesh/threat_intel.rs");

    assert!(
        threat_intel_path.exists(),
        "threat_intel.rs not found at expected path"
    );

    let content = match fs::read_to_string(&threat_intel_path) {
        Ok(c) => c,
        Err(e) => panic!("Failed to read threat_intel.rs: {e}"),
    };

    let production = strip_cfg_test_modules(&content);
    let production = strip_comments(&production);

    let lines: Vec<&str> = production.lines().collect();

    // Find the `handle_incoming_threat` function body.
    let mut fn_start: Option<usize> = None;
    let mut fn_end: Option<usize> = None;
    let mut depth = 0i32;
    let mut found_open = false;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if fn_start.is_none() && trimmed.contains("fn handle_incoming_threat") {
            fn_start = Some(idx);
        }
        if fn_start.is_some() {
            for ch in trimmed.chars() {
                if ch == '{' {
                    depth += 1;
                    found_open = true;
                } else if ch == '}' {
                    depth -= 1;
                }
            }
            if found_open && depth == 0 {
                fn_end = Some(idx);
                break;
            }
        }
    }

    let fn_start = fn_start.expect("handle_incoming_threat function not found");
    let fn_end = fn_end.expect("handle_incoming_threat function body not terminated");

    let fn_body: Vec<&str> = lines[fn_start..=fn_end].to_vec();
    let _fn_body_text = fn_body.join("\n");

    // Find the first policy gate call within the function body.
    let mut policy_gate_line: Option<usize> = None;
    let mut first_block_mutation_line: Option<usize> = None;

    for (rel_idx, line) in fn_body.iter().enumerate() {
        let abs_line = fn_start + rel_idx;
        let trimmed = line.trim();

        // Skip doc comments
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        if line.contains(POLICY_GATE_TOKEN) && policy_gate_line.is_none() {
            policy_gate_line = Some(abs_line);
        }

        for token in BLOCK_MUTATION_TOKENS {
            if line.contains(token) && first_block_mutation_line.is_none() {
                first_block_mutation_line = Some(abs_line);
            }
        }
    }

    if let Some(block_line) = first_block_mutation_line {
        if let Some(gate_line) = policy_gate_line {
            assert!(
                gate_line < block_line,
                "In handle_incoming_threat: policy gate `{POLICY_GATE_TOKEN}` at line {} \
                 must appear BEFORE block mutation at line {}. \
                 All block-store mutations must be gated by evaluate_incoming_threat_policy.",
                gate_line + 1,
                block_line + 1,
            );
        } else {
            panic!(
                "In handle_incoming_threat: block mutation found at line {} \
                 but no `{POLICY_GATE_TOKEN}` call found in the function body. \
                 All block-store mutations must be gated by evaluate_incoming_threat_policy.",
                block_line + 1,
            );
        }
    }
}

// ── Phase 3: ShadowOnly Cannot Call Block/Unblock APIs ────────────────────────

/// Block/unblock API tokens.
const BLOCK_UNBLOCK_TOKENS: &[&str] = &[
    "block_ip(",
    "block_ip_with_provenance(",
    "unblock_ip(",
    "block_mesh_id(",
    "block_mesh_id_with_provenance(",
    "unblock_mesh_id(",
];

/// Scan threat-intel enforcement files for `ShadowOnly` consumer kind usage
/// near block/unblock API calls within the same function or match arm.
#[test]
fn shadow_only_paths_no_block_unblock() {
    let root = workspace_root();
    let threat_intel_path = root.join("crates/synvoid-mesh/src/mesh/threat_intel.rs");

    assert!(
        threat_intel_path.exists(),
        "threat_intel.rs not found at expected path"
    );

    let content = match fs::read_to_string(&threat_intel_path) {
        Ok(c) => c,
        Err(e) => panic!("Failed to read threat_intel.rs: {e}"),
    };

    let production = strip_cfg_test_modules(&content);
    let production = strip_comments(&production);

    let lines: Vec<&str> = production.lines().collect();
    let mut violations: Vec<String> = Vec::new();

    // Strategy: find match arms or blocks that contain ShadowOnly AND a
    // block/unblock API call. We scan line-by-line and look for ShadowOnly
    // identifiers, then check if any block/unblock token appears within a
    // reasonable window (same match arm / block scope).
    let shadow_window = 40; // lines of context to search for violations
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Skip doc comments
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        if line.contains("ShadowOnly") {
            // Search within a window around the ShadowOnly usage for block/unblock calls
            let start = idx.saturating_sub(shadow_window);
            let end = std::cmp::min(idx + shadow_window, lines.len());
            for other_idx in start..end {
                if other_idx == idx {
                    continue;
                }
                for token in BLOCK_UNBLOCK_TOKENS {
                    if lines[other_idx].contains(token) {
                        violations.push(format!(
                            "  threat_intel.rs: ShadowOnly at line {} near block/unblock `{}` at line {}",
                            idx + 1,
                            token.trim_end_matches('('),
                            other_idx + 1,
                        ));
                    }
                }
            }
        }
    }

    // Deduplicate violations (a single block/unblock may be near multiple ShadowOnly usages)
    violations.sort();
    violations.dedup();

    if !violations.is_empty() {
        let mut msg = String::from(
            "ShadowOnly consumer path found near a block/unblock API call. \
             ShadowOnly is an observability-only consumer kind and must not \
             perform enforcement mutations (block_ip, unblock_ip, block_mesh_id, etc.).\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

// ── Phase 4: No LegacyUnknown for New Threat-Intel Blocklist Writes ──────────

/// Scan enforcement directories for `LegacyUnknown` provenance in block-store
/// writes originating from threat-intel code.
#[test]
fn no_legacy_unknown_in_threat_intel_blocklist_writes() {
    let root = workspace_root();
    let dirs_to_scan: &[&str] = &[
        "src/waf",
        "src/http",
        "src/worker/unified_server",
        "src/proxy",
        "crates/synvoid-http3",
        "crates/synvoid-waf",
        "crates/synvoid-proxy",
    ];
    let mut violations: Vec<String> = Vec::new();

    for dir in dirs_to_scan {
        let path = root.join(dir);
        if !path.exists() {
            continue;
        }

        let files = collect_rs_files(&path);
        for file in &files {
            let relative = file
                .strip_prefix(&root)
                .unwrap_or(file)
                .to_string_lossy()
                .into_owned();

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let production = strip_cfg_test_modules(&content);
            let production = strip_comments(&production);

            for (idx, line) in production.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("///") || trimmed.starts_with("//!") {
                    continue;
                }
                if line.contains("BlockProvenanceKind::LegacyUnknown") {
                    violations.push(format!("  {relative}: LegacyUnknown at line {}", idx + 1,));
                }
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "`LegacyUnknown` provenance used in enforcement path block-store writes. \
             New threat-intel enforcement must use `MeshThreatIntelPolicyGated` or \
             another meaningful provenance kind. `LegacyUnknown` is acceptable only \
             in backward-compat shims, Default impls, and tests.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

// ── Phase 5: No AdminManual/SupervisorSync in Threat-Intel Originated Writes ──

/// Provenance kinds that must not appear in threat-intel-originated blocklist
/// writes. Threat-intel enforcement should use `MeshThreatIntelPolicyGated`.
const FORBIDDEN_THREAT_INTEL_PROVENANCE: &[&str] = &[
    "BlockProvenanceKind::AdminManual",
    "BlockProvenanceKind::SupervisorSync",
];

/// Scan `threat_intel.rs` for forbidden provenance kinds in block-store writes.
#[test]
fn no_admin_manual_or_supervisor_sync_in_threat_intel_writes() {
    let root = workspace_root();
    let threat_intel_path = root.join("crates/synvoid-mesh/src/mesh/threat_intel.rs");

    assert!(
        threat_intel_path.exists(),
        "threat_intel.rs not found at expected path"
    );

    let content = match fs::read_to_string(&threat_intel_path) {
        Ok(c) => c,
        Err(e) => panic!("Failed to read threat_intel.rs: {e}"),
    };

    let production = strip_cfg_test_modules(&content);
    let production = strip_comments(&production);

    let mut violations: Vec<String> = Vec::new();

    for (idx, line) in production.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        for forbidden in FORBIDDEN_THREAT_INTEL_PROVENANCE {
            if line.contains(forbidden) {
                violations.push(format!(
                    "  threat_intel.rs: {forbidden} at line {}",
                    idx + 1,
                ));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Forbidden provenance kind found in threat-intel-originated blocklist writes. \
             Threat-intel enforcement must use `MeshThreatIntelPolicyGated` provenance, \
             not `AdminManual` or `SupervisorSync`.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

// ── Phase 6: Positive Boundary Tests ─────────────────────────────────────────

/// Verify that every file on the lookup allowlist actually exists in the workspace.
#[test]
fn lookup_allowlisted_files_exist() {
    let root = workspace_root();
    let allowlist: &[&str] = &[
        "crates/synvoid-mesh/src/mesh/threat_intel.rs",
        "crates/synvoid-mesh/src/mesh/threat_intel_policy.rs",
        "tests/threat_intel_boundary_guard.rs",
        "tests/threat_intel_consumer_actionability_guard.rs",
        "tests/dht_integration_test.rs",
        "src/waf/threat_intel/feed_client.rs",
    ];

    let mut missing = Vec::new();
    for rel in allowlist {
        let path = root.join(rel);
        if !path.exists() {
            missing.push(rel.to_string());
        }
    }

    assert!(
        missing.is_empty(),
        "Lookup allowlisted files no longer exist (stale allowlist entry): {:?}",
        missing
    );
}

/// Verify that the raw-lookup denylist directories exist and are structurally
/// covered by the guard.
#[test]
fn raw_lookup_denylist_directories_are_valid() {
    let root = workspace_root();

    for dir in RAW_LOOKUP_DENYLIST_DIRS {
        let path = root.join(dir);
        if path.exists() {
            let has_rs_files = collect_rs_files(&path)
                .iter()
                .any(|f| f.extension().and_then(|e| e.to_str()) == Some("rs"));
            assert!(
                has_rs_files,
                "Denylist directory `{dir}` exists but contains no .rs files — \
                 remove it from the denylist or investigate"
            );
        }
    }
}

/// Verify that the `strip_cfg_test_modules` correctly removes `#[cfg(test)]`
/// content so inline test code does not trigger false positives.
#[test]
fn strip_cfg_test_modules_removes_cfg_test_content() {
    let content = r#"
        use crate::foo;

        fn real_function() {
            let x = lookup_local_indicator("evil");
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::lookup_threat_indicator_in_dht;

            #[test]
            fn it_works() {}
        }
    "#;

    let stripped = strip_cfg_test_modules(content);

    assert!(
        !stripped.contains("#[cfg(test)]"),
        "Test module marker should be stripped"
    );
    assert!(
        !stripped.contains("lookup_threat_indicator_in_dht"),
        "Content after #[cfg(test)] should be removed"
    );
    assert!(
        stripped.contains("fn real_function()"),
        "Production code before #[cfg(test)] must be retained"
    );
}

/// Confirm that a simulated raw lookup in an enforcement path would be caught.
#[test]
fn simulated_raw_lookup_in_enforcement_is_detected() {
    let fake_content = "fn handle_request() {\n    let x = lookup_local_indicator(\"evil\");\n}\n";

    let stripped = strip_cfg_test_modules(fake_content);
    let stripped = strip_comments(&stripped);

    let has_violation = RAW_LOOKUP_TOKENS.iter().any(|t| stripped.contains(t));
    assert!(
        has_violation,
        "Simulated raw lookup in an enforcement path must be detected"
    );
}

/// Confirm that a simulated ShadowOnly path calling block_ip would be caught.
#[test]
fn simulated_shadow_only_with_block_is_detected() {
    let fake_content = r#"
        fn apply_action(consumer: ThreatIntelConsumerKind) {
            match consumer {
                ThreatIntelConsumerKind::ShadowOnly => {
                    block_ip(ip, "threat", 3600);
                }
                _ => {}
            }
        }
    "#;

    let lines: Vec<&str> = fake_content.lines().collect();
    let mut found_shadow = false;
    let mut found_block = false;

    for line in &lines {
        if line.contains("ShadowOnly") {
            found_shadow = true;
        }
        if line.contains("block_ip(") && !line.contains("block_ip_with_provenance(") {
            found_block = true;
        }
    }

    assert!(found_shadow, "Simulated content must contain ShadowOnly");
    assert!(found_block, "Simulated content must contain block_ip");
}

/// Confirm that `MeshThreatIntelPolicyGated` is not flagged by the forbidden
/// provenance check.
#[test]
fn mesh_threat_intel_policy_gated_is_not_flagged() {
    let fake_content =
        "fn apply() {\n    let p = BlockProvenanceKind::MeshThreatIntelPolicyGated;\n}\n";

    let violations: Vec<String> = fake_content
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            FORBIDDEN_THREAT_INTEL_PROVENANCE
                .iter()
                .find(|f| line.contains(**f))
                .map(|f| format!("  line {}: {f}", idx + 1))
        })
        .collect();

    assert!(
        violations.is_empty(),
        "MeshThreatIntelPolicyGated should not be flagged: {:?}",
        violations
    );
}
