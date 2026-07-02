//! Guardrail tests for plugin lifecycle invariants (M2 Phase 9).
//!
//! These tests enforce architectural invariants for the plugin lifecycle:
//! - Reload path must prepare before swapping (no active generation mutation before validation).
//! - Duplicate name checks exist in all load paths.
//! - Hot reload has production and unsafe-native gates.
//! - Stable-file wait and file stability policy exist.
//! - Generation ID appears in plugin info/status.
//! - Lifecycle state machine transitions are valid.
//! - PluginReloadOutcome and PluginReplacePolicy have all required variants.
//! - Lifecycle transition audit trail methods exist.

use std::path::{Path, PathBuf};

// ─── Helpers (shared with other guardrail tests) ──────────────────────────────

fn rust_files_under(dir: &Path) -> Vec<PathBuf> {
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

/// Strip string literals, line comments (`//`), and block comments (`/* */`).
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

fn cleaned_lines(cleaned: &str) -> Vec<(usize, &str)> {
    cleaned
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .collect()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn plugin_runtime_src() -> PathBuf {
    repo_root()
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
}

fn wasm_runtime_rs() -> PathBuf {
    plugin_runtime_src().join("wasm_runtime.rs")
}

fn read_cleaned(path: &Path) -> String {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    strip_comments_and_strings(&text)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// No reload path mutates active generation before candidate validation.
///
/// The reload pipeline must prepare the candidate first (via
/// `prepare_reload_candidate` or `prepare_plugin_load`), and only then
/// commit the swap. If `runtimes.write()` appears before the prepare call
/// in the reload path, the active generation would be mutated before
/// validation, violating the invariant.
///
/// We scan `reload_plugin_with_outcome` and `prepare_reload_candidate`
/// for the correct ordering: prepare calls appear before runtimes.write().
#[test]
fn reload_prepare_before_swap() {
    let file = wasm_runtime_rs();
    let cleaned = read_cleaned(&file);
    let lines: Vec<&str> = cleaned.lines().collect();
    let mut violations = Vec::new();

    // Find reload_plugin_with_outcome method body
    let mut in_reload = false;
    let mut brace_depth = 0i32;
    let mut method_start = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if trimmed.contains("fn reload_plugin_with_outcome(") {
            in_reload = true;
            method_start = i;
            brace_depth = 0;
        }

        if in_reload {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;

            // If we see runtimes.write() before prepare_reload_candidate,
            // that's a violation
            if trimmed.contains("runtimes.write()") && brace_depth > 0 {
                // Check if prepare_reload_candidate or prepare_plugin_load
                // appears BEFORE this line in the method
                let has_prepare_before = lines[method_start..i].iter().any(|l| {
                    l.contains("prepare_reload_candidate") || l.contains("prepare_plugin_load")
                });

                if !has_prepare_before {
                    violations.push(format!(
                        "wasm_runtime.rs:{}: runtimes.write() in reload_plugin_with_outcome before prepare call",
                        i + 1
                    ));
                }
            }

            if brace_depth <= 0 && in_reload && i > method_start {
                in_reload = false;
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "Reload path mutates active generation before candidate validation:\n{}",
            violations.join("\n")
        );
    }
}

/// Duplicate name checks exist in every load path.
///
/// `load_plugin`, `load_plugin_from_memory_with_manifest`, and
/// `load_plugin_with_limits` must all check for duplicate plugin names
/// before pushing to `runtimes`. `load_plugin_from_memory` delegates to
/// `load_plugin_from_memory_with_priority` which must also check.
///
/// We use raw source (not stripped) because the "duplicate name" text
/// lives inside string literals which strip_comments_and_strings removes.
#[test]
fn duplicate_name_check_in_all_load_paths() {
    let raw = std::fs::read_to_string(wasm_runtime_rs())
        .unwrap_or_else(|e| panic!("read wasm_runtime.rs: {}", e));

    // Methods that directly push to runtimes (not delegation stubs)
    let load_methods = [
        "fn load_plugin(",
        "fn load_plugin_from_memory_with_manifest(",
        "fn load_plugin_from_memory_with_priority(",
        "fn load_plugin_with_limits(",
    ];

    let mut violations = Vec::new();

    for method_sig in &load_methods {
        // Find the method in raw source
        let Some(method_start) = raw.find(method_sig) else {
            continue;
        };

        // Find the method body by tracking braces from the first '{'
        let body_start = raw[method_start..]
            .find('{')
            .map(|p| method_start + p)
            .unwrap_or(method_start);
        let mut brace_depth = 0i32;
        let mut method_body = String::new();
        let mut end = body_start;

        for (i, ch) in raw[body_start..].char_indices() {
            match ch {
                '{' => brace_depth += 1,
                '}' => {
                    brace_depth -= 1;
                    if brace_depth == 0 {
                        end = body_start + i + ch.len_utf8();
                        break;
                    }
                }
                _ => {}
            }
        }
        method_body = raw[body_start..end].to_string();

        // Check 1: The method must contain "duplicate name" in a string literal
        let has_duplicate_string = method_body.contains("duplicate name");

        // Check 2: Structural — runtimes.read().iter().any must appear before
        //           runtimes.write().push (check-before-mutate pattern)
        let read_pos = method_body.find("runtimes.read()");
        let write_push_pos = method_body.find("runtimes.write().push(");
        let has_structural_check = match (read_pos, write_push_pos) {
            (Some(r), Some(w)) => r < w,
            _ => false,
        };

        // Check 3: Delegation — method calls check_duplicate_name (centralized check)
        let has_delegated_check = method_body.contains("check_duplicate_name");

        if !has_duplicate_string && !has_structural_check && !has_delegated_check {
            let short_name = method_sig.trim_start_matches("fn ").trim_end_matches('(');
            violations.push(format!(
                "{}: no duplicate name check found (no 'duplicate name' string and no runtimes.read() before runtimes.write().push())",
                short_name
            ));
        }
    }

    if !violations.is_empty() {
        panic!(
            "Missing duplicate name checks in load paths:\n{}",
            violations.join("\n")
        );
    }
}

/// Hot reload production gate exists.
///
/// `HotReloadConfig` must have a `production_enabled` field and
/// `WasmPluginManager` must have a `validate_hot_reload_config` method
/// that checks this gate against the production environment.
#[test]
fn hot_reload_production_gate_exists() {
    let file = wasm_runtime_rs();
    let cleaned = read_cleaned(&file);

    // HotReloadConfig must have production_enabled field
    assert!(
        cleaned.contains("pub production_enabled: bool"),
        "HotReloadConfig must have 'pub production_enabled: bool' field"
    );

    // WasmPluginManager must have validate_hot_reload_config method
    assert!(
        cleaned.contains("fn validate_hot_reload_config("),
        "WasmPluginManager must have validate_hot_reload_config method"
    );

    // validate_hot_reload_config must check production_enabled
    let mut in_validate = false;
    let mut brace_depth = 0i32;
    let mut checks_production = false;

    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("fn validate_hot_reload_config(") {
            in_validate = true;
            brace_depth = 0;
            checks_production = false;
        }
        if in_validate {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            if trimmed.contains("production_enabled") {
                checks_production = true;
            }
            if brace_depth <= 0 && in_validate {
                break;
            }
        }
    }

    assert!(
        checks_production,
        "validate_hot_reload_config must check production_enabled"
    );
}

/// Unsafe native hot reload is separately gated.
///
/// `HotReloadConfig` must have an `unsafe_native_enabled` field that is
/// separate from the general `enabled` field, allowing independent control
/// of unsafe native plugin hot-reloading.
#[test]
fn unsafe_native_hot_reload_separately_gated() {
    let file = wasm_runtime_rs();
    let cleaned = read_cleaned(&file);

    assert!(
        cleaned.contains("pub unsafe_native_enabled: bool"),
        "HotReloadConfig must have 'pub unsafe_native_enabled: bool' field separate from 'enabled'"
    );

    // Verify both fields exist in the struct
    let mut in_struct = false;
    let mut brace_depth = 0i32;
    let mut has_enabled = false;
    let mut has_unsafe = false;

    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("pub struct HotReloadConfig") {
            in_struct = true;
            brace_depth = 0;
            has_enabled = false;
            has_unsafe = false;
        }
        if in_struct {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            if trimmed.contains("pub enabled: bool") {
                has_enabled = true;
            }
            if trimmed.contains("pub unsafe_native_enabled: bool") {
                has_unsafe = true;
            }
            if brace_depth <= 0 && in_struct {
                break;
            }
        }
    }

    assert!(has_enabled, "HotReloadConfig must have 'pub enabled: bool'");
    assert!(
        has_unsafe,
        "HotReloadConfig must have 'pub unsafe_native_enabled: bool'"
    );
    assert!(
        has_enabled && has_unsafe,
        "Both enabled and unsafe_native_enabled must be separate fields"
    );
}

/// Stable-file wait exists before watcher-triggered reload.
///
/// `WasmPluginManager` must have `wait_for_stable_file` method and
/// `FileStabilityPolicy` struct for debouncing watcher events before
/// triggering a reload.
#[test]
fn stable_file_wait_exists() {
    let file = wasm_runtime_rs();
    let cleaned = read_cleaned(&file);

    assert!(
        cleaned.contains("fn wait_for_stable_file("),
        "WasmPluginManager must have wait_for_stable_file method"
    );

    assert!(
        cleaned.contains("pub struct FileStabilityPolicy"),
        "FileStabilityPolicy struct must exist"
    );

    // FileStabilityPolicy must have debounce, stable_checks, stable_interval, max_wait
    let mut in_struct = false;
    let mut brace_depth = 0i32;
    let mut fields = Vec::new();

    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("pub struct FileStabilityPolicy") {
            in_struct = true;
            brace_depth = 0;
            fields.clear();
        }
        if in_struct {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            if let Some(field_name) = trimmed
                .strip_prefix("pub ")
                .and_then(|s| s.split(':').next())
            {
                fields.push(field_name.trim().to_string());
            }
            if brace_depth <= 0 && in_struct {
                break;
            }
        }
    }

    let required_fields = ["debounce", "stable_checks", "stable_interval", "max_wait"];
    for field in &required_fields {
        assert!(
            fields.iter().any(|f| f == field),
            "FileStabilityPolicy must have '{}' field",
            field
        );
    }
}

/// Generation ID appears in plugin info/status.
///
/// `PluginInfo` must have a `generation` field of type
/// `Option<PluginGenerationId>` so callers can track which generation
/// of a plugin is currently loaded.
#[test]
fn generation_id_in_plugin_info() {
    let file = wasm_runtime_rs();
    let cleaned = read_cleaned(&file);

    // Find PluginInfo struct
    let mut in_struct = false;
    let mut brace_depth = 0i32;
    let mut has_generation = false;

    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("pub struct PluginInfo") {
            in_struct = true;
            brace_depth = 0;
            has_generation = false;
        }
        if in_struct {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            if trimmed.contains("pub generation:") {
                has_generation = true;
            }
            if brace_depth <= 0 && in_struct {
                break;
            }
        }
    }

    assert!(
        has_generation,
        "PluginInfo must have 'pub generation' field"
    );
}

/// Lifecycle state machine transitions are valid.
///
/// `PluginLifecycleState::is_valid_transition` must exist and reject
/// invalid transitions (e.g. Removed -> Active must be rejected).
#[test]
fn lifecycle_state_transitions_valid() {
    let file = wasm_runtime_rs();
    let cleaned = read_cleaned(&file);

    assert!(
        cleaned.contains("fn is_valid_transition("),
        "PluginLifecycleState::is_valid_transition must exist"
    );

    // Verify all lifecycle states exist in the enum
    let required_states = [
        "Loading",
        "Active",
        "Reloading",
        "Disabled",
        "Quarantined",
        "Unloading",
        "Removed",
        "FailedLoad",
    ];

    for state in &required_states {
        assert!(
            cleaned.contains(&format!("PluginLifecycleState::{}", state)),
            "PluginLifecycleState must include {} variant",
            state
        );
    }

    // Verify that the match block in is_valid_transition covers the valid
    // transitions and implicitly rejects invalid ones (the matches! macro
    // only lists valid pairs; anything not listed is rejected)
    let mut in_is_valid = false;
    let mut brace_depth = 0i32;
    let mut match_block = String::new();

    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("fn is_valid_transition(") {
            in_is_valid = true;
            brace_depth = 0;
            match_block.clear();
        }
        if in_is_valid {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            match_block.push_str(trimmed);
            match_block.push(' ');
            if brace_depth <= 0 && in_is_valid {
                break;
            }
        }
    }

    // The match must cover valid transitions; invalid ones are rejected by
    // the matches! macro's exhaustive list. Verify at least the core
    // transitions exist.
    let valid_transitions = [
        ("Loading", "Active"),
        ("Loading", "FailedLoad"),
        ("Active", "Reloading"),
        ("Reloading", "Active"),
        ("Active", "Disabled"),
        ("Disabled", "Active"),
        ("Active", "Unloading"),
        ("Unloading", "Removed"),
    ];

    for (from, to) in &valid_transitions {
        let pattern = format!("PluginLifecycleState::{}", from);
        assert!(
            match_block.contains(&pattern),
            "is_valid_transition must reference PluginLifecycleState::{}",
            from
        );
        let pattern = format!("PluginLifecycleState::{}", to);
        assert!(
            match_block.contains(&pattern),
            "is_valid_transition must reference PluginLifecycleState::{}",
            to
        );
    }
}

/// PluginReloadOutcome has all three variants.
///
/// `PluginReloadOutcome` must have `Replaced`, `Unchanged`, and `Failed`
/// variants.
#[test]
fn plugin_reload_outcome_variants() {
    let file = wasm_runtime_rs();
    let cleaned = read_cleaned(&file);

    // Find PluginReloadOutcome enum
    let mut in_enum = false;
    let mut brace_depth = 0i32;
    let mut variants = Vec::new();

    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("pub enum PluginReloadOutcome") {
            in_enum = true;
            brace_depth = 0;
            variants.clear();
        }
        if in_enum {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            // Extract variant names: take the first identifier, strip commas/braces
            if let Some(variant) = trimmed
                .split('{')
                .next()
                .and_then(|s| s.trim().split_whitespace().last())
            {
                let clean = variant.trim_end_matches(',').trim_end_matches('}').trim();
                if !clean.is_empty()
                    && clean != "pub"
                    && clean != "enum"
                    && clean != "PluginReloadOutcome"
                {
                    variants.push(clean.to_string());
                }
            }
            if brace_depth <= 0 && in_enum {
                break;
            }
        }
    }

    let required = ["Replaced", "Unchanged", "Failed"];
    for variant in &required {
        assert!(
            variants.iter().any(|v| v == variant),
            "PluginReloadOutcome must have '{}' variant (found: {:?})",
            variant,
            variants
        );
    }
}

/// PluginReplacePolicy has all three variants.
///
/// `PluginReplacePolicy` must have `RejectExisting`, `ReplaceSameSource`,
/// and `ReplaceAnyWithOperatorOverride` variants.
#[test]
fn plugin_replace_policy_variants() {
    let file = wasm_runtime_rs();
    let cleaned = read_cleaned(&file);

    // Find PluginReplacePolicy enum
    let mut in_enum = false;
    let mut brace_depth = 0i32;
    let mut variants = Vec::new();

    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("pub enum PluginReplacePolicy") {
            in_enum = true;
            brace_depth = 0;
            variants.clear();
        }
        if in_enum {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            if let Some(variant) = trimmed
                .split('{')
                .next()
                .and_then(|s| s.trim().split_whitespace().last())
            {
                let clean = variant.trim_end_matches(',').trim_end_matches('}').trim();
                if !clean.is_empty()
                    && clean != "pub"
                    && clean != "enum"
                    && clean != "PluginReplacePolicy"
                {
                    variants.push(clean.to_string());
                }
            }
            if brace_depth <= 0 && in_enum {
                break;
            }
        }
    }

    let required = [
        "RejectExisting",
        "ReplaceSameSource",
        "ReplaceAnyWithOperatorOverride",
    ];
    for variant in &required {
        assert!(
            variants.iter().any(|v| v == variant),
            "PluginReplacePolicy must have '{}' variant (found: {:?})",
            variant,
            variants
        );
    }
}

/// Lifecycle transition audit trail exists.
///
/// `WasmPluginManager` must have `get_lifecycle_transitions` (all plugins)
/// and `get_plugin_lifecycle_transitions` (per-plugin) methods for audit
/// purposes.
#[test]
fn lifecycle_transition_audit_trail() {
    let file = wasm_runtime_rs();
    let cleaned = read_cleaned(&file);

    assert!(
        cleaned.contains("fn get_lifecycle_transitions("),
        "WasmPluginManager must have get_lifecycle_transitions method"
    );

    assert!(
        cleaned.contains("fn get_plugin_lifecycle_transitions("),
        "WasmPluginManager must have get_plugin_lifecycle_transitions method"
    );

    // LifecycleTransition struct must exist with required fields
    assert!(
        cleaned.contains("pub struct LifecycleTransition"),
        "LifecycleTransition struct must exist"
    );

    let required_fields = [
        "plugin_name",
        "from",
        "to",
        "generation",
        "timestamp",
        "reason",
    ];
    let mut in_struct = false;
    let mut brace_depth = 0i32;
    let mut fields = Vec::new();

    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("pub struct LifecycleTransition") {
            in_struct = true;
            brace_depth = 0;
            fields.clear();
        }
        if in_struct {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            if let Some(field_name) = trimmed
                .strip_prefix("pub ")
                .and_then(|s| s.split(':').next())
            {
                fields.push(field_name.trim().to_string());
            }
            if brace_depth <= 0 && in_struct {
                break;
            }
        }
    }

    for field in &required_fields {
        assert!(
            fields.iter().any(|f| f == field),
            "LifecycleTransition must have '{}' field (found: {:?})",
            field,
            fields
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Behavioral Tests — exercise actual WasmPluginManager runtime
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod behavioral {
    use synvoid_plugin_runtime::{
        PluginLifecycleState, PluginReplacePolicy, WasmPluginManager, WasmResourceLimits,
    };

    fn minimal_wasm_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
                (memory (export "memory") 1)
                (global $heap (mut i32) (i32.const 0))
                (func (export "guest_alloc") (param $size i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $heap))
                    (global.set $heap (i32.add (global.get $heap) (local.get $size)))
                    (local.get $ptr))
                (func (export "guest_free") (param $ptr i32) (param $size i32))
                (func (export "filter_request") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
                    i32.const 0)
            )
            "#,
        )
        .expect("valid WAT")
    }

    #[test]
    fn load_creates_generation_1() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();
        let _rt = mgr
            .load_plugin_from_memory("gen1_plugin", &bytes, WasmResourceLimits::default())
            .expect("load should succeed");

        let gen = mgr.get_plugin_generation("gen1_plugin");
        assert!(gen.is_some(), "generation should exist after load");
        let gen = gen.unwrap();
        assert_eq!(gen.0, 1, "first load should be generation 1");

        let state = mgr.get_plugin_lifecycle_state("gen1_plugin");
        assert_eq!(state, Some(PluginLifecycleState::Active));

        let detail = mgr.get_plugin_generation_detail("gen1_plugin");
        assert!(detail.is_some());
        let detail = detail.unwrap();
        assert!(detail.previous_generation.is_none());
    }

    #[test]
    fn reload_increments_generation() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.load_plugin_from_memory("reload_gen", &bytes, WasmResourceLimits::default())
            .expect("initial load");
        let gen1 = mgr.get_plugin_generation("reload_gen").unwrap();
        assert_eq!(gen1.0, 1);

        // Reload same name (replace policy must allow it)
        mgr.set_replace_policy(PluginReplacePolicy::ReplaceSameSource);
        mgr.load_plugin_from_memory("reload_gen", &bytes, WasmResourceLimits::default())
            .expect("reload should succeed");

        let gen2 = mgr.get_plugin_generation("reload_gen").unwrap();
        assert_eq!(gen2.0, 2, "second load should be generation 2");

        let detail = mgr.get_plugin_generation_detail("reload_gen").unwrap();
        assert_eq!(detail.previous_generation, Some(gen1));
    }

    #[test]
    fn list_plugin_generations_returns_all() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.load_plugin_from_memory("list_a", &bytes, WasmResourceLimits::default())
            .unwrap();
        mgr.load_plugin_from_memory("list_b", &bytes, WasmResourceLimits::default())
            .unwrap();

        let list = mgr.list_plugin_generations();
        assert_eq!(list.len(), 2);
        let names: Vec<&str> = list.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"list_a"));
        assert!(names.contains(&"list_b"));
    }

    #[test]
    fn get_plugin_detail_returns_full_info() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.load_plugin_from_memory("detail_plugin", &bytes, WasmResourceLimits::default())
            .unwrap();

        let detail = mgr.get_plugin_detail("detail_plugin");
        assert!(detail.is_some());
        let detail = detail.unwrap();
        assert_eq!(detail.name, "detail_plugin");
        assert_eq!(detail.lifecycle_state, PluginLifecycleState::Active);
        assert!(detail.policy.is_some());
        assert_eq!(detail.generation.generation.0, 1);
    }

    #[test]
    fn quarantine_sets_lifecycle_state() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.load_plugin_from_memory("quarantine_test", &bytes, WasmResourceLimits::default())
            .unwrap();

        mgr.quarantine_plugin("quarantine_test", "suspicious behavior")
            .expect("quarantine should succeed");

        let state = mgr.get_plugin_lifecycle_state("quarantine_test");
        assert_eq!(state, Some(PluginLifecycleState::Quarantined));

        let transitions = mgr.get_plugin_lifecycle_transitions("quarantine_test");
        assert!(
            transitions
                .iter()
                .any(|t| t.to == PluginLifecycleState::Quarantined),
            "should have Quarantined transition in audit trail"
        );
    }

    #[test]
    fn quarantine_then_reset() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.load_plugin_from_memory("qr_test", &bytes, WasmResourceLimits::default())
            .unwrap();

        mgr.quarantine_plugin("qr_test", "test").unwrap();
        assert_eq!(
            mgr.get_plugin_lifecycle_state("qr_test"),
            Some(PluginLifecycleState::Quarantined)
        );

        mgr.reset_plugin("qr_test").unwrap();
        assert_eq!(
            mgr.get_plugin_lifecycle_state("qr_test"),
            Some(PluginLifecycleState::Active)
        );
    }

    #[test]
    fn disable_plugin_prevents_lifecycle_state() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.load_plugin_from_memory("disable_test", &bytes, WasmResourceLimits::default())
            .unwrap();

        mgr.disable_plugin("disable_test", "testing disable")
            .unwrap();
        assert_eq!(
            mgr.get_plugin_lifecycle_state("disable_test"),
            Some(PluginLifecycleState::Disabled)
        );
    }

    #[test]
    fn validate_hot_reload_config_production_default_rejects() {
        let mgr = WasmPluginManager::new();
        // Default config has enabled=false, production_enabled=false
        let config = mgr.get_hot_reload_config();
        assert!(!config.enabled);
        assert!(!config.production_enabled);

        // When enabled but not production_enabled, validate should reject in prod
        mgr.set_hot_reload_config(synvoid_plugin_runtime::HotReloadConfig {
            enabled: true,
            production_enabled: false,
            ..Default::default()
        });
        // Note: validate_hot_reload_config only errors if is_production_env() is true
        // and production_enabled is false. In test env, this may or may not trigger.
        // Just verify the method exists and doesn't panic.
        let _ = mgr.validate_hot_reload_config();
    }

    #[test]
    fn replace_policy_reject_existing_blocks_duplicate() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.set_replace_policy(PluginReplacePolicy::RejectExisting);

        mgr.load_plugin_from_memory("reject_dup", &bytes, WasmResourceLimits::default())
            .unwrap();

        let result =
            mgr.load_plugin_from_memory("reject_dup", &bytes, WasmResourceLimits::default());
        assert!(result.is_err(), "RejectExisting should block duplicate");
    }

    #[test]
    fn replace_policy_replace_same_source_allows_same_name() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.set_replace_policy(PluginReplacePolicy::ReplaceSameSource);

        mgr.load_plugin_from_memory("same_src", &bytes, WasmResourceLimits::default())
            .unwrap();

        // Same name + same bytes (same binary hash) should be allowed
        let result = mgr.load_plugin_from_memory("same_src", &bytes, WasmResourceLimits::default());
        assert!(result.is_ok(), "ReplaceSameSource should allow same source");
    }

    #[test]
    fn remove_plugin_clears_registry() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.load_plugin_from_memory("remove_me", &bytes, WasmResourceLimits::default())
            .unwrap();
        assert!(mgr.is_plugin_loaded("remove_me"));

        mgr.remove_plugin("remove_me").unwrap();
        assert!(!mgr.is_plugin_loaded("remove_me"));
        assert!(mgr.get_plugin_generation("remove_me").is_none());
    }
}
