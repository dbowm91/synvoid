//! Guardrail test for manifest authority wiring load path enforcement.
//!
//! Ensures that all plugin load paths use `prepare_plugin_load` or
//! `limits_from_manifest` rather than directly calling `WasmRuntime::load`
/// with `self.default_limits.clone()` after manifest enforcement.
use std::path::PathBuf;

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
            '"' => {
                while let Some(next) = chars.next() {
                    if next == '\\' {
                        chars.next();
                    } else if next == '"' {
                        break;
                    }
                }
            }
            _ => {}
        }
        result.push(ch);
    }
    result
}

/// Test 1: All load paths in WasmPluginManager must go through prepare_plugin_load.
///
/// After manifest enforcement was introduced, no load path should call
/// `WasmRuntime::load(path, self.default_limits.clone())` directly.
#[test]
fn all_load_paths_use_prepare_plugin_load() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    // Find all methods in WasmPluginManager that look like load paths
    let load_methods = [
        "pub fn load_plugin(",
        "pub fn load_plugin_with_limits(",
        "pub fn load_plugin_from_memory(",
        "pub fn load_plugin_from_memory_with_priority(",
        "pub fn reload_plugin(",
    ];

    for method_sig in &load_methods {
        // Find the method body
        let lines: Vec<&str> = cleaned.lines().collect();
        let mut method_start = None;
        let mut brace_depth = 0u32;
        let mut in_method = false;

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains(method_sig) {
                in_method = true;
                brace_depth = 0;
                method_start = Some(i);
            }
            if in_method {
                brace_depth += trimmed.matches('{').count() as u32;
                brace_depth = brace_depth.saturating_sub(trimmed.matches('}').count() as u32);
                if brace_depth == 0 && i > method_start.unwrap_or(0) {
                    // Extract method body
                    let body: String = lines
                        .iter()
                        .skip(method_start.unwrap())
                        .take(i - method_start.unwrap() + 1)
                        .copied()
                        .collect::<Vec<_>>()
                        .join("\n");

                    // The method must NOT contain a direct call to
                    // WasmRuntime::load with self.default_limits
                    assert!(
                        !body.contains("WasmRuntime::load(")
                            || body.contains("prepare_plugin_load")
                            || body.contains("load_with_policy"),
                        "Load path '{}' must use prepare_plugin_load or load_with_policy, \
                         not WasmRuntime::load() directly:\n{}",
                        method_sig,
                        body
                    );
                    break;
                }
            }
        }
    }
}

/// Test 2: prepare_plugin_load exists and returns PreparedPluginLoad.
///
/// The central enforcement method must exist and return the new type.
#[test]
fn prepare_plugin_load_exists_and_returns_prepared() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    assert!(
        cleaned.contains("fn prepare_plugin_load("),
        "prepare_plugin_load method must exist in wasm_runtime.rs"
    );
    assert!(
        cleaned.contains("PreparedPluginLoad"),
        "prepare_plugin_load must reference PreparedPluginLoad"
    );
}

/// Test 3: limits_from_manifest function exists in policy module.
///
/// The manifest-to-runtime conversion helper must be available.
#[test]
fn limits_from_manifest_exists() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let policy_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("policy.rs");

    let text = std::fs::read_to_string(&policy_file).expect("read policy.rs");

    assert!(
        text.contains("pub fn limits_from_manifest("),
        "limits_from_manifest function must exist in policy.rs"
    );
    assert!(
        text.contains("EffectivePluginPolicy"),
        "EffectivePluginPolicy struct must exist in policy.rs"
    );
    assert!(
        text.contains("PreparedPluginLoad"),
        "PreparedPluginLoad struct must exist in policy.rs"
    );
}

/// Test 4: WasmResourceLimits has Debug derive.
///
/// Required for EffectivePluginPolicy and PreparedPluginLoad to derive Debug.
#[test]
fn wasm_resource_limits_has_debug() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    // Find the struct definition and check for Debug
    let lines: Vec<&str> = cleaned.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("pub struct WasmResourceLimits") {
            // Check the previous line for #[derive(Debug, Clone)]
            if i > 0 {
                let prev = lines[i - 1];
                assert!(
                    prev.contains("Debug"),
                    "WasmResourceLimits must derive Debug, found: {}",
                    prev
                );
            }
            break;
        }
    }
}

/// Test 5: PluginInfo has version and trust_tier fields.
///
/// Ensures introspection fields are present.
#[test]
fn plugin_info_has_introspection_fields() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    assert!(
        cleaned.contains("pub struct PluginInfo"),
        "PluginInfo struct must exist"
    );
    assert!(
        cleaned.contains("pub version: String"),
        "PluginInfo must have version field"
    );
    assert!(
        cleaned.contains("pub trust_tier: PluginTrustTier"),
        "PluginInfo must have trust_tier field"
    );
    assert!(
        cleaned.contains("pub timeout: Duration"),
        "PluginInfo must have timeout field (Duration)"
    );
    assert!(
        cleaned.contains("pub capabilities_summary:"),
        "PluginInfo must have capabilities_summary field"
    );
}
