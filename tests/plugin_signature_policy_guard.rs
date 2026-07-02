//! Guardrail tests for plugin signature and trust policy enforcement.
//!
//! These tests enforce architectural invariants:
//! - `enforce_plugin_load_policy` must exist and be callable from all loader paths.
//! - SignedSandboxed plugins must pass through `verify_plugin_signature`.
//! - DevelopmentHotReload must require `dev_mode` config.
//! - Disabled trust tier must always be rejected.
//! - Error messages must not leak key material.
//! - Required error enum variants must exist.

use std::path::PathBuf;

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test 1: `enforce_plugin_load_policy` must exist in sandbox/types.rs.
///
/// This function is the central enforcement point for plugin trust policy.
/// If it is accidentally removed, all loader paths lose their enforcement.
#[test]
fn enforce_plugin_load_policy_exists() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    assert!(
        types_file.exists(),
        "sandbox/types.rs must exist at {}",
        types_file.display()
    );

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");
    assert!(
        text.contains("pub fn enforce_plugin_load_policy("),
        "enforce_plugin_load_policy must be a public function in sandbox/types.rs"
    );
}

/// Test 2: All plugin loader files must reference enforcement.
///
/// Every file that loads plugins must either call `enforce_plugin_load_policy`
/// directly or reference `PluginLoadConfig`. This ensures loader paths are
/// aware of trust-tier enforcement.
///
/// Exception allowlist:
/// - `unsafe_native_loader.rs`: Native `.so` loader — no WASM manifest concept.
///   Trust validation is file-permission-based (no symlinks, size, ABI version).
#[test]
fn all_load_paths_call_enforcement() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let plugin_runtime_src = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src");

    // Files exempted from enforcement reference requirement with reasons
    let exempt_files: Vec<PathBuf> = vec![
        // Native .so loader: no WASM manifest/signing concept. Validates via
        // file permissions, no symlinks, size checks, and ABI version.
        plugin_runtime_src.join("unsafe_native_loader.rs"),
        // Composition root that delegates to WasmPluginManager. Trust-tier
        // enforcement happens inside WasmPluginManager::load_plugin_with_limits.
        repo.join("src").join("server").join("plugin_runtime.rs"),
    ];

    let loader_files = [
        plugin_runtime_src.join("plugin_manager.rs"),
        plugin_runtime_src.join("wasm_runtime.rs"),
        plugin_runtime_src.join("unsafe_native_loader.rs"),
        repo.join("src").join("plugin").join("mod.rs"),
        repo.join("src").join("server").join("plugin_runtime.rs"),
    ];

    let mut hard_violations = Vec::new();

    for file in &loader_files {
        if !file.exists() {
            continue;
        }
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let cleaned = strip_comments_and_strings(&text);
        let relative = file
            .strip_prefix(&repo)
            .unwrap_or(file)
            .display()
            .to_string();

        let has_enforcement =
            cleaned.contains("enforce_plugin_load_policy") || cleaned.contains("PluginLoadConfig");

        if !has_enforcement && !exempt_files.contains(file) {
            hard_violations.push(relative);
        }
    }

    if !hard_violations.is_empty() {
        panic!(
            "Plugin loader files must reference enforce_plugin_load_policy or PluginLoadConfig. \
             New loader paths must be classified before merging.\nViolations:\n  {}",
            hard_violations.join("\n  ")
        );
    }
}

/// Test 3: `verify_plugin_signature` must exist.
///
/// The cryptographic signature verification function must be present so that
/// `enforce_plugin_load_policy` can delegate to it for SignedSandboxed tier.
#[test]
fn verify_plugin_signature_exists() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");
    assert!(
        text.contains("pub fn verify_plugin_signature("),
        "verify_plugin_signature must be a public function in sandbox/types.rs"
    );
}

/// Test 4: SignedSandboxed must not bypass signature verification.
///
/// The `enforce_plugin_load_policy` function must call `verify_plugin_signature`
/// when handling `SignedSandboxed` — it must not just return `Ok(())`.
#[test]
fn signed_sandboxed_cannot_bypass_verification() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");
    let cleaned = strip_comments_and_strings(&text);

    // Find the enforce_plugin_load_policy function body and check the
    // SignedSandboxed arm calls verify_plugin_signature.
    let lines: Vec<&str> = cleaned.lines().collect();
    let mut in_fn = false;
    let mut signed_sandboxed_arm_start = None;
    let mut fn_brace_depth = 0u32;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if trimmed.contains("pub fn enforce_plugin_load_policy(") {
            in_fn = true;
            fn_brace_depth = 0;
        }

        if in_fn {
            fn_brace_depth += trimmed.matches('{').count() as u32;
            fn_brace_depth = fn_brace_depth.saturating_sub(trimmed.matches('}').count() as u32);

            if trimmed.contains("SignedSandboxed") && trimmed.contains("=>") {
                signed_sandboxed_arm_start = Some(i);
            }

            // Once we've collected enough of the function, break
            if fn_brace_depth == 0 && i > 0 && signed_sandboxed_arm_start.is_some() {
                break;
            }
        }
    }

    assert!(
        signed_sandboxed_arm_start.is_some(),
        "enforce_plugin_load_policy must handle SignedSandboxed variant"
    );

    // Check a window after the SignedSandboxed arm for verify_plugin_signature call
    let start = signed_sandboxed_arm_start.unwrap();
    let window: String = lines
        .iter()
        .skip(start)
        .take(30)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        window.contains("verify_plugin_signature"),
        "SignedSandboxed arm in enforce_plugin_load_policy must call verify_plugin_signature, \
         but found no reference in the surrounding window:\n{}",
        window
    );
}

/// Test 5: DevelopmentHotReload must require dev_mode config.
///
/// The `enforce_plugin_load_policy` function must check `config.dev_mode`
/// when handling `DevelopmentHotReload` and reject if dev_mode is false.
#[test]
fn development_hot_reload_requires_dev_mode() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");
    let cleaned = strip_comments_and_strings(&text);

    let lines: Vec<&str> = cleaned.lines().collect();
    let mut in_fn = false;
    let mut dev_hot_reload_arm_start = None;
    let mut fn_brace_depth = 0u32;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if trimmed.contains("pub fn enforce_plugin_load_policy(") {
            in_fn = true;
            fn_brace_depth = 0;
        }

        if in_fn {
            fn_brace_depth += trimmed.matches('{').count() as u32;
            fn_brace_depth = fn_brace_depth.saturating_sub(trimmed.matches('}').count() as u32);

            if trimmed.contains("DevelopmentHotReload") && trimmed.contains("=>") {
                dev_hot_reload_arm_start = Some(i);
            }

            if fn_brace_depth == 0 && i > 0 && dev_hot_reload_arm_start.is_some() {
                break;
            }
        }
    }

    assert!(
        dev_hot_reload_arm_start.is_some(),
        "enforce_plugin_load_policy must handle DevelopmentHotReload variant"
    );

    let start = dev_hot_reload_arm_start.unwrap();
    let window: String = lines
        .iter()
        .skip(start)
        .take(15)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        window.contains("dev_mode"),
        "DevelopmentHotReload arm must check config.dev_mode, but found no reference in the \
         surrounding window:\n{}",
        window
    );
}

/// Test 6: Disabled trust tier must always be rejected.
///
/// The `enforce_plugin_load_policy` function must return an error when
/// the trust tier is `Disabled`, regardless of config.
#[test]
fn disabled_trust_tier_always_rejected() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");
    let cleaned = strip_comments_and_strings(&text);

    let lines: Vec<&str> = cleaned.lines().collect();
    let mut in_fn = false;
    let mut disabled_arm_start = None;
    let mut fn_brace_depth = 0u32;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if trimmed.contains("pub fn enforce_plugin_load_policy(") {
            in_fn = true;
            fn_brace_depth = 0;
        }

        if in_fn {
            fn_brace_depth += trimmed.matches('{').count() as u32;
            fn_brace_depth = fn_brace_depth.saturating_sub(trimmed.matches('}').count() as u32);

            if trimmed.contains("Disabled") && trimmed.contains("=>") && !trimmed.contains("//") {
                disabled_arm_start = Some(i);
            }

            if fn_brace_depth == 0 && i > 0 && disabled_arm_start.is_some() {
                break;
            }
        }
    }

    assert!(
        disabled_arm_start.is_some(),
        "enforce_plugin_load_policy must handle Disabled variant"
    );

    let start = disabled_arm_start.unwrap();
    let window: String = lines
        .iter()
        .skip(start)
        .take(5)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        window.contains("Err("),
        "Disabled arm must return an error (fail-closed), but found no Err( in the \
         surrounding window:\n{}",
        window
    );
}

/// Test 7: Signature error messages must not leak key material.
///
/// The `PluginSignatureError` Display impl must not include raw key bytes
/// or signature bytes in error messages. It may include hashes, key IDs,
/// algorithm names, and byte-length diagnostics, but not the actual keys.
#[test]
fn signature_errors_not_logged_with_key_material() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");
    let cleaned = strip_comments_and_strings(&text);

    // Find the Display impl for PluginSignatureError
    let lines: Vec<&str> = cleaned.lines().collect();
    let mut in_display_impl = false;
    let mut display_lines = Vec::new();
    let mut brace_depth = 0u32;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.contains("impl std::fmt::Display for PluginSignatureError") {
            in_display_impl = true;
            brace_depth = 0;
        }
        if in_display_impl {
            brace_depth += trimmed.matches('{').count() as u32;
            brace_depth = brace_depth.saturating_sub(trimmed.matches('}').count() as u32);
            display_lines.push(trimmed.to_string());
            if brace_depth == 0 && display_lines.len() > 1 {
                break;
            }
        }
    }

    assert!(
        !display_lines.is_empty(),
        "Display impl for PluginSignatureError must exist"
    );

    let display_text = display_lines.join("\n");

    // The Display impl should not format key bytes or signature bytes directly.
    // It can reference key IDs, hashes, algorithm names, and length diagnostics.
    // We check that the impl doesn't have patterns that look like formatting
    // raw key/signature data (e.g., format! with `key_bytes`, `sig_bytes`,
    // `public_key`, `signature` fields being directly interpolated).
    let dangerous_patterns = [
        "format!(\"{}\", key",
        "format!(\"{}\", sig",
        "format!(\"{}\", public_key",
        "format!(\"{}\", signature",
        "write!(f, \"{}\", key_bytes",
        "write!(f, \"{}\", sig_bytes",
    ];

    let mut violations = Vec::new();
    for pattern in &dangerous_patterns {
        if display_text.contains(pattern) {
            violations.push(format!(
                "PluginSignatureError Display leaks key material: {}",
                pattern
            ));
        }
    }

    if !violations.is_empty() {
        panic!(
            "PluginSignatureError Display leaks key material:\n{}",
            violations.join("\n")
        );
    }
}

/// Test 8: `PluginLoadError` enum must have required variants.
///
/// The error type returned by `enforce_plugin_load_policy` must include
/// all structural variants to ensure callers can match on them.
#[test]
fn plugin_load_error_type_exists() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");
    let cleaned = strip_comments_and_strings(&text);

    // Verify the enum definition exists
    assert!(
        cleaned.contains("pub enum PluginLoadError"),
        "PluginLoadError enum must exist in sandbox/types.rs"
    );

    // Verify required variants
    let required_variants = [
        "Disabled",
        "DevHotReloadNotAllowed",
        "LocalTrustedNotAllowed",
        "Signature",
    ];

    // Find the enum block
    let lines: Vec<&str> = cleaned.lines().collect();
    let mut in_enum = false;
    let mut enum_text = String::new();
    let mut brace_depth = 0u32;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.contains("pub enum PluginLoadError") {
            in_enum = true;
            brace_depth = 0;
        }
        if in_enum {
            brace_depth += trimmed.matches('{').count() as u32;
            brace_depth = brace_depth.saturating_sub(trimmed.matches('}').count() as u32);
            enum_text.push_str(trimmed);
            enum_text.push('\n');
            if brace_depth == 0 && enum_text.contains("PluginLoadError") {
                break;
            }
        }
    }

    assert!(
        !enum_text.is_empty(),
        "PluginLoadError enum block must be found"
    );

    for variant in &required_variants {
        assert!(
            enum_text.contains(variant),
            "PluginLoadError must have '{}' variant, but enum body is:\n{}",
            variant,
            enum_text
        );
    }
}

/// Test 9: Hot reload must use the same trust policy as initial load.
///
/// The `reload_plugin` method in `WasmRuntime` must delegate to `load_with_priority`
/// (the same code path used for initial loads). If hot reload bypasses the initial
/// load path, signature verification and trust-tier enforcement would be skipped.
#[test]
fn hot_reload_uses_same_trust_policy_as_initial_load() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    assert!(
        wasm_file.exists(),
        "wasm_runtime.rs must exist at {}",
        wasm_file.display()
    );

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    // Find the reload_plugin method body
    let lines: Vec<&str> = cleaned.lines().collect();
    let mut in_reload_fn = false;
    let mut reload_fn_start = None;
    let mut fn_brace_depth = 0u32;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if trimmed.contains("pub fn reload_plugin(") && trimmed.contains("Path") {
            in_reload_fn = true;
            fn_brace_depth = 0;
            reload_fn_start = Some(i);
        }

        if in_reload_fn {
            fn_brace_depth += trimmed.matches('{').count() as u32;
            fn_brace_depth = fn_brace_depth.saturating_sub(trimmed.matches('}').count() as u32);

            if fn_brace_depth == 0 && i > reload_fn_start.unwrap() {
                break;
            }
        }
    }

    assert!(
        reload_fn_start.is_some(),
        "WasmRuntime::reload_plugin must exist"
    );

    // Check the reload_plugin body calls load_with_priority (same path as initial load)
    let start = reload_fn_start.unwrap();
    let window: String = lines
        .iter()
        .skip(start)
        .take(30)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        window.contains("load_with_priority")
            || window.contains("load_with_policy")
            || window.contains("reload_plugin_with_outcome")
            || window.contains("prepare_reload_candidate"),
        "reload_plugin must delegate to load_with_priority, load_with_policy, \
         reload_plugin_with_outcome, or prepare_reload_candidate \
         (same trust policy as initial load), but found no reference in the method body:\n{}",
        window
    );
}

/// Test 10: Loader trust audit document must exist.
///
/// The `architecture/plugin_loader_trust_audit.md` document must exist and contain
/// the loader table. This ensures the audit is kept alongside the enforcement code.
#[test]
fn loader_trust_audit_document_exists() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let audit_doc = repo
        .join("architecture")
        .join("plugin_loader_trust_audit.md");

    assert!(
        audit_doc.exists(),
        "architecture/plugin_loader_trust_audit.md must exist at {}",
        audit_doc.display()
    );

    let text = std::fs::read_to_string(&audit_doc).expect("read audit doc");
    assert!(
        text.contains("Loader path"),
        "audit doc must contain a loader path table"
    );
    assert!(
        text.contains("Trust tier"),
        "audit doc must contain trust tier column"
    );
}

/// Test 11: `load_with_policy` must use `Module::from_binary` for TOCTOU closure.
///
/// When `prepared` bytes are provided, `load_with_policy` must instantiate via
/// `Module::from_binary` (not `Module::from_file`) to close the TOCTOU race
/// between verification and instantiation. This guard test scans the function
/// body to ensure the bytes path exists.
#[test]
fn load_with_policy_uses_module_from_binary_for_toctou_closure() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    assert!(
        wasm_file.exists(),
        "wasm_runtime.rs must exist at {}",
        wasm_file.display()
    );

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    // Find the load_with_policy function body
    let lines: Vec<&str> = cleaned.lines().collect();
    let mut in_fn = false;
    let mut fn_start = None;
    let mut fn_brace_depth = 0u32;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if trimmed.contains("pub fn load_with_policy(") {
            in_fn = true;
            fn_brace_depth = 0;
            fn_start = Some(i);
        }

        if in_fn {
            fn_brace_depth += trimmed.matches('{').count() as u32;
            fn_brace_depth = fn_brace_depth.saturating_sub(trimmed.matches('}').count() as u32);

            if fn_brace_depth == 0 && i > fn_start.unwrap() {
                break;
            }
        }
    }

    assert!(
        fn_start.is_some(),
        "WasmRuntime::load_with_policy must exist"
    );

    // Collect the function body
    let start = fn_start.unwrap();
    let fn_body: String = lines
        .iter()
        .skip(start)
        .take(50)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    // The function must use Module::from_binary when prepared bytes are available
    assert!(
        fn_body.contains("Module::from_binary"),
        "load_with_policy must use Module::from_binary for TOCTOU closure when \
         prepared bytes are available, but found no reference in the function body:\n{}",
        fn_body
    );

    // Must also have the prepared bytes check that selects between from_binary and from_file
    assert!(
        fn_body.contains("Some(bytes)") || fn_body.contains("prepared"),
        "load_with_policy must check for prepared bytes to choose between \
         Module::from_binary and Module::from_file, but found no reference:\n{}",
        fn_body
    );
}

/// Test 12: Mesh memory load path must go through `prepare_plugin_load`.
///
/// The `load_plugin_from_memory_with_priority` method (used for mesh-distributed
/// plugins) must delegate to `prepare_plugin_load`, which in turn calls
/// `enforce_plugin_load_policy`. This ensures mesh-loaded plugins are subject
/// to trust-tier enforcement and cannot bypass policy.
#[test]
fn mesh_memory_load_path_enforces_policy() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    assert!(
        wasm_file.exists(),
        "wasm_runtime.rs must exist at {}",
        wasm_file.display()
    );

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    // Find the load_plugin_from_memory_with_priority function body
    let lines: Vec<&str> = cleaned.lines().collect();
    let mut in_fn = false;
    let mut fn_start = None;
    let mut fn_brace_depth = 0u32;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if trimmed.contains("fn load_plugin_from_memory_with_priority(") {
            in_fn = true;
            fn_brace_depth = 0;
            fn_start = Some(i);
        }

        if in_fn {
            fn_brace_depth += trimmed.matches('{').count() as u32;
            fn_brace_depth = fn_brace_depth.saturating_sub(trimmed.matches('}').count() as u32);

            if fn_brace_depth == 0 && i > fn_start.unwrap() {
                break;
            }
        }
    }

    assert!(
        fn_start.is_some(),
        "WasmPluginManager::load_plugin_from_memory_with_priority must exist"
    );

    // Collect the function body
    let start = fn_start.unwrap();
    let fn_body: String = lines
        .iter()
        .skip(start)
        .take(40)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    // The function must call prepare_plugin_load, which internally calls enforce_plugin_load_policy
    assert!(
        fn_body.contains("prepare_plugin_load"),
        "load_plugin_from_memory_with_priority must delegate to prepare_plugin_load \
         (which enforces trust-tier policy), but found no reference in the method body:\n{}",
        fn_body
    );
}
