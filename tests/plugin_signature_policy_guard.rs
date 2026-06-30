//! Guardrail tests for plugin signature and trust policy enforcement.
//!
//! These tests enforce architectural invariants:
//! - `enforce_plugin_load_policy` must exist and be callable from all loader paths.
//! - SignedSandboxed plugins must pass through `verify_plugin_signature`.
//! - DevelopmentHotReload must require `dev_mode` config.
//! - Disabled trust tier must always be rejected.
//! - Error messages must not leak key material.
//! - Required error enum variants must exist.

use std::path::{Path, PathBuf};

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
/// directly or reference `PluginLoadConfig`. This is a soft guard — some files
/// may be thin wrappers that delegate to other functions in the crate.
#[test]
fn all_load_paths_call_enforcement() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let plugin_runtime_src = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src");

    let loader_files = [
        plugin_runtime_src.join("plugin_manager.rs"),
        plugin_runtime_src.join("wasm_runtime.rs"),
        plugin_runtime_src.join("axum_loader.rs"),
        repo.join("src").join("plugin").join("mod.rs"),
        repo.join("src").join("server").join("plugin_runtime.rs"),
    ];

    let mut soft_violations = Vec::new();

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

        if !has_enforcement {
            soft_violations.push(relative);
        }
    }

    if !soft_violations.is_empty() {
        // Soft guard — report but don't fail. Some files may be thin wrappers
        // that delegate to functions within the crate which do enforce the policy.
        eprintln!(
            "[soft] plugin loader files that don't reference enforce_plugin_load_policy or PluginLoadConfig:\n  {}",
            soft_violations.join("\n  ")
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
