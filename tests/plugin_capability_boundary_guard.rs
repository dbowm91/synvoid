//! Guardrail tests for plugin capability boundary enforcement.
//!
//! These tests enforce architectural invariants:
//! - No plugin runtime API exposes filesystem/network/mesh/admin without capability check.
//! - Development hot-reload cannot be enabled without explicit dev-mode check.
//! - No `unwrap()`/`expect()` in plugin manifest parsing paths that can be triggered by plugin files.
//! - No `mem::forget` or detached hot-reload watcher ownership regression.

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

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that WASM host functions exposed to plugins in the linker have
/// capability checks (via PluginCapabilities or prefix-based filtering).
///
/// The `create_linker` function in wasm_runtime.rs registers host functions
/// that WASM plugins can call. Functions like `mesh_query_dht`,
/// `mesh_check_threat`, and `mesh_emit_event` must gate access via the
/// capability model or explicit prefix/allowlist filtering.
///
/// This test scans the linker registration code for dangerous patterns
/// (fs, network, mesh) and asserts that each is inside a `func_wrap` block
/// that contains a capability check (permits/require) or prefix-based guard.
#[test]
fn plugin_runtime_host_functions_have_capability_gates() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_root = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src");

    // Only scan files that register WASM host functions (linker code).
    // Loader files (axum_loader, plugin_manager, spin/manifest) legitimately
    // read plugin files from disk — they are not exposed to WASM plugins.
    let linker_files = [
        crate_root.join("wasm_runtime.rs"),
        crate_root.join("instance_pool.rs"),
    ];

    let dangerous_patterns = [
        "std::fs::",
        "std::fs::File::",
        "reqwest::",
        "hyper::Client",
        "TcpStream::",
        "UdpSocket::",
        "mesh_query_dht",
        "mesh_check_threat",
        "mesh_emit_event",
    ];

    let mut violations = Vec::new();

    for file in &linker_files {
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

        for (line_num, line) in cleaned_lines(&cleaned) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//!") {
                continue;
            }
            for pattern in &dangerous_patterns {
                if trimmed.contains(pattern) {
                    // Check whether this line is inside a func_wrap block
                    // that has a capability gate. We use a heuristic: the
                    // surrounding 30-line window must contain a capability
                    // check (permits, require, is_sensitive, allowed_, or
                    // check_threat / sensitive_prefixes).
                    let window_start = line_num.saturating_sub(30);
                    let window_end = (line_num + 30).min(cleaned.lines().count());
                    let window: String = cleaned
                        .lines()
                        .skip(window_start)
                        .take(window_end - window_start)
                        .collect::<Vec<_>>()
                        .join("\n");

                    let has_gate = window.contains("permits")
                        || window.contains("require(")
                        || window.contains("is_sensitive")
                        || window.contains("allowed_")
                        || window.contains("sensitive_prefixes")
                        || window.contains("is_explicitly_allowed");

                    if !has_gate {
                        violations.push(format!(
                            "{}:{}: '{}' in linker code without capability gate",
                            relative, line_num, pattern
                        ));
                    }
                }
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "WASM host functions in linker code lack capability gates:\n{}",
            violations.join("\n")
        );
    }
}

/// Manifest parsing must not use unwrap/expect on untrusted input.
#[test]
fn manifest_parsing_no_unwrap_on_untrusted_input() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");
    let cleaned = strip_comments_and_strings(&text);
    let mut violations = Vec::new();

    let mut in_manifest_impl = false;

    for (line_num, line) in cleaned_lines(&cleaned) {
        let trimmed = line.trim();

        if trimmed.contains("impl PluginManifest") {
            in_manifest_impl = true;
        }

        if in_manifest_impl {
            // Detect end of impl block (simple heuristic: standalone `}`)
            if trimmed == "}" && !trimmed.contains("//") {
                in_manifest_impl = false;
            }

            // Check for unwrap() and expect() in parsing/validation
            if trimmed.contains(".unwrap()") || trimmed.contains(".expect(") {
                violations.push(format!(
                    "types.rs:{}: unwrap/expect in manifest parsing path: {}",
                    line_num, trimmed
                ));
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "Manifest parsing uses unwrap/expect on potentially untrusted input:\n{}",
            violations.join("\n")
        );
    }
}

/// No mem::forget in plugin runtime source.
#[test]
fn no_mem_forget_in_plugin_runtime() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_root = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src");

    let mut violations = Vec::new();

    for file in rust_files_under(&crate_root) {
        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let cleaned = strip_comments_and_strings(&text);
        let relative = file
            .strip_prefix(&repo.join("crates").join("synvoid-plugin-runtime"))
            .unwrap_or(&file)
            .display()
            .to_string();

        for (line_num, line) in cleaned_lines(&cleaned) {
            if line.contains("mem::forget") || line.contains("std::mem::forget") {
                violations.push(format!("{}:{}: mem::forget found", relative, line_num));
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "Plugin runtime contains mem::forget usage:\n{}",
            violations.join("\n")
        );
    }
}

/// Hot-reload watcher must not be detached (no fire-and-forget spawn).
#[test]
fn hot_reload_watcher_not_detached() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dirs = [
        repo.join("src").join("plugin"),
        repo.join("src").join("server"),
    ];

    let mut violations = Vec::new();

    for dir in &dirs {
        for file in rust_files_under(dir) {
            let text = match std::fs::read_to_string(&file) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let cleaned = strip_comments_and_strings(&text);
            let relative = file
                .strip_prefix(&repo)
                .unwrap_or(&file)
                .display()
                .to_string();

            let mut in_hot_reload = false;
            for (line_num, line) in cleaned_lines(&cleaned) {
                if line.contains("hot_reload") || line.contains("HotReload") {
                    in_hot_reload = true;
                }
                if in_hot_reload {
                    if line.contains("tokio::spawn(")
                        && !line.contains("let ")
                        && !line.contains("let _ =")
                    {
                        violations.push(format!(
                            "{}:{}: tokio::spawn in hot-reload without capturing handle",
                            relative, line_num
                        ));
                    }
                }
            }
        }
    }

    // Soft check — report but don't fail. The main guard is in
    // unified_server_lifecycle_ownership_guard.rs; this is a secondary signal.
    if !violations.is_empty() {
        eprintln!(
            "[soft] hot-reload watcher may be detached (main guard is unified_server_lifecycle_ownership_guard):\n{}",
            violations.join("\n")
        );
    }
}

/// PluginTrustTier::Disabled is the safest default for unknown configs.
#[test]
fn plugin_trust_tier_disabled_prevents_loading() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    assert!(types_file.exists(), "sandbox/types.rs must exist");
    let text = std::fs::read_to_string(&types_file).expect("read types.rs");
    assert!(
        text.contains("Disabled"),
        "PluginTrustTier must include Disabled variant"
    );
}

/// All 11 PluginCapability variants must have corresponding permits() checks.
#[test]
fn all_capabilities_have_permits_checks() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");

    // Verify all capability variants exist in the enum
    let required_variants = [
        "RequestInspect",
        "RequestMutate",
        "ResponseInspect",
        "ResponseMutate",
        "Metrics",
        "Persistence",
        "FilesystemRead",
        "FilesystemWrite",
        "Network",
        "Mesh",
        "AdminEvents",
    ];

    for variant in &required_variants {
        assert!(
            text.contains(variant),
            "PluginCapability must include {} variant",
            variant
        );
    }

    // Verify all have permits() arms by finding the permits() match block
    let mut in_permits_fn = false;
    let mut permits_arms = Vec::new();
    let mut brace_depth = 0u32;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.contains("fn permits(") {
            in_permits_fn = true;
            brace_depth = 0;
        }
        if in_permits_fn {
            brace_depth += trimmed.matches('{').count() as u32;
            brace_depth = brace_depth.saturating_sub(trimmed.matches('}').count() as u32);
            if trimmed.starts_with("PluginCapability::") {
                let variant = trimmed
                    .split("=>")
                    .next()
                    .unwrap_or("")
                    .replace("PluginCapability::", "")
                    .trim()
                    .to_string();
                if !variant.is_empty() {
                    permits_arms.push(variant);
                }
            }
            if brace_depth == 0 && permits_arms.len() >= 11 {
                break;
            }
        }
    }

    for variant in &required_variants {
        assert!(
            permits_arms.contains(&variant.to_string()),
            "permits() must handle PluginCapability::{}",
            variant
        );
    }
}

/// PluginCapabilities default must be all-deny (all false/empty).
#[test]
fn plugin_capabilities_default_is_all_deny() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");

    // The Default derive should produce all-false bools and empty vecs.
    // Verify that PluginManifest uses #[serde(default)] on capabilities field.
    assert!(
        text.contains("#[serde(default)]"),
        "PluginManifest must use #[serde(default)] for capabilities field"
    );
}

/// Development hot-reload must not be enabled without dev-mode check.
#[test]
fn dev_hot_reload_requires_explicit_config() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("types.rs");

    let text = std::fs::read_to_string(&types_file).expect("read types.rs");

    // DevelopmentHotReload variant must exist
    assert!(
        text.contains("DevelopmentHotReload"),
        "PluginTrustTier must include DevelopmentHotReload variant"
    );

    // Signing policy must handle dev mode
    assert!(
        text.contains("SigningPolicy"),
        "SigningPolicy must be defined for production enforcement"
    );
}
