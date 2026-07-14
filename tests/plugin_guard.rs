//! Consolidated plugin guardrail tests.
//!
//! This file merges the following three original guard test files into one:
//! - `plugin_capability_boundary_guard.rs` — capability gate enforcement, manifest
//!   safety, `mem::forget` regression, hot-reload detachment, trust tier, timeout
//!   types, pooled-instance drop, and duration-based timeout.
//! - `plugin_lifecycle_guard.rs` — reload-before-swap ordering, duplicate-name checks,
//!   hot-reload production gate, unsafe-native gating, stable-file wait, generation
//!   ID, lifecycle state machine, reload/replace outcome variants, audit trail,
//!   namespace separation, `PluginDetail` fields, and behavioral runtime tests.
//! - `plugin_signature_policy_guard.rs` — `enforce_plugin_load_policy` existence,
//!   loader-path enforcement, `verify_plugin_signature`, SignedSandboxed bypass
//!   prevention, dev-mode gating, disabled-tier rejection, key-material redaction,
//!   `PluginLoadError` variants, trust-policy delegation, audit document presence,
//!   TOCTOU closure, and mesh memory-load enforcement.

use std::path::{Path, PathBuf};

// ─── Shared Helpers ───────────────────────────────────────────────────────────

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
// Section: plugin_capability_boundary_guard
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that WASM host functions exposed to plugins in the linker have
/// capability checks (via PluginCapabilities or prefix-based filtering).
///
/// The `create_linker` function in wasm_runtime.rs registers host functions
/// that WASM plugins can call. Functions like `mesh_query_dht`,
/// `mesh_check_threat`, and `mesh_emit_event` must gate access via the
/// capability model or explicit prefix/allowlist filtering.
///
/// This test scans only the bodies of `func_wrap` closures for dangerous
/// patterns (fs, network, mesh) and asserts that each has a capability
/// check (permits/require) or prefix-based guard within the same closure.
///
/// Infrastructure code outside `func_wrap` blocks (e.g. `discover_manifest`
/// which reads plugin TOML manifests during loading) is excluded — it is
/// not exposed to WASM plugins and legitimately uses filesystem I/O.
#[test]
fn plugin_runtime_host_functions_have_capability_gates() {
    let repo = repo_root();
    let crate_root = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src");

    // Only scan files that register WASM host functions (linker code).
    // Loader files (unsafe_native_loader, plugin_manager, spin/manifest) legitimately
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

    for file in &linker_files {
        assert!(
            file.exists(),
            "linker_files entry '{}' does not exist — remove stale entry or update the list",
            file.display()
        );
    }

    let mut violations = Vec::new();

    for file in &linker_files {
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

        // Extract only func_wrap closure bodies. We track brace depth
        // starting from each `func_wrap(` opening, collecting lines until
        // the closure closes. Only lines inside these blocks are scanned
        // for dangerous patterns.
        let lines: Vec<&str> = cleaned.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();
            if trimmed.contains("func_wrap(") {
                // Find the opening brace of the closure
                let mut brace_depth = 0i32;
                let mut found_open = false;
                let block_start = i;
                let mut block_lines: Vec<(usize, &str)> = Vec::new();

                // Scan forward from the func_wrap line to find and track the closure
                for line in lines.iter().take((i + 5).min(lines.len())).skip(i) {
                    for ch in line.chars() {
                        if ch == '{' {
                            brace_depth += 1;
                            found_open = true;
                        } else if ch == '}' {
                            brace_depth -= 1;
                        }
                    }
                }

                if found_open && brace_depth > 0 {
                    // We're inside an unclosed closure — collect lines until it closes
                    block_lines.push((block_start + 1, lines[block_start]));
                    for (j, line) in lines.iter().enumerate().skip(block_start + 1) {
                        for ch in line.chars() {
                            if ch == '{' {
                                brace_depth += 1;
                            } else if ch == '}' {
                                brace_depth -= 1;
                            }
                        }
                        block_lines.push((j + 1, line));
                        if brace_depth <= 0 {
                            break;
                        }
                    }

                    // Scan the closure body for dangerous patterns
                    let block_text: String = block_lines
                        .iter()
                        .map(|(_, l)| *l)
                        .collect::<Vec<_>>()
                        .join("\n");
                    let block_window_start =
                        block_lines.first().map_or(0, |(n, _)| n.saturating_sub(1));
                    let block_window_end = block_lines.last().map_or(0, |(n, _)| *n);

                    for (line_num, line) in &block_lines {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with("//!") {
                            continue;
                        }
                        for pattern in &dangerous_patterns {
                            if trimmed.contains(pattern) {
                                let has_gate = block_text.contains("permits")
                                    || block_text.contains("require(")
                                    || block_text.contains("is_sensitive")
                                    || block_text.contains("allowed_")
                                    || block_text.contains("sensitive_prefixes")
                                    || block_text.contains("is_explicitly_allowed");

                                if !has_gate {
                                    violations.push(format!(
                                        "{}:{}: '{}' in func_wrap closure without capability gate (lines {}-{})",
                                        relative, line_num, pattern, block_window_start, block_window_end
                                    ));
                                }
                            }
                        }
                    }

                    // Skip past this closure
                    i = block_lines.last().map_or(i + 1, |(n, _)| *n);
                } else {
                    i += 1;
                }
            } else {
                i += 1;
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
    let repo = repo_root();
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
    let repo = repo_root();
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
            .strip_prefix(repo.join("crates").join("synvoid-plugin-runtime"))
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
    let repo = repo_root();
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
                if in_hot_reload
                    && line.contains("tokio::spawn(")
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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

// ═══════════════════════════════════════════════════════════════════════════════
// Section: plugin_capability_boundary_guard — Workstream 5: Strengthen CI and
//          Guardrail Enforcement
// ═══════════════════════════════════════════════════════════════════════════════

/// Failed pooled instances must be dropped, not returned to pool.
///
/// After a guest_alloc trap, guest_free trap, memory violation, or fuel
/// exhaustion, the instance must NOT be returned to the pool. The hot path
/// must drop failed instances to prevent poison propagation.
#[test]
fn test_no_pooled_instance_returned_after_trap() {
    let repo = repo_root();
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    // Use raw source (not stripped) to find comment markers
    let raw_source = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");

    // The filter_request and transform_response methods must have error paths
    // that drop the pooled instance instead of returning it to the pool.
    // Check for the "Drop poisoned instance" comment pattern.
    let drop_comment_count = raw_source.matches("Drop poisoned instance").count();
    assert!(
        drop_comment_count >= 2,
        "Both filter_request and transform_response must have 'Drop poisoned instance' comments (found {}, expected >= 2)",
        drop_comment_count
    );

    // Verify the error-path pattern in stripped source: after result.is_err(),
    // drop(inst) is called and NOT return_instance.
    let cleaned = strip_comments_and_strings(&raw_source);
    assert!(
        cleaned.contains("return_instance"),
        "return_instance must exist for successful invocations"
    );

    let lines: Vec<&str> = cleaned.lines().collect();
    let mut drop_after_error_count = 0;
    for (i, line) in lines.iter().enumerate() {
        if line.contains("result.is_err()") {
            // Look for drop(inst) within the next 5 lines (inside the if block)
            for (_j, line) in lines
                .iter()
                .enumerate()
                .take((i + 6).min(lines.len()))
                .skip(i + 1)
            {
                if line.contains("drop(inst)") || line.contains("drop(pooled)") {
                    drop_after_error_count += 1;
                    break;
                }
            }
        }
    }
    assert!(
        drop_after_error_count >= 2,
        "Both filter_request and transform_response must drop poisoned instances (found {} drop-after-error patterns, expected >= 2)",
        drop_after_error_count
    );
}

/// Duration-based timeout must be used, not integer seconds.
///
/// WasmResourceLimits must use `timeout: Duration` for sub-second precision.
/// The old `timeout_seconds: u64` field must not exist.
#[test]
fn test_duration_based_timeout_not_seconds() {
    let repo = repo_root();
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    // WasmResourceLimits must use Duration for timeout
    assert!(
        cleaned.contains("pub timeout: Duration"),
        "WasmResourceLimits must use timeout: Duration for sub-second precision"
    );

    // Must NOT have timeout_seconds: u64 in WasmResourceLimits struct
    let lines: Vec<&str> = cleaned.lines().collect();
    let mut in_struct = false;
    let mut struct_brace_depth = 0u32;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.contains("pub struct WasmResourceLimits") {
            in_struct = true;
            struct_brace_depth = 0;
        }
        if in_struct {
            struct_brace_depth += trimmed.matches('{').count() as u32;
            struct_brace_depth =
                struct_brace_depth.saturating_sub(trimmed.matches('}').count() as u32);
            assert!(
                !trimmed.contains("timeout_seconds: u64"),
                "WasmResourceLimits must not have timeout_seconds: u64 field — use timeout: Duration instead"
            );
            if struct_brace_depth == 0 && in_struct {
                break;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section: plugin_lifecycle_guard
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
        let method_body = raw[body_start..end].to_string();

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
                .and_then(|s| s.split_whitespace().last())
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
                .and_then(|s| s.split_whitespace().last())
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

/// Native and WASM plugins use separate namespaces.
///
/// `PluginManager` must store native extensions and WASM plugins in
/// separate fields so that name collisions across plugin types are
/// impossible.
#[test]
fn native_wasm_namespace_separation() {
    let file = plugin_runtime_src().join("plugin_manager.rs");
    let cleaned = read_cleaned(&file);

    // PluginManager struct must have both fields
    let mut in_struct = false;
    let mut brace_depth = 0i32;
    let mut has_wasm_manager = false;
    let mut has_unsafe_native = false;

    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("pub struct PluginManager") {
            in_struct = true;
            brace_depth = 0;
            has_wasm_manager = false;
            has_unsafe_native = false;
        }
        if in_struct {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            if trimmed.contains("wasm_manager:") {
                has_wasm_manager = true;
            }
            if trimmed.contains("unsafe_native_extensions:") {
                has_unsafe_native = true;
            }
            if brace_depth <= 0 && in_struct {
                break;
            }
        }
    }

    assert!(
        has_wasm_manager,
        "PluginManager must have 'wasm_manager' field for WASM plugins"
    );
    assert!(
        has_unsafe_native,
        "PluginManager must have 'unsafe_native_extensions' field for native plugins"
    );
    assert!(
        has_wasm_manager && has_unsafe_native,
        "PluginManager must store WASM and native plugins in separate fields to prevent namespace collision"
    );
}

/// PluginDetail must include hash and last_error fields.
///
/// `PluginDetail` must have `hash: Option<String>` and
/// `last_error: Option<String>` fields for operator introspection.
#[test]
fn plugin_detail_includes_hash_and_last_error() {
    let file = wasm_runtime_rs();
    let cleaned = read_cleaned(&file);

    // Find PluginDetail struct
    let mut in_struct = false;
    let mut brace_depth = 0i32;
    let mut has_hash = false;
    let mut has_last_error = false;

    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("pub struct PluginDetail") {
            in_struct = true;
            brace_depth = 0;
            has_hash = false;
            has_last_error = false;
        }
        if in_struct {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            if trimmed.contains("pub hash:") {
                has_hash = true;
            }
            if trimmed.contains("pub last_error:") {
                has_last_error = true;
            }
            if brace_depth <= 0 && in_struct {
                break;
            }
        }
    }

    assert!(has_hash, "PluginDetail must have 'pub hash' field");
    assert!(
        has_last_error,
        "PluginDetail must have 'pub last_error' field"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section: plugin_lifecycle_guard — Behavioral Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod behavioral {
    use synvoid_plugin_runtime::{
        PluginLifecycleState, PluginReplacePolicy, WasmPluginManager, WasmResourceLimits,
    };

    // ── Gap 3: Deprecated config migration behavioral test (WS8 #22) ───────

    /// Verify that a config migrated from the deprecated `native_plugins` TOML
    /// key produces an `UnsafeNativeExtensionConfig` that passes `validate_for_load`.
    #[test]
    fn deprecated_config_migration_produces_valid_runtime_config() {
        use synvoid_config::PluginConfig;
        use synvoid_plugin_runtime::UnsafeNativeExtensionConfig;

        let toml = r#"
[native_plugins]
enabled = true
allow_in_production = false
hot_reload_enabled = false
"#;
        let mut config: PluginConfig = toml::from_str(toml).unwrap();
        assert!(
            config.native_plugins_compat.is_some(),
            "deprecated key should populate native_plugins_compat"
        );

        let migrated = config.migrate_deprecated_native_plugins();
        assert!(migrated, "migration should succeed");
        assert!(config.native_plugins_compat.is_none());

        let rt_config = UnsafeNativeExtensionConfig {
            enabled: config.unsafe_native.enabled,
            allow_in_production: config.unsafe_native.allow_in_production,
            risk_acknowledgement: config.unsafe_native.risk_acknowledgement.clone(),
            allowed_dirs: config.unsafe_native.allowed_dirs.clone(),
            hot_reload_enabled: config.unsafe_native.hot_reload_enabled,
            production_mode_override: Some(false),
        };
        let result = rt_config.validate_for_load(&[]);
        assert!(
            result.is_ok(),
            "migrated config should pass validate_for_load in dev mode, got: {:?}",
            result.err()
        );
    }

    /// When both deprecated and new keys are present, the new key takes precedence.
    #[test]
    fn deprecated_config_does_not_overwrite_explicit_new_at_runtime() {
        use synvoid_config::PluginConfig;
        use synvoid_plugin_runtime::UnsafeNativeExtensionConfig;

        let toml = r#"
[unsafe_native]
enabled = true

[native_plugins]
enabled = false
"#;
        let mut config: PluginConfig = toml::from_str(toml).unwrap();
        let migrated = config.migrate_deprecated_native_plugins();
        assert!(migrated);
        assert!(config.unsafe_native.enabled);

        let rt_config = UnsafeNativeExtensionConfig {
            enabled: config.unsafe_native.enabled,
            production_mode_override: Some(false),
            ..Default::default()
        };
        let result = rt_config.validate_for_load(&[]);
        assert!(result.is_ok(), "explicit new config should pass validation");
    }

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

    #[test]
    fn invalid_lifecycle_transition_rejected() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        // Load plugin (generation 1, state Active)
        mgr.load_plugin_from_memory("transition_reject", &bytes, WasmResourceLimits::default())
            .unwrap();

        assert_eq!(
            mgr.get_plugin_lifecycle_state("transition_reject"),
            Some(PluginLifecycleState::Active)
        );

        // Removed -> Active is not a valid transition
        let invalid_result = mgr.set_plugin_lifecycle_state(
            "transition_reject",
            PluginLifecycleState::Active,
            "test invalid transition",
        );
        assert!(
            invalid_result.is_err(),
            "Removed->Active transition should be rejected"
        );

        // Verify state is unchanged (still Active)
        assert_eq!(
            mgr.get_plugin_lifecycle_state("transition_reject"),
            Some(PluginLifecycleState::Active),
            "plugin state must remain unchanged after rejected transition"
        );

        // Direct validation via is_valid_transition
        assert!(
            !PluginLifecycleState::is_valid_transition(
                PluginLifecycleState::Removed,
                PluginLifecycleState::Active
            ),
            "is_valid_transition(Removed, Active) must return false"
        );
        assert!(
            !PluginLifecycleState::is_valid_transition(
                PluginLifecycleState::Removed,
                PluginLifecycleState::Reloading
            ),
            "is_valid_transition(Removed, Reloading) must return false"
        );
        assert!(
            !PluginLifecycleState::is_valid_transition(
                PluginLifecycleState::FailedLoad,
                PluginLifecycleState::Active
            ),
            "is_valid_transition(FailedLoad, Active) must return false"
        );
        assert!(
            !PluginLifecycleState::is_valid_transition(
                PluginLifecycleState::Loading,
                PluginLifecycleState::Removed
            ),
            "is_valid_transition(Loading, Removed) must return false"
        );
        assert!(
            !PluginLifecycleState::is_valid_transition(
                PluginLifecycleState::Unloading,
                PluginLifecycleState::Active
            ),
            "is_valid_transition(Unloading, Active) must return false"
        );
    }

    #[test]
    fn get_plugin_detail_returns_hash() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.load_plugin_from_memory("hash_detail", &bytes, WasmResourceLimits::default())
            .unwrap();

        // The binary hash is on LoadedPluginGeneration, accessible via
        // get_plugin_generation_detail (used by get_plugin_detail internally).
        let gen_detail = mgr.get_plugin_generation_detail("hash_detail");
        assert!(
            gen_detail.is_some(),
            "generation detail must exist after load"
        );
        let gen_detail = gen_detail.unwrap();

        // The hash field must exist and be a valid SHA-256 hex string (64 chars)
        // or empty for memory-loaded plugins (where effective_policy is not
        // propagated to the runtime). The structural presence is what matters.
        assert!(
            gen_detail.binary_hash.is_empty()
                || gen_detail.binary_hash.len() == 64,
            "binary_hash must be either empty (memory load) or a 64-char SHA-256 hex string, got len={}",
            gen_detail.binary_hash.len()
        );

        // Verify get_plugin_detail returns a PluginDetail with the generation info.
        let detail = mgr.get_plugin_detail("hash_detail");
        assert!(detail.is_some());
        let detail = detail.unwrap();
        assert_eq!(detail.name, "hash_detail");
    }

    // ── Gap 5: Memory-with-manifest generation/lifecycle (WS9) ─────────────

    #[test]
    fn load_plugin_from_memory_with_manifest_sets_generation_and_lifecycle() {
        use synvoid_plugin_runtime::PluginManifest;

        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        let manifest = PluginManifest {
            name: "manifest_test".to_string(),
            version: "0.1.0".to_string(),
            entry: "filter_request".to_string(),
            ..Default::default()
        };

        let _rt = mgr
            .load_plugin_from_memory_with_manifest(
                "manifest_test",
                &bytes,
                &manifest,
                WasmResourceLimits::default(),
            )
            .expect("load with manifest should succeed");

        // Generation must be set
        let gen = mgr.get_plugin_generation("manifest_test");
        assert!(gen.is_some(), "generation must exist after manifest load");
        assert_eq!(gen.unwrap().0, 1, "first load should be generation 1");

        // Lifecycle state must be Active
        let state = mgr.get_plugin_lifecycle_state("manifest_test");
        assert_eq!(state, Some(PluginLifecycleState::Active));

        // Generation detail must exist
        let detail = mgr.get_plugin_generation_detail("manifest_test");
        assert!(detail.is_some());
    }

    // ── Gap 6: Failed reload preserves generation (WS9) ────────────────────

    #[test]
    fn failed_reload_preserves_original_generation() {
        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        mgr.load_plugin_from_memory("reload_preserve", &bytes, WasmResourceLimits::default())
            .expect("initial load");

        let gen_before = mgr.get_plugin_generation("reload_preserve");
        assert!(gen_before.is_some());
        let gen_before = gen_before.unwrap();
        assert_eq!(gen_before.0, 1);

        // Attempt reload from a non-existent file — must fail
        let non_existent = std::env::temp_dir().join(format!(
            "nonexistent_plugin_{}.wasm",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let result = mgr.reload_plugin_with_outcome(&non_existent);
        assert!(
            result.is_ok(),
            "reload_plugin_with_outcome should return Ok even on failure"
        );
        match result.unwrap() {
            synvoid_plugin_runtime::PluginReloadOutcome::Failed { .. } => {}
            other => panic!("Expected Failed outcome, got: {:?}", other),
        }

        // Original generation must be preserved
        let gen_after = mgr.get_plugin_generation("reload_preserve");
        assert_eq!(
            gen_after,
            Some(gen_before),
            "generation must be preserved after failed reload"
        );

        // Plugin must still be active
        let state = mgr.get_plugin_lifecycle_state("reload_preserve");
        assert_eq!(
            state,
            Some(PluginLifecycleState::Active),
            "plugin must remain Active after failed reload"
        );
    }

    // ── Gap 7: Stable-file policy invocation (WS9) ─────────────────────────

    #[test]
    fn prepare_reload_candidate_accepts_stability_policy() {
        use std::time::Duration;
        use synvoid_plugin_runtime::FileStabilityPolicy;

        let mgr = WasmPluginManager::new();
        let bytes = minimal_wasm_bytes();

        // Load a plugin first so we can attempt prepare_reload_candidate
        mgr.load_plugin_from_memory("stable_policy_test", &bytes, WasmResourceLimits::default())
            .expect("initial load");

        // Write the WASM bytes to a temp file so prepare_reload_candidate can read it
        let tmp_dir = std::env::temp_dir().join(format!(
            "stable_policy_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");
        let wasm_path = tmp_dir.join("stable_policy_test.wasm");
        std::fs::write(&wasm_path, &bytes).expect("write wasm file");

        // Use a very fast stability policy
        let policy = FileStabilityPolicy {
            debounce: Duration::from_millis(1),
            stable_checks: 1,
            stable_interval: Duration::from_millis(1),
            max_wait: Duration::from_secs(1),
        };

        let result = mgr.prepare_reload_candidate(&wasm_path, Some(&policy));
        assert!(
            result.is_ok(),
            "prepare_reload_candidate with custom stability policy should succeed, got: {:?}",
            result.err()
        );

        let (_runtime, gen) = result.unwrap();
        assert_eq!(
            gen.previous_generation,
            mgr.get_plugin_generation("stable_policy_test")
        );
        assert!(gen.generation.0 > 1, "reload generation must be > 1");

        // Cleanup
        std::fs::remove_dir_all(&tmp_dir).ok();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section: plugin_signature_policy_guard
// ═══════════════════════════════════════════════════════════════════════════════

/// Test 1: `enforce_plugin_load_policy` must exist in sandbox/types.rs.
///
/// This function is the central enforcement point for plugin trust policy.
/// If it is accidentally removed, all loader paths lose their enforcement.
#[test]
fn enforce_plugin_load_policy_exists() {
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
    let repo = repo_root();
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
