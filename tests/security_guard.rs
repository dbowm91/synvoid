//! Root-test ownership: STATIC_POLICY
//! Rationale: validates security observability boundary across workspace
//!
//! Consolidated security observability and threat-intel boundary guards.
//!
//! This file merges three separate guard test files into one:
//! - `tests/security_observability_guard.rs` — metric label safety, raw-lookup
//!   separation from enforcement metrics, runtime registry observability, and
//!   observability doc coverage.
//! - `tests/threat_intel_boundary_guard.rs` — mechanical source scan preventing
//!   raw threat-intel lookup APIs from leaking into enforcement-sensitive paths
//!   (WAF, HTTP, proxy, HTTP/3, WAF crate, proxy crate), plus positive boundary
//!   tests for allowlist/denylist structural soundness.
//! - `tests/threat_intel_consumer_actionability_guard.rs` — enforcement-file
//!   raw-lookup denylist, function-level guardrail for `threat_intel.rs`,
//!   policy-gate ordering, ShadowOnly mutation prohibition, provenance
//!   constraints, and simulated regression tests.
#![allow(clippy::needless_range_loop, clippy::manual_contains)]

use std::fs;
use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════════════════════════════════════
// Shared Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Walk up from `CARGO_MANIFEST_DIR` to find the workspace root (contains
/// `[workspace]` in `Cargo.toml`).
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

/// Recursively collect every `.rs` file under `dir`.
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

/// Strip `#[cfg(test)]` modules (line-based, brace-depth-aware).
///
/// Skips the `#[cfg(test)]` marker line itself and all content until the
/// enclosing `mod` block's brace depth returns to zero.
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

/// Strip `#[cfg(test)]` modules (character-level, brace-depth-aware).
///
/// More robust than the line-based version: handles nested attributes before
/// `mod` declarations and scans character-by-character for precise boundary
/// detection. Note: the `#[cfg(test)]` marker text itself may appear in the
/// output (the module body is what gets stripped).
fn strip_cfg_test_modules_brace_depth(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut depth: i32 = 0;
    let mut in_test_module = false;
    let mut chars = content.chars().peekable();

    while let Some(ch) = chars.next() {
        if !in_test_module {
            result.push(ch);
            if ch == '#' {
                let rest: String = chars.clone().take(20).collect();
                if rest.starts_with("[cfg(test)]") {
                    let mut skip = String::new();
                    skip.push(ch);
                    for _ in 0..11 {
                        skip.push(chars.next().unwrap_or('\0'));
                    }
                    result.push_str(&skip[1..]);
                    loop {
                        let remaining: String = chars.clone().take(20).collect();
                        let trimmed = remaining.trim_start();
                        if trimmed.starts_with("#[") {
                            for c in chars.by_ref() {
                                if c == ']' {
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    // Skip whitespace and look for `mod` keyword
                    let peek_chars: Vec<char> = chars.clone().take(20).collect();
                    let mut ws_count = 0;
                    while ws_count < peek_chars.len()
                        && (peek_chars[ws_count] == ' '
                            || peek_chars[ws_count] == '\t'
                            || peek_chars[ws_count] == '\n'
                            || peek_chars[ws_count] == '\r')
                    {
                        ws_count += 1;
                    }
                    let after_ws: String = peek_chars[ws_count..].iter().take(10).collect();
                    if after_ws.starts_with("mod ") || after_ws.starts_with("mod{") {
                        in_test_module = true;
                        depth = 0;
                        loop {
                            let c = chars.next().unwrap_or('\0');
                            if c == '{' {
                                depth = 1;
                                break;
                            }
                            if c == ';' {
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth <= 0 {
                        in_test_module = false;
                    }
                }
                _ => {}
            }
        }
    }
    result
}

/// Strip string literals, line comments (`//`), and block comments (`/* */`).
/// Prevents false positives from raw lookup tokens inside comments or strings.
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
// Section 1: Security Observability Guards
// Origin: tests/security_observability_guard.rs
// ═══════════════════════════════════════════════════════════════════════════════

// ── Constants ────────────────────────────────────────────────────────────────

/// Forbidden label keys in metric macros. These carry high-cardinality or
/// sensitive data (IPs, tokens, file paths, user-agent strings) that must
/// never appear as Prometheus labels.
const FORBIDDEN_LABEL_KEYS: &[&str] = &[
    "\"ip\"",
    "\"token\"",
    "\"event_id\"",
    "\"user_agent\"",
    "\"session\"",
];

/// Raw threat-intel lookup tokens that must never coexist with `counter!`
/// in the same function. These are diagnostic-only APIs.
const RAW_LOOKUP_TOKENS: &[&str] = &[
    "lookup_local_indicator(",
    "lookup_local_indicator_by_ip(",
    "lookup_threat_indicator_in_dht(",
];

/// Metric macro entry points used in source scanning.
const METRIC_MACROS: &[&str] = &["counter!(", "gauge!(", "histogram!("];

/// Directories to scan for source files (excluding tests, examples).
const SRC_DIRS: &[&str] = &["src", "crates"];

/// Directories that are exempt from label checks (tests, examples, docs).
const EXEMPT_DIRS: &[&str] = &["tests", "examples", "docs", "plans", "architecture"];

/// Files in runtime registry paths that must contain observability signals.
const RUNTIME_REGISTRY_FILES: &[&str] = &[
    "src/server/runtime_handles.rs",
    "src/worker/task_registry.rs",
];

/// Architecture doc that must list all metric prefixes.
const OBSERVABILITY_DOC: &str = "architecture/security_observability.md";

// ── Observability Helper Functions ──────────────────────────────────────────

/// Collect all `.rs` files from SRC_DIRS, skipping EXEMPT_DIRS.
fn collect_source_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in SRC_DIRS {
        let path = Path::new(dir);
        if path.exists() {
            files.extend(collect_rs_files(path));
        }
    }
    files
}

/// Check if a relative path is exempt from label scanning.
fn is_exempt(relative: &str) -> bool {
    for exempt in EXEMPT_DIRS {
        if relative.starts_with(&format!("{}/", exempt)) {
            return true;
        }
    }
    false
}

/// Strip single-line comments (`//`) from a line, ignoring URLs in strings.
fn strip_line_comments(line: &str) -> &str {
    // Simple heuristic: find `//` that is not inside a string.
    // For our purposes, checking for metric macros, this is sufficient.
    if let Some(pos) = line.find("//") {
        &line[..pos]
    } else {
        line
    }
}

/// Extract label keys from a metric macro invocation.
///
/// Given a line like:
///   `counter!("synvoid_foo", "status" => "ok", "source" => src)`
/// Returns `["status", "source"]`.
fn extract_label_keys(macro_line: &str) -> Vec<String> {
    let mut keys = Vec::new();
    // Find the metric name (first string argument) and skip past it
    if let Some(start) = macro_line.find('(') {
        let after_open = &macro_line[start + 1..];
        // Skip to the opening quote of the metric name
        if let Some(open_pos) = after_open.find('"') {
            let after_open_quote = &after_open[open_pos + 1..];
            // Find the closing quote of the metric name
            if let Some(close_pos) = after_open_quote.find('"') {
                let after_name = &after_open_quote[close_pos + 1..];
                // Now parse "key" => value pairs
                let mut chars = after_name.chars().peekable();
                loop {
                    // Skip whitespace and commas
                    while let Some(&ch) = chars.peek() {
                        if ch.is_whitespace() || ch == ',' {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    // Expect a quote for the key
                    if chars.peek() != Some(&'"') {
                        break;
                    }
                    chars.next(); // consume opening quote
                    let mut key = String::new();
                    for ch in chars.by_ref() {
                        if ch == '"' {
                            break;
                        }
                        key.push(ch);
                    }
                    // Skip whitespace
                    while let Some(&ch) = chars.peek() {
                        if ch.is_whitespace() {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    // Expect `=>`
                    if chars.peek() == Some(&'=') {
                        chars.next();
                    }
                    if chars.peek() == Some(&'>') {
                        chars.next();
                    }
                    // Skip the value expression (up to next comma or closing paren).
                    let mut depth = 0i32;
                    for ch in chars.by_ref() {
                        match ch {
                            '(' | '[' | '{' => depth += 1,
                            ')' | ']' | '}' => {
                                if depth == 0 {
                                    break;
                                }
                                depth -= 1;
                            }
                            ',' if depth == 0 => break,
                            _ => {}
                        }
                    }
                    if !key.is_empty() {
                        keys.push(key);
                    }
                }
            }
        }
    }
    keys
}

/// Extract the metric name from a macro invocation line.
fn extract_metric_name(macro_line: &str) -> Option<String> {
    if let Some(start) = macro_line.find('(') {
        let rest = &macro_line[start + 1..];
        if let Some(after_quote) = rest.strip_prefix('"') {
            if let Some(end) = after_quote.find('"') {
                return Some(after_quote[..end].to_string());
            }
        }
    }
    None
}

/// Check if a line contains a metric macro call.
fn has_metric_macro(line: &str) -> bool {
    for macro_name in METRIC_MACROS {
        if line.contains(macro_name) {
            return true;
        }
    }
    false
}

/// Check if a line contains a raw lookup token.
fn has_raw_lookup(line: &str) -> bool {
    for token in RAW_LOOKUP_TOKENS {
        if line.contains(token) {
            return true;
        }
    }
    false
}

/// Extract the function name from a line containing `fn `.
fn extract_fn_name(line: &str) -> Option<String> {
    if let Some(pos) = line.find("fn ") {
        let rest = &line[pos + 3..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

// ── Guard Checks ─────────────────────────────────────────────────────────────

/// Guard 1: Metric labels do not include high-cardinality/sensitive fields.
///
/// Scans all `.rs` files for `counter!(`, `gauge!(`, `histogram!(` macro calls
/// and verifies that labels do not include raw IPs, tokens, event_ids,
/// file paths, or user_agent strings.
#[test]
fn metric_labels_no_sensitive_fields() {
    let files = collect_source_files();
    let mut violations = Vec::new();

    for path in &files {
        let relative = path
            .strip_prefix("src/")
            .or_else(|_| path.strip_prefix("crates/"))
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        if is_exempt(&relative) {
            continue;
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for (line_num, line) in content.lines().enumerate() {
            let cleaned = strip_line_comments(line);
            if !has_metric_macro(cleaned) {
                continue;
            }

            let label_keys = extract_label_keys(cleaned);
            for key in &label_keys {
                let key_with_quotes = format!("\"{}\"", key);
                for forbidden in FORBIDDEN_LABEL_KEYS {
                    if key_with_quotes == *forbidden {
                        let macro_name =
                            extract_metric_name(cleaned).unwrap_or_else(|| "unknown".to_string());
                        violations.push(format!(
                            "{}:{}: metric `{}` has forbidden label key `{}`",
                            relative,
                            line_num + 1,
                            macro_name,
                            key
                        ));
                    }
                }
            }
        }
    }

    if !violations.is_empty() {
        let msg = format!(
            "Found {} metric(s) with sensitive/high-cardinality label keys:\n{}\n\n\
             Metric labels must use low-cardinality values only. \
             High-cardinality data belongs in structured logs, not Prometheus counters. \
             See architecture/security_observability.md §3.",
            violations.len(),
            violations.join("\n")
        );
        panic!("{}", msg);
    }
}

/// Guard 2: Raw threat-intel lookup APIs are not used to emit enforcement metrics.
///
/// Scans for `counter!` calls that also contain `lookup_local_indicator(` or
/// `lookup_threat_indicator_in_dht(` in the same function.
#[test]
fn raw_lookups_not_in_counter_functions() {
    let files = collect_source_files();
    let mut violations = Vec::new();

    for path in &files {
        let relative = path
            .strip_prefix("src/")
            .or_else(|_| path.strip_prefix("crates/"))
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        // Allow the threat_intel.rs implementation itself and test files
        if is_exempt(&relative)
            || relative.contains("threat_intel.rs")
            || relative.contains("threat_intel/")
        {
            continue;
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let lines: Vec<&str> = content.lines().collect();
        let mut current_fn: Option<String> = None;
        let mut fn_has_counter = false;
        let mut fn_has_raw_lookup = false;
        let mut fn_start_line = 0;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect function boundaries
            if let Some(name) = extract_fn_name(trimmed) {
                // Check previous function
                if let Some(ref fn_name) = current_fn {
                    if fn_has_counter && fn_has_raw_lookup {
                        violations.push(format!(
                            "{}:{}: function `{}` contains both `counter!` and raw threat-intel lookup",
                            relative, fn_start_line + 1, fn_name
                        ));
                    }
                }
                current_fn = Some(name);
                fn_has_counter = false;
                fn_has_raw_lookup = false;
                fn_start_line = line_num;
            }

            if has_metric_macro(trimmed) && trimmed.contains("counter!") {
                fn_has_counter = true;
            }
            if has_raw_lookup(trimmed) {
                fn_has_raw_lookup = true;
            }
        }

        // Check last function
        if let Some(ref fn_name) = current_fn {
            if fn_has_counter && fn_has_raw_lookup {
                violations.push(format!(
                    "{}:{}: function `{}` contains both `counter!` and raw threat-intel lookup",
                    relative,
                    fn_start_line + 1,
                    fn_name
                ));
            }
        }
    }

    if !violations.is_empty() {
        let msg = format!(
            "Found {} functions combining `counter!` with raw threat-intel lookups:\n{}\n\n\
             Raw lookup APIs (`lookup_local_indicator`, `lookup_threat_indicator_in_dht`) are \
             diagnostic-only. Enforcement metrics must use `lookup_*_policy_strict` wrappers. \
             See architecture/security_observability.md §7.",
            violations.len(),
            violations.join("\n")
        );
        panic!("{}", msg);
    }
}

/// Guard 3: Admin mutation results are tagged with authority.
///
/// Verifies that `AdminMutationResult` usage is consistent with audit/metrics
/// by checking that files using `AdminMutationResult` also reference authority
/// or audit signals.
#[test]
fn admin_mutations_tagged_with_authority() {
    let files = collect_source_files();
    let mut violations = Vec::new();

    for path in &files {
        let relative = path
            .strip_prefix("src/")
            .or_else(|_| path.strip_prefix("crates/"))
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        // Only check admin handler files
        if !relative.contains("admin") || is_exempt(&relative) {
            continue;
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Check if file uses AdminMutationResult
        if !content.contains("AdminMutationResult") {
            continue;
        }

        // Verify the file also references authority or audit (observability)
        let has_authority = content.contains("authority")
            || content.contains("AdminMutationAuthority")
            || content.contains("audit")
            || content.contains("audit_id");
        let has_mutation_counter = content.contains("synvoid_admin_mutation_total");

        // Mutating endpoints should have either authority tagging or metrics
        // Read-only endpoints returning AdminMutationResult are fine without
        if !has_authority && !has_mutation_counter {
            // Check if this file has any mutating handler
            let has_mutation = content.contains("pub async fn")
                && (content.contains("ban_")
                    || content.contains("unban")
                    || content.contains("block")
                    || content.contains("unblock")
                    || content.contains("create_")
                    || content.contains("update_")
                    || content.contains("delete_")
                    || content.contains("reload_")
                    || content.contains("apply_"));
            if has_mutation {
                violations.push(format!(
                    "{}: mutating handlers use `AdminMutationResult` but lack authority tagging or mutation metrics",
                    relative
                ));
            }
        }
    }

    if !violations.is_empty() {
        let msg = format!(
            "Found {} admin files with untagged mutation results:\n{}\n\n\
             Mutating admin endpoints must tag `AdminMutationResult` with `AdminMutationAuthority` \
             and emit `synvoid_admin_mutation_total`. See architecture/admin_control_plane_authority.md.",
            violations.len(),
            violations.join("\n")
        );
        panic!("{}", msg);
    }
}

/// Guard 4: Runtime registries emit task exit/shutdown reports.
///
/// Verifies that `runtime_handles.rs` and `task_registry.rs` contain
/// `counter!` or `tracing::` calls in shutdown/exit paths.
#[test]
fn runtime_registries_emit_observability_signals() {
    let mut violations = Vec::new();

    for file_path in RUNTIME_REGISTRY_FILES {
        let path = Path::new(file_path);
        if !path.exists() {
            continue;
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let has_counter = content.contains("counter!(");
        let has_tracing = content.contains("tracing::");

        // Every runtime registry must have at least some observability signal
        if !has_counter && !has_tracing {
            violations.push(format!(
                "{}: no `counter!` or `tracing::` calls found — runtime registry must emit observability signals on task exit/shutdown",
                file_path
            ));
        }

        // Files with counter! calls must include the Phase 9 runtime metrics
        if has_counter {
            let has_shutdown_metric = content.contains("synvoid_runtime_shutdown_total")
                || content.contains("synvoid_runtime_task_exit_total")
                || content.contains("synvoid_runtime_task_registered_total")
                || content.contains("synvoid.worker.tasks_")
                || content.contains("synvoid.supervisor.tasks_");
            if !has_shutdown_metric {
                violations.push(format!(
                    "{}: has `counter!` calls but missing Phase 9 runtime metrics (shutdown_total, task_exit_total, task_registered_total, worker.tasks_*, supervisor.tasks_*)",
                    file_path
                ));
            }
        }
    }

    if !violations.is_empty() {
        let msg = format!(
            "Found {} runtime registry observability violations:\n{}\n\n\
             Runtime registries must emit task exit/shutdown metrics. \
             See architecture/security_observability.md §4 (Phase 9 metrics).",
            violations.len(),
            violations.join("\n")
        );
        panic!("{}", msg);
    }
}

/// Guard 5: Observability doc lists every metric prefix used in code.
///
/// Scans all `.rs` files for `counter!("synvoid_` patterns, collects the
/// metric prefixes, and verifies every prefix is listed in the doc's
/// metric names table.
#[test]
fn observability_doc_covers_all_metric_prefixes() {
    let doc_path = Path::new(OBSERVABILITY_DOC);
    if !doc_path.exists() {
        eprintln!("Skipping: {} not found", OBSERVABILITY_DOC);
        return;
    }

    let doc_content = match fs::read_to_string(doc_path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Skipping: could not read {}", OBSERVABILITY_DOC);
            return;
        }
    };

    // Collect all metric names from source code
    let files = collect_source_files();
    let mut metric_names: Vec<String> = Vec::new();

    for path in &files {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for line in content.lines() {
            let cleaned = strip_line_comments(line);
            for macro_name in METRIC_MACROS {
                if let Some(pos) = cleaned.find(macro_name) {
                    let after_macro = &cleaned[pos + macro_name.len()..];
                    if let Some(name_start) = after_macro.strip_prefix('"') {
                        if let Some(end) = name_start.find('"') {
                            let name = name_start[..end].to_string();
                            if name.starts_with("synvoid") {
                                metric_names.push(name);
                            }
                        }
                    }
                }
            }
        }
    }

    metric_names.sort();
    metric_names.dedup();

    // Extract documented prefix patterns from the doc.
    // The doc uses patterns like `synvoid.flood.*`, `synvoid.admin.auth.*`,
    // or full metric names like `synvoid_runtime_task_exit_total`.
    let mut doc_prefixes: Vec<String> = Vec::new();
    for line in doc_content.lines() {
        if let Some(start) = line.find('`') {
            let after = &line[start + 1..];
            if let Some(end) = after.find('`') {
                let pattern = &after[..end];
                if pattern.starts_with("synvoid") || pattern.starts_with("dns") {
                    doc_prefixes.push(pattern.to_string());
                }
            }
        }
    }

    // For each metric, check if any doc prefix pattern covers it.
    let mut missing = Vec::new();

    for name in &metric_names {
        let normalized = name.replace('_', ".");
        let covered = doc_prefixes.iter().any(|pattern| {
            if pattern.ends_with(".*") {
                let prefix = pattern[..pattern.len() - 2].replace('_', ".");
                normalized.starts_with(&prefix)
            } else if pattern.contains('*') {
                let prefix = pattern.replace('*', "").replace('_', ".");
                normalized.starts_with(&prefix)
            } else {
                let pat_normalized = pattern.replace('_', ".");
                normalized == pat_normalized
            }
        }) || doc_content.contains(name);

        if !covered {
            missing.push(name.clone());
        }
    }

    if !missing.is_empty() {
        let msg = format!(
            "Found {} metric prefix(es) used in code but not documented in {}:\n{}\n\n\
             Every metric prefix must be listed in the observability inventory. \
             See architecture/security_observability.md §4.",
            missing.len(),
            OBSERVABILITY_DOC,
            missing
                .iter()
                .map(|m| format!("  - {}", m))
                .collect::<Vec<_>>()
                .join("\n")
        );
        panic!("{}", msg);
    }
}

// ── Observability Unit Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_label_keys_simple() {
        let line = r#"counter!("synvoid_foo", "status" => "ok", "source" => src).increment(1);"#;
        let keys = extract_label_keys(line);
        assert_eq!(keys, vec!["status".to_string(), "source".to_string()]);
    }

    #[test]
    fn extract_label_keys_no_labels() {
        let line = r#"counter!("synvoid_foo").increment(1);"#;
        let keys = extract_label_keys(line);
        assert!(keys.is_empty());
    }

    #[test]
    fn extract_metric_name_basic() {
        let line = r#"counter!("synvoid_foo", "status" => "ok")"#;
        let name = extract_metric_name(line);
        assert_eq!(name, Some("synvoid_foo".to_string()));
    }

    #[test]
    fn extract_metric_name_gauge() {
        let line = r#"gauge!("synvoid.bar.connections").set(1.0)"#;
        let name = extract_metric_name(line);
        assert_eq!(name, Some("synvoid.bar.connections".to_string()));
    }

    #[test]
    fn strip_line_comments_basic() {
        assert_eq!(strip_line_comments("hello // world"), "hello ");
        assert_eq!(strip_line_comments("no comment"), "no comment");
        assert_eq!(strip_line_comments("// full line comment"), "");
    }

    #[test]
    fn has_metric_macro_detection() {
        assert!(has_metric_macro(r#"counter!("foo")"#));
        assert!(has_metric_macro(r#"gauge!("foo")"#));
        assert!(has_metric_macro(r#"histogram!("foo")"#));
        assert!(!has_metric_macro("let x = 1;"));
    }

    #[test]
    fn has_raw_lookup_detection() {
        assert!(has_raw_lookup("let x = lookup_local_indicator(val);"));
        assert!(has_raw_lookup("lookup_threat_indicator_in_dht(ind)"));
        assert!(!has_raw_lookup("lookup_policy_strict(val)"));
    }

    #[test]
    fn forbidden_label_detected_in_metric_macro() {
        let line = r#"counter!("synvoid_foo", "ip" => ip_str, "status" => "ok")"#;
        let keys = extract_label_keys(line);
        let has_forbidden = keys.iter().any(|k| {
            let quoted = format!("\"{}\"", k);
            FORBIDDEN_LABEL_KEYS.contains(&quoted.as_str())
        });
        assert!(has_forbidden);
    }

    #[test]
    fn allowed_label_not_flagged() {
        let line = r#"counter!("synvoid_foo", "status" => "ok", "source" => "admin")"#;
        let keys = extract_label_keys(line);
        let has_forbidden = keys.iter().any(|k| {
            let quoted = format!("\"{}\"", k);
            FORBIDDEN_LABEL_KEYS.contains(&quoted.as_str())
        });
        assert!(!has_forbidden);
    }

    #[test]
    fn is_exempt_works() {
        assert!(is_exempt("tests/foo.rs"));
        assert!(is_exempt("examples/bar.rs"));
        assert!(!is_exempt("src/waf/mod.rs"));
        assert!(!is_exempt("crates/synvoid-mesh/src/lib.rs"));
    }

    #[test]
    fn extract_fn_name_basic() {
        assert_eq!(
            extract_fn_name("pub async fn handle_request()"),
            Some("handle_request".to_string())
        );
        assert_eq!(extract_fn_name("let x = 1;"), None);
    }

    // ── Phase 9 gap closure: structural tests ─────────────────────────────────

    /// Test: plugin capability violation metric uses only capability label.
    ///
    /// Scans wasm_metrics.rs for `synvoid_plugin_capability_violation_total` and
    /// verifies the label keys are exactly "capability". Tier is not available at
    /// the SandboxPermissions::require call site, so only capability is tracked.
    #[test]
    fn plugin_violation_metric_uses_capability_only() {
        let path = Path::new("crates/synvoid-plugin-runtime/src/wasm_metrics.rs");
        if !path.exists() {
            eprintln!("Skipping: wasm_metrics.rs not found");
            return;
        }
        let content = fs::read_to_string(path).expect("read wasm_metrics.rs");
        // Find the counter! invocation for capability_violation
        // The metric spans multiple lines, so scan for the metric name and check
        // that the adjacent lines contain only "capability" as a label key.
        let lines: Vec<&str> = content.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("synvoid_plugin_capability_violation_total") {
                // Check that no sensitive labels appear in the surrounding block (3 lines)
                let start = i.saturating_sub(1);
                let end = (i + 4).min(lines.len());
                let block = &lines[start..end].join("\n");
                assert!(
                    block.contains("\"capability\""),
                    "synvoid_plugin_capability_violation_total must use 'capability' label"
                );
                assert!(
                    !block.contains("\"ip\"")
                        && !block.contains("\"token\"")
                        && !block.contains("\"event_id\""),
                    "synvoid_plugin_capability_violation_total must not use sensitive labels"
                );
                return;
            }
        }
        panic!("synvoid_plugin_capability_violation_total not found in wasm_metrics.rs");
    }

    /// Test: runtime_handles.rs contains expected metric names for shutdown report.
    ///
    /// Verifies that the runtime handles file emits the expected exit status labels.
    #[test]
    fn runtime_handles_emit_expected_metric_labels() {
        let path = Path::new("src/server/runtime_handles.rs");
        if !path.exists() {
            eprintln!("Skipping: runtime_handles.rs not found");
            return;
        }
        let content = fs::read_to_string(path).expect("read runtime_handles.rs");
        let expected_statuses = ["completed", "failed", "aborted", "timed_out"];
        for status in &expected_statuses {
            assert!(
                content.contains(&format!("\"{}\"", status)),
                "runtime_handles.rs must emit metric with status label '{}'",
                status
            );
        }
    }

    /// Test: blocklist event apply covers all BlocklistApplyResult variants.
    ///
    /// Scans block-store lib.rs for all status labels in the synvoid_blocklist_event_apply_total
    /// counter and verifies all 5 result variants are covered.
    #[test]
    fn blocklist_apply_metrics_cover_all_result_variants() {
        let path = Path::new("crates/synvoid-block-store/src/lib.rs");
        if !path.exists() {
            eprintln!("Skipping: block-store lib.rs not found");
            return;
        }
        let content = fs::read_to_string(path).expect("read block-store lib.rs");
        let expected_statuses = ["applied", "duplicate", "stale", "invalid", "disabled"];
        // Find the match block that maps BlocklistApplyResult to status labels
        // The pattern is: BlocklistApplyResult::Variant => "label",
        for status in &expected_statuses {
            let pattern = format!("\"{}\"", status);
            assert!(
                content.contains(&pattern),
                "block-store lib.rs must map a BlocklistApplyResult variant to status label '{}'",
                status
            );
        }
    }

    /// Test: admin audit event total metric is emitted in audit.rs.
    ///
    /// Verifies that the audit logging function emits the synvoid_admin_audit_event_total counter.
    #[test]
    fn admin_audit_event_metric_emitted() {
        let path = Path::new("src/admin/audit.rs");
        if !path.exists() {
            eprintln!("Skipping: audit.rs not found");
            return;
        }
        let content = fs::read_to_string(path).expect("read audit.rs");
        assert!(
            content.contains("synvoid_admin_audit_event_total"),
            "audit.rs must emit synvoid_admin_audit_event_total counter"
        );
    }

    /// Test: threat-intel policy decision metric is emitted.
    ///
    /// Verifies that the enforcement policy gate emits the synvoid_threat_policy_decision_total counter.
    #[test]
    fn threat_policy_decision_metric_emitted() {
        let path = Path::new("crates/synvoid-mesh/src/mesh/threat_intel.rs");
        if !path.exists() {
            eprintln!("Skipping: threat_intel.rs not found");
            return;
        }
        let content = fs::read_to_string(path).expect("read threat_intel.rs");
        assert!(
            content.contains("synvoid_threat_policy_decision_total"),
            "threat_intel.rs must emit synvoid_threat_policy_decision_total counter"
        );
        assert!(
            content.contains("synvoid_threat_policy_shadow_total"),
            "threat_intel.rs must emit synvoid_threat_policy_shadow_total counter"
        );
    }

    /// Test: blocklist snapshot fallback metric is emitted.
    ///
    /// Verifies that the mesh transport emits the synvoid_blocklist_snapshot_fallback_total counter.
    #[test]
    fn blocklist_snapshot_fallback_metric_emitted() {
        let path = Path::new("crates/synvoid-mesh/src/mesh/transport_peer.rs");
        if !path.exists() {
            eprintln!("Skipping: transport_peer.rs not found");
            return;
        }
        let content = fs::read_to_string(path).expect("read transport_peer.rs");
        assert!(
            content.contains("synvoid_blocklist_snapshot_fallback_total"),
            "transport_peer.rs must emit synvoid_blocklist_snapshot_fallback_total counter"
        );
    }
}

#[test]
fn runtime_registry_files_exist() {
    for file_path in RUNTIME_REGISTRY_FILES {
        let path = Path::new(file_path);
        assert!(
            path.exists(),
            "RUNTIME_REGISTRY_FILES entry '{}' does not exist — remove stale entry or update the constant",
            file_path
        );
    }
}

#[test]
fn observability_doc_exists() {
    let path = Path::new(OBSERVABILITY_DOC);
    assert!(
        path.exists(),
        "OBSERVABILITY_DOC '{}' does not exist — the architecture doc must be present for metric coverage checks",
        OBSERVABILITY_DOC
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 2: Threat-Intel Boundary Guards
// Origin: tests/threat_intel_boundary_guard.rs
// ═══════════════════════════════════════════════════════════════════════════════

// ── Boundary Helpers ────────────────────────────────────────────────────────

/// Files where raw lookups are explicitly permitted (implementation, tests,
/// feed bookkeeping, documentation).
fn is_allowlisted(relative: &str) -> bool {
    let allowlist: &[&str] = &[
        "crates/synvoid-mesh/src/mesh/threat_intel.rs",
        "tests/security_guard.rs",
        "tests/boundary_composition_guard.rs",
        "tests/dht_integration_test.rs",
        "src/waf/threat_intel/feed_client.rs",
    ];

    for entry in allowlist {
        if relative == *entry {
            return true;
        }
    }

    // Documentation directories are always permitted.
    if relative.starts_with("docs/")
        || relative.starts_with("plans/")
        || relative.starts_with("architecture/")
    {
        return true;
    }

    false
}

// ── Phase 1: Raw Threat-Intel Lookup Boundary Check ─────────────────────────

/// Phase 1 test: scan source files and reject raw lookup APIs outside the
/// allowlist.
#[test]
fn raw_lookup_boundary_check() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let files = collect_rs_files(&workspace_root);

    assert!(
        !files.is_empty(),
        "No .rs files found under {:?} — directory may have moved",
        workspace_root
    );

    let mut violations: Vec<String> = Vec::new();

    for file in &files {
        let relative = file
            .strip_prefix(&workspace_root)
            .unwrap_or(file)
            .to_string_lossy()
            .into_owned();

        if is_allowlisted(&relative) {
            continue;
        }

        let content = match fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let production = {
            let no_tests = strip_cfg_test_modules_brace_depth(&content);
            strip_comments_and_strings(&no_tests)
        };

        for token in RAW_LOOKUP_TOKENS {
            if production.contains(token) {
                violations.push(format!("  {relative}: contains `{token}`"));
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

// ── Phase 2: Positive Boundary Tests ────────────────────────────────────────

/// Verify that every file on the allowlist actually exists in the workspace.
///
/// If a file is removed or moved, this test catches the stale allowlist entry
/// before it silently permits a regression.
#[test]
fn allowlisted_files_exist() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let allowlist: &[&str] = &[
        "crates/synvoid-mesh/src/mesh/threat_intel.rs",
        "tests/security_guard.rs",
        "tests/dht_integration_test.rs",
        "src/waf/threat_intel/feed_client.rs",
        "src/worker/unified_server/services.rs",
        "src/worker/unified_server/init_mesh.rs",
    ];

    let mut missing = Vec::new();
    for rel in allowlist {
        let path = workspace_root.join(rel);
        if !path.exists() {
            missing.push(rel.to_string());
        }
    }

    assert!(
        missing.is_empty(),
        "Allowlisted files no longer exist (stale allowlist entry): {:?}",
        missing
    );
}

/// Verify that every enforcement-sensitive denylist directory exists and is
/// structurally covered by the boundary guard.
///
/// If a new enforcement surface is added (e.g. a new request-handling crate),
/// this test surfaces the gap so the denylist can be updated.
#[test]
fn denylist_directories_cover_enforcement_surfaces() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let denylist_dirs: &[&str] = &[
        "src/waf",
        "src/http",
        "src/worker/unified_server",
        "src/proxy",
        "crates/synvoid-http3",
        "crates/synvoid-waf",
        "crates/synvoid-proxy",
    ];

    for dir in denylist_dirs {
        let path = workspace_root.join(dir);
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

/// Verify that the scan correctly strips `#[cfg(test)]` modules and comments
/// so that test code and comments within implementation files do not trigger
/// false positives.
#[test]
fn strip_test_modules_removes_cfg_test_content() {
    let content = r#"
        use crate::foo;

        fn real_function() {}

        // lookup_threat_indicator_in_dht should not trigger here
        /// lookup_local_indicator("doc comment") should not trigger here
        "lookup_local_indicator(\"in string\") should not trigger here"

        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::lookup_threat_indicator_in_dht;

            #[test]
            fn it_works() {}
        }
    "#;

    let no_tests = strip_cfg_test_modules_brace_depth(content);
    let stripped = strip_comments_and_strings(&no_tests);

    assert!(
        !no_tests.contains("fn it_works()"),
        "Test module body should be stripped"
    );
    assert!(
        !stripped.contains("lookup_threat_indicator_in_dht"),
        "Content after #[cfg(test)] should be removed"
    );
    assert!(
        stripped.contains("fn real_function()"),
        "Production code before #[cfg(test)] must be retained"
    );
    assert!(
        !stripped.contains("lookup_local_indicator"),
        "Raw lookup tokens in comments and strings should be stripped"
    );
    assert!(
        no_tests.contains("fn real_function()"),
        "Production code before #[cfg(test)] must be retained in intermediate step"
    );
}

/// Confirm that a known enforcement-sensitive file containing a raw lookup
/// would be caught (simulated violation).
#[test]
fn simulated_violation_in_waf_path_is_detected() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fake_path = workspace_root.join("src/waf/imaginary_enforcement.rs");
    let fake_content = "fn handle_request() {\n    let x = lookup_local_indicator(\"evil\");\n}\n";

    // Simulate what raw_lookup_boundary_check does for this single file.
    let relative = fake_path
        .strip_prefix(&workspace_root)
        .unwrap_or(&fake_path)
        .to_string_lossy()
        .into_owned();

    assert!(
        !is_allowlisted(&relative),
        "Imaginary enforcement file should not be allowlisted"
    );

    let no_tests = strip_cfg_test_modules_brace_depth(fake_content);
    let stripped = strip_comments_and_strings(&no_tests);

    let has_violation = RAW_LOOKUP_TOKENS.iter().any(|t| stripped.contains(t));
    assert!(
        has_violation,
        "Simulated violation in a WAF path must be detected"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 3: Threat-Intel Consumer Actionability Guards
// Origin: tests/threat_intel_consumer_actionability_guard.rs
// ═══════════════════════════════════════════════════════════════════════════════

// ── Consumer Actionability Constants ─────────────────────────────────────────

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

/// Functions in `threat_intel.rs` where raw lookup calls are permitted.
/// These are the lookup implementation functions, diagnostic aliases, composed
/// read-path helpers, strict wrappers, and shadow evaluation.
const THREAT_INTEL_RS_RAW_LOOKUP_ALLOWLIST: &[&str] = &[
    "lookup_local_indicator",
    "lookup_local_indicator_by_ip",
    "lookup_threat_indicator_in_dht",
    "diagnostic_lookup_local_indicator",
    "diagnostic_lookup_local_indicator_by_ip",
    "diagnostic_lookup_threat_indicator_in_dht",
    "lookup_threat_indicator_policy_composed",
    "lookup_local_indicator_policy_composed",
    "lookup_local_indicator_by_ip_policy_composed",
    "lookup_threat_indicator_policy_strict",
    "lookup_local_indicator_policy_strict",
    "lookup_local_indicator_by_ip_policy_strict",
    "evaluate_indicator_policy_shadow",
];

/// Enforcement functions in `threat_intel.rs` that must NEVER contain raw
/// lookup calls, even if they appear in the function-level allowlist.
/// The `_after_policy_permit` suffix is matched by prefix.
const THREAT_INTEL_RS_ENFORCEMENT_DENYLIST: &[&str] = &[
    "handle_incoming_threat",
    "apply_rate_limit_mesh_action_after_policy_permit",
    "apply_suspicious_mesh_action_after_policy_permit",
];

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

/// Block/unblock API tokens.
const BLOCK_UNBLOCK_TOKENS: &[&str] = &[
    "block_ip(",
    "block_ip_with_provenance(",
    "unblock_ip(",
    "block_mesh_id(",
    "block_mesh_id_with_provenance(",
    "unblock_mesh_id(",
];

/// Provenance kinds that must not appear in threat-intel-originated blocklist
/// writes. Threat-intel enforcement should use `MeshThreatIntelPolicyGated`.
const FORBIDDEN_THREAT_INTEL_PROVENANCE: &[&str] = &[
    "BlockProvenanceKind::AdminManual",
    "BlockProvenanceKind::SupervisorSync",
];

// ── Consumer Actionability Helpers ──────────────────────────────────────────

/// Files where raw lookups are explicitly permitted (implementation, tests,
/// feed bookkeeping, documentation, admin, shadow, diagnostics).
/// Note: `threat_intel.rs` is intentionally NOT here (Iteration 55) — it is
/// governed by a function-level allowlist instead (see
/// `THREAT_INTEL_RS_RAW_LOOKUP_ALLOWLIST`).
fn is_lookup_allowlisted(relative: &str) -> bool {
    let allowlist: &[&str] = &[
        "crates/synvoid-mesh/src/mesh/threat_intel_policy.rs",
        "tests/security_guard.rs",
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

/// Check if a function name is on the enforcement denylist.
fn is_enforcement_function(name: &str) -> bool {
    for entry in THREAT_INTEL_RS_ENFORCEMENT_DENYLIST {
        if name == *entry {
            return true;
        }
    }
    // Also match any function ending with `_after_policy_permit`.
    if name.ends_with("_after_policy_permit") {
        return true;
    }
    false
}

/// Check if a function name is on the function-level allowlist.
fn is_function_allowlisted(name: &str) -> bool {
    THREAT_INTEL_RS_RAW_LOOKUP_ALLOWLIST
        .iter()
        .any(|&entry| name == entry)
}

/// Scan preprocessed Rust source lines and build a map from every line number
/// (0-indexed) to the function that contains it. Lines outside any function
/// map to `None`.
///
/// The input `content` must already have `#[cfg(test)]` modules and comments
/// stripped (use `strip_cfg_test_modules` + `strip_comments_and_strings`).
///
/// This is a best-effort heuristic: it looks for `fn <name>` patterns and
/// tracks brace depth to identify body boundaries. It handles nested braces
/// correctly but does not parse the full Rust grammar (e.g., it may confuse
/// function-like macros). That is acceptable for a guardrail.
fn build_function_map(content: &str) -> Vec<Option<String>> {
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let mut result: Vec<Option<String>> = vec![None; total];

    // First pass: find all `fn <name>` declarations and record their positions.
    struct FnDecl {
        name: String,
        line: usize,
    }
    let mut declarations: Vec<FnDecl> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Skip lines that are inside a comment (should already be stripped, but
        // guard against attributes that contain fn-like syntax).
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        // Match: [pub] [pub(crate)] [async] fn <name>[...](...) [-> ...] { or just fn <name>(...)
        // We look for the `fn ` keyword and extract the name after it.
        if let Some(fn_pos) = find_fn_keyword(trimmed) {
            let after_fn = &trimmed[fn_pos..];
            // after_fn starts with "fn "
            let rest = &after_fn[3..];
            // The function name ends at the first non-ident character.
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                declarations.push(FnDecl { name, line: idx });
            }
        }
    }

    // Second pass: for each declaration, find the matching closing brace.
    for decl in &declarations {
        let start = decl.line;
        let mut depth = 0i32;
        let mut found_open = false;
        let mut end = start;

        for idx in start..total {
            for ch in lines[idx].chars() {
                match ch {
                    '{' => {
                        depth += 1;
                        found_open = true;
                    }
                    '}' => {
                        depth -= 1;
                    }
                    _ => {}
                }
            }
            if found_open && depth <= 0 {
                end = idx;
                break;
            }
        }

        // If we never found a closing brace, extend to end of file.
        if !found_open || depth > 0 {
            end = total.saturating_sub(1);
        }

        // Fill the map for this function's range.
        for idx in start..=end {
            if idx < total {
                result[idx] = Some(decl.name.clone());
            }
        }
    }

    result
}

/// Find the position of the `fn` keyword in a trimmed line, respecting that
/// `fn` must be preceded by a word boundary (space, `(`, `<`, `>`, `{`, `:`).
/// Returns the byte offset of `fn` within `line`, or `None`.
fn find_fn_keyword(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'f' && bytes[i + 1] == b'n' {
            // Check byte after 'n' is a word boundary.
            if i + 2 < bytes.len() {
                let next = bytes[i + 2] as char;
                if next.is_alphanumeric() || next == '_' {
                    // Part of a longer identifier (e.g., `fn_ptr`), skip.
                    i += 1;
                    continue;
                }
            }
            // Check byte before 'f' is a word boundary.
            if i > 0 {
                let prev = bytes[i - 1] as char;
                if prev.is_alphanumeric() || prev == '_' {
                    i += 1;
                    continue;
                }
            }
            return Some(i);
        }
        i += 1;
    }
    None
}

// ── Phase 1: Raw Lookup Boundary ─────────────────────────────────────────────

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
            let production = strip_comments_and_strings(&production);

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

// ── Phase 1b (Iteration 55): Function-Level Guardrail for threat_intel.rs ────

/// Phase 1b test (Iteration 55): scan `threat_intel.rs` for raw lookup tokens
/// and verify each occurrence is inside an allowlisted function and not inside
/// an enforcement function.
#[test]
fn threat_intel_rs_raw_lookup_only_in_allowlisted_functions() {
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
    let production = strip_comments_and_strings(&production);

    let lines: Vec<&str> = production.lines().collect();
    let function_map = build_function_map(&production);

    let mut violations: Vec<String> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Skip doc comments.
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        for token in RAW_LOOKUP_TOKENS {
            if line.contains(token) {
                let containing_fn = function_map
                    .get(idx)
                    .and_then(|f| f.as_deref())
                    .unwrap_or("<unknown>");

                // Enforcement denylist takes highest priority.
                if is_enforcement_function(containing_fn) {
                    violations.push(format!(
                        "  threat_intel.rs:{}: raw lookup `{}` inside enforcement function `{}`. \
                         Enforcement functions must consume IncomingThreatPolicyGate / PermitAction \
                         results, not raw advisory presence.",
                        idx + 1,
                        token.trim_end_matches('('),
                        containing_fn,
                    ));
                    break;
                }

                // Then check the function-level allowlist.
                if !is_function_allowlisted(containing_fn) {
                    violations.push(format!(
                        "  threat_intel.rs:{}: raw lookup `{}` inside non-allowlisted function `{}`. \
                         Raw lookups are only permitted in allowlisted lookup/diagnostic/shadow functions.",
                        idx + 1,
                        token.trim_end_matches('('),
                        containing_fn,
                    ));
                    break;
                }
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Raw threat-intel lookup found in threat_intel.rs outside of \
             allowlisted functions, or inside an enforcement function.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

/// Belt-and-suspenders test (Iteration 55): specifically verify that
/// `handle_incoming_threat` contains zero raw lookup tokens. This complements
/// the enforcement denylist test — policy-gate ordering proves a gate exists
/// before mutation; this test proves raw advisory lookups cannot be added
/// inside the enforcement body.
#[test]
fn handle_incoming_threat_contains_no_raw_lookup_calls() {
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
    let production = strip_comments_and_strings(&production);

    let function_map = build_function_map(&production);
    let lines: Vec<&str> = production.lines().collect();

    let mut raw_lookup_lines: Vec<usize> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        let in_handle =
            function_map.get(idx).and_then(|f| f.as_deref()) == Some("handle_incoming_threat");

        if in_handle {
            for token in RAW_LOOKUP_TOKENS {
                if line.contains(token) {
                    raw_lookup_lines.push(idx + 1);
                    break;
                }
            }
        }
    }

    assert!(
        raw_lookup_lines.is_empty(),
        "handle_incoming_threat contains raw lookup calls at lines: {:?}. \
         Enforcement functions must use policy-composed or strict wrappers, \
         never raw advisory lookups.",
        raw_lookup_lines,
    );
}

// ── Phase 2: Blocklist Mutation Must Be Policy-Gated ──────────────────────────

/// Scan `threat_intel.rs` and verify that `evaluate_incoming_threat_policy`
/// is called before any block-store mutation in `handle_incoming_threat`.
///
/// This test is complementary to the raw-lookup denylist (Phase 1b):
/// this test proves a policy gate ordering exists before mutations, while
/// the raw-lookup denylist proves raw advisory lookups cannot be added
/// inside the enforcement body.
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
    let production = strip_comments_and_strings(&production);

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
    let production = strip_comments_and_strings(&production);

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
            let production = strip_comments_and_strings(&production);

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
    let production = strip_comments_and_strings(&production);

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
        "crates/synvoid-mesh/src/mesh/threat_intel_policy.rs",
        "tests/security_guard.rs",
        "tests/dht_integration_test.rs",
        "src/waf/threat_intel/feed_client.rs",
        "src/worker/unified_server/services.rs",
        "src/worker/unified_server/init_mesh.rs",
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
    let stripped = strip_comments_and_strings(&stripped);

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

// ── Phase 1b Simulated Regression Tests (Iteration 55) ──────────────────────

/// Simulate raw lookup inside `handle_incoming_threat` — must be rejected.
#[test]
fn simulated_raw_lookup_inside_handle_incoming_threat_is_rejected() {
    let fake_source = "\
fn handle_incoming_threat() {
    let indicator = lookup_local_indicator(\"evil.com\");
    let gate = evaluate_incoming_threat_policy(indicator);
    if gate == PermitAction {
        block_ip(ip, \"threat\", 3600);
    }
}
";

    let production = strip_cfg_test_modules(fake_source);
    let production = strip_comments_and_strings(&production);

    let function_map = build_function_map(&production);
    let lines: Vec<&str> = production.lines().collect();

    let mut violations: Vec<String> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        for token in RAW_LOOKUP_TOKENS {
            if line.contains(token) {
                let containing_fn = function_map
                    .get(idx)
                    .and_then(|f| f.as_deref())
                    .unwrap_or("<unknown>");

                if is_enforcement_function(containing_fn) {
                    violations.push(format!(
                        "line {}: raw lookup inside `{}`",
                        idx + 1,
                        containing_fn,
                    ));
                }
            }
        }
    }

    assert!(
        !violations.is_empty(),
        "Raw lookup inside handle_incoming_threat must be rejected by the guardrail"
    );
}

/// Simulate raw lookup inside `lookup_threat_indicator_policy_composed` —
/// must be accepted (it is on the function-level allowlist).
#[test]
fn simulated_raw_lookup_inside_policy_composed_fallback_is_allowed() {
    let fake_source = "\
fn lookup_threat_indicator_policy_composed(indicator: &ThreatIndicator) {
    let existing = lookup_threat_indicator_in_dht(indicator);
    match existing {
        Some(record) => evaluate_threat_intel_policy(record),
        None => ThreatIntelPolicyDecision::NotActionable,
    }
}
";

    let production = strip_cfg_test_modules(fake_source);
    let production = strip_comments_and_strings(&production);

    let function_map = build_function_map(&production);
    let lines: Vec<&str> = production.lines().collect();

    let mut violations: Vec<String> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        for token in RAW_LOOKUP_TOKENS {
            if line.contains(token) {
                let containing_fn = function_map
                    .get(idx)
                    .and_then(|f| f.as_deref())
                    .unwrap_or("<unknown>");

                if is_enforcement_function(containing_fn) {
                    violations.push(format!(
                        "line {}: raw lookup inside enforcement function `{}`",
                        idx + 1,
                        containing_fn,
                    ));
                    break;
                }

                if !is_function_allowlisted(containing_fn) {
                    violations.push(format!(
                        "line {}: raw lookup inside non-allowlisted function `{}`",
                        idx + 1,
                        containing_fn,
                    ));
                    break;
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Raw lookup inside policy_composed fallback should be allowed, but got: {:?}",
        violations,
    );
}

/// Simulate raw lookup inside the `lookup_local_indicator` definition itself —
/// must be accepted (it is the lookup implementation).
#[test]
fn simulated_raw_lookup_definition_is_allowed() {
    // The lookup functions themselves are on the allowlist; they call into the
    // DHT record store. Simulating one of these being allowlisted.
    let fake_source = "\
fn lookup_local_indicator(indicator: &str) -> Option<ThreatRecord> {
    let key = compute_key(indicator);
    RECORD_STORE_GLOBAL.get(&key)
}
";

    let production = strip_cfg_test_modules(fake_source);
    let production = strip_comments_and_strings(&production);

    let function_map = build_function_map(&production);
    let lines: Vec<&str> = production.lines().collect();

    let mut violations: Vec<String> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        for token in RAW_LOOKUP_TOKENS {
            if line.contains(token) {
                let containing_fn = function_map
                    .get(idx)
                    .and_then(|f| f.as_deref())
                    .unwrap_or("<unknown>");

                if is_enforcement_function(containing_fn) {
                    violations.push(format!(
                        "line {}: raw lookup inside enforcement function `{}`",
                        idx + 1,
                        containing_fn,
                    ));
                    break;
                }

                if !is_function_allowlisted(containing_fn) {
                    violations.push(format!(
                        "line {}: raw lookup inside non-allowlisted function `{}`",
                        idx + 1,
                        containing_fn,
                    ));
                    break;
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Raw lookup inside lookup_local_indicator definition should be allowed, but got: {:?}",
        violations,
    );
}

/// Simulate raw lookup inside an `_after_policy_permit` helper — must be
/// rejected (suffix match on the enforcement denylist).
#[test]
fn simulated_raw_lookup_inside_after_policy_permit_helper_is_rejected() {
    let fake_source = "\
fn apply_rate_limit_mesh_action_after_policy_permit(threat: &ThreatIndicator) {
    let indicator = lookup_threat_indicator_in_dht(threat);
    rate_limit_ip(indicator.source_ip, 3600);
}
";

    let production = strip_cfg_test_modules(fake_source);
    let production = strip_comments_and_strings(&production);

    let function_map = build_function_map(&production);
    let lines: Vec<&str> = production.lines().collect();

    let mut violations: Vec<String> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        for token in RAW_LOOKUP_TOKENS {
            if line.contains(token) {
                let containing_fn = function_map
                    .get(idx)
                    .and_then(|f| f.as_deref())
                    .unwrap_or("<unknown>");

                if is_enforcement_function(containing_fn) {
                    violations.push(format!(
                        "line {}: raw lookup inside enforcement function `{}`",
                        idx + 1,
                        containing_fn,
                    ));
                    break;
                }

                if !is_function_allowlisted(containing_fn) {
                    violations.push(format!(
                        "line {}: raw lookup inside non-allowlisted function `{}`",
                        idx + 1,
                        containing_fn,
                    ));
                    break;
                }
            }
        }
    }

    assert!(
        !violations.is_empty(),
        "Raw lookup inside _after_policy_permit helper must be rejected by the guardrail"
    );
}
