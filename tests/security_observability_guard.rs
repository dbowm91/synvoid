//! Guardrail: security observability invariants (Phase 9).
//!
//! Enforces:
//! - Metric labels do not include high-cardinality/sensitive fields
//! - Raw threat-intel lookup APIs are not used to emit enforcement metrics
//! - Runtime registries emit task exit/shutdown reports
//! - Observability doc lists every metric prefix used in code

use std::fs;
use std::path::{Path, PathBuf};

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
const RAW_LOOKUP_TOKENS: &[&str] = &["lookup_local_indicator(", "lookup_threat_indicator_in_dht("];

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

// ── Helper Functions ─────────────────────────────────────────────────────────

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

// ── Unit Tests ───────────────────────────────────────────────────────────────

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
