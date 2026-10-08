//! B-3 — the admin HTTP control plane is compiled but never mounted.
//!
//! ## The defect this pins
//!
//! `src/admin/` (~20k lines: router, middleware, handlers, OpenAPI, state,
//! alerting, metrics publisher) plus `crates/synvoid-admin/` compile into every
//! worker. The single public entry point, `create_admin_router`
//! (`src/admin/mod.rs`), has no production caller — its only references are the
//! three root test files that drive it through `ServiceExt::oneshot`.
//! `start_metrics_publisher` has no caller at all.
//!
//! The binding doc `architecture/admin_control_plane_authority.md` (and
//! `AGENTS.md`) describe this API as *the* control plane, with authority,
//! propagation and audit semantics. None of it is reachable, and the
//! verification contract's three `admin-contract` lanes certify the router
//! rather than the binary — they can go green while the shipped surface is
//! absent. That is the "silent skip" failure mode the F-1 post-mortem warns
//! about.
//!
//! ## What this gate enforces
//!
//! The pairing, not a policy. Either the router is mounted (and this gate is
//! updated/removed), or the binding doc says plainly that it is not. A
//! behavioural test cannot express "this documented surface does not exist";
//! what it can do is refuse to let the two drift apart silently.

use std::fs;
use std::path::Path;

use synvoid_repo_guards::{workspace_root, Violations};

/// The binding doc that carries the authority model.
const AUTHORITY_DOC: &str = "architecture/admin_control_plane_authority.md";

/// Marker that must exist while the router is unmounted.
const NOT_MOUNTED_MARKER: &str = "Shipping status: NOT MOUNTED IN THE BINARY";

/// The public entry point whose reachability is in question.
const ROUTER_FN: &str = "create_admin_router";

/// Source roots scanned for production callers. `tests/` is excluded: the whole
/// point is that only tests call it.
const SOURCE_ROOTS: &[&str] = &["src"];

/// Does anything outside test code call the router?
fn has_production_caller() -> (bool, String) {
    let root = workspace_root();
    let mut callers = Vec::new();

    for dir in SOURCE_ROOTS {
        let walk = root.join(dir);
        let Ok(_) = std::fs::read_dir(&walk) else {
            continue;
        };
        let mut stack = vec![walk];
        while let Some(current) = stack.pop() {
            let Ok(read) = std::fs::read_dir(&current) else {
                continue;
            };
            for entry in read.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let Ok(text) = fs::read_to_string(&path) else {
                    continue;
                };
                for (idx, line) in text.lines().enumerate() {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("//") {
                        continue;
                    }
                    // The definition itself does not count as a caller.
                    if trimmed.contains(&format!("fn {ROUTER_FN}")) {
                        continue;
                    }
                    if trimmed.contains(ROUTER_FN) {
                        callers.push(format!(
                            "{}:{}",
                            path.strip_prefix(&root).unwrap_or(&path).display(),
                            idx + 1
                        ));
                    }
                }
            }
        }
    }

    let mounted = !callers.is_empty();
    (mounted, callers.join(", "))
}

/// B-3: the unmounted-admin notice and the code must agree.
#[test]
fn admin_surface_is_not_mounted() {
    let root = workspace_root();
    let doc_path = root.join(AUTHORITY_DOC);
    let mut violations = Violations::new();

    if !Path::new(&doc_path).exists() {
        violations.push(format!(
            "{AUTHORITY_DOC} is in this guard's scope but no longer exists; \
             re-scope the gate rather than letting it silently stop covering it"
        ));
        violations.assert_ok("admin_surface_is_not_mounted");
        return;
    }

    let (mounted, callers) = has_production_caller();
    let doc = fs::read_to_string(&doc_path).unwrap_or_default();
    let declares_not_mounted = doc.contains(NOT_MOUNTED_MARKER);

    if mounted && declares_not_mounted {
        violations.push(format!(
            "`{ROUTER_FN}` now has production caller(s) ({callers}) but \
             {AUTHORITY_DOC} still carries \"{NOT_MOUNTED_MARKER}\". Either the \
             notice is stale or the router is wired; reconcile them in this commit."
        ));
    }

    if !mounted && !declares_not_mounted {
        violations.push(format!(
            "`{ROUTER_FN}` has no production caller (only tests reference it), yet \
             {AUTHORITY_DOC} does not say so. The doc reads as a description of \
             the shipped control plane. Add the \"{NOT_MOUNTED_MARKER}\" notice, \
             or mount the router."
        ));
    }

    violations.assert_ok("admin_surface_is_not_mounted");
}

/// The operator-facing feature matrix must not advertise the admin API as
/// available. This is the document an operator reads to decide what a build
/// actually does.
#[test]
fn feature_status_does_not_advertise_the_admin_api() {
    let root = workspace_root();
    let rel = "docs/FEATURE_STATUS.md";
    let mut violations = Violations::new();

    let Ok(text) = fs::read_to_string(root.join(rel)) else {
        violations.push(format!("{rel} could not be read"));
        violations.assert_ok("feature_status_does_not_advertise_the_admin_api");
        return;
    };

    for line in text.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('|') || !trimmed.contains("Admin HTTP API") {
            continue;
        }
        if !trimmed.contains("Not shipped") {
            violations.push(format!(
                "{rel} advertises the Admin HTTP API without a \"Not shipped\" \
                 marker: {trimmed}"
            ));
        }
    }

    violations.assert_ok("feature_status_does_not_advertise_the_admin_api");
}
