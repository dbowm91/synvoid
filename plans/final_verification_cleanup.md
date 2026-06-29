# Final Verification and Cleanup Plan

Status: detailed handoff plan.

Scope: final corrective verification pass after the Phase 1–10 architecture-hardening roadmap was marked complete.

Primary goal: independently verify that the roadmap-complete status is true in code, CI, guards, docs, and release artifacts. This pass should not start new feature work. It should close mismatches, sharpen weak guards, and produce a final verification report that distinguishes confirmed guarantees from aspirational documentation.

## Current Assessment

The repo now contains implementation work for the remaining roadmap phases:

- Phase 6: admin/control-plane authority and typed mutation results.
- Phase 7: plugin sandbox manifest, trust tiers, capabilities, limits, and guardrails.
- Phase 8: CI profile matrix, fuzz targets, failure-injection tests, docs path guard.
- Phase 9: security observability metrics, reports, guards, and admin diagnostics.
- Phase 10: final surface audit and release hardening reports.

The main remaining uncertainty is independent verification:

- The repo includes `.github/workflows/ci.yml`, but connector status did not show workflow runs or combined commit checks.
- Release reports claim many green checks; this pass must reproduce or correct those claims.
- Some new guards may be brittle or string-scanning-heavy.
- Plugin sandbox types may exist without complete enforcement at every runtime call site.
- The public surface audit may overstate stability for transitional/internal APIs.

## Non-Goals

Do not add new capabilities.

Do not start another roadmap.

Do not expand plugin privileges.

Do not weaken guards to make them pass.

Do not mark surfaces as stable unless the code and tests support the claim.

## Deliverables

1. `architecture/final_verification_cleanup_report.md` with command results and findings.
2. Any corrective code/doc/guard patches needed to make reports truthful.
3. CI workflow verification or documented reason why workflow status is unavailable.
4. Tightened guard allowlists/liveness checks where gaps are found.
5. Plugin sandbox enforcement audit and any missing call-site checks.
6. Final update to `architecture/release_hardening_report.md` if claims change.
7. Final update to `plans/roadmap.md` only if roadmap status must be corrected.

## Phase A: Establish Baseline and CI Truth

### A1. Inspect CI Workflow

Review:

```bash
sed -n '1,240p' .github/workflows/ci.yml
```

Check:

- Workflow triggers include `push` and/or `pull_request` for `main`.
- Jobs are not disabled by impossible path filters.
- Matrix commands match release report claims.
- Guard tests listed in release report are actually run in CI or in a documented local script.
- `scripts/verify_architecture.sh` is executable and current.

If CI is meant to run on pushes, push a harmless workflow/doc update if needed to trigger it. If the environment intentionally does not run GitHub Actions, document this explicitly in the verification report and keep local verification as the source of truth.

### A2. Run Full Local Verification Matrix

Run the exact matrix claimed by `architecture/release_hardening_report.md`.

Minimum:

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
./scripts/verify_architecture.sh
```

Then run all release-required guards explicitly:

```bash
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
cargo test --test unified_server_lifecycle_ownership_guard
cargo test --test supervisor_task_ownership_guard
cargo test --test request_path_capability_boundary_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test http_request_pipeline_boundary_guard
cargo test --test http3_waf_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard --features mesh,dns
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test --test admin_auth_boundary
cargo test --test mesh_admin_edge_cases
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_failure_does_not_poison_manager
cargo test --test docs_path_reference_guard
cargo test --test failure_injection
cargo test --test security_observability_guard
cargo test --test unified_worker_composition_root_guard
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Record each command in `architecture/final_verification_cleanup_report.md`.

Report table:

```markdown
| Command | Status | Duration | Notes / Failure |
|---------|--------|----------|-----------------|
```

## Phase B: Release Report Truthfulness Audit

Review:

```text
architecture/release_hardening_report.md
architecture/final_surface_audit.md
plans/roadmap.md
README.md
CHANGELOG.md
AGENTS.md
```

Check every numeric claim:

- guard count,
- assertion count,
- architecture doc count,
- profile count,
- fuzz target count,
- completion status,
- CI status wording.

Correct any claim that cannot be independently reproduced.

Preferred wording if CI still has no visible runs:

> Local verification passed; GitHub Actions status was not available/observed during this pass.

Do not say “CI green” unless the workflow actually ran and passed.

## Phase C: Guardrail Quality Cleanup

Inventory all guards:

```bash
find tests -maxdepth 1 -name '*guard*.rs' -print | sort
```

For each guard, check:

- fail-closed behavior for new source files,
- liveness tests for exception allowlists,
- narrow path+token exceptions rather than broad directories,
- comment/string stripping if scanning source text,
- clear failure messages with remediation guidance,
- no stale paths after moves.

Prioritize these likely weak spots:

1. `threat_intel_boundary_guard.rs` — historically had file-level allowlists and weak comment stripping.
2. `root_dependency_ownership_guard.rs` — verify ledger liveness and no stale dependency entries.
3. `unified_server_lifecycle_ownership_guard.rs` — verify it detects direct long-lived spawns, not just expected strings.
4. `admin_mutation_response_guard.rs` — verify it distinguishes read-only diagnostics from mutating endpoints.
5. `plugin_capability_boundary_guard.rs` — verify it checks enforcement call sites, not only type definitions.
6. `security_observability_guard.rs` — verify metric-label checks are not overfitted.

Add liveness helpers where missing:

```rust
#[test]
fn boundary_exceptions_are_live() {
    for exception in BOUNDARY_EXCEPTIONS {
        assert!(
            path_contains_token(exception.path_suffix, exception.token),
            "stale guard exception: {:?}",
            exception
        );
    }
}
```

## Phase D: Plugin Sandbox Enforcement Audit

The plugin sandbox model is high-value and high-risk. Verify enforcement, not only schema presence.

Inspect:

```bash
rg "PluginCapability|PluginCapabilities|PluginInvocationGuard|invoke_with_limits|check_filesystem_access|check_network_access|request_mutate|response_mutate|mesh|admin_events" crates/synvoid-plugin-runtime src/plugin src/server src/waf src/http crates/synvoid-http crates/synvoid-waf tests
```

Checklist:

- Manifest defaults deny every capability.
- Every capability-sensitive hook checks `PluginCapability` before invocation.
- Request mutation and response mutation are separate from inspect-only hooks.
- Filesystem access canonicalizes and rejects symlink/path escape.
- Network access is default-deny and host/port allowlisted.
- Mesh/admin event capabilities are denied unless fully implemented and guarded.
- Signing policy cannot silently allow unsigned plugins in production defaults.
- `DevelopmentHotReload` requires explicit dev-mode/config gate.
- Timeout, input size, output size, and concurrency limits are applied at invocation boundaries.
- Plugin failure disables/quarantines plugin rather than poisoning global manager.

Potential corrective patches:

- Add missing `capabilities.require(PluginCapability::X)` before hook invocation.
- Add tests for inspect-only plugin denied mutation.
- Add tests for default-deny manifest parsing.
- Add tests for unsigned production plugin rejected unless explicitly allowed.
- Add guard checks for any new host function exposing mesh/admin/network/filesystem.

## Phase E: Admin Authority and Audit Verification

Inspect:

```bash
rg "AdminMutationResult|AdminMutationStatus|PropagationStatus|AdminAuditEvent|AdminMutationAuthority|success.*true|\"success\"" src/admin crates/synvoid-admin crates/synvoid-core tests
```

Checklist:

- Mutating endpoints return typed mutation results.
- Read-only endpoints are clearly classified and allowed to use diagnostic responses.
- Block/unblock distinguishes applied, no-op, duplicate, stale, failed.
- Propagation status is explicit and does not imply delivered mesh state.
- Audit event includes actor authority and sanitized actor/session metadata.
- Raw admin tokens/session tokens are never logged or serialized in audit events.
- Supervisor/manual/mesh/compatibility authority are not conflated.

Potential corrective patches:

- Replace lingering generic success responses in mutating handlers.
- Add missing audit sink call for mutation endpoints.
- Add test for no raw tokens in serialized audit event.

## Phase F: Observability Verification

Inspect:

```bash
rg "synvoid_.*_total|security_observability|metric|counter|gauge|histogram|label" crates/synvoid-metrics src tests architecture/security_observability.md
```

Checklist:

- Metric names in code are documented in `architecture/security_observability.md`.
- Labels are low-cardinality.
- No raw IP, event ID, token, user agent, path, or plugin arbitrary name in metric labels.
- Runtime task exit/shutdown metrics map all statuses/classes.
- Admin mutation metrics map all mutation statuses and propagation statuses.
- Blocklist convergence metrics distinguish stale/duplicate/applied/failed.
- Plugin metrics distinguish load/invoke/capability violation without high-cardinality labels.
- Raw threat-intel diagnostics are not represented as enforcement decisions.

Potential corrective patches:

- Rename or document metrics.
- Add sanitizer helpers.
- Tighten `security_observability_guard.rs` denylist.

## Phase G: CI/Fuzz/Failure-Injection Verification

Inspect fuzz configuration:

```bash
find fuzz -maxdepth 2 -type f -print | sort
cat fuzz/Cargo.toml
```

Run bounded smoke targets if tooling is available:

```bash
cargo fuzz run dns_message_decode -- -runs=1000
cargo fuzz run http_path_normalization -- -runs=1000
cargo fuzz run plugin_manifest -- -runs=1000
```

If `cargo fuzz` is unavailable, document that and run substitute unit/property tests if present.

Inspect failure tests:

```bash
cargo test --test failure_injection
```

Checklist:

- Failure-injection tests assert outcomes, not merely no-panic.
- Lifecycle failure tests verify join/abort/shutdown report behavior.
- Blocklist failure tests verify cursor is not advanced incorrectly after failed event/snapshot.
- Plugin failure tests verify manager remains usable.
- CI workflow includes docs-path guard and profile matrix.

## Phase H: Public Surface Stability Cleanup

Review `architecture/final_surface_audit.md`.

Flag any item marked `stable_public` that is actually transitional or internal.

High-risk areas to verify:

- plugin WASM guest ABI stability claims,
- Axum native plugin ABI stability claims,
- root binary stability claims,
- config key stability claims,
- root re-exports marked stable despite transitional façade status.

Corrective rule:

If there is no semver or compatibility policy, mark as `transitional` or `internal_public_for_crate_boundary`, not `stable_public`.

Add a short `Semver / Stability Policy` section if missing:

- root CLI is operator-facing but not yet semver-stable unless explicitly declared,
- internal workspace crates are not public API unless named,
- compatibility facades are transitional,
- plugin ABI stability is provisional unless versioned tests exist.

## Phase I: Transitional Root Modules Cleanup Notes

The final audit still lists large `split_required` root modules. Verify they are accurately documented:

- `admin`
- `auth`
- `challenge`
- `http`
- `http_client`
- `platform`
- `plugin`
- `tarpit`
- `tls`
- `utils`
- `waf`

Do not extract them in this pass. Instead ensure each has:

- current owner,
- target crate or reason to stay root,
- blocker,
- guard coverage,
- suggested future cleanup priority.

If any module is mislabeled, correct `architecture/root_module_ledger.md` and `architecture/final_surface_audit.md`.

## Phase J: Final Report

Create `architecture/final_verification_cleanup_report.md`.

Suggested structure:

```markdown
# Final Verification Cleanup Report

Date: YYYY-MM-DD
Base: <commit before pass>
Head: <commit after pass>

## Summary

## CI Status

## Commands Run

| Command | Status | Notes |
|---------|--------|-------|

## Corrections Applied

| Area | Files | Summary |
|------|-------|---------|

## Plugin Enforcement Audit

## Admin Authority Audit

## Observability Audit

## Guardrail Audit

## Public Surface Stability Corrections

## Residual Risks

## Final Status
```

Final status options:

- `Verified roadmap complete` — only if all claims are reproduced and corrections are applied.
- `Locally verified; CI not observed` — if local matrix passes but GitHub Actions still unavailable.
- `Roadmap complete with blockers` — if release-required guards/profiles fail.

## Verification Commands After Corrections

Run:

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
./scripts/verify_architecture.sh
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_failure_does_not_poison_manager
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test --test admin_auth_boundary
cargo test --test mesh_admin_edge_cases
cargo test --test security_observability_guard
cargo test --test docs_path_reference_guard
cargo test --test failure_injection
```

## Acceptance Criteria

This cleanup pass is complete when:

- The final verification report exists.
- Every release report claim is reproduced or corrected.
- CI status is either observed or honestly documented as unavailable.
- All supported profile checks pass locally.
- All release-required guard tests pass locally.
- Plugin capability enforcement is verified at call sites, not just in type definitions.
- Admin mutation/audit paths are verified for typed outcomes and no token leakage.
- Observability metrics are verified for low-cardinality labels and doc coverage.
- Public surface stability labels are conservative and truthful.
- Any remaining risks are explicit and not hidden behind “complete” language.

## Handoff Notes

This is a cleanup verification pass. Prefer truthfulness and guard sharpness over new abstractions.

If a claim cannot be verified, correct the claim. Do not weaken the code to match docs.

If CI cannot be observed, state that directly in release artifacts rather than implying CI green.
