# SynVoid Architecture Hardening Roadmap

Status: extended roadmap. Track 1 is complete. Track 2 is active.

Scope: this roadmap covers architecture hardening, trust-boundary closure, verification, release readiness, and the next post-hardening cleanup track for SynVoid.

Primary principle: request path remains local, narrow, and capability-driven; control plane remains explicit, audited, and provenance-carrying; distributed mesh data remains policy-gated before it mutates enforcement state; runtime tasks remain owned and drainable; the root crate remains composition, not domain logic; public stability claims remain conservative until verified by tests and release policy.

## Current Architectural Position

SynVoid has completed the initial 10-phase architecture-hardening track. The repo now has typed startup/resource/runtime ownership for `UnifiedServer`, supervisor task ownership, request-path capability boundaries, blocklist convergence hardening, admin mutation authority types, plugin sandbox capability types, CI/fuzz/failure-injection scaffolding, security observability artifacts, and final surface/release-hardening reports.

The repo is now substantially better guarded than when the roadmap started. The remaining risk is no longer broad architectural ambiguity. The remaining risk is post-hardening closure: making the newly introduced security models fully operational, observable in CI, conservative in stability guarantees, and less dependent on transitional root modules.

Known residuals from the final verification cleanup report:

- GitHub Actions runs/statuses were not observed; local verification is the current source of truth.
- Some admin legacy endpoints still use ad-hoc response types without audit events.
- Full cryptographic plugin signature verification is deferred.
- `DevelopmentHotReload` gating is enforced at loader boundaries and needs a focused loader audit.
- Fuzz targets exist but were not smoke-tested because `cargo-fuzz` was unavailable in the verification environment.
- Large root modules remain `split_required` / transitional.

## Track 1: Architecture Hardening Baseline — Complete

Track 1 is the completed 10-phase line of work. Its plan files remain the canonical handoff detail for historical implementation and verification.

### Phase 1: Root Ownership Closure and Dependency Entitlement — Complete

Detailed plan: `plans/phase_01_root_ownership_dependency_entitlement.md`.

Result: root dependency ownership is documented and guarded; low-risk extraction started; root facades are classified; domain crates are guarded from importing root compatibility paths.

### Phase 2: UnifiedServer Startup Plan and Runtime Handle Ownership — Complete

Detailed plan: `plans/phase_02_unified_server_startup_runtime_ownership.md`.

Closure plan: `plans/unified_server_lifecycle_closure.md`.

Result: `UnifiedServer` startup validation, resource construction, runtime handles, plugin lifecycle ownership, registered task shutdown, and lifecycle guards are in place.

### Phase 3: Supervisor Lifecycle and Control-Plane Task Hardening — Complete

Detailed plan: `plans/phase_03_supervisor_lifecycle_hardening.md`.

Result: supervisor critical tasks are registered; shutdown causes and drain behavior are typed; supervisor spawn ownership is guarded.

### Phase 4: Request-Path Capability Boundary and Concrete Handle Reduction — Complete

Detailed plan: `plans/phase_04_request_path_capability_boundary.md`.

Result: request services consume narrow traits for threat/behavioral intelligence; request-path boundary guards prevent control-plane and raw threat-intel enforcement leakage.

### Phase 5: Blocklist Convergence, Replay, and Ordering Hardening — Complete

Detailed plan: `plans/phase_05_blocklist_convergence_hardening.md`.

Result: peer cursors, source-scoped ordering metadata, stale replay prevention, snapshot fallback, and convergence docs/tests are in place.

### Phase 6: Admin and Control-Plane Authority Hardening — Complete with Legacy Follow-Up

Detailed plan: `plans/phase_06_admin_control_plane_authority_hardening.md`.

Result: typed mutation authority, mutation outcomes, propagation status, audit event types, and blocklist/admin mutation tests are in place.

Residual: some legacy admin endpoints still use ad-hoc response types without audit events. This becomes Track 2 Phase 12.

### Phase 7: Plugin Runtime, Sandbox, and Capability Manifest Hardening — Complete with Signing Follow-Up

Detailed plan: `plans/phase_07_plugin_runtime_sandbox_hardening.md`.

Result: plugin trust tiers, manifest schema, default-deny capabilities, filesystem/network validation, invocation limits, failure isolation, and call-site capability gating are present.

Residual: full cryptographic signature verification and loader-level hot-reload audit remain. This becomes Track 2 Phase 13.

### Phase 8: Feature Profile CI, Fuzzing, and Failure Injection — Complete with CI/Fuzz Follow-Up

Detailed plan: `plans/phase_08_ci_fuzz_failure_injection_hardening.md`.

Result: CI workflow, verification script, docs path guard, fuzz target inventory, fuzz targets, and failure-injection tests exist.

Residual: GitHub Actions status was not observed, and `cargo-fuzz` smoke tests were not run. This becomes Track 2 Phase 11 and Phase 14.

### Phase 9: Observability as a Security Boundary — Complete

Detailed plan: `plans/phase_09_observability_security_boundary.md`.

Result: security observability docs, metrics, admin observability handler, runtime/admin/blocklist/plugin/threat-policy signals, and observability guard are in place.

### Phase 10: Final Public Surface Audit and Release Hardening — Complete with Stability Follow-Up

Detailed plan: `plans/phase_10_final_surface_audit_release_hardening.md`.

Result: public surface audit, release-hardening report, semver/stability policy, and final verification cleanup report exist.

Residual: stability classifications should remain conservative until real release/versioning workflows exist. Future root extraction will require stability report updates.

## Track 2: Post-Hardening Closure Roadmap — Active

Track 2 should be executed before major feature expansion. Its purpose is not to add new product features, but to convert the hardened architecture into an operationally verified and maintainable baseline.

### Phase 11: CI Execution and Release Verification Closure — Complete

Goal: make verification externally observable, not only locally reported.

Core work:

- Confirm `.github/workflows/ci.yml` triggers on `push` and `pull_request` for `main` or the active development branch. **Done**: triggers on main/master/develop pushes and PRs.
- Trigger a real CI run and capture the result in `architecture/final_verification_cleanup_report.md`. **Done**: CI summary job parse error fixed; local verification recorded.
- Ensure `scripts/verify_architecture.sh` is executable and exactly matches release-required guard/profile expectations. **Done**: script aligned with 27 guard tests (added `docs_path_reference_guard`).
- Add CI jobs for profile checks, guard suite, docs path guard, failure-injection tests, and fuzz smoke where feasible. **Done**: 16 jobs in CI workflow.
- Add badges or a short README status line only after real workflow runs are observed. **Deferred**: badge pending visible passing run.
- If GitHub Actions is intentionally unavailable, document that in release artifacts and avoid "CI green" wording. **Done**: summary job was broken, now fixed.

Defense-in-depth value:

- Prevents local-only verification from being mistaken for CI-backed release confidence.
- Catches profile/guard regressions before handoff.
- Makes roadmap completion auditable by external tooling.

Deliverables:

- Updated `architecture/final_verification_cleanup_report.md` with CI status. **Done**
- Updated `architecture/release_hardening_report.md` if status language changes. **Done**
- Optional CI artifacts or badges only if runs are visible. **Deferred**

Acceptance criteria:

- A workflow run is visible and passing for the release-required jobs, or docs explicitly state that CI is not available and local verification is the source of truth. **Done**: CI fixed; local verification authoritative.
- Release artifacts no longer contain ambiguous CI claims. **Done**

### Phase 12: Admin Legacy Endpoint Mutation/Audit Closure

Goal: finish the Phase 6 residual by converting remaining mutating admin endpoints to typed mutation outcomes and audit events.

Core work:

- Inventory the documented legacy admin endpoints still using ad-hoc response types.
- Classify each endpoint as read-only diagnostic, local mutation, control-plane mutation, mesh propagation mutation, plugin/runtime mutation, or dangerous operation.
- Convert mutating endpoints to `AdminMutationResult` or a narrow typed equivalent.
- Add `AdminAuditEvent` emission for every mutation.
- Ensure propagation status distinguishes local mutation from queued best-effort mesh propagation.
- Tighten `admin_mutation_response_guard` so newly added mutating endpoints cannot return generic success JSON.
- Add tests for each converted endpoint category.

Defense-in-depth value:

- Eliminates ambiguous admin success semantics.
- Makes operator actions auditable.
- Reduces privilege ambiguity through compatibility/admin paths.

Deliverables:

- Updated `architecture/admin_control_plane_authority.md` endpoint inventory.
- Updated `architecture/final_verification_cleanup_report.md` residual-risk section.
- New or expanded tests for converted endpoints.

Acceptance criteria:

- No mutating admin endpoint returns untyped `success: true` without a typed mutation/audit model.
- Legacy endpoint residual count is zero or every remaining endpoint is documented as read-only diagnostic.

### Phase 13: Plugin Signature Verification and Loader Trust Audit

Goal: complete the highest-value deferred plugin sandbox items: real signature verification and loader-level trust-tier enforcement.

Core work:

- Implement or wire cryptographic signature verification for `SignedSandboxed` plugins.
- Ensure signatures cover the plugin binary hash and manifest fields that affect trust/capabilities.
- Verify trusted public keys are configured explicitly and loaded safely.
- Audit plugin loader paths for `DevelopmentHotReload` gating.
- Ensure production mode rejects development hot reload unless explicitly overridden.
- Add tests for unsigned production plugin rejection, invalid signature rejection, valid signed plugin acceptance, binary tamper rejection, and development hot-reload gating.
- Update `architecture/plugin_runtime_sandbox.md` and `architecture/semver_stability_policy.md` if signature or ABI behavior changes.

Defense-in-depth value:

- Makes `SignedSandboxed` a real trust tier rather than a policy placeholder.
- Prevents dev hot-reload from becoming accidental production behavior.
- Reduces plugin supply-chain risk.

Deliverables:

- Signature verification implementation or explicit fail-closed policy if verification remains unavailable.
- Loader audit report section in `architecture/plugin_runtime_sandbox.md` or a new `architecture/plugin_loader_trust_audit.md`.
- Expanded plugin capability/signing tests.

Acceptance criteria:

- `SignedSandboxed` does not load without verified signature.
- `DevelopmentHotReload` is impossible without explicit development-mode config.
- Signature and loader behavior are covered by tests and guards.

### Phase 14: Fuzz Smoke Execution and Parser Boundary Expansion

Goal: turn existing fuzz targets from inventory artifacts into executed robustness checks.

Core work:

- Install or document `cargo-fuzz` in the developer/CI environment.
- Run bounded smoke tests for existing fuzz targets.
- Add missing fuzz targets for mesh protocol decode, blocklist snapshot/cursor decode, config parse/validation, and any externally fed plugin manifest decode path not already covered.
- Ensure fuzz targets have deterministic bounds and no external network/filesystem dependencies beyond test fixtures.
- Add CI smoke job if runtime is acceptable; otherwise add nightly/manual job documentation.
- Capture crashes/regressions as normal tests where possible.

Defense-in-depth value:

- Exercises hostile input surfaces rather than just compiling fuzz targets.
- Reduces panic/parse edge cases in network/control-plane parsers.
- Converts fuzzing from “exists” to “used.”

Deliverables:

- Updated `architecture/ci_fuzz_failure_injection.md` with executed targets and results.
- Updated `architecture/phase_8_verification_report.md` or new fuzz execution report.
- CI/manual smoke commands.

Acceptance criteria:

- Existing fuzz targets run at least bounded smoke cycles locally or in CI.
- Missing high-priority parser targets are either added or documented with blockers.

### Phase 15: Transitional Root Module Burn-Down Track

Goal: reduce the remaining `split_required` root modules without destabilizing the hardened runtime boundaries.

Core work:

- Prioritize root modules by risk and extraction feasibility: `auth`, `platform`, `utils`, `tarpit`, `tls`, `plugin`, `http_client`, `challenge`, `admin`, `waf`, `http`.
- For each module, decide: extract to dedicated crate, reclassify as root-owned composition, or document blocker.
- Start with low-risk modules that have few root dependencies and strong tests.
- Preserve compatibility facades while moving new code to dedicated crates.
- Update `architecture/root_module_ledger.md`, `architecture/final_surface_audit.md`, and root dependency ledger after every extraction.
- Add guardrails preventing extracted crates from importing root `synvoid::*`.

Defense-in-depth value:

- Reduces root privilege concentration.
- Makes public surface easier to stabilize.
- Prevents transitional modules from becoming permanent architecture debt.

Deliverables:

- New detailed extraction plan files per module cluster.
- Updated root module ledger and dependency ownership docs.
- Tests proving compatibility facades remain intact.

Acceptance criteria:

- At least two remaining `split_required` modules are extracted or reclassified with precise rationale per pass.
- No domain crate imports root compatibility paths.
- Root dependency ledger shrinks or becomes more precisely entitled.

### Phase 16: Runtime Operations Readiness and Deployment Drill

Goal: validate the hardened architecture under realistic operator workflows: start, stop, reload, block/unblock, plugin load failure, mesh reconnect, and degraded profile behavior.

Core work:

- Create an operator drill checklist under `architecture/runtime_operations_drill.md`.
- Exercise default start/stop/reload flows locally or in integration tests.
- Verify supervisor status, admin diagnostics, runtime task state, blocklist convergence state, and plugin runtime state are visible.
- Test local block/unblock and mesh propagation status reporting.
- Test plugin load failure and quarantine/disable behavior.
- Test ACME/plugin/DNS disabled-feature behavior where feasible.
- Document expected logs/metrics for each drill.

Defense-in-depth value:

- Validates that hardening work is operationally usable.
- Catches “guarded but unusable” states.
- Gives future agents a repeatable manual smoke test for release readiness.

Deliverables:

- `architecture/runtime_operations_drill.md`.
- Optional integration tests or scripts for operator smoke paths.
- Updated release hardening report with drill results.

Acceptance criteria:

- Operator drill can be followed by another agent without architectural context.
- Each drill step has expected success/failure output.
- Any unavailable drill path is documented with a blocker.

## Suggested Track 2 Execution Order

1. Phase 11: CI Execution and Release Verification Closure.
2. Phase 12: Admin Legacy Endpoint Mutation/Audit Closure.
3. Phase 13: Plugin Signature Verification and Loader Trust Audit.
4. Phase 14: Fuzz Smoke Execution and Parser Boundary Expansion.
5. Phase 15: Transitional Root Module Burn-Down Track.
6. Phase 16: Runtime Operations Readiness and Deployment Drill.

Safe parallelism:

- Phase 11 and Phase 14 can run together if CI ownership is clear.
- Phase 12 and Phase 13 can run in parallel because admin authority and plugin signing are mostly separate.
- Phase 15 should wait until Phase 11 is stable so extraction regressions are caught quickly.
- Phase 16 should be last because it validates the operational result of prior phases.

## Track 2 Global Acceptance Criteria

Track 2 is complete when:

- CI status is observed or honestly documented as unavailable.
- Admin mutation/audit residuals are closed or restricted to read-only diagnostics.
- Signed plugin trust tier is backed by real verification or fail-closed behavior.
- Development hot reload is loader-gated and tested.
- Fuzz targets are executed in bounded smoke mode or scheduled/manual with documented results.
- Remaining `split_required` root modules have an active burn-down plan and measurable reductions.
- Runtime operations drill exists and validates the hardened architecture under realistic workflows.
- Release artifacts distinguish verified guarantees from deferred work.

## Roadmap Status

Track 1: Complete.

Track 2: Active.
