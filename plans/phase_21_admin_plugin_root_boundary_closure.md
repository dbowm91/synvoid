# Phase 21 Plan: Admin and Plugin Root-Boundary Closure

Status: detailed handoff plan.

Roadmap position: Track 3, Phase 21 of `plans/roadmap.md`.

Primary goal: close the remaining large mixed root modules by ensuring `admin` contains transport/control-plane composition rather than domain implementations, and `plugin` contains application lifecycle wiring rather than a second plugin runtime.

## Context

The completed admin corrective line substantially hardened router composition, browser authentication, mutation/audit semantics, realtime behavior, alerting, and frontend/backend contract integrity. That work did not attempt to make the root `admin` module small. The root module ledger still classifies `admin` as `split_required` because it contains a large Axum/router/handler surface wired directly to WAF, config, mesh, metrics, supervisor, and other runtime managers.

Likewise, `synvoid-plugin-runtime` is the intended owner of reusable plugin execution, while root `plugin` still mixes lifecycle/composition with runtime-facing behavior.

This phase is not a feature addition. It is an ownership audit that moves remaining domain behavior to existing owners and then deliberately reclassifies root composition where appropriate.

## Constraints

- Do not reopen the browser/session/API behavior already closed by the admin corrective roadmap except where ownership migration requires mechanical import/type changes.
- Preserve `AdminMutationResult`, `AdminMutationAuthority`, `AdminAuditEvent`, propagation-status, and client-identity semantics.
- Do not create `synvoid-admin` merely to move LOC. Create a crate only if there is genuinely reusable admin transport/domain behavior with a clean dependency graph.
- Keep Axum application router composition root-owned unless there is a compelling reuse boundary.
- Plugin capability checks, signature verification, resource limits, and fail-closed behavior must not weaken.
- `synvoid-plugin-runtime` must not import root `synvoid::*`.

## Part A: Admin ownership inventory

Create `architecture/admin_root_ownership.md` with a submodule/handler inventory.

For each admin module/handler classify code as:

- HTTP transport/router/middleware composition
- request/response DTO
- authentication/session behavior
- domain mutation/query logic
- runtime service adapter
- feature-capability discovery
- static UI delivery
- compatibility/legacy route

The target boundary is:

- root admin owns Axum transport, route registration, middleware ordering, extraction of authenticated operator identity, response adaptation, and application service wiring;
- domain crates/managers own validation and mutation/query semantics;
- shared admin mutation/audit DTOs remain in their existing canonical low-level owner;
- authentication/session logic uses `synvoid-auth` after Phase 18.

## Part B: Thin handlers around typed services

For each mutating handler, ensure the handler performs only transport concerns plus a call into an authoritative service/manager operation.

A healthy mutation flow is:

1. parse/authenticate/authorize request
2. validate transport-level shape
3. call typed domain/control-plane method
4. receive typed mutation result
5. emit/attach audit event through the established authority path
6. map result to HTTP response

Move business rules currently duplicated in handlers into the appropriate existing owner (`synvoid-config`, block store, mesh, plugin runtime, supervisor/root process service, etc.).

Do not add repository-wide service-locator abstractions. `AdminState` may continue to hold explicit typed handles.

## Part C: Read/query handlers

Apply the same ownership rule to read-only endpoints:

- metrics formatting may remain transport-specific, but metrics collection stays in `synvoid-metrics`
- mesh status calculation belongs in mesh/service APIs, not duplicated in handlers
- config canonicalization/validation stays in `synvoid-config`
- supervisor/process state comes from the root supervisor service rather than being reconstructed independently
- plugin status comes from the plugin lifecycle/runtime owner

Remove duplicate state derivation where it can drift from the runtime source of truth.

## Part D: Decide `admin` final classification

After the inventory and moves, choose one of two outcomes:

### Preferred: `keep_app_root`

Use this if the remaining module is predominantly Axum application/control-plane composition. Document that admin transport is intentionally root-owned and stop treating its size alone as extraction debt.

### Conditional: `synvoid-admin`

Create a dedicated crate only if a substantial transport-neutral admin API layer exists that:

- does not depend on root application composition
- is meaningfully reusable/testable independently
- reduces dependency direction rather than adding another facade

Do not create a crate simply to relocate handlers that still require every root subsystem.

## Part E: Plugin ownership audit

Inventory `src/plugin/` against `crates/synvoid-plugin-runtime/`.

Classify each root component as:

- plugin process/application lifecycle composition
- loader/trust policy
- reusable runtime execution
- manifest/capability validation
- root service adapter
- stale/duplicate implementation

Reusable plugin behavior must have one canonical owner. In particular, do not retain root copies of:

- manifest/capability validation
- trust-tier/signature decisions
- WASM execution policy
- invocation timeout/resource-limit policy
- quarantine/failure-accounting behavior

where those are already or should be owned by `synvoid-plugin-runtime`.

## Part F: Keep lifecycle composition explicit

Root may legitimately own:

- loading plugins from application configuration
- attaching plugin runtime to `UnifiedServer`/worker state
- supervisor task ownership and shutdown
- application-specific route/filter registration
- handoff to process-jail execution when Phase 22 is enabled

If this is all that remains, reclassify root `plugin` to `keep_app_root` with a concise ownership statement.

## Part G: Remaining root mixed-module sweep

After admin/plugin cleanup, re-read `architecture/root_module_ledger.md` and disposition any remaining `split_required` entries not closed by Phases 18–20.

For each one choose:

- `facade_existing_crate`
- `keep_app_root`
- a new targeted blocker requiring its own future plan

Do not leave `split_required` merely because a module is large. The classification should describe ownership ambiguity, not LOC.

Also reconcile known documentation drift between `root_module_ledger.md`, `root_module_burndown_report.md`, and `final_surface_audit.md` so they list the same remaining mixed modules.

## Guardrails

Update/add guards so:

- admin handlers do not directly implement duplicate domain mutation policy when a canonical manager exists
- root plugin cannot duplicate crate-owned manifest/trust/runtime types
- domain crates do not import root admin/plugin compatibility modules
- root module ledger and burn-down report agree on classification names
- newly classified facades remain thin

Keep source guards conservative and maintainable; prefer explicit import/path checks over brittle LOC thresholds.

## Acceptance criteria

Phase 21 is complete when:

- admin submodules/handlers have a documented owner classification
- authentication/session behavior is consumed from its canonical owner
- mutating admin handlers are thin adapters over authoritative typed operations
- read handlers do not reconstruct canonical subsystem state unnecessarily
- `admin` is reclassified to `keep_app_root` or a dedicated crate is justified by an actual clean reuse boundary
- root plugin contains lifecycle/application composition rather than duplicate runtime/trust/capability implementations
- `plugin` is reclassified from `split_required` with precise rationale
- all remaining `split_required` ledger entries after Phases 18–21 have either been closed or carry a concrete unresolved blocker
- root ledger, burn-down report, final surface audit, and dependency ownership docs agree
- completed admin security/contract regression tests remain green

## Rejection criteria

Reject an implementation that:

- creates `synvoid-admin` only to move files while it still depends on nearly every root subsystem
- moves Axum/browser transport concerns into unrelated domain crates
- bypasses typed mutation/audit authority to simplify handlers
- duplicates plugin manifest/signature/capability validation in root
- marks a genuinely mixed module `keep_app_root` without moving domain logic first
- uses LOC thresholds as the primary definition of architectural correctness

## Verification

At minimum run:

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo test -p synvoid-plugin-runtime
cargo test --test admin_mutation_response_guard
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
cargo test --test request_path_capability_boundary_guard
```

Also run the focused admin router/auth/CSRF/contract tests from the completed admin roadmap and plugin signing/capability tests from Track 2.
