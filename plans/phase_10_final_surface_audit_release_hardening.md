# Phase 10 Plan: Final Public Surface Audit and Release Hardening

Status: completed.

Roadmap position: Phase 10 of `plans/roadmap.md`.

Primary goal: close the architecture-hardening roadmap by auditing public API, CLI, admin endpoints, root exports, feature profiles, docs, guardrails, and release readiness. This phase should produce a clear statement of what is stable, what is transitional, what is internal, and what residual risks remain.

## Context

Phases 1–9 harden ownership, lifecycle, request boundaries, blocklist convergence, admin authority, plugins, CI/fuzzing, and observability. Phase 10 is a closure pass: no new major subsystem work unless required to fix an audit failure.

## Non-Goals

Do not add new product features.

Do not perform broad refactors unless necessary to close public/internal boundary violations.

Do not delete compatibility facades without call-site inventory and migration notes.

Do not invent stability promises that the code cannot support.

## Deliverables

1. Public surface inventory.
2. CLI command classification report.
3. Admin endpoint authority/audit/propagation inventory.
4. Root export audit against `architecture/root_module_ledger.md`.
5. Feature profile support matrix.
6. Guardrail completeness report.
7. Release-hardening checklist.
8. Architecture doc: `architecture/final_surface_audit.md`.
9. Release report: `architecture/release_hardening_report.md`.

## Phase A: Public Surface Inventory

Inventory public surfaces:

- root crate exports in `src/lib.rs`,
- binaries in `Cargo.toml`,
- CLI commands in `src/commands/`,
- admin HTTP/gRPC endpoints,
- plugin APIs,
- config keys,
- IPC/protocol message types,
- mesh wire messages,
- public crate exports under `crates/synvoid-*`.

Create `architecture/final_surface_audit.md` with tables:

```markdown
| Surface | File/crate | Classification | Stability | Owner | Notes |
|---------|------------|----------------|-----------|-------|-------|
```

Classification values:

- `stable_public`
- `internal_public_for_crate_boundary`
- `compat_facade`
- `transitional`
- `test_only`
- `deprecated`

## Phase B: Root Export Audit

Compare `src/lib.rs` against `architecture/root_module_ledger.md`.

Checks:

- Every exported root module appears in ledger.
- Classification is valid.
- `facade_existing_crate` modules have doc comments pointing to canonical crate.
- `split_required` modules have current blockers or phase references.
- `legacy_or_stale` modules are not active exports unless deliberately transitional.
- Domain crates do not import root `synvoid::` paths.

Commands:

```bash
cargo test --test root_module_ledger_guard
cargo test --test root_facade_boundary_guard
rg "synvoid::" crates
```

Potential correction:

Add deprecation docs to compatibility facades rather than removing them abruptly.

## Phase C: CLI Command Classification

Inspect `src/commands/` and `src/main.rs`.

Every CLI command should be classified as:

- local inspection,
- one-shot local operation,
- supervisor/control-plane mutation,
- runtime launch,
- dangerous/privileged operation,
- test/development-only.

Create table:

```markdown
| Command | Classification | Side effects | Auth/permissions | Runtime dependency | Tests | Notes |
|---------|----------------|--------------|------------------|--------------------|-------|-------|
```

Guard expectations:

- `main.rs` remains thin.
- command planning remains mostly pure.
- runtime launch mechanics remain behind typed launch boundary.
- supervisor mutations are explicit and audited after Phase 6.

Run:

```bash
cargo test --test cli_command_dispatch_guard
cargo test -p synvoid --lib commands
```

## Phase D: Admin Endpoint Audit

Inventory every admin endpoint and classify:

- read-only diagnostic,
- local mutation,
- supervisor mutation,
- mesh propagation mutation,
- plugin/runtime mutation,
- dangerous operation.

For each endpoint verify:

- auth requirement,
- authority classification,
- mutation result schema,
- audit event behavior,
- propagation semantics,
- rate limit/replay protection where applicable,
- sensitive output redaction.

Run Phase 6 guard:

```bash
cargo test --test admin_mutation_response_guard
```

If that guard does not exist because Phase 6 implementation deferred it, mark admin surface as not release-hardened and block final closure.

## Phase E: Feature Profile Support Matrix

Finalize supported feature profiles.

Table:

```markdown
| Profile | Command | Supported | CI gated | Runtime behavior | Notes |
|---------|---------|-----------|----------|------------------|-------|
```

Minimum profiles:

- default,
- no-default-features,
- mesh,
- dns,
- mesh+dns.

Optional profiles:

- HTTP/3 if separately gated,
- WireGuard,
- post-quantum,
- ICMP filter,
- swagger UI,
- socket handoff,
- erased pool.

Run the Phase 8 verification script if present.

## Phase F: Guardrail Completeness Audit

Inventory all guard tests and classify coverage.

```bash
find tests -maxdepth 1 -name "*guard*.rs" -print | sort
```

For each guard:

- What invariant does it enforce?
- Is it fail-closed for new files?
- Does it have exception liveness tests?
- Are exceptions narrow?
- Does it ignore comments/strings sanely?
- Does it have clear failure messages?

Create table:

```markdown
| Guard | Invariant | Strength | Known gaps | Required for release |
|-------|-----------|----------|------------|----------------------|
```

At minimum, final release gates should include:

- root facade boundary,
- root module ledger,
- root dependency ownership,
- unified server lifecycle ownership,
- supervisor task ownership,
- request-path capability boundary,
- data-plane composition boundary,
- threat-intel boundary,
- threat-intel consumer actionability,
- mesh-ID boundary,
- admin mutation response,
- plugin capability boundary,
- docs path reference,
- security observability guard.

## Phase G: Protocol and Serialization Surface Audit

Inventory externally fed parsers/decoders:

- HTTP request parsing/normalization,
- HTTP/3 request dispatch,
- DNS decode,
- mesh protocol decode,
- IPC message decode,
- blocklist event/snapshot decode,
- plugin manifest decode,
- config decode.

For each:

- fuzz/smoke coverage,
- typed error behavior,
- panic risk,
- size limits,
- trust boundary classification.

This should reference Phase 8 fuzz inventory.

## Phase H: Release-Hardening Checklist

Create `architecture/release_hardening_report.md`.

Checklist:

- all supported profile checks pass,
- all release-required guards pass,
- fuzz smoke targets run or explicitly deferred,
- admin mutation audit model implemented,
- plugin capability model implemented,
- observability signals present,
- docs path guard passes,
- no known `mem::forget` lifecycle leaks,
- no domain crate root imports,
- no request-path control-plane imports,
- no raw threat-intel enforcement paths,
- blocklist convergence non-guarantees documented,
- public root facades documented,
- known residual risks listed.

## Phase I: Semver/Stability Notes

If the repo has public crate consumers, add a stability note:

- which crates are intended public API,
- which crates are internal workspace implementation details,
- compatibility promises for root facades,
- deprecation process for transitional exports,
- config compatibility policy.

If semver is not yet meaningful, say so explicitly.

## Phase J: Final Verification Commands

Run:

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

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
cargo test --test plugin_capability_boundary_guard
cargo test --test docs_path_reference_guard
cargo test --test security_observability_guard
```

Adjust if some guards are not implemented, but final report must state whether that blocks release hardening.

## Acceptance Criteria

This phase is complete when:

- `architecture/final_surface_audit.md` exists and inventories public/internal surfaces.
- `architecture/release_hardening_report.md` exists and records commands run.
- Root exports are ledger-accurate.
- CLI commands are classified by side effect and runtime boundary.
- Admin endpoints are classified by authority/mutation/audit/propagation.
- Feature support matrix is explicit.
- Release-required guard suite passes or blockers are documented.
- Public API stability/deprecation posture is explicit.
- Residual risks are documented and accepted.

## Handoff Notes

This is a closure phase. Prefer audits, guard tightening, and documentation truthfulness over new functionality.

Do not mark the roadmap complete if Phase 6, 7, 8, or 9 guards are missing and still considered release-required.
