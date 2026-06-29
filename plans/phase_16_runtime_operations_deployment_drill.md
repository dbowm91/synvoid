# Phase 16 Plan: Runtime Operations Readiness and Deployment Drill

Status: detailed handoff plan.

Roadmap position: Track 2, Phase 16 of `plans/roadmap.md`.

Primary goal: validate that the hardened architecture is operationally usable under realistic operator workflows: start, stop, reload, status, block/unblock, plugin load failure, mesh reconnect, and degraded feature/profile behavior.

## Context

The prior phases add strong static boundaries, typed outcomes, lifecycle ownership, plugin capabilities, CI/fuzz scaffolding, and observability. This phase checks whether those mechanisms are actually usable by an operator or future agent during a release/deployment smoke drill.

## Non-Goals

Do not build a production deployment platform.

Do not require a live public domain, real ACME certificate, or multi-machine mesh unless already available.

Do not add new runtime features.

Do not mask failures with overly broad manual steps.

## Deliverables

1. `architecture/runtime_operations_drill.md` with reproducible operator drill steps.
2. Optional script(s) for local smoke setup if practical.
3. Recorded drill results in `architecture/runtime_operations_drill_report.md`.
4. Any corrective patches for operator-blocking failures.
5. Updates to release-hardening report if drill changes release confidence.

## Phase A: Define Drill Environment

Document environment assumptions:

- OS and kernel expectations.
- Required privileges or ports.
- Whether mesh is enabled.
- Whether DNS/HTTP3/TLS/ACME are enabled or stubbed.
- Whether admin API is bound to localhost.
- Whether plugins are test fixtures only.

Create `architecture/runtime_operations_drill.md` with:

```markdown
## Environment
| Item | Value | Notes |
|------|-------|-------|
```

Preferred local drill profile:

- localhost-only bind addresses,
- temporary config directory,
- admin token generated for test only,
- mesh disabled or single-node mesh unless two-node local mesh is easy,
- test plugin fixture with intentional failure,
- no real ACME external dependency.

## Phase B: Prepare Test Configs

Create minimal configs under `examples/` or `tests/fixtures/ops/` if appropriate.

Suggested fixtures:

- `ops_minimal.toml`
- `ops_mesh_single_node.toml`
- `ops_plugin_failure.toml`
- `ops_dns_disabled.toml`

Do not commit real secrets. Use generated/test-only tokens and clearly mark them invalid for production.

## Phase C: Drill 1 — Config Validation and Startup

Steps:

```bash
cargo run -- --config tests/fixtures/ops/ops_minimal.toml --configtest
cargo run -- --config tests/fixtures/ops/ops_minimal.toml
```

Expected:

- config validation succeeds,
- runtime starts,
- `UnifiedServerRuntimeHandles` registers expected tasks,
- admin diagnostics endpoint available if enabled,
- logs include startup profile and task registration.

Record expected log snippets or metrics names, not full logs.

## Phase D: Drill 2 — Status, Reload, Stop

Exercise CLI/supervisor control paths:

```bash
synvoid --status
synvoid --rehash
synvoid --stop
```

Expected:

- status returns typed runtime/supervisor state,
- reload produces typed outcome or documented no-op,
- stop triggers graceful shutdown,
- shutdown report includes joined/aborted task counts,
- no orphaned processes remain.

If binary naming/path differs, document exact command.

## Phase E: Drill 3 — Admin Block/Unblock and Audit

Use localhost admin endpoint or helper tests.

Steps:

1. Submit block for a test IP such as `203.0.113.10`.
2. Verify typed `AdminMutationResult` status `Applied` or equivalent.
3. Repeat block; expect `NoOpAlreadyPresent` or documented refresh behavior.
4. Submit unblock; expect `Applied`.
5. Repeat unblock; expect `NoOpAlreadyAbsent`.
6. Verify audit events were emitted and contain no raw token.
7. Verify propagation status says local-only or queued best-effort, not delivered.

Expected outputs should be documented as JSON examples.

## Phase F: Drill 4 — Plugin Failure and Capability Denial

Use test plugin fixtures.

Scenarios:

- inspect-only plugin attempts request mutation,
- plugin attempts mesh host function without `PluginCapability::Mesh`,
- plugin times out,
- plugin load fails due to invalid manifest/signature policy.

Expected:

- denied capability returns plugin error/quarantine state,
- manager remains usable,
- server continues,
- metrics/logs reflect plugin failure without high-cardinality labels,
- hot reload does not bypass trust policy.

If full runtime plugin execution is not easy, provide a deterministic integration/unit test path that exercises the loader/invocation guard.

## Phase G: Drill 5 — Mesh / Blocklist Convergence Smoke

If mesh can run locally:

- start two local nodes with separate ports/data dirs,
- block on node A,
- verify node B receives event or catchup/snapshot repair path,
- disconnect/reconnect node B,
- verify cursor/catchup status,
- unblock and ensure stale old block does not resurrect.

If only single-node mesh is feasible:

- run mesh-enabled profile,
- verify blocklist cursor persistence and diagnostics endpoints,
- test snapshot/catchup helper functions via tests.

Expected:

- convergence health visible via admin diagnostics,
- request path remains local-only,
- mesh propagation described as best-effort.

## Phase H: Drill 6 — Degraded Feature/Profile Behavior

Exercise disabled or unavailable features:

- no-default-features binary behavior,
- DNS disabled,
- mesh disabled,
- plugin disabled,
- ACME unavailable/stubbed,
- HTTP3 disabled.

Expected:

- behavior matches docs,
- disabled features fail closed or no-op explicitly,
- logs do not imply enabled protection when disabled,
- admin diagnostics show capability/profile state.

## Phase I: Observability Checklist

For each drill, record whether expected signal exists:

```markdown
| Drill | Logs | Metrics | Admin diagnostic | Audit event | Notes |
|-------|------|---------|------------------|-------------|-------|
```

Signals to verify:

- runtime task registration/shutdown,
- admin mutation result/audit,
- blocklist apply/cursor status,
- plugin load/invoke/failure,
- threat policy decision if exercised,
- profile/feature activation.

## Phase J: Corrective Patches

If drill reveals blocking issues, fix in this order:

1. Dangerous false-success reports.
2. Token/secret leakage.
3. Runtime shutdown hangs/leaks.
4. Plugin sandbox bypass.
5. Admin mutation/audit inconsistency.
6. Missing docs for intentional no-op/degraded behavior.
7. Observability gaps.

Do not patch around runtime failures by weakening guards or changing expectations without code evidence.

## Phase K: Drill Report

Create `architecture/runtime_operations_drill_report.md`.

Suggested structure:

```markdown
# Runtime Operations Drill Report

Date: YYYY-MM-DD
Commit: <sha>
Environment: <summary>

## Summary

## Drill Results

| Drill | Status | Notes |
|-------|--------|-------|

## Commands Run

## Observability Signals

## Corrections Applied

## Residual Risks

## Final Operational Readiness Statement
```

Final statuses:

- `Operational smoke verified locally`
- `Partially verified; blockers documented`
- `Not operationally verified`

## Verification Commands

At minimum:

```bash
cargo fmt --all -- --check
cargo check --no-default-features --features mesh,dns
cargo check
./scripts/verify_architecture.sh
cargo test --test failure_injection
cargo test --test admin_mutation_blocklist
cargo test --test plugin_failure_does_not_poison_manager
cargo test --test security_observability_guard
```

Plus actual drill commands documented in the report.

## Acceptance Criteria

This phase is complete when:

- `architecture/runtime_operations_drill.md` exists and is reproducible.
- Drill report records which runtime paths were actually exercised.
- Start/status/reload/stop or their available equivalents are verified.
- Admin block/unblock typed outcomes and audit behavior are verified.
- Plugin failure/capability denial behavior is verified or blocked with reason.
- Mesh/convergence smoke is verified or blocked with reason.
- Disabled-feature behavior is documented and truthful.
- Observability signals exist for exercised security-relevant transitions.

## Handoff Notes

This is an operations-readiness pass, not a feature pass. The most valuable output is a truthful drill report that another operator or agent can replay.
