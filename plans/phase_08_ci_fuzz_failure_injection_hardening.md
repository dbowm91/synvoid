# Phase 8 Plan: Feature Profile CI, Fuzzing, and Failure Injection

Status: detailed handoff plan.

Roadmap position: Phase 8 of `plans/roadmap.md`.

Primary goal: make profile compatibility, parser robustness, and failure behavior continuously verified. SynVoid now has many architecture guardrails; this phase turns the most important ones into repeatable CI/profile gates and adds fuzz/failure-injection coverage for hostile inputs and degraded runtime conditions.

## Context

The repo has many feature profiles and boundary guard tests. Several recent corrective passes found profile-gated issues only after explicit local verification. This phase reduces that risk by making profile checks, guard suites, fuzz targets, and failure-injection tests first-class.

## Non-Goals

Do not attempt exhaustive fuzz coverage in one pass.

Do not require every optional feature combination to be CI-gated if it is not supported.

Do not make slow fuzz jobs mandatory on every PR unless runtime is bounded.

Do not redesign runtime components solely for testability unless a small seam unlocks critical failure-injection coverage.

## Deliverables

1. CI profile matrix for supported feature profiles.
2. Consolidated architecture guard test command group.
3. Initial fuzz target inventory and missing high-value fuzz targets.
4. Failure-injection tests for startup rollback, server lifecycle shutdown, supervisor task failure, mesh catchup failure, plugin failure, and snapshot interruption.
5. Docs path validation guard for `architecture/`, `.opencode/skills/`, `docs/`, and `AGENTS.md` references.
6. Architecture doc: `architecture/ci_fuzz_failure_injection.md`.
7. Verification report: `architecture/phase_8_verification_report.md`.

## Phase A: Define Supported Profile Matrix

Create or update a CI workflow if present. If no CI workflow exists, create documentation and a local script first.

Supported baseline profiles:

```bash
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Additional profiles to classify:

- `wireguard`
- `post-quantum`
- `icmp-filter`
- `swagger-ui`
- `erased_pool`
- `socket-handoff`
- platform-specific Linux-only capabilities

Create a table in `architecture/ci_fuzz_failure_injection.md`:

```markdown
| Profile | Command | Required in CI | Expected platform | Notes |
|---------|---------|----------------|-------------------|-------|
```

Only mark profiles required if they are intended to work.

## Phase B: Add Local Verification Script

Create a script such as `scripts/verify_architecture.sh` if scripts already exist; otherwise use `justfile` or documented commands.

Minimum script:

```bash
#!/usr/bin/env bash
set -euo pipefail

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
```

Make script optional for CI but useful for handoff agents.

## Phase C: CI Workflow

If `.github/workflows/` exists, add or update `ci.yml`.

Recommended jobs:

1. `fmt-and-guards`
2. `profile-checks`
3. `crate-tests-core`
4. `crate-tests-mesh-dns`
5. `docs-link-guard`
6. `fuzz-smoke` bounded/optional

Use caching if already present. Keep runtime reasonable.

Profile matrix example:

```yaml
strategy:
  fail-fast: false
  matrix:
    include:
      - name: default
        command: cargo check
      - name: no-default
        command: cargo check --no-default-features
      - name: mesh
        command: cargo check --no-default-features --features mesh
      - name: dns
        command: cargo check --no-default-features --features dns
      - name: mesh-dns
        command: cargo check --no-default-features --features mesh,dns
```

If GitHub Actions is not desired, document why and keep local verification script.

## Phase D: Fuzz Target Inventory

Inspect existing fuzz crate:

```bash
find fuzz -maxdepth 3 -type f -print
rg "fuzz_target|libfuzzer|arbitrary" fuzz crates src tests
```

Create table:

```markdown
| Target | Input type | Current status | Runtime bound | Owner crate | Priority |
|--------|------------|----------------|---------------|-------------|----------|
```

High-value fuzz targets:

- HTTP request parsing and header normalization.
- Chunked response/body framing.
- URL/path normalization and routing matcher.
- DNS message parsing.
- Mesh protocol message decode.
- Blocklist event decode and snapshot cursor decode.
- Plugin manifest parse.
- Config parse and validation.
- Serialization/postcard/rkyv boundaries if externally fed.

## Phase E: Add Missing Fuzz Smoke Targets

Add bounded smoke fuzz tests where full libFuzzer integration is too heavy.

Example property-style tests:

- random bytes to mesh message decoder never panic,
- random bytes to DNS parser never panic,
- malformed snapshot cursor returns error not panic,
- malformed plugin manifest fails closed,
- malformed config returns typed error.

If using `cargo fuzz`, add targets under `fuzz/fuzz_targets/`:

- `mesh_protocol_decode.rs`
- `blocklist_snapshot_cursor.rs`
- `plugin_manifest.rs`
- `dns_message_decode.rs`
- `http_path_normalization.rs`

Set short CI smoke runs:

```bash
cargo fuzz run mesh_protocol_decode -- -runs=1000
```

Keep long fuzz runs manual/nightly.

## Phase F: Failure-Injection Test Seams

Add small test seams where needed, not broad mocks.

Target failure cases:

1. `UnifiedServer` registered task fails; shutdown report counts critical failure.
2. Supervisor critical task fails; maps to `SupervisorShutdownCause::TaskFailed`.
3. Blocklist catchup cursor points beyond retained history; snapshot fallback requested.
4. Snapshot apply interrupted; cursor not advanced incorrectly.
5. Plugin manifest parse fails; plugin disabled, server continues.
6. Plugin invocation timeout; plugin failure isolated.
7. Mesh peer reconnect with cursor load failure; fallback to full retained catchup or snapshot.
8. Startup resource construction fails after partial resource build; no task leak.

Prefer focused unit/integration tests over full end-to-end process spawning.

## Phase G: Docs Path Validation Guard

Add `tests/docs_path_reference_guard.rs`.

Behavior:

- Scan `architecture/`, `.opencode/skills/`, `docs/`, `AGENTS.md`, and root README if present.
- Extract Markdown links that are local relative paths.
- Fail if the target file does not exist.
- Ignore external URLs.
- Ignore anchors when resolving paths.
- Allow documented historical removed files only through explicit allowlist with liveness.

This catches stale architecture paths after module moves.

## Phase H: Failure-Injection Report

Create `architecture/phase_8_verification_report.md` after implementation.

Include:

- profile matrix run results,
- guard test results,
- fuzz target inventory,
- fuzz smoke commands run,
- failure-injection tests added,
- unsupported profile rationale,
- residual risks.

## Verification Commands

```bash
cargo fmt --all -- --check
./scripts/verify_architecture.sh
cargo test --test docs_path_reference_guard
cargo test -p synvoid-block-store blocklist
cargo test -p synvoid-mesh --features mesh blocklist
cargo test -p synvoid --lib server::runtime_handles
cargo test -p synvoid --lib supervisor::task_registry
cargo test -p synvoid-plugin-runtime
```

Fuzz smoke, if enabled:

```bash
cargo fuzz run mesh_protocol_decode -- -runs=1000
cargo fuzz run blocklist_snapshot_cursor -- -runs=1000
cargo fuzz run plugin_manifest -- -runs=1000
```

## Acceptance Criteria

This phase is complete when:

- Supported profile matrix is documented and either CI-gated or local-script gated.
- Architecture guard suite has one canonical command/script.
- Docs local path validation exists and passes.
- High-value fuzz target inventory exists.
- At least three new fuzz/smoke targets or malformed-input tests are added.
- At least four failure-injection tests are added for lifecycle/convergence/plugin/startup behavior.
- CI or local verification report records actual commands run.
- Unsupported profiles are documented rather than silently ignored.

## Handoff Notes

Start with the local verification script and docs path guard. They give immediate value.

Do not make slow fuzzing mandatory on every commit. Use bounded smoke runs for CI and keep long runs manual/nightly.
