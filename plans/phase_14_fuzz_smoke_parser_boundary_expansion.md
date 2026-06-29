# Phase 14 Plan: Fuzz Smoke Execution and Parser Boundary Expansion

Status: detailed handoff plan.

Roadmap position: Track 2, Phase 14 of `plans/roadmap.md`.

Primary goal: make existing fuzz targets executed robustness checks rather than inventory artifacts, and expand fuzz/smoke coverage to remaining externally fed parser boundaries.

## Context

Phase 8 added fuzz targets and failure-injection scaffolding, but the final verification cleanup report noted that `cargo-fuzz` was not available and fuzz targets were not smoke-tested. This phase installs or documents fuzz tooling, runs bounded smoke tests, fixes crashes, and adds missing high-value parser targets.

## Non-Goals

Do not require long-running fuzz jobs on every PR.

Do not add nondeterministic or network-dependent fuzz targets.

Do not treat fuzz smoke as proof of parser correctness.

Do not hide crashes by catching panics without asserting safe error behavior.

## Deliverables

1. Executed bounded smoke runs for existing fuzz targets or documented tooling blocker.
2. Added high-priority fuzz targets for missing parser surfaces.
3. CI/manual workflow for bounded smoke fuzzing.
4. Crash repros converted into deterministic tests when found.
5. Updated `architecture/ci_fuzz_failure_injection.md` and a fuzz execution report.

## Phase A: Inventory Current Fuzz Targets

Run:

```bash
find fuzz -maxdepth 2 -type f -print | sort
cat fuzz/Cargo.toml
rg "fuzz_target|arbitrary|libfuzzer" fuzz crates src tests
```

Update `architecture/ci_fuzz_failure_injection.md` with:

```markdown
| Target | Input surface | Exists | Smoke run | CI/manual | Notes |
|--------|---------------|--------|-----------|-----------|-------|
```

Expected existing targets include at least:

- `dns_message_decode`
- `http_path_normalization`
- `plugin_manifest`

Also account for previously documented target count in release reports.

## Phase B: Install or Document Fuzz Tooling

Try:

```bash
cargo fuzz --help
```

If unavailable:

```bash
cargo install cargo-fuzz
```

If installation is not possible in the environment:

- document exact error,
- keep fuzz smoke as manual blocker,
- run substitute malformed-input unit tests if present,
- do not claim fuzz smoke passed.

## Phase C: Run Bounded Smoke Tests

Run bounded smoke cycles:

```bash
cargo fuzz run dns_message_decode -- -runs=1000
cargo fuzz run http_path_normalization -- -runs=1000
cargo fuzz run plugin_manifest -- -runs=1000
```

If targets are named differently, use actual names from `fuzz/Cargo.toml`.

Record:

- target name,
- command,
- runs,
- status,
- failure/crash path,
- fix commit if any.

## Phase D: Add Missing High-Priority Targets

Add targets for externally fed or trust-boundary decoders not yet covered:

1. `mesh_protocol_decode`
2. `blocklist_snapshot_cursor_decode`
3. `config_parse_validation`
4. `admin_mutation_result_decode` if externally accepted
5. `plugin_manifest_signature_block`
6. `http_header_normalization` if distinct from path normalization
7. `ipc_message_decode` if safe to fuzz without full runtime

Example target skeleton:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = synvoid_mesh::decode_message(data);
});
```

Rules:

- Target must not open sockets.
- Target must not read arbitrary filesystem paths.
- Target must not require global runtime initialization.
- Decoder errors are expected; panics are failures.
- Bound allocations where possible.

## Phase E: Convert Crashes to Regression Tests

For every crash:

1. Save minimized input under `tests/fixtures/fuzz/` or relevant crate fixture path.
2. Add deterministic unit test reproducing safe behavior.
3. Fix parser to return typed error/no-op.
4. Re-run fuzz smoke.

Test naming:

```rust
#[test]
fn fuzz_regression_mesh_protocol_decode_case_001() {
    let input = include_bytes!("fixtures/fuzz/mesh_decode_001.bin");
    assert!(decode_message(input).is_err());
}
```

## Phase F: CI or Manual Smoke Workflow

Preferred CI job:

- optional/manual workflow_dispatch or nightly schedule,
- bounded `-runs=1000`,
- fail on crash,
- cache cargo-fuzz install if reasonable.

If PR CI runtime is too high, add manual workflow:

```yaml
on:
  workflow_dispatch:
```

Document manual command in `AGENTS.md`.

## Phase G: Documentation and Reports

Create `architecture/phase_14_fuzz_execution_report.md`.

Include:

```markdown
# Phase 14 Fuzz Execution Report

## Tooling
## Targets Inventory
## Smoke Runs
## Crashes / Fixes
## CI / Manual Workflow Status
## Residual Risks
```

Update:

- `architecture/ci_fuzz_failure_injection.md`
- `architecture/release_hardening_report.md` fuzz target count/status
- `AGENTS.md` quick commands

## Verification Commands

```bash
cargo fmt --all -- --check
cargo check --no-default-features --features mesh,dns
cargo check
cargo test --test failure_injection
cargo test --test docs_path_reference_guard
cargo fuzz run dns_message_decode -- -runs=1000
cargo fuzz run http_path_normalization -- -runs=1000
cargo fuzz run plugin_manifest -- -runs=1000
```

Plus any new targets added.

## Acceptance Criteria

This phase is complete when:

- Existing fuzz targets are smoke-run or the tooling blocker is explicitly documented.
- At least two missing high-priority parser boundary targets are added or documented with blockers.
- Any crashes are converted to regression tests.
- Fuzz execution status in release docs is truthful.
- CI/manual workflow exists for future bounded smoke runs.

## Handoff Notes

Prefer three useful fuzz targets that run reliably over ten targets that require full runtime state. Keep targets narrow, deterministic, and parser-focused.
