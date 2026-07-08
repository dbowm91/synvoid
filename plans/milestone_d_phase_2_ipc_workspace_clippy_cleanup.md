# Milestone D Phase 2: IPC and Remaining Workspace Clippy Cleanup

## Purpose

Close the remaining known clippy debt outside `synvoid-tunnel`, especially `synvoid-ipc` test-helper warnings, then move the workspace toward a clean `cargo clippy --all-targets --all-features -- -D warnings` gate.

Phase 1 owns tunnel-specific cleanup. This phase owns IPC and residual workspace-wide lint hygiene.

## Current issues

From workspace validation:

- `synvoid-ipc` test code clippy warnings:
  - `clone_on_copy`
  - `field_reassign_with_default`
- Additional workspace clippy output should be rechecked after Phase 1 because fixing tunnel may expose or unblock later warnings.

## Non-goals

- Do not rewrite IPC architecture.
- Do not add broad crate-level clippy allows.
- Do not weaken `-D warnings` gates.
- Do not refactor unrelated crates beyond mechanical clippy fixes.

## Workstream 1: Reproduce IPC warnings

Run:

```bash
cargo clippy -p synvoid-ipc --all-targets -- -D warnings
cargo clippy -p synvoid-ipc --all-targets --all-features -- -D warnings
```

Capture exact file/line/function for each warning.

## Workstream 2: Fix known IPC test warnings

### `clone_on_copy`

Preferred fix:

- remove `.clone()` on `Copy` values
- pass/copy values directly
- avoid changing ownership semantics for non-`Copy` types

### `field_reassign_with_default`

Preferred fix:

- construct the struct with update syntax:

```rust
let config = Config {
    field: value,
    ..Default::default()
};
```

Do not mutate default-initialized structs unless mutation is intentionally part of the test.

## Workstream 3: Workspace clippy sweep

After IPC and tunnel cleanup, run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

If all-features remains noisy due unsupported features, run supported feature profiles and document unsupported profiles separately.

Classify every warning:

- mechanical fix
- API-boundary allow justified
- unsupported feature profile
- generated/test-only code
- release blocker

## Workstream 4: Lint policy cleanup

Review any new `#[allow]` added during Phase 1/2.

Every allow must be:

- narrow: function/item-level preferred
- named exactly
- accompanied by a reason
- not masking safety or correctness warnings

Remove stale or incorrect allow attributes.

## Workstream 5: Update validation notes

If workspace clippy status changes, update or create:

- `plans/milestone_d_validation_results.md`, if final validation is also being run
- otherwise a phase-specific note under `plans/` only if failures remain

Record exact commands and outputs.

## Local validation commands

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-ipc --all-targets -- -D warnings
cargo test -p synvoid-ipc --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

If workspace all-features fails due known unsupported WireGuard before Phase 1 is complete, do not claim closure; rerun after Phase 1 lands.

## Success criteria

- `synvoid-ipc` clippy is clean under all-targets.
- Workspace default clippy is clean.
- Workspace all-targets/all-features clippy is clean or every remaining failure is explicitly outside supported release profiles.
- No broad clippy suppression is introduced.

## Handoff notes

This phase should be mostly mechanical. Any warning that appears to indicate a real correctness issue should be fixed as a product bug and called out in the commit message.
