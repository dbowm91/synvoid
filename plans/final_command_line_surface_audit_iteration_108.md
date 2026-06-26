# Final Command-Line Surface Audit — Iteration 108

## Purpose

This is the closing phase for the command/supervisor cleanup line.

By this point, the expected state is:

- `src/main.rs` is thin;
- command planning is typed;
- supervisor-control commands have typed outcomes/errors;
- runtime launch has a typed launch boundary;
- one-shot commands have typed outcomes/errors;
- source guards protect the major boundaries.

This phase should audit the complete CLI command surface for compatibility, precedence, mutual exclusion, feature gates, restart behavior, and exit-code documentation.

## Non-Goals

Do not introduce new commands.

Do not rename commands or flags.

Do not change supervisor IPC protocol.

Do not do architecture extraction unless needed to fix a discovered CLI-surface bug.

Do not alter HTTP/mesh/worker runtime internals beyond command-surface compatibility fixes.

## Desired End State

After this phase:

- every major command class has planner tests;
- invalid combinations have explicit behavior;
- restart combinations are defined and tested;
- mesh-gated commands are tested with and without mesh where practical;
- exit-code expectations are documented;
- command-dispatch docs match implementation;
- this command/supervisor cleanup line can be considered closed.

## Phase 1 — Inventory CLI Flags And Commands

Inspect:

```text
crates/synvoid-cli/src/**
src/commands/plan.rs
src/commands/execute.rs
src/commands/supervisor_control.rs
src/commands/runtime_launch.rs
src/commands/one_shot.rs
architecture/cli_supervisor_command_dispatch.md
```

Build a table:

```text
flag/command | plan category | required args | feature gate | compatible flags | incompatible flags | expected exit code
```

Keep this in `architecture/cli_supervisor_command_dispatch.md` or a concise appendix if useful.

## Phase 2 — Define Precedence Rules Explicitly

Current planner order determines precedence for commands such as:

- `--configtest` with runtime flags;
- `--status` with `--restart`;
- `--stop` with worker mode flags;
- `--export-openapi` with config path;
- `--hash-token` with `--hash-cost`;
- mesh-gated commands without mesh.

Decide whether current precedence is intended or should reject conflicting combinations.

Conservative approach:

- preserve current behavior if users may rely on it;
- document precedence explicitly;
- reject only combinations already clearly invalid or dangerous.

## Phase 3 — Expand Planner Tests

Add tests for every command class and important combinations.

Required tests:

```rust
configtest_takes_precedence_or_rejects_runtime_flags()
status_with_control_addr_and_tls_preserved()
stop_with_control_addr_and_tls_preserved()
rehash_with_control_addr_and_tls_preserved()
restart_with_status_is_defined()
restart_with_stop_is_defined()
hash_token_cost_is_clamped()
export_threat_feed_mesh_gate()
worker_mode_mutual_exclusion_all_pairs_or_table_driven()
```

Prefer table-driven tests where possible.

## Phase 4 — Audit Exit Codes

Document and test exit-code classes.

Suggested doc section:

```text
Exit-code model:
0 = success
1 = generic command failure / validation failure
future: variant-specific control-plane failures remain intentionally collapsed to 1 until compatibility review
```

If Iteration 105 introduced variant-specific exit codes, document them here and test them.

## Phase 5 — Feature-Gate Matrix

Audit behavior with mesh disabled and mesh enabled.

Commands likely affected:

- `--genesis`;
- `--show-node-info`;
- `--export-threat-feed`;
- `--mesh-agent`.

Add tests using `#[cfg(feature = "mesh")]` / `#[cfg(not(feature = "mesh"))]` for planner classification or error behavior.

## Phase 6 — Guard Documentation Sync

Extend command guard tests so docs cannot drift from the implementation.

Suggested guards:

```rust
architecture_doc_lists_all_command_categories()
architecture_doc_mentions_restart_pre_action()
architecture_doc_mentions_runtime_launch_boundary()
architecture_doc_mentions_one_shot_boundary()
architecture_doc_mentions_supervisor_control_boundary()
```

Keep guards broad enough to avoid noisy failures from wording changes.

## Phase 7 — Manual Compatibility Checklist

Add a checklist to the architecture doc or this phase's implementation notes:

```bash
synvoid --help
synvoid --configtest
synvoid --export-openapi
synvoid --export-api-spec
synvoid --hash-token <token>
synvoid --checkregex '<pattern>'
synvoid --status
synvoid --stop
synvoid --rehash
synvoid --restart
synvoid --cpu-worker --cpu-worker-id 0
synvoid --unified-server-worker --unified-worker-id 0
```

For commands requiring config/supervisor availability, document if they were not run.

## Phase 8 — Final Docs Update

Update:

```text
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
architecture/root_module_ledger.md
plans/roadmap.md
```

Mark this line of work as closed when acceptance criteria pass.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test -p synvoid commands
cargo test --test cli_command_dispatch_guard
```

Recommended broader guard suite:

```bash
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test unified_worker_composition_root_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test http_request_pipeline_boundary_guard
```

Feature checks:

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-mesh --features mesh
```

## Acceptance Criteria

This phase is complete when:

- the command-line surface is documented;
- precedence and invalid combinations are tested or explicitly documented;
- restart combinations are defined and tested;
- mesh feature gates are tested;
- exit-code behavior is documented;
- all command-boundary guards pass;
- no command implementation logic exists in `src/main.rs`;
- the command/supervisor cleanup roadmap can be marked closed.

## Expected Files To Touch

Likely:

```text
src/commands/plan.rs
src/commands/*
tests/cli_command_dispatch_guard.rs
architecture/cli_supervisor_command_dispatch.md
architecture/root_module_ledger.md
AGENTS.md
plans/roadmap.md
```

Possibly:

```text
crates/synvoid-cli/src/**
```

Avoid touching unless a CLI compatibility bug requires it:

```text
src/main.rs
crates/synvoid-http/**
crates/synvoid-http3/**
src/worker/unified_server/**
crates/synvoid-mesh/**
```

## Handoff Summary

Iteration 108 is the closeout pass. It should not introduce a new architectural direction. Audit the command-line surface, lock in precedence and feature-gate behavior with tests, document exit semantics, and mark the command/supervisor cleanup line closed when guards and checks pass.
