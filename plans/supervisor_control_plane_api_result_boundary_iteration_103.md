# Supervisor Control-Plane API Result Boundary — Iteration 103

## Purpose

This phase is the next roadmap item after the CLI command dispatch corrective pass.

Iteration 101 moved command classification/execution out of `src/main.rs` and into `src/commands`. Iteration 102 should correct restart/hash-token planning details. After that, the next architectural seam is the boundary between command execution and supervisor-control APIs.

The goal of this phase is to make supervisor-control command execution typed, auditable, and testable without changing supervisor IPC semantics.

Today, command execution calls existing handlers such as:

```rust
handle_status(...)
handle_stop(...)
handle_rehash(...)
handle_export_threat_feed(...)
```

Those handlers likely print directly, return generic errors, and mix user-facing output formatting with control-plane request/response handling. This phase should introduce a typed result boundary so CLI command execution can handle status/stop/rehash/export/restart outcomes consistently.

## Relationship To Prior Phases

This phase depends on:

- Iteration 101 command-dispatch extraction being present;
- Iteration 102 restart/hash-token corrective pass being applied.

Do not start this phase until restart planning preserves control address/TLS correctly.

## Problem Statement

The CLI command dispatcher should not need to understand the details of supervisor IPC, response text, or per-command formatting. Conversely, supervisor-control handlers should not be forced to decide process exit codes directly.

The desired boundary is:

```text
SupervisorControlCommand -> typed supervisor request -> typed command outcome -> CLI formatting/exit code
```

rather than:

```text
SupervisorControlCommand -> handler prints and returns generic Result -> dispatcher maps loosely to 0/1
```

## Non-Goals

Do not change CLI command names.

Do not change supervisor IPC wire protocol unless an existing internal type can be reused without compatibility impact.

Do not change status/stop/rehash/export behavior.

Do not change restart semantics from Iteration 102.

Do not move supervisor runtime launch logic.

Do not move one-shot config/token/regex commands into this boundary.

Do not add dependencies.

Do not weaken the `main.rs` thin-entrypoint guard.

## Desired End State

After this pass:

- supervisor-control commands return typed outcomes rather than ad-hoc printed strings/generic errors where practical;
- command execution maps typed outcomes to exit codes in one place;
- user-facing formatting is centralized or clearly owned;
- restart pre-action uses the same typed supervisor-control operation as stop;
- tests cover command outcome-to-exit-code mapping without requiring a live supervisor;
- existing supervisor IPC behavior remains unchanged.

## Boundary Model

Use three conceptual layers.

### Command Plan Layer

Owned by:

```text
src/commands/plan.rs
```

Responsibilities:

- classify user intent;
- preserve control address/TLS/signing/site flags;
- avoid I/O.

This layer should remain mostly unchanged after Iteration 102.

### Supervisor Control Adapter Layer

Candidate owner:

```text
src/commands/supervisor_control.rs
```

or existing:

```text
src/supervisor/commands.rs
```

Responsibilities:

- convert a typed supervisor-control command into the existing supervisor IPC/helper call;
- return a typed outcome;
- not decide final process exit except by encoding success/failure in the outcome.

### CLI Execution Layer

Owned by:

```text
src/commands/execute.rs
```

Responsibilities:

- call supervisor-control adapter;
- format typed outcomes if not already formatted lower down;
- map outcome to exit code;
- keep restart pre-action behavior explicit.

## Phase 1 — Audit Existing Supervisor Command Handlers

Inspect:

```text
src/supervisor/commands.rs
src/commands/execute.rs
src/supervisor/**
src/ipc/**
crates/synvoid-ipc/**
```

List each supervisor-control command and current behavior:

```text
Command | Handler | Inputs | Output/printing | Error type | Exit behavior | IPC touched
```

At minimum audit:

- status;
- stop;
- restart pre-stop;
- rehash;
- export threat feed.

Do not refactor during audit except for comments.

## Phase 2 — Introduce Typed Outcome

Add a typed outcome enum near the command execution boundary.

Possible shape:

```rust
pub enum SupervisorControlOutcome {
    StatusDisplayed,
    StopRequested,
    RehashRequested,
    ThreatFeedExported { bytes: usize },
    RestartPreStopRequested,
}

impl SupervisorControlOutcome {
    pub fn exit_code(&self) -> i32 { 0 }
}
```

And a typed error:

```rust
pub enum SupervisorControlError {
    ConnectionFailed(String),
    RequestFailed(String),
    UnsupportedFeature(&'static str),
    Io(String),
}

impl SupervisorControlError {
    pub fn exit_code(&self) -> i32 { 1 }
}
```

If current handlers already expose an error type, wrap or reuse it rather than inventing a parallel hierarchy.

## Phase 3 — Add A Supervisor-Control Adapter Function

Add an adapter function that dispatches supervisor-control commands and returns typed outcomes.

Suggested shape:

```rust
pub fn execute_supervisor_control_command(
    command: SupervisorControlCommand,
) -> Result<SupervisorControlOutcome, SupervisorControlError> {
    match command {
        SupervisorControlCommand::Status { control_addr, use_tls } => {
            handle_status(control_addr, use_tls)
                .map_err(SupervisorControlError::from)?;
            Ok(SupervisorControlOutcome::StatusDisplayed)
        }
        SupervisorControlCommand::Stop { control_addr, use_tls } => {
            handle_stop(control_addr, use_tls)
                .map_err(SupervisorControlError::from)?;
            Ok(SupervisorControlOutcome::StopRequested)
        }
        // ...
    }
}
```

If handlers print internally, the outcome can initially mean “handler completed successfully.” Do not force a broad formatting rewrite in the first pass.

## Phase 4 — Use Typed Outcome In `execute.rs`

Update `src/commands/execute.rs` so supervisor-control handling becomes:

```rust
match execute_supervisor_control_command(command) {
    Ok(outcome) => outcome.exit_code(),
    Err(err) => {
        eprintln!("{}", err);
        err.exit_code()
    }
}
```

Do the same for restart pre-action if possible:

```rust
execute_supervisor_control_command(SupervisorControlCommand::Stop { control_addr, use_tls })?;
```

Do not duplicate stop logic between restart pre-action and normal stop.

## Phase 5 — Separate Formatting From Exit Mapping Where Practical

If current handlers print success details, leave them in place unless easy to centralize.

If some command returns data rather than printing, prefer:

```rust
pub enum SupervisorControlOutcome {
    Status { text: String },
    ThreatFeed { json: String },
    StopRequested,
    RehashRequested,
}
```

and centralize formatting:

```rust
pub fn print_supervisor_control_outcome(outcome: &SupervisorControlOutcome) { ... }
```

Do not overfit; preserve behavior over purity.

## Phase 6 — Tests Without Live Supervisor

Add tests for outcome-to-exit-code and error mapping without requiring a live supervisor.

Candidate tests:

```rust
#[test]
fn supervisor_control_success_outcomes_exit_zero() { ... }

#[test]
fn supervisor_control_errors_exit_nonzero() { ... }

#[test]
fn restart_pre_action_reuses_stop_supervisor_control_shape() { ... }
```

If command adapter calls live IPC directly and is hard to unit test, split the mapping layer from the actual call layer so tests can cover mapping without network/IPC.

## Phase 7 — Source Guards

Extend:

```text
tests/cli_command_dispatch_guard.rs
```

Add guards:

```rust
#[test]
fn supervisor_control_exit_mapping_is_typed() {
    let source = read("src/commands/execute.rs");
    assert!(source.contains("SupervisorControlOutcome") || source.contains("execute_supervisor_control_command"));
}
```

Add guard against duplicated restart stop logic if Iteration 102 introduced typed pre-actions:

```rust
#[test]
fn restart_pre_action_uses_supervisor_control_adapter() {
    let source = read("src/commands/execute.rs");
    assert!(!source.contains("handle_stop(control_addr, use_tls)") || source.contains("execute_supervisor_control_command"));
}
```

Keep guards low-noise. Do not make them dependent on exact formatting if possible.

## Phase 8 — Documentation

Update:

```text
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
architecture/root_module_ledger.md
```

Required doc note:

- `src/commands/plan.rs` owns classification;
- supervisor-control adapter owns command-to-handler mapping;
- typed outcomes/errors own exit-code mapping;
- `main.rs` remains thin.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test -p synvoid commands
cargo test --test cli_command_dispatch_guard
```

Supervisor/control focused checks if available:

```bash
cargo test supervisor_control
cargo test supervisor_commands
cargo test command_dispatch
```

Architecture guard checks:

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

If unrelated failures exist, document exact error text and confirm targeted tests pass.

## Acceptance Criteria

This phase is complete when:

- supervisor-control command execution returns typed outcomes/errors or a clearly equivalent structured result;
- `execute.rs` maps supervisor-control outcomes/errors to exit codes consistently;
- restart pre-action reuses the same stop/control adapter path as normal stop;
- tests cover exit-code mapping without a live supervisor;
- `src/main.rs` remains thin;
- supervisor IPC wire semantics and command behavior remain unchanged.

## Expected Files To Touch

Likely:

```text
src/commands/execute.rs
src/commands/plan.rs
src/commands/mod.rs
tests/cli_command_dispatch_guard.rs
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
```

Possibly:

```text
src/commands/supervisor_control.rs
src/supervisor/commands.rs
architecture/root_module_ledger.md
```

Avoid touching unless required:

```text
src/main.rs
crates/synvoid-http/**
crates/synvoid-http3/**
src/worker/unified_server/**
crates/synvoid-mesh/**
```

## Review Checklist

Reject or revise the implementation if:

- it changes supervisor IPC wire behavior;
- it changes CLI output substantially without tests;
- it moves command implementation back into `main.rs`;
- it makes planner tests require a live supervisor;
- it collapses one-shot commands into supervisor-control logic;
- it weakens Iteration 101/102 guards;
- it performs unrelated runtime/mesh/HTTP cleanup.

## Handoff Summary

After command planning is corrected, the next seam is supervisor-control result handling. Iteration 103 should keep existing supervisor command semantics while adding a typed result/error boundary, centralizing exit-code mapping, and ensuring restart pre-action uses the same supervisor-control adapter as normal stop.
