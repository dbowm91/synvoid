# Runtime Launch Boundary Cleanup — Iteration 106

## Purpose

`src/commands/execute.rs` is now much smaller than the old `src/main.rs`, but it still owns detailed runtime-launch mechanics:

- panic handler setup;
- logging initialization;
- Tokio runtime construction;
- worker argument construction;
- PID file acquisition;
- calls into supervisor, CPU worker, unified worker, mesh agent, and jail modes.

This phase should move runtime-launch wiring into a typed boundary so command execution dispatches a `RuntimeCommand` into a launch plan/launcher without being the runtime composition expert.

## Non-Goals

Do not change runtime startup semantics.

Do not change worker thread defaults.

Do not change CPU affinity, worker ID, total worker, or reuse-port behavior.

Do not change supervisor PID handling.

Do not change panic handler setup behavior.

Do not change CLI flags.

Do not refactor supervisor-control or one-shot command output in this phase.

Do not add dependencies.

## Desired End State

After this phase:

- `execute.rs` delegates runtime launches to a typed launcher module;
- launch planning is testable without starting runtimes;
- runtime modes have structured launch inputs;
- behavior remains unchanged;
- `execute.rs` no longer directly builds Tokio runtimes or worker args.

## Candidate Module Shape

Add:

```text
src/commands/runtime_launch.rs
```

or, if preferred:

```text
src/runtime/launch.rs
```

Suggested API:

```rust
pub struct RuntimeLaunchContext {
    pub config_path: Option<PathBuf>,
    pub foreground: bool,
    pub test_flags: Option<Vec<String>>,
    pub cpu_worker_id: Option<usize>,
    pub unified_worker_id: Option<usize>,
    pub worker_threads: Option<usize>,
    pub cpu_affinity: Option<usize>,
    pub total_workers: Option<usize>,
    pub reuse_port: bool,
}

pub enum RuntimeLaunchPlan {
    Supervisor { config_path: Option<PathBuf>, foreground: bool, test_flags: Option<Vec<String>> },
    CpuWorker { args: CpuWorkerArgs },
    UnifiedServerWorker { args: UnifiedServerWorkerArgs, worker_threads: usize },
    MeshAgent { config_path: PathBuf, foreground: bool },
    WasmJail,
    YaraJail,
}

pub fn plan_runtime_launch(command: RuntimeCommand, ctx: &RuntimeLaunchContext) -> RuntimeLaunchPlan;
pub fn execute_runtime_launch(plan: RuntimeLaunchPlan) -> i32;
```

Use actual worker arg types and project naming.

## Phase 1 — Inventory Runtime Launch Responsibilities

Inspect:

```text
src/commands/execute.rs
src/startup/worker.rs
src/startup/bootstrap.rs
src/startup/daemon.rs
src/worker/**
src/supervisor/**
src/sandbox/**
```

Record current behavior for each runtime mode:

```text
mode | logging | panic handler | runtime threads | arg builder | blocking call | exit behavior
```

Do not refactor during inventory.

## Phase 2 — Introduce Runtime Launch Context

Move the runtime-specific fields from `CommandPlan` into a conversion method or context builder.

Example:

```rust
impl RuntimeLaunchContext {
    pub fn from_command_plan(plan: &CommandPlan) -> Self { ... }
}
```

Keep `CommandPlan` unchanged unless simplification is safe. The first pass can simply copy fields into context.

## Phase 3 — Add Runtime Launch Planner

Create `plan_runtime_launch()` that converts `RuntimeCommand + RuntimeLaunchContext` into a `RuntimeLaunchPlan`.

This function should not:

- build a Tokio runtime;
- launch a worker;
- acquire PID files;
- initialize logging;
- perform filesystem or network I/O.

It may construct plain argument structs if they are pure.

Add tests for:

- CPU worker args preserve ID/config;
- unified worker args preserve worker ID/thread count/affinity/reuse-port;
- supervisor launch preserves config/foreground/test flags;
- mesh agent default config path stays `config`.

## Phase 4 — Add Runtime Launch Executor

Move runtime-starting side effects into `execute_runtime_launch()`.

Preserve current behavior exactly:

- CPU worker uses 2 Tokio threads;
- unified worker uses requested or default worker thread count;
- supervisor acquires PID file before launch;
- test-mode warning prints before runtime launch;
- panic handlers are set for worker modes as before.

`execute.rs` should become:

```rust
fn execute_runtime(command: RuntimeCommand, plan: &CommandPlan) -> i32 {
    let ctx = RuntimeLaunchContext::from_command_plan(plan);
    let launch = plan_runtime_launch(command, &ctx);
    execute_runtime_launch(launch)
}
```

## Phase 5 — Add Typed Launch Outcome If Low Risk

If straightforward, introduce:

```rust
pub enum RuntimeLaunchOutcome {
    Completed,
    Failed(String),
}
```

But do not overdo this phase. Returning `i32` from the executor is acceptable if launch side effects are isolated and plan tests exist.

## Phase 6 — Guard `execute.rs`

Extend `tests/cli_command_dispatch_guard.rs`.

Forbid direct runtime-building details in `execute.rs`:

```rust
let forbidden = [
    "tokio::runtime::Builder",
    "build_cpu_worker_args",
    "build_unified_server_worker_args",
    "run_cpu_worker",
    "run_unified_server_worker",
    "acquire_pid_file",
];
```

Require adapter use:

```rust
assert!(source.contains("plan_runtime_launch"));
assert!(source.contains("execute_runtime_launch"));
```

Keep the existing `main.rs` guard intact.

## Phase 7 — Documentation

Update:

```text
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
architecture/root_module_ledger.md
```

Required doc note:

- `execute.rs` delegates runtime mode handling to the runtime-launch boundary;
- launch planning is pure/testable;
- launch execution owns runtime side effects.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test -p synvoid runtime_launch
cargo test --test cli_command_dispatch_guard
```

Recommended:

```bash
cargo test -p synvoid commands
cargo test command_dispatch
```

## Acceptance Criteria

This phase is complete when:

- runtime launch planning is represented by typed structs/enums;
- `execute.rs` no longer directly builds runtimes or worker args;
- launch planner tests cover all runtime modes;
- runtime behavior remains unchanged;
- guards prevent launch mechanics from drifting back into `execute.rs`.

## Expected Files To Touch

Likely:

```text
src/commands/execute.rs
src/commands/runtime_launch.rs
src/commands/mod.rs
tests/cli_command_dispatch_guard.rs
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
architecture/root_module_ledger.md
```

Possibly:

```text
src/startup/worker.rs
src/startup/bootstrap.rs
```

Avoid touching:

```text
src/main.rs
src/commands/plan.rs except import adjustments
src/commands/supervisor_control.rs
crates/synvoid-http/**
crates/synvoid-http3/**
src/worker/unified_server/**
```

## Handoff Summary

Iteration 106 should make runtime launch a typed boundary. Keep launch planning pure, launch execution side-effecting, and `execute.rs` thin. Preserve all existing runtime behavior while adding tests and guards around the new boundary.
