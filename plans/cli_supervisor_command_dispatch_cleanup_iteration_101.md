# CLI and Supervisor Command Dispatch Cleanup — Iteration 101

## Purpose

This phase is the next roadmap item after HTTP request pipeline normalization.

The previous phases reduced major runtime composition-root pressure:

- Iterations 91–92: root facade reduction and guardrails.
- Iterations 93–97: unified worker composition-root decomposition and mesh attachment cleanup.
- Iteration 98: data-plane service boundary finalization.
- Iterations 99–100: HTTP request pipeline normalization and doc/guard polish.

The next remaining root-gravity area is command dispatch: the binary entrypoint and supervisor command handling still appear to contain imperative command matching, one-off handler calls, and mixed command behavior. This phase should make CLI/supervisor command dispatch explicit, typed, and easier to test without changing command semantics.

## Current Context

The primary entrypoint is likely:

```text
src/main.rs
```

Related command handling likely spans:

```text
crates/synvoid-cli/**
src/supervisor/**
src/worker/**
src/startup/**
src/server/**
src/config/**
src/admin/**
src/mesh/**
src/dns/**
src/tls/**
```

The exact file set must be audited first. Do not guess command ownership before inspection.

Historical review noted that `src/main.rs` handles many command cases directly, including examples like:

- config validation;
- OpenAPI/export commands;
- genesis/node info commands;
- token generation/hash/check helpers;
- status/stop/rehash/export-threat-feed;
- restart;
- worker mode mutual-exclusion validation;
- dispatch into CPU worker, unified server worker, mesh agent, WASM/YARA jail, or supervisor.

This may have changed. Start from the current code.

## Problem Statement

The binary entrypoint should remain a thin process-level composition root. It should not accumulate business logic for every CLI and supervisor command.

The desired shape is:

```text
Args parse -> CommandPlan / Command enum -> handler -> exit result
```

rather than:

```text
Args parse -> large imperative match with mixed side effects in main.rs
```

This pass should make command dispatch explicit and testable while preserving existing behavior and compatibility.

## Non-Goals

Do not change command names.

Do not change CLI flags.

Do not change exit codes unless an existing bug is explicitly documented and tested.

Do not change supervisor IPC protocol semantics.

Do not change worker startup behavior.

Do not change systemd/deployment behavior unless it is part of an existing command path and can be isolated without behavior changes.

Do not move large runtime ownership into `synvoid-cli` if it would pull in server/worker internals unnecessarily.

Do not introduce new dependencies.

Do not perform broad root facade cleanup in this phase.

## Desired End State

After this pass:

- `src/main.rs` is a thin entrypoint.
- CLI command classification is centralized in one internal module or crate layer.
- Command handlers are grouped by responsibility.
- Supervisor-control commands have a clear boundary from runtime-start commands.
- Worker-mode dispatch has a typed plan/enum rather than scattered conditionals.
- Command validation is testable without launching server/worker runtime.
- Existing command behavior remains unchanged.
- Guard tests prevent `src/main.rs` from growing back into a broad command implementation bucket.

## Suggested Ownership Model

Use a layered model.

### CLI Parse Layer

Owned by:

```text
crates/synvoid-cli/**
```

Responsibilities:

- define `Args` / clap parser types;
- represent raw CLI flags;
- avoid depending on heavy runtime crates where possible.

### Command Planning Layer

Candidate owner:

```text
src/cli_dispatch.rs
```

or:

```text
src/commands/mod.rs
src/commands/plan.rs
src/commands/handlers.rs
```

Responsibilities:

- convert parsed `Args` into a typed command plan;
- validate mutually exclusive modes;
- classify command as one of:
  - one-shot local command;
  - supervisor-control command;
  - worker runtime command;
  - supervisor runtime command;
  - special diagnostic/export command.

### Command Execution Layer

Candidate owner:

```text
src/commands/execute.rs
```

Responsibilities:

- execute one-shot commands;
- call supervisor command APIs;
- call worker/supervisor runtime entrypoints;
- return a typed exit result.

### Runtime Layers

Existing worker/supervisor modules continue to own runtime behavior. The command dispatcher should call into them; it should not inline their logic.

## Phase 1 — Audit Current Command Dispatch

Inspect:

```text
src/main.rs
crates/synvoid-cli/src/**
src/supervisor/**
src/worker/**
src/startup/**
```

Identify every distinct command or dispatch branch.

Create a temporary table in the plan implementation notes or as comments in the new module:

```text
Command / Mode | Current branch | Side effects | Suggested owner | Behavior risk
```

Focus on current source, not old assumptions.

## Phase 2 — Introduce Typed Command Classification

Add a type such as:

```rust
pub enum SynvoidCommandPlan {
    OneShot(OneShotCommand),
    SupervisorControl(SupervisorControlCommand),
    Runtime(RuntimeCommand),
}

pub enum RuntimeCommand {
    Supervisor,
    UnifiedServerWorker,
    CpuWorker,
    MeshAgent,
    WasmJail,
    YaraJail,
}
```

Use actual current modes.

The classification function should be pure or mostly pure:

```rust
pub fn plan_command(args: &synvoid_cli::Args) -> Result<SynvoidCommandPlan, CommandPlanError>
```

If some validation needs config, split it:

```rust
pub fn plan_command_from_args(args: &Args) -> Result<InitialCommandPlan, CommandPlanError>
pub async fn resolve_command_plan(plan: InitialCommandPlan, env: CommandEnv) -> Result<SynvoidCommandPlan, CommandPlanError>
```

Keep the first pass simple.

## Phase 3 — Extract One-Shot Commands

Move one-shot command execution out of `main.rs` into focused helpers.

Likely one-shot classes:

- config test / config validation;
- OpenAPI/API spec export;
- genesis / node info;
- token generation/hash/check;
- regex validation;
- status / stop / restart / rehash / export threat feed if they do not launch the runtime.

Suggested shape:

```rust
pub enum OneShotCommand {
    ConfigTest,
    ExportOpenApi,
    ExportApiSpec,
    Genesis,
    ShowNodeInfo,
    GenerateToken,
    HashToken,
    CheckRegex,
}

pub async fn execute_one_shot(command: OneShotCommand, ctx: CommandExecutionContext) -> CommandResult
```

Do not invent new commands; map current commands only.

## Phase 4 — Extract Supervisor-Control Commands

Supervisor-control commands should be separated from commands that launch the supervisor runtime.

Suggested types:

```rust
pub enum SupervisorControlCommand {
    Status,
    Stop,
    Restart,
    Rehash,
    ExportThreatFeed,
}
```

Execution should call existing supervisor command APIs, not reimplement IPC.

If the existing APIs live in `synvoid::supervisor::commands`, preserve that owner and call it from the dispatcher.

Acceptance:

- supervisor-control commands are clearly distinct from supervisor runtime launch;
- `main.rs` does not manually perform supervisor-control command details.

## Phase 5 — Extract Runtime Dispatch

Runtime launch modes should be represented explicitly.

Suggested type:

```rust
pub enum RuntimeCommand {
    Supervisor,
    UnifiedServerWorker,
    CpuWorker,
    MeshAgent,
    WasmJail,
    YaraJail,
}
```

Execution should remain a thin call into existing runtime functions:

```rust
match runtime {
    RuntimeCommand::UnifiedServerWorker => run_unified_server_worker(args).await,
    RuntimeCommand::CpuWorker => run_cpu_worker(args).await,
    RuntimeCommand::Supervisor => run_supervisor(args).await,
    // etc.
}
```

The key improvement is not fewer lines alone; it is that runtime mode selection is typed and testable.

## Phase 6 — Make `main.rs` Thin

Target shape:

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = synvoid_cli::Args::parse();
    let plan = synvoid::commands::plan_command(&args)?;
    synvoid::commands::execute_command(plan, args).await?;
    Ok(())
}
```

Exact error type and runtime macro should follow existing project conventions.

`main.rs` may still own:

- logger/tracing process initialization if that is currently process-level;
- panic hook setup;
- top-level tokio runtime attribute;
- final exit-code conversion.

`main.rs` should not own:

- detailed command implementations;
- large command match branches;
- worker mode compatibility logic beyond calling planner;
- supervisor-control command body.

## Phase 7 — Add Unit Tests For Planning

Add tests for command planning without launching runtimes.

Candidate test file:

```text
tests/cli_command_dispatch_guard.rs
```

or module tests inside the new command planning module.

Test classes:

- mutually exclusive worker modes reject;
- one-shot config/export commands classify as one-shot;
- supervisor-control commands classify separately from runtime supervisor launch;
- default invocation maps to expected runtime mode;
- worker mode flags map to correct runtime command.

Do not require network, ports, filesystem writes, or actual runtime startup.

## Phase 8 — Add Source Guard For `main.rs`

Add a source guard that keeps `src/main.rs` thin.

Suggested guard:

```rust
#[test]
fn main_rs_remains_thin_command_entrypoint() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/main.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(non_comment.contains("plan_command") || non_comment.contains("execute_command"));
    assert!(
        non_comment.lines().count() <= 180,
        "src/main.rs should remain a thin process entrypoint"
    );
    assert!(
        !non_comment.contains("match args") || non_comment.matches("match args").count() <= 1,
        "large imperative command matching should live in command dispatch modules, not main.rs"
    );
}
```

Set the line threshold after inspecting current file size. Do not make it unrealistically low in the first pass.

Add guard against forbidden command implementation tokens in `main.rs` if useful:

```rust
let forbidden = [
    "export_threat_feed",
    "generate_token",
    "hash_token",
    "run_unified_server_worker",
];
```

Only add tokens after verifying they are truly moved.

## Phase 9 — Documentation Updates

Update concise docs:

```text
AGENTS.md
src/worker/AGENTS.override.md
architecture/worker_data_plane_composition_root.md
```

Possibly add:

```text
architecture/cli_supervisor_command_dispatch.md
```

The doc should describe:

- parse layer;
- command planning layer;
- command execution layer;
- supervisor-control vs supervisor-runtime distinction;
- runtime-mode dispatch ownership.

Keep it short unless the implementation is complex enough to justify a standalone doc.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test cli_command
cargo test command_dispatch
```

If a new guard exists:

```bash
cargo test --test cli_command_dispatch_guard
```

Existing architecture guards:

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

If known unrelated failures exist, document exact error text and confirm targeted planner/guard tests pass.

## Acceptance Criteria

This phase is complete when:

- command classification is represented by typed plan enums or equivalent structured types;
- one-shot commands are handled outside `main.rs`;
- supervisor-control commands are distinct from supervisor-runtime launch;
- runtime-mode dispatch is explicit and testable;
- `main.rs` becomes a thin process entrypoint;
- planning tests cover major command classes and invalid combinations;
- source guards prevent `main.rs` from re-growing broad command logic;
- command behavior, names, flags, and exit semantics remain compatible.

## Expected Files To Touch

Likely:

```text
src/main.rs
src/commands/mod.rs
src/commands/plan.rs
src/commands/execute.rs
crates/synvoid-cli/src/**
tests/cli_command_dispatch_guard.rs
AGENTS.md
```

Possibly:

```text
src/supervisor/commands.rs
src/startup/**
src/worker/**
architecture/cli_supervisor_command_dispatch.md
src/worker/AGENTS.override.md
```

Avoid touching unless required:

```text
crates/synvoid-http/**
crates/synvoid-http3/**
src/worker/unified_server/mesh_attachment.rs
src/worker/unified_server/shutdown_executor.rs
src/worker/unified_server/supervision_loop.rs
crates/synvoid-mesh/**
```

## Review Checklist

Reject or revise the implementation if:

- it changes CLI flag names or command names without explicit tests;
- it changes supervisor IPC semantics;
- it changes worker runtime startup behavior;
- it introduces network/port/runtime side effects into planner unit tests;
- it moves heavy runtime dependencies into `synvoid-cli` unnecessarily;
- it weakens previous architecture guard tests;
- it performs unrelated HTTP, mesh, or data-plane cleanup.

## Handoff Summary

Iteration 101 should reduce command-dispatch root gravity. Keep the binary entrypoint thin, introduce typed command planning, separate one-shot commands from supervisor-control commands and runtime launch commands, and add tests/guards that make command classification stable without launching full runtimes.
