---
name: supervisor
description: Supervisor process lifecycle — spawns/monitors UnifiedServerWorker + CPU worker, owns IPC, control-plane gRPC API, drain/shutdown, CLI command handling.
---

# Skill: Supervisor Process Lifecycle

## Context

SynVoid runs as Supervisor (control plane) → UnifiedServerWorker (data plane) + CPU worker
(offload). The Supervisor is NOT process-per-tenant. Full reference:
`architecture/supervisor.md`, `architecture/supervisor_lifecycle.md`,
`architecture/process_lifecycle.md`, `architecture/ipc_process.md`.
Subsystem rules: `src/supervisor/AGENTS.override.md`.

## When to Use

Use this skill when:
- Changing process spawn/supervision/restart behavior
- Modifying supervisor ↔ worker IPC messages or signing
- Working on the gRPC control-plane API (`--status`, `--rehash`, `--stop`)
- Touching drain-aware shutdown or exit-code mapping
- Adding CLI operational flags (see also the `cli_dispatch` area in `src/commands/`)

## Key Files

| File | Purpose |
|------|---------|
| `src/supervisor/process.rs` | Core Supervisor: child spawn/monitor loop |
| `src/supervisor/state.rs` | Shared supervisor state |
| `src/supervisor/ipc.rs` | IPC server: worker connections, message routing |
| `src/supervisor/api.rs` | gRPC control-plane service |
| `src/supervisor/cli_commands.rs` | Operational command handlers (`--status`, `--stop`, ...) |
| `src/supervisor/mesh.rs` | Mesh agent-mode composition |
| `src/supervisor/drain_manager.rs` | Drain-aware shutdown coordination |
| `src/supervisor/task_registry.rs` | Supervised task registry |
| `src/process/manager.rs` | Child process manager (passes `--worker` etc.) |
| `src/commands/{plan,execute,runtime_launch}.rs` | CLI arg → runtime command planning/dispatch |

## Invariants

1. **IPC signing**: inter-process messages are signed with replay protection
   (`SYNVOID_IPC_KEY`, 32 bytes hex). See the `ipc_hardening` skill before touching IPC.
2. **Exit codes**: worker shutdown causes map through `WorkerShutdownCause::exit_code()`;
   only the worker composition root may call `std::process::exit()`.
3. **Config path**: `--config-path` takes the DIRECTORY containing `main.toml` + `sites/`.
4. The legacy `BaseWorkerProcess` (`src/process/worker.rs`) is retained for non-HTTP
   legacy paths; HTTP serving happens exclusively in UnifiedServerWorker.

## Verification

```bash
cargo nextest run --test worker_supervision_control_flow --features mesh,dns --cargo-profile ci --profile ci -- --test-threads=1
cargo xtask test guards
```
