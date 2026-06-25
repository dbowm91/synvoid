# CLI and Supervisor Command Dispatch

This document describes the typed command dispatch architecture introduced in Iteration 101.

## Overview

The binary entrypoint (`src/main.rs`) is a thin process-level composition root. It parses CLI args, plans the command, and delegates execution to `src/commands/`.

```text
Args parse -> plan_command() -> CommandPlan -> execute_command() -> exit code
```

## Layers

### Parse Layer

Owned by: `crates/synvoid-cli/src/lib.rs`

Defines the Clap `Args` struct representing raw CLI flags. No business logic.

### Planning Layer

Owned by: `src/commands/plan.rs`

Classifies parsed `Args` into a typed `SynvoidCommandPlan`:

- **OneShot**: Commands that complete without launching the server (config test, export, genesis, token ops, regex check).
- **SupervisorControl**: IPC commands sent to a running instance (status, stop, restart, rehash, export threat feed).
- **Runtime**: Long-running process launch (supervisor, unified server worker, CPU worker, mesh agent, WASM/YARA jail).

The `plan_command()` function is pure — it validates mutual exclusivity of worker modes, test mode requirements, and feature gates without I/O.

### Execution Layer

Owned by: `src/commands/execute.rs`

Executes the planned command by calling into existing runtime/supervisor modules:

- `execute_one_shot()`: Config validation, OpenAPI export, genesis key generation, token operations, regex check.
- `execute_supervisor_control()`: IPC commands via existing `handle_status()`, `handle_stop()`, etc.
- `execute_runtime()`: Runtime launch via existing `run_supervisor_mode()`, `run_cpu_worker()`, etc.

## Command Classification

| Command | Plan Category | Handler |
|---------|--------------|---------|
| `--configtest` | OneShot | `handle_configtest()` |
| `--export-openapi` | OneShot | schema export |
| `--export-api-spec` | OneShot | OpenAPI export |
| `--genesis` | OneShot | `GenesisKeyConfig::generate()` |
| `--show-node-info` | OneShot | config reader |
| `--generatetoken` | OneShot | `handle_generatetoken()` |
| `--generatenewtoken` | OneShot | `handle_generatenewtoken()` |
| `--hash-token` | OneShot | `hash_admin_token_with_cost()` |
| `--checkregex` | OneShot | `check_regex_complexity()` |
| `--status` | SupervisorControl | `handle_status()` via IPC |
| `--stop` | SupervisorControl | `handle_stop()` via IPC |
| `--restart` | SupervisorControl | stop + sleep + runtime launch |
| `--rehash` | SupervisorControl | `handle_rehash()` via IPC |
| `--export-threat-feed` | SupervisorControl | `handle_export_threat_feed()` |
| `--cpu-worker` | Runtime | `run_cpu_worker()` |
| `--unified-server-worker` | Runtime | `run_unified_server_worker()` |
| `--mesh-agent` | Runtime | `run_mesh_agent_mode()` |
| `--wasm-jail` | Runtime | `run_wasm_jail_mode()` |
| `--yara-jail` | Runtime | `run_yara_jail_mode()` |
| (default) | Runtime | `run_supervisor_mode()` |

## Guards

- `tests/cli_command_dispatch_guard.rs`: Ensures `src/main.rs` remains thin (<=30 lines), uses `plan_command()`/`execute_command()`, and does not contain command implementations.
- `tests/root_module_ledger_guard.rs`: Ensures `commands` is recorded in `architecture/root_module_ledger.md`.
