# CLI and Supervisor Command Dispatch

This document describes the typed command dispatch architecture introduced in Iteration 101, refined in Iteration 102, extended with a typed result boundary in Iteration 103, separated from handler output in Iteration 104, and hardened with a typed error taxonomy in Iteration 105.

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
- **SupervisorControl**: IPC commands sent to a running instance (status, stop, rehash, export threat feed).
- **Runtime**: Long-running process launch (supervisor, unified server worker, CPU worker, mesh agent, WASM/YARA jail).

The `plan_command()` function is pure — it validates mutual exclusivity of worker modes, test mode requirements, and feature gates without I/O.

`--restart` is a typed pre-action (`CommandPreAction::RestartSupervisor`), not a standalone supervisor-control command. It preserves the control address and TLS setting from CLI args, executing a stop before the normal runtime launch.

### Supervisor Control Adapter Layer

Owned by: `src/commands/supervisor_control.rs`

Converts typed `SupervisorControlCommand` variants into data-returning handler calls and returns structured outcomes:

- `execute_supervisor_control_command()`: Dispatches to `handle_status_data`, `handle_stop_data`, `handle_rehash_data`, or `handle_export_threat_feed_data` and wraps results in `SupervisorControlOutcome` / `SupervisorControlError`.
- `execute_restart_pre_stop()`: Reuses the same stop adapter for restart pre-actions, ensuring no duplicated logic.
- `SupervisorControlOutcome`: Data-bearing success variants with centralized `exit_code()` and `display()` mapping:
  - `Status(SupervisorStatusDisplay)` — carries formatted status text
  - `Stop(StopOutcome)` — carries acknowledged/shutdown_confirmed/timed_out flags
  - `Rehash(RehashOutcome)` — carries acknowledged flag
  - `ThreatFeedExported(ThreatFeedExportSummary)` — carries byte count and optional record count
  - `RestartPreStopRequested` — silent pre-action
- `SupervisorControlError`: Typed error variants with centralized `exit_code()` mapping:
  - `ConnectionUnavailable(String)` — could not connect to the supervisor (no socket, no running instance, connection refused)
  - `Timeout(String)` — the control request timed out
  - `Protocol(String)` — protocol-level error (send failed, serialization error)
  - `RequestRejected(String)` — the supervisor rejected the request or returned an unexpected error
  - `Authentication(String)` — authentication or authorization failure
  - `UnsupportedFeature(&'static str)` — feature not available (e.g., missing feature gate)
  - `Io(String)` — an I/O error occurred
  - `InvalidResponse(String)` — supervisor returned an uninterpretable response
  - `Unknown(String)` — unclassified error (transitional; new errors should use a more specific variant)

  Error classification uses `classify_control_error()` which maps erased `Box<dyn Error>` messages to typed variants via pattern matching on the lowercased message text. All variants currently return exit code 1 for backwards compatibility; variant-specific exit codes are deferred until a compatibility review.

### Handler Data Layer

Owned by: `src/supervisor/cli_commands.rs`

Handlers expose data-returning `_data` variants alongside print-based compatibility wrappers:

- `handle_status_data()` → `SupervisorStatusDisplay` — formats status into a string
- `handle_stop_data()` → `StopOutcome` — returns structured stop result
- `handle_rehash_data()` → `RehashOutcome` — returns structured rehash result
- `handle_export_threat_feed_data()` → `ThreatFeedExportSummary` — returns real byte metadata
- `handle_export_threat_feed()` — legacy print-based wrapper (preserved for backward compatibility)

### Execution Layer

Owned by: `src/commands/execute.rs`

Executes the planned command by calling into existing runtime/supervisor modules:

- `execute_one_shot()`: Config validation, OpenAPI export, genesis key generation, token operations, regex check.
- `execute_supervisor_control()`: Delegates to the typed adapter, maps outcomes/errors to exit codes, prints `outcome.display()` when non-None.
- `execute_runtime()`: Runtime launch via existing `run_supervisor_mode()`, `run_cpu_worker()`, etc.

Pre-actions (e.g., restart pre-stop) are executed before the main plan dispatch using the same typed adapter as normal stop.

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
| `--status` | SupervisorControl | `handle_status_data()` via typed adapter |
| `--stop` | SupervisorControl | `handle_stop_data()` via typed adapter |
| `--restart` | Pre-action | `execute_restart_pre_stop()` + sleep → Runtime |
| `--rehash` | SupervisorControl | `handle_rehash_data()` via typed adapter |
| `--export-threat-feed` | SupervisorControl | `handle_export_threat_feed_data()` via typed adapter |
| `--cpu-worker` | Runtime | `run_cpu_worker()` |
| `--unified-server-worker` | Runtime | `run_unified_server_worker()` |
| `--mesh-agent` | Runtime | `run_mesh_agent_mode()` |
| `--wasm-jail` | Runtime | `run_wasm_jail_mode()` |
| `--yara-jail` | Runtime | `run_yara_jail_mode()` |
| (default) | Runtime | `run_supervisor_mode()` |

## Pre-Actions

Pre-actions are operations executed before the main command plan. Currently the only pre-action is `RestartSupervisor`, which:

1. Sends a stop command to the existing supervisor via the typed adapter (preserving `control_addr` and `control_api_tls` from CLI args).
2. Waits 1 second for the process to exit.
3. Proceeds with the normal runtime launch (typically `RuntimeCommand::Supervisor`).

```rust
pub enum CommandPreAction {
    RestartSupervisor {
        control_addr: Option<String>,
        use_tls: bool,
    },
}
```

## Guards

- `tests/cli_command_dispatch_guard.rs`: Ensures `src/main.rs` remains thin (<=30 lines), uses `plan_command()`/`execute_command()`, does not contain command implementations, uses typed `CommandPreAction` for restart, does not force TLS=false during restart pre-stop, uses typed supervisor-control exit mapping, restart pre-stop uses the typed adapter, `SupervisorControlOutcome` uses data-bearing variants, `execute.rs` delegates formatting through `outcome.display()`, `supervisor_control.rs` does not use placeholder `ThreatFeedExported { bytes: 0 }`, `SupervisorControlError` has `ConnectionUnavailable` and `Timeout` variants, and `supervisor_control.rs` uses `classify_control_error` (not the old `boxed_error_to_control_error`).
- `tests/root_module_ledger_guard.rs`: Ensures `commands` is recorded in `architecture/root_module_ledger.md`.
