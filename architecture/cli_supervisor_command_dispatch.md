# CLI and Supervisor Command Dispatch

This document describes the typed command dispatch architecture introduced in Iteration 101, refined in Iteration 102, extended with a typed result boundary in Iteration 103, separated from handler output in Iteration 104, hardened with a typed error taxonomy in Iteration 105, cleaned up with a runtime-launch boundary in Iteration 106, given a typed one-shot result boundary in Iteration 107, audited for completeness in Iteration 108, and locked down for output compatibility in Iteration 109.

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

- `execute_one_shot()`: Delegates to the one-shot adapter, maps outcomes/errors to exit codes, prints `outcome.display()` when non-None.
- `execute_supervisor_control()`: Delegates to the typed adapter, maps outcomes/errors to exit codes, prints `outcome.display()` when non-None.
- `execute_runtime()`: Delegates to the runtime-launch boundary for all runtime mode handling.

`execute.rs` no longer directly builds Tokio runtimes, constructs worker args, acquires PID files, or initializes logging. These responsibilities are owned by the runtime-launch boundary.

`execute.rs` no longer owns one-shot command implementation details. These are owned by the one-shot adapter layer.

Pre-actions (e.g., restart pre-stop) are executed before the main plan dispatch using the same typed adapter as normal stop.

### One-Shot Adapter Layer

Owned by: `src/commands/one_shot.rs`

Introduced in Iteration 107 to provide a typed result/error boundary for one-shot commands:

- `execute_one_shot_command()`: Dispatches to existing one-shot handlers and wraps results in `OneShotOutcome` / `OneShotError`.
- `OneShotOutcome`: Data-bearing success variants with centralized `exit_code()` and `display()` mapping:
  - `ConfigValid` — config validation passed
  - `OpenApiJson(String)` — OpenAPI schema exported as JSON
  - `ApiSpecJson(String)` — API specification exported as JSON
  - `GenesisKeyGenerated { display }` — genesis key generated
  - `NodeInfo { display }` — node information queried
  - `TokenGenerated { token }` — admin token generated
  - `NewTokenGenerated { token, config_path }` — admin token generated and saved to config
  - `TokenHash { hash }` — token hashed with bcrypt
  - `RegexCheck { safe, pattern, reason }` — regex checked for ReDoS safety
- `OneShotError`: Typed error variants with centralized `exit_code()` and `Display` mapping:
  - `ConfigInvalid(String)` — config validation failed
  - `Serialization(String)` — JSON serialization failed
  - `UnsupportedFeature(&'static str)` — missing feature gate
  - `Io(String)` — an I/O error occurred
  - `TokenHash(String)` — bcrypt hashing failed
  - `RegexUnsafe(String)` — regex check error
  - `Unknown(String)` — unclassified error

The guard test `execute_rs_does_not_contain_one_shot_implementation_details` ensures `execute.rs` does not contain one-shot implementation details (`schema_for!`, `synvoidOpenApi::openapi_json`, `hash_admin_token_with_cost`, `check_regex_complexity`, `GenesisKeyConfig::generate`).

### Runtime-Launch Boundary

Owned by: `src/commands/runtime_launch.rs`

Introduced in Iteration 106 to separate runtime-launch planning (pure, testable) from runtime-launch execution (side-effecting):

- `RuntimeLaunchContext`: Structured launch inputs derived from `CommandPlan`. Carries only the fields needed for runtime launch decisions.
- `RuntimeLaunchPlan`: Pure description of what to launch, one variant per runtime mode. Each variant carries the exact inputs needed to start that mode.
- `RuntimeLaunchOutcome`: Typed result of a launch attempt (`Completed` / `Failed(String)`).
- `plan_runtime_launch()`: Converts `RuntimeCommand + RuntimeLaunchContext` into a `RuntimeLaunchPlan`. **Pure** — no Tokio runtime construction, no PID files, no logging, no I/O.
- `execute_runtime_launch()`: Performs all side effects (runtime build, PID file, logging, panic handlers). Returns `RuntimeLaunchOutcome`.
- `execute_runtime()`: Thin bridge called by `execute.rs` that handles test-mode warnings, then delegates to the planner and launcher.

```text
execute.rs::execute_runtime(cmd, plan)
  -> runtime_launch::execute_runtime(cmd, plan)
    -> plan_runtime_launch(cmd, &ctx)  // pure
    -> execute_runtime_launch(plan)    // side-effecting
```

The guard test `execute_rs_does_not_build_runtimes_or_worker_args` ensures `execute.rs` does not contain runtime-building details (`tokio::runtime::Builder`, `build_cpu_worker_args`, etc.).

## Command Classification

| Command | Plan Category | Handler |
|---------|--------------|---------|
| `--configtest` | OneShot | `execute_one_shot_command()` via typed adapter |
| `--export-openapi` | OneShot | `execute_one_shot_command()` via typed adapter |
| `--export-api-spec` | OneShot | `execute_one_shot_command()` via typed adapter |
| `--genesis` | OneShot | `execute_one_shot_command()` via typed adapter |
| `--show-node-info` | OneShot | `execute_one_shot_command()` via typed adapter |
| `--generatetoken` | OneShot | `execute_one_shot_command()` via typed adapter |
| `--generatenewtoken` | OneShot | `execute_one_shot_command()` via typed adapter |
| `--hash-token` | OneShot | `execute_one_shot_command()` via typed adapter |
| `--checkregex` | OneShot | `execute_one_shot_command()` via typed adapter |
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

## CLI Flag Inventory

Complete mapping of all CLI flags to their plan categories and behavior.

### One-Shot Flags

| Flag | Plan Category | Required Args | Feature Gate | Expected Exit Code |
|------|--------------|---------------|-------------|-------------------|
| `--configtest` | OneShot(ConfigTest) | none | none | 0 (valid) / 1 (invalid) |
| `--export-openapi` | OneShot(ExportOpenApi) | none | none | 0 |
| `--export-api-spec` | OneShot(ExportApiSpec) | none | none | 0 |
| `--genesis` | OneShot(Genesis) | none | mesh | 0 / 1 (no mesh) |
| `--show-node-info` | OneShot(ShowNodeInfo) | none | mesh | 0 / 1 (no mesh) |
| `--generatetoken` | OneShot(GenerateToken) | none | none | 0 |
| `--generatenewtoken` | OneShot(GenerateNewToken) | none | none | 0 |
| `--hash-token <token>` | OneShot(HashToken) | token value | none | 0 / 1 (missing token) |
| `--checkregex '<pattern>'` | OneShot(CheckRegex) | pattern string | none | 0 (safe) / 1 (unsafe) |

### Supervisor Control Flags

| Flag | Plan Category | Required Args | Feature Gate | Expected Exit Code |
|------|--------------|---------------|-------------|-------------------|
| `--status` | SupervisorControl(Status) | none | none | 0 (success) / 1 (error) |
| `--stop` | SupervisorControl(Stop) | none | none | 0 (success) / 1 (error) |
| `--rehash` | SupervisorControl(Rehash) | none | none | 0 (success) / 1 (error) |
| `--export-threat-feed` | SupervisorControl(ExportThreatFeed) | none | mesh | 0 (success) / 1 (error/no mesh) |

### Runtime Flags

| Flag | Plan Category | Required Args | Feature Gate | Expected Exit Code |
|------|--------------|---------------|-------------|-------------------|
| (default, no flags) | Runtime(Supervisor) | none | none | 0 (clean exit) |
| `--cpu-worker` | Runtime(CpuWorker) | none | none | 0 |
| `--unified-server-worker` | Runtime(UnifiedServerWorker) | none | none | 0 |
| `--mesh-agent` | Runtime(MeshAgent) | none | mesh | 0 |
| `--wasm-jail` | Runtime(WasmJail) | none | none | 0 |
| `--yara-jail` | Runtime(YaraJail) | none | none | 0 |

### Modifier Flags

| Flag | Effect | Compatible With | Incompatible With |
|------|--------|----------------|-------------------|
| `--restart` | Adds RestartSupervisor pre-action before main plan | All command categories | none (combines with any) |
| `--foreground` / `-f` | Runtime: run in foreground | Runtime commands | Supervisor control commands |
| `--test <flags>` | Runtime: test mode (requires --force) | Runtime commands | One-shot commands |
| `--force` | Required with --test | --test | none |
| `--control-addr <addr>` | Supervisor control: target address | Supervisor control, --restart | none |
| `--control-api-tls` | Supervisor control: use TLS | Supervisor control, --restart | none |
| `--config-path <path>` | Config: custom config directory | All | none |
| `--log-level <level>` | Runtime: log level override | Runtime commands | none |
| `--sign-with <path>` | Export threat feed: signing key | --export-threat-feed | none |
| `--site-id <id>` | Export threat feed: site filter | --export-threat-feed | none |
| `--hash-cost <n>` | Hash token: bcrypt cost (4-31, default 12) | --hash-token | none |
| `--cpu-worker-id <id>` | CPU worker: worker ID | --cpu-worker | none |
| `--unified-worker-id <id>` | Unified worker: worker ID | --unified-server-worker | none |
| `--worker-threads <n>` | Unified worker: Tokio threads | --unified-server-worker | none |
| `--cpu-affinity <core>` | Unified worker: pin to CPU core | --unified-server-worker | none |
| `--total-workers <n>` | Unified worker: pool size | --unified-server-worker | none |
| `--reuse-port` | Unified worker: shared port (hidden) | --unified-server-worker | none |

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

## Precedence Rules

The planner evaluates flags in a fixed priority order. When multiple flags are present, the first match in the if-else chain wins for the main plan. `--restart` is always processed as a pre-action regardless of the main plan.

### Evaluation Order

1. `--configtest` → OneShot(ConfigTest) — takes precedence over all other flags
2. `--export-openapi` → OneShot(ExportOpenApi)
3. `--export-api-spec` → OneShot(ExportApiSpec)
4. `--genesis` → OneShot(Genesis) [mesh gate]
5. `--show-node-info` → OneShot(ShowNodeInfo) [mesh gate]
6. `--generatetoken` → OneShot(GenerateToken)
7. `--hash-token` → OneShot(HashToken) — requires token value, cost clamped to 4-31
8. `--checkregex` → OneShot(CheckRegex)
9. `--generatenewtoken` → OneShot(GenerateNewToken)
10. `--status` → SupervisorControl(Status)
11. `--stop` → SupervisorControl(Stop)
12. `--rehash` → SupervisorControl(Rehash)
13. `--export-threat-feed` → SupervisorControl(ExportThreatFeed) [mesh gate]
14. `--cpu-worker` → Runtime(CpuWorker)
15. `--unified-server-worker` → Runtime(UnifiedServerWorker)
16. `--mesh-agent` → Runtime(MeshAgent)
17. `--wasm-jail` → Runtime(WasmJail)
18. `--yara-jail` → Runtime(YaraJail)
19. (default) → Runtime(Supervisor)

### Pre-Action Processing

`--restart` is processed after the main plan classification. It adds a `CommandPreAction::RestartSupervisor` pre-action that executes before the main plan dispatch. The pre-action preserves `control_addr` and `control_api_tls` from CLI args.

### Invalid Combinations

| Combination | Behavior |
|-------------|----------|
| Multiple worker modes (e.g., `--cpu-worker --unified-server-worker`) | Error: `MultipleWorkerModes` |
| `--test` without `--force` | Error: `TestModeRequiresForce` |
| `--hash-token` without token value | Error: `MissingHashToken` |
| `--genesis` without mesh feature | Error: `MeshFeatureRequired` |
| `--show-node-info` without mesh feature | Error: `MeshFeatureRequired` |
| `--export-threat-feed` without mesh feature | Error: `MeshFeatureRequired` |

### Explicitly Tested Combinations

These combinations have dedicated tests to ensure correct behavior:

- `--configtest` with `--cpu-worker` → configtest wins (OneShot)
- `--configtest` with `--restart` → one-shot with pre-action
- `--status` with `--control-addr` and `--control-api-tls` → values preserved
- `--stop` with `--control-addr` and `--control-api-tls` → values preserved
- `--rehash` with `--control-addr` and `--control-api-tls` → values preserved
- `--restart` with `--status` → pre-action + status plan
- `--restart` with `--stop` → pre-action + stop plan
- `--hash-token` with `--hash-cost 2` → cost clamped to 4
- `--hash-token` with `--hash-cost 100` → cost clamped to 31

## Exit Code Model

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success — command completed as expected |
| 1 | Generic failure — validation error, command error, or runtime error |

### Exit Code Classes

- **OneShotOutcome::exit_code()**: Returns 0 for all success variants except `RegexCheck { safe: false }` which returns 1.
- **OneShotError::exit_code()**: Returns 1 for all error variants.
- **SupervisorControlOutcome::exit_code()**: Returns 0 for all success variants.
- **SupervisorControlError::exit_code()**: Returns 1 for all error variants. Variant-specific exit codes are deferred until a compatibility review.
- **RuntimeLaunchOutcome::exit_code()**: Returns 0 for `Completed`, 1 for `Failed`.
- **CommandPlanError**: Mapped to exit code 1 at the process entrypoint (`src/main.rs`).
- **Process exit**: `src/main.rs` calls `std::process::exit(exit_code)` with the code returned by `execute_command()`.

### Design Note

All `SupervisorControlError` variants currently return exit code 1 for backwards compatibility. Variant-specific exit codes (e.g., connection unavailable → 2, timeout → 3) are intentionally deferred until a compatibility review confirms no downstream tooling depends on the current exit code values.

## Output Compatibility Contracts

Iteration 109 locks down stdout contracts for script-facing commands. Tests in `src/commands/one_shot.rs` enforce these invariants; guard tests in `tests/cli_command_dispatch_guard.rs` prevent regressions.

### Script-Facing Stdout Contracts

| Command | Stdout on Success | Stderr | Machine Contract |
|---------|------------------|--------|-----------------|
| `--export-openapi` | JSON only (no preamble) | errors | stdout is parseable JSON |
| `--export-api-spec` | JSON only (no preamble) | errors | stdout is parseable JSON |
| `--hash-token` | bcrypt hash only (single line, no label) | errors | stdout is the hash string |
| `--generatetoken` | hex token only (single line, no label) | errors | stdout is the token string |
| `--generatenewtoken` | token on first line, then config path and notes | errors + warnings | first line is the token |
| `--checkregex` | human-readable safe/unsafe text | errors | exit code 0 = safe, 1 = unsafe |
| `--configtest` | human-readable validation result | errors | exit code 0 = valid, 1 = invalid |

### Human-Facing Commands

| Command | Stdout on Success | Notes |
|---------|------------------|-------|
| `--genesis` | Multi-line text with genesis key and config instructions | Contains `genesis_key_base64` |
| `--show-node-info` | Multi-line text with node information | Contains `Node Information:` |
| `--export-threat-feed` | Binary/JSON feed data | Requires running supervisor |

### Stderr Policy

Stderr is reserved for errors and warnings. Successful command output goes to stdout only. Logging output (via `tracing`) goes to stderr and is not part of the stdout contract.

### Shape Tests

Output contract tests are in `src/commands/one_shot.rs` under the `#[cfg(test)]` module:

- `openapi_outcome_stdout_is_json_only` — validates JSON-only output for `--export-openapi`
- `api_spec_outcome_stdout_is_json_only` — validates JSON-only output for `--export-api-spec`
- `hash_token_outcome_stdout_is_hash_only` — validates hash-only output, no labels
- `generated_token_outcome_stdout_is_token_only` — validates token-only output, no labels
- `new_token_generated_first_line_is_token` — validates token-first-line for `--generatenewtoken`
- `regex_safe_display_contains_safe_label` / `regex_unsafe_display_contains_unsafe_label` — shape tests for regex output
- `regex_exit_codes_are_correct` — validates exit code contract for `--checkregex`
- `config_valid_exit_code_is_zero_and_no_contamination` — validates configtest output is not JSON/token/hash
- `genesis_key_generated_shape` / `node_info_shape` — shape tests for mesh-gated human commands

## Manual Compatibility Checklist

Commands that can be run without a running supervisor or config:

```bash
synvoid --help                                    # Expected: help text
synvoid --configtest                              # Expected: config validation
synvoid --export-openapi                          # Expected: OpenAPI JSON
synvoid --export-api-spec                         # Expected: API spec JSON
synvoid --hash-token "test123"                    # Expected: bcrypt hash
synvoid --checkregex '^[a-z]+$'                   # Expected: safe regex
synvoid --generatetoken                           # Expected: hex token
```

Commands requiring mesh feature:

```bash
synvoid --genesis                                 # Expected: genesis key (mesh feature required)
synvoid --show-node-info                          # Expected: node info (mesh feature required)
synvoid --export-threat-feed                      # Expected: threat feed (mesh feature required)
```

Commands requiring a running supervisor:

```bash
synvoid --status                                  # Expected: status display
synvoid --stop                                    # Expected: shutdown confirmation
synvoid --rehash                                  # Expected: rehash confirmation
synvoid --restart                                 # Expected: stop + restart
```

Runtime modes (require appropriate setup):

```bash
synvoid --cpu-worker --cpu-worker-id 0            # Expected: CPU worker launch
synvoid --unified-server-worker --unified-worker-id 0  # Expected: unified worker launch
synvoid --mesh-agent                              # Expected: mesh agent launch (mesh feature)
```

**Note**: Commands requiring a running supervisor or specific config were not run during this audit. The planner tests verify correct classification without requiring a live environment.

## Guards

- `tests/cli_command_dispatch_guard.rs`: Ensures `src/main.rs` remains thin (<=30 lines), uses `plan_command()`/`execute_command()`, does not contain command implementations, uses typed `CommandPreAction` for restart, does not force TLS=false during restart pre-stop, uses typed supervisor-control exit mapping, restart pre-stop uses the typed adapter, `SupervisorControlOutcome` uses data-bearing variants, `execute.rs` delegates formatting through `outcome.display()`, `supervisor_control.rs` does not use placeholder `ThreatFeedExported { bytes: 0 }`, `SupervisorControlError` has `ConnectionUnavailable` and `Timeout` variants, `supervisor_control.rs` uses `classify_control_error` (not the old `boxed_error_to_control_error`), `execute.rs` does not build runtimes or worker args, `execute.rs` delegates to the runtime-launch boundary, `runtime_launch.rs` exists with planner and executor, planner is pure (no Tokio builder/PID/logging), `commands/mod.rs` exports the runtime-launch types, `one_shot.rs` exists with `execute_one_shot_command`, `OneShotOutcome` and `OneShotError` are exported, `execute.rs` delegates to the one-shot adapter, `execute.rs` does not contain one-shot implementation details (`schema_for!`, `synvoidOpenApi::openapi_json`, `hash_admin_token_with_cost`, `check_regex_complexity`, `GenesisKeyConfig::generate`), `OneShotOutcome` has `exit_code()` and `display()` methods, `OneShotError` implements `Display` and has `exit_code()`. **Iteration 109**: source guards prevent human-preamble text (`OpenAPI schema:`, `Exported OpenAPI`, `API Schema`) in JSON display outputs, prevent labeled token/hash output (`"Hash:"`, `"Token:"`), and verify output contract documentation exists.
- `tests/root_module_ledger_guard.rs`: Ensures `commands` is recorded in `architecture/root_module_ledger.md`.
- Iteration 108 added precedence, combination, feature-gate, and cost-clamping tests to `src/commands/plan.rs` unit tests.
- Iteration 109 added output contract tests to `src/commands/one_shot.rs` (JSON-only, token-only, hash-only, regex shape, configtest contamination, genesis/node-info shape, generatenewtoken first-line).
