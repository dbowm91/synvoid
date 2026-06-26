# One-Shot Command Result Boundary — Iteration 107

## Purpose

One-shot commands are still handled as direct match branches that print and return raw `i32` values. This was acceptable during the initial command-dispatch extraction, but it leaves one-shot command behavior less structured than supervisor-control commands.

This phase should introduce a typed result/error boundary for one-shot commands while preserving CLI output and exit semantics.

## Non-Goals

Do not change command names or flags.

Do not change generated token/hash formats.

Do not change config validation semantics.

Do not change OpenAPI/API spec output schemas.

Do not change mesh genesis/node-info semantics.

Do not refactor supervisor-control or runtime-launch boundaries except import updates.

Do not add dependencies.

## Current One-Shot Commands

Current one-shot command set:

- config test;
- export OpenAPI schema;
- export API spec;
- genesis key generation;
- show node info;
- generate token;
- generate new token;
- hash token;
- check regex.

## Desired End State

After this phase:

- one-shot commands return typed outcomes/errors;
- display formatting and exit-code mapping are centralized;
- tests can verify command outcomes without relying on terminal output where practical;
- `execute.rs` delegates one-shot behavior to a one-shot adapter module;
- behavior remains compatible.

## Candidate Module Shape

Add:

```text
src/commands/one_shot.rs
```

Suggested types:

```rust
pub enum OneShotOutcome {
    ConfigValid,
    OpenApiJson(String),
    ApiSpecJson(String),
    GenesisKeyGenerated { display: String },
    NodeInfo { display: String },
    TokenGenerated { token: String },
    NewTokenGenerated,
    TokenHash { hash: String },
    RegexCheck { safe: bool, display: String },
}

pub enum OneShotError {
    ConfigInvalid(String),
    Serialization(String),
    UnsupportedFeature(&'static str),
    Io(String),
    TokenHash(String),
    RegexUnsafe(String),
    Unknown(String),
}
```

Keep names aligned with project conventions.

## Phase 1 — Audit Current One-Shot Output

Inspect:

```text
src/commands/execute.rs
src/supervisor/commands.rs
src/admin/**
src/mesh/**
src/config/**
src/utils/**
```

For each command, record:

```text
command | current function | stdout | stderr | exit success | exit failure | feature gates
```

Do not refactor during audit.

## Phase 2 — Introduce Outcome/Error Types

Add `OneShotOutcome` and `OneShotError` with:

```rust
impl OneShotOutcome {
    pub fn exit_code(&self) -> i32 { ... }
    pub fn display(&self) -> Option<String> { ... }
}

impl OneShotError {
    pub fn exit_code(&self) -> i32 { ... }
}
```

Conservative exit mapping:

- success outcomes: `0`;
- unsafe regex or validation failure: preserve existing nonzero behavior;
- errors: `1` unless current behavior is otherwise documented.

## Phase 3 — Move Execution Into One-Shot Adapter

Add:

```rust
pub fn execute_one_shot_command(
    command: OneShotCommand,
) -> Result<OneShotOutcome, OneShotError>
```

Move command bodies from `execute.rs` into `one_shot.rs`. Keep existing helper functions private to `one_shot.rs`.

`execute.rs` should reduce to:

```rust
fn execute_one_shot(command: OneShotCommand) -> i32 {
    match execute_one_shot_command(command) {
        Ok(outcome) => { print display; outcome.exit_code() }
        Err(err) => { eprintln!(...); err.exit_code() }
    }
}
```

## Phase 4 — Preserve Output Compatibility

For commands where output is an API contract, preserve exact output:

- `--hash-token` should print only the hash on success;
- `--export-openapi` and `--export-api-spec` should print JSON only;
- `--checkregex` should preserve safe/unsafe text unless intentionally changed;
- token generation output should remain compatible with existing user expectations.

If exact output is not easy to test, add snapshot-like string tests for the new formatter functions.

## Phase 5 — Tests

Add unit tests in `src/commands/one_shot.rs` for pure formatting/outcomes.

Suggested tests:

```rust
#[test]
fn token_hash_outcome_prints_hash_only() { ... }

#[test]
fn regex_safe_exits_zero() { ... }

#[test]
fn regex_unsafe_exits_nonzero() { ... }

#[test]
fn openapi_outcome_prints_json_payload() { ... }
```

Do not require live supervisor or network.

## Phase 6 — Source Guards

Extend `tests/cli_command_dispatch_guard.rs`.

Forbid one-shot implementation details in `execute.rs`:

```rust
let forbidden = [
    "schema_for!",
    "synvoidOpenApi::openapi_json",
    "hash_admin_token_with_cost",
    "check_regex_complexity",
    "GenesisKeyConfig::generate",
];
```

Require:

```rust
assert!(source.contains("execute_one_shot_command"));
```

## Phase 7 — Documentation

Update:

```text
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
architecture/root_module_ledger.md
```

Required doc note:

- one-shot commands have a typed result/error boundary;
- output formatting and exit codes are centralized;
- `execute.rs` delegates one-shot execution.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test -p synvoid one_shot
cargo test --test cli_command_dispatch_guard
```

Recommended:

```bash
cargo test -p synvoid commands
cargo test command_dispatch
```

Feature checks if mesh one-shot commands are touched:

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-mesh --features mesh
```

## Acceptance Criteria

This phase is complete when:

- one-shot commands flow through typed outcomes/errors;
- `execute.rs` no longer owns one-shot implementation details;
- output compatibility is preserved for JSON/hash/token/regex commands;
- tests cover key outcome formatting and exit codes;
- guards prevent one-shot implementation details from returning to `execute.rs`.

## Expected Files To Touch

Likely:

```text
src/commands/one_shot.rs
src/commands/execute.rs
src/commands/mod.rs
tests/cli_command_dispatch_guard.rs
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
architecture/root_module_ledger.md
```

Possibly:

```text
src/supervisor/commands.rs
src/mesh/**
src/admin/**
```

Avoid touching:

```text
src/main.rs
src/commands/plan.rs except import updates
src/commands/supervisor_control.rs
src/commands/runtime_launch.rs
crates/synvoid-http/**
src/worker/unified_server/**
```

## Handoff Summary

Iteration 107 should give one-shot commands the same structured treatment as supervisor-control commands. Move one-shot bodies behind `execute_one_shot_command()`, centralize formatting/exit codes, preserve existing output contracts, and guard `execute.rs` against regrowing command details.
