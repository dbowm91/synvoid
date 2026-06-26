# Control-Plane Error Taxonomy Hardening — Iteration 105

## Purpose

Iteration 103 introduced `SupervisorControlError`, but most handler failures are still normalized through a broad conversion:

```rust
fn boxed_error_to_control_error(e: Box<dyn std::error::Error>) -> SupervisorControlError {
    SupervisorControlError::RequestFailed(e.to_string())
}
```

That is structurally better than ad-hoc branch-local error handling, but it loses useful diagnostic detail. This phase should harden the error taxonomy for supervisor-control commands without changing CLI flags, command behavior, or supervisor IPC wire semantics.

## Non-Goals

Do not change supervisor IPC protocol.

Do not change command names or flags.

Do not change successful command output except where required to preserve existing behavior after typed data separation.

Do not add dependencies.

Do not move runtime-launch behavior.

Do not refactor one-shot commands.

Do not weaken guards from Iterations 101–104.

## Desired End State

After this phase:

- supervisor-control errors are classified into actionable categories;
- CLI output can distinguish connection failures from request/protocol failures;
- unsupported feature and auth-like failures have explicit variants if present;
- exit-code mapping is centralized and documented;
- conversions from existing handler errors preserve source messages;
- tests cover error classification and display without needing a live supervisor.

## Target Error Categories

Use only categories supported by current code. Candidate enum:

```rust
pub enum SupervisorControlError {
    ConnectionUnavailable(String),
    Timeout(String),
    Protocol(String),
    RequestRejected(String),
    Authentication(String),
    UnsupportedFeature(&'static str),
    Io(String),
    InvalidResponse(String),
    Unknown(String),
}
```

If authentication is not present, omit it or leave it reserved with no current use.

Avoid overfitting exact lower-level error strings unless no typed error exists.

## Phase 1 — Audit Existing Error Sources

Inspect:

```text
src/supervisor/commands.rs
src/commands/supervisor_control.rs
src/ipc/**
crates/synvoid-ipc/**
```

Map all errors returned by supervisor-control handlers:

```text
handler | lower-level error type | message examples | likely taxonomy variant | exit code
```

At minimum audit:

- status connection failure;
- stop connection failure;
- rehash request failure;
- threat-feed export filesystem/signing failure;
- unsupported mesh feature.

## Phase 2 — Refine `SupervisorControlError`

Update `src/commands/supervisor_control.rs`.

Replace or extend current variants:

```rust
ConnectionFailed(String)
RequestFailed(String)
UnsupportedFeature(&'static str)
Io(String)
```

with clearer categories. Keep backwards-compatible display style if tests or user output rely on it.

Suggested display messages:

```text
Connection unavailable: <message>
Control request timed out: <message>
Control protocol error: <message>
Control request rejected: <message>
Feature 'mesh' is not enabled
I/O error: <message>
Invalid control response: <message>
Unexpected control error: <message>
```

## Phase 3 — Implement Classification Helpers

Replace the broad converter with classification helpers.

Suggested shape:

```rust
fn classify_control_error(e: Box<dyn std::error::Error>) -> SupervisorControlError {
    let msg = e.to_string();
    classify_control_error_message(msg)
}

fn classify_control_error_message(msg: String) -> SupervisorControlError {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("connection refused") || lower.contains("connect") {
        SupervisorControlError::ConnectionUnavailable(msg)
    } else if lower.contains("timeout") || lower.contains("timed out") {
        SupervisorControlError::Timeout(msg)
    } else if lower.contains("unauthorized") || lower.contains("forbidden") {
        SupervisorControlError::Authentication(msg)
    } else if lower.contains("invalid response") || lower.contains("decode") {
        SupervisorControlError::InvalidResponse(msg)
    } else {
        SupervisorControlError::RequestRejected(msg)
    }
}
```

Prefer typed downcasting if current lower-level errors expose typed variants. Use string classification only as a last-resort bridge.

## Phase 4 — Centralize Exit Codes

Keep `exit_code()` on `SupervisorControlError`, but make it explicit.

Suggested mapping:

```rust
ConnectionUnavailable | Timeout => 2
Authentication => 3
UnsupportedFeature => 4
Protocol | InvalidResponse => 5
Io => 6
RequestRejected | Unknown => 1
```

If existing CLI compatibility expects every error to exit `1`, keep all errors at `1` for now and document the future mapping. Do not silently change exit codes without tests.

Preferred conservative approach for this pass:

- all errors still return `1`;
- docs explicitly say variant-specific exit codes are deferred until compatibility review.

## Phase 5 — Tests

Add unit tests in `src/commands/supervisor_control.rs`.

Suggested tests:

```rust
#[test]
fn classifies_connection_refused_as_connection_unavailable() { ... }

#[test]
fn classifies_timeout_as_timeout() { ... }

#[test]
fn classifies_invalid_response_as_invalid_response() { ... }

#[test]
fn unsupported_feature_display_is_stable() { ... }

#[test]
fn all_errors_have_documented_exit_code() { ... }
```

Keep tests deterministic; do not require live IPC.

## Phase 6 — Source Guards

Extend `tests/cli_command_dispatch_guard.rs`.

Guard against the old broad helper name/shape:

```rust
assert!(!source.contains("boxed_error_to_control_error"));
```

Or guard that a classifier exists:

```rust
assert!(source.contains("classify_control_error"));
```

Also guard that `SupervisorControlError` contains at least `Connection` and `Timeout` variants.

## Phase 7 — Documentation

Update:

```text
architecture/cli_supervisor_command_dispatch.md
plans/roadmap.md only if recording completed phase status
AGENTS.md if command error semantics are mentioned
```

Document:

- error classification is typed;
- exit-code mapping remains centralized;
- compatibility decision for per-error exit codes.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test -p synvoid supervisor_control
cargo test --test cli_command_dispatch_guard
```

Recommended:

```bash
cargo test -p synvoid commands
cargo test command_dispatch
cargo test supervisor_commands
```

## Acceptance Criteria

This phase is complete when:

- supervisor-control errors have actionable typed categories;
- broad `RequestFailed(String)` catch-all is no longer the default for all handler errors;
- tests cover classification and display;
- exit-code mapping is centralized and compatibility-safe;
- guards prevent regression to the old broad converter;
- supervisor IPC semantics remain unchanged.

## Expected Files To Touch

Likely:

```text
src/commands/supervisor_control.rs
tests/cli_command_dispatch_guard.rs
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
```

Possibly:

```text
src/supervisor/commands.rs
crates/synvoid-ipc/**
```

Avoid touching:

```text
src/main.rs
src/commands/plan.rs
src/commands/execute.rs except import/display updates
crates/synvoid-http/**
crates/synvoid-http3/**
src/worker/unified_server/**
```

## Handoff Summary

Iteration 105 should make supervisor-control failures diagnosable. Classify connection, timeout, protocol, unsupported-feature, I/O, and invalid-response failures with typed variants, keep exit-code mapping centralized and compatibility-safe, and test classification without live supervisor dependencies.
