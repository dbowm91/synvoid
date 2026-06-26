# Supervisor Handler Output/Data Separation — Iteration 104

## Purpose

Iteration 103 introduced a typed boundary between command execution and supervisor-control handlers:

```text
SupervisorControlCommand -> execute_supervisor_control_command()
    -> Result<SupervisorControlOutcome, SupervisorControlError>
    -> exit code
```

That boundary is structurally correct, but most underlying supervisor handlers still print internally and return generic results. `SupervisorControlOutcome` is therefore partly a typed shell around side-effecting handlers. The clearest example is `ThreatFeedExported { bytes: 0 }`, which is a placeholder rather than real export metadata.

This phase should separate supervisor handler output/data from CLI formatting while preserving existing command behavior and supervisor IPC semantics.

## Non-Goals

Do not change CLI command names or flags.

Do not change supervisor IPC wire protocol.

Do not change stop/status/rehash/export-threat-feed semantics.

Do not change restart pre-action behavior from Iteration 102/103.

Do not move runtime-launch behavior.

Do not refactor one-shot commands in this phase.

Do not add dependencies.

Do not weaken the thin `main.rs` or command-dispatch guards.

## Current Problem

`src/commands/supervisor_control.rs` owns typed outcomes, but it still delegates to handlers that may print directly:

```rust
crate::supervisor::commands::handle_status(control_addr, use_tls)?;
Ok(SupervisorControlOutcome::StatusDisplayed)
```

This means the typed boundary cannot yet fully test or format command output. It also cannot carry accurate metadata for commands such as threat-feed export.

## Desired End State

After this phase:

- supervisor-control handlers return structured data where practical;
- `SupervisorControlOutcome` carries useful data for status/export commands;
- formatting is centralized in `supervisor_control.rs` or a dedicated display helper;
- existing visible output remains compatible unless explicitly improved and tested;
- handlers may still perform unavoidable IPC, but should not own CLI exit-code mapping;
- `ThreatFeedExported { bytes }` carries real bytes/records metadata or an explicit data struct, not a placeholder.

## Phase 1 — Audit Supervisor Handler Output

Inspect:

```text
src/supervisor/commands.rs
src/commands/supervisor_control.rs
src/commands/execute.rs
```

For each command, record:

```text
command | handler | prints? | returns data? | returns Result? | current user-visible text | safe typed outcome shape
```

Minimum commands:

- status;
- stop;
- rehash;
- export threat feed;
- restart pre-stop via stop adapter.

Do not refactor during audit except comments.

## Phase 2 — Define Data-Bearing Outcome Shapes

Extend `SupervisorControlOutcome` as needed.

Potential target shape:

```rust
pub enum SupervisorControlOutcome {
    Status(SupervisorStatusDisplay),
    StopRequested,
    RehashRequested,
    ThreatFeedExported(ThreatFeedExportSummary),
}

pub struct SupervisorStatusDisplay {
    pub text: String,
}

pub struct ThreatFeedExportSummary {
    pub bytes: usize,
    pub records: Option<usize>,
    pub path: Option<PathBuf>,
}
```

Use actual data available from the existing handlers. Do not invent fields that require invasive changes.

If status currently only produces formatted text, returning `Status { text: String }` is acceptable for this phase.

## Phase 3 — Convert Handlers To Return Data Where Low Risk

Prefer changing `src/supervisor/commands.rs` handler internals so they return data rather than print directly.

Example pattern:

```rust
pub fn handle_status_data(
    control_addr: Option<String>,
    use_tls: bool,
) -> Result<SupervisorStatusDisplay, Box<dyn std::error::Error>> {
    // old handle_status logic, but collect display text into String
}

pub fn handle_status(
    control_addr: Option<String>,
    use_tls: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = handle_status_data(control_addr, use_tls)?;
    println!("{}", status.text);
    Ok(())
}
```

This preserves compatibility for existing callers while giving `src/commands/supervisor_control.rs` a data-returning path.

If adding parallel `*_data` helpers is too noisy, change the original handler return type only if all call sites are easy to update.

## Phase 4 — Move Formatting Into Supervisor-Control Boundary

Update `SupervisorControlOutcome::display()` or a separate formatter:

```rust
impl SupervisorControlOutcome {
    pub fn display(&self) -> Option<String> {
        match self {
            SupervisorControlOutcome::Status(status) => Some(status.text.clone()),
            SupervisorControlOutcome::ThreatFeedExported(summary) => {
                Some(format!("Exported {} bytes", summary.bytes))
            }
            _ => None,
        }
    }
}
```

Avoid double-printing. If a handler still prints internally, do not also print in `execute.rs` for that command.

Acceptance: each command prints at most once.

## Phase 5 — Replace ThreatFeed Placeholder Metadata

Eliminate placeholder `ThreatFeedExported { bytes: 0 }`.

Preferred outcome:

```rust
SupervisorControlOutcome::ThreatFeedExported {
    bytes: exported_bytes,
    records: exported_records,
}
```

If byte count is not readily available, use an explicit enum/struct that does not pretend to know:

```rust
pub enum ThreatFeedExportSummary {
    Written { bytes: usize },
    Completed,
}
```

Do not keep `bytes: 0` unless zero is the actual result.

## Phase 6 — Add Tests

Add unit tests for formatting and data mapping without live supervisor.

Suggested tests:

```rust
#[test]
fn status_outcome_displays_status_text() { ... }

#[test]
fn threat_feed_export_summary_displays_real_metadata() { ... }

#[test]
fn threat_feed_export_does_not_use_placeholder_zero_bytes() { ... }
```

If live IPC is hard to mock, test the data structs and formatter separately.

## Phase 7 — Add Source Guard

Extend `tests/cli_command_dispatch_guard.rs`.

Suggested guard:

```rust
#[test]
fn supervisor_control_does_not_use_placeholder_threat_feed_bytes() {
    let source = read("src/commands/supervisor_control.rs");
    assert!(!source.contains("ThreatFeedExported { bytes: 0 }"));
}
```

Add guard that `execute.rs` still delegates formatting through outcomes:

```rust
assert!(source.contains("outcome.display()"));
```

## Phase 8 — Documentation

Update:

```text
architecture/cli_supervisor_command_dispatch.md
plans/roadmap.md only if phase status is being recorded
AGENTS.md if it has a command-dispatch section
```

Required doc note:

- supervisor handlers now expose structured data where practical;
- formatting is owned at the command boundary;
- threat-feed export no longer uses placeholder metadata.

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

If unrelated failures exist, document exact error text and targeted test results.

## Acceptance Criteria

This phase is complete when:

- supervisor-control outcomes carry structured data where practical;
- status/export formatting is centralized or clearly owned by the command boundary;
- threat-feed export no longer reports placeholder byte metadata;
- no command double-prints;
- existing command behavior remains compatible;
- guards protect against placeholder metadata and `main.rs` regressions.

## Expected Files To Touch

Likely:

```text
src/commands/supervisor_control.rs
src/supervisor/commands.rs
src/commands/execute.rs
tests/cli_command_dispatch_guard.rs
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
```

Avoid touching:

```text
src/main.rs
src/commands/plan.rs except if outcome shape requires import updates
crates/synvoid-http/**
crates/synvoid-http3/**
src/worker/unified_server/**
crates/synvoid-mesh/**
```

## Handoff Summary

Iteration 104 should turn the typed supervisor-control adapter from a wrapper around printing handlers into a real data/result boundary. Keep behavior compatible, avoid wire-protocol changes, and prioritize status/export data paths plus removal of placeholder threat-feed byte metadata.
