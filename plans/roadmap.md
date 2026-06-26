# Command and Supervisor Cleanup Roadmap

## Purpose

This roadmap narrows the next line of work to the command-dispatch and supervisor-control cleanup track.

Recent iterations moved SynVoid out of the old `src/main.rs` command bucket shape:

- Iteration 101 extracted typed command planning and execution into `src/commands/{plan,execute}.rs`.
- Iteration 102 corrected restart planning and hash-token error semantics.
- Iteration 103 introduced `src/commands/supervisor_control.rs` with typed `SupervisorControlOutcome` / `SupervisorControlError` and centralized supervisor-control exit-code mapping.
- Iteration 104 separated handler output from data — handlers now expose `_data` variants returning structured data, `SupervisorControlOutcome` carries data-bearing variants, formatting is centralized in `display()`, and threat-feed export uses real byte metadata instead of a placeholder.

The command line is now structurally cleaner, but this line is not fully finished. The remaining work is to remove the last ad-hoc output/error/runtime seams while preserving CLI compatibility and supervisor IPC semantics.

## Current Posture

Good state:

- `src/main.rs` is a thin process entrypoint.
- command classification is typed and mostly pure.
- restart is a typed pre-action preserving control address and TLS.
- missing `--hash-token` values have a dedicated planner error.
- supervisor-control commands flow through a typed adapter with data-bearing outcomes.
- handlers expose `_data` variants returning structured data.
- formatting is centralized in `SupervisorControlOutcome::display()`.
- threat-feed export returns real byte metadata via `ThreatFeedExportSummary`.
- guards prevent command implementation logic from returning to `main.rs` and protect against placeholder metadata.

Remaining weak spots:

- the typed error taxonomy still collapses most failures into `RequestFailed(String)`;
- runtime launch still builds Tokio runtimes, worker args, panic handlers, PID handling, and runtime calls directly inside `execute.rs`;
- one-shot commands still print and return `i32` directly;
- the final CLI flag precedence/compatibility surface has not been audited as a whole.

## Roadmap Sequence

The order below is deliberate. First separate supervisor handler data from printing, then harden errors, then move runtime launch and one-shot command paths behind typed result boundaries, and finally audit the complete command-line surface.

## Phase 104 — Supervisor Handler Output/Data Separation ✅

Make supervisor-control handlers return structured data where practical, with formatting owned by `src/commands/supervisor_control.rs` or a small display helper.

Primary goal: stop the typed supervisor-control boundary from being only a shell around internally-printing handlers.

**Completed (Iteration 104):**

- status, stop, rehash, and threat-feed export have typed data-bearing outcomes (`SupervisorStatusDisplay`, `StopOutcome`, `RehashOutcome`, `ThreatFeedExportSummary`);
- threat-feed export returns a real byte count via `ThreatFeedExportSummary::Written { bytes, records }` instead of `bytes: 0`;
- existing user-facing text remains compatible — output is unchanged, just produced via `outcome.display()` instead of handler-internal `println!`;
- no supervisor IPC wire semantics changed;
- guards protect against placeholder metadata and `main.rs` regressions.

## Phase 105 — Control-Plane Error Taxonomy Hardening

Replace the broad `RequestFailed(String)` catch-all behavior with a more useful internal error taxonomy.

Expected categories:

- connection refused/unavailable;
- timeout;
- protocol/request failure;
- authentication/authorization failure if present;
- unsupported feature;
- filesystem/I/O;
- invalid response/unexpected state.

Primary goal: improve diagnostics and exit-code ownership without changing command names or wire protocol.

## Phase 106 — Runtime Launch Boundary Cleanup

Move runtime-launch wiring out of `execute.rs` into a typed runtime launch boundary.

Primary goal: `execute.rs` should dispatch `RuntimeCommand` into a `RuntimeLaunchPlan` / launcher, not own Tokio runtime construction, worker arg construction, panic handler setup, PID acquisition, and runtime calls inline.

Expected outcomes:

- `src/commands/execute.rs` becomes thinner;
- runtime launch modes are represented by typed launch plans;
- runtime setup remains behavior-preserving;
- tests can validate launch planning without starting full runtimes.

## Phase 107 — One-Shot Command Result Boundary

Give one-shot commands the same typed result/error treatment as supervisor-control commands.

Primary goal: config test, OpenAPI export, token operations, regex check, genesis, and node-info paths should return typed outcomes/errors, with display and exit-code mapping centralized.

Expected outcomes:

- one-shot commands no longer return raw `i32` from scattered match branches;
- output formatting is centralized where practical;
- tests can check outcomes without depending on terminal output;
- command behavior remains compatible.

## Phase 108 — Final Command-Line Surface Audit

Audit the complete command-line surface for precedence, mutual exclusion, feature gates, restart combinations, and exit semantics.

Primary goal: close this command/supervisor cleanup line with compatibility confidence.

Expected outcomes:

- all command classes have tests for classification and important invalid combinations;
- restart combined with status/stop/worker modes is explicitly defined;
- mesh-gated commands behave consistently with and without `mesh`;
- exit codes are documented and guarded;
- `src/main.rs`, planning, supervisor-control, runtime-launch, and one-shot boundaries are all protected by source guards.

## Exit Criteria For This Line Of Work

This cleanup line is complete when:

- `src/main.rs` remains a minimal entrypoint;
- `src/commands/plan.rs` owns classification only;
- supervisor-control, runtime-launch, and one-shot commands each have typed result/error boundaries;
- CLI formatting and exit-code mapping are centralized and testable;
- command behavior and supervisor IPC compatibility are preserved;
- guards prevent regression to ad-hoc command implementation in `main.rs` or broad untyped branches in `execute.rs`.
