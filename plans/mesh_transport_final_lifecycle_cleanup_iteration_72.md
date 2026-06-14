# Mesh Transport Final Lifecycle Cleanup — Iteration 72

## Purpose

Iterations 68–71 established a substantially stronger mesh lifecycle model: task ownership, stable exit publication, staged startup, policy-aware bootstrap, rollback, active QUIC runtime cleanup, structured peer mutation tracking, shared shutdown deadlines, and bounded task teardown.

The review of `3dd4e9cafd8f2028704e6e6276e560e9e2441bda` and `72b6fca635f1dd59a60d43eb124508e7ac24ed98` identified a final set of edge cases that still violate the intended guarantees:

1. The accept loop publishes its report into a clone-local `accept_loop_report`, so the original transport still reads zero counts.
2. Rollback verification failures do not affect lifecycle state selection; the service can become `Stopped` even when verification proves cleanup is incomplete.
3. `MeshLifecycleState::Failed` remains directly restartable despite representing incomplete rollback.
4. Startup-created peer sessions are not selectively owned or cancelled; rollback drains the global `JoinSet` and can affect unrelated sessions.
5. Rollback session cleanup reuses one stale timeout value and does not reliably await all aborted sessions.
6. Existing topology state is not restored after a failed startup overwrites it.
7. DHT routing mutations created during startup are not rolled back.
8. Outbound peer preflight work remains detached through a bare `tokio::spawn()`.
9. Rollback abort accounting is derived from post-join active counts rather than authoritative task exits.

This pass should close those remaining mesh-local lifecycle defects without enabling deferred worker mesh supervision or changing mesh protocol behavior.

The invariant is:

> Failed startup must either restore the exact pre-start state and return to `Stopped`, or remain `Failed` with an explicit incomplete-cleanup error; no startup-created task, session, topology mutation, DHT mutation, or report path may escape that decision.

## Current Known State

At `72b6fca635f1dd59a60d43eb124508e7ac24ed98`:

- `commit_startup()` is inside the transaction and can restore the staged task group on transition failure.
- task-group ownership is installed before lifecycle publication.
- `StagedPeerResource` records session ID, node ID, prior topology existence, connection insertion, and session-task creation.
- startup-created peer resources are recorded by `connect_to_peer(..., Some(stage))`.
- `QuicRuntime::stop_server()` actively closes the endpoint.
- rollback errors can produce `StartupRollbackFailed`.
- accept-loop child counts are intended to flow through `MeshAcceptLoopReport`.

Known remaining defects:

- `clone_for_maintenance()` creates a new `accept_loop_report` instead of cloning the original shared handle.
- verification issues are appended only after `finish_failed_startup()` selects `Stopped` versus `Failed`.
- `can_start()` allows `Failed`.
- peer sessions are stored in a global `JoinSet<()>` without selective handles.
- rollback computes `session_remaining` once and reuses it per join.
- rollback aborts sessions, waits only briefly, and may return with tasks still present.
- prior topology state is represented only by a boolean.
- DHT registration is not tracked in staged peer resources.
- `preflight_peer_routes()` is spawned detached.
- `tasks_aborted` does not derive from `MeshTaskExitReason::Aborted`.

## Non-Goals

Do not enable worker mesh supervision in this iteration.

Do not change DHT/Raft consistency semantics.

Do not alter peer authentication, TLS validation, threat-intel, blocklist, or membership rules.

Do not add task restart policy.

Do not redesign the mesh protocol or connection handshake.

Do not migrate unrelated worker tasks.

## Phase 1 — Share The Accept-Loop Report Handle Correctly

Fix `clone_for_maintenance()` so the cloned transport used by the accept loop shares the original report handle.

Required change:

```rust
accept_loop_report: self.accept_loop_report.clone(),
```

Do not allocate a new default report in maintenance clones.

Audit every other lifecycle-sensitive field in `clone_for_maintenance()` for the same problem:

- task group;
- lifecycle state;
- shutdown state;
- peer sessions;
- exit sender;
- running projection;
- task ID generator.

Any field representing shared runtime state must remain shared across clones.

## Phase 2 — Reset Accept-Loop Report Per Startup Generation

A stable shared report can retain counts from a previous generation.

Before starting a new accept loop:

```rust
*self.accept_loop_report.lock().await = MeshAcceptLoopReport::default();
```

or attach a startup generation ID to the report.

Required semantics:

- every startup begins with a clean report;
- shutdown reads only the current generation’s report;
- failed startup rollback cannot leave stale child counts for a later run.

Preferred robust model:

```rust
pub struct MeshAcceptLoopReport {
    pub generation: u64,
    ...
}
```

and validate generation when reading.

## Phase 3 — Merge Verification Failures Before Lifecycle Selection

Refactor `rollback_and_return()` so verification findings become part of the authoritative rollback result before calling `finish_failed_startup()`.

Required ordering:

```rust
let mut rollback = self.rollback_startup(stage).await;
let verification_issues = self.verify_rollback_complete(stage).await;
rollback.errors.extend(verification_issues);
rollback.clean = rollback.errors.is_empty();
self.finish_failed_startup(&rollback).await;
```

Then:

- `rollback.clean == true` -> lifecycle `Stopped`, return original startup error;
- `rollback.clean == false` -> lifecycle `Failed`, return `StartupRollbackFailed`.

Do not allow a verification failure to coexist with lifecycle `Stopped`.

## Phase 4 — Make `Failed` Non-Restartable

Change lifecycle semantics so `Failed` cannot transition directly to `Starting`.

Required change:

```rust
pub fn can_start(&self) -> bool {
    matches!(self, MeshLifecycleState::Stopped)
}
```

Introduce explicit recovery if needed:

```rust
pub async fn recover_failed_state(&self, timeout: Duration) -> Result<(), MeshTransportError>
```

Recovery must:

1. acquire `lifecycle_op`;
2. verify current state is `Failed`;
3. re-run cleanup against remaining resources;
4. verify no owned tasks/sessions/connections/topology/DHT/runtime resources remain;
5. transition to `Stopped` only after successful verification.

Do not treat a new startup attempt as implicit cleanup.

## Phase 5 — Protect Against Replacing A Non-Empty Task Group

`commit_startup()` currently replaces `self.task_group` and drops the old value.

Before replacement, assert the old group is empty and shutdown-complete:

```rust
let active = old_group.active_count();
if active != (0, 0, 0) {
    return Err(MeshTransportError::StartupFailed(...));
}
```

Because `Failed` becomes non-restartable, this should normally hold.

If a non-empty group is found:

- restore ownership;
- route through rollback/recovery;
- never drop its handles.

## Phase 6 — Replace Global Peer Session `JoinSet` With A Keyed Registry

The current global `JoinSet<()>` cannot selectively cancel startup-created sessions.

Introduce a keyed session-task registry.

Suggested shape:

```rust
pub struct PeerSessionTask {
    pub session_id: String,
    pub node_id: String,
    pub handle: JoinHandle<()>,
}

peer_sessions: Arc<Mutex<HashMap<String, PeerSessionTask>>>
```

Alternative:

- `HashMap<SessionId, AbortHandle + JoinHandle>`;
- a dedicated `PeerSessionTaskGroup` supporting spawn, cancel-by-ID, join-by-ID, and shutdown-all.

Required capabilities:

- register session by session ID;
- remove completed session automatically;
- cancel/join one session;
- cancel/join a set of staged sessions;
- drain all sessions during normal shutdown;
- report drained versus aborted sessions accurately.

## Phase 7 — Record Session Task Identity In `StagedPeerResource`

Replace the boolean-only field:

```rust
session_task_created: bool
```

with an exact task/session identifier if session ID alone is insufficient.

Suggested:

```rust
pub session_task_id: Option<String>
```

or use the session ID as the task-registry key.

Rollback should target only sessions recorded by the failed startup attempt.

Do not abort unrelated sessions from a prior healthy generation.

## Phase 8 — Use One True Shared Rollback Deadline

Rollback must recompute remaining time before every await.

Required pattern:

```rust
while !pending.is_empty() {
    let left = remaining(deadline);
    if left.is_zero() {
        break;
    }
    match timeout(left, next_completion()).await { ... }
}
```

Do not compute `session_remaining` once and reuse it.

The one rollback deadline must cover:

- staged task-group join;
- staged peer-session drain;
- runtime stop;
- async topology/DHT restoration;
- final verification where bounded operations are involved.

## Phase 9 — Abort And Await Every Remaining Staged Session

When the shared rollback deadline expires:

1. collect remaining staged session IDs;
2. abort each corresponding handle;
3. await every aborted handle;
4. remove each registry entry;
5. count each forced abort;
6. add an error if any handle cannot be accounted for.

Do not use a fixed 100 ms best-effort wait and return with live tasks.

Abort-and-await may exceed the cooperative deadline slightly; document this as bounded forced cleanup rather than cooperative drain time.

## Phase 10 — Strengthen Rollback Verification For Sessions

Extend `verify_rollback_complete()` to check:

- no staged session IDs remain in the session-task registry;
- no staged peer connections remain;
- no staged topology/DHT mutations remain;
- staged runtime endpoint is stopped;
- staged task group has zero active handles;
- running projection is false;
- lifecycle is not `Running`.

A live staged session must force `rollback.clean = false`.

## Phase 11 — Snapshot Prior Topology State

`topology_existed_before: bool` is insufficient when startup overwrites an existing peer.

Extend `StagedPeerResource` with the prior topology snapshot.

Suggested:

```rust
pub previous_topology: Option<StagedTopologySnapshot>

pub struct StagedTopologySnapshot {
    pub peer_info: MeshPeerInfo,
    pub status: PeerStatus,
}
```

Record the snapshot before calling `topology.add_peer(...)`.

Rollback behavior:

- `previous_topology == None` -> remove the newly created entry;
- `Some(snapshot)` -> restore prior info/status exactly.

Do not leave startup-mutated address, capabilities, trust, role, ports, upstreams, health, or status behind after failure.

## Phase 12 — Track DHT Routing Mutations

Extend `StagedPeerResource`:

```rust
pub dht_registration_created: bool
```

or store a precise DHT mutation record.

When `dht_on_peer_connected()` adds a peer during startup, record whether that entry was newly created or replaced.

Rollback must:

- remove newly added routing entries;
- restore previous DHT peer state when startup replaced existing data;
- remove pending startup-generated routing queries if they are retained beyond the attempt.

Add or expose a routing-manager removal/restoration API if missing.

## Phase 13 — Ensure DHT Rollback Uses Native Identity

Audit DHT routing keys:

- node ID;
- hashed node ID;
- address/port tuple.

Use the same key representation for rollback that insertion uses.

Add a regression test with distinct session ID and node ID so connection-map and DHT rollback cannot accidentally use the wrong identifier.

## Phase 14 — Own Outbound Preflight Tasks

Replace the bare detached preflight spawn:

```rust
tokio::spawn(async move { preflight_peer_routes(...).await });
```

Choose one ownership model.

### Preferred During Startup

Register preflight as a staged bounded child in `MeshTaskGroup` and record the task ID in the stage.

### Acceptable

Await preflight inline after connection establishment but before startup commit.

### Steady-State Connections

Use a transport-owned bounded child group or peer-session task registry.

Required behavior:

- rollback cancels/joins startup preflight work;
- shutdown cancels/joins steady-state preflight work;
- preflight cannot mutate route/cache state after its peer has been rolled back.

## Phase 15 — Define Preflight Failure Policy

Preflight is currently best-effort.

Keep it nonfatal unless policy requires otherwise, but make the lifecycle explicit:

- failure logs/metrics only;
- task completion is owned;
- rollback cancellation is expected;
- no detached work survives.

Do not promote best-effort preflight failure into startup failure without an explicit policy change.

## Phase 16 — Correct Rollback Abort Accounting

Derive task abort counts from authoritative exits:

```rust
let tasks_aborted = exits
    .iter()
    .filter(|exit| matches!(exit.reason, MeshTaskExitReason::Aborted))
    .count();
```

Do not inspect active counts only after `join_all()` has consumed handles.

Similarly, session abort counts should derive from the exact set of handles forcibly aborted.

`RollbackReport` should distinguish:

- tasks joined cooperatively;
- tasks aborted;
- peer sessions joined cooperatively;
- peer sessions aborted;
- preflight children aborted.

## Phase 17 — Reset And Verify Accept-Loop Report On Rollback

If runtime startup occurred and then failed:

- reset current generation report before start;
- accept-loop shutdown publishes the final report;
- rollback may record the report for diagnostics;
- a later startup starts from zero.

Add report generation or startup generation identity if a stale publication from a prior task is possible.

## Phase 18 — Behavioral Tests For Shared Report Wiring

Add a test that exercises the actual cloned accept-loop path:

1. create transport;
2. verify clone shares `accept_loop_report` by `Arc::ptr_eq` where accessible;
3. run the accept loop with one child;
4. trigger shutdown;
5. assert the original transport sees drained/aborted counts.

Do not satisfy this only by writing directly to the original report mutex.

Add a second test proving a new startup resets old counts.

## Phase 19 — Behavioral Tests For Verification State

Required scenarios:

### Verification Failure

- inject a staged resource that rollback fails to remove;
- `verify_rollback_complete()` reports it;
- lifecycle becomes `Failed`, not `Stopped`;
- returned error is `StartupRollbackFailed`.

### Clean Rollback

- all cleanup and verification succeed;
- lifecycle becomes `Stopped`;
- retry is allowed.

### Failed Restart

- lifecycle is `Failed`;
- direct `start()` returns `NotAvailable` or dedicated recovery-required error;
- `recover_failed_state()` is required.

## Phase 20 — Selective Session Rollback Tests

Create two peer sessions:

- one pre-existing session;
- one created during the startup attempt.

Trigger startup failure.

Assert:

- staged session is cancelled, awaited, and removed;
- pre-existing session remains active;
- rollback counts only the staged session;
- no global `abort_all()` affects unrelated sessions.

Add cooperative and hung staged-session variants.

## Phase 21 — Topology Restoration Tests

Required cases:

### New Peer

- no prior topology entry;
- startup adds peer;
- rollback removes it.

### Existing Peer

- prior peer has different address/status/capabilities/trust metadata;
- startup overwrites it;
- rollback restores exact prior state.

### Multiple Peers

- mixed existing/new peers;
- rollback handles each independently.

## Phase 22 — DHT Restoration Tests

Required cases:

- startup adds a new DHT peer; rollback removes it;
- startup updates an existing DHT peer; rollback restores previous state;
- failed DHT bootstrap does not leave routing entries or pending request state;
- rollback uses node identity, not session ID.

## Phase 23 — Preflight Ownership Tests

Required cases:

- startup preflight is active when failure occurs;
- rollback cancels/joins it;
- route/cache state is not mutated after rollback completion;
- steady-state preflight is joined during shutdown;
- no bare `tokio::spawn()` remains in the peer-connection preflight path.

## Phase 24 — Guardrail Updates

Strengthen `tests/mesh_task_ownership_guard.rs`.

Add checks that:

- `clone_for_maintenance()` clones `accept_loop_report`;
- report is reset per startup generation;
- verification issues are merged before `finish_failed_startup()`;
- `can_start()` does not accept `Failed`;
- replacing a task group checks that the old group is empty;
- peer sessions are keyed/selectively owned, not a bare global `JoinSet<()>` only;
- rollback recomputes `remaining(deadline)` inside loops;
- `abort_all()` is followed by complete joins;
- topology prior-state snapshots exist;
- DHT rollback fields and removal/restoration paths exist;
- `preflight_peer_routes()` is not launched with bare `tokio::spawn()`;
- task abort counts derive from exit reasons.

Behavioral tests remain authoritative.

## Phase 25 — Documentation Cleanup

Update:

- `architecture/mesh_transport_lifecycle.md`
- `architecture/mesh.md`
- `skills/synvoid_mesh.md`
- `AGENTS.md`
- `crates/synvoid-mesh/AGENTS.override.md` if present

Document:

- `Failed` versus `Stopped` semantics;
- explicit recovery requirement;
- selective peer-session ownership;
- topology and DHT rollback snapshots;
- owned preflight tasks;
- current-generation accept-loop reporting;
- authoritative rollback abort accounting;
- worker mesh supervision remains deferred.

## Phase 26 — Suggested Implementation Sequence

Implement in this order:

1. Fix shared accept-loop report cloning and reset behavior.
2. Merge verification issues before lifecycle selection.
3. Make `Failed` non-restartable and add recovery scaffolding.
4. Introduce keyed peer-session task ownership.
5. Convert rollback to selective shared-deadline session cleanup.
6. Add topology snapshots and restoration.
7. Add DHT mutation tracking and restoration.
8. Move preflight work under ownership.
9. Correct abort accounting.
10. Add behavioral tests, guardrails, and docs.

## Phase 27 — Verification Commands

Run:

```bash
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test -p synvoid-mesh --features mesh task_group
cargo test -p synvoid-mesh --features mesh startup
cargo test -p synvoid-mesh --features mesh shutdown
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy -p synvoid-mesh --features mesh,dns -- -D warnings
```

If peer-session registry or DHT rollback APIs affect workspace crates:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This cleanup is complete when:

1. The accept loop and original transport share the same report handle.
2. Accept-loop reports are reset or generation-qualified per startup.
3. Rollback verification failures force lifecycle `Failed`.
4. Lifecycle `Failed` cannot directly restart.
5. Explicit recovery is required before returning to `Stopped`.
6. No non-empty old task group can be dropped during commit.
7. Startup-created peer sessions are selectively owned, cancelled, awaited, and removed.
8. Rollback uses one true shared deadline and awaits every forced abort.
9. Prior topology state is restored exactly.
10. Attempt-created DHT routing state is removed or restored.
11. Preflight work is owned and cannot survive rollback or shutdown.
12. Rollback abort counts are derived from authoritative exits/handles.
13. No startup-created task, session, connection, topology mutation, DHT mutation, runtime endpoint, or preflight child survives failed startup.
14. Clean rollback returns `Stopped`; incomplete rollback returns `Failed` and `StartupRollbackFailed`.
15. Worker mesh supervision remains accurately documented as deferred.
16. Existing blocklist, threat-intel, provenance, mesh-ID, composition, worker lifecycle, and mesh ownership guardrails remain green.

## Notes for the Implementer

This should be the final mesh-local lifecycle cleanup.

The most important corrections are not additional abstractions; they are preserving exact pre-start state, selectively owning startup-created sessions, and ensuring lifecycle state reflects verified cleanup reality.
