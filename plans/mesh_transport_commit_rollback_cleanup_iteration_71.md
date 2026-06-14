# Mesh Transport Commit/Rollback Cleanup — Iteration 71

## Purpose

Iteration 70 established the main transactional-startup framework for `MeshTransport`: a lifecycle operation lock, staged startup, policy-aware bootstrap, a single rollback funnel for `run_startup_phases()`, globally unique task IDs, atomic running projection, and a shared shutdown deadline.

The remaining issues are narrow but correctness-sensitive:

1. `commit_startup()` remains outside the rollback funnel. A lifecycle-transition or commit failure can still drop the staged task group without cancellation/join.
2. Commit ordering exposes `MeshLifecycleState::Running` before the staged task group and running projection are fully installed.
3. `MeshStartupStage` declares peer/session/runtime resource tracking, but the bootstrap/connect paths do not populate it.
4. Rollback removes peers using node IDs even though peer connection ownership may be keyed by session ID.
5. Topology mutations and staged runtime/listener resources are not actively undone.
6. Rollback peer-session cleanup is not bounded by one deadline and does not abort-and-await remnants.
7. `RollbackReport` is not surfaced through `StartupRollbackFailed` when cleanup is incomplete.
8. `MeshAcceptLoopReport` is declared but remains unwired; shutdown report child counters therefore remain non-authoritative.

This pass should close those final mesh-local lifecycle gaps without enabling deferred worker mesh supervision or changing mesh protocol semantics.

The invariant is:

> No uncommitted startup stage may be dropped while it owns live tasks or resources, and no failed startup may return without either complete rollback or an explicit rollback-failure error.

## Current Known State

At `9ce45681527678eca7d3903eef260b793b01d73f`:

- `start_with_policy()` serializes lifecycle operations with `lifecycle_op`.
- `run_startup_phases()` contains all ordinary post-spawn startup work.
- errors from `run_startup_phases()` invoke `rollback_startup()`.
- required/optional seed, configured-peer, and DHT behavior is policy-driven.
- `MeshStartupReport` is returned by the primary startup API.
- `MeshStartupStage` owns a staged `MeshTaskGroup` and resource-tracking fields.
- `running_projection` provides nonblocking runtime state observation.
- worker mesh supervision is explicitly deferred.

Known remaining defects:

- `Ok(report) => self.commit_startup(stage, report).await` can return an error outside rollback handling.
- `commit_startup()` transitions lifecycle to `Running` before transferring the task group.
- the post-commit failure hook can roll back after state was already exposed as `Running`.
- `record_peer_session()` is defined but not called by seed/configured-peer bootstrap paths.
- `created_peer_sessions`, `created_peer_nodes`, and `runtime_started` are not sufficient unless populated from exact mutations.
- rollback does not restore topology state.
- rollback does not stop staged runtime/listener resources.
- rollback peer-session draining can exit with sessions still live.
- incomplete rollback still returns only the original startup error.
- accept-loop handshake child counts remain deferred and zero-valued in the final report.

## Non-Goals

Do not enable worker mesh-exit supervision in this iteration.

Do not redesign mesh DHT, Raft, peer authentication, TLS, threat-intel, or membership behavior.

Do not add task restart policy.

Do not migrate unrelated worker or mesh subsystems.

Do not change supervisor protocol messages.

## Phase 1 — Put Commit Inside The Transaction Boundary

Refactor the success branch so commit errors also flow through rollback.

Preferred shape:

```rust
let result = self
    .run_startup_phases(&mut stage, &policy, &shutdown_rx)
    .await
    .and_then(|report| async { self.commit_startup(&mut stage, report).await });
```

Because ordinary `and_then` is not async, use an explicit match:

```rust
let report = match self.run_startup_phases(...).await {
    Ok(report) => report,
    Err(error) => return self.rollback_and_return(&mut stage, error).await,
};

match self.commit_startup(&mut stage, report).await {
    Ok(report) => Ok(report),
    Err(error) => self.rollback_and_return(&mut stage, error).await,
}
```

Required properties:

- lifecycle transition failure invokes rollback;
- task-group installation failure invokes rollback;
- post-commit failure injection invokes rollback;
- no `MeshStartupStage` owning live tasks can be dropped by returning directly from `commit_startup()`.

## Phase 2 — Add One `rollback_and_return()` Helper

Centralize rollback error propagation.

Suggested helper:

```rust
async fn rollback_and_return<T>(
    &self,
    stage: &mut MeshStartupStage,
    startup_error: MeshTransportError,
) -> Result<T, MeshTransportError> {
    let rollback = self.rollback_startup(stage).await;
    self.finish_failed_startup(&rollback).await;

    if rollback.clean {
        Err(startup_error)
    } else {
        Err(MeshTransportError::StartupRollbackFailed {
            startup_error: startup_error.to_string(),
            rollback_errors: rollback.errors,
        })
    }
}
```

Preserve structured source errors if the error type supports nesting rather than stringification.

All startup failure paths should use this helper.

## Phase 3 — Make Commit Ordering Atomic From Observers’ Perspective

Current ordering sets lifecycle to `Running` before task-group ownership is installed.

Required ordering:

1. Validate that lifecycle state is still `Starting` without mutating it.
2. Prepare compatibility shutdown sender and any runtime handles.
3. Transfer staged task group into transport ownership using a reversible swap.
4. Store staged runtime/listener handles.
5. Transition lifecycle state to `Running`.
6. Set `running_projection = true`.
7. Mark the stage committed.
8. Return the startup report.

No external reader should observe `Running` before the task group and runtime resources are owned by `MeshTransport`.

## Phase 4 — Make Task-Group Transfer Reversible

Transferring the staged task group before the lifecycle transition requires rollback if the transition fails.

Use one of these designs:

### Preferred — Swap Guard

```rust
struct TaskGroupInstallGuard<'a> {
    slot: &'a Mutex<MeshTaskGroup>,
    previous: Option<MeshTaskGroup>,
    installed: bool,
}
```

On failure, restore the previous group and recover the staged group for rollback.

### Acceptable — Validate Then Infallible Transition

Under the lifecycle operation lock, validate `Starting` first and make the final transition infallible because no concurrent transition is possible:

```rust
assert!(matches!(*state, MeshLifecycleState::Starting));
*state = MeshLifecycleState::Running;
```

This is simpler, but the invariants must be explicit and tested.

Do not retain a fallible transition after consuming the only staged task-group owner unless recovery is possible.

## Phase 5 — Move The `AfterLifecycleCommit` Hook Before External Commit

The current hook name suggests post-commit failure but running it after exposing `Running` creates unnecessary rollback complexity.

Preferred change:

- rename to `BeforeLifecycleCommit` or `BeforeCommit`;
- invoke it after all startup phases succeed but before task-group transfer and state publication.

If a true post-commit failure test is required, it must exercise a reversible commit guard and prove rollback can reclaim installed resources.

For this iteration, prefer a pre-commit failure injection point.

## Phase 6 — Track Exact Startup-Created Peer Mutations

Replace parallel string vectors with a structured resource record.

Suggested type:

```rust
pub struct StagedPeerResource {
    pub session_id: String,
    pub node_id: String,
    pub topology_existed_before: bool,
    pub connection_inserted: bool,
    pub session_task_created: bool,
}
```

Store:

```rust
pub(crate) created_peers: Vec<StagedPeerResource>
```

Record resources at the exact point each mutation succeeds.

Required integration points:

- seed connection establishment;
- configured-peer connection establishment;
- any DHT bootstrap path that creates a persistent peer connection;
- incoming/outgoing session registration if it can occur during startup.

## Phase 7 — Thread The Startup Stage Through Bootstrap Helpers

Current helpers mutate transport state without access to the stage.

Choose one:

### Preferred

Return exact mutation results:

```rust
async fn bootstrap_from_seeds(
    &self,
) -> Result<Vec<StagedPeerResource>, MeshTransportError>
```

The caller records them in the stage.

### Acceptable

Pass a mutable stage/resource recorder:

```rust
async fn bootstrap_from_seeds(
    &self,
    stage: &mut MeshStartupStage,
) -> Result<(), MeshTransportError>
```

Avoid embedding transaction-state knowledge deeply into unrelated protocol code when return values are sufficient.

## Phase 8 — Use The Correct Peer-Connection Key During Rollback

Audit the actual key for `peer_connections`.

If keyed by session ID:

```rust
self.peer_connections.remove(&resource.session_id);
```

Do not attempt lookup/removal by node ID.

If multiple indexes exist, explicitly remove each index using its native key.

Add a regression test that inserts different node and session IDs and proves rollback removes the correct entry.

## Phase 9 — Roll Back Topology Mutations

For every peer added or modified during startup:

- remove the topology entry if it did not exist before;
- restore prior status/metadata if it existed and startup changed it;
- remove DHT routing entries created solely by the failed attempt where appropriate.

Do not remove pre-existing peer state.

This may require a lightweight snapshot of prior topology state in `StagedPeerResource`.

Suggested fields:

```rust
pub previous_topology_status: Option<PeerStatus>,
pub previous_peer_info: Option<PeerInfo>,
```

Use only the minimum state necessary for correct restoration.

## Phase 10 — Track And Stop Staged Runtime Resources

`runtime_started: bool` is insufficient without a cleanup operation.

Introduce a staged runtime handle or explicit cleanup contract:

```rust
pub enum StagedRuntimeResource {
    QuicRuntimeStarted,
    ListenerBound(...),
}
```

Rollback must call the actual runtime stop/close API.

Required behavior:

- stop accepting;
- close endpoint/listener;
- release bound sockets;
- await runtime shutdown if it owns tasks;
- record cleanup failure in `RollbackReport`.

Add a test proving the same endpoint can be rebound after rollback.

## Phase 11 — Use One Rollback Deadline

Define a total rollback timeout:

```rust
let deadline = Instant::now() + self.config.lifecycle.startup_rollback_timeout;
```

or a documented constant if no config exists.

All rollback phases consume this one budget:

- staged top-level tasks;
- staged runtime shutdown;
- startup-created peer sessions;
- topology cleanup where async;
- final verification.

Do not apply a fresh timeout per session or task.

## Phase 12 — Abort And Await All Startup-Created Peer Sessions

Rollback should target sessions created by the startup attempt, not indiscriminately drain every global session unless the lifecycle contract guarantees none pre-existed.

Preferred design:

- peer session group supports abort/join by session ID or task ID;
- stage records session task IDs;
- rollback cancels those sessions;
- waits until shared deadline;
- aborts and awaits every remaining staged session.

If selective session-task control is not currently possible, introduce a small session registry:

```rust
HashMap<SessionId, JoinHandle<()>>
```

rather than a bare `JoinSet<()>`.

Required invariant:

- no startup-created session survives failed startup.

## Phase 13 — Make Rollback Completeness Verifiable

At the end of rollback, verify:

- staged task group is empty;
- staged peer connections are absent;
- staged peer session tasks are absent;
- staged topology changes are restored;
- staged runtime/listener resources are stopped;
- `running_projection == false`;
- lifecycle has not become `Running`.

Any failed verification adds a `RollbackReport.errors` entry and leaves lifecycle in `Failed`.

## Phase 14 — Return `StartupRollbackFailed` On Incomplete Cleanup

Wire the existing error variant into production flow.

Required information:

- original startup error;
- rollback error list;
- optional rollback duration;
- optional remaining resource counts.

Suggested display:

```text
mesh startup failed: <startup>; rollback incomplete: <n> errors
```

Do not return the original startup error alone when cleanup is incomplete.

## Phase 15 — Make `RollbackReport` More Informative

Extend if useful:

```rust
pub struct RollbackReport {
    pub clean: bool,
    pub errors: Vec<String>,
    pub tasks_joined: usize,
    pub tasks_aborted: usize,
    pub peer_connections_closed: usize,
    pub peer_sessions_joined: usize,
    pub peer_sessions_aborted: usize,
    pub topology_entries_restored: usize,
    pub runtime_stopped: bool,
}
```

Avoid decorative fields that are not populated.

## Phase 16 — Resolve `MeshAcceptLoopReport`

Choose one honest outcome.

### Outcome A — Wire It Now

Make the accept loop publish its final child report through:

- a oneshot result slot owned by the transport; or
- a typed task output wrapper.

Populate:

- `drained_peer_children`;
- `aborted_peer_children`;
- optionally `rejected_at_capacity` in a separate metrics/report field.

### Outcome B — Defer Cleanly

If wiring it now is disproportionate:

- remove `drained_peer_children` and `aborted_peer_children` from `MeshShutdownReport` for now, or mark them explicitly unavailable with `Option<usize>`;
- move `MeshAcceptLoopReport` to the deferred ledger;
- ensure docs do not imply authoritative values.

Do not keep authoritative-looking integer fields that always remain zero.

Preferred: Outcome A if it can be completed without generic task-output refactoring.

## Phase 17 — Strengthen Behavioral Startup Tests

Update `tests/mesh_startup_rollback.rs` to exercise real startup and commit failures.

Required scenarios:

### Commit Transition Failure

- inject or force commit validation failure;
- assert rollback runs;
- assert staged task counters stop;
- assert no task group is detached;
- assert lifecycle ends `Stopped` after clean rollback.

### Pre-Commit Hook Failure

- trigger renamed pre-commit hook;
- assert no observer sees `Running`;
- assert task group is rolled back.

### Peer Resource Rollback

- create startup peer with distinct node/session IDs;
- fail after connection registration;
- assert connection map removal by session ID;
- assert topology restored;
- assert session task terminated.

### Runtime Resource Rollback

- bind/start runtime;
- fail before commit;
- assert runtime stopped and endpoint reusable.

### Incomplete Rollback

- inject cleanup failure;
- assert returned error is `StartupRollbackFailed`;
- assert lifecycle is `Failed`.

## Phase 18 — Add Commit Visibility Tests

Use barriers or test hooks to pause commit between steps.

Assert:

- before task-group transfer, lifecycle is `Starting`;
- after task-group transfer but before state publication, external `is_running()` remains false;
- once lifecycle is `Running`, task-group ownership and running projection are already installed;
- shutdown cannot interleave due to `lifecycle_op`.

## Phase 19 — Add Rollback Deadline Tests

Required cases:

- all staged sessions exit cooperatively before deadline;
- one staged session hangs and is aborted/awaited;
- multiple hung sessions do not multiply the timeout;
- rollback duration stays within configured deadline plus small abort-join margin;
- timeout/abort counts appear in `RollbackReport`.

## Phase 20 — Guardrail Updates

Strengthen `tests/mesh_task_ownership_guard.rs`.

Add checks that:

- `commit_startup()` errors cannot bypass rollback;
- lifecycle transitions to `Running` only after task-group installation;
- startup stage resource-recording methods are called from bootstrap/connect paths;
- rollback removes peer connections using session IDs where applicable;
- topology rollback code exists;
- `runtime_started` has a corresponding cleanup path;
- rollback session cleanup aborts and awaits remnants under a shared deadline;
- `StartupRollbackFailed` is constructed in startup control flow;
- handshake report fields are either wired or explicitly optional/deferred.

Behavioral tests remain primary.

## Phase 21 — Documentation Cleanup

Update:

- `architecture/mesh_transport_lifecycle.md`
- `architecture/mesh.md`
- `skills/synvoid_mesh.md`
- `AGENTS.md`
- `crates/synvoid-mesh/AGENTS.override.md` if present

Document:

- exact commit ordering;
- stage ownership transfer;
- rollback resource inventory;
- clean rollback versus incomplete rollback;
- startup error versus rollback error reporting;
- topology/runtime cleanup semantics;
- handshake-report status;
- worker mesh supervision remains explicitly deferred.

## Phase 22 — Suggested Implementation Sequence

Implement in this order:

1. Add `rollback_and_return()` and route commit errors through it.
2. Reorder commit so ownership is installed before `Running` publication.
3. Rename/move the post-commit failure hook to pre-commit.
4. Introduce structured staged-peer resource records.
5. Thread mutation results through bootstrap/connect helpers.
6. Correct connection-map key usage and topology restoration.
7. Add staged runtime cleanup.
8. Replace rollback session drain with selective shared-deadline abort-and-await.
9. Wire `StartupRollbackFailed` and richer rollback reporting.
10. Resolve accept-loop reporting.
11. Add tests, guardrails, and docs.

## Phase 23 — Verification Commands

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

If bootstrap helper signatures or error types affect workspace callers:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This cleanup is complete when:

1. `commit_startup()` cannot fail outside the rollback transaction.
2. No observer can see `Running` before task-group and runtime ownership are installed.
3. Every startup-created peer/session/topology mutation is recorded.
4. Rollback removes connections using the correct native keys.
5. Rollback restores topology state without removing pre-existing peers.
6. Staged runtime/listener resources are actively stopped.
7. Startup-created peer sessions are selectively aborted and awaited under one deadline.
8. Clean rollback returns lifecycle to `Stopped`.
9. Incomplete rollback leaves lifecycle `Failed` and returns `StartupRollbackFailed`.
10. Rollback diagnostics preserve the original startup error.
11. No staged task, peer session, connection, topology mutation, or listener survives failed startup.
12. Handshake child shutdown counts are either correctly wired or explicitly non-authoritative/removed.
13. Worker mesh supervision remains accurately documented as deferred.
14. Existing blocklist, threat-intel, provenance, mesh-ID, composition, worker lifecycle, and mesh ownership guardrails remain green.

## Notes for the Implementer

This should be the final mesh-local lifecycle cleanup before closing the subsystem.

The highest-priority correction is to make commit part of the same rollback transaction as startup phases. The presence of a lifecycle operation lock reduces race probability but does not make dropping an uncommitted live task group safe.
