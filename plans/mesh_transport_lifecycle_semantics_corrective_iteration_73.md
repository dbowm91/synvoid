# Mesh Transport Lifecycle Semantics Corrective Pass — Iteration 73

## Purpose

Iterations 68–72 established a mature mesh-local lifecycle architecture: owned task groups, stable exit publication, staged startup and rollback, explicit lifecycle states, keyed peer-session ownership, active runtime cleanup, accept-loop reporting, topology/DHT rollback scaffolding, and failed-state recovery.

The review of `1305201458c96789fc24c94c4cf82a397a526548` found that the remaining defects are no longer broad architectural omissions. They are semantic mismatches between the implemented bookkeeping and the guarantees the lifecycle model claims to provide:

1. `commit_startup()` detects a non-empty old task group only after replacement and continues, allowing live handles to be dropped and detached.
2. Outbound topology state is snapshotted after `topology.add_peer()` has already overwritten the prior entry.
3. DHT mutation tracking records whether DHT is enabled rather than whether startup created or replaced a routing entry.
4. `recover_failed_state()` does not stop or join the top-level `MeshTaskGroup`, does not verify all owned registries, and ignores its timeout.
5. Selective rollback aborts staged sessions but can drop the aborted handle without awaiting it once the cooperative deadline is exhausted.
6. Steady-state preflight still uses a bare detached `tokio::spawn()`.
7. Completed peer-session tasks remain in the keyed registry until shutdown or rollback.
8. Session shutdown reporting classifies panic/cancellation `JoinError`s as cleanly drained.

This pass should correct those semantics without expanding into worker-level mesh supervision or protocol changes.

The invariant is:

> Lifecycle bookkeeping must describe the real resource transition: prior state is captured before mutation, every owned handle remains owned until joined, recovery proves all lifecycle-owned resources are gone, and shutdown reports distinguish clean completion from panic, cancellation, and forced abort.

## Current Known State

At `1305201458c96789fc24c94c4cf82a397a526548`:

- `MeshLifecycleState::Failed` is non-restartable.
- `recover_failed_state()` is the explicit path back to `Stopped`.
- peer sessions are stored in `HashMap<String, PeerSessionTask>`.
- `StagedPeerResource` carries:
  - session ID;
  - node ID;
  - optional topology snapshot;
  - connection insertion flag;
  - session task ID;
  - DHT registration-created flag.
- rollback selectively removes staged sessions.
- topology restoration and DHT removal paths exist.
- startup preflight is owned through the staged task group.
- accept-loop reporting is shared and generation-aware.

Known remaining defects:

- non-empty old task group replacement only logs and then drops the group;
- topology snapshot is captured after mutation;
- DHT mutation tracking is inferred from `rm.is_enabled()`;
- recovery ignores top-level tasks and several resource ledgers;
- `_timeout` in recovery is unused;
- forced session abort is not always followed by an await;
- steady-state preflight is detached;
- peer-session registry entries are not reaped after normal completion;
- shutdown treats all `JoinError`s as drained.

## Non-Goals

Do not enable worker mesh supervision in this iteration.

Do not change DHT/Raft consistency semantics.

Do not alter peer authentication, TLS, threat-intel, blocklist, membership, or routing policy.

Do not add automatic task restart policy.

Do not redesign the mesh protocol or handshake wire format.

Do not migrate unrelated worker tasks.

## Phase 1 — Make Non-Empty Task-Group Replacement A Hard Failure

Current commit logic replaces the task group and then inspects the old group.

Refactor to inspect before replacement.

Required shape:

```rust
let mut slot = self.task_group.lock().await;
let (critical, background, children) = slot.active_count();
if critical + background + children != 0 {
    return Err(MeshTransportError::LifecycleConflict(format!(
        "cannot commit startup over non-empty task group: {critical} critical, {background} background, {children} children"
    )));
}

let old = std::mem::replace(&mut *slot, std::mem::take(&mut stage.task_group));
```

Required properties:

- no live old handles are dropped;
- staged group remains recoverable if the guard fails;
- commit error flows through the existing rollback funnel;
- the old empty group may be dropped safely.

Add a behavioral test with a deliberately non-empty old group and assert:

- commit fails;
- old task remains owned;
- staged group rolls back;
- no handle is detached.

## Phase 2 — Capture Topology State Before Mutation

The current outbound connection path calls `topology.add_peer()` before reading `topology.get_peer()` for the staged snapshot.

Move prior-state capture before any topology mutation.

Required sequence:

```rust
let previous_topology = if stage.is_some() {
    self.topology.get_peer(&peer_node_id).await.map(snapshot_from_peer)
} else {
    None
};

self.topology.add_peer(new_peer_info, PeerStatus::Healthy).await;
```

Then store `previous_topology` in `StagedPeerResource`.

Do not reconstruct prior capabilities from current config. Snapshot the actual stored peer record faithfully.

If `MeshTopology::get_peer()` does not expose all fields needed for exact restoration, add an internal snapshot/export method returning the native stored representation.

## Phase 3 — Preserve Exact Topology State

`StagedTopologySnapshot` must retain enough information to restore the original peer entry exactly.

Audit all mutable peer fields:

- address;
- role;
- capabilities;
- global/trusted flags;
- latency;
- upstreams;
- QUIC/WireGuard/advertised ports;
- DNS health;
- peer status;
- score/health metadata where stored in the same record;
- any timestamps or version counters relevant to replacement semantics.

Prefer storing the topology’s native peer-state type rather than reconstructing a `MeshPeerInfo` from partial fields.

Rollback behavior:

- no prior entry -> remove startup-created entry;
- prior entry -> restore exact native snapshot;
- restoration failure -> add rollback error and keep lifecycle `Failed`.

## Phase 4 — Make DHT Mutation Reporting Explicit

Replace the current inference:

```rust
let dht_created = routing_manager.is_enabled();
```

with mutation metadata returned by the DHT registration operation.

Suggested type:

```rust
pub enum DhtPeerMutation {
    None,
    Created,
    Replaced(DhtPeerSnapshot),
    UpdatedInPlace(DhtPeerSnapshot),
}
```

Preferred API:

```rust
async fn dht_on_peer_connected(...) -> Result<DhtPeerMutation, MeshTransportError>
```

If the existing function intentionally cannot fail, return `DhtPeerMutation` directly.

`StagedPeerResource` should carry the mutation value, not a boolean.

## Phase 5 — Restore DHT State Precisely

Rollback behavior by mutation:

- `None` -> no operation;
- `Created` -> remove the new routing entry;
- `Replaced(previous)` -> restore the previous routing entry;
- `UpdatedInPlace(previous)` -> restore previous state.

Use the routing manager’s native identity/key type.

Do not use session ID for DHT rollback unless the routing table is actually keyed by session ID.

Add internal APIs if needed:

```rust
async fn snapshot_peer(&self, node_id: &str) -> Option<DhtPeerSnapshot>;
async fn restore_peer(&self, snapshot: DhtPeerSnapshot);
async fn remove_peer(&self, node_id: &str);
```

## Phase 6 — Capture DHT State Before Mutation

The DHT snapshot must be obtained before calling `dht_on_peer_connected()`.

Required sequence:

1. inspect/snapshot prior DHT entry;
2. perform registration/update;
3. derive exact mutation result;
4. record mutation in the startup stage.

Add tests where:

- peer was absent -> rollback removes it;
- peer existed -> rollback restores prior address/role/latency/state;
- DHT disabled -> mutation is `None` and rollback does nothing.

## Phase 7 — Turn Recovery Into Full Lifecycle Cleanup

`recover_failed_state()` should execute the same ownership guarantees as shutdown/rollback rather than only clearing connections and sessions.

Required recovery phases:

1. acquire `lifecycle_op`;
2. verify state is `Failed`;
3. compute one deadline from the supplied timeout;
4. set shutdown intent;
5. signal the top-level `MeshTaskGroup`;
6. stop the QUIC runtime/endpoint;
7. close peer connections;
8. drain/abort/await peer sessions;
9. drain/abort/await owned bounded children/preflight tasks;
10. join/abort/await the top-level task group;
11. clear or restore residual topology/DHT state using retained recovery metadata where available;
12. reset accept-loop report for the failed generation;
13. verify every owned registry is empty;
14. transition to `Stopped` only on complete verification.

The timeout parameter must be consumed.

## Phase 8 — Retain Recovery Metadata For Incomplete Rollback

After an incomplete startup rollback, the local `MeshStartupStage` is otherwise lost when the error returns.

Add retained failed-cleanup metadata to `MeshTransport`.

Suggested field:

```rust
failed_startup_residue: Arc<Mutex<Option<FailedStartupResidue>>>
```

Suggested contents:

```rust
pub struct FailedStartupResidue {
    pub peers: Vec<StagedPeerResource>,
    pub generation: u64,
    pub runtime_started: bool,
    pub rollback_errors: Vec<String>,
}
```

Store only resources not proven clean, or store the full stage ledger if simpler.

`recover_failed_state()` uses this ledger to restore topology/DHT state and target exact sessions/resources.

Clear the residue only after successful recovery verification.

## Phase 9 — Verify Top-Level Task Group During Recovery

Recovery verification must inspect:

- critical task count;
- background task count;
- child task count;
- pending peer sessions;
- peer connections;
- runtime endpoint state;
- running projection;
- lifecycle state;
- failed-startup residue;
- accept-loop generation/report state where applicable.

Any non-zero owned task count keeps lifecycle in `Failed`.

Do not transition to `Stopped` based only on empty peer connections.

## Phase 10 — Separate Cooperative Deadline From Forced Cleanup

For rollback, shutdown, and recovery:

- cooperative drain respects the caller/configured deadline;
- once the deadline expires, abort remaining handles;
- every aborted handle is awaited unconditionally before the method returns.

Required pattern:

```rust
handle.abort();
let _ = handle.await;
```

Do not drop an aborted handle merely because `remaining(deadline) == 0`.

Document that forced abort-join cleanup may extend slightly beyond the cooperative timeout but is required for ownership completion.

## Phase 11 — Correct Selective Session Abort-And-Await

Refactor staged-session rollback so each removed `PeerSessionTask` follows one of two paths:

- completes before deadline -> classify from `JoinHandle` result;
- remains active at deadline -> abort, await, classify as forced abort.

Required accounting:

```rust
match handle.await {
    Ok(()) => cooperative_count += 1,
    Err(err) if err.is_cancelled() && forced_abort => aborted_count += 1,
    Err(err) if err.is_panic() => failed_count += 1,
    Err(err) => failed_count += 1,
}
```

Do not increment `tasks_aborted` for peer sessions; use dedicated session fields in `RollbackReport` if needed.

## Phase 12 — Extend `RollbackReport` For Session Outcomes

Add explicit fields:

```rust
pub peer_sessions_drained: usize,
pub peer_sessions_aborted: usize,
pub peer_sessions_failed: usize,
```

Deprecate or replace the ambiguous `peer_sessions_cleaned` total.

The report should allow verification that every targeted session ended in exactly one category.

## Phase 13 — Own Steady-State Preflight Work

Remove the bare steady-state `tokio::spawn(preflight_future)` path.

Introduce a transport-owned bounded-child registry for one-shot auxiliary tasks.

Possible design:

```rust
auxiliary_tasks: Arc<Mutex<HashMap<MeshTaskId, JoinHandle<MeshTaskExit>>>>
```

or reuse a dedicated `MeshTaskGroup` child facility that is available after startup commit.

Required behavior:

- startup preflight remains staged;
- steady-state preflight is registered under transport ownership;
- completion is reaped;
- shutdown/recovery aborts and awaits outstanding preflight tasks;
- preflight cannot mutate state after peer rollback/shutdown completion.

## Phase 14 — Bind Preflight To Peer Lifetime

Associate each preflight task with peer/session identity.

Suggested metadata:

```rust
pub struct AuxiliaryTask {
    pub task_id: MeshTaskId,
    pub session_id: Option<String>,
    pub kind: AuxiliaryTaskKind,
    pub handle: JoinHandle<MeshTaskExit>,
}
```

When a peer session is removed or rolled back:

- cancel auxiliary tasks associated with that session;
- await their termination;
- then finalize topology/DHT removal.

This ordering prevents late cache/route mutations for a removed peer.

## Phase 15 — Add Peer-Session Completion Reaping

A completed session must not remain indefinitely in `peer_sessions`.

Preferred architecture:

- session task sends `PeerSessionExit` over a stable completion channel;
- a transport-owned reaper removes the matching registry entry;
- exit reason is logged/recorded;
- stale handle entries do not accumulate.

Suggested type:

```rust
pub struct PeerSessionExit {
    pub session_id: String,
    pub node_id: String,
    pub reason: PeerSessionExitReason,
}
```

Alternative: periodic `JoinHandle::is_finished()` reaping, though a completion channel is more deterministic.

The reaper itself must be owned by the transport task group.

## Phase 16 — Define Peer Session Exit Reasons

Introduce explicit classification:

```rust
pub enum PeerSessionExitReason {
    Clean,
    ConnectionClosed,
    Cancelled,
    Error(String),
    Panic(String),
    Aborted,
}
```

If `peer_message_loop()` currently returns `()`, consider returning `Result<PeerSessionExitReason, E>` or wrapping panic/error classification around it.

This metadata should drive:

- registry reaping;
- shutdown report;
- rollback report;
- diagnostics/metrics.

## Phase 17 — Correct Normal Shutdown Session Reporting

Current logic treats every `JoinError` as drained.

Required mapping:

- `Ok(())` / expected connection close -> drained;
- explicit forced abort -> aborted;
- panic -> failed;
- unexpected cancellation before forced abort -> failed or cancelled, but not drained.

Extend `MeshShutdownReport` if necessary:

```rust
pub failed_peer_sessions: usize
```

or retain detailed session exits in a vector.

The sum of drained + aborted + failed should equal sessions present at shutdown start, after accounting for already-reaped sessions.

## Phase 18 — Remove Registry Entries On Session Completion

The session reaper should remove entries only when the completion event matches the current session generation/identity.

Protect against session-ID reuse or replacement by including a task/session generation ID.

Suggested key:

```rust
PeerSessionTaskId {
    session_id: String,
    generation: u64,
}
```

Do not let a late completion from an old session remove a newer entry with the same logical key.

## Phase 19 — Verify Accept-Loop Generation On Read

The accept-loop report now carries a generation, but shutdown should verify it matches the active transport generation before using its counts.

Add an authoritative startup generation field on `MeshTransport` if not already present.

On mismatch:

- log/report stale data;
- do not attribute old counts to current shutdown;
- treat current counts as unavailable or zero with explicit diagnostic.

## Phase 20 — Tighten Recovery Verification

Before `recover_failed_state()` transitions to `Stopped`, assert:

- task group active counts are zero;
- peer-session registry is empty;
- auxiliary/preflight task registry is empty;
- peer connection map is empty;
- runtime endpoint is stopped;
- failed-startup residue is empty;
- staged topology/DHT state has been restored;
- running projection is false;
- accept-loop report belongs to no active generation.

Return `StartupRollbackFailed` with all verification issues otherwise.

## Phase 21 — Behavioral Tests For Task-Group Replacement

Required test:

1. install an old task group with one live task;
2. begin a new staged startup;
3. reach commit;
4. assert commit fails before replacement;
5. assert old task remains owned and can be shut down;
6. assert staged group is rolled back;
7. assert no detached counter continues changing.

Add a clean empty-group replacement test as the positive case.

## Phase 22 — Topology Snapshot Timing Tests

Required cases:

### Existing Peer

- install topology state A;
- startup attempts to write state B;
- fail after mutation;
- rollback restores exact A.

The test should fail if the snapshot is captured after the write.

### New Peer

- no prior entry;
- startup writes B;
- rollback removes B.

### Metadata Fidelity

- verify capabilities, trust, ports, upstreams, health/status, and other retained fields.

## Phase 23 — DHT Mutation Tests

Required cases:

- absent peer -> `Created`, rollback removes;
- existing peer -> `Replaced(previous)`, rollback restores;
- unchanged peer -> `None`/`Unchanged`, rollback leaves it intact;
- DHT disabled -> no mutation;
- session ID differs from node ID -> rollback uses native DHT key.

## Phase 24 — Recovery Completeness Tests

Construct a `Failed` transport containing:

- live top-level critical/background task;
- live peer session;
- live preflight/auxiliary task;
- peer connection;
- active runtime endpoint;
- failed-startup topology/DHT residue.

Call `recover_failed_state(timeout)` and assert:

- all handles are aborted/joined;
- runtime stops;
- topology/DHT restores;
- registries empty;
- lifecycle becomes `Stopped` only after full verification.

Add a cleanup-failure variant that remains `Failed`.

## Phase 25 — Abort-And-Await Deadline Tests

Required tests:

- cooperative deadline already expired before session cleanup;
- session is aborted and still awaited;
- drop guard proves task destruction occurred before rollback returns;
- multiple hung sessions do not escape ownership;
- forced cleanup is accurately counted.

## Phase 26 — Preflight Ownership Tests

Required cases:

- steady-state preflight appears in auxiliary registry;
- normal completion is reaped;
- peer removal cancels associated preflight;
- shutdown aborts/awaits hung preflight;
- recovery clears preflight residue;
- no bare `tokio::spawn(preflight_future)` remains.

## Phase 27 — Session Reaper Tests

Required cases:

- clean session completion removes registry entry;
- panic completion removes registry entry and reports failure;
- cancelled/aborted session is classified correctly;
- stale completion cannot remove a newer session entry;
- long-running connection churn does not grow the registry monotonically.

## Phase 28 — Guardrail Updates

Strengthen `tests/mesh_task_ownership_guard.rs`.

Add checks that:

- non-empty old task group causes an error before replacement;
- topology snapshot code appears before `topology.add_peer()` in the outbound path;
- DHT mutation is not derived from `rm.is_enabled()`;
- `recover_failed_state()` calls task-group shutdown/join and consumes its timeout;
- aborted session handles are awaited unconditionally;
- no bare steady-state preflight spawn remains;
- a peer-session completion/reaping path exists;
- shutdown does not map all `JoinError`s to drained;
- recovery verifies task/session/auxiliary registries.

Behavioral tests remain authoritative.

## Phase 29 — Documentation Cleanup

Update:

- `architecture/mesh_transport_lifecycle.md`
- `architecture/mesh.md`
- `skills/synvoid_mesh.md`
- `AGENTS.md`
- `crates/synvoid-mesh/AGENTS.override.md` if present

Document:

- hard rejection of non-empty task-group replacement;
- pre-mutation topology/DHT snapshots;
- retained failed-startup residue;
- full recovery ownership guarantees;
- cooperative deadline versus forced abort-and-await;
- owned auxiliary/preflight tasks;
- peer-session completion reaping and exit classification;
- worker mesh supervision remains deferred.

## Phase 30 — Suggested Implementation Sequence

Implement in this order:

1. Make task-group replacement fail before swap.
2. Move topology snapshot before mutation and preserve native state.
3. Add DHT mutation-result/snapshot APIs.
4. Add failed-startup residue retention.
5. Upgrade `recover_failed_state()` to full task/resource cleanup.
6. Guarantee unconditional await after forced session abort.
7. Introduce owned auxiliary/preflight task registry.
8. Add peer-session completion channel/reaper.
9. Correct session exit classification and reports.
10. Add tests, guardrails, and docs.

## Phase 31 — Verification Commands

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

If DHT snapshot APIs or topology native snapshot types affect other crates:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This corrective pass is complete when:

1. A non-empty old task group is never replaced or dropped.
2. Topology state is snapshotted before startup mutation and restored exactly.
3. DHT mutation tracking distinguishes created, replaced, unchanged, and disabled cases.
4. DHT rollback restores prior state rather than blindly removing enabled peers.
5. Failed-state recovery consumes its timeout and cleans the top-level task group.
6. Recovery verifies every owned task/resource registry before returning to `Stopped`.
7. Incomplete rollback retains enough residue metadata for explicit recovery.
8. Every forced peer-session abort is awaited before rollback/shutdown/recovery returns.
9. Steady-state preflight work is transport-owned and joined.
10. Completed peer-session tasks are reaped from the registry.
11. Session shutdown reports distinguish drained, aborted, and failed outcomes.
12. No lifecycle-owned task, session, preflight child, connection, runtime endpoint, topology mutation, or DHT mutation survives successful rollback, shutdown, or recovery.
13. Worker mesh supervision remains accurately documented as deferred.
14. Existing blocklist, threat-intel, provenance, mesh-ID, composition, worker lifecycle, and mesh ownership guardrails remain green.

## Notes for the Implementer

This should be the final mesh-local lifecycle corrective pass.

The important work is semantic rather than structural: capture state before mutation, refuse unsafe replacement rather than logging it, and never treat dropping an owned handle as cleanup.
