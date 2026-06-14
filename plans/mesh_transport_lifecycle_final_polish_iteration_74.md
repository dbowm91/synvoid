# Mesh Transport Lifecycle Final Polish — Iteration 74

## Purpose

Iteration 73 corrected the major lifecycle-semantics defects in `MeshTransport`: unsafe task-group replacement, post-mutation topology snapshots, inferred DHT mutation state, incomplete failed-state recovery, detached steady-state preflight work, missing peer-session exit classification, and stale session-reaper generations.

The combined state at `f76fdb7cdd6e69cf3a18c960ec05e6af682d916d` is structurally sound, but seven narrow correctness gaps remain:

1. `recover_failed_state()` clears `FailedStartupResidue` without applying the residue's retained topology and DHT restoration data.
2. The session reaper removes `PeerSessionTask` entries without awaiting the removed `JoinHandle`.
3. The session reaper has no shutdown branch and therefore normally exits only through forced task-group abort.
4. Topology restoration reconstructs `MeshPeerInfo` from `PeerState` instead of restoring the native `PeerState` directly, losing state such as DNS health and potentially other internal fields.
5. DHT rollback snapshots only address, port, and role rather than the complete native `PeerContact`.
6. Completed auxiliary/preflight tasks remain in `auxiliary_tasks` until shutdown, rollback, or recovery.
7. Steady-state outbound peer sessions still use generation `0`, and stale accept-loop report counts are still copied into shutdown reports after generation mismatch.

This pass should make lifecycle ownership and restoration claims literally true, then close the mesh-local lifecycle subsystem. Worker-level mesh supervision remains explicitly deferred.

The core invariant is:

> A lifecycle cleanup operation may report success only after every owned handle has been joined and every retained logical-state snapshot has been applied or verified; stale-generation data must never be reported as current state.

---

## Current Known State

At `f76fdb7cdd6e69cf3a18c960ec05e6af682d916d`:

- `commit_startup()` rejects a non-empty old task group before replacement.
- topology state is captured before mutation.
- DHT state is captured before mutation.
- startup-created peer resources are retained in `StagedPeerResource`.
- incomplete rollback stores `FailedStartupResidue` on `MeshTransport`.
- `recover_failed_state(timeout)`:
  - acquires the lifecycle operation lock;
  - checks state is `Failed`;
  - signals the top-level task group;
  - stops the QUIC runtime;
  - closes connections;
  - drains/aborts peer sessions;
  - joins top-level tasks;
  - aborts auxiliary tasks;
  - clears the accept-loop report;
  - verifies task/session/connection/auxiliary counts.
- steady-state preflight is tracked in `auxiliary_tasks`.
- peer-session exits are published through `session_exit_tx`.
- `spawn_session_reaper()` removes registry entries when exit generation matches.
- inbound peer sessions use a transport-level generation counter.
- outbound startup sessions use the startup-stage generation counter.
- outbound steady-state sessions currently use generation `0`.
- shutdown distinguishes drained, aborted, and failed peer sessions.

Known remaining defects:

- recovery discards retained residue without restoring its topology or DHT state;
- session reaper drops completed session handles without awaiting them;
- session reaper has no cancellation branch;
- topology rollback is still a lossy conversion;
- DHT rollback is still a reduced-state conversion;
- auxiliary task registry does not reap completed tasks;
- steady-state outbound session generation remains zero;
- stale accept-loop counts are warned about but still used.

---

## Non-Goals

Do not enable worker-level mesh supervision in this iteration.

Do not change DHT/Raft consistency boundaries.

Do not change peer authentication, TLS validation, blocklist, threat-intel, or membership policy.

Do not add task restart policy.

Do not redesign the QUIC handshake or mesh wire protocol.

Do not migrate unrelated worker or mesh tasks.

Do not broaden this pass into general routing-table or topology refactoring beyond the restoration APIs required here.

---

# Part A — Recovery Must Apply Retained Residue

## Phase 1 — Add One Shared Peer-Restoration Helper

Extract the existing rollback topology/DHT restoration logic into one helper used by both startup rollback and failed-state recovery.

Suggested signature:

```rust
async fn restore_staged_peer_resource(
    &self,
    resource: &StagedPeerResource,
) -> Result<(), String>
```

Required behavior:

1. Close/remove the staged peer connection if still present.
2. Cancel and join any auxiliary tasks bound to the session.
3. Cancel and join any peer session matching the staged session ID and generation.
4. Restore topology state from `previous_topology`.
5. Restore DHT state from `dht_mutation`.
6. Verify the startup-created connection/session no longer exists.

Do not duplicate slightly different rollback and recovery restoration code.

The helper should be idempotent:

- removing an already-removed new topology entry is success;
- restoring an already-restored topology entry is success;
- removing an already-removed DHT entry is success;
- restoring an already-restored DHT entry is success.

## Phase 2 — Apply `FailedStartupResidue` During Recovery

Change `recover_failed_state()` so it takes, applies, and conditionally clears the residue.

Required sequence:

```rust
let residue = self.failed_startup_residue.lock().await.take();

if let Some(residue) = residue {
    for peer in &residue.peers {
        if let Err(error) = self.restore_staged_peer_resource(peer).await {
            recovery_errors.push(error);
        }
    }
}
```

Important: do not permanently clear the residue before restoration succeeds.

Safer pattern:

```rust
let residue = {
    let mut guard = self.failed_startup_residue.lock().await;
    guard.take()
};

let restoration_result = apply_residue(&residue).await;

if restoration_result.is_err() {
    *self.failed_startup_residue.lock().await = residue;
}
```

If recovery is incomplete, retain the unresolved residue so a later recovery attempt still has the required metadata.

## Phase 3 — Preserve Residue On Partial Recovery

If only some residue entries restore successfully:

- remove successfully restored entries from the retained residue;
- retain only unresolved peer resources;
- append new recovery errors to `rollback_errors`;
- keep lifecycle state `Failed`.

Suggested approach:

```rust
let mut remaining = Vec::new();
for peer in residue.peers {
    match restore(peer).await {
        Ok(()) => {}
        Err(error) => {
            remaining.push(peer);
            errors.push(error);
        }
    }
}
```

Then store a new `FailedStartupResidue` containing only `remaining`.

## Phase 4 — Verify Logical State, Not Only Empty Registries

Extend recovery verification to check logical restoration.

For each residue peer that was successfully restored:

- if `previous_topology == None`, topology must not contain the peer;
- if `previous_topology == Some(snapshot)`, topology must equal the snapshot;
- if DHT mutation was `Created`, routing table must not contain the peer;
- if DHT mutation was `Replaced`/`UpdatedInPlace`, routing table must equal the previous snapshot.

Add helper predicates if needed:

```rust
async fn topology_matches_snapshot(...)
async fn dht_matches_snapshot(...)
```

Do not mark recovery clean merely because `failed_startup_residue` was set to `None`.

---

# Part B — Exact Native Topology Restoration

## Phase 5 — Add Native `PeerState` Restoration API

Add an internal topology method that restores the exact stored peer state.

Suggested API in `crates/synvoid-mesh/src/mesh/topology.rs`:

```rust
pub async fn restore_peer_state(&self, peer: PeerState) {
    // replace native state directly
}
```

Use the topology's native storage key and synchronization primitive.

Required properties:

- every `PeerState` field is preserved;
- no lossy conversion through `MeshPeerInfo`;
- prior status, health, timestamps, scores, counters, trust state, DNS health, ports, capabilities, upstreams, and metadata are restored exactly;
- restoration is idempotent.

If topology stores additional indexes/caches derived from `PeerState`, update them consistently.

## Phase 6 — Use Native Restoration In Rollback

Replace rollback code that reconstructs `MeshPeerInfo` with:

```rust
self.topology
    .restore_peer_state(snapshot.peer_state.clone())
    .await;
```

For `previous_topology == None`, continue removing the newly created entry.

Do not hardcode `dns_serving_healthy: false`.

## Phase 7 — Use Native Restoration In Recovery

The shared peer-restoration helper from Phase 1 must use the same native topology API.

Rollback and recovery must not diverge.

## Phase 8 — Add Exact Topology Equality Tests

Create a `PeerState` fixture with non-default values for every relevant field, including:

- status;
- DNS health;
- latency;
- trust;
- capabilities;
- role;
- all ports;
- upstreams;
- audit counters;
- reputation/score fields;
- last-seen/created timestamps where deterministic;
- any failure counters or health metadata.

Test:

1. Insert state A.
2. Startup mutates it to state B.
3. Force startup failure.
4. Rollback restores exact A.
5. Compare native `PeerState`, not a subset projection.

Repeat through `recover_failed_state()` after intentionally incomplete first rollback.

---

# Part C — Exact Native DHT Restoration

## Phase 9 — Replace Reduced `DhtPeerSnapshot`

Current `DhtPeerSnapshot` stores only node ID, address, port, and role.

Prefer storing the complete native routing contact:

```rust
pub struct DhtPeerSnapshot {
    pub contact: PeerContact,
}
```

If `PeerContact` cannot be cloned directly, create a complete serializable snapshot containing every mutable field:

- native node ID/hash;
- node ID string;
- address;
- port;
- latency;
- global flag;
- trusted flag;
- geo;
- PoW nonce;
- public key;
- any routing score/failure/last-seen metadata stored on the contact.

Do not omit fields that `add_peer()` can modify.

## Phase 10 — Add Native Routing Contact Restore API

In `DhtRoutingManager`, add:

```rust
pub async fn restore_peer_contact(&self, snapshot: &DhtPeerSnapshot)
```

The method should directly reinsert/replace the full prior contact rather than reconstructing a reduced contact.

Use the routing table's native insertion/update semantics.

If `try_insert()` refuses an older or lower-scored contact, add an explicit internal replacement API for rollback restoration.

## Phase 11 — Add DHT Snapshot Equality Helper

Add a test/internal method:

```rust
pub async fn peer_matches_snapshot(
    &self,
    snapshot: &DhtPeerSnapshot,
) -> bool
```

This allows rollback/recovery verification to prove exact logical restoration.

## Phase 12 — Distinguish `Replaced` And `UpdatedInPlace` Honestly

Current code maps any pre-existing DHT entry to `Replaced`.

For this pass, choose one of two outcomes:

### Preferred

Compare pre- and post-mutation contacts:

- identical -> `None`;
- same logical entry mutated -> `UpdatedInPlace(previous)`;
- replacement semantics -> `Replaced(previous)`;
- absent before -> `Created`.

### Acceptable

Collapse both prior-entry cases into one variant:

```rust
Previous(DhtPeerSnapshot)
```

This is simpler and more honest than exposing distinctions the runtime does not determine.

Do not retain unused semantic variants that imply precision not present in code.

## Phase 13 — Add Exact DHT Restoration Tests

Test prior contacts with non-default:

- latency;
- trust;
- geo;
- PoW nonce;
- public key;
- global/edge role;
- address/port.

Required cases:

1. Absent before -> rollback removes created entry.
2. Present before -> rollback restores every field.
3. DHT disabled -> no mutation or restoration.
4. Recovery from retained residue restores every field.

---

# Part D — Session Reaper Must Remain An Owner

## Phase 14 — Make Session Reaper Cancellation-Aware

`spawn_session_reaper()` currently waits only on `session_exit_tx.recv()`.

Give it a task-group shutdown receiver/token and select over both:

```rust
loop {
    tokio::select! {
        event = exit_rx.recv() => { ... }
        _ = shutdown.changed() => {
            if *shutdown.borrow() {
                break;
            }
        }
    }
}
```

Use the same cancellation mechanism as other `MeshTaskGroup` tasks.

Expected shutdown classification:

- reaper exits normally after shutdown intent;
- task wrapper records expected cancellation/clean completion;
- normal shutdown should not routinely abort the reaper.

## Phase 15 — Await Removed Session Handles

When the reaper receives a matching exit:

1. lock `peer_sessions`;
2. remove the matching `PeerSessionTask`;
3. release the lock;
4. await the removed handle;
5. record/log the final join outcome.

Required pattern:

```rust
let removed = {
    let mut sessions = peer_sessions.lock().await;
    match sessions.get(&exit.session_id) {
        Some(task) if task.generation == exit.generation => {
            sessions.remove(&exit.session_id)
        }
        _ => None,
    }
};

if let Some(task) = removed {
    match task.handle.await {
        Ok(()) => {}
        Err(error) if error.is_panic() => { ... }
        Err(error) => { ... }
    }
}
```

Never await while holding the registry lock.

## Phase 16 — Preserve Exit Metadata Through Join

The exit event describes the peer-session loop result. The `JoinHandle` result describes the wrapper task.

Use both:

- `PeerSessionExitReason` for domain-level session outcome;
- `JoinError` for wrapper panic/cancellation.

If the wrapper join panics after sending an exit event, record the wrapper failure separately.

## Phase 17 — Handle Reaper Lag Safely

A broadcast reaper can lag and lose exit notifications.

Current behavior only logs lag.

On `RecvError::Lagged`:

- scan `peer_sessions` for `handle.is_finished()`;
- remove and await finished handles;
- classify their completion from join result;
- prevent stale finished entries from accumulating.

Extract a helper:

```rust
async fn reap_finished_peer_sessions(&self)
```

Use it:

- after lag;
- periodically if desired;
- before shutdown drains the registry;
- during recovery verification.

## Phase 18 — Reaper Shutdown Test

Test:

1. Start reaper.
2. Send task-group shutdown.
3. Assert reaper exits cooperatively.
4. Assert top-level shutdown report does not list `session_reaper` as aborted.
5. Assert task group is empty.

## Phase 19 — Reaper Join Ownership Test

Use a drop guard in a session wrapper after sending the exit event.

Assert:

- reaper removes the registry entry;
- reaper awaits the wrapper handle;
- drop guard fires before reaping is considered complete.

---

# Part E — Auxiliary Task Completion Reaping

## Phase 20 — Add Auxiliary Exit Channel

Introduce a stable auxiliary completion channel:

```rust
auxiliary_exit_tx: broadcast::Sender<AuxiliaryTaskExit>
```

Suggested type:

```rust
pub struct AuxiliaryTaskExit {
    pub task_id: MeshTaskId,
    pub session_id: Option<String>,
    pub reason: MeshTaskExitReason,
}
```

Every steady-state auxiliary task wrapper should publish one exit event before returning.

## Phase 21 — Add Auxiliary Task Reaper

Spawn one transport-owned reaper task after startup commit.

Responsibilities:

- receive auxiliary exit events;
- remove matching task ID from `auxiliary_tasks`;
- await removed handle outside the lock;
- ignore stale/unknown task IDs safely;
- respond to task-group shutdown cancellation;
- handle broadcast lag by scanning `is_finished()` handles.

The reaper itself must be registered in `MeshTaskGroup`.

## Phase 22 — Avoid One Reaper Per Task Type If Unnecessary

A shared auxiliary reaper is preferred over spawning cleanup work per preflight task.

Do not have an auxiliary task remove its own handle entry directly.

## Phase 23 — Ensure Rollback/Shutdown Remain Compatible

Rollback and shutdown may remove auxiliary tasks before the reaper receives their exit event.

The reaper must tolerate missing task IDs.

Use task IDs as the sole registry identity.

## Phase 24 — Auxiliary Churn Test

Simulate many short-lived preflight tasks.

Assert:

- registry grows while tasks are active;
- registry returns to zero after completions;
- no monotonic accumulation;
- shutdown has no stale completed auxiliary entries;
- lag recovery reaps finished handles.

---

# Part F — Use Global Session Generations Everywhere

## Phase 25 — Remove Zero Generation For Steady-State Outbound Sessions

Current outbound code sets:

```rust
let session_generation_for_task = if let Some(stage) = stage {
    stage.next_session_generation()
} else {
    0
};
```

Replace with a transport-global allocator for every session:

```rust
let generation = self.session_generation.fetch_add(1, Ordering::SeqCst) + 1;
```

For startup sessions, record this same global generation in `StagedPeerResource`.

The stage-local generation counter can then be removed unless used elsewhere.

## Phase 26 — Use One Generation Domain

Inbound and outbound sessions must share the same generation allocator.

Required property:

- no live or historical peer session on one `MeshTransport` instance reuses a generation;
- session ID + generation uniquely identifies a registry entry lifetime.

Use the same `session_generation` atomic for:

- inbound accepted sessions;
- outbound startup sessions;
- outbound steady-state sessions.

## Phase 27 — Remove Legacy Generation-Zero Compatibility

After all session creation paths use a nonzero generation:

- remove comments and tests permitting generation zero;
- guard against zero in debug assertions if useful;
- keep reaper matching strict equality only.

## Phase 28 — Generation Test Matrix

Test:

- inbound generation > 0;
- outbound startup generation > 0;
- outbound steady-state generation > 0;
- generations are monotonic/unique;
- stale exit from older generation cannot remove newer same-session-key entry.

---

# Part G — Stale Accept-Loop Reports Must Not Be Published As Current

## Phase 29 — Add Report Freshness Status

Extend `MeshShutdownReport` with an explicit freshness indicator:

```rust
pub accept_loop_report_fresh: bool
```

or:

```rust
pub accept_loop_report: Option<MeshAcceptLoopReport>
```

Preferred:

```rust
pub accept_loop_report: Option<MeshAcceptLoopReport>
```

where `None` means unavailable/stale.

If preserving existing integer fields is required for compatibility, add:

```rust
pub accept_loop_report_stale: bool
```

## Phase 30 — Suppress Stale Counts

On generation mismatch:

- log a warning;
- do not copy stale drained/aborted handshake counts into current report;
- set counts to zero and `stale = true`, or set optional report to `None`.

Do not knowingly label old-generation counts as current-generation data.

## Phase 31 — Reset Report After Shutdown

After consuming a fresh report for shutdown:

- reset counts;
- retain or clear generation according to chosen model;
- ensure repeated shutdown calls cannot reuse old counts.

## Phase 32 — Accept Report Tests

Required tests:

- matching generation -> counts copied and freshness true;
- mismatched generation -> counts suppressed and freshness false;
- no startup generation -> no false stale warning;
- new startup resets prior report;
- repeated shutdown does not reuse counts.

---

# Part H — Recovery Ordering And Error Semantics

## Phase 33 — Reorder Recovery To Apply Logical Restoration Before Clearing Residue

Recommended recovery ordering:

1. Acquire lifecycle operation lock.
2. Verify state `Failed`.
3. Compute deadline.
4. Signal top-level shutdown.
5. Stop runtime.
6. Close connections.
7. Cancel/await sessions.
8. Cancel/await auxiliary tasks.
9. Join top-level task group.
10. Take retained residue.
11. Apply topology and DHT restoration.
12. Verify physical and logical state.
13. Clear residue only after successful verification.
14. Transition to `Stopped`.

If logical restoration fails, keep state `Failed` and retain unresolved residue.

## Phase 34 — Recovery Must Not Hide Restoration Failures

Return:

```rust
MeshTransportError::StartupRollbackFailed {
    startup_error: "Recovery from Failed state".to_string(),
    rollback_errors: errors,
}
```

Include:

- task cleanup failures;
- session/auxiliary cleanup failures;
- topology restoration failures;
- DHT restoration failures;
- verification failures.

## Phase 35 — Add Recovery Report Internally

Optionally add an internal `RecoveryReport` for testing/telemetry:

```rust
pub struct RecoveryReport {
    pub tasks_joined: usize,
    pub sessions_joined: usize,
    pub auxiliary_joined: usize,
    pub topology_restored: usize,
    pub dht_restored: usize,
    pub errors: Vec<String>,
}
```

Public API may remain `Result<(), MeshTransportError>`.

---

# Part I — File-Level Implementation Guide

## Phase 36 — `crates/synvoid-mesh/src/mesh/topology.rs`

Implement:

- `restore_peer_state(PeerState)`;
- optional `peer_state_matches(&PeerState)` helper for tests/verification.

Do not reconstruct through `MeshPeerInfo`.

## Phase 37 — `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs`

Implement:

- complete native DHT snapshot;
- complete native restore;
- snapshot equality verification;
- optional explicit replace method if routing-table insertion policy prevents restoration.

## Phase 38 — `crates/synvoid-mesh/src/mesh/lifecycle.rs`

Update:

- `DhtPeerSnapshot` to complete native state;
- `DhtPeerMutation` variants if simplified;
- `AuxiliaryTaskExit` type;
- shutdown-report accept freshness field;
- remove stage-local session generation if no longer needed;
- optional `RecoveryReport`.

## Phase 39 — `crates/synvoid-mesh/src/mesh/transport.rs`

Implement:

- shared peer restoration helper;
- residue-aware recovery;
- cancellation-aware session reaper;
- session handle await in reaper;
- finished-session scan on lag;
- auxiliary exit channel/reaper;
- global generation use for all session paths;
- stale accept-report suppression;
- updated shutdown/recovery verification.

## Phase 40 — `crates/synvoid-mesh/src/mesh/transport_peer.rs`

Update `peer_message_loop()` only if needed for clearer exit reasons.

Ensure every return path preserves the supplied generation.

## Phase 41 — `crates/synvoid-mesh/src/mesh/transport_connection.rs`

Ensure clone helpers share:

- session generation allocator;
- session exit channel;
- auxiliary exit channel;
- auxiliary registry;
- accept report;
- failed residue.

No clone-local lifecycle registry/channel should be allocated.

---

# Part J — Tests A Smaller Model Must Add

## Phase 42 — Recovery Residue Test

Test exact sequence:

1. Create prior topology A and DHT A.
2. Start mutation to topology B and DHT B.
3. Force rollback cleanup failure so residue is retained.
4. Assert state becomes `Failed`.
5. Call `recover_failed_state()`.
6. Assert topology exactly equals A.
7. Assert DHT exactly equals A.
8. Assert residue is cleared only after restoration.
9. Assert lifecycle becomes `Stopped`.

## Phase 43 — Recovery Partial Failure Test

1. Retain residue for two peers.
2. Make one restoration fail.
3. Run recovery.
4. Assert lifecycle remains `Failed`.
5. Assert returned error includes restoration failure.
6. Assert residue still contains the unresolved peer only.

## Phase 44 — Session Reaper Await Test

1. Spawn a session wrapper that sends exit then blocks briefly before returning.
2. Reaper receives exit and removes entry.
3. Assert reaper does not consider cleanup complete until wrapper returns.
4. Verify drop guard occurs before handle is discarded.

## Phase 45 — Session Reaper Cancellation Test

1. Start reaper.
2. Trigger task-group shutdown.
3. Assert reaper exits without forced abort.
4. Assert shutdown report classifies it as clean/cancelled.

## Phase 46 — Reaper Lag Test

1. Overflow the broadcast channel or directly trigger lag handling.
2. Leave finished session handles in registry.
3. Assert lag recovery scans and joins finished handles.
4. Assert registry becomes empty.

## Phase 47 — Auxiliary Reaper Test

1. Spawn many short auxiliary tasks.
2. Publish completions.
3. Assert registry reaches zero.
4. Verify all handles were awaited.

## Phase 48 — Global Generation Test

Create:

- inbound session;
- outbound startup session;
- outbound steady-state session.

Assert all generations are nonzero and unique.

## Phase 49 — Stale Accept Report Test

1. Set current generation N.
2. Set report generation N-1 with nonzero counts.
3. Shutdown.
4. Assert stale counts are not copied.
5. Assert freshness flag/optional report indicates stale.

## Phase 50 — Exact Topology Snapshot Test

Use non-default native `PeerState` fields and compare full state after rollback and recovery.

## Phase 51 — Exact DHT Snapshot Test

Use non-default `PeerContact` fields and compare full contact after rollback and recovery.

---

# Part K — Guardrails

## Phase 52 — Update `tests/mesh_task_ownership_guard.rs`

Add source-level checks that:

- `recover_failed_state()` reads/applies `failed_startup_residue` before clearing it;
- topology rollback calls native `restore_peer_state`;
- DHT snapshot is not limited to address/port/role;
- session reaper selects on shutdown;
- session reaper awaits removed handle;
- auxiliary completion reaper exists;
- steady-state outbound generation does not use `0`;
- accept-report mismatch suppresses counts;
- no restoration path hardcodes `dns_serving_healthy: false`.

Behavioral tests remain authoritative.

## Phase 53 — Add No-Loss Snapshot Guard

If practical, add compile-time/test assertions that snapshot types contain the same relevant fields as native types, or avoid separate snapshot structs entirely by wrapping native cloneable types.

## Phase 54 — Keep Exceptions Reason-Bearing

Any remaining intentionally unawaited task or lossy snapshot exception must include an explicit code comment and guardrail allow-list reason.

The expected final state should have no such exception in the lifecycle paths covered by this plan.

---

# Part L — Documentation

## Phase 55 — Update Lifecycle Documentation

Update:

- `architecture/mesh_transport_lifecycle.md`;
- `architecture/mesh.md`;
- `skills/synvoid_mesh.md`;
- `AGENTS.md`;
- `crates/synvoid-mesh/AGENTS.override.md` if present.

Document:

- residue application during recovery;
- native topology and DHT restoration;
- reaper ownership and cancellation;
- auxiliary completion reaping;
- one global session-generation domain;
- accept-loop report freshness semantics;
- worker mesh supervision remains deferred.

## Phase 56 — Remove Overstated Claims

Before implementation is complete, remove or correct claims that:

- recovery already restores topology/DHT residue;
- session reaper fully joins removed tasks;
- DHT snapshot is exact;
- auxiliary entries self-reap;
- stale accept counts are never reported.

After implementation, document the actual guarantees precisely.

---

# Part M — Implementation Order

A smaller model should implement in this exact order:

1. Add native topology restore API and tests.
2. Replace DHT snapshot with complete native state and add restore tests.
3. Extract shared `restore_staged_peer_resource()` helper.
4. Apply retained residue during recovery and retain unresolved residue.
5. Make session reaper cancellation-aware.
6. Make session reaper remove-then-await handles.
7. Add lag fallback reaping for finished sessions.
8. Add auxiliary exit channel and reaper.
9. Replace all session generation allocation with the transport-global atomic.
10. Suppress stale accept-loop counts and add freshness reporting.
11. Extend recovery verification for logical state.
12. Add all behavioral tests.
13. Add guardrails.
14. Update documentation.

Do not combine these changes with worker-level mesh supervision.

---

# Part N — Verification Commands

Run focused tests first:

```bash
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test -p synvoid-mesh --features mesh topology
cargo test -p synvoid-mesh --features mesh dht
cargo test -p synvoid-mesh --features mesh startup
cargo test -p synvoid-mesh --features mesh shutdown
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Then regression checks:

```bash
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy -p synvoid-mesh --features mesh,dns -- -D warnings
```

If native topology/DHT snapshot APIs affect other crates:

```bash
cargo test --workspace --no-run
```

Record any pre-existing certificate-test failures separately; do not classify new failures as pre-existing without confirming against the base commit.

---

# Acceptance Criteria

This iteration is complete only when all of the following are true:

1. `recover_failed_state()` applies retained topology and DHT residue before clearing it.
2. Unresolved residue remains stored when recovery is incomplete.
3. Topology restoration uses the native `PeerState` without lossy conversion.
4. DHT restoration preserves the complete prior native routing contact.
5. Recovery verifies logical topology/DHT restoration, not only empty registries.
6. Session reaper exits cooperatively on shutdown.
7. Session reaper awaits every handle it removes from the registry.
8. Session-reaper lag cannot leave finished handles permanently registered.
9. Completed auxiliary tasks are reaped and their handles awaited.
10. Every inbound and outbound session uses a nonzero transport-global generation.
11. Stale session exits cannot remove newer entries.
12. Stale accept-loop reports do not contribute counts to current shutdown reports.
13. Shutdown reports expose accept-report freshness or unavailability explicitly.
14. No session, auxiliary task, task-group task, connection, runtime endpoint, topology mutation, DHT mutation, or residue survives a successful rollback, shutdown, or recovery.
15. Worker-level mesh supervision remains accurately documented as deferred.
16. Existing blocklist, threat-intel, provenance, mesh-ID, composition, worker-lifecycle, and mesh-ownership guardrails remain green.

---

## Notes For The Implementer

This is a final semantic-polish pass. Do not add new lifecycle abstractions unless required by one of the explicit ownership gaps above.

The most important rule is simple:

> Removing an entry from a registry is not equivalent to joining its task, and clearing a residue record is not equivalent to restoring the state it describes.
