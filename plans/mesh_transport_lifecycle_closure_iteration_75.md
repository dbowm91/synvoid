# Mesh Transport Lifecycle Closure Pass — Iteration 75

## Purpose

Iteration 74 completed most of the final mesh-local lifecycle work: retained residue is applied during recovery, topology and DHT restoration are verified, session and auxiliary reapers are cancellation-aware, removed handles are awaited, auxiliary tasks self-reap, all session paths use generation counters, and stale accept-loop reports are suppressed.

The review of `d7d6a03c15c5632680ebecf2f5d8c87d21041644` and `8bd716763999f6022bcc8301e3cf955e007bf3eb` identified five remaining correctness gaps:

1. DHT restoration calls normal `try_insert()`, which does not replace an existing contact and therefore cannot restore a mutated pre-existing routing entry.
2. Topology restoration does not update all secondary indexes and verification does not compare all relevant native `PeerState` fields.
3. Startup rollback restores topology/DHT state before the corresponding peer session and session-bound auxiliary tasks are fully terminated, allowing late task writes to invalidate the restoration after verification.
4. Recovery drops a peer from retained residue as soon as the restoration function returns `Ok`, even if subsequent verification fails.
5. Each peer session still detaches per-stream message handlers with bare `tokio::spawn()`, so joining the peer-session handle does not prove all session work has stopped.

This pass should close these final ownership and restoration races. After this iteration, the mesh-local lifecycle subsystem can be considered complete; worker-level mesh supervision remains a separate deferred target.

The primary invariant is:

> Physical work must terminate before logical state is restored, restoration must use force-replacement semantics and include all secondary indexes, and no peer session may report completion while child stream handlers remain alive.

---

## Current Known State

At `8bd716763999f6022bcc8301e3cf955e007bf3eb`:

- `restore_peer_logical_state()` is shared by rollback and recovery.
- `restore_peer_state()` restores the native topology `PeerState` into the primary peer store.
- `DhtPeerSnapshot` captures most `PeerContact` fields.
- `DhtRoutingManager::restore_peer()` reconstructs a contact and calls `RoutingTable::try_insert()`.
- rollback verifies topology and DHT state after restoration.
- recovery verifies topology and DHT state after residue restoration.
- session and auxiliary reapers await removed handles.
- all session creation paths use nonzero generations.
- `MeshShutdownReport.accept_loop_report` is `None` for stale generations.
- peer sessions are transport-owned through `peer_sessions`.

Known remaining defects:

- `try_insert()` only marks an existing contact seen; it does not overwrite its fields.
- DHT snapshot omits `last_seen`, `last_pinged`, and complete geographic coordinates during verification.
- topology `global_nodes` can remain stale when restoring/removing global peers.
- topology verification omits `capabilities`, `first_seen`, `last_seen`, `previous_reputation`, and secondary-index membership.
- rollback restoration occurs before staged session and auxiliary task termination.
- verification-failed residue entries are not re-retained.
- `peer_message_loop()` detaches each accepted bidirectional stream handler.

---

## Non-Goals

Do not enable worker-level mesh supervision.

Do not change DHT/Raft responsibility boundaries.

Do not change peer authentication, TLS validation, blocklist, threat-intel, or membership semantics.

Do not add general task restart policy.

Do not redesign the mesh wire protocol.

Do not refactor unrelated topology or DHT behavior beyond the force-restore and verification APIs required here.

---

# Part A — Force-Restore DHT Contacts

## Phase 1 — Add A Routing-Table Force-Replacement API

Add an internal API to `crates/synvoid-mesh/src/mesh/dht/routing/table.rs` that replaces the contact for an existing node ID without applying normal admission/update semantics.

Suggested API:

```rust
pub(crate) fn force_restore_contact(
    &mut self,
    contact: PeerContact,
) -> Result<(), InsertError>
```

Required behavior:

1. Reject the local node ID.
2. Locate the correct K-bucket using the contact node ID.
3. Remove any existing contact with the same node ID.
4. Insert the supplied contact exactly.
5. Invalidate `closest_cache`.
6. Remove or refresh any `pending_pings` entry for that node.
7. Do not run PoW admission checks during rollback restoration; the contact was previously accepted state.
8. Do not evict an unrelated peer to restore the same node ID.

If `KBucket` lacks a direct replace operation, implement one:

```rust
pub(crate) fn replace(&mut self, contact: PeerContact) -> Option<PeerContact>
```

or remove then insert after guaranteeing capacity.

## Phase 2 — Use Force Restoration In `DhtRoutingManager`

Replace:

```rust
table.try_insert(contact);
```

inside `restore_peer()` with the new force-replacement API.

Return a result:

```rust
pub async fn restore_peer(
    &self,
    snapshot: &DhtPeerSnapshot,
) -> Result<(), DhtRestoreError>
```

Do not silently ignore restoration failure.

`restore_peer_logical_state()` must convert the DHT restore error into its returned `Err(String)` so rollback/recovery retains the residue.

## Phase 3 — Make The DHT Snapshot Truly Native

Preferred approach: store the complete `PeerContact` directly.

```rust
#[derive(Debug, Clone)]
pub struct DhtPeerSnapshot {
    pub contact: PeerContact,
}
```

`PeerContact` is already `Clone`.

This avoids field drift when `PeerContact` evolves.

If direct storage creates module dependency problems, include every field:

- `node_id`;
- `node_id_string`;
- `address`;
- `port`;
- complete `geo`, including latitude and longitude;
- `latency_ms`;
- `last_seen`;
- `last_pinged`;
- `is_global`;
- `is_trusted`;
- `pow_nonce`;
- `public_key`.

Document whether restoring `last_seen`/`last_pinged` exactly is required. Preferred: exact restoration because the plan claims pre-start state restoration.

## Phase 4 — Make DHT Verification Compare The Native Contact

`peer_matches_snapshot()` should compare the complete native contact or every explicitly retained field.

Do not compare only country/region for `GeoInfo`; include latitude and longitude.

If timestamps are intentionally excluded, encode this explicitly in the snapshot type and method name, for example:

```rust
DhtPeerLogicalSnapshot
peer_matches_logical_snapshot()
```

Do not call the restoration exact while omitting fields silently.

## Phase 5 — Add Force-Restore Tests

Required cases:

### Existing Contact Mutated

1. Insert contact A with non-default values for all fields.
2. Update/replace it with contact B.
3. Call `restore_peer(snapshot_of_A)`.
4. Assert the routing table contains A, not B.

This test must fail under the current `try_insert()` implementation.

### Existing Contact In Full Bucket

- Fill the bucket.
- Mutate an existing contact.
- Restore it.
- Assert no unrelated contact was evicted.

### Cache Invalidation

- Prime `closest_cache` with the mutated contact.
- Restore prior contact.
- Assert subsequent lookup observes restored data.

### Pending Ping Cleanup

- Add a pending ping for the node.
- Force restore.
- Assert pending state is consistent with the chosen restore policy.

---

# Part B — Correct Topology Primary And Secondary State

## Phase 6 — Make `restore_peer_state()` Bidirectionally Update `global_nodes`

Current code inserts the node when `peer_state.is_global` but does not remove it otherwise.

Required implementation:

```rust
pub async fn restore_peer_state(&self, peer_state: PeerState) {
    let node_id = peer_state.node_id.clone();
    {
        let mut global = self.global_nodes.write().await;
        if peer_state.is_global {
            global.insert(node_id.clone());
        } else {
            global.remove(&node_id);
        }
    }
    self.peer_store.restore_peer_snapshot(...);
}
```

## Phase 7 — Remove Global Index Entries In `remove_peer()`

Update `MeshTopology::remove_peer()`:

```rust
self.global_nodes.write().await.remove(node_id);
```

Do this whether or not the primary peer entry exists, so cleanup is idempotent.

Audit any additional secondary topology indexes keyed by node ID and update them consistently.

At minimum inspect:

- `global_nodes`;
- compatibility score maps;
- peer versions;
- route stability;
- connection failure/success history;
- latency history;
- bandwidth tracking.

Determine which are part of startup-mutated peer state and which are intentionally preserved across reconnects.

## Phase 8 — Decide The Exact Topology Snapshot Boundary

`PeerState` restoration alone does not restore all per-peer entries in `ShardedPeerStore`, such as:

- `PeerScore`;
- connection failures;
- connection successes;
- latency history;
- peer version;
- route stability;
- bandwidth tracker.

Choose and document one of two models.

### Preferred — Full Peer Store Snapshot

Add:

```rust
pub struct PeerStoreSnapshot {
    pub peer: PeerState,
    pub score: Option<PeerScore>,
    pub connection_failures: Option<u32>,
    pub connection_successes: Option<u32>,
    pub latency_history: Option<Vec<(Instant, u32)>>,
    pub peer_version: Option<u64>,
    pub route_stability: Option<RouteStability>,
    pub bandwidth: Option<BandwidthStats>,
    pub global_index_member: bool,
}
```

Store this in `StagedTopologySnapshot` and restore it atomically under one shard lock.

### Acceptable — Explicit Logical Snapshot

If those secondary metrics intentionally survive connection replacement, rename/document the snapshot as logical peer state and list exclusions.

At minimum, ensure all values changed by `topology.add_peer()` are restored.

## Phase 9 — Add An Atomic Store Restoration API

Preferred API on `ShardedPeerStore`:

```rust
pub fn restore_peer_snapshot(&self, snapshot: PeerStoreSnapshot)
```

Acquire the shard write lock once and restore all included maps consistently.

Avoid calling separate setters that allow readers to observe a partially restored state.

## Phase 10 — Make Verification Match The Chosen Snapshot Boundary

Current `topology_matches_snapshot()` omits several `PeerState` fields.

If retaining `PeerState` snapshot, compare all fields except `connection_handle` if intentionally non-restorable:

- node ID;
- address;
- role;
- status;
- capabilities;
- upstreams;
- latency;
- first seen;
- last seen;
- global/trusted flags;
- geo;
- audit counters;
- performance counters;
- all ports;
- previous reputation.

Also verify:

```rust
self.global_nodes.read().await.contains(node_id) == snapshot.peer_state.is_global
```

If using `PeerStoreSnapshot`, compare all included secondary map entries.

## Phase 11 — Add Topology Secondary-Index Tests

Required cases:

### Global To Non-Global Restoration

- Prior state A is non-global.
- Startup writes global state B.
- Rollback restores A.
- Assert peer is absent from `global_nodes`.

### New Global Peer Removal

- Startup adds a new global peer.
- Rollback removes it.
- Assert primary store and `global_nodes` both lack the node.

### Non-Global To Global Restoration

- Prior state A is global.
- Startup writes non-global B.
- Rollback restores A.
- Assert `global_nodes` contains the node.

### Complete Field Equality

Use distinct non-default values for every snapshotted field and assert exact restoration.

---

# Part C — Teardown Before Logical Restoration

## Phase 12 — Reorder `rollback_startup()`

The current order restores/verifies logical state before terminating staged sessions.

Required rollback ordering:

1. Signal staged task-group shutdown.
2. Close staged peer connections.
3. Cancel and await session-bound auxiliary tasks.
4. Cancel and await staged peer sessions.
5. Join/abort remaining staged top-level tasks.
6. Stop staged runtime/listener resources.
7. Restore topology and DHT state.
8. Verify topology and DHT state.
9. Run final physical-resource verification.

The critical invariant is:

```text
no peer/session/auxiliary task that can mutate topology or DHT remains live before restoration begins
```

## Phase 13 — Extract One Staged Peer Teardown Helper

Suggested helper:

```rust
async fn stop_staged_peer_activity(
    &self,
    peer: &StagedPeerResource,
    deadline: Instant,
    report: &mut RollbackReport,
) -> Result<(), String>
```

Responsibilities:

- close connection;
- remove connection-map entry;
- cancel/await session-bound auxiliary tasks;
- remove, cancel, and await matching peer session using session ID and generation;
- verify no matching tasks remain.

Use this helper before `restore_peer_logical_state()`.

## Phase 14 — Preserve Global Deadline Semantics

Cooperative waits use `remaining(deadline)`.

When the deadline expires:

- abort remaining session/auxiliary handles;
- await them unconditionally;
- count forced aborts;
- continue to logical restoration only after handles are joined.

Do not skip restoration simply because the cooperative deadline elapsed, unless forced task destruction itself fails.

## Phase 15 — Reorder Verification

Logical verification must occur after all staged activity is stopped.

Final rollback verification order:

1. no staged sessions;
2. no staged auxiliary tasks;
3. no staged connections;
4. task group empty;
5. topology matches prior snapshot or peer absent;
6. DHT matches prior snapshot or peer absent;
7. runtime stopped;
8. running projection false.

## Phase 16 — Add Late-Write Race Test

Create a staged peer session whose shutdown path writes `PeerStatus::Disconnected` after connection closure.

Test:

1. Prior topology state is `Healthy`.
2. Startup replaces it.
3. Force rollback.
4. Session receives close and writes `Disconnected`.
5. Rollback waits for session completion.
6. Rollback restores prior `Healthy` state.
7. Assert final state remains `Healthy` after rollback returns.

This test must fail under the current restore-before-session-join order.

## Phase 17 — Add Auxiliary Late-Write Test

Create a session-bound auxiliary task that writes route/cache/topology state when released.

Trigger rollback while it is active.

Assert:

- auxiliary task is terminated before logical restoration;
- no late mutation occurs after rollback verification;
- final state matches snapshot.

---

# Part D — Retain Residue When Verification Fails

## Phase 18 — Replace Restore-Then-Separate-Verify With Restore-And-Verify

Add:

```rust
async fn restore_and_verify_peer_logical_state(
    &self,
    peer: &StagedPeerResource,
) -> Result<(), String>
```

Implementation:

1. call `restore_peer_logical_state(peer)`;
2. verify topology;
3. verify DHT;
4. return `Ok` only when all checks pass.

Use this helper in both rollback and recovery.

## Phase 19 — Retain Verification-Failed Peers In Recovery Residue

Current recovery removes a peer from residue after the restore call succeeds, before verification.

Required model:

```rust
for peer in residue.peers {
    match self.restore_and_verify_peer_logical_state(&peer).await {
        Ok(()) => successfully_restored += 1,
        Err(error) => {
            remaining_peers.push(peer);
            errors.push(error);
        }
    }
}
```

Store `remaining_peers` back into `failed_startup_residue`.

Do not clear the residue until every peer passes both restoration and verification.

## Phase 20 — Preserve Residue Across Repeated Recovery

A second recovery attempt must still have:

- topology snapshot;
- DHT snapshot;
- session/connection identity;
- startup generation;
- prior rollback errors.

Append new errors without discarding the original diagnostic history, but avoid unbounded duplicate strings if the same failure repeats.

Suggested deduplication:

```rust
if !rollback_errors.contains(&error) {
    rollback_errors.push(error);
}
```

## Phase 21 — Use The Same Semantics In `rollback_and_return()`

When startup rollback restoration or verification fails, retain only unresolved peers if possible rather than cloning every staged peer into residue.

Extend `RollbackReport` with:

```rust
pub unresolved_peer_ids: Vec<String>
```

or return unresolved resources directly from `rollback_startup()`.

Preferred type:

```rust
pub struct RollbackOutcome {
    pub report: RollbackReport,
    pub unresolved_peers: Vec<StagedPeerResource>,
}
```

Then `rollback_and_return()` stores only unresolved peers.

## Phase 22 — Add Verification-Failure Recovery Test

Test:

1. Residue contains peer snapshot A.
2. Force `restore_peer_logical_state()` to return `Ok` but make verification fail.
3. Recovery returns `StartupRollbackFailed`.
4. Lifecycle remains `Failed`.
5. Residue still contains peer A.
6. Fix restoration implementation/test hook.
7. Second recovery succeeds using retained A.

---

# Part E — Own Per-Stream Peer Message Handlers

## Phase 23 — Replace Detached Stream Spawns With Session-Local `JoinSet`

In `peer_message_loop()`, add:

```rust
let mut stream_handlers: JoinSet<Result<(), MeshTransportError>> = JoinSet::new();
```

Replace bare `tokio::spawn()` with:

```rust
stream_handlers.spawn(async move {
    transport
        .handle_peer_message(&mut send_stream, &mut recv_stream, &topo, peer_id)
        .await
});
```

The peer session remains the owner of every accepted stream handler.

## Phase 24 — Reap Completed Stream Handlers During The Session

Add a `tokio::select!` branch:

```rust
Some(result) = stream_handlers.join_next(), if !stream_handlers.is_empty() => {
    classify/log result;
}
```

This prevents completed handler accumulation during long-lived sessions.

Classification:

- `Ok(Ok(()))` -> clean handler completion;
- `Ok(Err(error))` -> log/metric handler failure;
- `Err(join_error)` panic -> log/metric panic;
- cancellation during session shutdown -> expected.

Decide whether one stream-handler failure is peer-session fatal. Recommended for this pass: nonfatal unless it indicates transport/session corruption.

## Phase 25 — Add Stream Handler Capacity Limit

A malicious peer can open many bidirectional streams.

Add a configured or constant maximum active stream handlers per peer session.

Suggested config:

```rust
pub max_concurrent_peer_streams: usize
```

Use a semaphore or reject/close streams when `stream_handlers.len()` reaches the limit.

Do not allow unbounded `JoinSet` growth.

## Phase 26 — Add Stream Handler Timeouts

Audit `handle_peer_message()` reads.

Apply bounded total or read timeout so a peer cannot keep one handler alive indefinitely with a partial message.

Suggested:

```rust
pub peer_message_timeout: Duration
```

Wrap the handler or its reads with `tokio::time::timeout()`.

This is required for bounded session shutdown.

## Phase 27 — Drain Handlers Before Emitting `PeerSessionExit`

When connection close/error is detected:

1. stop accepting new streams;
2. allow handlers to drain to a session-local deadline;
3. abort remaining handlers;
4. await every aborted handler;
5. only then update final topology status if appropriate;
6. return `PeerSessionExit`.

Suggested helper:

```rust
async fn drain_peer_stream_handlers(
    handlers: &mut JoinSet<Result<(), MeshTransportError>>,
    timeout: Duration,
) -> PeerStreamDrainReport
```

## Phase 28 — Avoid Late Topology Writes From Stream Handlers

Audit `handle_peer_message()` and called handlers for topology/DHT mutations.

The session must not return until all such handlers have stopped.

If a handler launches further tasks, those tasks must also be owned or awaited inline.

Add a source guard against bare `tokio::spawn()` inside:

- `peer_message_loop()`;
- `handle_peer_message()`;
- direct helper paths called for one peer stream.

Reason-bearing exceptions require explicit review.

## Phase 29 — Add Stream Drain Reporting

Optionally add:

```rust
pub struct PeerStreamDrainReport {
    pub drained: usize,
    pub aborted: usize,
    pub failed: usize,
}
```

Attach it to `PeerSessionExit` or metrics if useful.

At minimum, log aggregate counts at debug level and expose metrics without peer-ID labels.

## Phase 30 — Add Stream Ownership Tests

Required tests:

### Session Waits For Handler

- Start one stream handler with a drop guard.
- Close the connection.
- Assert peer session does not return before the handler is joined/aborted.

### Hung Handler

- Handler blocks beyond drain timeout.
- Session aborts and awaits it.
- Drop guard fires before `PeerSessionExit` is emitted.

### Many Completed Handlers

- Spawn many short handlers.
- Assert `JoinSet` is reaped during session lifetime.
- No unbounded accumulation.

### Capacity Limit

- Exceed maximum concurrent streams.
- Assert excess streams are rejected/closed without new handler tasks.

### Panic Classification

- One handler panics.
- Panic is observed and counted, not detached or silently lost.

---

# Part F — File-Level Implementation Guide

## Phase 31 — `crates/synvoid-mesh/src/mesh/dht/routing/table.rs`

Implement:

- `force_restore_contact()` or equivalent;
- cache invalidation;
- pending-ping cleanup;
- tests for replacement in occupied/full buckets.

## Phase 32 — `crates/synvoid-mesh/src/mesh/dht/routing/bucket.rs`

If needed, add a native replacement method that preserves bucket invariants and ordering.

Do not emulate replacement by normal insertion when the node already exists.

## Phase 33 — `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs`

Update:

- `DhtPeerSnapshot` capture;
- `restore_peer()` to return `Result` and force replace;
- `peer_matches_snapshot()` to compare the full declared snapshot boundary.

## Phase 34 — `crates/synvoid-mesh/src/mesh/topology/types.rs`

Add full peer-store snapshot support if selected.

At minimum add atomic getters/restorers for all fields considered part of lifecycle rollback.

## Phase 35 — `crates/synvoid-mesh/src/mesh/topology.rs`

Update:

- `restore_peer_state()` secondary indexes;
- `remove_peer()` secondary indexes;
- exact verification;
- optional full store-snapshot API.

## Phase 36 — `crates/synvoid-mesh/src/mesh/transport.rs`

Update:

- rollback ordering;
- staged peer activity teardown helper;
- restore-and-verify helper;
- unresolved residue retention;
- rollback outcome type if introduced.

## Phase 37 — `crates/synvoid-mesh/src/mesh/transport_peer.rs`

Update:

- session-local stream-handler `JoinSet`;
- capacity and timeout handling;
- handler reaping;
- shutdown drain/abort/await;
- final session exit after child completion.

## Phase 38 — `crates/synvoid-mesh/src/mesh/lifecycle.rs`

Update types as needed:

- native DHT snapshot;
- full topology/store snapshot;
- rollback unresolved resources/outcome;
- optional stream drain report.

---

# Part G — Guardrails

## Phase 39 — Update `tests/mesh_task_ownership_guard.rs`

Add checks that:

- DHT restore no longer calls `try_insert(contact)`;
- a force-replacement API exists;
- `restore_peer_state()` removes non-global peers from `global_nodes`;
- `remove_peer()` removes from `global_nodes`;
- topology verification includes capabilities, timestamps, previous reputation, and global index membership, or explicitly named logical-snapshot exclusions;
- rollback stops peer sessions before calling logical restoration;
- recovery retains peers whose verification fails;
- `peer_message_loop()` contains a `JoinSet`;
- no bare stream-handler `tokio::spawn()` remains;
- stream handlers are drained/aborted before `PeerSessionExit` return.

Behavioral tests remain authoritative.

## Phase 40 — Add Ordering Guard

Add a source-level guard asserting the rollback function places staged-session teardown before `restore_peer_logical_state()`.

This is a supplementary regression guard, not a substitute for the late-write behavioral test.

## Phase 41 — Add Snapshot Completeness Guard

Prefer native cloneable snapshot types to avoid field-list drift.

If using separate structs, add tests that enumerate native fields and fail when a new field is added without snapshot/verification handling.

---

# Part H — Documentation

## Phase 42 — Update Architecture Docs

Update:

- `architecture/mesh_transport_lifecycle.md`;
- `architecture/mesh.md`;
- `skills/synvoid_mesh.md`;
- `AGENTS.md`;
- `crates/synvoid-mesh/AGENTS.override.md` if present.

Document:

- force-replacement DHT restoration;
- topology secondary-index restoration;
- teardown-before-restoration ordering;
- residue retention through verification failure;
- session-local ownership of stream handlers;
- stream concurrency/time limits;
- worker mesh supervision remains deferred.

## Phase 43 — Remove Overstated “Exact” Claims Until Complete

Before implementation, correct claims that DHT/topology restoration is exact if the native snapshot boundary remains partial.

After implementation, state the exact included/excluded fields explicitly.

---

# Part I — Ordered Handoff Sequence

A smaller model should implement in this exact order:

1. Add DHT force-replacement API and focused tests.
2. Switch DHT restore to force replace and return errors.
3. Correct topology `global_nodes` restoration/removal.
4. Expand topology snapshot/verification to the chosen exact boundary.
5. Add `restore_and_verify_peer_logical_state()`.
6. Reorder rollback so session and auxiliary teardown precede restoration.
7. Retain verification-failed peers in residue.
8. Introduce session-local stream-handler `JoinSet`.
9. Add stream capacity and timeout limits.
10. Drain/abort/await stream handlers before session exit.
11. Add behavioral tests.
12. Add guardrails.
13. Update documentation.

Do not begin worker-level mesh supervision during this pass.

---

# Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-mesh --features mesh dht
cargo test -p synvoid-mesh --features mesh topology
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test -p synvoid-mesh --features mesh transport_peer
cargo test -p synvoid-mesh --features mesh startup
cargo test -p synvoid-mesh --features mesh shutdown
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Run regressions:

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

If routing-table, topology snapshot, or stream-limit config types affect workspace crates:

```bash
cargo test --workspace --no-run
```

Record the two known certificate-test failures separately if still present. Confirm they reproduce at the base commit before treating them as pre-existing.

---

# Acceptance Criteria

This closure pass is complete only when all of the following are true:

1. DHT restoration force-replaces an existing mutated contact.
2. DHT restore failure is propagated into rollback/recovery error handling.
3. DHT snapshot and verification cover the explicitly declared native state boundary.
4. Topology restoration updates `global_nodes` bidirectionally.
5. Topology removal clears relevant secondary indexes.
6. Topology verification covers every declared snapshotted field and secondary index.
7. Startup rollback terminates session and auxiliary work before logical restoration.
8. No late peer-session write can invalidate topology/DHT state after rollback verification.
9. Recovery retains any peer whose restoration or verification fails.
10. Repeated recovery can retry using the retained snapshot.
11. Every per-stream message handler is owned by its peer session.
12. Peer session exit occurs only after all stream handlers are drained or aborted and awaited.
13. Per-peer concurrent stream handlers are bounded.
14. Hung message handlers cannot make session shutdown unbounded.
15. No lifecycle-owned task, stream handler, session, auxiliary task, connection, runtime endpoint, topology mutation, or DHT mutation survives successful rollback, shutdown, or recovery.
16. Worker-level mesh supervision remains accurately documented as deferred.
17. Existing blocklist, threat-intel, provenance, mesh-ID, composition, worker-lifecycle, and mesh-ownership guardrails remain green.

---

## Notes For The Implementer

This is a narrow closure pass. Avoid creating new generalized lifecycle abstractions unless they are directly required by these defects.

The two most important rules are:

> Stop all writers before restoring shared state.

and

> Restoration APIs must replace prior state directly; normal admission/update paths are not rollback mechanisms.
