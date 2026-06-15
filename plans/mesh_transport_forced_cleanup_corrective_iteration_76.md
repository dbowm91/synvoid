# Mesh Transport Forced-Cleanup Corrective Pass — Iteration 76

## Purpose

Iteration 75 closed most of the remaining mesh-local lifecycle gaps: DHT restoration now has a force-replacement path, topology restoration updates the `global_nodes` index, rollback tears down staged peer activity before logical restoration, verification-failed peers remain in residue, and per-stream peer handlers are owned by a session-local `JoinSet`.

The review of `9ffff1dce611aa466f3442980c4dcd1c25fb11c6` found six remaining issues:

1. `rollback_startup()` skips `MeshTaskGroup::join_all()` when the shared rollback deadline is already exhausted, allowing staged top-level task handles to be dropped and detached.
2. Rollback/recovery can forcibly abort a `PeerSessionTask` parent. That bypasses the parent’s normal `drain_peer_stream_handlers()` path and does not prove every child stream handler was joined.
3. DHT force restoration can evict an unrelated contact when the target snapshot is absent and the bucket is full.
4. DHT snapshot documentation claims complete/exact restoration while `last_seen` is intentionally refreshed and `last_pinged` is not verified.
5. The new per-stream timeout wraps the entire `handle_peer_message()` lifetime, including proxy/streaming work, and may be too broad.
6. The most important deadline-exhaustion and nested-task ownership guarantees are still covered mainly by source guards rather than behavioral tests.

This pass should correct forced-cleanup semantics and make the remaining lifecycle guarantees mechanically testable.

The primary invariant is:

> Cooperative deadlines may expire, but ownership cleanup must still abort and await every owned task tree before rollback, shutdown, or recovery returns. Restoration must never mutate unrelated DHT contacts, and timeout semantics must match the actual operation being bounded.

---

## Current Known State

At `9ffff1dce611aa466f3442980c4dcd1c25fb11c6`:

- `rollback_startup()`:
  - signals staged task-group shutdown;
  - closes staged peer connections;
  - stops session-bound auxiliary tasks;
  - drains/aborts staged peer sessions;
  - joins staged top-level tasks only when `remaining(deadline) > 0`;
  - restores and verifies topology/DHT state;
  - stops runtime resources.
- `recover_failed_state()`:
  - closes runtime/connections;
  - drains/aborts peer sessions;
  - joins the top-level task group with `remaining(deadline)`;
  - restores retained residue;
  - aborts and awaits auxiliary tasks;
  - verifies registries.
- `peer_message_loop()`:
  - owns stream handlers in `JoinSet<Result<(), MeshTransportError>>`;
  - limits concurrent stream handlers;
  - wraps each full handler in `peer_message_timeout_secs`;
  - drains/aborts/awaits handlers before normal session return.
- `RoutingTable::force_restore_contact()`:
  - rejects local node ID;
  - calls `KBucket::force_replace()`;
  - invalidates closest cache;
  - clears pending ping state.
- `KBucket::force_replace()`:
  - replaces an existing target contact;
  - inserts if room exists;
  - evicts the oldest unrelated contact if target is absent and bucket is full.
- `DhtPeerSnapshot` stores a full `PeerContact`, but restoration refreshes `last_seen`.

---

## Non-Goals

Do not enable worker-level mesh supervision.

Do not redesign DHT/Raft boundaries.

Do not change peer authentication, TLS, blocklist, threat-intel, or membership semantics.

Do not introduce task restart policy.

Do not redesign the QUIC protocol or message schema.

Do not broaden this pass into general proxy timeout redesign beyond the exact stream timeout semantics required here.

---

# Part A — Always Finalize `MeshTaskGroup`

## Phase 1 — Remove The Zero-Remaining Skip

In `rollback_startup()`, replace:

```rust
let exits = if task_remaining.is_zero() {
    Vec::new()
} else {
    stage.task_group.join_all(task_remaining).await
};
```

with:

```rust
let exits = stage.task_group.join_all(remaining(deadline)).await;
```

`MeshTaskGroup::join_all(Duration::ZERO)` must remain valid and immediately enter its abort-and-await path.

Required behavior:

- zero remaining cooperative time still triggers forced cleanup;
- all critical/background/child handles are removed from the group;
- every forced abort produces a `MeshTaskExit` with `MeshTaskExitReason::Aborted`;
- rollback never returns with `stage.task_group.active_count() != (0, 0, 0)`.

## Phase 2 — Audit All `join_all()` Call Sites

Search for patterns such as:

```rust
if remaining.is_zero() { ... } else { group.join_all(...) }
```

or direct early returns before `join_all()`.

Audit at minimum:

- startup rollback;
- failed-state recovery;
- normal shutdown;
- accept-loop child cleanup;
- auxiliary task cleanup.

The rule is:

> A zero cooperative budget changes cleanup from drain to forced abort; it does not permit skipping ownership finalization.

## Phase 3 — Add An Explicit Task-Group Finalization Helper

To reduce future divergence, add a small helper:

```rust
async fn finalize_task_group(
    group: &mut MeshTaskGroup,
    deadline: Instant,
) -> Vec<MeshTaskExit> {
    group.join_all(remaining(deadline)).await
}
```

Use it in rollback, recovery, and shutdown where practical.

Do not add a generalized lifecycle abstraction; this helper should remain narrow.

## Phase 4 — Add A Zero-Budget Unit Test To `MeshTaskGroup`

In `tests/mesh_lifecycle_tests.rs` or task-group unit tests:

1. Spawn one critical task that never exits cooperatively.
2. Call `join_all(Duration::ZERO)`.
3. Assert exactly one exit is returned.
4. Assert exit reason is `Aborted`.
5. Assert the task’s drop guard fired before `join_all()` returned.
6. Assert the group is empty.

This test defines the contract rollback relies on.

## Phase 5 — Add A Rollback Deadline-Exhaustion Test

Create a behavioral test using a real or test-accessible `MeshStartupStage`:

1. Add a staged critical task with a drop guard.
2. Make staged peer cleanup consume or start with a zero rollback budget.
3. Invoke rollback.
4. Assert the critical task is aborted and awaited.
5. Assert the drop guard fired before rollback returned.
6. Assert `RollbackReport.tasks_aborted >= 1`.
7. Assert `stage.task_group.is_empty()`.

Do not satisfy this with a source-string assertion.

---

# Part B — Cooperative Peer-Session Cancellation

## Phase 6 — Add A Per-Session Shutdown Signal

Extend `PeerSessionTask` with an explicit cancellation channel.

Suggested type:

```rust
pub struct PeerSessionTask {
    pub session_id: String,
    pub node_id: String,
    pub generation: u64,
    pub shutdown_tx: watch::Sender<bool>,
    pub handle: JoinHandle<()>,
}
```

When spawning a peer session:

```rust
let (shutdown_tx, shutdown_rx) = watch::channel(false);
```

Pass `shutdown_rx` into `peer_message_loop()`.

Apply to both:

- inbound sessions;
- outbound startup sessions;
- outbound steady-state sessions.

## Phase 7 — Make `peer_message_loop()` Cancellation-Aware

Change the signature:

```rust
pub(crate) async fn peer_message_loop(
    &self,
    session_id: String,
    peer_node_id: String,
    connection: Connection,
    topology: Arc<MeshTopology>,
    generation: u64,
    mut shutdown_rx: watch::Receiver<bool>,
) -> PeerSessionExit
```

Add a select branch:

```rust
_ = shutdown_rx.changed() => {
    if *shutdown_rx.borrow() {
        exit_reason = PeerSessionExitReason::Cancelled;
        break;
    }
}
```

Required behavior:

- cancellation stops accepting new streams;
- connection may be closed before or immediately after the signal;
- the loop exits into the normal stream-handler drain path;
- `PeerSessionExit` is emitted only after child handlers are drained or aborted and awaited.

## Phase 8 — Centralize Session Finalization

Extract the tail of `peer_message_loop()` into one helper or one clearly shared block:

```rust
async fn finalize_peer_session(
    stream_handlers: &mut JoinSet<Result<(), MeshTransportError>>,
    drain_timeout: Duration,
    topology: &MeshTopology,
    peer_node_id: &str,
    exit_reason: PeerSessionExitReason,
) -> (PeerSessionExitReason, PeerStreamDrainReport)
```

The important property is that all exit paths—connection close, error, explicit cancellation—pass through the same child cleanup.

Do not return directly from inside the accept/select loop.

## Phase 9 — Change Rollback Session Teardown Order

In `stop_staged_peer_activity()`:

1. cancel/await session-bound auxiliary tasks;
2. remove the `PeerSessionTask` from the registry;
3. send `shutdown_tx.send(true)`;
4. close the QUIC connection;
5. wait for the parent session until `remaining(deadline)`;
6. if it returns, classify as cooperative cleanup;
7. only if it does not return, treat parent abortion as a cleanup failure path.

Recommended shape:

```rust
let _ = task.shutdown_tx.send(true);
let mut handle = task.handle;

if timeout(remaining(deadline), &mut handle).await.is_err() {
    handle.abort();
    let _ = handle.await;
    report.peer_sessions_aborted += 1;
    report.errors.push(format!(
        "Peer session {} required parent abort; child stream cleanup could not be proven cooperative",
        peer.session_id
    ));
}
```

Important semantic distinction:

- cooperative cancellation + normal session return means child handlers were finalized;
- parent abort means the child cleanup guarantee is no longer proven and rollback should be considered incomplete unless ownership is externalized.

## Phase 10 — Change Recovery Session Teardown The Same Way

`recover_failed_state()` must use the same session-cancellation helper as rollback.

Do not maintain separate forced-abort logic.

Extract:

```rust
async fn stop_peer_session_task(
    &self,
    task: PeerSessionTask,
    deadline: Instant,
) -> PeerSessionStopOutcome
```

Suggested outcome:

```rust
pub enum PeerSessionStopOutcome {
    Drained(PeerSessionExitReason),
    ForcedParentAbort,
    Failed(String),
}
```

Use this helper in:

- rollback;
- recovery;
- normal shutdown.

## Phase 11 — Decide The Parent-Abort Policy Explicitly

Preferred policy:

- parent abort is a last resort;
- it is always awaited;
- it increments an aborted counter;
- rollback/recovery records an error because child-handler join completion cannot be proven through the parent’s normal path;
- lifecycle remains `Failed` until a later recovery/verification proves no residual work remains.

Alternative, stronger design:

- move the per-session stream-handler `JoinSet` into an externally owned session supervisor object;
- allow lifecycle code to abort and join child handlers directly even after parent failure.

For this pass, prefer cooperative cancellation unless externalizing the `JoinSet` is straightforward.

## Phase 12 — Add Session Cancellation Tests

Required behavioral cases:

### Cooperative Session Cancellation

1. Start a peer session with one active child stream handler.
2. Send the session shutdown signal.
3. Assert the session stops accepting streams.
4. Assert child handler is drained or aborted and awaited.
5. Assert its drop guard fires before parent session handle returns.
6. Assert `PeerSessionExitReason::Cancelled`.

### Deadline Expiry During Child Drain

1. Start a child handler that exceeds the session drain timeout.
2. Cancel the session.
3. Assert handler is aborted and awaited by the session.
4. Assert parent returns normally after child finalization.
5. Assert no outer parent abort is required.

### Parent Supervisor Hangs

1. Inject a test-only condition that prevents the session supervisor from returning after cancellation.
2. Outer lifecycle aborts and awaits parent.
3. Assert rollback/recovery records incomplete cleanup.
4. Assert lifecycle remains `Failed`.

---

# Part C — Safe DHT Force Restoration

## Phase 13 — Change Full-Bucket Absent-Target Behavior

Current `KBucket::force_replace()` evicts the oldest peer when the target snapshot is absent and the bucket is full.

Change the API to return a result:

```rust
pub enum ForceRestoreError {
    BucketFullTargetAbsent,
}

pub fn force_replace(
    &mut self,
    contact: PeerContact,
) -> Result<Option<PeerContact>, ForceRestoreError>
```

Required behavior:

- target exists -> replace it, return previous target;
- target absent and room exists -> insert;
- target absent and bucket full -> return `BucketFullTargetAbsent`;
- never evict an unrelated contact during rollback restoration.

## Phase 14 — Propagate Restore Conflict Upward

`RoutingTable::force_restore_contact()` should convert the bucket error into a restore error.

Suggested routing-level error:

```rust
pub enum ForceRestoreContactError {
    SameNodeId,
    BucketFullTargetAbsent,
}
```

`DhtRoutingManager::restore_peer()` must propagate this as `Err(String)` or a typed error.

`restore_and_verify_peer_logical_state()` then:

- records the peer as unresolved;
- retains residue;
- keeps lifecycle `Failed`.

Do not silently insert by evicting another contact.

## Phase 15 — Clarify Restoration Cases By Mutation Type

For `DhtPeerMutation::Previous(snapshot)`, the target existed before startup. If absent during restore and the bucket is full, this is a state conflict.

For `DhtPeerMutation::Created`, rollback removes the target; no force insertion occurs.

For `DhtPeerMutation::None`, no action occurs.

Document these semantics in code comments and architecture docs.

## Phase 16 — Add DHT Full-Bucket Conflict Tests

Required tests:

### Existing Target In Full Bucket

- full bucket contains target and unrelated peers;
- restore target snapshot;
- target is replaced;
- no unrelated peer is evicted.

### Absent Target In Full Bucket

- full bucket does not contain target;
- call force restore;
- receive `BucketFullTargetAbsent`;
- every unrelated contact remains present;
- residue remains unresolved.

### Absent Target With Capacity

- bucket has room;
- force restore inserts snapshot successfully.

---

# Part D — DHT Snapshot Boundary

## Phase 17 — Choose One Explicit Snapshot Contract

The current implementation stores the full `PeerContact` but refreshes `last_seen` and does not verify `last_pinged`.

Choose one contract.

### Preferred For This Pass — Logical Snapshot

Rename:

```rust
DhtPeerSnapshot
```

to:

```rust
DhtPeerLogicalSnapshot
```

or document prominently that the snapshot excludes recency timers.

Logical fields include:

- node identity;
- node ID string;
- address;
- port;
- geo;
- latency;
- global/trusted flags;
- PoW nonce;
- public key.

Excluded fields:

- `last_seen`;
- `last_pinged`.

Restoration may set `last_seen = Instant::now()` and preserve/reset `last_pinged` according to routing policy.

### Alternative — Exact Temporal Snapshot

Restore and verify both `last_seen` and `last_pinged` exactly.

This is more literal but may be less operationally meaningful.

## Phase 18 — Align Type Names, Docs, And Verification

Whichever contract is selected:

- type name must match;
- `restore_peer()` comments must match;
- `peer_matches_snapshot()` must compare every included field;
- architecture docs must list intentional exclusions;
- tests must assert included and excluded behavior.

Do not use “complete/exact” language for a logical snapshot that intentionally refreshes time fields.

## Phase 19 — Add Snapshot Boundary Tests

For logical snapshot semantics:

1. Snapshot a contact with old `last_seen`/`last_pinged`.
2. Mutate all logical fields and timestamps.
3. Restore.
4. Assert every logical field matches snapshot.
5. Assert `last_seen` follows the declared refresh policy.
6. Assert `last_pinged` follows the declared reset/preserve policy.

---

# Part E — Refine Peer Stream Timeout Semantics

## Phase 20 — Separate Framing Timeout From Total Handler Lifetime

The current code wraps all of `handle_peer_message()` in one total timeout. This includes HTTP proxy and potentially streaming/serverless operations.

Introduce separate configuration:

```rust
pub peer_message_read_timeout_secs: u64,
pub peer_stream_total_timeout_secs: Option<u64>,
```

Recommended defaults:

- read/framing timeout: bounded and enabled;
- total stream timeout: optional/disabled by default for long-lived proxy streams, or set to a policy-appropriate high value.

## Phase 21 — Apply Timeout At Blocking Read Boundaries

Prefer read-idle/framing timeouts around:

- first-byte read;
- length-prefix read;
- message-body read;
- initial HTTP header read.

Do not automatically apply the same short timeout to:

- full proxy response lifetime;
- long-lived HTTP streaming;
- serverless execution that has its own timeout policy;
- large but valid application operations.

## Phase 22 — Preserve Bounded Session Shutdown Independently

Session shutdown remains bounded by:

- explicit session cancellation signal;
- child drain timeout;
- forced child abort-and-await.

Therefore, lifecycle boundedness does not require every stream’s normal execution to have one short total timeout.

## Phase 23 — Add Timeout Behavior Tests

Required cases:

### Partial Framing Stall

- peer sends first bytes then stalls;
- read timeout expires;
- handler returns timeout error;
- session remains healthy unless policy says otherwise.

### Long-Lived Valid Proxy Stream

- handler exceeds framing timeout duration after framing completes;
- operation remains alive if total timeout is disabled/high;
- explicit session cancellation still stops it.

### Configured Total Timeout

- when total timeout is enabled, operation is aborted at that bound.

---

# Part F — Behavioral Test Matrix

## Phase 24 — Create A Dedicated Forced-Cleanup Test Module

Add:

```text
tests/mesh_forced_cleanup.rs
```

Use real drop guards, atomics, barriers, and test hooks.

Avoid relying primarily on source-text inspection.

## Phase 25 — Test Zero-Budget Top-Level Cleanup

Test exact behavior:

- rollback/recovery budget is zero;
- top-level staged task is live;
- cleanup aborts and awaits it;
- drop guard fires before return;
- group is empty;
- exit reason is `Aborted`.

## Phase 26 — Test Nested Session/Stream Ownership

Test exact behavior:

- session owns a live stream handler;
- lifecycle sends cooperative session shutdown;
- session drains/aborts child and awaits it;
- parent returns afterward;
- outer cleanup does not need to abort parent.

## Phase 27 — Test Parent-Abort Failure Classification

Test-only hook causes parent supervisor not to complete after shutdown.

Assert:

- outer cleanup aborts/awaits parent;
- cleanup report records an error;
- lifecycle remains `Failed`;
- recovery is required.

## Phase 28 — Test No DHT Collateral Eviction

Use a full bucket with unrelated contacts and an absent restore target.

Assert:

- restore fails;
- all unrelated contacts remain;
- unresolved residue is retained.

## Phase 29 — Test Timeout Boundary

Assert framing timeout and total operation timeout are independent.

---

# Part G — File-Level Implementation Guide

## Phase 30 — `crates/synvoid-mesh/src/mesh/task_group.rs`

Verify or adjust:

- `join_all(Duration::ZERO)` aborts and awaits every retained handle;
- no early return leaves handles in vectors/maps;
- exit metadata remains accurate.

Add focused unit tests here if internal access is easier.

## Phase 31 — `crates/synvoid-mesh/src/mesh/lifecycle.rs`

Update:

- `PeerSessionTask` with `shutdown_tx`;
- optional `PeerSessionStopOutcome`;
- optional DHT logical snapshot rename;
- restore error types if exposed at lifecycle level;
- reporting fields for forced parent aborts if needed.

## Phase 32 — `crates/synvoid-mesh/src/mesh/transport.rs`

Update:

- always call top-level `join_all()`;
- add shared `stop_peer_session_task()` helper;
- use cooperative session cancellation in rollback, recovery, shutdown;
- classify parent abort as incomplete cleanup;
- retain residue on restore conflict.

## Phase 33 — `crates/synvoid-mesh/src/mesh/transport_peer.rs`

Update:

- `peer_message_loop()` signature with shutdown receiver;
- cancellation select branch;
- one shared session finalization path;
- read/framing timeout placement;
- optional total timeout behavior.

## Phase 34 — `crates/synvoid-mesh/src/mesh/dht/routing/bucket.rs`

Update:

- `force_replace()` result type;
- no unrelated eviction when target absent and bucket full;
- focused unit tests.

## Phase 35 — `crates/synvoid-mesh/src/mesh/dht/routing/table.rs`

Update:

- force-restore error propagation;
- cache/pending-ping behavior remains correct;
- full-bucket conflict tests.

## Phase 36 — `crates/synvoid-mesh/src/mesh/dht/routing/manager.rs`

Update:

- restore error propagation;
- snapshot-boundary naming/docs;
- verification semantics.

## Phase 37 — Config Files

Update:

- `crates/synvoid-config/src/mesh.rs`;
- `crates/synvoid-mesh/src/mesh/config.rs`;
- defaults, serde fields, and documentation.

Prefer backward-compatible defaults.

---

# Part H — Guardrails

## Phase 38 — Update `tests/mesh_task_ownership_guard.rs`

Add checks that:

- `rollback_startup()` does not skip `join_all()` when remaining time is zero;
- `PeerSessionTask` has an explicit shutdown sender;
- `peer_message_loop()` selects on a shutdown receiver;
- rollback/recovery send session shutdown before parent abort;
- parent abort is treated as incomplete cleanup or explicit failure;
- DHT force restoration does not evict unrelated contacts;
- snapshot docs do not claim exact temporal restoration if recency fields are excluded;
- peer-message timeout is not one unconditional wrapper around the full proxy/stream lifetime unless explicitly configured.

Behavioral tests remain authoritative.

## Phase 39 — Add A No-Skip Task-Group Guard

Source guard should reject patterns like:

```rust
if remaining.is_zero() { Vec::new() } else { group.join_all(...) }
```

in lifecycle cleanup paths.

## Phase 40 — Add A No-Collateral-Restore Guard

Guard that `KBucket::force_replace()` does not remove index `0` or another unrelated peer in the target-absent/full-bucket branch.

---

# Part I — Documentation

## Phase 41 — Update Lifecycle Documentation

Update:

- `architecture/mesh_transport_lifecycle.md`;
- `architecture/mesh.md`;
- `skills/synvoid_mesh.md`;
- `AGENTS.md`;
- `crates/synvoid-mesh/AGENTS.override.md` if present.

Document:

- zero-budget cleanup still aborts and awaits;
- cooperative peer-session shutdown;
- forced parent abort is an incomplete-cleanup signal;
- DHT restore conflicts never evict unrelated peers;
- exact logical snapshot boundary for DHT state;
- framing/read timeout versus total stream timeout;
- worker-level mesh supervision remains deferred.

## Phase 42 — Remove Overstated Closure Claims Until Tests Pass

Do not mark mesh-local lifecycle fully closed until the behavioral tests in this plan pass.

After completion, state explicitly:

- every task group is finalized even at zero remaining budget;
- every peer session normally owns and finalizes all stream children;
- forced parent abort is surfaced as incomplete cleanup;
- DHT restoration never creates collateral eviction.

---

# Ordered Handoff Sequence

A smaller model should implement in this exact order:

1. Add and verify `join_all(Duration::ZERO)` behavior.
2. Remove rollback’s zero-budget skip.
3. Add per-session shutdown channel to `PeerSessionTask`.
4. Make all peer-session spawn paths pass a shutdown receiver.
5. Make `peer_message_loop()` cancellation-aware with one finalization path.
6. Add shared `stop_peer_session_task()` and use it in rollback, recovery, shutdown.
7. Treat forced parent abort as incomplete cleanup.
8. Change DHT force-restore full-bucket behavior to return conflict without eviction.
9. Clarify DHT logical snapshot semantics.
10. Split framing/read timeout from optional total stream timeout.
11. Add behavioral tests in `tests/mesh_forced_cleanup.rs`.
12. Add source guardrails.
13. Update documentation.

Do not begin worker-level mesh supervision in this pass.

---

# Verification Commands

Run focused tests:

```bash
cargo test -p synvoid-mesh --features mesh task_group
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test -p synvoid-mesh --features mesh transport_peer
cargo test -p synvoid-mesh --features mesh dht
cargo test --test mesh_forced_cleanup --features mesh,dns
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

If config fields or peer-session task types affect workspace callers:

```bash
cargo test --workspace --no-run
```

Record known certificate-test failures separately and confirm they reproduce at the base commit before classifying them as pre-existing.

---

# Acceptance Criteria

This corrective pass is complete only when all of the following are true:

1. `MeshTaskGroup::join_all(Duration::ZERO)` aborts, awaits, reports, and removes every owned task.
2. Rollback never skips top-level task-group finalization.
3. Every peer session has an explicit cooperative shutdown channel.
4. Rollback, recovery, and shutdown signal session cancellation before considering parent abort.
5. Cooperative peer-session cancellation drains or aborts and awaits every stream handler before parent return.
6. A forced parent-session abort is awaited and reported as incomplete cleanup unless child ownership is externally proven complete.
7. DHT force restoration never evicts an unrelated contact when the target is absent.
8. Full-bucket restore conflicts retain unresolved residue and keep lifecycle `Failed`.
9. DHT snapshot names, docs, restore logic, and verification agree on whether recency fields are included.
10. Framing/read timeout is distinct from optional total stream lifetime timeout.
11. Valid long-lived proxy/stream operations are not unintentionally killed by a short framing timeout.
12. Real behavioral tests prove zero-budget cleanup and nested stream-handler ownership.
13. No lifecycle-owned task tree, session, stream handler, auxiliary task, connection, runtime endpoint, topology mutation, or DHT mutation survives successful rollback, shutdown, or recovery.
14. Worker-level mesh supervision remains accurately documented as deferred.
15. Existing blocklist, threat-intel, provenance, mesh-ID, composition, worker-lifecycle, and mesh-ownership guardrails remain green.

---

## Notes For The Implementer

This is a narrow forced-cleanup correction. Do not introduce broad new abstractions.

Two rules should guide every change:

> Zero time remaining means abort-and-await now; it never means skip cleanup.

> Parent task completion is not enough when the parent owns child tasks; the child task tree must be finalized or the cleanup must remain failed.
