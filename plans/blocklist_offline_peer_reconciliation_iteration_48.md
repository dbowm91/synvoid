# Blocklist Offline-Peer Reconciliation and Periodic Catchup — Iteration 48

## Purpose

Iteration 46 added mesh-wide block/unblock propagation, and Iteration 47 made local application semantics honest with FIFO event dedupe and per-target stale suppression. The remaining consistency gap is offline-peer recovery: a peer that is disconnected when `BlocklistEventGossip` is emitted can miss an unblock and retain stale block state until TTL, manual correction, or restart-dependent behavior.

This pass should add a bounded reconciliation/catchup mechanism so peers can converge after missed gossip without adding request-path network lookups or Raft to operational blocklist state.

Desired end state:

- nodes retain a bounded recent blocklist event log suitable for replay;
- reconnecting peers can request events since a cursor/watermark;
- peers apply replayed events through `BlockStore::apply_blocklist_event()`;
- if the requested history is unavailable, fallback to an explicit snapshot/digest reconciliation path;
- WAF/request paths remain local-only;
- Raft remains out of operational blocklist reconciliation unless a future CA/global-node authority model is introduced.

## Current Known State

Recent iterations established:

- `BlockTargetKind::{Ip, MeshId}` for target-aware state.
- `BlocklistEvent` with operation, target kind, identifier, site scope, provenance, timestamp, source node, event ID, TTL, and version.
- `BlocklistEventGossip` mesh message.
- `BlocklistEventUpdate` supervisor/worker IPC message.
- `BlockStore::apply_blocklist_event()` with event-ID dedupe and per-target stale suppression.
- `SeenEventCache` FIFO dedupe.
- `TargetStateCache` per-target LWW memory.
- Admin unban emits blocklist remove events after successful local removal.
- Existing limitations: best-effort gossip, no acknowledged delivery, no offline catchup, in-memory stale suppression lost on restart.

## Non-Goals

Do not add request-path mesh/DHT/Raft lookups.

Do not introduce Raft for operational blocklist state.

Do not redesign WAF request decisions.

Do not redesign threat-intel policy gates.

Do not build a full durable event-sourcing subsystem.

Do not require exact global linearizability.

Do not remove existing gossip propagation.

Do not add admin auth/authz changes.

Do not implement acknowledged delivery for every event in this pass.

## Phase 1 — Inventory Existing Event Retention / Mesh Sync Primitives

Audit whether the repo already has reusable mechanisms for bounded replay, peer reconnect hooks, DHT record fetches, or periodic sync.

Search terms:

- `BlocklistEventGossip`
- `BlocklistEventUpdate`
- `announce_local_unblock`
- `HotThreatGossip`
- `Dht`
- `Kademlia`
- `snapshot`
- `sync`
- `reconcile`
- `cursor`
- `version`
- `last_seen`
- `peer_connected`
- `reconnect`
- `BlocklistResponse`
- `BlocklistUpdate`
- `MeshMessage`
- `prost`
- `proto`

Inspect likely files:

- `crates/synvoid-core/src/block_store.rs`
- `crates/synvoid-block-store/src/lib.rs`
- `crates/synvoid-mesh/**`
- `proto/**` or protobuf generation sources
- `src/supervisor/**`
- `src/worker/unified_server/lifecycle.rs`
- `src/admin/handlers/mesh_admin.rs`
- `architecture/blocklist_remove_consistency.md`

Update/create:

- `architecture/blocklist_reconciliation.md`

Document current reconnect/sync affordances and where catchup should attach.

## Phase 2 — Define Reconciliation Guarantees

Target guarantees for this pass:

- Online peers receive best-effort `BlocklistEventGossip` as they do today.
- Reconnecting peers can request recent blocklist events since a cursor/watermark.
- If recent history is available, replay converges through `apply_blocklist_event()`.
- If history is unavailable, peer requests or receives a bounded current-state snapshot/digest reconciliation.
- Request/WAF paths never wait on reconciliation.
- Reconciliation is eventually consistent and best-effort, not Raft-linearizable.

Explicitly document what is not guaranteed:

- no guaranteed delivery while offline;
- no permanent event log unless implemented;
- no exact convergence if a node is offline longer than retention and no snapshot fallback is implemented;
- no request-path remote checks.

## Phase 3 — Add a Bounded Local Blocklist Event Log

Add an in-memory bounded event log that records locally-originated and/or received blocklist events after they are accepted for propagation/application.

Suggested type:

```rust
struct BlocklistEventLog {
    events: VecDeque<BlocklistEvent>,
    by_event_id: HashSet<String>,
    max_events: usize,
}
```

Possible ownership location:

- mesh threat-intel manager if it owns propagation;
- BlockStore if it owns apply state;
- a small dedicated blocklist reconciliation component if dependencies permit.

Preferred: keep transport-level event replay near mesh propagation code, not in WAF/request path.

Event log requirements:

- bounded capacity, default around 10k events or config-driven;
- event ID required for replayable distributed events;
- dedupe before insertion;
- expose query by cursor/time/source/version;
- do not block request path;
- testable without real networking.

## Phase 4 — Define Cursor / Watermark Semantics

Add a simple replay cursor.

Options:

### Timestamp cursor

Peer asks for events after `last_seen_timestamp`.

Pros: simple.
Cons: clock skew and equal-timestamp ambiguity.

### Event-log sequence cursor

Local node assigns monotonic local sequence to event log entries.

Pros: deterministic per source node.
Cons: source-local, not globally comparable.

### Hybrid cursor

Use `(source_node, last_seen_sequence, last_seen_timestamp)`.

Recommended for this pass:

- each node assigns a local `event_seq` or replay cursor for its retained log;
- peer stores per-source cursor where feasible;
- fallback to timestamp if no sequence exists.

If adding `event_seq` to wire format is too invasive, stage it as a local replay wrapper rather than changing `BlocklistEvent` immediately.

## Phase 5 — Add Catchup Request / Response Wire Messages

Add protobuf/wire messages for catchup.

Suggested messages:

```proto
message BlocklistEventCatchupRequest {
  string requesting_node = 1;
  optional string since_event_id = 2;
  optional uint64 since_timestamp = 3;
  optional uint64 since_sequence = 4;
  uint32 max_events = 5;
}

message BlocklistEventCatchupResponse {
  repeated BlocklistEventData events = 1;
  bool history_complete = 2;
  optional uint64 latest_sequence = 3;
  optional uint64 latest_timestamp = 4;
  bool snapshot_required = 5;
}
```

Use exact project protobuf conventions.

Compatibility requirements:

- add new message variants rather than changing existing ones destructively;
- old nodes ignore unknown messages or fail gracefully;
- no request-path dependency on these messages.

## Phase 6 — Add Snapshot / Digest Fallback

Event retention can be exceeded. Add a fallback path or explicitly stage it.

Preferred minimum fallback:

- current node can produce a blocklist digest:
  - target kind;
  - site scope;
  - identifier hash;
  - last timestamp/version;
  - operation/current present/absent where known.

Better fallback:

- current node sends current positive block snapshot plus recent tombstones for unblocks within retention window.

Important caution:

A pure positive snapshot cannot represent removals safely if ownership/source is ambiguous. Use event replay for removals where possible.

Recommended implementation split:

1. Implement event catchup first.
2. If `history_complete == false`, return `snapshot_required: true` and document snapshot fallback as follow-up unless a simple safe snapshot already exists.
3. Do not implement dangerous full snapshot removal reconciliation without ownership/source filtering.

## Phase 7 — Hook Catchup Into Peer Lifecycle

Use existing peer connection/reconnect hooks if available.

Trigger catchup when:

- a mesh peer connects/reconnects;
- a node joins/rejoins mesh;
- periodic interval fires;
- admin/manual command triggers diagnostics/reconcile, if cheap.

Reconciliation flow:

1. peer connects;
2. local node sends catchup request with last known cursor;
3. remote responds with bounded events;
4. receiver applies each event via `BlockStore::apply_blocklist_event()`;
5. receiver updates cursor only after applying/processing response;
6. if history incomplete, log warning and request/stage snapshot fallback.

Do not block peer establishment on catchup completion unless existing mesh semantics require it.

## Phase 8 — Cursor Persistence

Decide whether cursors survive restart.

Minimum acceptable:

- in-memory cursor per peer/source;
- docs state restart loses cursor and may require snapshot/admin retry.

Better:

- persist per-source cursor to a small JSON file with safe permissions.

Recommended for Iteration 48:

- implement in-memory cursor first;
- if there is already a mesh metadata persistence path, use it;
- otherwise document restart limitation and stage persisted cursors later.

## Phase 9 — Worker/Supervisor Reconciliation

Supervisor/worker sync should not miss removes either.

Audit whether `BlocklistEventUpdate` IPC is delivered to currently connected workers only.

If yes, add one of:

- supervisor retains recent blocklist events and replays them to workers on worker reconnect;
- worker receives periodic blocklist event catchup from supervisor;
- supervisor sends current state plus recent tombstones.

Preferred: reuse the same bounded event log and catchup API internally for supervisor/worker if feasible.

Acceptance for this pass:

- connected workers still get events;
- reconnecting workers have a path to receive recent missed events or docs clearly stage worker catchup separately.

## Phase 10 — Admin / Diagnostics Observability

Add minimal diagnostics so operators can see reconciliation state.

Possible fields/endpoints/logs:

- retained event count;
- oldest/newest event timestamp;
- per-peer last catchup cursor;
- catchup requests/responses count;
- history incomplete count;
- snapshot required count;
- apply results: Applied / NoopDuplicate / IgnoredStale / InvalidTarget.

Do not build full UI. Structured logs or metrics are sufficient if consistent with existing patterns.

## Phase 11 — Tests

Add focused tests.

### Event log tests

- append event with event ID;
- duplicate event ID is not inserted twice;
- capacity evicts oldest event;
- query since timestamp/sequence returns expected events;
- query beyond retained history returns incomplete/history gap.

### Catchup message tests

- encode/decode request;
- encode/decode response;
- unknown/empty cursor behavior;
- max event limit respected.

### Apply replay tests

- replay block then unblock converges to removed state;
- replay duplicate events does not mutate twice;
- replay stale event returns `IgnoredStale`;
- replay mesh-ID unblock removes only that mesh ID.

### Peer lifecycle tests, if feasible

- reconnect triggers catchup request;
- peer receives response and applies events;
- missing history logs/flags snapshot requirement.

### Supervisor/worker tests

- worker reconnect receives retained remove event, or clear staged behavior documented/tested.

## Phase 12 — Documentation

Update:

- `architecture/blocklist_reconciliation.md`
- `architecture/blocklist_remove_consistency.md`
- `architecture/blockstore_admin_observability.md`
- `architecture/manual_enforcement_ownership.md`
- `docs/THREAT_INTEL.md` if threat-intel sync docs mention blocklist propagation
- `AGENTS.md` if durable implementation rules are added

Docs must state:

- gossip is still best-effort;
- catchup repairs missed events within retention;
- retention window and gap behavior;
- snapshot fallback status;
- cursor persistence status;
- request/WAF path remains local-only;
- Raft remains intentionally unused for operational blocklist reconciliation;
- offline peers beyond retention may need snapshot/admin retry if fallback is not complete.

## Verification Commands

Run focused tests:

```bash
cargo test -p synvoid-core blocklist_event
cargo test -p synvoid-block-store apply_blocklist_event
cargo test -p synvoid-mesh blocklist_event
cargo test -p synvoid-mesh catchup
cargo test -p synvoid-mesh reconciliation
cargo test --lib supervisor
cargo test --lib blocklist
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
```

If protobuf changes are involved:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This pass is complete when:

1. A bounded local blocklist event log exists for replayable events.
2. Catchup request/response wire messages or equivalent mesh messages exist.
3. Reconnecting peers can request and apply recent missed events.
4. Catchup applies events through `BlockStore::apply_blocklist_event()`.
5. Event history gaps are detected and surfaced.
6. Snapshot/digest fallback is implemented or explicitly staged with honest docs.
7. Supervisor/worker missed-event behavior is handled or explicitly staged.
8. Request/WAF paths remain local-only.
9. Raft remains out of operational blocklist reconciliation, with documented rationale.
10. Tests cover event log retention, catchup replay, duplicate/stale events, and history gaps.

## Notes for the Implementer

This is a reconciliation pass. Do not turn it into a consensus redesign.

The invariant is:

> Gossip handles timely propagation, catchup repairs missed propagation, and local `BlockStore::apply_blocklist_event()` remains the only enforcement mutation boundary. Request processing must never wait on reconciliation.
