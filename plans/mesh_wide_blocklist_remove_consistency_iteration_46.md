# Mesh-Wide Blocklist Remove Consistency — Iteration 46

## Purpose

Iteration 44 introduced first-class mesh-ID block entries, and Iteration 45 hardened BlockStore counters, legacy sentinel migration, and staged a target-aware `BlocklistEvent` model. Mesh-wide removal consistency is now the next correctness boundary.

This pass should implement explicit, target-aware blocklist remove propagation across the mesh without introducing request-path network dependencies.

The desired end state:

- admin/manual unblock creates a target-aware remove event;
- remove events are serialized on the existing protobuf/wire path;
- remove events are applied idempotently by peers/workers;
- IP and mesh-ID unblocks are both supported;
- local request/WAF paths remain purely local BlockStore reads;
- Raft/DHT/gossip responsibilities are clearly separated.

## Current Known State

Known from recent iterations:

- `BlockTargetKind::{Ip, MeshId}` exists.
- `BlocklistOperation::{Block, Unblock}` exists.
- `BlocklistEvent` exists in `synvoid-core::block_store`.
- `BlocklistEvent` is currently used for structured local debug logs only.
- Admin IP and mesh-ID unban are local-only.
- Admin IP ban still uses `announce_local_block` for block propagation.
- There is no `announce_local_unblock` or equivalent remove propagation API.
- Supervisor/worker sync has been extended to carry mesh-ID block entries.
- WAF/request paths read local `BlockStore` only and must remain free of mesh/DHT/Raft lookups.

## Non-Goals

Do not add request-path network lookups.

Do not redesign threat-intel policy gates.

Do not redesign WAF decisions.

Do not remove existing block propagation until replacement is working.

Do not require every edge node to run Raft.

Do not make DHT/gossip authoritative for CA/global-node critical state.

Do not build a broad event-sourcing subsystem.

Do not change admin auth/authz.

Do not remove old IP block message compatibility unless migration is complete.

## Phase 1 — Inventory Existing Block Propagation Paths

Audit the current block propagation stack before adding removes.

Search terms:

- `announce_local_block`
- `HotThreatGossip`
- `BlocklistUpdate`
- `BlocklistResponse`
- `BlockEntryData`
- `MeshBlockEntryData`
- `threat_intel`
- `gossip`
- `dht`
- `raft`
- `prost`
- `proto`
- `BlockStoreApi`
- `SupervisorSync`
- `handle_incoming_threat`

Inspect likely files:

- `crates/synvoid-core/src/block_store.rs`
- `crates/synvoid-block-store/src/lib.rs`
- `crates/synvoid-mesh/**`
- `proto/**` or `*.proto` files
- `build.rs` / prost generation wiring
- `src/admin/handlers/mesh_admin.rs`
- `src/supervisor/**`
- `src/worker/unified_server/lifecycle.rs`
- `src/waf/**`
- `docs/THREAT_INTEL.md`
- `architecture/blockstore_admin_observability.md`

Update or create:

- `architecture/blocklist_remove_consistency.md`

Document:

- existing block propagation path;
- current supervisor sync path;
- available protobuf/wire messages;
- whether current hot gossip has replay/idempotency support;
- whether DHT records have delete/tombstone semantics;
- whether Raft is present only for global/CA class nodes;
- which nodes are expected to apply removal events.

## Phase 2 — Decide Authority Model

Use the existing separation:

- **Raft**: linearizable consensus for small critical global-node/control-plane state.
- **DHT/gossip**: eventual consistency for mesh-wide non-critical distribution.
- **Supervisor/worker IPC**: local/control-plane replication into workers.
- **BlockStore**: local enforcement state.

Recommended model:

### Local authority

Admin unban mutates local BlockStore immediately and emits a signed/identified `BlocklistEvent::Unblock`.

### Mesh distribution

Use existing mesh gossip/DHT/threat-intel propagation path to distribute remove/tombstone events eventually.

### Global-node canonicalization, if available

If the cluster has global/CA nodes and Raft is already used for critical network authority, use Raft only if the blocklist remove is intended to be globally authoritative and operator-controlled. Otherwise keep it as gossip/DHT eventual state.

Decision rule:

- IP/mesh-ID manual unblock for operational blocklists: gossip/DHT/tombstone is enough.
- CA/global-node identity revocation/unrevocation: Raft path, not this blocklist API.

Document the chosen model. Do not mix Raft into request-path enforcement.

## Phase 3 — Extend `BlocklistEvent` for Distributed Idempotency

`BlocklistEvent` already has `source_node` and `event_id` placeholders. Make them useful.

Required fields or equivalents:

- `operation`: `Block` / `Unblock`
- `target_kind`: `Ip` / `MeshId`
- `identifier`: IP string or mesh ID
- `site_scope`
- `reason`: optional, present for block
- `provenance`
- `timestamp`
- `source_node`
- `event_id`
- optional `expires_at` or `ttl_secs` for block operations
- optional `version` / monotonic sequence if available

Idempotency requirements:

- applying the same event twice is safe;
- an older unblock must not remove a newer re-block of the same target if timestamps/versions prove ordering;
- an older block must not resurrect a target after a newer unblock if ordering metadata exists;
- if no strict ordering is available, document last-writer-wins by timestamp and clock-skew limitations.

Preferred event ID:

```text
{source_node}:{timestamp}:{operation}:{target_kind}:{site_scope}:{identifier}:{hash(reason/provenance)}
```

or use an existing UUID/hash utility if present.

## Phase 4 — Protobuf / Wire Contract

Add protobuf-compatible wire representation for blocklist events.

Potential message:

```proto
message BlocklistEventData {
  string event_id = 1;
  string source_node = 2;
  uint64 timestamp = 3;
  BlocklistOperation operation = 4;
  BlockTargetKind target_kind = 5;
  string identifier = 6;
  string site_scope = 7;
  optional string reason = 8;
  string provenance_kind = 9;
  optional string provenance_source = 10;
  optional uint64 ttl_secs = 11;
}

enum BlocklistOperation {
  BLOCKLIST_OPERATION_UNSPECIFIED = 0;
  BLOCKLIST_OPERATION_BLOCK = 1;
  BLOCKLIST_OPERATION_UNBLOCK = 2;
}

enum BlockTargetKind {
  BLOCK_TARGET_KIND_UNSPECIFIED = 0;
  BLOCK_TARGET_KIND_IP = 1;
  BLOCK_TARGET_KIND_MESH_ID = 2;
}
```

Adapt exact style to existing protobuf conventions.

Compatibility requirements:

- add fields rather than breaking existing messages;
- use `serde(default)` or protobuf defaults on Rust-side mirror types;
- preserve existing IP block sync messages until all call sites migrate;
- old nodes should ignore unknown event fields where possible.

## Phase 5 — Local Apply Function

Add a single local apply function that mutates BlockStore based on a `BlocklistEvent`.

Suggested API:

```rust
pub enum BlocklistApplyResult {
    Applied,
    NoopDuplicate,
    IgnoredStale,
    InvalidTarget,
    StoreDisabled,
}

pub fn apply_blocklist_event(
    block_store: &BlockStore,
    event: &BlocklistEvent,
) -> BlocklistApplyResult
```

or equivalent method on `BlockStore` if dependency direction permits.

Behavior:

- `Block + Ip` -> `block_ip_with_provenance`
- `Unblock + Ip` -> `unblock_ip`
- `Block + MeshId` -> `block_mesh_id_with_provenance`
- `Unblock + MeshId` -> `unblock_mesh_id`
- invalid IP string -> reject/invalid
- missing reason on block -> reject or default only if existing semantics require it
- duplicate event -> no-op
- stale event -> ignored if ordering is implemented

Keep this function local and deterministic. Do not perform network I/O inside it.

## Phase 6 — Event Deduplication / Tombstone State

Remove events need dedupe and possibly tombstones to prevent stale replays.

Minimum acceptable dedupe:

- maintain an in-memory bounded LRU/set of recently seen `event_id`s per node;
- duplicate events are no-ops.

Better consistency:

- maintain per-target last-applied timestamp/version;
- ignore older events for the same target;
- persist tombstone metadata for unblocks with TTL to prevent stale block replays.

Suggested staged design:

### Iteration 46 minimum

- event ID required;
- bounded in-memory dedupe;
- apply order by received event, with timestamp logged;
- document that stale replay protection is best-effort unless per-target versions are added.

### Stronger option if small

- add a local `BlocklistTombstone` map keyed by `(target_kind, site_scope, identifier)` with last event timestamp;
- ignore older events.

Avoid large distributed consensus here unless the chosen authority model requires it.

## Phase 7 — Admin Emit Path

Update admin block/unblock paths to emit real blocklist events into the mesh/control-plane propagation path.

For now:

- local mutation still happens first;
- event is emitted only after local mutation succeeds;
- response states local success and, if implemented, event queued/emitted status separately;
- failure to emit should be logged and may return partial success only if existing API has a way to express it.

Suggested response addition only if API style supports it:

```json
{
  "success": true,
  "removed": true,
  "propagation": "queued"
}
```

Do not claim `propagated: true` unless acknowledgements exist.

## Phase 8 — Mesh/DHT/Gossip Transport

Wire blocklist event propagation through the existing mesh distribution mechanism.

Preferred path depends on current code:

### If hot gossip already exists for block/threat events

Extend it to carry `BlocklistEventData` with operation and target kind.

### If DHT record publication is the current block distribution path

Publish event/tombstone records keyed by target:

```text
blocklist:event:{event_id}
blocklist:target:{target_kind}:{site_scope}:{identifier}
```

Use TTL appropriate for tombstones and replay protection.

### If supervisor is the distribution root

Extend supervisor sync to include blocklist events or removals, not only current block snapshots.

Important:

- do not block request handling on DHT/gossip/Raft;
- do not require immediate global consistency for request path;
- all peers apply events locally to their BlockStore.

## Phase 9 — Supervisor/Worker Sync Semantics

Extend supervisor/worker sync to propagate removals, not just current positive block entries.

Options:

### Snapshot model

Supervisor sends full desired block snapshot, worker reconciles by removing absent entries. This is simple but can be dangerous without clear ownership/source filtering.

### Event model

Supervisor sends `BlocklistEventData` operations. Workers apply idempotently.

Preferred: event model, since it matches unblock propagation.

Requirements:

- `SupervisorSync` provenance applied for replicated events;
- block/unblock target kind preserved;
- workers can apply IP and mesh-ID events;
- backward compatibility with old positive-entry sync preserved.

## Phase 10 — Raft Boundary

Explicitly avoid using Raft unless this blocklist state is intended to be authoritative global-node control-plane state.

If using Raft for operator blocklist state:

- only global-node class participates;
- Raft commits blocklist event log entries;
- edge nodes receive committed events via supervisor/mesh distribution;
- DHT/gossip may distribute committed events but not decide authority.

If not using Raft in this pass:

- document why: operational blocklist removals are eventually consistent, not CA-critical.
- keep future hook if policy changes.

Recommended for Iteration 46: do not implement Raft unless current code already has a natural committed event-log abstraction for blocklist events.

## Phase 11 — Tests

Add focused tests at each layer.

### Core/event tests

- serialize/deserialize `BlocklistEvent`
- IP block event construction
- IP unblock event construction
- mesh-ID block event construction
- mesh-ID unblock event construction
- event ID/source node required for distributed path

### Apply tests

- apply block IP creates IP entry
- apply unblock IP removes IP entry
- apply block mesh ID creates mesh entry
- apply unblock mesh ID removes only that mesh ID
- duplicate event is no-op
- invalid IP event rejected
- stale event ignored if tombstone/version implemented

### Admin tests

- admin IP unban emits unblock event after local removal
- admin mesh-ID unban emits unblock event after local removal
- missing target returns 404 and emits no event
- response does not claim completed global propagation without ack

### Mesh transport tests

- event is encoded to protobuf/wire and decoded back
- receiving peer applies event locally
- duplicate received event does not mutate twice
- mesh-ID event survives sync/gossip path

### Supervisor/worker tests

- supervisor sends unblock event
- worker applies unblock event
- old snapshot/positive-only sync still deserializes

## Phase 12 — Documentation

Update:

- `architecture/blocklist_remove_consistency.md`
- `architecture/blockstore_admin_observability.md`
- `architecture/manual_enforcement_ownership.md`
- `docs/THREAT_INTEL.md`
- `AGENTS.md`
- protobuf/wire docs if present

Docs must state:

- remove consistency model;
- authority split between admin/local, gossip/DHT, supervisor sync, and Raft;
- whether propagation is queued, best-effort, or acknowledged;
- idempotency and stale-event semantics;
- request path remains local-only;
- current limitations.

## Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-core blocklist_event
cargo test -p synvoid-block-store blocklist_event
cargo test -p synvoid-block-store unblock
cargo test -p synvoid-mesh blocklist_event
cargo test --lib mesh_admin
cargo test --lib supervisor
cargo test --lib blocklist
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
```

If protobuf generation changes:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual module/test names.

## Acceptance Criteria

This pass is complete when:

1. A protobuf/wire-compatible blocklist event representation exists for block and unblock operations.
2. IP and mesh-ID unblock events are target-aware and provenance-bearing.
3. Admin unban emits remove events only after successful local removal.
4. Peers/workers can receive and apply remove events idempotently.
5. Duplicate events do not double-mutate counters or state.
6. Stale replay behavior is defined and tested, even if best-effort.
7. Supervisor/worker sync can represent removals or has a clear staged bridge.
8. Request/WAF paths remain local-only and do not perform mesh/Raft/DHT lookups.
9. Raft is either intentionally unused for operational blocklist removals or used only at the global-node/control-plane boundary with documented authority.
10. Docs accurately state propagation guarantees and limitations.

## Notes for the Implementer

Treat this as a distributed-state consistency pass, not a WAF/request-path pass.

The invariant is:

> A blocklist remove is a first-class, target-aware event. It must be safe to replay, safe to receive out of order according to the documented semantics, and must never require a request-path network lookup to enforce local state.
