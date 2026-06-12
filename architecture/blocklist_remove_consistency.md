# Blocklist Remove Consistency

## Overview

This document describes the authority model, propagation mechanism, and consistency guarantees for blocklist block and unblock operations in SynVoid. Implemented in Iterations 46-47.

## Authority Model

Blocklist operations follow a layered authority model where each layer is responsible for its domain:

| Layer | Responsibility | Mechanism |
|-------|---------------|-----------|
| **Local Authority** | Admin mutates local `BlockStore`, emits signed `BlocklistEvent::Unblock` | Direct `BlockStore` mutation via admin API |
| **Mesh Distribution** | Event propagation to peers for eventual consistency | `BlocklistEventGossip` mesh message |
| **Supervisor/Worker IPC** | Local/control-plane replication | `BlocklistEventUpdate` IPC message |
| **BlockStore** | Local enforcement | `BlockStore` sharded locks |

**Raft is NOT used for operational blocklist removals.** Block and unblock operations are eventually consistent, not CA-critical. The threat-intel pipeline and canonical trust domains handle consistency for high-security indicators, but operational blocklist removes are best-effort.

## Existing Block Propagation

IP blocks propagate via mesh through two paths:

1. `announce_local_block` creates a `ThreatIndicator` + `HotThreatGossip` (for IP blocks)
2. Admin unban calls `announce_local_unblock()` which sends `BlocklistEventGossip` (for both IP and mesh-ID unbans)
3. Supervisor pushes `BlocklistEventUpdate` IPC to workers for both block and unblock events

## Remove Consistency Model

### Admin Unblock Flow

1. Admin issues unban via admin API
2. `BlocklistEvent::Unblock` is created with target kind, identifier, and site scope
3. Event is emitted locally with structured logging
4. `BlocklistEvent::Unblock` is gossiped via `BlocklistEventGossip` mesh message
5. Peers apply idempotently via `BlockStore::apply_blocklist_event`

### Event Propagation

Events propagate via the `BlocklistEventGossip` mesh message type (proto field 178):

- **Source**: Node that performed the original unblock
- **Targets**: All connected mesh peers
- **Delivery**: Best-effort gossip (no acknowledged delivery)
- **Ordering**: Last-writer-wins by per-target version/timestamp ordering (Iteration 47)
- **IPC**: Supervisor also pushes `BlocklistEventUpdate` to workers

### Local Application

Request/WAF paths remain local-only. The `BlockStore` is the single source of truth for local enforcement. Mesh-ID blocks are control-plane/admin scoped only — `is_mesh_id_blocked()` is never called by WAF/request code (Iteration 51, Outcome A; enforced by `tests/mesh_id_boundary_guard.rs`). `apply_blocklist_event` dispatches based on `(operation, target_kind)`:

- `(Block, Ip)` → `block_ip_with_provenance`
- `(Unblock, Ip)` → `unblock_ip`
- `(Block, MeshId)` → `block_mesh_id_with_provenance`
- `(Unblock, MeshId)` → `unblock_mesh_id`

## Idempotency

Distributed events carry a required `event_id` for idempotent application:

### Event ID Format

```
{source_node}:{timestamp}:{operation}:{target_kind}:{site_scope}:{identifier_hash}
```

Where `identifier_hash` is a short hash of the identifier (IP or mesh ID) to keep the event ID bounded.

### Deduplication

- FIFO dedupe cache: `SeenEventCache` wrapping `HashSet<String>` + `VecDeque<String>`
- Bounded to 10,000 event IDs
- On capacity: oldest event ID evicted one-by-one (not full-set clear)
- Event IDs are checked before application; duplicates return `NoopDuplicate`
- Events without `event_id` are not deduped (applied directly)

### Ordering

Last-writer-wins per-target ordering (Iteration 47):

- Each target `(target_kind, site_scope, identifier)` tracks the last-applied event's timestamp and version.
- If both events have `version`, higher version wins.
- If only timestamps are available, higher timestamp wins.
- Equal timestamp with neither version present: the event is rejected as stale.
- Older block must not resurrect a target after newer unblock.
- Older unblock must not remove a newer block.
- `IgnoredStale` is returned when a per-target event is rejected.

Clock skew between nodes is a known caveat — nodes with significantly skewed clocks may produce out-of-order application. This is acceptable for operational blocklist removes where approximate consistency is sufficient.

**Limitation**: Per-target state is in-memory only. Process restart loses stale replay protection. Events received after restart will apply based on dedup only (until the target is re-observed).

## Current Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| No Raft integration for blocklist | Operational removes are not linearizable | Acceptable for operational blocklist; threat-intel uses canonical trust |
| Best-effort propagation | Events may be lost if peer is offline | Catchup repairs missed events within retention window (Iteration 48) |
| No acknowledged delivery | Sender does not know if peer received event | Catchup provides eventual reconciliation for reconnecting peers |
| Clock skew ordering | Events may apply out of order on skewed nodes | Bounded by reasonable clock drift; admin retry |
| In-memory per-target state | Stale replay protection lost on restart | Acceptable for operational blocklist; periodic sync (future) can mitigate |
| In-memory event log | Event log lost on restart; catchup only covers retained window | Configurable capacity; snapshot/admin fallback for gaps |

## Implementation Details

### Proto Wire Format

- `BlocklistEventData` message: carries event_id, source_node, timestamp, operation, target_kind, identifier, site_scope, reason, provenance, ttl_secs, version
- `BlocklistEventGossip` message: wraps `BlocklistEventData` + signature + signer_public_key
- `MeshMessage` oneof variant: `blocklist_event_gossip = 178`

### BlockStore Apply

- `BlockStore::apply_blocklist_event()`: deterministic, local, no I/O
- `BlocklistApplyResult`: Applied, NoopDuplicate, IgnoredStale, InvalidTarget, StoreDisabled
- 5-step apply pipeline: validate target → check dedup → check per-target stale → mutate → record state
- FIFO dedup via `SeenEventCache` (HashSet + VecDeque), capped at 10,000
- Per-target stale suppression via `TargetStateCache` (AHashMap + VecDeque), capped at 10,000
- Per-target state is in-memory only; not persisted across restarts

### Admin Emit Path

- Admin unban calls `announce_local_unblock()` after successful local removal
- Response includes `"propagation": "queued"` to indicate event was emitted
- Supervisor pushes `BlocklistEventUpdate` IPC to all connected workers

### Supervisor/Worker Sync

- `BlocklistEventUpdate` IPC message carries serialized `BlocklistEvent` JSON, including `BlockProvenance` (preferred path for provenance-preserving propagation)
- `BlockEntryData`/`MeshBlockEntryData` carry optional `provenance_kind`/`provenance_source` fields (Iteration 50); `ipc_data_to_provenance()` maps `None` to `SupervisorSync` for backward compat
- Workers deserialize and apply via `apply_blocklist_event()`
- Backward compatible: old `BlocklistUpdate`/`BlocklistResponse` still work

## Offline-Peer Catchup (Iteration 48, Cursor Fix Iteration 49)

Reconnecting peers can now request recent blocklist events via `BlocklistCatchupRequest`/`BlocklistCatchupResponse` mesh messages. The event log is bounded (10,000 events default) and in-memory only. History gaps are detected and surfaced as `snapshot_required: true` in the response. See `architecture/blocklist_reconciliation.md` for full details.

Iteration 49 fixed cursor semantics: `since_sequence: None` replays from the oldest retained event (including sequence 0), while `since_sequence: Some(n)` returns events with sequence `> n`. The previous `since_sequence: 0` for "full catchup" silently skipped event at sequence 0.

## Future Work

- Periodic blocklist sync for offline-peer catchup (partially addressed by Iteration 48 catchup)
- Per-source cursor persistence for cross-restart convergence
- Full snapshot fallback for history gaps beyond retention window
- Acknowledged delivery for critical removes
- Persisted per-target tombstones for stale replay protection across restarts
