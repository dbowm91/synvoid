# Blocklist Remove Consistency

## Overview

This document describes the authority model, propagation mechanism, and consistency guarantees for blocklist block and unblock operations in SynVoid. Implemented in Iteration 46.

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
- **Ordering**: Timestamp-based last-writer-wins
- **IPC**: Supervisor also pushes `BlocklistEventUpdate` to workers

### Local Application

Request/WAF paths remain local-only. The `BlockStore` is the single source of truth for local enforcement. `apply_blocklist_event` dispatches based on `(operation, target_kind)`:

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

- In-memory `HashSet<String>` bounded to 10,000 entries
- Oldest entries evicted when capacity is reached (FIFO approximation)
- Event IDs are checked before application; duplicates return `NoopDuplicate`

### Ordering

Last-writer-wins based on `timestamp`. Clock skew between nodes is a known caveat — nodes with significantly skewed clocks may produce out-of-order application. This is acceptable for operational blocklist removes where approximate consistency is sufficient.

## Current Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| No Raft integration for blocklist | Operational removes are not linearizable | Acceptable for operational blocklist; threat-intel uses canonical trust |
| Best-effort propagation | Events may be lost if peer is offline | Periodic blocklist sync (future) |
| No acknowledged delivery | Sender does not know if peer received event | Gossip protocol semantics; eventual consistency |
| Clock skew ordering | Events may apply out of order on skewed nodes | Bounded by reasonable clock drift; admin retry |

## Implementation Details

### Proto Wire Format

- `BlocklistEventData` message: carries event_id, source_node, timestamp, operation, target_kind, identifier, site_scope, reason, provenance, ttl_secs, version
- `BlocklistEventGossip` message: wraps `BlocklistEventData` + signature + signer_public_key
- `MeshMessage` oneof variant: `blocklist_event_gossip = 178`

### BlockStore Apply

- `BlockStore::apply_blocklist_event()`: deterministic, local, no I/O
- `BlocklistApplyResult`: Applied, NoopDuplicate, IgnoredStale, InvalidTarget, StoreDisabled
- In-memory dedup via `seen_events: HashSet<String>` capped at 10,000

### Admin Emit Path

- Admin unban calls `announce_local_unblock()` after successful local removal
- Response includes `"propagation": "queued"` to indicate event was emitted
- Supervisor pushes `BlocklistEventUpdate` IPC to all connected workers

### Supervisor/Worker Sync

- New `BlocklistEventUpdate` IPC message carries serialized `BlocklistEvent` JSON
- Workers deserialize and apply via `apply_blocklist_event()`
- Backward compatible: old `BlocklistUpdate`/`BlocklistResponse` still work

## Future Work

- Periodic blocklist sync for offline-peer catchup
- Acknowledged delivery for critical removes
- Per-target version/sequence numbers for stronger ordering guarantees
