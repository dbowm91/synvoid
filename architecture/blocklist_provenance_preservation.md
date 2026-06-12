# Blocklist IPC Provenance Preservation

## Overview

Iteration 50 established that blocklist provenance (the origin of a block/unblock decision) must be preserved end-to-end across all IPC and sync boundaries. Transport may explain how a blocklist event arrived, but it must not erase why the blocklist event exists.

## Origin Provenance vs Relay Context

### Origin Provenance

The actor/system that originally caused the blocklist state change. Stored in `BlockProvenance { kind, source }` on `BlockEntry`, `MeshBlockEntry`, `BlocklistEvent`, and `BlockRecord`.

Examples:
- `AdminManual` — admin API ban/unban
- `MeshThreatIntelPolicyGated` — mesh threat-intel with policy gating
- `SupervisorSync` — only when the supervisor itself originated the block
- `LegacyUnknown` — old data without provenance (backward compat)

### Relay Context

The transport path that delivered the operation. Must NOT overwrite origin provenance. Use tracing fields or log labels for relay information:
- `relay="supervisor_sync"` for supervisor-to-worker snapshot sync
- `relay="mesh_gossip"` for peer gossip
- `relay="catchup_replay"` for offline-peer catchup

## IPC Wire Types

### BlockEntryData / MeshBlockEntryData

Added `provenance_kind: Option<String>` and `provenance_source: Option<String>` fields (Iteration 50). Backward compatible — missing fields default to `None` on deserialization.

### BlocklistEventUpdate

Carries a full `BlocklistEvent` as JSON, including `provenance: BlockProvenance`. This is the preferred path for provenance-preserving propagation.

### Legacy Path Behavior

When `provenance_kind` and `provenance_source` are both `None` (legacy messages), the `ipc_data_to_provenance()` helper defaults to `SupervisorSync` since the supervisor is the relay context.

## Preservation Paths

| Path | Provenance Preserved? | Notes |
|------|----------------------|-------|
| Admin ban → BlockStore | ✅ | `AdminManual` set at origin |
| Admin ban → worker IPC (`BlocklistEventUpdate`) | ✅ | Full `BlocklistEvent` serialized as JSON |
| Admin unban → worker IPC (`BlocklistEventUpdate`) | ✅ | Full `BlocklistEvent` serialized as JSON |
| Admin unban → mesh gossip (`BlocklistEventGossip`) | ✅ | Provenance fields in wire format |
| Mesh gossip receive → `apply_blocklist_event` | ✅ | Original provenance reconstructed |
| Mesh catchup response → `apply_blocklist_event` | ✅ | `BlocklistEventData` round-trip preserves provenance |
| Supervisor snapshot → worker (`BlocklistResponse`) | ✅ | Provenance carried in `BlockEntryData` fields |
| Supervisor update → worker (`BlocklistUpdate`) | ✅ | Provenance carried in `BlockEntryData` fields |
| Worker replay from retained event log | ✅ | Events carry full provenance |
| Target-state persistence across restarts | ✅ | Iteration 53: `source_node` and `provenance` preserved in `BlocklistTargetStateRecord` |

## Admin Ban → Worker Propagation

After Iteration 50, admin `ban_ip` and `ban_mesh_id` handlers broadcast `BlocklistEventUpdate` to workers (previously only unban did this). Workers receive the full `BlocklistEvent` with `AdminManual` provenance preserved.

## Guardrails

- `manual_enforcement_provenance_guard.rs` includes a test (`no_unconditional_supervisor_sync_in_blocklist_ingestion`) that scans worker/supervisor blocklist ingestion paths for unconditional `BlockProvenanceKind::SupervisorSync` assignment.
- The `ipc_data_to_provenance()` helper is excluded from this guardrail since it is the canonical deserialization path.
- `mesh_id_boundary_guard.rs` (Iteration 51) scans WAF/request/proxy/HTTP/3 source files to prevent `is_mesh_id_blocked()` from being called in request-path code. Mesh-ID blocks are control-plane/admin scoped only.

## Backward Compatibility

- Old messages without `provenance_kind`/`provenance_source` fields deserialize with `None` values.
- `ipc_data_to_provenance()` maps `None` to `SupervisorSync` (relay default).
- No wire format breaking changes — all new fields are `Option` with `#[serde(default)]`.
