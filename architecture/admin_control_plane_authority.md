# Admin Control-Plane Authority

This document describes the typed authority, outcome, and audit model for admin and control-plane mutations.

## Overview

Every admin/control-plane mutation must be explicit about:
- **Authority**: who or what initiated the mutation
- **Provenance**: the source of the mutation for auditability
- **Local outcome**: whether the local store was mutated
- **Propagation**: whether mesh propagation was attempted and its status
- **Audit**: whether the mutation was logged for incident response

## Mutation Authority Taxonomy

| Authority | Description | Use Cases |
|-----------|-------------|-----------|
| `AdminManual` | An administrator manually triggered the mutation via the admin API | Block/unblock IP, config updates, plugin reload |
| `SupervisorManual` | The supervisor process triggered the mutation via gRPC or IPC | Supervisor-initiated block, stop, restart |
| `SupervisorSync` | The supervisor triggered an automatic sync | Config propagation to workers |
| `MeshPolicyGated` | A mesh policy rule triggered the mutation | Threat-intel policy gate block |
| `LocalDetector` | A local detector triggered the mutation | WAF block, honeypot block, ASN tracker block |
| `WorkerIpc` | A worker process triggered the mutation via IPC | Worker-reported probe block |
| `CompatibilityLegacy` | A legacy compatibility path triggered the mutation | Backward-compatible migration paths |

**Rule**: Compatibility paths must use `CompatibilityLegacy` explicitly rather than silently defaulting to admin authority.

## Actor Model

```rust
pub struct AdminActor {
    pub authority: AdminMutationAuthority,
    pub actor_id: Option<String>,      // username, node ID
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub session_id_hash: Option<String>, // NEVER raw tokens
}
```

**Security**: Raw session tokens must never be stored in audit logs. If a session ID is included, it must be hashed.

## Mutation Outcome Types

### AdminMutationStatus

| Status | Description |
|--------|-------------|
| `Applied` | The mutation was applied to the local store |
| `NoOpAlreadyPresent` | Target already in requested state (e.g., block already present) |
| `NoOpAlreadyAbsent` | Target already absent (e.g., unblock of something not blocked) |
| `DuplicateIgnored` | The event was a duplicate and was ignored |
| `StaleIgnored` | The event was stale and was ignored |
| `InvalidRejected` | The request was invalid and was rejected |
| `UnauthorizedRejected` | The request was unauthorized and was rejected |
| `Failed` | The mutation failed |

### PropagationStatus

| Status | Description |
|--------|-------------|
| `NotApplicable` | Propagation is not applicable (local-only operation) |
| `QueuedBestEffort` | Mutation queued for best-effort mesh propagation (NOT guaranteed delivery) |
| `AppliedLocalOnly` | Mutation applied locally only; no propagation attempted |
| `SnapshotRepairRequired` | Snapshot repair needed for peer consistency |
| `FailedToQueue` | Queuing failed |
| `Deferred` | Propagation deferred to later |

**Non-guarantee**: `QueuedBestEffort` does NOT mean all peers received the mutation. It means the event was placed in the propagation queue. Actual delivery depends on network conditions, peer availability, and queue processing.

### AdminMutationResult

```rust
pub struct AdminMutationResult<T = serde_json::Value> {
    pub status: AdminMutationStatus,
    pub target: T,
    pub local_store_mutated: bool,
    pub propagation: PropagationStatus,
    pub event_id: Option<String>,
    pub audit_id: Option<String>,
    pub message: String,
}
```

Builder methods: `applied()`, `applied_with_propagation()`, `noop()`, `duplicate()`, `stale()`, `invalid()`, `failed()`, `with_event_id()`, `with_audit_id()`, `with_propagation()`.

## Audit Event Schema

```rust
pub struct AdminAuditEvent {
    pub audit_id: String,
    pub timestamp: u64,
    pub actor: AdminActor,
    pub action: String,
    pub target_kind: String,
    pub target_id: String,
    pub prior_state: Option<serde_json::Value>,
    pub requested_state: Option<serde_json::Value>,
    pub resulting_state: Option<serde_json::Value>,
    pub mutation_status: AdminMutationStatus,
    pub propagation_status: PropagationStatus,
    pub event_id: Option<String>,
}
```

### Audit Sink Trait

```rust
pub trait AdminAuditSink: Send + Sync {
    fn record(&self, event: AdminAuditEvent);
}
```

Implementations:
- `TracingAuditSink` — logs via `tracing::info!`
- `NoOpAuditSink` — discards all events

Durable audit storage is future work.

## Endpoint Inventory

### Block/Unblock Endpoints (Priority)

| Endpoint | File | Authority | Current Response | Target Result |
|----------|------|-----------|------------------|---------------|
| POST `/mesh/ban/ip` | `src/admin/handlers/mesh_admin.rs:420` | `AdminManual` | `Json(json!({"success": true}))` | `AdminMutationResult<BlockMutationTarget>` |
| POST `/mesh/ban/mesh-id` | `src/admin/handlers/mesh_admin.rs:518` | `AdminManual` | `Json(json!({"success": true}))` | `AdminMutationResult<BlockMutationTarget>` |
| DELETE `/mesh/ban` | `src/admin/handlers/mesh_admin.rs:618` | `AdminManual` | `Json(json!({"success": true}))` | `AdminMutationResult<BlockMutationTarget>` |
| POST `/probes/block` | `crates/synvoid-admin/src/handlers/probes.rs:315` | `SupervisorManual` | `Json(json!({"blocked": [...]}))` | `AdminMutationResult` |

### Supervisor gRPC Commands

| Command | File | Authority | Current Response | Target Result |
|---------|------|-----------|------------------|---------------|
| `ReloadConfig` | `src/supervisor/api.rs:70` | `SupervisorManual` | `ReloadResponse { success: true }` | `AdminMutationResult` |
| `Stop` | `src/supervisor/api.rs:84` | `SupervisorManual` | `StopResponse { success: true }` | `AdminMutationResult` |
| `BlockIp` | `src/supervisor/api.rs:97` | `SupervisorManual` | `BlockResponse { success: true }` | `AdminMutationResult` |
| `UnblockIp` | `src/supervisor/api.rs:122` | `SupervisorManual` | `UnblockResponse { success: true }` | `AdminMutationResult` |

### Config Endpoints (Deferred)

All `PUT /config/*` endpoints currently return `StatusResponse::success(...)`. These are lower priority for conversion since they are local-only mutations without mesh propagation. They will be converted in a future phase.

### Site Management Endpoints (Deferred)

All `POST/PUT/DELETE /sites/*` endpoints currently return typed DTOs. These are lower priority and will be converted in a future phase.

## Propagation Semantics

Three propagation channels exist for block/unblock operations:

1. **Upstream Block Broadcast** (MeshProxy layer): Triggered after consecutive upstream failures. Broadcasts to 50% of global peers.
2. **Blocklist Event Gossip** (ThreatIntel layer): Individual block/unblock events gossiped with configurable fanout.
3. **Blocklist Catchup** (Reconciliation): Offline-peer catchup via event log replay and snapshot fallback.

**Key invariant**: Mesh propagation is best-effort. Admin endpoints must report `QueuedBestEffort`, not delivery confirmation.

## Non-Guarantees

- Best-effort mesh propagation is not delivery acknowledgement.
- Audit events are emitted before response return, but durable storage is not guaranteed in this phase.
- Config mutations are local-only; they do not propagate to mesh peers.
- Supervisor gRPC commands are local to the supervisor process; they do not propagate to mesh.
