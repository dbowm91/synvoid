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

Phase 12 completed the conversion of all legacy mutating endpoints. All mutating endpoints now return typed `AdminMutationResult` and emit `AdminAuditEvent`. Config and site management endpoints are deferred.

### Phase 12 Gap Closure (2026-06-30)

The following endpoints were converted in the final Phase 12 pass:

| Endpoint | File | Change |
|----------|------|--------|
| `create_session`, `delete_session` | auth.rs | Audit events added, responses use `AdminMutationResult` |
| `update_theme` | theme.rs | Converted from `ThemeResponse` to `AdminMutationResult`, audit event added |
| `create_listener`, `delete_listener` | tcp_udp.rs | Converted to `AdminMutationResult`, audit events added |
| `derive_signing_key`, `submit_audit_report`, `report_signature_failure`, `create_organization` | mesh_admin.rs | Converted from custom response types to `AdminMutationResult`, audit events added |
| `restart_worker`, `batch_restart_workers` | system.rs | Converted from `StatusResponse`/`BatchRestartResponse` to `AdminMutationResult`, audit events added |
| `scale_workers` | system.rs | Audit event added (already had `AdminMutationResult`) |
| `update_error_page` | logs.rs | Converted from `ErrorPageResponse` to `AdminMutationResult`, audit event added |
| `delete_probe`, `delete_suspicious_word`, `delete_upstream_error` | probes.rs | Converted from `StatusCode::NO_CONTENT` to `AdminMutationResult`, audit events added |
| `block_probes` | probes.rs | Audit event added (already had `AdminMutationResult`) |

**Guard test update**: The `admin_mutation_response_guard` now also detects `StatusResponse::success` as a legacy pattern, in addition to `{"success": true}` and `StatusCode::NO_CONTENT`.

All non-deferred mutating endpoints now return `AdminMutationResult` and emit `AdminAuditEvent`. The only remaining legacy patterns are the deferred config PUT endpoints (~50+) and site management endpoints (~6).

### Block/Unblock Endpoints (Priority) — ALL CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| POST `/mesh/ban/ip` | mesh_admin.rs | AdminManual | AdminMutationResult<BlockMutationTarget> |
| POST `/mesh/ban/mesh-id` | mesh_admin.rs | AdminManual | AdminMutationResult<BlockMutationTarget> |
| DELETE `/mesh/ban` | mesh_admin.rs | AdminManual | AdminMutationResult<BlockMutationTarget> |
| POST `/mesh/attest-capability` | mesh_admin.rs | AdminManual | AdminMutationResult<String> |
| POST `/probes/block` | probes.rs | SupervisorManual | AdminMutationResult<String> |

### ICMP Endpoints — ALL CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| POST `/icmp/enable` | icmp.rs | AdminManual | AdminMutationResult<String> |
| POST `/icmp/disable` | icmp.rs | AdminManual | AdminMutationResult<String> |
| PUT `/icmp/config` | icmp.rs | AdminManual | AdminMutationResult<String> |

### Honeypot Endpoints — ALL CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| POST `/honeypot/control` | honeypot.rs | AdminManual | AdminMutationResult<String> |
| PUT `/honeypot/config` | honeypot.rs | AdminManual | AdminMutationResult<String> |

### YARA Endpoints — ALL CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| POST `/yara/submissions/{id}/approve` | yara_rules.rs | AdminManual | AdminMutationResult<String> |
| POST `/yara/submissions/{id}/reject` | yara_rules.rs | AdminManual | AdminMutationResult<String> |
| POST `/yara/broadcast` | yara_rules.rs | AdminManual | AdminMutationResult<String> |
| POST `/yara/sync` | yara_rules.rs | AdminManual | AdminMutationResult<String> |
| POST `/yara/submit` | yara_rules.rs | AdminManual | AdminMutationResult<String> |
| POST `/yara/apply` | yara_rules.rs | AdminManual | AdminMutationResult<String> |
| DELETE `/yara/submissions/{id}` | yara_rules.rs | AdminManual | AdminMutationResult<String> |

### Alerting Endpoints — CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| POST `/alerting/test-webhook` | alerting.rs | AdminManual | AdminMutationResult<String> |

### Threat Level Endpoints — ALL CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| PUT `/threat-level/level/{level}` | threat_level.rs | AdminManual | AdminMutationResult<String> |
| POST `/threat-level/auto` | threat_level.rs | AdminManual | AdminMutationResult<String> |
| POST `/threat-level/baseline/reset` | threat_level.rs | AdminManual | AdminMutationResult<String> |
| POST `/threat-level/backup` | threat_level.rs | AdminManual | AdminMutationResult<String> |
| DELETE `/threat-level/backup` | threat_level.rs | AdminManual | AdminMutationResult<String> |
| POST `/threat-level/history/prune` | threat_level.rs | AdminManual | AdminMutationResult<String> |

### Serverless Endpoints — CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| PUT `/serverless/config` | serverless.rs | AdminManual | AdminMutationResult<String> |

### Spin Endpoints — ALL CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| POST `/spin/apps` | spin.rs | AdminManual | AdminMutationResult<String> |
| DELETE `/spin/apps/{name}` | spin.rs | AdminManual | AdminMutationResult<String> |

### Rule Feed Endpoints — ALL CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| POST `/rule-feed/apply` | rule_feed.rs | AdminManual | AdminMutationResult<String> |
| POST `/rule-feed/discard` | rule_feed.rs | AdminManual | AdminMutationResult<String> |

### Plugin Endpoints — ALL CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| POST `/plugins/{name}/reload` | plugins.rs | AdminManual | AdminMutationResult<String> |

### PHP Endpoints — CONVERTED

| Endpoint | File | Authority | Response |
|----------|------|-----------|----------|
| POST `/system/php-pools/reload` | php.rs | AdminManual | AdminMutationResult<String> |

### Config Endpoints (Deferred)

All `PUT /config/*` endpoints still use `StatusResponse::success(...)`. These are local-only mutations without mesh propagation. Conversion is deferred to a future phase.

### Site Management Endpoints (Deferred)

All `POST/PUT/DELETE /sites/*` endpoints use typed DTOs. Conversion is deferred to a future phase.

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
