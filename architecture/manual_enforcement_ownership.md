# Manual and Supervisor Enforcement Ownership

## Overview

This document defines the ownership model for manual and supervisor-driven IP enforcement, separating it from automated mesh threat-intel and WAF enforcement.

## Enforcement Classification

| Category | Authority Source | Policy Gate | Provenance Kind |
|----------|-----------------|-------------|-----------------|
| Admin manual ban | Human operator via Admin API | None (operator authority) | `AdminManual` |
| Supervisor manual block | Control-plane via gRPC | None (control-plane authority) | `SupervisorManual` |
| Supervisor blocklist sync | Supervisor-to-worker IPC | None (control-plane replication) | `SupervisorSync` |
| Mesh threat-intel enforcement | Remote mesh advisory data | `MeshThreatIntelPolicyGated` | `MeshThreatIntelPolicyGated` |
| Local WAF action | WAF engine rule match | None (local engine) | `LocalWaf` |
| Local honeypot | Honeypot trap interaction | None (local detection) | `LocalHoneypot` |
| Local ASN tracker | ASN scraping thresholds | None (local detection) | `LocalAsnTracker` |
| Proxy health probe | Upstream error tracking | None (local health check) | `ProxyHealthProbe` |

## Ownership Rules

1. **Manual/supervisor production block writes must use `block_ip_with_provenance`**, not legacy `block_ip`.
2. **Provenance kind must be correct**: `AdminManual` for admin API/operator actions, `SupervisorManual` for explicit supervisor commands, `SupervisorSync` for replicated blocklist state.
3. **Source strings should be meaningful**: Use stable action identifiers (e.g., `admin_ban_ip`, `grpc_block_ip`, `blocklist_update`).
4. **Manual/supervisor paths bypass threat-intel policy gates** because their authority comes from operator/control-plane intent, not remote advisory data.
5. **Do not use `LegacyUnknown`** for new manual/supervisor production block writes.
6. **Responses should expose provenance** where block entries are returned.

## Production Enforcement Surfaces

### Admin Ban IP
- **File:** `src/admin/handlers/mesh_admin.rs:ban_ip()`
- **Route:** `POST /mesh/ban/ip`
- **Provenance:** `AdminManual`, source `admin_ban_ip`
- **Behavior:** Blocks IP, announces to mesh via `announce_local_block()`
- **Observability:** Emits `BlocklistEvent` debug log (target `blocklist_event`) with operation `Block`

### Admin Ban Mesh ID
- **File:** `src/admin/handlers/mesh_admin.rs:ban_mesh_id()`
- **Route:** `POST /mesh/ban/mesh-id`
- **Provenance:** `AdminManual`, source `admin_ban_mesh_id`
- **Behavior:** Blocks mesh ID using first-class `block_mesh_id_with_provenance()` API with `site_scope: "global"`
- **Concurrency:** Multiple mesh-ID bans can coexist concurrently. Unblocking one mesh ID does not affect others.
- **Observability:** Emits `BlocklistEvent` debug log (target `blocklist_event`) with operation `Block`

### Admin Unban
- **File:** `src/admin/handlers/mesh_admin.rs:unban()`
- **Route:** `DELETE /mesh/ban`
- **Behavior:** Removes block entry. For `ban_type=ip`, calls `unblock_ip()`. For `ban_type=mesh_id`, calls `unblock_mesh_id()` for the specific mesh ID.
- **Accuracy:** Returns `success: true` only when an entry was actually removed. Returns 404 when no matching entry exists.
- **Propagation:** After local removal, calls `announce_local_unblock()` to gossip `BlocklistEventGossip` to mesh peers. Supervisor pushes `BlocklistEventUpdate` IPC to workers. Response includes `"propagation": "queued"`.
- **Observability:** Emits `BlocklistEvent` debug log (target `blocklist_event`) with operation `Unblock`

### Admin List Bans
- **File:** `src/admin/handlers/mesh_admin.rs:list_bans()`
- **Route:** `GET /mesh/bans`
- **Response:** `BanRecord` with `target_kind` ("ip" or "mesh_id"), `provenance` (kind string), `provenance_source` (optional detail), and `is_legacy_sentinel` flag.
- **Mesh-ID bans:** Listed as first-class entries with `ban_type: "mesh_id"` and `target_kind: "mesh_id"`.

### Supervisor gRPC Block IP
- **File:** `src/supervisor/api.rs:block_ip()`
- **Provenance:** `SupervisorManual`, source `grpc_block_ip`

### Supervisor gRPC Unblock IP
- **File:** `src/supervisor/api.rs:unblock_ip()`

### Worker Blocklist Sync (IPC)
- **File:** `src/worker/unified_server/lifecycle.rs`
- **Provenance:** Carried via `BlockEntryData`/`MeshBlockEntryData` optional `provenance_kind`/`provenance_source` fields (Iteration 50). Legacy messages without these fields default to `SupervisorSync` via `ipc_data_to_provenance()`.
- **Note:** `BlocklistEventUpdate` IPC (preferred path) carries full `BlocklistEvent` JSON including `BlockProvenance`.

## Response Exposure

| Endpoint | Provenance Exposed | Source Exposed | Other Fields |
|----------|-------------------|----------------|--------------|
| `GET /mesh/bans` | Yes (`BanRecord.provenance`) | Yes (`BanRecord.provenance_source`) | Mesh-ID bans included |
| `POST /mesh/ban/ip` | Yes (response JSON) | Yes (response JSON) | — |
| `POST /mesh/ban/mesh-id` | Yes (response JSON) | Yes (response JSON) | — |
| `DELETE /mesh/ban` | No | No | `identifier`, `ban_type`, `removed` |
| gRPC `BlockResponse` | No | No | — |

## Known Gaps

1. **~~IPC blocklist sync loses provenance~~**: **Resolved (Iteration 50).** `BlockEntryData`/`MeshBlockEntryData` now carry optional `provenance_kind`/`provenance_source` fields. `BlocklistEventUpdate` carries full `BlocklistEvent` JSON with `BlockProvenance`. Legacy messages without provenance fields default to `SupervisorSync` via `ipc_data_to_provenance()`. See `architecture/blocklist_provenance_preservation.md`.
2. **Unban propagation is best-effort**: Admin unban now gossips `BlocklistEventGossip` to mesh peers and pushes `BlocklistEventUpdate` IPC to workers, but delivery is not acknowledged. Mesh peers that are offline may miss the event. Periodic blocklist sync (future) can mitigate this.
3. **Mesh-ID blocks not enforced at WAF request path** (resolved — Iteration 51, Outcome A): `RequestContext`, `WafContext`, and all WAF trait signatures lack a mesh identity field. External HTTP clients do not present mesh credentials. Mesh-ID blocks are explicitly scoped to admin/control-plane operations only. A mechanical guardrail test (`tests/mesh_id_boundary_guard.rs`) prevents `is_mesh_id_blocked()` from being called in WAF/request code. If request-path mesh-ID enforcement is desired in the future (Outcome B), a trusted `mesh_identity: Option<AuthenticatedMeshIdentity>` field must first be added to the request context and populated at a composition root.
4. **Per-target stale suppression is in-memory only**: `TargetStateCache` is not persisted across process restarts. After restart, stale replay protection relies on event-ID dedup only until targets are re-observed. Persisted tombstones (future) can mitigate.
