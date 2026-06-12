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

### Admin Ban Mesh ID
- **File:** `src/admin/handlers/mesh_admin.rs:ban_mesh_id()`
- **Route:** `POST /mesh/ban/mesh-id`
- **Provenance:** `AdminManual`, source `admin_ban_mesh_id`
- **Behavior:** Blocks mesh ID using first-class `block_mesh_id_with_provenance()` API with `site_scope: "global"`
- **Concurrency:** Multiple mesh-ID bans can coexist concurrently. Unblocking one mesh ID does not affect others.

### Admin Unban
- **File:** `src/admin/handlers/mesh_admin.rs:unban()`
- **Route:** `DELETE /mesh/ban`
- **Behavior:** Removes block entry. For `ban_type=ip`, calls `unblock_ip()`. For `ban_type=mesh_id`, calls `unblock_mesh_id()` for the specific mesh ID.
- **Accuracy:** Returns `success: true` only when an entry was actually removed. Returns 404 when no matching entry exists.
- **Propagation:** Unban is local-only. There is no mesh unblock propagation API; removal is not gossiped to mesh peers. Mesh peers retain stale blocks until TTL expiry. (See Known Gaps.)

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
- **Provenance:** `SupervisorSync`, source `blocklist_update` or `blocklist_response`
- **Note:** `BlockEntryData` IPC wire format does not carry provenance; workers re-assign `SupervisorSync` on receipt

## Response Exposure

| Endpoint | Provenance Exposed | Source Exposed | Other Fields |
|----------|-------------------|----------------|--------------|
| `GET /mesh/bans` | Yes (`BanRecord.provenance`) | Yes (`BanRecord.provenance_source`) | Mesh-ID bans included |
| `POST /mesh/ban/ip` | Yes (response JSON) | Yes (response JSON) | — |
| `POST /mesh/ban/mesh-id` | Yes (response JSON) | Yes (response JSON) | — |
| `DELETE /mesh/ban` | No | No | `identifier`, `ban_type`, `removed` |
| gRPC `BlockResponse` | No | No | — |

## Known Gaps

1. **IPC blocklist sync loses provenance**: `BlockEntryData` does not carry provenance; workers re-assign `SupervisorSync` regardless of original provenance.
2. **Unban does not propagate to mesh**: When an IP or mesh ID is unbanned via admin API, the removal is not gossiped to mesh peers. There is no `announce_local_unblock` or equivalent mesh removal message. Mesh peers retain stale blocks until TTL expiry. **Follow-up needed:** Add an unblock propagation mechanism (e.g., `HotThreatGossip` removal or dedicated unblock message) if global consistency is required.
3. **Mesh-ID blocks not enforced at WAF request path**: `RequestContext` does not carry mesh ID, so mesh-ID blocks are scoped to admin/control-plane operations only. **Follow-up needed:** If mesh-ID blocking should affect request routing, `mesh_id` must be added to `RequestContext` and wired through the WAF pipeline.
