# BlockStore Admin Observability Model

## BlockStore Entity Model

### Current Entity Types

| Entity | Key Shape | Consumers | Mutation API | Response DTO | Persistence | Proposed Change |
|--------|-----------|-----------|-------------|-------------|-------------|-----------------|
| IP Block | `block:{site_scope}:{ip}` | WAF check_block_store, WAF check_early, Admin list_bans, Mesh stubs | `block_ip()`, `block_ip_with_provenance()`, `unblock_ip()`, `is_blocked()` | `BanRecord` with `ban_type="ip"` | `blocks.json` (JSON) | No change |
| Mesh-ID Block (first-class) | `mesh_block:{site_scope}:{mesh_id}` | Admin list_bans, Supervisor sync | `block_mesh_id_with_provenance()`, `unblock_mesh_id()`, `is_mesh_id_blocked()` | `BanRecord` with `ban_type="mesh_id"` | `mesh_blocks.json` (JSON) | New first-class entity |
| Legacy Sentinel Mesh-ID | `block:{site_scope}:0.0.0.0` | Admin list_bans (compat), migration | Legacy `block_ip_with_provenance()` | Parsed as `ban_type="mesh_id"` | `blocks.json` | Auto-migrated to first-class `MeshBlockEntry` during `BlockStore::new` |
| Supervisor Sync (IP) | Same as IP Block | Worker BlockStore | `block_ip_with_provenance()` with `SupervisorSync` | Via `BlockEntryData` IPC | Worker local | Extended with mesh blocks |
| Supervisor Sync (Mesh) | Same as Mesh-ID Block | Worker BlockStore | `block_mesh_id_with_provenance()` with `SupervisorSync` | Via `MeshBlockEntryData` IPC | Worker local | New |

### BlockTargetKind Enum

```rust
pub enum BlockTargetKind {
    Ip,
    MeshId,
}
```

### BlockRecord (Unified Listing)

```rust
pub struct BlockRecord {
    pub target_kind: BlockTargetKind,
    pub identifier: String,       // IP string or mesh_id
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub access_count: u64,
    pub last_access: u64,
    pub provenance: BlockProvenance,
}
```

## Admin API Changes

### POST /mesh/ban/mesh-id
- Now calls `block_mesh_id_with_provenance()` instead of sentinel `block_ip_with_provenance()`
- Response includes `site_scope: "global"` field
- Multiple mesh-ID bans can coexist concurrently

### DELETE /mesh/ban?identifier=X&ban_type=mesh_id
- Now calls `unblock_mesh_id()` for the specific mesh ID
- Only removes the requested mesh ID, not all mesh-ID bans
- Returns 404 if the specific mesh ID is not blocked

### GET /mesh/bans
- Uses `get_all_block_records()` which returns both IP and mesh-ID blocks
- Each record has `target_kind: "ip"` or `target_kind: "mesh_id"`
- `BanRecord` includes `is_legacy_sentinel` field (always false for new entries)

## IPC Sync Changes

### BlocklistResponse
- New `mesh_blocks: Vec<MeshBlockEntryData>` field (serde(default) for backward compat)
- Workers apply mesh blocks with `SupervisorSync` provenance

### BlocklistUpdate
- New `mesh_blocks: Vec<MeshBlockEntryData>` field
- Same backward-compatible deserialization

### MeshBlockEntryData
```rust
pub struct MeshBlockEntryData {
    pub mesh_id: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub provenance_kind: Option<String>,    // Iteration 50
    pub provenance_source: Option<String>,  // Iteration 50
}
```

## WAF / Request-Time Semantics

**Mesh-ID blocks are control-plane/admin scoped only (Iteration 51, Outcome A).**

Mesh-ID blocks are NOT enforced at the WAF request path because:
1. `RequestContext` does not carry mesh ID information
2. `WafContext` and all WAF trait signatures (`Http3RequestWaf::check_request_full`, `BufferedRequestWaf::check_request_full`, `WafProcessor::check_request`) lack a mesh identity field
3. WAF block checks use `is_blocked(client_ip, site_scope)` which matches against IP keys
4. The sentinel `0.0.0.0` key is never matched by real client IPs
5. External HTTP clients do not present mesh credentials — mesh identity exists only at the mesh transport layer for mesh-to-mesh communication
6. No `AuthenticatedMeshIdentity` or `MeshIdentitySource` type exists in the codebase

A mechanical guardrail test (`tests/mesh_id_boundary_guard.rs`) scans WAF/request/proxy/HTTP/3 source files to prevent `is_mesh_id_blocked()` from being called in request-path code.

Mesh-ID block enforcement is scoped to:
- Admin API ban/unban/list operations (control-plane)
- Supervisor/worker sync replication (control-plane)
- Mesh control-plane operations (peer trust, membership)
- `BlockStore::is_mesh_id_blocked()` exists but is only called by admin handlers and mesh stubs — never by WAF/request code

If request-path mesh-ID enforcement is desired in the future (Outcome B), a trusted `mesh_identity: Option<AuthenticatedMeshIdentity>` field must first be added to the request context and populated at a composition root without using untrusted HTTP headers.

## Persistence

### IP Blocks
- File: `blocks.json` in data directory
- Format: JSON array of `BlockEntry` objects
- Backward compatible: old entries without `provenance` field deserialize with `LegacyUnknown` default

### Mesh-ID Blocks
- File: `mesh_blocks.json` in data directory (alongside `blocks.json`)
- Format: JSON array of `MeshBlockEntry` objects
- Separate file avoids schema migration issues with existing `blocks.json`

### Migration
- `migrate_legacy_sentinel_entries()` converts sentinel `0.0.0.0` entries with `mesh_id_ban:` prefix to first-class mesh entries
- **Auto-called**: `BlockStore::new` automatically calls `migrate_legacy_sentinel_entries()` after loading both IP and mesh files from disk
- One-way migration: once migrated, entries are stored in `mesh_blocks.json`

## Unblock Propagation

Admin unban now propagates to mesh peers and workers:

1. Local BlockStore mutation (immediate)
2. `announce_local_unblock()` gossips `BlocklistEventGossip` to mesh peers
3. Supervisor pushes `BlocklistEventUpdate` IPC to all connected workers
4. Peers/workers apply via `BlockStore::apply_blocklist_event()` (idempotent)
5. Response includes `"propagation": "queued"` (not `"propagated: true"` — no ack)

## BlocklistEvent (Structured Logging + Mesh Propagation)

`BlocklistEvent` and `BlocklistOperation` types in `synvoid-core::block_store` are used for both structured local logging AND mesh propagation:

- Admin ban/unban handlers emit `BlocklistEvent` logs at **debug level** with target `blocklist_event`
- Admin unban handlers also call `announce_local_unblock()` to gossip the event
- `BlocklistEvent` supports distributed fields: `event_id`, `source_node`, `ttl_secs`, `version`
- Event ID format: `{source_node}:{timestamp}:{operation}:{target_kind}:{site_scope}:{identifier_hash}`
- **Dedupe**: FIFO `SeenEventCache` (HashSet + VecDeque), capped at 10,000. Evicts oldest one-by-one, not full-clear.
- **Stale suppression**: Per-target `TargetStateCache` tracks last-applied event timestamp/version. Older events return `IgnoredStale`.
- **Apply pipeline**: validate → dedup → stale check → mutate → record state
- **IPC provenance** (Iteration 50): `BlocklistEventUpdate` carries full `BlocklistEvent` JSON with `BlockProvenance`. Admin `ban_ip`/`ban_mesh_id` now also broadcast to workers. `BlockEntryData`/`MeshBlockEntryData` include optional `provenance_kind`/`provenance_source` fields; `ipc_data_to_provenance()` maps `None` to `SupervisorSync`. See `architecture/blocklist_provenance_preservation.md`.
- See `architecture/blocklist_remove_consistency.md` for full consistency model

## Enforcement Rules (unchanged)

- Manual/supervisor block writes use `block_ip_with_provenance()` or `block_mesh_id_with_provenance()` with correct provenance
- `AdminManual` for admin API, `SupervisorManual` for gRPC, `SupervisorSync` for IPC replication
- `LegacyUnknown` only for backward compat, tests, and mocks
- Manual/supervisor paths bypass threat-intel policy gates
