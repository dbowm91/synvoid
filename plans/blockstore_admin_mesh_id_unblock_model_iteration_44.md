# BlockStore/Admin Mesh-ID Block Model and Unblock Propagation — Iteration 44

## Purpose

The manual enforcement path is now provenance-bearing and mesh-ID unban is no longer a false-success no-op. The remaining issues are larger modeling concerns that should be handled together rather than continuing to patch the sentinel `0.0.0.0` representation.

This pass should design and implement the next clean model for:

1. Concurrent mesh-ID bans as first-class manual/control-plane block targets.
2. Mesh unblock propagation semantics for admin/manual removals.
3. BlockStore/admin observability that can represent IP, mesh-ID, and propagated removals clearly.

The goal is to move from “mesh-ID encoded inside an IP block reason” to an explicit enforcement target model that can be inspected, synced, and unblocked correctly.

## Current Known State

Iteration 42/43 established:

- Admin IP bans use `AdminManual` provenance.
- Admin mesh-ID bans use `AdminManual` provenance.
- Supervisor manual blocks use `SupervisorManual` provenance.
- Supervisor blocklist sync uses `SupervisorSync` provenance.
- Mesh-ID bans currently use sentinel IP `0.0.0.0` and encode `mesh_id_ban:{mesh_id}:{reason}` in the reason string.
- Mesh-ID unban now removes the sentinel entry and only returns success when something was actually removed.
- `BlockStore::unblock_ip` now returns `false` when no entry exists.
- `list_bans` now surfaces sentinel mesh-ID bans.

Known limitations to resolve:

- BlockStore key is `(site_scope, ip)`, so only one mesh-ID ban can exist under sentinel `0.0.0.0` at a time.
- Banning a second mesh ID overwrites the first.
- Admin unban is local-only; there is no mesh unblock propagation API.
- Existing blocklist sync wire types do not carry enough target/provenance semantics for richer manual-control-plane reconciliation.

## Non-Goals

Do not redesign threat-intel policy semantics.

Do not change WAF request-path decision behavior except where it needs to query the new block target model.

Do not add request-path DHT/network lookups.

Do not introduce a full event-sourced audit log unless an existing lightweight event mechanism can be reused.

Do not rewrite all BlockStore persistence if a backward-compatible additive model is feasible.

Do not remove legacy IP `BlockEntry` support.

Do not remove compatibility for existing persisted sentinel mesh-ID entries until migration/backward compatibility is handled.

Do not build a full admin UI.

## Phase 1 — Audit Current BlockStore Shape and Consumers

Before changing types, document the current block model.

Inspect:

- `crates/synvoid-block-store/src/lib.rs`
- `crates/synvoid-core/src/block_store.rs`
- `crates/synvoid-waf/src/traits.rs`
- `src/waf/adapters.rs`
- `src/admin/handlers/mesh_admin.rs`
- `src/supervisor/**`
- `src/worker/unified_server/lifecycle.rs`
- mesh threat-intel sync / gossip types
- stubs and IPC wire types that expose block entries

Create or update:

- `architecture/blockstore_admin_observability.md`

Include a table of:

- current stored entity;
- key shape;
- consumers;
- mutation API;
- response DTO exposure;
- persistence/wire compatibility concern;
- proposed change.

Explicitly classify:

- IP blocks;
- mesh-ID blocks;
- supervisor sync blocks;
- local WAF/honeypot/ASN/proxy-originated blocks;
- legacy sentinel mesh-ID entries.

## Phase 2 — Define a First-Class Block Target Model

Introduce a small target abstraction that can represent more than IP blocks.

Preferred conceptual model:

```rust
pub enum BlockTarget {
    Ip { ip: IpAddr, site_scope: String },
    MeshId { mesh_id: String, site_scope: String },
}
```

or a persisted equivalent:

```rust
pub enum BlockTargetKind {
    Ip,
    MeshId,
}

pub struct BlockTargetKey {
    pub kind: BlockTargetKind,
    pub identifier: String,
    pub site_scope: String,
}
```

Requirements:

- IP blocks retain current behavior and compatibility.
- Mesh-ID blocks can coexist concurrently with different mesh IDs.
- The target type is serializable/deserializable.
- Existing persisted IP entries still load.
- Existing sentinel `0.0.0.0` mesh-ID entries are either migrated on read or surfaced as legacy/sentinel entries with a clear compatibility path.

Avoid over-generalizing to domain/URL/cert/ASN in this pass unless the type naturally supports future extension without implementing those targets.

## Phase 3 — Add Mesh-ID Block APIs

Add explicit APIs rather than reusing IP block APIs with sentinel encoding.

Suggested API shape:

```rust
block_mesh_id_with_provenance(mesh_id, reason, duration, site_scope, provenance) -> bool
unblock_mesh_id(mesh_id, site_scope) -> bool
is_mesh_id_blocked(mesh_id, site_scope) -> Option<BlockEntryLike>
get_all_block_entries() -> Vec<BlockRecord>
```

Use concrete names that match repository style.

Behavior requirements:

- Multiple mesh IDs can be blocked concurrently.
- Unblocking one mesh ID does not remove another.
- Mesh-ID block entries expose provenance, reason, duration, expiry, and site scope.
- Mesh-ID entries are visible in admin list responses.
- Legacy sentinel entries remain readable during transition.

If `BlockEntry` is currently IP-specific, either:

### Option A — Add a parallel `MeshBlockEntry`

Good if minimal and avoids destabilizing IP WAF paths.

### Option B — Generalize `BlockEntry` into `BlockRecord`

Good if done carefully with serde compatibility.

Preferred path: additive parallel/target-aware model first, then optionally unify later.

## Phase 4 — Admin API Updates

Update admin manual enforcement paths to use the new mesh-ID APIs.

Required changes:

- `ban_mesh_id` calls `block_mesh_id_with_provenance`, not sentinel `block_ip_with_provenance`.
- `unban` with `ban_type="mesh_id"` calls `unblock_mesh_id` for the requested mesh ID.
- `list_bans` lists all IP and mesh-ID block entries without sentinel parsing.
- Response payloads include:
  - `ban_type`;
  - `identifier`;
  - `reason`;
  - duration/expiry;
  - site scope;
  - provenance;
  - provenance source.

Compatibility behavior:

- If legacy sentinel mesh-ID entries exist, list them as `ban_type="mesh_id"` and mark/source them clearly if possible.
- Decide whether unban should remove both first-class and legacy sentinel mesh-ID entries for the same mesh ID during migration. Preferred: yes, if safe.

## Phase 5 — WAF / Request-Time Semantics

Decide where mesh-ID block checks are actually enforced.

Questions to answer:

- What request context carries mesh ID today?
- Are mesh IDs only meaningful for mesh peers, not external HTTP clients?
- Is mesh-ID blocking intended for admin mesh membership/control-plane behavior, request routing, or peer trust?

Do not add request-path network lookups.

If request context lacks mesh ID, keep mesh-ID block enforcement scoped to mesh/admin/control-plane operations and document that it does not affect ordinary client HTTP requests.

If mesh peer handling has a local mesh ID at decision time, add local in-memory BlockStore lookup there only.

Document the enforcement surface explicitly in `architecture/blockstore_admin_observability.md`.

## Phase 6 — Mesh Unblock Propagation Protocol

Audit existing mesh propagation:

- `announce_local_block`
- `HotThreatGossip`
- threat-intel sync messages
- supervisor blocklist sync
- any DHT remove/delete/tombstone semantics
- IPC message types between supervisor and worker

Design a minimal unblock propagation mechanism.

Preferred model:

```rust
BlocklistEvent {
    op: Block | Unblock,
    target: BlockTarget,
    reason: Option<String>,
    provenance: BlockProvenance,
    timestamp: u64,
    ttl_or_expiry: Option<u64>,
    source_node: Option<String>,
}
```

or an equivalent repository-native type.

Requirements:

- unblocks are explicit events, not inferred from absence;
- events carry target kind (`Ip` or `MeshId`);
- events carry provenance/control-plane source;
- replay/idempotency is safe;
- stale unblock events should not remove newer re-blocks accidentally if timestamps/versions exist;
- no request-path blocking on mesh propagation.

If full gossip/DHT propagation is too large for one pass, split implementation:

1. Define local event type and admin/supervisor API surface.
2. Wire local admin unban to emit/log event.
3. Add a follow-up for distributed transport.

But do not leave response wording implying global propagation unless it actually exists.

## Phase 7 — Supervisor/Worker Sync Updates

Update supervisor blocklist sync to understand target kinds.

Current limitation:

- Worker sync reassigns `SupervisorSync` and may only carry IP-style `BlockEntryData`.

Target state:

- sync payload can carry IP and mesh-ID block records;
- sync can carry removals/unblocks or tombstones;
- worker applies `SupervisorSync` provenance for replicated state;
- local admin/supervisor manual operations remain distinct from replicated sync.

Keep backwards compatibility for old IP-only messages if needed.

## Phase 8 — Admin/Debug Observability

Improve BlockStore/admin inspection so operators can reason about state.

Add or update response fields:

- `target_kind`: `ip` / `mesh_id`;
- `identifier`;
- `site_scope`;
- `reason`;
- `provenance`;
- `provenance_source`;
- `is_legacy_sentinel` if applicable;
- `expires_at`;
- `source_node` or `sync_source` if available.

Possible admin endpoints:

- existing `GET /mesh/bans` extended;
- optional debug endpoint for raw block-store records if one already exists;
- avoid adding large new APIs unless necessary.

Docs should explain exactly which entries are local-only, mesh-propagated, supervisor-synced, or legacy.

## Phase 9 — Migration / Backward Compatibility

Handle existing sentinel entries deliberately.

Acceptable options:

### Read-time compatibility

When listing or checking mesh-ID blocks, recognize legacy sentinel entries and present them as legacy mesh-ID blocks.

### One-time migration on load

When persisted blocks are loaded, convert sentinel entries into first-class mesh-ID entries if reason parsing succeeds.

### No migration, explicit legacy display only

Allowed only if documented and tests prove legacy entries do not crash or disappear unexpectedly.

Preferred: read-time compatibility first; migration can be a later cleanup if persistence changes are risky.

## Phase 10 — Tests

Add focused tests for the new model.

Required tests:

1. Can block multiple mesh IDs concurrently.
2. Unblocking one mesh ID leaves others intact.
3. Re-blocking the same mesh ID updates/overwrites only that mesh ID.
4. Admin `ban_mesh_id` uses first-class mesh-ID block API and `AdminManual` provenance.
5. Admin `unban mesh_id` removes only the requested mesh ID.
6. `GET /mesh/bans` lists multiple mesh-ID bans distinctly.
7. Legacy sentinel mesh-ID entry is listed as mesh-ID compatibility record.
8. Legacy sentinel unban behavior is defined and tested.
9. IP block/unblock behavior is unchanged.
10. Supervisor sync can carry/apply mesh-ID block entries if implemented.
11. Unblock propagation event is emitted/applied/idempotent if implemented.
12. Manual/provenance guard still passes.

Guardrail tests:

- admin mesh-ID ban should not call sentinel IP helper except in legacy compatibility code;
- new production mesh-ID block writes should not use `.block_ip(`;
- unblock propagation response text should not claim global propagation unless an event is emitted.

## Phase 11 — Documentation

Update:

- `architecture/manual_enforcement_ownership.md`
- `architecture/blockstore_admin_observability.md`
- `docs/THREAT_INTEL.md`
- `AGENTS.md`
- any admin/OpenAPI docs if generated manually

Documentation must state:

- mesh-ID blocks are first-class and concurrent;
- legacy sentinel entries are compatibility-only;
- unban propagation semantics:
  - local-only, event-emitted, or fully mesh-propagated;
- whether WAF request paths consult mesh-ID blocks;
- how supervisor sync represents block and unblock events.

## Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-block-store mesh_id
cargo test -p synvoid-block-store block_target
cargo test --lib mesh_admin
cargo test --lib supervisor
cargo test --lib blocklist
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
```

If new mesh propagation tests exist:

```bash
cargo test -p synvoid-mesh unblock
cargo test -p synvoid-mesh blocklist_event
```

Adjust exact filters to match implementation.

## Acceptance Criteria

This pass is complete when:

1. Mesh-ID blocks no longer depend on sentinel `0.0.0.0` for new writes.
2. Multiple mesh-ID bans can coexist concurrently.
3. Unblocking one mesh ID removes only that mesh ID.
4. IP block behavior remains backward compatible.
5. Admin list/detail responses expose IP and mesh-ID blocks clearly.
6. Legacy sentinel mesh-ID entries are handled deliberately.
7. Unban propagation semantics are implemented or explicitly documented as local-only with no misleading response text.
8. If propagation is implemented, unblock events are explicit, target-aware, idempotent, and provenance-bearing.
9. Supervisor/worker sync path is either target-aware or has a documented staged follow-up.
10. Tests cover concurrent mesh-ID blocks, targeted unblocks, legacy sentinel compatibility, admin responses, and propagation/local-only semantics.
11. Existing WAF/threat-intel boundary guardrails still pass.

## Notes for the Implementer

This is a state-model pass. Avoid turning it into a WAF or threat-intel redesign.

The key invariant is:

> BlockStore/admin state must represent enforcement targets explicitly. IP blocks and mesh-ID blocks are different target types. Manual/admin/supervisor unblocks must remove the intended target only, and distributed unblock semantics must be explicit rather than implied.

Prefer additive compatibility over disruptive rewrites. If the unblock propagation protocol becomes too large, define the local event/model cleanly and stage distributed transport as a follow-up, but do not leave admin responses ambiguous about propagation scope.
