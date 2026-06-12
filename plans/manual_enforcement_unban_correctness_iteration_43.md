# Manual Enforcement Unban Correctness — Iteration 43

## Purpose

Iteration 42 established the ownership model for admin/supervisor manual enforcement and confirmed that manual/supervisor block writes now carry explicit provenance. It also documented a concrete correctness gap: admin mesh-ID unban currently reports success but does not remove the sentinel block entry used by mesh-ID bans.

This follow-up should close the unban correctness gaps without expanding scope.

Primary targets:

1. Make mesh-ID unban actually remove the corresponding block entry.
2. Make unban responses accurately reflect whether state changed.
3. Decide and document whether admin unban should propagate removal to mesh peers.
4. Add tests and, if useful, a small guardrail so manual enforcement cannot silently report success without mutation.

## Current Known State

From Iteration 42:

- Admin IP bans use `block_ip_with_provenance` with `BlockProvenanceKind::AdminManual` and source `admin_ban_ip`.
- Admin mesh-ID bans use `block_ip_with_provenance` with `BlockProvenanceKind::AdminManual` and source `admin_ban_mesh_id`.
- Mesh-ID bans are encoded as sentinel IP `0.0.0.0` with the mesh ID embedded in the reason string, roughly `mesh_id_ban:{mesh_id}:{reason}`.
- Admin IP unban parses the identifier as an IP and calls `block_store.unblock_ip(&ip, "global")`.
- Admin mesh-ID unban currently logs and returns success but does not remove the sentinel block entry.
- Admin unban does not currently propagate removal to mesh peers.

Known documented gaps:

- Mesh-ID unban is a no-op.
- Unban success response can be misleading.
- Unban propagation semantics are unclear.

## Non-Goals

Do not redesign mesh-ID ban storage.

Do not replace the sentinel-IP representation unless a tiny local helper is required.

Do not add a full audit/event log system.

Do not redesign admin auth/authz.

Do not change threat-intel policy semantics.

Do not change automated WAF/threat-intel enforcement behavior.

Do not add broad blocklist replication architecture.

Do not change `BlockStore` persistence format unless unavoidable.

## Phase 1 — Extract Mesh-ID Sentinel Helpers

The current mesh-ID ban representation is fragile because the sentinel IP and reason-string encoding are implicit.

Add small local helpers near the admin handler or in an appropriate manual-enforcement helper module:

```rust
const MESH_ID_BAN_SENTINEL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

fn mesh_id_ban_reason(mesh_id: &str, reason: &str) -> String {
    format!("mesh_id_ban:{mesh_id}:{reason}")
}

fn is_mesh_id_ban_reason(reason: &str, mesh_id: &str) -> bool {
    reason.starts_with(&format!("mesh_id_ban:{mesh_id}:"))
}
```

If `const IpAddr` is awkward, use a small function:

```rust
fn mesh_id_ban_sentinel_ip() -> IpAddr { ... }
```

Use the helper in both `ban_mesh_id` and `unban`.

Do not move this into a broad new crate unless the code already has a better local manual-enforcement utility module.

## Phase 2 — Implement Real Mesh-ID Unban

Update `src/admin/handlers/mesh_admin.rs::unban` for `ban_type == "mesh_id"`.

Required behavior:

1. Locate the sentinel block entry for `0.0.0.0` whose reason matches the requested mesh ID.
2. If found, remove it with `block_store.unblock_ip(&sentinel_ip, "global")` or an equivalent targeted method.
3. Return success only if an entry was actually removed.
4. Return `404 Not Found` or a structured success=false response if no matching mesh-ID ban exists.

Important: if multiple mesh-ID bans can exist simultaneously under a single sentinel IP, the current representation may be insufficient because `unblock_ip(&0.0.0.0, "global")` removes the entire sentinel entry, not a specific mesh ID.

Audit the current block-store model before implementing:

- Is the key `(ip, site_scope)` only?
- Can multiple reasons exist for the same IP/scope?
- Does banning two mesh IDs overwrite the same sentinel entry?

If the current model supports only one sentinel entry, document that limitation and choose one of two options:

### Option A — Keep current semantics and document single active mesh-ID sentinel ban

Acceptable only if mesh-ID bans are effectively single-entry today.

### Option B — Store mesh-ID bans with deterministic pseudo-IP mapping

If multiple mesh-ID bans are required, create a deterministic mapping from mesh ID to a loopback/reserved pseudo-IP or add a dedicated mesh-ID block table. This is larger and should be deferred unless current code already has support.

Preferred for this pass: avoid schema redesign. Fix correctness within current representation, then document any limitation.

## Phase 3 — Make Unban Responses Accurate

Current IP unban returns success only when `unblock_ip` returns true, otherwise falls through to `404`. Keep or clarify that behavior.

For both IP and mesh-ID unban, response should include:

- `success: true` only when a block was removed;
- `identifier`;
- `ban_type`;
- optionally `removed: true`;
- optionally `provenance`/`provenance_source` of the removed entry if cheaply available before removal.

For not-found:

- either return `404` with no body, preserving existing style;
- or return a JSON body with `success: false` if existing admin API style supports it.

Do not silently return success for no-op unbans.

## Phase 4 — Decide Mesh Propagation Semantics

Audit existing mesh block propagation APIs:

- `announce_local_block`
- any unblock/remove/gossip counterpart;
- blocklist sync behavior;
- threat-intel removal or expiry mechanisms.

Determine whether admin unban should propagate to mesh peers.

Preferred outcomes:

### If an existing unblock propagation API exists

Call it from admin IP unban and mesh-ID unban after successful local removal.

### If no existing unblock propagation API exists

Do not invent one in this pass. Instead:

- document that unban is local-only today;
- add an explicit TODO/follow-up in `architecture/manual_enforcement_ownership.md`;
- ensure response wording does not imply global mesh propagation.

Avoid adding a half-designed mesh removal gossip protocol in this focused pass.

## Phase 5 — Tests

Add focused tests.

Recommended tests:

1. `ban_mesh_id_writes_sentinel_entry_with_admin_manual_provenance`.
2. `unban_mesh_id_removes_existing_sentinel_entry`.
3. `unban_mesh_id_returns_not_found_when_missing`.
4. `unban_ip_removes_existing_block`.
5. `unban_ip_returns_not_found_when_missing`.
6. If multiple mesh-ID bans are unsupported, test/document overwrite behavior or add an ignored/follow-up test describing the limitation.
7. If propagation API exists, test that successful unban calls the unblock propagation hook.

If full Axum handler tests are heavy, add lower-level helper tests for sentinel reason parsing plus one integration-style handler/service test.

## Phase 6 — Guardrail / Regression Test

Consider extending `tests/manual_enforcement_provenance_guard.rs` or adding a small test that catches no-op mesh-ID unban behavior.

Possible guardrail:

- assert `ban_type == "mesh_id"` branch in `unban` contains either `unblock_ip` or a named helper such as `unban_mesh_id`.

Keep this pragmatic. A handler-level test is better than a source-scan guard if feasible.

## Phase 7 — Documentation

Update `architecture/manual_enforcement_ownership.md`:

- remove or resolve the “mesh-ID unban is a no-op” known gap;
- document current mesh-ID ban storage semantics;
- document whether unban is local-only or mesh-propagated;
- document any known limitation around multiple mesh-ID bans if unresolved.

Update `docs/THREAT_INTEL.md` only if unban propagation semantics affect threat-intel/blocklist behavior.

Update `AGENTS.md` only if a durable implementation rule is added, such as:

- manual unban responses must reflect actual state mutation;
- no admin unban path may report success without removing state or explicitly documenting no-op behavior.

## Verification Commands

Run focused checks:

```bash
cargo test --test manual_enforcement_provenance_guard
cargo test --lib mesh_admin
cargo test --lib manual_enforcement
cargo test --lib block_store
cargo test --lib --no-run
```

If handler tests live elsewhere, use the appropriate filters.

Also rerun existing provenance/boundary checks if practical:

```bash
cargo test -p synvoid-block-store provenance
cargo test --test threat_intel_boundary_guard
```

If GitHub CI status is unavailable, document the local commands run.

## Acceptance Criteria

This pass is complete when:

1. Mesh-ID unban no longer reports success without removing state.
2. Mesh-ID ban/unban share a clear helper for sentinel IP and reason encoding.
3. IP unban and mesh-ID unban responses accurately distinguish removed vs missing entries.
4. Unban propagation semantics are audited and documented.
5. If unblock propagation already exists, successful admin unban uses it.
6. Tests cover mesh-ID unban success and missing-entry behavior.
7. Manual enforcement architecture docs no longer list mesh-ID unban as an unresolved no-op.
8. No broad storage/schema redesign is introduced unless strictly necessary.

## Notes for the Implementer

This is a focused correctness fix. The central invariant is:

> Manual enforcement APIs must not claim success unless they actually mutate enforcement state or clearly report that no matching state existed.

Treat the sentinel mesh-ID representation carefully. If it cannot support multiple concurrent mesh-ID bans, document that honestly and avoid pretending this pass solved a larger modeling problem.
