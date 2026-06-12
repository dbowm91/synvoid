# Mesh-ID Request-Path Enforcement Boundary — Iteration 51

## Purpose

The blocklist consistency and provenance tracks are now in good shape. The remaining architectural ambiguity is mesh-ID enforcement scope.

Today, mesh-ID blocks are first-class in BlockStore, admin, mesh propagation, event replay, and observability, but docs still describe mesh-ID blocks as control-plane/admin scoped because request/WAF contexts do not reliably carry a mesh ID. This pass should make a deliberate decision:

1. **Outcome A — Formalize control-plane-only semantics** and harden docs/guards so mesh-ID blocks are never implied to affect request routing; or
2. **Outcome B — Wire mesh ID into request context and WAF evaluation** with strict local-only enforcement and no mesh/DHT/Raft request-path lookup.

The preferred investigation is to determine whether a reliable request-time mesh identity exists. If yes, implement Outcome B. If not, implement Outcome A and leave a future integration point.

## Current Known State

- `BlockTargetKind::MeshId` exists.
- `MeshBlockEntry` exists and persists separately from IP blocks.
- Admin can ban/unban mesh IDs.
- Mesh-wide blocklist events support `target_kind=MeshId`.
- `BlockStore::is_mesh_id_blocked()` exists.
- Mesh-ID blocks are synchronized/replayed/provenance-preserved.
- Docs currently say mesh-ID blocks are not WAF request-path enforced because request context does not carry mesh ID.
- Remaining known gap: if mesh-ID blocking should affect request routing, `mesh_id` must be added to request context and wired through the WAF pipeline.

## Non-Goals

Do not perform mesh/DHT/Raft lookups on the request path.

Do not infer mesh ID from untrusted HTTP headers.

Do not weaken existing IP block behavior.

Do not change blocklist propagation semantics.

Do not redesign threat-intel policy gates.

Do not make mesh-ID enforcement depend on remote availability.

Do not add user-visible claims that mesh-ID blocks affect requests unless the path is actually implemented and tested.

## Phase 1 — Inventory Request Identity Sources

Audit whether request-time mesh identity exists today.

Search terms:

- `RequestContext`
- `mesh_id`
- `peer_id`
- `node_id`
- `client_id`
- `identity`
- `mtls`
- `certificate`
- `subject`
- `principal`
- `mesh peer`
- `waf_context`
- `RequestWaf`
- `Http3RequestWaf`
- `check_request`
- `BlockStore`
- `is_mesh_id_blocked`

Likely files:

- `crates/synvoid-core/**`
- `crates/synvoid-waf/**`
- `src/waf/**`
- `src/worker/unified_server/**`
- `src/worker/unified_server/lifecycle.rs`
- `src/worker/unified_server/services.rs`
- `src/http3/**`
- `crates/synvoid-mesh/**`
- `architecture/http3_request_waf_boundary.md`
- `architecture/blockstore_admin_observability.md`
- `architecture/manual_enforcement_ownership.md`

Classify possible identity sources:

- cryptographically authenticated mesh peer identity;
- supervisor-provided worker connection identity;
- mTLS client certificate subject;
- internal mesh transport peer ID;
- untrusted HTTP header or user-controlled field.

Only cryptographically authenticated or supervisor/root-composed identities are acceptable for request enforcement.

## Phase 2 — Decide Outcome A or B

### Outcome A — Control-plane-only hardening

Choose this if there is no reliable request-time mesh identity.

Actions:

- Keep `MeshBlockEntry` and mesh-ID admin operations.
- Keep mesh-ID blocklist propagation/replay.
- Explicitly document mesh-ID blocks as admin/control-plane/mesh-operation scoped only.
- Add guardrails preventing `is_mesh_id_blocked()` from being called in WAF/request-path code without an authenticated context.
- Rename UI wording if it overclaims request blocking.
- Add tests/docs proving request path does not claim mesh-ID enforcement.

### Outcome B — Request-path enforcement

Choose this only if request context can receive trusted mesh identity without request-path remote lookups.

Actions:

- Add `mesh_id: Option<MeshId>` or equivalent to request context.
- Populate it only at trusted composition roots.
- Thread it through WAF evaluation.
- Check `BlockStore::is_mesh_id_blocked(mesh_id, site_scope)` locally.
- Define precedence against IP blocks and other WAF actions.
- Add tests for blocked mesh ID, unblocked mesh ID, absent mesh ID, and spoofed/untrusted headers.

Recommended decision rule:

- If mesh identity is available from authenticated mesh/transport/session state: Outcome B.
- If identity would come from HTTP headers or request payload: Outcome A.

## Phase 3A — Outcome A Implementation: Formalize Control-Plane Scope

If choosing Outcome A, update docs and guardrails.

Docs to update:

- `architecture/blockstore_admin_observability.md`
- `architecture/manual_enforcement_ownership.md`
- `architecture/blocklist_remove_consistency.md`
- `architecture/blocklist_reconciliation.md`
- `architecture/blocklist_provenance_preservation.md`
- `architecture/http3_request_waf_boundary.md`
- `AGENTS.md`

Required language:

- Mesh-ID blocks are first-class blocklist records.
- Mesh-ID blocks affect admin/control-plane/mesh operations where mesh ID is available.
- Mesh-ID blocks do not affect HTTP/WAF request decisions unless a trusted request context mesh ID is wired.
- Do not infer mesh ID from untrusted HTTP headers.
- Request path remains IP/header/body/protocol based until Outcome B is implemented.

Guardrail options:

- source-scan test preventing request/WAF modules from calling `is_mesh_id_blocked()`;
- exception allowed only in a specific trusted request-context integration module;
- test ensuring docs do not claim mesh-ID HTTP blocking.

## Phase 3B — Outcome B Implementation: Add Request Context Mesh Identity

If choosing Outcome B, add a trusted field to request context.

Suggested type:

```rust
pub struct RequestContext {
    ...
    pub mesh_id: Option<String>,
}
```

or stronger:

```rust
pub struct AuthenticatedMeshIdentity {
    pub mesh_id: String,
    pub source: MeshIdentitySource,
}
```

Recommended stronger model:

```rust
pub enum MeshIdentitySource {
    AuthenticatedMeshPeer,
    SupervisorAssigned,
    MtlsPeerCertificate,
}

pub struct AuthenticatedMeshIdentity {
    pub mesh_id: String,
    pub source: MeshIdentitySource,
}
```

Then request context carries:

```rust
pub mesh_identity: Option<AuthenticatedMeshIdentity>
```

Do not use raw headers or request fields as trusted mesh ID.

## Phase 4B — Trusted Population at Composition Root

Populate mesh identity where connection/session state is available and trusted.

Likely locations:

- worker/data-plane composition root;
- HTTP/3 connection/session adapter;
- mesh transport request adapter;
- supervisor-provided worker context.

Rules:

- identity is attached once at ingress boundary;
- downstream WAF code reads it but does not derive it;
- missing identity means mesh-ID WAF check is skipped;
- spoofed headers are ignored unless explicitly mapped by trusted root logic.

## Phase 5B — Local WAF Enforcement

Add local-only mesh-ID block check to WAF/request evaluation.

Pseudo-flow:

```rust
if let Some(identity) = ctx.mesh_identity.as_ref() {
    if block_store.is_mesh_id_blocked(&identity.mesh_id, &ctx.site_scope) {
        return WafDecision::Block { reason: "mesh_id_blocked", ... };
    }
}
```

Requirements:

- no async/network dependency;
- no DHT/gossip/Raft lookup;
- uses local BlockStore only;
- structured log includes provenance/target kind if available;
- metrics separate mesh-ID blocks from IP blocks.

Define precedence:

- If IP block and mesh-ID block both match, either IP-first or mesh-ID-first is acceptable, but document it.
- Preferred: return the most specific identity block if available; otherwise IP block.
- Do not weaken existing IP block behavior.

## Phase 6 — Tests

### Shared tests

- Admin mesh-ID block records still list correctly.
- Mesh-ID block/unblock propagation still works.
- Provenance remains preserved.

### Outcome A tests

- WAF/request modules do not call `is_mesh_id_blocked()`.
- Docs state control-plane-only semantics.
- Admin response wording does not imply HTTP request enforcement.
- Guardrail blocks untrusted header-based mesh-ID enforcement.

### Outcome B tests

- request with trusted blocked mesh identity is blocked.
- request with trusted unblocked mesh identity proceeds to normal WAF checks.
- request without mesh identity does not perform mesh-ID check.
- spoofed `X-Mesh-Id` or equivalent header does not trigger identity enforcement.
- site-scoped mesh-ID block only affects matching site scope.
- global mesh-ID fallback works if existing semantics support it.
- IP block behavior remains unchanged.
- no request-path async/mesh lookup occurs.

## Phase 7 — Observability

If Outcome B is implemented, add logs/metrics:

- mesh-ID WAF block count;
- target kind `mesh_id`;
- site scope;
- identity source;
- provenance from `MeshBlockEntry` if available;
- decision reason `mesh_id_blocked`.

If Outcome A is implemented, add diagnostics that make scope clear:

- admin list shows mesh-ID blocks as `control_plane_only: true` or docs equivalent;
- optional warning when operators create mesh-ID blocks if not request-enforced.

## Phase 8 — Documentation

Update architecture docs to reflect the chosen outcome.

Docs must answer:

- Are mesh-ID blocks request-path enforced?
- Where does request-time mesh identity come from?
- Is the identity cryptographically trusted?
- What happens when identity is absent?
- Does enforcement require network lookup? It must not.
- What is the precedence versus IP blocks?
- What remains future work?

## Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-core mesh_id
cargo test -p synvoid-block-store mesh_id
cargo test -p synvoid-waf mesh_id
cargo test --lib waf
cargo test --lib worker
cargo test --lib mesh_admin
cargo test --test manual_enforcement_provenance_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
```

If HTTP/3 request context changes:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This pass is complete when one of the following is true:

### Outcome A complete

1. Mesh-ID blocks are explicitly documented as control-plane/admin scoped only.
2. Request/WAF docs do not imply mesh-ID request enforcement.
3. Guardrails prevent accidental request-path mesh-ID enforcement from untrusted data.
4. Admin/UI wording is accurate.
5. Existing mesh-ID blocklist consistency/provenance tests still pass.

### Outcome B complete

1. Request context has a trusted mesh identity field.
2. Trusted composition roots populate it without using untrusted request headers.
3. WAF checks local BlockStore for mesh-ID blocks when identity is present.
4. Missing identity skips mesh-ID enforcement safely.
5. No request-path mesh/DHT/Raft lookup is added.
6. Tests cover blocked, unblocked, absent, spoofed, site-scoped, and global fallback cases.
7. Docs define precedence and trust boundaries.
8. Existing IP block behavior is unchanged.

## Notes for the Implementer

This is a boundary-definition pass. The wrong implementation is worse than no implementation.

The invariant is:

> Mesh-ID request enforcement is allowed only if mesh identity is already trusted at the request ingress boundary. Never derive enforcement identity from attacker-controlled request data.
