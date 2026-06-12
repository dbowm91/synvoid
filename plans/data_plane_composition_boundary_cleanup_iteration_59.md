# Data-Plane Composition Boundary Cleanup — Iteration 59

## Purpose

Iteration 58 moved concrete `BlockStore` ownership upward from WAF/ASN request-path structs into `UnifiedServer`, added an architecture doc, and introduced `tests/data_plane_composition_boundary_guard.rs`.

The remaining cleanup is to make the boundary sharper and less dependent on broad directory allowlists. Some composition-root directories are currently fully exempt, including `src/worker/unified_server/**`, even though parts of that tree may contain request dispatch or request-path-sensitive code. There is also a remaining request-path-facing `ThreatIntelligenceManager` signature in `WafCore::check_dht_threat_lookup`, currently a no-op placeholder.

This pass should tighten the guardrail and finish the capability boundary decision for WAF-local blocklist/threat-intel hooks.

## Current Known State

Iteration 58 established:

- `WafCoreConfig` no longer carries `block_store`.
- `WafCore` no longer stores concrete `BlockStore`.
- `AsnTracker` no longer stores concrete `BlockStore`.
- `UnifiedServer` owns `block_store: Option<Arc<BlockStore>>` and exposes `with_block_store()` / `get_block_store()`.
- WAF block-store methods became no-ops because the old concrete field was reportedly always `None` in production.
- `architecture/worker_data_plane_composition_root.md` defines ownership direction.
- `tests/data_plane_composition_boundary_guard.rs` scans request-path directories for concrete infra tokens.

Known cleanup targets:

1. Replace broad allowlists with file/function-level or role-specific allowlists.
2. Address `WafCore::check_dht_threat_lookup(... ThreatIntelligenceManager ...)` request-path signature.
3. Decide whether WAF local blocklist reads should remain no-op or use a narrow capability trait.
4. Strengthen guardrail tokens to catch imports/types, not only constructors.

## Non-Goals

Do not redesign blocklist convergence.

Do not change threat-intel actionability semantics.

Do not add request-path mesh/DHT/Raft lookups.

Do not add request-path mesh-ID enforcement.

Do not route request path through remote control-plane systems.

Do not introduce broad global singletons.

Do not reintroduce concrete `BlockStore` into `WafCore` or `AsnTracker`.

## Phase 1 — Split Broad Allowlists Into Roles

Refactor `tests/data_plane_composition_boundary_guard.rs` allowlisting.

Current broad allowlist includes:

- `src/worker/unified_server/`
- `src/server/mod.rs`
- `src/worker/connection.rs`
- `src/worker/cpu_task/`
- `src/tls/`

Replace this with role-specific classification:

```rust
enum BoundaryRole {
    CompositionRoot,
    RequestPath,
    ControlPlane,
    Admin,
    SharedTypes,
    TestOnly,
}
```

Add explicit path classification helpers:

```rust
fn classify_path(path: &Path) -> BoundaryRole
```

For `src/worker/unified_server/**`, classify individual files rather than the whole directory.

Suggested initial classification:

### CompositionRoot

- `src/worker/unified_server/mod.rs`
- `src/worker/unified_server/init_mesh.rs`
- `src/worker/unified_server/init_waf.rs`
- `src/worker/unified_server/init_apps.rs`
- `src/worker/unified_server/services.rs`
- `src/worker/unified_server/lifecycle.rs` if it only runs IPC/control-loop code
- `src/worker/unified_server/state.rs` if it only owns state/bootstrap
- `src/server/mod.rs`
- `src/main.rs`
- `src/supervisor/**`
- `src/admin/**`

### RequestPath

Any request dispatch/handler/postlude files under:

- `src/worker/unified_server/**` that process live request traffic;
- `src/http/**`;
- `src/waf/**`;
- `src/proxy/**`;
- `src/http3/**`;
- `crates/synvoid-http/**`;
- `crates/synvoid-waf/**`;
- `crates/synvoid-proxy/**`;
- `crates/synvoid-http3/**`;
- `crates/synvoid-http-client/**`.

Do not guess silently. Audit file names and imports, then classify.

## Phase 2 — Broaden Forbidden Token Coverage

The current guardrail catches construction/control operations but can miss type-level dependencies.

Add token groups:

### Construction/Ownership Tokens

- `BlockStore::new`
- `ThreatIntelligenceManager::new`
- `ThreatIntelligenceManager::from_external_config`
- `MeshTransportManager::new`
- `MeshBackendPool::new`
- `DhtRoutingManager::new`
- `RecordStoreManager`
- `RaftAwareClient::new`

### Type/Import Tokens

- `crate::block_store::BlockStore`
- `synvoid_block_store::BlockStore`
- `crate::mesh::threat_intel::ThreatIntelligenceManager`
- `synvoid_mesh::mesh::threat_intel::ThreatIntelligenceManager`
- `crate::mesh::transport::MeshTransportManager`
- `crate::mesh::MeshBackendPool`
- `crate::raft::`
- `openraft::`
- `crate::dht::`
- `RecordStoreManager`

### Control-Plane Operation Tokens

- `export_blocklist_snapshot`
- `apply_blocklist_snapshot`
- `query_blocklist_catchup`
- `apply_blocklist_event`
- `BlocklistSnapshotRequest`
- `BlocklistSnapshotResponse`
- `BlocklistCatchupRequest`
- `BlocklistCatchupResponse`
- `BlocklistEventGossip`
- `lookup_threat_indicator_in_dht`
- `lookup_local_indicator`
- `lookup_local_indicator_by_ip`

Allow exceptions only with file-specific reasons.

## Phase 3 — Replace File Exemptions With Scoped Exceptions

For pass-through concrete types that are intentionally threaded through request dispatch contexts, avoid broad file exemption if possible.

Current documented pass-through examples:

- `MeshTransportManager`
- `MeshBackendPool`
- `MeshConfig`
- `AsyncIpcStream`
- `WorkerId`
- `ServerlessManager`
- `GranianSupervisor`

If these must remain in request dispatch structures, add an explicit exception table:

```rust
struct BoundaryException {
    path_suffix: &'static str,
    token: &'static str,
    reason: &'static str,
}
```

The guardrail failure output should print the reason requirement when no exception exists.

Avoid directory-level exceptions for `crates/synvoid-http/src/**` unless every occurrence is audited and documented.

## Phase 4 — Address `check_dht_threat_lookup` Signature

`WafCore::check_dht_threat_lookup` currently has a request-path-facing signature under `feature = "mesh"`:

```rust
Option<&Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>>
```

It is currently a placeholder/no-op, but the concrete type dependency violates the shape target.

Choose one outcome:

### Outcome A — Remove The Placeholder

If unused, delete `check_dht_threat_lookup` entirely.

Preferred if no call sites exist.

### Outcome B — Trait-Erase It

If call sites exist or future placeholder is useful, replace concrete type with a narrow trait:

```rust
pub trait RequestThreatIntelReader: Send + Sync {
    fn check_request_indicator(&self, ip: IpAddr, site_scope: &str) -> Option<WafDecision>;
}
```

The trait must be local-only and policy-composed; no raw DHT lookup on request path.

### Outcome C — Keep Placeholder But Move To Control-Plane File

If it is not request-path code, move it to a control-plane module and document why.

Acceptance: request-path files must not mention `ThreatIntelligenceManager` concrete type.

## Phase 5 — Decide WAF Blocklist Capability Behavior

Iteration 58 made several WAF methods no-op:

- `check_early`
- `block_ip_for_honeypot`
- `block_ip_with_threat_intel`

This may preserve production behavior if the old `block_store` field was always `None`, but the long-term architecture should be explicit.

Choose one outcome:

### Outcome A — Explicit No-Op Boundary

Keep no-ops, but rename/comment them as compatibility shims.

Document:

- WAF request path does not own blocklist mutation capability.
- Blocklist writes occur via dedicated local/control-plane enforcement paths.
- These methods are retained only for API compatibility.

Add tests asserting no block-store dependency.

### Outcome B — Narrow Local Capability Trait

Introduce a local trait, not concrete block store:

```rust
pub trait WafLocalBlocklist: Send + Sync {
    fn check_ip(&self, ip: IpAddr, site_scope: &str) -> Option<WafDecision>;
    fn block_ip_local(&self, ip: IpAddr, reason: &str, ttl_secs: u64, site_scope: &str) -> bool;
}
```

Then composition root wires `Arc<dyn WafLocalBlocklist>`.

Use only if these paths are intended to enforce local blocklist state.

### Recommended

Prefer **Outcome A** unless a real production call path depends on these WAF methods. If enforcement is needed, implement Outcome B carefully in a separate iteration.

## Phase 6 — Improve Guardrail Assertions

Add tests:

- `request_path_no_concrete_blockstore_types`
- `request_path_no_threat_intelligence_manager_types`
- `request_path_no_mesh_transport_ownership`
- `request_path_no_raft_or_dht_imports`
- `request_path_no_blocklist_snapshot_or_catchup_ops`
- `worker_unified_server_request_dispatch_files_are_not_broadly_allowlisted`
- `boundary_exceptions_have_reasons`
- `simulated_concrete_type_import_is_detected`
- `simulated_pass_through_exception_is_allowed`

The guardrail should catch both:

```rust
use crate::block_store::BlockStore;
```

and:

```rust
fn foo(store: Arc<BlockStore>) {}
```

not only `BlockStore::new()`.

## Phase 7 — Documentation Cleanup

Update:

- `architecture/worker_data_plane_composition_root.md`
- `AGENTS.md`
- `skills/synvoid_mesh.md`
- any HTTP/3/WAF boundary docs if present

Docs should clearly state:

- which `src/worker/unified_server/**` files are composition roots;
- which are request dispatch/request-path sensitive;
- concrete pass-through types and why they are tolerated;
- whether WAF blocklist methods are explicit no-op compatibility shims or narrow-trait backed;
- request path must not mention `ThreatIntelligenceManager` directly.

## Phase 8 — Verification Commands

Run:

```bash
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --test manual_enforcement_provenance_guard
cargo test -p synvoid-waf --lib
cargo test -p synvoid-proxy --lib
cargo test -p synvoid-http --lib
cargo test -p synvoid-http3 --lib
cargo test --lib --no-run
```

If trait signatures or request dispatch contexts change:

```bash
cargo test --workspace --no-run
```

Adjust package names/filters to actual workspace layout.

## Acceptance Criteria

This cleanup is complete when:

1. `src/worker/unified_server/**` is not broadly exempt from request-path boundary checks.
2. Request-path-sensitive files under worker/unified-server are classified and scanned.
3. Guardrail catches concrete type imports/usages, not only constructors.
4. All pass-through concrete type exceptions are file-specific and have documented reasons.
5. Request-path files no longer mention concrete `ThreatIntelligenceManager`.
6. WAF blocklist methods are either documented no-op compatibility shims or backed by a narrow local trait.
7. No concrete `BlockStore` returns to `WafCore` or `AsnTracker`.
8. Existing mesh-ID, threat-intel, provenance, and snapshot/blocklist guardrails still pass.
9. Architecture docs precisely describe composition roots versus request-path files.

## Notes for the Implementer

Iteration 58 fixed the main direction. Iteration 59 should make the guardrail trustworthy enough to prevent future boundary drift.

The invariant remains:

> Composition roots may thread concrete infrastructure through setup/control contexts, but request-path code must not own, construct, or directly depend on control-plane infrastructure.
