# Worker/Data-Plane Composition Root Ownership Audit — Iteration 58

## Purpose

The blocklist convergence and threat-intel actionability tracks are now mature enough to stop touching unless tests expose defects. The next architectural risk is dependency ownership: concrete infrastructure must be wired at the worker/data-plane composition root, while request-path code should consume narrow traits/capabilities.

This pass audits and tightens the data-plane boundary so request handlers, WAF modules, proxy adapters, and HTTP/3 glue do not import or instantiate mesh/DHT/Raft/admin/concrete block-store internals.

The invariant is:

> Composition roots own concrete infrastructure; request-path modules consume capabilities.

## Current Known State

Recent hardening established:

- Blocklist propagation, catchup, snapshot fallback, provenance, and target-state semantics are coherent.
- Threat-intel consumer actionability is classified and guarded.
- Mesh-ID blocks are control-plane/admin scoped only.
- Request/WAF paths remain local-only.
- HTTP/3/WAF decoupling work previously introduced or targeted narrow boundaries such as `Arc<dyn Http3RequestWaf>`.
- Multiple source-scan guardrails exist for mesh-ID, threat-intel, and provenance boundaries.

The next cleanup is to ensure all these hardened subsystems are wired from the right ownership layer.

## Non-Goals

Do not redesign blocklist semantics.

Do not redesign threat-intel policy composition.

Do not add request-path remote lookups.

Do not add request-path mesh-ID enforcement.

Do not introduce Raft for operational blocklist or threat-intel actions.

Do not rewrite the worker lifecycle wholesale unless necessary.

Do not remove legitimate control-plane/admin capabilities.

Do not collapse traits back into concrete types for convenience.

## Phase 1 — Inventory Composition Roots and Request-Path Modules

Identify files that construct concrete infrastructure versus files that process live request-path traffic.

Likely composition/root files:

- `src/worker/**/lifecycle.rs`
- `src/worker/**/server.rs`
- `src/worker/unified_server/**`
- `src/main.rs`
- worker bootstrap/config modules
- supervisor/worker IPC setup
- mesh transport bootstrap
- HTTP/3 adapter construction

Likely request-path/data-plane files:

- `src/waf/**`
- `src/proxy/**`
- `src/http/**`
- `src/http3/**`
- `src/worker/unified_server/**/request*.rs`
- `crates/synvoid-waf/**`
- `crates/synvoid-proxy/**`
- `crates/synvoid-http3/**`

For each file, classify:

- `CompositionRoot`
- `RequestPath`
- `ControlPlane`
- `Admin`
- `SharedTypes`
- `TestOnly`

Produce or update an architecture doc with this map.

Suggested doc:

```text
architecture/worker_data_plane_composition_root.md
```

## Phase 2 — Define Allowed Dependency Directions

Create a clear dependency rule set.

### Composition Root May Own Concrete Infrastructure

Composition roots may construct/wire:

- concrete `BlockStore`
- concrete `ThreatIntelligenceManager`
- mesh transport / DHT / Raft handles
- IPC manager/client/server handles
- metrics providers
- config objects
- WAF engine implementation
- HTTP/3 adapter implementation
- supervisor/worker synchronization channels

### Request Path Must Consume Narrow Capabilities

Request-path modules should receive only:

- `Arc<dyn RequestWaf>` / `Arc<dyn Http3RequestWaf>` / equivalent trait object
- immutable config snapshots
- local blocklist query capability trait
- local rate-limit/tarpit/bot-detection capability traits
- request context objects populated at the boundary
- telemetry emitter traits

### Request Path Must Not Import Or Own

Request-path modules must not import/use:

- mesh transport concrete types
- DHT record store types
- Raft client/state-machine types
- admin handlers
- threat-intel raw lookup APIs
- concrete `ThreatIntelligenceManager` unless through a narrow trait explicitly designed for request path
- concrete block-store internals/shards
- supervisor IPC manager internals
- snapshot/catchup/gossip APIs

## Phase 3 — Audit Concrete Construction

Search for constructors and concrete type usage outside composition roots.

Search terms:

- `BlockStore::new`
- `ThreatIntelligenceManager::new`
- `MeshTransport::new`
- `Raft`
- `Dht`
- `RecordStore`
- `BlockStoreApi`
- `get_record_store`
- `apply_blocklist_event`
- `export_blocklist_snapshot`
- `apply_blocklist_snapshot`
- `query_blocklist_catchup`
- `lookup_local_indicator`
- `lookup_threat_indicator_in_dht`
- `ThreatIntelPolicyContext`
- `MeshMessage::Blocklist`
- `BlocklistSnapshot`
- `BlocklistCatchup`

For every match, decide:

- Is this composition/control/admin/test code? If yes, document or allowlist.
- Is this request-path code? If yes, replace with narrow trait/capability or move wiring upward.

## Phase 4 — Narrow Request-Path Traits

Where concrete types leak into request-path modules, introduce narrow traits in stable/shared locations.

Possible trait shapes:

```rust
pub trait LocalBlocklistReader: Send + Sync {
    fn is_ip_blocked(&self, ip: &IpAddr, site_scope: &str) -> Option<BlockDecision>;
}
```

```rust
pub trait Http3RequestWaf: Send + Sync {
    async fn evaluate(&self, request: Http3RequestContext<'_>) -> WafDecision;
}
```

```rust
pub trait ThreatIntelActionabilityReader: Send + Sync {
    fn evaluate_request_indicator(&self, indicator: &RequestIndicator) -> ThreatIntelDecision;
}
```

Only add traits where needed. Avoid trait explosion. Prefer existing traits if present.

## Phase 5 — Move Concrete Wiring Upward

For any request-path module currently constructing or owning concrete infrastructure:

1. Move construction to the worker/data-plane composition root.
2. Pass a trait object or capability handle down.
3. Keep ownership/lifetime in the composition root or worker state object.
4. Do not create global singletons unless already established and justified.
5. Preserve existing runtime behavior.

Examples:

- HTTP/3 adapter should receive `Arc<dyn Http3RequestWaf>` or equivalent, not build WAF internals.
- Proxy request handler should receive a local blocklist reader trait, not a concrete block-store shard handle.
- WAF request evaluator should not know about mesh transport or DHT.
- Worker lifecycle may receive concrete mesh/threat-intel/block-store objects and adapt them to request-path traits.

## Phase 6 — Guardrail Tests

Add source-scan tests to prevent boundary regression.

Suggested file:

```text
tests/data_plane_composition_boundary_guard.rs
```

Guardrails:

1. Request-path directories do not import mesh transport concrete types.
2. Request-path directories do not import DHT/record-store concrete types.
3. Request-path directories do not import Raft types.
4. Request-path directories do not import admin handlers.
5. Request-path directories do not call threat-intel raw lookup APIs.
6. Request-path directories do not call blocklist catchup/snapshot/gossip APIs.
7. Request-path directories do not construct concrete `BlockStore` or `ThreatIntelligenceManager`.
8. HTTP/3 adapter depends on a WAF trait boundary, not concrete WAF internals, where applicable.
9. Control-plane/admin/test directories are explicitly allowlisted.

Candidate request-path denylist directories:

```text
src/waf
src/proxy
src/http
src/http3
src/worker/unified_server
crates/synvoid-waf
crates/synvoid-proxy
crates/synvoid-http3
```

Candidate allowed directories:

```text
src/admin
src/supervisor
src/worker/lifecycle
crates/synvoid-mesh
crates/synvoid-core
crates/synvoid-block-store
tests
architecture
plans
skills
```

Tune carefully so the guardrail reflects actual repo layout and does not block legitimate shared type imports.

## Phase 7 — Boundary Documentation

Create or update:

- `architecture/worker_data_plane_composition_root.md`
- `architecture/data_plane_boundaries.md` if present
- `architecture/http3_waf_boundary.md` if present
- `AGENTS.md`
- `skills/synvoid_mesh.md` or relevant skill docs

Docs should state:

- concrete ownership belongs to composition/control-plane roots;
- request-path modules consume capabilities only;
- request-path remains local-only;
- mesh/DHT/Raft/snapshot/catchup are control-plane only;
- admin/manual paths are separate from request-path enforcement;
- how to add a new capability safely.

## Phase 8 — Tests and Compile Checks

Add focused tests and run existing guardrails.

Suggested commands:

```bash
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --test manual_enforcement_provenance_guard
cargo test -p synvoid-block-store snapshot
cargo test -p synvoid-mesh catchup
cargo test -p synvoid-waf --lib
cargo test -p synvoid-proxy --lib
cargo test -p synvoid-http3 --lib
cargo test --lib --no-run
```

If trait signatures or crate boundaries change:

```bash
cargo test --workspace --no-run
```

Adjust filters to actual test names.

## Acceptance Criteria

This pass is complete when:

1. Composition-root and request-path files are inventoried and documented.
2. Concrete infrastructure construction is centralized or explicitly justified in control/admin/test code.
3. Request-path modules no longer construct mesh/threat-intel/block-store concrete infrastructure.
4. Request-path modules do not call mesh/DHT/Raft/snapshot/catchup/gossip APIs.
5. Request-path modules consume narrow traits/capabilities for WAF/blocklist/rate-limit decisions.
6. HTTP/3 adapter boundary uses `Arc<dyn Http3RequestWaf>` or equivalent narrow trait where applicable.
7. New source-scan guardrail prevents forbidden imports/calls in request-path directories.
8. Existing mesh-ID, threat-intel, provenance, and blocklist guardrails still pass.
9. Docs clearly define dependency direction and ownership.
10. Runtime behavior is preserved.

## Notes for the Implementer

This is an architectural shape pass. Avoid changing behavior unless a boundary leak forces it.

The target end-state is simple:

- worker/data-plane root wires concrete systems;
- request path receives local capabilities;
- control-plane systems stay out of live request handlers;
- guardrails prevent accidental backsliding.
