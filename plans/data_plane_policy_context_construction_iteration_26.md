# Data-Plane Policy Context Construction — Iteration 26

## Goal

Add a root-side construction path for a populated `ThreatIntelPolicyContext` using already-root-owned canonical/advisory inputs, then pass that context through `DataPlaneServices`.

The current state after Iteration 25:

- `DataPlaneServices` carries `Option<ThreatIntelPolicyContext>`;
- `DataPlaneServicesBuilder::with_threat_intel_policy(...)` exists;
- `DataPlaneServices::apply_threat_intel_policy_context()` wires the optional context into `ThreatIntelligenceManager`;
- the default remains `None`, preserving legacy behavior;
- no proxy/YARA/WASM/routing/WAF/DHT sync/ingestion behavior was migrated.

This pass should determine where concrete root-owned canonical/advisory source handles are already available, build a populated context only when both sides are cleanly available, and keep all consumers behavior-neutral unless a context is explicitly present.

## Core Principle

`DataPlaneServices` can carry and apply a `ThreatIntelPolicyContext`; it should not discover one itself.

The construction site must be root-side and explicit:

```text
canonical trust reader + advisory record source
        ↓
root construction helper
        ↓
ThreatIntelPolicyContext
        ↓
DataPlaneServicesBuilder::with_threat_intel_policy(Some(ctx))
        ↓
DataPlaneServices::apply_threat_intel_policy_context()
```

If either dependency is absent, the root should pass `None` and preserve current legacy behavior.

## Non-Goals

Do not migrate proxy request evaluation.

Do not migrate YARA/WASM/plugin callbacks.

Do not migrate routing policy, bot policy, WAF enforcement, DHT sync, ingestion, Push/Announce ingress, quorum, anti-entropy, or Raft apply behavior.

Do not change threat-intel policy semantics.

Do not remove raw lookup APIs.

Do not create global canonical/advisory state.

Do not make `DataPlaneServices` construct DHT/Raft objects internally.

Do not require a policy context for mesh startup.

Do not add live DHT/Raft/network tests.

## Phase 1 — Inventory Existing Canonical/Advisory Ownership

Find where canonical and advisory source implementations are available or can be cleanly derived.

Run:

```bash
rg "CanonicalTrustReader|SnapshotCanonicalTrustReader|StaticCanonicalTrustReader|CanonicalTrustSnapshot|RecordStoreAdvisorySource|AdvisoryRecordSource|ThreatIntelPolicyContext|RecordStoreManager|get_record_store|DataPlaneServicesBuilder|init_mesh_and_threat_intel" crates src architecture docs AGENTS.md
```

Specifically inspect:

- `crates/synvoid-mesh/src/mesh/canonical.rs`;
- `crates/synvoid-mesh/src/mesh/dht/advisory_source.rs`;
- `src/worker/unified_server/init_mesh.rs`;
- `src/worker/unified_server/mod.rs`;
- `src/worker/unified_server/services.rs`;
- architecture docs that describe canonical/advisory seams.

Classify each dependency source:

1. root-owned and safe to pass;
2. subsystem-owned and not safe to reach into yet;
3. test-only;
4. compatibility/global fallback;
5. unavailable.

### Acceptance Criteria

Do not construct a populated context until both canonical and advisory sources are root-owned or passed explicitly from a root-owned handle.

## Phase 2 — Add A Small Construction Helper

Add a helper at the root/wiring layer, not inside policy consumers.

Candidate location:

- `src/worker/unified_server/services.rs` if dependencies are already present at worker composition time;
- `src/worker/unified_server/init_mesh.rs` if mesh init naturally owns both handles;
- a new small helper module under `src/worker/unified_server/` if keeping services.rs narrow is preferred.

Suggested shape:

```rust
#[cfg(feature = "mesh")]
pub fn build_threat_intel_policy_context(
    canonical: Option<Arc<dyn CanonicalTrustReader>>,
    advisory: Option<Arc<dyn AdvisoryRecordSource>>,
) -> Option<ThreatIntelPolicyContext> {
    Some(ThreatIntelPolicyContext::new(canonical?, advisory?))
}
```

If concrete handles are unavoidable, keep the helper explicit:

```rust
#[cfg(feature = "mesh")]
pub fn build_threat_intel_policy_context_from_sources(
    canonical: Arc<dyn CanonicalTrustReader>,
    advisory: Arc<dyn AdvisoryRecordSource>,
) -> ThreatIntelPolicyContext {
    ThreatIntelPolicyContext::new(canonical, advisory)
}
```

### Rules

- The helper must not query DHT/Raft.
- The helper must not inspect current trust state.
- The helper must not call threat-intel lookup/evaluation methods.
- The helper must not create hidden globals.
- The helper should only package already-constructed trait objects.

### Acceptance Criteria

A root-side helper exists and has no side effects beyond packaging dependencies into `ThreatIntelPolicyContext`.

## Phase 3 — Derive Advisory Source From Explicit Record Store If Safe

If `RecordStoreManager` is already explicit in `DataPlaneServicesBuilder`, consider constructing:

```rust
Arc::new(RecordStoreAdvisorySource::new(record_store.clone()))
```

only if `RecordStoreAdvisorySource` has a clean constructor and no network side effects.

Rules:

- Use the explicit `record_store` handle from mesh init / builder, not global `get_global_record_store()`.
- Do not create or mutate DHT records.
- Do not perform a lookup during construction.
- Keep advisory source optional if no record store exists.

### Acceptance Criteria

Advisory source construction, if added, is explicit, side-effect-free, and uses the root-owned record-store handle.

## Phase 4 — Determine Canonical Source Availability

Identify whether a real canonical reader is available at worker/root construction time.

If a real `SnapshotCanonicalTrustReader` or equivalent root-owned canonical snapshot exists, pass it.

If not available, do **not** fake it with `StaticCanonicalTrustReader` in production code.

Instead:

- keep `threat_intel_policy` as `None` in worker bootstrap;
- document that advisory construction is ready but populated context awaits canonical snapshot ownership;
- add tests using static canonical/advisory sources only in test code.

### Acceptance Criteria

Production code must not pretend canonical trust exists. If no real canonical reader is root-owned, no populated production context is created.

## Phase 5 — Wire Populated Context Only When Both Sides Exist

In worker bootstrap, pass the constructed optional context through the existing builder:

```rust
builder = builder
    .with_mesh_transport(mesh_init.transport_manager)
    .with_threat_intel(mesh_init.threat_intel)
    .with_yara_rules(yara_rules)
    .with_record_store(record_store)
    .with_threat_intel_policy(threat_intel_policy_context);
```

Rules:

- `None` remains valid and expected.
- `apply_threat_intel_policy_context()` remains the only place that applies the context to `ThreatIntelligenceManager`.
- No request path behavior changes unless a real context exists.
- No caller is migrated from raw lookup to composed lookup in this pass.

### Acceptance Criteria

The existing builder/apply flow carries the constructed optional context. No broad consumer changes are made.

## Phase 6 — Tests

Add focused tests for construction behavior.

Required tests:

1. construction helper returns `None` when canonical is missing;
2. construction helper returns `None` when advisory is missing;
3. construction helper returns `Some` when both are present;
4. context constructed by the helper enables `evaluate_indicator_actionability_configured(...)` in an existing manager test;
5. no production helper uses `StaticCanonicalTrustReader` outside tests;
6. no construction path calls DHT/Raft/network operations.

If advisory construction from record store is added:

7. constructing `RecordStoreAdvisorySource` from explicit record store has no lookup side effects;
8. no global record-store accessor is used.

### Acceptance Criteria

Tests prove optional construction and do not require live networking.

## Phase 7 — Documentation

Update `architecture/mesh_trust_domains.md` or add a data-plane composition doc.

Required documentation points:

- `DataPlaneServices` owns optional `ThreatIntelPolicyContext`.
- The new helper packages root-owned canonical/advisory sources only.
- If canonical reader is unavailable, production context remains `None`.
- `RecordStoreAdvisorySource` may be derived from explicit record store only if side-effect-free.
- No proxy/YARA/WASM/routing/WAF/enforcement behavior is migrated.

Suggested text:

```markdown
### Iteration 26 Data-Plane Policy Context Construction

The worker data-plane composition layer now has an explicit helper for constructing `ThreatIntelPolicyContext` from root-owned canonical/advisory source handles. Construction is optional: if either source is missing, the context remains `None`, preserving legacy behavior. Production code does not synthesize canonical trust from static test readers. No proxy, YARA/WASM, routing, WAF enforcement, DHT sync, ingestion, or Raft behavior was migrated.
```

If real canonical source is still unavailable:

```markdown
The advisory side can be derived from an explicit record-store handle, but production policy context remains unset until a real root-owned canonical reader is available.
```

### Acceptance Criteria

Docs describe whether a populated production context is actually created or only prepared.

## Phase 8 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid --features mesh
cargo test -p synvoid data_plane --features mesh
cargo test -p synvoid unified_server --features mesh
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
cargo test -p synvoid-mesh advisory_source --features mesh
cargo test -p synvoid-mesh canonical --features mesh
```

Then adjacent seam checks:

```bash
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh ingress_policy --features mesh
```

Then broad checks if practical:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If package names differ, use actual workspace package names from `cargo metadata`.

## Completion Criteria

This iteration is complete when:

- root-side availability of canonical/advisory sources is documented;
- a side-effect-free construction helper exists;
- populated context is created only when both source handles are present;
- production code does not fake canonical trust;
- `DataPlaneServicesBuilder` receives the optional constructed context;
- `apply_threat_intel_policy_context()` remains the only manager-apply step;
- no broader behavior is migrated;
- tests cover present/missing source behavior;
- docs clearly state whether production context is populated or still deferred.

## Follow-Up Recommendation

If production context remains `None` because canonical reader ownership is not root-visible, the next pass should target canonical snapshot ownership/export into the worker/data-plane composition root.

If production context is successfully populated from real root-owned sources, the next pass should be a design-only plan for fail-open/fail-closed semantics before any proxy/YARA/WASM/routing consumer uses policy-composed threat intel.
