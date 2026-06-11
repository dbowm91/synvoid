# Canonical Reader Export Into Data-Plane Composition — Iteration 27

## Goal

Export a real root-owned canonical trust reader into the worker/data-plane composition root so `ThreatIntelPolicyContext` can be populated from real canonical + advisory handles instead of remaining `None` in production worker bootstrap.

The current state after Iteration 26:

- `DataPlaneServices` carries `Option<ThreatIntelPolicyContext>`;
- `DataPlaneServicesBuilder::build_threat_intel_policy_context(...)` packages optional canonical/advisory trait objects;
- worker bootstrap derives an advisory source from the explicit record-store handle;
- worker bootstrap passes `None` for canonical because no root-owned canonical reader is visible there yet;
- production behavior remains legacy/raw because no populated context is created.

This pass should make canonical ownership/export explicit. It should not migrate request consumers.

## Core Principle

Canonical trust is authority state. It must be exported from the authoritative mesh/canonical owner, not synthesized in worker bootstrap.

The desired flow is:

```text
Raft / canonical state owner
        ↓
root-owned CanonicalTrustReader trait object
        ↓
worker/data-plane composition root
        ↓
DataPlaneServicesBuilder::build_threat_intel_policy_context(Some(canonical), advisory)
        ↓
DataPlaneServices::apply_threat_intel_policy_context()
```

If the canonical owner cannot provide a real reader yet, keep production context as `None` and document the exact missing ownership boundary.

## Non-Goals

Do not fake canonical trust with `StaticCanonicalTrustReader` in production.

Do not migrate proxy request evaluation.

Do not migrate YARA/WASM/plugin callbacks.

Do not migrate routing policy, bot policy, WAF enforcement, DHT sync, ingestion, Push/Announce ingress, quorum, anti-entropy, or Raft apply behavior.

Do not change `ThreatIntelPolicyDecision`, `CanonicalTrustReader`, `AdvisoryRecordSource`, or threat-intel actionability semantics.

Do not remove raw lookup APIs.

Do not introduce canonical globals or service locators.

Do not make `DataPlaneServices` query Raft or build canonical state internally.

Do not add live network tests.

## Phase 1 — Inventory Canonical Ownership

Find all current canonical reader/state ownership points.

Run:

```bash
rg "CanonicalTrustReader|CanonicalTrustSnapshot|SnapshotCanonicalTrustReader|StaticCanonicalTrustReader|canonical_reader|canonical trust|trusted_intel|threat_intel_ids|AuthorizedGlobalNodes|Revocation|Raft|state_machine|Consensus|init_mesh_and_threat_intel|MeshInit" crates/synvoid-mesh src architecture AGENTS.md
```

Inspect at minimum:

- `crates/synvoid-mesh/src/mesh/canonical.rs`;
- `crates/synvoid-mesh/src/mesh/raft/state_machine.rs`;
- `crates/synvoid-mesh/src/mesh/raft/consensus.rs`;
- `crates/synvoid-mesh/src/mesh/peer_auth.rs`;
- `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`;
- `src/worker/unified_server/init_mesh.rs`;
- `src/worker/unified_server/mod.rs`;
- `src/worker/unified_server/services.rs`.

Classify each canonical source as:

1. real authoritative/root-owned;
2. snapshot reader derived from authoritative state;
3. local/test-only static reader;
4. consumer-local temporary reader;
5. unavailable to worker root.

### Acceptance Criteria

Do not edit wiring until you know where canonical authority is actually owned.

## Phase 2 — Add Or Expose A Canonical Reader Handle In Mesh Init Output

If `init_mesh_and_threat_intel(...)` or its return type already owns canonical state, extend its output with:

```rust
#[cfg(feature = "mesh")]
pub canonical_reader: Option<Arc<dyn CanonicalTrustReader>>,
```

If canonical state is available only as a snapshot, export a `SnapshotCanonicalTrustReader` constructed by the canonical/mesh owner, not by worker bootstrap.

If canonical state is not available yet, add no production reader and instead document the missing boundary.

### Rules

- The mesh/canonical owner may construct a `SnapshotCanonicalTrustReader` if it owns the snapshot.
- Worker bootstrap may receive/pass the trait object, but must not synthesize canonical trust.
- Do not use `StaticCanonicalTrustReader` in production code.
- Do not create a global canonical reader.
- Do not make consumers depend on concrete reader types.

### Acceptance Criteria

Either a real optional `Arc<dyn CanonicalTrustReader>` is available from mesh init output, or the pass documents why it is not yet possible.

## Phase 3 — Thread Canonical Reader Through Worker Bootstrap

If a canonical reader is available from mesh init, thread it into the existing construction helper:

```rust
let canonical_reader = mesh_init.canonical_reader.clone();
let threat_intel_policy_context =
    services::DataPlaneServicesBuilder::build_threat_intel_policy_context(
        canonical_reader,
        advisory_source,
    );

builder = builder
    .with_mesh_transport(mesh_init.transport_manager)
    .with_threat_intel(mesh_init.threat_intel)
    .with_yara_rules(yara_rules)
    .with_record_store(record_store)
    .with_threat_intel_policy(threat_intel_policy_context);
```

If canonical reader is unavailable, leave the existing `None` and document it.

### Rules

- The builder remains optional; missing canonical still returns `None`.
- `apply_threat_intel_policy_context()` remains the only manager-apply step.
- Do not call threat-intel lookup methods from bootstrap.
- Do not change request path behavior.

### Acceptance Criteria

Worker bootstrap either carries a real canonical reader into context construction or explicitly keeps `None` with documented rationale.

## Phase 4 — Add Tests For Canonical Export / Absence

If canonical reader is exported:

1. test mesh init output can carry `Some(Arc<dyn CanonicalTrustReader>)`;
2. test worker construction helper returns `Some` when canonical + advisory are both present;
3. test applying populated context enables configured actionability;
4. test missing canonical still returns `None`;
5. test no production code imports/uses `StaticCanonicalTrustReader` outside `#[cfg(test)]`.

If canonical reader is not exported:

1. test construction remains `None` when canonical is absent;
2. add documentation test/comment proving worker bootstrap deliberately passes `None`;
3. add a follow-up TODO or plan reference naming the canonical owner that must be exposed later.

### Acceptance Criteria

Tests cover the selected path without live networking.

## Phase 5 — Documentation

Update `architecture/mesh_trust_domains.md` and, if useful, `architecture/data_plane_composition.md`.

If canonical reader is exported, use language like:

```markdown
### Iteration 27 Canonical Reader Export

The mesh/canonical owner now exports an optional `Arc<dyn CanonicalTrustReader>` to worker/data-plane composition. Worker bootstrap passes this reader, together with the advisory source derived from the explicit record-store handle, into `DataPlaneServicesBuilder::build_threat_intel_policy_context(...)`. The context remains optional and no request consumers were migrated.
```

If canonical reader is not exported, use language like:

```markdown
### Iteration 27 Canonical Reader Ownership Assessment

The data-plane composition root is ready to carry a populated `ThreatIntelPolicyContext`, and advisory construction is available from the explicit record-store handle. A real root-owned canonical reader is not yet exported to worker bootstrap, so production context remains `None`. The next step is to expose canonical snapshots from the mesh/canonical owner without introducing globals or test-only static readers.
```

Also update `AGENTS.md` or worker `AGENTS.override.md` if they summarize `DataPlaneServices` ownership facts.

### Acceptance Criteria

Docs clearly state whether production context is populated after this pass or still deferred.

## Phase 6 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid --features mesh
cargo test -p synvoid data_plane --features mesh
cargo test -p synvoid unified_server --features mesh
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
cargo test -p synvoid-mesh advisory_source --features mesh
```

Then adjacent checks:

```bash
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh ingress_policy --features mesh
```

Then broad checks if practical:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If package names differ, use actual names from `cargo metadata`.

## Completion Criteria

This iteration is complete when:

- canonical ownership has been inventoried;
- production code does not synthesize canonical trust;
- either a real `Arc<dyn CanonicalTrustReader>` is exported to worker composition, or the missing boundary is explicitly documented;
- worker bootstrap passes the real canonical reader into context construction when available;
- advisory source still comes from explicit record-store handle only;
- `ThreatIntelPolicyContext` remains optional;
- no proxy/YARA/WASM/routing/WAF/enforcement consumer is migrated;
- tests cover exported or absent canonical behavior;
- docs state the exact result.

## Follow-Up Recommendation

If canonical reader export succeeds and production `ThreatIntelPolicyContext` becomes populated, the next plan should be design-only fail-open/fail-closed semantics before any proxy/YARA/WASM/routing consumer is migrated.

If canonical reader export is still blocked, the next plan should target the canonical state owner directly: expose a snapshot/reader from the Raft/canonical subsystem without introducing globals.
