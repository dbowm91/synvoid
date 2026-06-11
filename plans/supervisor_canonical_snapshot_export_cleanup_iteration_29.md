# Supervisor Canonical Snapshot Export Cleanup — Iteration 29

## Goal

Complete or correct the Supervisor-to-worker canonical snapshot export path after Iteration 28.

Iteration 28 successfully added the foundational snapshot model:

- `CanonicalTrustSnapshot` exists as a bounded, serializable data model;
- it implements `CanonicalTrustReader` directly;
- tests cover snapshot reader behavior for global nodes, org keys, revocations, freshness, and threat-intel IDs.

However, the repository documentation currently claims a full export path that is not visible in code:

- `EdgeReplicaManager::canonical_trust_snapshot()`;
- `CanonicalTrustSnapshotUpdate` IPC message;
- worker-side storage in `UnifiedServerWorkerState.canonical_snapshot`;
- live update through `DataPlaneServices::update_threat_intel_policy_context()`.

This pass must either implement those missing pieces or revise docs so they accurately describe Iteration 28 as snapshot-model-only.

## Core Principle

Do not let documentation overstate canonical export status.

The target outcome is one of two explicit choices:

```text
Outcome A: Implement the missing export path.
Outcome B: Correct the docs and create a precise follow-up boundary.
```

Do not leave the repo in a state where docs claim working IPC export but code only contains the snapshot type.

## Non-Goals

Do not move Raft consensus into workers.

Do not let workers mutate canonical state.

Do not migrate proxy request evaluation.

Do not migrate YARA/WASM/plugin callbacks.

Do not migrate routing policy, bot policy, WAF enforcement, DHT sync, ingestion, Push/Announce ingress, quorum, anti-entropy, or Raft apply behavior.

Do not change threat-intel actionability semantics.

Do not remove raw lookup APIs.

Do not use `StaticCanonicalTrustReader` in production.

Do not introduce global canonical readers.

## Phase 1 — Verify Current Code/Docs Mismatch

Run:

```bash
rg "CanonicalTrustSnapshot|CanonicalTrustSnapshotUpdate|canonical_trust_snapshot|canonical_snapshot|update_threat_intel_policy_context|SnapshotCanonicalTrustReader|UnifiedServerWorkerState|process::Message" crates src architecture plans AGENTS.md
```

Confirm:

1. `CanonicalTrustSnapshot` exists and implements `CanonicalTrustReader`.
2. `CanonicalTrustSnapshotUpdate` IPC message either exists or is absent.
3. `EdgeReplicaManager::canonical_trust_snapshot()` either exists or is absent.
4. worker-side canonical snapshot storage either exists or is absent.
5. data-plane live update helper either exists or is absent.
6. architecture docs accurately or inaccurately describe the state.

### Acceptance Criteria

Record the mismatch before implementation. Do not proceed while assuming the export path exists.

## Phase 2 — Choose Outcome A Or B

### Outcome A — Implement Missing Export Path

Choose this only if the required owner and IPC path are straightforward.

Implement:

1. Supervisor/control-plane snapshot extraction.
2. IPC message definition.
3. Supervisor send path.
4. Worker receive/store path.
5. Data-plane context refresh path.
6. Tests.
7. Docs.

### Outcome B — Correct Docs Only

Choose this if implementation would require broader IPC/supervisor refactoring.

Do:

1. Revise architecture docs to say only the snapshot model landed.
2. Remove claims that IPC export and worker storage exist.
3. Add a precise follow-up plan target for IPC export.
4. Preserve current behavior.

### Acceptance Criteria

Exactly one outcome is selected. The repo must not keep false-positive documentation.

## Outcome A Details — Implement Export Path

### Phase A1 — Add Snapshot Extraction To Canonical Owner

Add a real method on the owner that can enumerate canonical state.

Preferred location if available:

```rust
impl EdgeReplicaManager {
    pub fn canonical_trust_snapshot(&self) -> CanonicalTrustSnapshot { ... }
}
```

Rules:

- Snapshot export is read-only.
- No worker code calls Raft directly.
- Do not include private key material or signer secrets.
- Include `generated_at_unix`.
- Use bounded vectors.
- Preserve existing timestamp standards.

If `EdgeReplicaManager` cannot enumerate all required data yet, either add minimal safe enumeration methods or choose Outcome B.

### Phase A2 — Add IPC Message Variant

Add a typed IPC message, likely near threat-intel/blocklist messages:

```rust
CanonicalTrustSnapshotUpdate {
    snapshot: CanonicalTrustSnapshot,
    version: u64,
}
```

or if versioning is not available:

```rust
CanonicalTrustSnapshotUpdate {
    snapshot: CanonicalTrustSnapshot,
}
```

Rules:

- Use typed data, not JSON blobs.
- Ensure imports are feature-gated if `CanonicalTrustSnapshot` lives behind mesh features.
- Avoid breaking non-mesh builds.
- Add serialization tests if there are IPC message roundtrip tests.

### Phase A3 — Supervisor Send Path

Find the point where a unified worker becomes ready, then send the latest canonical snapshot if mesh/control-plane canonical state is available.

Candidate trigger:

- on `UnifiedServerWorkerReady`;
- after worker spawn registration;
- after supervisor canonical state initializes;
- on explicit snapshot refresh event.

Rules:

- Snapshot send must be optional.
- Failure to send should log but not crash workers unless existing IPC policy says otherwise.
- Do not block hot paths.
- Do not expose live Raft handles.

### Phase A4 — Worker Receive / Store Path

Add worker-side optional storage, likely in `UnifiedServerWorkerState`:

```rust
#[cfg(feature = "mesh")]
pub canonical_snapshot: Arc<RwLock<Option<CanonicalTrustSnapshot>>>,
```

or a narrower state holder if consistent with worker state patterns.

On receiving `CanonicalTrustSnapshotUpdate`, store the snapshot and refresh threat-intel policy context if advisory source is available.

### Phase A5 — Data-Plane Context Refresh

Add a helper that rebuilds `ThreatIntelPolicyContext` from:

- latest `CanonicalTrustSnapshot` as `Arc<dyn CanonicalTrustReader>`;
- existing explicit advisory source / record-store-derived source.

Possible helper:

```rust
#[cfg(feature = "mesh")]
pub fn update_threat_intel_policy_context(
    &self,
    canonical: Option<Arc<dyn CanonicalTrustReader>>,
    advisory: Option<Arc<dyn AdvisoryRecordSource>>,
) {
    let ctx = DataPlaneServicesBuilder::build_threat_intel_policy_context(canonical, advisory);
    if let Some(threat_intel) = &self.threat_intel {
        threat_intel.set_policy_context(ctx);
    }
}
```

Rules:

- This helper must not query DHT/Raft.
- It only packages snapshot/advisory handles.
- Missing snapshot/advisory clears or leaves context according to existing policy; document which.

### Phase A6 — Tests

Required tests:

1. snapshot extraction from canonical owner produces expected `CanonicalTrustSnapshot`;
2. IPC message with snapshot serializes/deserializes;
3. worker state stores received snapshot;
4. snapshot can be used as `CanonicalTrustReader`;
5. data-plane context construction returns `Some` with snapshot + advisory;
6. missing snapshot returns `None`;
7. no static canonical reader is used in production paths.

## Outcome B Details — Correct Docs

If implementation is deferred, update docs to say:

```markdown
Iteration 28 added a bounded serializable `CanonicalTrustSnapshot` model and implemented `CanonicalTrustReader` for it. It did not yet add Supervisor extraction, IPC delivery, worker storage, or live data-plane context refresh. Production worker context remains unset until a follow-up implements the export path.
```

Also add a short plan or TODO reference to this file.

### Required Docs To Check

- `architecture/mesh_trust_domains.md`
- `src/worker/unified_server/init_mesh.rs` comments
- `src/worker/unified_server/mod.rs` comments
- `src/worker/unified_server/services.rs` comments
- `skills/synvoid_mesh.md` if it mentions the boundary
- `AGENTS.md` if it mentions the boundary

## Phase 3 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid --features mesh
cargo test -p synvoid ipc --features mesh
cargo test -p synvoid unified_server --features mesh
cargo test -p synvoid data_plane --features mesh
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
```

Then adjacent checks:

```bash
cargo test -p synvoid-mesh advisory_source --features mesh
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

This pass is complete when:

- the code/docs mismatch is resolved;
- either the real IPC export path exists and is tested, or docs truthfully describe snapshot-model-only status;
- production code does not fake canonical trust;
- workers do not own Raft/control-plane state;
- `ThreatIntelPolicyContext` remains optional;
- no proxy/YARA/WASM/routing/WAF/enforcement consumers are migrated;
- focused checks pass or unrelated failures are documented.

## Follow-Up Recommendation

If Outcome A succeeds, the next plan should define snapshot freshness, refresh cadence, and fail-open/fail-closed semantics before any broader consumer uses policy-composed threat intel.

If Outcome B is selected, the next plan should implement the first missing piece only: `EdgeReplicaManager::canonical_trust_snapshot()` plus tests, before touching IPC delivery.
