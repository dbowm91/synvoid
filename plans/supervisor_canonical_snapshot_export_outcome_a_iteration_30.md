# Supervisor Canonical Snapshot Export Outcome A — Iteration 30

## Goal

Implement the full Supervisor-to-worker canonical snapshot export path and correct the current documentation drift.

Current state:

- `CanonicalTrustSnapshot` exists and implements `CanonicalTrustReader`.
- `DataPlaneServices` can carry and apply an optional `ThreatIntelPolicyContext`.
- Worker bootstrap can derive an advisory source from the explicit record-store handle.
- Docs currently claim IPC export, worker storage, and live refresh exist, but those symbols are not visible in code.

This pass chooses **Outcome A**: implement the missing export path rather than merely correcting docs.

## Target Architecture

```text
Supervisor / canonical owner
        ↓
EdgeReplicaManager::canonical_trust_snapshot()
        ↓
Message::CanonicalTrustSnapshotUpdate { snapshot, version }
        ↓
worker IPC receive path
        ↓
UnifiedServerWorkerState canonical snapshot storage
        ↓
DataPlaneServices::update_threat_intel_policy_context(...)
        ↓
ThreatIntelligenceManager::set_policy_context(Some(ctx))
```

Workers receive bounded canonical snapshots. They do not own Raft, SQLite control-plane state, or `EdgeReplicaManager`.

## Non-Goals

Do not migrate proxy request evaluation.

Do not migrate YARA/WASM/plugin callbacks.

Do not migrate routing policy, bot policy, WAF enforcement, DHT sync, ingestion, Push/Announce ingress, quorum, anti-entropy, or Raft apply behavior.

Do not change threat-intel actionability semantics.

Do not remove raw lookup APIs.

Do not move Raft consensus into workers.

Do not give workers mutable canonical state.

Do not use `StaticCanonicalTrustReader` in production.

Do not introduce global canonical readers.

## Phase 1 — Verify Baseline And Locate Real Hooks

Run:

```bash
rg "CanonicalTrustSnapshot|CanonicalTrustSnapshotUpdate|canonical_trust_snapshot|UnifiedServerWorkerReady|UnifiedServerWorkerState|DataPlaneServices|update_threat_intel_policy_context|ThreatIntelPolicyContext|EdgeReplicaManager|canonical_snapshot" src crates/synvoid-mesh architecture AGENTS.md
```

Confirm baseline:

1. `CanonicalTrustSnapshot` exists.
2. `CanonicalTrustSnapshotUpdate` is absent.
3. `EdgeReplicaManager::canonical_trust_snapshot()` is absent.
4. worker-side canonical snapshot storage is absent.
5. docs currently overstate export status.

Then locate hooks:

- IPC message enum in `src/process/ipc.rs`;
- supervisor send path for `UnifiedServerWorkerReady` in process manager/supervisor code;
- worker receive path for IPC messages;
- `UnifiedServerWorkerState` definition;
- `DataPlaneServices` construction and storage/lifetime;
- `EdgeReplicaManager` canonical data accessors.

### Acceptance Criteria

Before edits, identify the exact supervisor send hook and exact worker receive/store hook.

## Phase 2 — Add Snapshot Extraction On EdgeReplicaManager

Add a method on `EdgeReplicaManager` or a thin canonical-export adapter owned by the control-plane side:

```rust
pub fn canonical_trust_snapshot(&self) -> CanonicalTrustSnapshot {
    CanonicalTrustSnapshot {
        generated_at_unix: synvoid_utils::safe_unix_timestamp(),
        authorized_global_nodes: self.list_authorized_global_nodes_for_snapshot(),
        org_key_entries: self.list_org_key_entries_for_snapshot(),
        revoked_node_ids: self.list_revoked_node_ids_for_snapshot(),
        threat_intel_ids: self.list_threat_intel_ids_for_snapshot(),
    }
}
```

If direct list methods do not exist, add narrow read-only enumeration methods for snapshot export.

Rules:

- No mutation.
- No worker dependency.
- No private key material.
- No signer secrets.
- Snapshot fields must remain bounded to canonical trust data only.
- Do not change existing canonical reader semantics.

### Acceptance Criteria

`EdgeReplicaManager` or a canonical export adapter can produce a populated `CanonicalTrustSnapshot` from controlled state.

## Phase 3 — Add IPC Message Variant

Add a typed IPC message variant to `src/process/ipc.rs` near threat-intel or unified-worker messages.

Preferred:

```rust
#[cfg(feature = "mesh")]
CanonicalTrustSnapshotUpdate {
    snapshot: synvoid_mesh::canonical::CanonicalTrustSnapshot,
    version: u64,
}
```

If feature-gating enum variants creates serialization/build issues, use an always-present internal DTO in the main crate that mirrors the snapshot shape and converts into `CanonicalTrustSnapshot` behind `mesh`.

Rules:

- Preserve non-mesh builds.
- Preserve existing serialization style.
- Add roundtrip test if IPC tests exist.
- Do not use raw JSON blobs.

### Acceptance Criteria

IPC can serialize/deserialize the canonical snapshot update message in mesh builds without breaking non-mesh builds.

## Phase 4 — Supervisor Send Path

Find where the supervisor handles unified worker readiness, likely `UnifiedServerWorkerReady` or worker registration.

On readiness:

1. If Supervisor has canonical snapshot provider, produce snapshot.
2. Send `CanonicalTrustSnapshotUpdate` to the worker.
3. Log send failures, do not crash unless existing IPC policy requires it.

Suggested helper:

```rust
fn send_canonical_snapshot_to_worker(&self, worker_id: WorkerId) -> Result<()> {
    let Some(snapshot_provider) = self.canonical_snapshot_provider() else {
        return Ok(());
    };
    let snapshot = snapshot_provider.canonical_trust_snapshot();
    self.send_to_worker(worker_id, Message::CanonicalTrustSnapshotUpdate { snapshot, version })
}
```

Rules:

- Snapshot send is optional.
- Do not block hot request paths.
- Do not send live references.
- Do not require Supervisor to have mesh enabled in non-mesh builds.

### Acceptance Criteria

Worker-ready path sends snapshot when available and safely no-ops when unavailable.

## Phase 5 — Worker Receive And Store Path

Add worker-side optional storage. Prefer the existing worker state type if it already persists worker services.

Candidate:

```rust
#[cfg(feature = "mesh")]
pub canonical_snapshot: Arc<RwLock<Option<CanonicalTrustSnapshot>>>,
```

On receiving `Message::CanonicalTrustSnapshotUpdate { snapshot, .. }`:

1. Store snapshot.
2. If `DataPlaneServices` is available, rebuild policy context using snapshot + advisory source.
3. Apply to `ThreatIntelligenceManager` through existing `set_policy_context` path.

### Acceptance Criteria

Workers can receive and store snapshots without owning Raft/control-plane state.

## Phase 6 — DataPlaneServices Live Update Helper

Add a helper that uses an incoming snapshot reader and the existing explicit advisory source to refresh the manager policy context.

Candidate:

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

Worker receive path can construct:

```rust
let canonical: Arc<dyn CanonicalTrustReader> = Arc::new(snapshot.clone());
```

Rules:

- Helper does not query DHT/Raft.
- Helper does not call lookup/evaluation methods.
- Missing canonical/advisory should clear context or leave it unset; document behavior.
- Keep `apply_threat_intel_policy_context()` for startup/static context.

### Acceptance Criteria

Data-plane policy context can be refreshed from received snapshots without changing consumers.

## Phase 7 — Startup Snapshot Use If Available

If worker state may already contain a snapshot before `DataPlaneServices` build, thread it into:

```rust
DataPlaneServicesBuilder::build_threat_intel_policy_context(canonical_reader, advisory_source)
```

If snapshot only arrives after worker ready, rely on live update path and document this.

Rules:

- No `StaticCanonicalTrustReader` in production.
- No request path migration.
- No boot failure if snapshot is missing.

### Acceptance Criteria

Startup or post-ready refresh path is explicit and optional.

## Phase 8 — Tests

Add focused tests. Required coverage:

1. `EdgeReplicaManager::canonical_trust_snapshot()` produces expected snapshot from controlled test data.
2. `CanonicalTrustSnapshotUpdate` serializes/deserializes through the IPC message format.
3. worker receive path stores a snapshot.
4. snapshot-as-reader can produce trusted/not-trusted decisions.
5. `DataPlaneServices::update_threat_intel_policy_context(...)` applies a populated context when snapshot + advisory are present.
6. missing snapshot/advisory leaves context unset or clears it according to documented behavior.
7. non-mesh build is not broken by the IPC variant/imports.
8. production code does not import/use `StaticCanonicalTrustReader` outside tests.

Use unit tests and narrow integration tests; do not require live network or real Raft cluster.

## Phase 9 — Fix Documentation Drift

Update all affected docs to match actual code.

Required docs:

- `architecture/mesh_trust_domains.md`;
- `src/worker/unified_server/init_mesh.rs` comments;
- `src/worker/unified_server/mod.rs` comments;
- `src/worker/unified_server/services.rs` comments;
- `AGENTS.md` or `skills/synvoid_mesh.md` if they mention this boundary.

Docs must state:

- `CanonicalTrustSnapshot` is exported by Supervisor/control plane through actual IPC path;
- workers store snapshots read-only;
- workers do not own Raft or mutate canonical state;
- `ThreatIntelPolicyContext` remains optional;
- no proxy/YARA/WASM/routing/WAF consumer migration happened.

If any part remains deferred, state it explicitly. Do not claim completion for missing code.

## Phase 10 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid --features mesh
cargo test -p synvoid ipc --features mesh
cargo test -p synvoid process --features mesh
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

- `EdgeReplicaManager` or the canonical owner exports a real `CanonicalTrustSnapshot`;
- IPC has a typed canonical snapshot update message or equivalent typed DTO;
- Supervisor sends snapshots to ready workers when available;
- workers receive/store snapshots read-only;
- `DataPlaneServices` can refresh threat-intel policy context from snapshot + advisory source;
- behavior remains unchanged for proxy/YARA/WASM/routing/WAF/enforcement consumers;
- documentation matches actual code;
- focused tests pass or unrelated failures are documented.

## Follow-Up Recommendation

After this pass, create a design-only plan for canonical snapshot freshness policy:

- stale threshold;
- fail-open/fail-closed behavior;
- refresh cadence;
- metrics/logging;
- how request/security consumers should behave when canonical snapshot is absent or stale.
