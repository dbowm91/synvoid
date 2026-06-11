# Supervisor Canonical Snapshot Export — Iteration 28

## Goal

Design and implement the first safe Supervisor-to-worker canonical snapshot export path so worker/data-plane composition can eventually receive a real `Arc<dyn CanonicalTrustReader>` without making workers own Raft or synthesize canonical trust.

Iteration 27 established the key boundary:

- workers are data-plane processes;
- Supervisor owns Raft consensus and `EdgeReplicaManager`;
- worker bootstrap derives advisory source from an explicit record-store handle;
- worker bootstrap still passes `None` for canonical into `build_threat_intel_policy_context(...)`;
- production `ThreatIntelPolicyContext` remains unset until canonical snapshots are exported.

This pass should expose a canonical snapshot from the Supervisor/control-plane side in a controlled, serializable, read-only form. It should not yet migrate proxy/YARA/WASM/routing/WAF consumers.

## Core Principle

Canonical trust should be copied to workers as a bounded snapshot, not shared as a live Raft/control-plane object.

Desired direction:

```text
Supervisor-owned canonical state / EdgeReplicaManager / Raft state machine
        ↓
CanonicalTrustSnapshot export
        ↓
IPC/startup message or explicit worker init payload
        ↓
SnapshotCanonicalTrustReader in worker/data-plane root
        ↓
DataPlaneServicesBuilder::build_threat_intel_policy_context(Some(reader), advisory)
```

Workers consume snapshots. Supervisor remains authoritative.

## Non-Goals

Do not move Raft consensus into workers.

Do not let workers mutate canonical state.

Do not expose live Supervisor internals by reference.

Do not introduce global canonical readers.

Do not use `StaticCanonicalTrustReader` in production.

Do not migrate proxy request evaluation, YARA/WASM/plugin callbacks, routing policy, bot policy, WAF enforcement, DHT sync, ingestion, Push/Announce ingress, quorum, anti-entropy, or Raft apply behavior.

Do not change threat-intel policy actionability semantics.

Do not remove raw lookup APIs.

Do not require live DHT/Raft/network tests for the first pass.

## Phase 1 — Inventory Supervisor / Canonical State Ownership

Find where Supervisor owns or can observe authoritative canonical state.

Run:

```bash
rg "Supervisor|EdgeReplicaManager|CanonicalTrustSnapshot|SnapshotCanonicalTrustReader|CanonicalTrustReader|AuthorizedGlobalNodes|Revocation|Namespace::Org|Namespace::Intel|Namespace::Revocation|state_machine|Raft|Consensus|worker.*ready|UnifiedServerWorkerReady|process::Message|IPC|init_mesh" src crates/synvoid-mesh architecture AGENTS.md
```

Inspect likely areas:

- Supervisor process orchestration and worker startup;
- IPC message definitions;
- Raft state machine namespaces;
- `EdgeReplicaManager` ownership;
- canonical reader/snapshot modules;
- worker initialization payloads;
- current blocklist/intelligence IPC paths.

Classify available data:

1. canonical state already materialized as snapshot;
2. canonical state derivable from Raft state machine;
3. canonical state derivable from `EdgeReplicaManager`;
4. only test/static canonical state exists;
5. no root-visible export point yet.

### Acceptance Criteria

Before implementation, identify the concrete Supervisor-side owner that can produce `CanonicalTrustSnapshot`, or document that this pass must add a snapshot extraction seam first.

## Phase 2 — Define Snapshot Export Boundary

Prefer a narrow export method owned by the canonical/control-plane component.

Candidate shape:

```rust
pub trait CanonicalSnapshotProvider {
    fn canonical_snapshot(&self) -> CanonicalTrustSnapshot;
}
```

or a concrete method on the owner:

```rust
impl EdgeReplicaManager {
    pub fn canonical_trust_snapshot(&self) -> CanonicalTrustSnapshot { ... }
}
```

Rules:

- Snapshot export must be read-only.
- Snapshot export must not mutate Raft/DHT state.
- Snapshot export must include freshness metadata.
- Snapshot export should be cheap enough for startup and occasional refresh.
- Snapshot export should not return live locks/guards to workers.

### Acceptance Criteria

A canonical snapshot export seam exists at the control-plane owner or a documented owner-specific adapter exists.

## Phase 3 — Ensure Snapshot Is Serializable / IPC-Safe

If `CanonicalTrustSnapshot` is already serializable in the IPC format, verify it.

If not, add a transport DTO rather than overloading internal runtime state.

Candidate DTO:

```rust
pub struct CanonicalTrustSnapshotMessage {
    pub generated_at_unix: u64,
    pub freshness: CanonicalFreshness,
    pub authorized_global_nodes: Vec<String>,
    pub revoked_ids: Vec<String>,
    pub trusted_intel_ids: Vec<String>,
}
```

Rules:

- Use stable typed structs, not `serde_json::Value`.
- Preserve existing timestamp standards.
- Avoid sending private key material or signer secrets.
- Keep payload bounded; avoid dumping unrelated Raft state.
- Prefer existing binary/typed IPC conventions if present.

### Acceptance Criteria

The snapshot can cross the Supervisor/worker boundary as typed data, or a clear blocker is documented.

## Phase 4 — Add Worker Receive / Store Path Without Enabling Consumers

Add a worker-side place to receive and store the latest canonical snapshot.

Preferred first implementation:

```rust
pub struct WorkerCanonicalSnapshotState {
    latest: ArcSwap<Option<CanonicalTrustSnapshot>> // or RwLock<Option<_>> if ArcSwap not used
}
```

But keep it simple and consistent with existing worker state patterns.

Alternative: if startup-only payload is easier, pass snapshot into worker init and construct:

```rust
Arc::new(SnapshotCanonicalTrustReader::new(snapshot)) as Arc<dyn CanonicalTrustReader>
```

Rules:

- Worker state stores snapshots, not Raft handles.
- Missing snapshot remains valid.
- Stale snapshot must be represented via `CanonicalFreshness` / timestamp, not silently trusted as live.
- Do not wire this into proxy/YARA/WASM/routing consumers.

### Acceptance Criteria

Worker has a safe optional place to receive canonical snapshot data, but request behavior remains unchanged unless the data-plane root explicitly uses it later.

## Phase 5 — Thread Snapshot Reader Into DataPlaneServices When Available

If worker receives a snapshot by startup/init time, construct:

```rust
let canonical_reader = snapshot.map(|snapshot| {
    Arc::new(SnapshotCanonicalTrustReader::new(snapshot)) as Arc<dyn CanonicalTrustReader>
});
```

Then replace the explicit `None` currently passed to:

```rust
DataPlaneServicesBuilder::build_threat_intel_policy_context(None, advisory_source)
```

with:

```rust
DataPlaneServicesBuilder::build_threat_intel_policy_context(canonical_reader, advisory_source)
```

If snapshot is not yet available in worker bootstrap, keep `None` and document exact follow-up.

Rules:

- Use only `SnapshotCanonicalTrustReader` or equivalent real snapshot reader.
- Do not use static/test readers.
- Keep optional semantics.
- Do not call policy-composed lookups during bootstrap.

### Acceptance Criteria

Data-plane root receives a real canonical reader only when a real Supervisor-exported snapshot exists.

## Phase 6 — Tests

Add focused tests for snapshot export and worker construction.

Required tests if export implemented:

1. Supervisor/control-plane owner can produce a `CanonicalTrustSnapshot` from controlled test state;
2. exported snapshot contains trusted intel/global/revocation data expected by canonical reader;
3. worker-side reader constructed from snapshot implements `CanonicalTrustReader` correctly;
4. `build_threat_intel_policy_context(Some(snapshot_reader), advisory_source)` returns `Some`;
5. missing snapshot still returns `None`;
6. no production code imports `StaticCanonicalTrustReader` outside tests;
7. no worker code constructs Raft/control-plane state.

If export cannot yet be implemented:

1. add tests preserving current `None` behavior;
2. add a test or compile-time assertion that `MeshInit` does not carry fake canonical state;
3. document the exact owner where snapshot export must be added next.

### Acceptance Criteria

Tests prove either working snapshot export or the intentionally deferred boundary.

## Phase 7 — Documentation

Update `architecture/mesh_trust_domains.md` and possibly add `architecture/canonical_snapshot_export.md`.

If implemented:

```markdown
### Iteration 28 Supervisor Canonical Snapshot Export

Supervisor/control-plane code now exports a bounded `CanonicalTrustSnapshot` for worker data-plane use. Workers consume the snapshot through `SnapshotCanonicalTrustReader`; they do not own Raft or mutate canonical state. Data-plane composition can now build a populated `ThreatIntelPolicyContext` when an advisory source is also present. No proxy/YARA/WASM/routing/WAF consumers were migrated.
```

If deferred:

```markdown
### Iteration 28 Canonical Snapshot Export Assessment

The codebase still lacks a concrete Supervisor-owned `CanonicalTrustSnapshot` export path. Workers remain data-plane-only and production `ThreatIntelPolicyContext` remains unset. The next pass must add snapshot extraction at the Supervisor/EdgeReplicaManager/Raft state-machine owner before worker composition can receive a canonical reader.
```

Also update `AGENTS.md` or relevant local agent guides if they summarize canonical ownership.

### Acceptance Criteria

Docs state whether snapshot export exists, where it is owned, and whether worker composition now receives it.

## Phase 8 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid --features mesh
cargo test -p synvoid canonical --features mesh
cargo test -p synvoid data_plane --features mesh
cargo test -p synvoid unified_server --features mesh
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh threat_intel --features mesh
cargo test -p synvoid-mesh threat_intel_policy --features mesh
```

Then adjacent seam checks:

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

If package names differ, use actual workspace package names from `cargo metadata`.

## Completion Criteria

This iteration is complete when:

- Supervisor/control-plane canonical ownership is inventoried;
- a bounded snapshot export seam exists or the missing export owner is documented;
- workers do not own Raft/control-plane state;
- production does not use static/test canonical readers;
- worker/data-plane composition receives a real snapshot reader only when available;
- advisory source remains explicit record-store-derived;
- `ThreatIntelPolicyContext` remains optional;
- no proxy/YARA/WASM/routing/WAF/enforcement consumer is migrated;
- tests and docs reflect the selected result.

## Follow-Up Recommendation

If snapshot export succeeds, the next plan should define freshness and fail-open/fail-closed policy for using populated canonical snapshots in data-plane decisions.

If snapshot export is deferred, the next plan should directly target the Supervisor/EdgeReplicaManager/Raft state-machine owner to produce `CanonicalTrustSnapshot` without crossing into worker behavior.
