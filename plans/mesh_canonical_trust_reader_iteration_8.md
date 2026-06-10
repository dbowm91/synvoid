# Mesh Canonical Trust Reader — Iteration 8

## Goal

Implement the first concrete mesh trust-domain seam chosen in `architecture/mesh_trust_domains.md`: a narrow, read-only `CanonicalTrustReader` / `CanonicalTrustSnapshot` interface.

This pass must not reorganize mesh modules broadly. It should introduce the seam, wire one low-risk adapter over existing canonical/Raft/snapshot state, and add tests proving consumers can depend on the seam without importing Raft internals or raw DHT/quorum logic.

The core invariant remains:

> DHT answers "what has been advertised?" Raft/canonical state answers "what is trusted?" Policy answers "what may be acted on?" Transport answers "how peers communicate."

## Non-Goals

Do not split `synvoid-mesh` into multiple crates.

Do not move existing Raft, DHT, peer-auth, threat-intel, transport, or service files into new module trees yet.

Do not change Raft membership, state-machine behavior, snapshot replication, record propagation, DHT storage, or peer discovery behavior.

Do not remove `RECORD_STORE_GLOBAL` or compatibility fallbacks in this pass.

Do not rewrite `peer_auth.rs`, `dht/signed.rs`, `dht/key_policy.rs`, `threat_intel.rs`, or `proxy.rs` broadly.

Do not make policy decisions stricter by default.

Do not introduce async/network calls in tests unless already isolated and deterministic.

## Phase 1 — Inspect Existing Canonical Read Surfaces

Before writing the new seam, inspect existing canonical/Raft read surfaces.

Run:

```bash
rg "struct .*Snapshot|Snapshot|RecordReader|RaftAwareClient|EdgeReplica|AuthorizedGlobalNodes|GlobalRegistryStateMachine|OrgPublicKey|ThreatIntel|Revocation|GlobalNode|SignedRaftAttestation|validate_peer_role" crates/synvoid-mesh/src/mesh/raft crates/synvoid-mesh/src/mesh/peer_auth.rs crates/synvoid-mesh/src/mesh/organization.rs crates/synvoid-mesh/src/mesh/cert.rs crates/synvoid-mesh/src/mesh/dht/key_policy.rs
```

Read at minimum:

- `crates/synvoid-mesh/src/mesh/raft/state_machine.rs`
- `crates/synvoid-mesh/src/mesh/raft/client.rs`
- `crates/synvoid-mesh/src/mesh/raft/consensus.rs`
- `crates/synvoid-mesh/src/mesh/raft/edge_replica.rs`
- `crates/synvoid-mesh/src/mesh/peer_auth.rs`
- `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`

Classify what canonical answers are already available. Expected categories:

- organization public key / organization authority;
- global node authorization;
- revocation status;
- canonical threat-intel attestation/trust;
- snapshot freshness/staleness;
- failure/degraded behavior when canonical state is unavailable.

### Acceptance Criteria

The implementation is based on existing canonical data structures, not invented duplicate state.

If a desired canonical answer is not currently available, represent it as `Unknown` / `Unavailable` rather than fabricating behavior.

## Phase 2 — Add A Narrow Canonical Module Without Moving Existing Code

Add a new focused module under the current mesh tree. Prefer:

```text
crates/synvoid-mesh/src/mesh/canonical.rs
```

or, if the repo already has a suitable module layout:

```text
crates/synvoid-mesh/src/mesh/canonical/mod.rs
```

Do not move existing Raft files into it yet. This module is a seam/facade, not a reorganization.

Expose it from `crates/synvoid-mesh/src/mesh/mod.rs` with a clear comment:

```rust
// Domain: canonical. Read-only trust seam over Raft/global-node canonical state.
pub mod canonical;
```

### Acceptance Criteria

A canonical seam module exists.

Existing public imports remain source-compatible.

No existing Raft/DHT files are moved.

## Phase 3 — Define Core Types

Define small, explicit types. Keep them boring and stable.

Suggested types:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalFreshness {
    Live,
    Snapshot { age_ms: u64 },
    Stale { age_ms: u64 },
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalTrustDecision {
    Trusted { freshness: CanonicalFreshness },
    NotTrusted { freshness: CanonicalFreshness, reason: CanonicalTrustReason },
    Unknown { freshness: CanonicalFreshness, reason: CanonicalTrustReason },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalTrustReason {
    PresentInCanonicalState,
    NotPresentInCanonicalState,
    Revoked,
    ExpiredSnapshot,
    CanonicalUnavailable,
    UnsupportedDecisionType,
}

#[derive(Debug, Clone)]
pub struct CanonicalTrustSnapshot {
    pub freshness: CanonicalFreshness,
    // keep fields minimal; use existing canonical structures internally where possible
}
```

Define a trait:

```rust
pub trait CanonicalTrustReader: Send + Sync {
    fn freshness(&self) -> CanonicalFreshness;

    fn is_global_node_authorized(&self, node_id: &str) -> CanonicalTrustDecision;

    fn is_org_key_trusted(&self, org_id: &str, key_id_or_fingerprint: &str) -> CanonicalTrustDecision;

    fn is_node_revoked(&self, node_id: &str) -> CanonicalTrustDecision;

    fn is_threat_intel_canonical(&self, intel_id: &str) -> CanonicalTrustDecision;
}
```

Adjust names/types to match existing code. If node IDs/org IDs are strongly typed already, use existing types instead of `&str` where low-churn.

### Rules

- Do not make the trait async unless existing canonical read surfaces require async. Prefer snapshot-backed sync reads.
- Do not embed DHT record types in the canonical trait.
- Do not make signatures equal authorization; that belongs in policy.
- Do not expose Raft internals through this trait.

### Acceptance Criteria

The trait compiles without pulling DHT storage or transport into canonical.

Decision types distinguish trusted/not-trusted/unknown.

Freshness is always represented.

## Phase 4 — Implement A Low-Risk Snapshot Adapter

Implement a simple adapter over existing canonical state.

Preferred approach:

```rust
pub struct StaticCanonicalTrustReader {
    snapshot: CanonicalTrustSnapshot,
}
```

or, if existing edge replica/snapshot types are already usable:

```rust
pub struct SnapshotCanonicalTrustReader {
    snapshot: Arc<ExistingCanonicalSnapshotType>,
    freshness: CanonicalFreshness,
}
```

The adapter should read existing canonical data and answer the trait methods. If a method cannot be implemented accurately yet, return:

```rust
CanonicalTrustDecision::Unknown {
    freshness,
    reason: CanonicalTrustReason::UnsupportedDecisionType,
}
```

### Required Behavior

- Authorized global nodes: answer from existing authorized-global-node canonical state if available.
- Org key trust: answer from existing org public key canonical namespace if available.
- Revocation: answer from existing revocation list if available.
- Threat intel canonical trust: answer from existing canonical threat-intel namespace if available.
- Freshness: use existing snapshot age/staleness data if available; otherwise use `Unavailable` or a documented snapshot age source.

Do not introduce new persistence.

Do not duplicate canonical state into a new independent store.

### Acceptance Criteria

The adapter is read-only.

Unknown/unavailable cases are explicit.

The adapter can be constructed in tests with fake/static data without running a Raft cluster.

## Phase 5 — Add Mock/Test Reader and Unit Tests

Add tests in the canonical module.

Required test cases:

1. A static/mock reader returns `Trusted` for a known authorized global node.
2. It returns `NotTrusted` for a known absent global node when canonical state is available.
3. It returns `Trusted` for a known org key if that data is modeled in the adapter.
4. It returns a revoked decision for a known revoked node if revocation is modeled.
5. It returns `Unknown` when freshness is unavailable or a decision type is unsupported.
6. Freshness is propagated into every decision.

Keep tests offline and deterministic.

### Acceptance Criteria

`cargo test -p synvoid-mesh canonical` exercises the seam.

No test requires live networking, DHT, or a Raft cluster.

## Phase 6 — Add Boundary Documentation Near The Seam

Update `architecture/mesh_trust_domains.md` with a short implementation note:

```markdown
### Iteration 8 Implementation Seam

`CanonicalTrustReader` is the first concrete canonical boundary. It is read-only and snapshot-oriented. Services and future policy code should depend on this seam instead of importing Raft internals when they need canonical trust answers.
```

If useful, add short rustdoc comments on the trait explaining:

- canonical answers are not advisory DHT records;
- freshness is part of every answer;
- `Unknown` is distinct from `NotTrusted`;
- this trait does not make policy decisions by itself.

### Acceptance Criteria

The design note points to the new seam.

Rustdoc captures the trust-domain distinction.

## Phase 7 — Optional: One Low-Risk Consumer Compile Check

If low-churn, update one small internal call site or test-only consumer to depend on `dyn CanonicalTrustReader` rather than concrete Raft internals.

Prefer a test/mock or helper, not production rewiring yet.

Do not change runtime trust behavior in this pass.

### Acceptance Criteria

At least one compile-time example demonstrates a consumer can use the seam without importing Raft internals.

If no low-risk consumer exists, document that production consumer migration is deferred to the next pass.

## Validation Commands

Run focused checks first:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh canonical --features mesh
```

Then run broader mesh/workspace checks:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If workspace checks are too expensive or fail for unrelated reasons, record exactly which focused checks passed and what remains unverified.

## Completion Criteria

This iteration is complete when:

- a canonical seam module exists;
- `CanonicalTrustReader` and decision/freshness types exist;
- a read-only snapshot/static adapter exists;
- unknown/unavailable cases are explicit;
- tests cover trusted, not-trusted, unknown, revocation if available, and freshness propagation;
- no broad mesh module movement occurred;
- no runtime trust behavior changed;
- `architecture/mesh_trust_domains.md` references the implemented seam.

## Follow-Up Recommendation

The next pass should migrate exactly one security-sensitive consumer behind this seam. Good candidates are:

1. `peer_auth.rs` role/attestation validation, if it currently mixes identity and canonical trust checks; or
2. `dht/key_policy.rs`, if it needs canonical answers to classify DHT key authority.

Do not migrate `threat_intel.rs`, `proxy.rs`, or YARA/WASM services until the policy layer has a clearer interface that combines `CanonicalTrustReader` with an advisory DHT source.
