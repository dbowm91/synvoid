# Mesh AdvisoryRecordSource Seam — Iteration 16

## Goal

Start the next mesh trust-domain track by introducing a read-only `AdvisoryRecordSource` seam for advisory DHT data.

The completed prior track staged canonical trust through:

- `CanonicalTrustReader`;
- `peer_auth.rs` canonical helper;
- `dht/key_policy.rs` canonical authority helper;
- `dht/ingress_policy.rs` and direct Push/Announce ingress gating.

This track should add the complementary advisory read seam so future policy code can compose:

```text
canonical trust answers  +  advisory DHT observations  +  identity proofs  => policy decisions
```

The seam should make advisory reads explicit and prevent service code from treating raw DHT records as authority.

## Core Invariant

DHT answers: "what has been advertised?"

Canonical/Raft answers: "what is trusted?"

Policy answers: "what may be acted on?"

`AdvisoryRecordSource` must only expose advisory DHT observations. It must not answer trust, authority, ownership, revocation, or canonical validity questions.

## Non-Goals

Do not migrate service consumers (`threat_intel.rs`, `proxy.rs`, YARA/WASM) in this pass.

Do not remove `RECORD_STORE_GLOBAL`.

Do not rewrite `RecordStoreManager`, DHT replication, sync, anti-entropy, Kademlia routing, quorum, or Raft apply paths.

Do not add new consensus behavior.

Do not make advisory reads stricter or more authoritative.

Do not change Push/Announce ingress behavior from the completed canonical-reader track.

Do not introduce a large policy engine yet.

Do not move files into a new module tree unless a tiny module addition is required.

## Phase 1 — Inventory Current Raw Advisory Read Call Sites

Identify where raw DHT/store reads are currently consumed by services or policy-like code.

Run:

```bash
rg "get_record|get_records|get_by_prefix|get_global_record_store|RECORD_STORE_GLOBAL|record_store|query_record|find_record|ThreatIndicator|Yara|Wasm|proxy|threat_intel|behavioral|capability|policy_for_key|DhtKey::from_str" crates/synvoid-mesh/src src crates/synvoid-* architecture docs
```

Categorize call sites into:

1. Pure DHT mechanics: replication, sync, anti-entropy, query response, routing.
2. Advisory service reads: threat intel, proxy metadata, capability hints, YARA/WASM manifests, behavioral data.
3. Policy-like decisions: places where raw DHT records influence accept/reject/block/allow behavior.
4. Compatibility globals: paths using `RECORD_STORE_GLOBAL` or equivalent.
5. Tests and docs.

### Acceptance Criteria

Produce implementation notes in code comments or architecture docs identifying the first low-risk consumer category.

Do not migrate any call site yet unless it is test-only or a pure adapter test.

## Phase 2 — Add Minimal Advisory Read Types

Add minimal typed outcomes for advisory reads.

Preferred location:

```text
crates/synvoid-mesh/src/mesh/dht/advisory_source.rs
```

or another low-cycle DHT module location.

Suggested types:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryFreshness {
    Live,
    Cached { age_ms: u64 },
    Stale { age_ms: u64 },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryRecordStatus {
    Present,
    Missing,
    Expired,
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct AdvisoryRecord {
    pub key: String,
    pub value: Vec<u8>,
    pub source_node_id: String,
    pub timestamp: u64,
    pub ttl_seconds: u64,
    pub freshness: AdvisoryFreshness,
    pub status: AdvisoryRecordStatus,
}
```

Adjust to existing `DhtRecord`/`DhtRecordEntry` shapes. Keep it minimal.

### Rules

- Do not include trust/authority language in these types.
- Do not call anything `TrustedAdvisoryRecord` or `VerifiedAdvisoryRecord`.
- If signature verification status is exposed, call it `signature_observed` or `record_signature_valid` and document that it is identity/envelope information, not canonical authority.
- If values are raw bytes, keep them raw; do not decode service-specific payloads in the seam.

### Acceptance Criteria

Types make it obvious that records are advisory observations.

No service-specific schema enters the seam.

## Phase 3 — Define `AdvisoryRecordSource` Trait

Add a read-only trait.

Suggested shape:

```rust
pub trait AdvisoryRecordSource: Send + Sync {
    fn get_advisory_record(&self, key: &str) -> AdvisoryRecordLookup;

    fn get_advisory_records_by_prefix(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Vec<AdvisoryRecord>;
}

#[derive(Debug, Clone)]
pub enum AdvisoryRecordLookup {
    Present(AdvisoryRecord),
    Missing,
    Expired,
    Unavailable,
}
```

Optional only if easy:

```rust
fn source_name(&self) -> &'static str { "unknown" }
```

### Rules

- Trait is read-only.
- Trait does not expose mutation, publish, store, announce, quorum, or sync.
- Trait does not expose canonical trust decisions.
- Trait does not depend on `CanonicalTrustReader`.
- Policy code may later consume both `AdvisoryRecordSource` and `CanonicalTrustReader`, but this trait must not know about canonical state.

### Acceptance Criteria

Trait compiles and is object-safe.

Trait can be used as `&dyn AdvisoryRecordSource` or `Arc<dyn AdvisoryRecordSource>`.

## Phase 4 — Implement A RecordStore Adapter

Add a read-only adapter over the existing record store.

Suggested shape:

```rust
pub struct RecordStoreAdvisorySource<'a> {
    store: &'a RecordStoreManager,
}

impl<'a> RecordStoreAdvisorySource<'a> {
    pub fn new(store: &'a RecordStoreManager) -> Self { ... }
}

impl AdvisoryRecordSource for RecordStoreAdvisorySource<'_> { ... }
```

If lifetime ergonomics are awkward, use an `Arc<RecordStoreManager>` adapter:

```rust
pub struct ArcRecordStoreAdvisorySource {
    store: Arc<RecordStoreManager>,
}
```

### Mapping Rules

- `get_record`/store lookup maps to `Present`, `Missing`, `Expired`, or `Unavailable` based on existing store semantics.
- TTL/expiration should be represented as advisory freshness/status only.
- Do not validate trust in the adapter.
- Do not check canonical state.
- Do not apply service policy.
- Preserve current record-store read behavior.

### Acceptance Criteria

Existing record-store reads are available through the adapter.

No mutation path is exposed.

No behavior change to existing callers.

## Phase 5 — Add Static/Test Advisory Source

Add a simple test implementation.

Suggested shape:

```rust
#[derive(Default)]
pub struct StaticAdvisoryRecordSource {
    records: HashMap<String, AdvisoryRecord>,
    unavailable: bool,
}
```

Use it for tests and future policy unit tests.

### Acceptance Criteria

Tests can simulate present/missing/expired/unavailable advisory records without DHT/networking.

## Phase 6 — Add Focused Tests

Required tests:

1. Trait is object-safe through `&dyn AdvisoryRecordSource`.
2. Static source returns present/missing/unavailable as advisory outcomes.
3. Prefix lookup is bounded by limit.
4. RecordStore adapter maps present records to `AdvisoryRecordLookup::Present`.
5. RecordStore adapter maps missing records to `Missing`.
6. Expired/TTL behavior is represented as advisory status if the store exposes enough information.
7. No canonical trust types are required to use the advisory source.

### Acceptance Criteria

Tests require no live DHT/Raft/networking.

Tests do not alter Push/Announce ingress behavior.

## Phase 7 — Export Surface

Update DHT exports minimally.

Likely in `crates/synvoid-mesh/src/mesh/dht/mod.rs`:

```rust
pub mod advisory_source;
pub use advisory_source::{
    AdvisoryFreshness,
    AdvisoryRecord,
    AdvisoryRecordLookup,
    AdvisoryRecordSource,
    AdvisoryRecordStatus,
    RecordStoreAdvisorySource,
    StaticAdvisoryRecordSource,
};
```

Adjust exact names as implemented.

### Acceptance Criteria

Policy code can import the trait and test source without deep paths.

Concrete adapter export is available only if useful.

No broad public API churn.

## Phase 8 — Architecture Note Update

Update `architecture/mesh_trust_domains.md` with a new track section.

Suggested text:

```markdown
### Iteration 16 AdvisoryRecordSource Seam

`AdvisoryRecordSource` introduces a read-only seam for advisory DHT observations. It exposes present/missing/expired/unavailable advisory records and prefix reads without exposing mutation, replication, quorum, or canonical trust decisions. The record-store adapter preserves existing read behavior and does not validate authority. This seam complements `CanonicalTrustReader`; future policy code should compose both rather than letting service consumers read raw DHT records as authority.
```

Follow-up should say:

```markdown
Next: build a small policy composition helper that consumes `CanonicalTrustReader` + `AdvisoryRecordSource`; do not migrate service consumers until that helper exists.
```

### Acceptance Criteria

Docs make clear that advisory source is not authority.

Follow-up points to policy composition, not service migration yet.

## Phase 9 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh advisory_source --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh ingress_policy --features mesh
```

Then broader mesh checks:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broad checks fail for unrelated reasons, document the focused checks and exact unrelated failure.

## Completion Criteria

This iteration is complete when:

- `AdvisoryRecordSource` trait exists and is object-safe;
- advisory outcome types exist and avoid trust/authority language;
- record-store adapter exists and is read-only;
- static/test source exists;
- tests cover present/missing/unavailable/prefix/object-safety behavior;
- DHT exports are minimal and usable;
- no service consumers are migrated;
- no DHT mutation/replication behavior changes;
- architecture docs describe the seam and next policy-composition step.

## Follow-Up Recommendation

After this pass, create a small policy composition helper that accepts:

```rust
&dyn CanonicalTrustReader
&dyn AdvisoryRecordSource
```

and produces explicit policy outputs for one narrow domain, likely threat-intel or route/proxy metadata. Only after that helper is tested should service consumers begin migrating away from raw DHT reads.
