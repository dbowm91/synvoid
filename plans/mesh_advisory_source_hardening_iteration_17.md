# Mesh AdvisoryRecordSource Hardening — Iteration 17

## Goal

Harden the new `AdvisoryRecordSource` seam by adding focused tests for the real `RecordStoreAdvisorySource` adapter and tightening small consistency issues before moving to policy composition.

Iteration 16 successfully introduced:

- `AdvisoryRecordSource`;
- advisory lookup/status/freshness types;
- `RecordStoreAdvisorySource`;
- `StaticAdvisoryRecordSource`;
- DHT exports;
- architecture documentation.

The remaining gap is test coverage for the real record-store adapter. This pass should not add new architecture or migrate consumers.

## Non-Goals

Do not migrate service consumers (`threat_intel.rs`, `proxy.rs`, YARA/WASM`).

Do not add policy composition yet.

Do not introduce new canonical trust behavior.

Do not change Push/Announce ingress gating.

Do not change record-store mutation, sync, replication, anti-entropy, quorum, or routing behavior.

Do not remove `RECORD_STORE_GLOBAL`.

Do not add networking/Raft/DHT-cluster tests.

Do not decode service-specific advisory payloads.

## Phase 1 — Inspect RecordStore Test Utilities

Before adding tests, inspect current test helpers for `RecordStoreManager` and `DhtRecord` construction.

Run:

```bash
rg "RecordStoreManager::new|store_local_record|store_record_verified_internal|DhtRecord \{|verify_content_hash|content_hash|record_signature|signer_public_key|record_store.*test|make_.*record|test_.*record" crates/synvoid-mesh/src/mesh/dht crates/synvoid-mesh/src/mesh tests
```

Read:

- `crates/synvoid-mesh/src/mesh/dht/advisory_source.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store_crud.rs`
- existing tests in nearby DHT modules

### Acceptance Criteria

Use existing helpers if they exist.

If no helper exists, add the smallest local test helper in `advisory_source.rs` tests.

## Phase 2 — Add Real RecordStore Adapter Tests

Add tests in `advisory_source.rs` for `RecordStoreAdvisorySource` backed by a real `RecordStoreManager`.

Required cases:

1. **Present record maps to advisory present**
   - Insert or otherwise make a record available in `RecordStoreManager`.
   - Query through `RecordStoreAdvisorySource::new(Arc::new(store))`.
   - Assert `AdvisoryRecordLookup::Present`.
   - Assert key, value, source node ID, timestamp, TTL, status, and `record_signature_valid` mapping.

2. **Missing record maps to missing**
   - Query a key that is not present.
   - Assert `AdvisoryRecordLookup::Missing`.

3. **Expired record maps to expired for single lookup**
   - Insert an expired record or directly seed the store if public insert paths reject it.
   - Assert `AdvisoryRecordLookup::Expired`.
   - Do not mutate adapter behavior just for tests.

4. **Prefix lookup returns only live/non-expired records**
   - Insert multiple records under one prefix.
   - Include one expired record if feasible.
   - Assert results are bounded by `limit` and do not include expired entries.

5. **Prefix lookup honors limit**
   - Insert more records than the limit.
   - Assert returned length equals the limit.

6. **Adapter remains advisory-only**
   - No `CanonicalTrustReader`, canonical module, or trust decision types are needed in these tests.

### Practical Guidance

If public write paths require signatures/content hashes and make setup heavy, use one of these approaches in order:

1. Use existing valid signed-record helpers.
2. Add a local helper that creates `DhtRecord` with valid `content_hash` and plausible non-empty signature/signing metadata.
3. If public storage rejects due to policy, use existing record-store internals from same-module tests only if visibility allows.
4. Avoid weakening production validation.

### Acceptance Criteria

`RecordStoreAdvisorySource` has direct tests for present/missing/expired/prefix behavior.

Tests are offline and deterministic.

No canonical types are imported for adapter tests.

## Phase 3 — Clarify Freshness/Status Semantics If Needed

Review the current mapping:

- single lookup returns `Expired` for expired records;
- prefix lookup filters expired records;
- present records map to `AdvisoryRecordStatus::Present`;
- `classify_freshness` may classify expired records as `Stale`, but single lookup returns `Expired` before mapping.

If comments are unclear, add a short rustdoc note explaining:

- single-key lookup can distinguish expired;
- prefix lookup returns actionable/current advisory observations only and filters expired;
- `Stale` freshness is retained for future policy use where an implementation elects to expose stale records, but the current record-store adapter hides expired records in prefix reads.

### Acceptance Criteria

No confusing mismatch between `Expired` status and prefix filtering remains undocumented.

No behavior change unless tests expose an obvious bug.

## Phase 4 — Verify No Service Consumer Migration Happened

Run:

```bash
rg "AdvisoryRecordSource|RecordStoreAdvisorySource|StaticAdvisoryRecordSource|AdvisoryRecordLookup" crates/synvoid-mesh/src src crates/synvoid-* --glob '!crates/synvoid-mesh/src/mesh/dht/advisory_source.rs' --glob '!crates/synvoid-mesh/src/mesh/dht/mod.rs'
```

Expected current usage:

- exports;
- tests;
- architecture docs/plans;
- no service consumer migration yet.

### Acceptance Criteria

No `threat_intel.rs`, `proxy.rs`, YARA/WASM, route/proxy, or service consumer starts using the seam in this hardening pass.

## Phase 5 — Architecture Note Update

Update `architecture/mesh_trust_domains.md` with a small Iteration 17 note.

Suggested text:

```markdown
### Iteration 17 Advisory Source Hardening

`RecordStoreAdvisorySource` now has focused tests against a real `RecordStoreManager`, covering present, missing, expired, prefix-limit, and expired-prefix filtering behavior. The seam remains read-only and advisory-only; no service consumers were migrated and no canonical trust behavior was added.
```

If the implementation discovers adapter behavior needed correction, mention the correction precisely.

### Acceptance Criteria

Architecture docs reflect that this was hardening/test coverage, not a new migration step.

Follow-up still points to policy composition before service-consumer migration.

## Phase 6 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh advisory_source --features mesh
```

Then regression checks for adjacent seams:

```bash
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh ingress_policy --features mesh
```

Then broader checks if practical:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broad checks fail for unrelated reasons, record the focused checks that passed and the unrelated failure.

## Completion Criteria

This hardening pass is complete when:

- `RecordStoreAdvisorySource` has tests for present/missing/expired/prefix behavior;
- tests use real `RecordStoreManager` where feasible;
- freshness/status behavior is documented if necessary;
- no service consumers are migrated;
- no DHT mutation/replication behavior changes occur;
- architecture docs record Iteration 17 as hardening;
- focused advisory-source tests pass.

## Follow-Up Recommendation

After this pass, move to a small policy-composition helper over:

```rust
&dyn CanonicalTrustReader
&dyn AdvisoryRecordSource
```

Choose one narrow domain for the first policy helper, preferably threat-intel, because it already has clear canonical and advisory dimensions. Do not migrate service consumers until the helper has its own focused tests.
