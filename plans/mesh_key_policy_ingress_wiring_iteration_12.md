# Mesh Key Policy Ingress Wiring — Iteration 12

## Goal

Build on Iteration 11 by hardening the remaining untested canonical-unavailable branch and then, only if low-risk, wiring the reader-backed key-policy helper into one DHT record ingress path.

The primary objective is to move from a tested helper to a staged production-facing check without changing DHT propagation semantics broadly.

The helper from Iteration 11 is:

```rust
classify_key_authority_with_canonical_reader(
    &DhtKeyPolicyTable,
    reader: &dyn CanonicalTrustReader,
    key: &DhtKey,
    signer_node_id: Option<&str>,
    authority_hint: Option<DhtRecordAuthorityClass>,
) -> DhtKeyAuthorityDecision
```

This pass should preserve the trust-domain invariant:

> Advisory DHT records are not authoritative. Canonical/Raft state answers trust questions. Policy decides whether record ingress may proceed, defer, or reject.

## Non-Goals

Do not migrate service consumers (`threat_intel.rs`, `proxy.rs`, YARA/WASM) in this pass.

Do not introduce an `AdvisoryRecordSource` seam yet.

Do not reorganize mesh modules.

Do not remove `RECORD_STORE_GLOBAL`.

Do not rewrite record-store replication, Kademlia routing, record gossip, or sync behavior.

Do not require live Raft, live DHT, or networking in tests.

Do not make all existing remote writes strict by default unless the path was already intended to be canonical-gated and tests prove the behavior.

## Phase 1 — Add Explicit CanonicalUnavailable Branch Tests

### Problem

Iteration 11 tests prove that unavailable freshness does not silently accept global-required keys, but they do not directly exercise a `CanonicalTrustDecision::NotTrusted { reason: CanonicalUnavailable, .. }` branch returning `DhtKeyAuthorityDecision::Defer { CanonicalUnavailable }`.

### Required Test

Add a small custom mock reader in `dht/key_policy.rs` tests that can return `CanonicalUnavailable` from:

1. `node_revocation_status(...)`; and
2. `is_global_node_authorized(...)`.

Required cases:

```rust
#[test]
fn test_canonical_unavailable_revocation_defers_global_key() { ... }

#[test]
fn test_canonical_unavailable_global_auth_defers_global_key() { ... }
```

Expected result:

```rust
DhtKeyAuthorityDecision::Defer {
    reason: DhtKeyAuthorityDeferReason::CanonicalUnavailable,
}
```

### Acceptance Criteria

The explicit `CanonicalUnavailable` branches are covered by tests.

The tests prove unavailable canonical state is not accepted as advisory trust.

## Phase 2 — Inventory Candidate Ingress Paths

Before wiring anything, inspect the current DHT ingress paths.

Run:

```bash
rg "put_record|store_record|set_record|insert_record|publish|ingress|validate|DhtKeyPolicyTable|policy_for_key|is_remote_write_denied|SignedDhtRecord|DhtEnvelope|record_store|RecordStoreMessage|classify_key_authority" crates/synvoid-mesh/src/mesh/dht crates/synvoid-mesh/src/mesh/raft crates/synvoid-mesh/src/mesh
```

Read at minimum:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store.rs` or equivalent store manager file
- `crates/synvoid-mesh/src/mesh/dht/quorum.rs`
- any current call sites of `is_remote_write_denied(...)`

Classify candidate call sites into:

1. Local-only writes;
2. Remote ingress writes;
3. Signed-envelope validation;
4. Sync/replication replay;
5. Raft/canonical replication.

### Acceptance Criteria

Identify exactly one low-risk ingress point for optional wiring, or document why wiring should be deferred.

Do not wire sync/replay paths unless they already enforce ingress policy today.

## Phase 3 — Add A Narrow Adapter Function For Ingress Decisions

If there is an obvious ingress point, add a small adapter that maps `DhtKeyAuthorityDecision` to the existing ingress accept/reject/defer result type.

Suggested helper shape; adapt to existing types:

```rust
pub fn validate_dht_key_authority_for_ingress(
    reader: &dyn CanonicalTrustReader,
    key: &DhtKey,
    signer_node_id: Option<&str>,
    authority_hint: Option<DhtRecordAuthorityClass>,
) -> Result<(), DhtIngressPolicyError> {
    match classify_key_authority_with_canonical_reader(
        &DhtKeyPolicyTable,
        reader,
        key,
        signer_node_id,
        authority_hint,
    ) {
        DhtKeyAuthorityDecision::AcceptAdvisory => Ok(()),
        DhtKeyAuthorityDecision::AcceptCanonical { .. } => Ok(()),
        DhtKeyAuthorityDecision::Reject { reason } => Err(DhtIngressPolicyError::Rejected(reason)),
        DhtKeyAuthorityDecision::Defer { reason } => Err(DhtIngressPolicyError::Deferred(reason)),
    }
}
```

Use existing error types if present. Do not proliferate new public error types unless necessary.

### Acceptance Criteria

The adapter is testable without networking.

The adapter preserves the distinction between reject and defer.

No broad production call sites are rewired yet unless Phase 4 chooses one.

## Phase 4 — Optional: Wire One Production Ingress Path

Only do this if Phase 2 finds a clear low-risk ingress point that already performs key-policy checks.

Preferred target:

- A remote signed-record ingress validation path that already has:
  - parsed `DhtKey`;
  - signer node ID or signer public key;
  - authority class or policy context;
  - access to a canonical reader or an injectable policy context.

Avoid wiring if the only available path would require introducing globals, blocking calls, broad constructors, or record-store lifetime churn.

### Rules

- Do not use `RECORD_STORE_GLOBAL` to obtain canonical trust.
- Do not instantiate `SnapshotCanonicalTrustReader` deep inside ingress if a reader should be injected.
- Prefer dependency injection through an existing manager/config/context if available.
- If injection is not currently clean, stop at adapter + tests and document that production wiring is deferred.
- Do not change local writes or sync replay behavior unless the current code already treats them as ingress.

### Acceptance Criteria

Either:

1. one production ingress path uses the adapter and tests prove behavior; or
2. production wiring is explicitly deferred with a note explaining what dependency injection seam is missing.

## Phase 5 — Tests For Adapter / Optional Wiring

Add offline tests for the adapter or the wired path.

Required cases:

1. Advisory key accepted.
2. Canonical-required key accepted with authorized signer.
3. Canonical-required key rejected with unauthorized signer.
4. Canonical-required key rejected with revoked signer.
5. Canonical-required key deferred on canonical unavailable.
6. Canonical-required key deferred on canonical unknown.
7. Threat intel canonical accepted when present.
8. Threat intel rejected/deferred when not canonical or unavailable.

If production wiring is added, add one or two tests that prove the ingress path invokes the adapter rather than bypassing it.

### Acceptance Criteria

Tests are deterministic and do not require live DHT/Raft/networking.

Tests show reject/defer distinctions survive adapter mapping.

## Phase 6 — Architecture Note Update

Update `architecture/mesh_trust_domains.md` with Iteration 12 status.

If only adapter/tests were added:

```markdown
### Iteration 12 Key Policy Ingress Preparation

The key-policy canonical helper now explicitly tests `CanonicalUnavailable` defer branches and has an ingress adapter preserving accept/reject/defer distinctions. Production record ingress wiring remains deferred until a clean `CanonicalTrustReader` injection point exists; no DHT propagation/storage behavior changed.
```

If one ingress path was wired:

```markdown
### Iteration 12 Key Policy Ingress Wiring

One remote signed-record ingress path now routes canonical-required key decisions through the key-policy adapter backed by `CanonicalTrustReader`. Advisory-only keys remain advisory; canonical-required keys reject/defer on unauthorized, revoked, unavailable, or unknown canonical state. Sync/replay/local paths were not broadly changed.
```

### Acceptance Criteria

The architecture note accurately states whether production ingress was wired or deferred.

The note does not claim service consumer migration.

## Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh peer_auth --features mesh
```

If production ingress is wired, run the relevant ingress/signed-record tests:

```bash
cargo test -p synvoid-mesh record_store --features mesh
cargo test -p synvoid-mesh signed --features mesh
cargo test -p synvoid-mesh record_store_message --features mesh
```

Then broader checks:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broad checks fail for unrelated reasons, record the focused checks that passed and the unrelated failure.

## Completion Criteria

This iteration is complete when:

- explicit `CanonicalUnavailable` defer branch tests exist;
- an ingress adapter exists or the absence of a clean adapter target is documented;
- optionally, exactly one low-risk ingress path is wired;
- reject/defer/accept distinctions are preserved;
- no service consumers are migrated;
- no broad record propagation/storage behavior changes occur;
- architecture docs state whether wiring happened or was deferred.

## Follow-Up Recommendation

After this pass, if production ingress wiring remains deferred, create the dependency-injection seam needed to provide `CanonicalTrustReader` cleanly to DHT ingress. If one ingress path is wired successfully, the next pass can either harden signed-record ingress coverage or begin the `AdvisoryRecordSource` seam before touching service consumers.
