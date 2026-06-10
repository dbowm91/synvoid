# Mesh DHT Ingress Canonical Reader Context — Iteration 13

## Goal

Create the dependency-injection seam needed for DHT record ingress to receive a `CanonicalTrustReader` cleanly, without globals, deep construction, or broad record-store behavior changes.

Iteration 12 deliberately stopped at helper + adapter level because production record ingress did not yet have a clean way to access canonical trust. This pass should introduce that access path as a context object or injectable handle, then optionally wire exactly one low-risk ingress validator to call the existing adapter:

```rust
validate_dht_key_authority_for_ingress(
    reader: &dyn CanonicalTrustReader,
    key: &DhtKey,
    signer_node_id: Option<&str>,
    authority_hint: Option<DhtRecordAuthorityClass>,
)
```

The target invariant remains:

> DHT ingress can ask policy for accept/reject/defer, but it must not construct canonical state, read Raft internals directly, or treat advisory records as authority.

## Non-Goals

Do not migrate service consumers (`threat_intel.rs`, `proxy.rs`, YARA/WASM) in this pass.

Do not introduce the full `AdvisoryRecordSource` seam yet.

Do not reorganize mesh modules.

Do not remove `RECORD_STORE_GLOBAL`.

Do not rewrite DHT record propagation, replication, sync, Kademlia routing, or storage.

Do not instantiate `SnapshotCanonicalTrustReader` inside low-level DHT ingress functions.

Do not make local writes or sync replay suddenly subject to remote ingress policy unless they already go through the same remote-ingress validation path.

Do not require live Raft, DHT, networking, or cluster setup in tests.

## Phase 1 — Identify The Cleanest Ingress Ownership Boundary

Inspect current DHT ingress and ownership types.

Run:

```bash
rg "struct .*Manager|struct .*Context|RecordStoreManager|RecordStoreMessage|SignedDhtRecord|DhtEnvelope|put_record|store_record|set_record|insert_record|publish|remote|ingress|validate|verify|policy_for_key|is_remote_write_denied|RecordReader|EdgeReplicaManager|CanonicalTrustReader" crates/synvoid-mesh/src/mesh/dht crates/synvoid-mesh/src/mesh crates/synvoid-mesh/src/lib.rs
```

Read at minimum:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store.rs` or equivalent store manager module
- `crates/synvoid-mesh/src/mesh/dht/mod.rs`
- `crates/synvoid-mesh/src/mesh/raft/edge_replica.rs`
- `crates/synvoid-mesh/src/mesh/canonical.rs`
- any code currently constructing `RecordStoreManager` or ingesting remote/signed records

Classify call paths into:

1. local writes;
2. remote client writes;
3. signed-record ingress;
4. gossip/sync replay;
5. Raft/edge-replica apply;
6. test-only helpers.

### Acceptance Criteria

A short source comment or implementation note identifies the exact chosen ingress ownership boundary.

The boundary must already know enough to receive or carry an injected canonical reader.

If no such boundary exists, stop after adding a context type and tests for it.

## Phase 2 — Add A Minimal Ingress Policy Context

Add a small injectable context type close to the DHT ingress/policy boundary.

Preferred location if it avoids cycles:

```text
crates/synvoid-mesh/src/mesh/dht/ingress_policy.rs
```

or inside `record_store_message.rs` if that is the only practical low-churn location.

Suggested shape:

```rust
use std::sync::Arc;
use crate::mesh::canonical::CanonicalTrustReader;

#[derive(Clone)]
pub struct DhtIngressPolicyContext {
    canonical_reader: Option<Arc<dyn CanonicalTrustReader>>,
}

impl DhtIngressPolicyContext {
    pub fn disabled() -> Self { ... }

    pub fn with_canonical_reader(reader: Arc<dyn CanonicalTrustReader>) -> Self { ... }

    pub fn canonical_reader(&self) -> Option<&dyn CanonicalTrustReader> { ... }
}
```

If existing manager/config/context types already exist, embed the field there instead of creating a new module.

### Rules

- `None` means the canonical ingress gate is not wired yet; preserve existing behavior.
- `Some(reader)` means canonical-required key decisions may be enforced by the adapter.
- Do not use global state to fill this context.
- Do not construct readers deep in DHT files.
- Prefer `Arc<dyn CanonicalTrustReader>` over concrete `SnapshotCanonicalTrustReader` in DHT modules.

### Acceptance Criteria

A context or equivalent injectable handle exists.

The context compiles and can be used in tests with `StaticCanonicalTrustReader`.

No runtime behavior changes merely from defining the context.

## Phase 3 — Add Adapter-Level Entry Function For Optional Context

Add a small function that accepts the optional context and preserves legacy behavior when disabled.

Suggested shape:

```rust
pub enum DhtIngressGateOutcome {
    Accepted,
    Rejected(DhtKeyAuthorityRejectReason),
    Deferred(DhtKeyAuthorityDeferReason),
    NotConfigured,
}

pub fn check_dht_ingress_authority(
    ctx: &DhtIngressPolicyContext,
    key: &DhtKey,
    signer_node_id: Option<&str>,
    authority_hint: Option<DhtRecordAuthorityClass>,
) -> DhtIngressGateOutcome {
    let Some(reader) = ctx.canonical_reader() else {
        return DhtIngressGateOutcome::NotConfigured;
    };

    match validate_dht_key_authority_for_ingress(reader, key, signer_node_id, authority_hint) {
        Ok(()) => DhtIngressGateOutcome::Accepted,
        Err(DhtIngressPolicyError::Rejected(r)) => DhtIngressGateOutcome::Rejected(r),
        Err(DhtIngressPolicyError::Deferred(d)) => DhtIngressGateOutcome::Deferred(d),
    }
}
```

Use existing error/outcome types if better ones already exist.

### Acceptance Criteria

Disabled context returns an explicit `NotConfigured`/legacy outcome.

Configured context preserves accept/reject/defer distinctions.

Tests cover both disabled and configured contexts.

## Phase 4 — Optional: Wire Exactly One Low-Risk Ingress Validator

Only wire production code if Phase 1 identifies an ingress validator that already has:

- parsed `DhtKey`;
- signer node/public key or equivalent signer identity;
- authority class or enough context to derive it;
- a natural place to receive `DhtIngressPolicyContext` or `Arc<dyn CanonicalTrustReader>` by injection;
- no need for globals or deep construction.

Preferred target:

- signed-record ingress validation, if it already validates envelope/signature and key policy.

Avoid:

- sync/replay apply paths;
- local admin writes;
- Raft edge-replica apply paths;
- service-level readers.

### Wiring Rules

- If context is `NotConfigured`, preserve existing behavior.
- If context returns `Accepted`, preserve current accept path.
- If context returns `Rejected`, reject the remote ingress record.
- If context returns `Deferred`, treat as rejection for remote ingress unless existing code already has an explicit defer/retry queue. Document the choice.
- Do not alter replication/replay semantics.

### Acceptance Criteria

Either:

1. exactly one ingress validator uses the context and tests prove configured/disabled behavior; or
2. production wiring is deferred because no clean injection point exists, with a clear note in the architecture doc.

## Phase 5 — Tests

Add offline tests. Use `StaticCanonicalTrustReader` and custom mock readers as needed.

Required context tests:

1. Disabled context returns `NotConfigured` / preserves legacy path.
2. Configured context accepts advisory key.
3. Configured context accepts canonical-required key with authorized signer.
4. Configured context rejects canonical-required key with unauthorized signer.
5. Configured context rejects revoked signer.
6. Configured context defers unavailable canonical state.
7. Configured context defers unknown canonical state.
8. Threat intel canonical accept/reject/defer still maps correctly.

If a production ingress validator is wired, add tests for:

1. Disabled context preserves old behavior.
2. Configured context rejects an unauthorized canonical-required key.
3. Configured context accepts an advisory key.
4. Configured context rejects/defer path does not affect local/sync replay paths.

### Acceptance Criteria

Tests are deterministic and require no live Raft/DHT/networking.

Tests show `Arc<dyn CanonicalTrustReader>` injection works.

Tests show no broad behavior changes when the context is disabled.

## Phase 6 — Architecture Note Update

Update `architecture/mesh_trust_domains.md` with Iteration 13 status.

If only context/adapter was added:

```markdown
### Iteration 13 DHT Ingress Canonical Reader Context

DHT ingress now has an injectable policy context capable of carrying `Arc<dyn CanonicalTrustReader>` to the key-policy ingress adapter. Disabled context preserves legacy behavior; configured context preserves accept/reject/defer distinctions. Production ingress wiring remains deferred until a specific remote signed-record validator can receive the context without globals or deep construction.
```

If one ingress validator was wired:

```markdown
### Iteration 13 DHT Ingress Canonical Reader Context

One remote signed-record ingress validator now receives an injected canonical-reader context and uses the key-policy ingress adapter for canonical-required keys. Disabled context preserves legacy behavior. Configured context rejects/defer canonical-required remote writes on unauthorized, revoked, unavailable, or unknown canonical state. Local writes, sync replay, and Raft apply paths were not broadly changed.
```

Also update the follow-up section from “optional production wiring” to the actual next step.

### Acceptance Criteria

The architecture note truthfully states whether production wiring happened or remains deferred.

It does not claim service consumer migration.

## Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh key_policy --features mesh
```

If a new ingress module/test name exists, run it explicitly:

```bash
cargo test -p synvoid-mesh ingress_policy --features mesh
cargo test -p synvoid-mesh record_store_message --features mesh
cargo test -p synvoid-mesh signed --features mesh
```

Then run baseline seam tests:

```bash
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh peer_auth --features mesh
```

Then broader checks:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broad checks fail for unrelated reasons, record the focused checks that passed and the unrelated failure.

## Completion Criteria

This iteration is complete when:

- DHT ingress has an injectable canonical-reader context or equivalent handle;
- disabled context preserves existing behavior;
- configured context routes through `validate_dht_key_authority_for_ingress`;
- accept/reject/defer distinctions are preserved in tests;
- optionally, exactly one low-risk ingress validator is wired;
- no globals or deep reader construction are introduced;
- no service consumers are migrated;
- no broad record propagation/storage behavior changes occur;
- architecture docs accurately record the status.

## Follow-Up Recommendation

If production wiring is still deferred, the next pass should wire the specific remote signed-record validator once the context can flow through constructors cleanly. If one validator is wired successfully, the next pass should add `AdvisoryRecordSource` rather than moving service consumers directly.
