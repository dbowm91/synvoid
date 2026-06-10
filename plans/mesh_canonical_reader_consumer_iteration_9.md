# Mesh Canonical Reader Consumer Migration — Iteration 9

## Goal

Build on the new `CanonicalTrustReader` / `CanonicalTrustSnapshot` seam by tightening its semantics and migrating exactly one low-risk consumer behind it. The preferred consumer is `peer_auth.rs`, because the trust-domain design identified it as a risky cross-domain file that mixes identity, policy, and canonical checks.

This pass should remain narrow:

1. replace placeholder snapshot freshness with real or explicitly injected freshness;
2. clarify revocation semantics so "not revoked" is not confused with "trusted overall";
3. introduce a low-churn `CanonicalTrustReader` integration point in `peer_auth.rs` or an adjacent helper;
4. preserve current runtime behavior unless the old behavior was clearly incorrect and tests document the change.

## Non-Goals

Do not reorganize the mesh module tree.

Do not split `synvoid-mesh` into multiple crates.

Do not migrate `threat_intel.rs`, `proxy.rs`, YARA/WASM services, or DHT record-store consumers yet.

Do not remove `RECORD_STORE_GLOBAL`.

Do not rewrite Raft state machine or edge replica persistence.

Do not turn advisory DHT data into canonical state.

Do not introduce new consensus behavior or network calls.

Do not make policy stricter by default unless existing code already did so.

## Phase 1 — Inspect Current Freshness Sources

### Problem

`SnapshotCanonicalTrustReader::freshness()` currently returns `CanonicalFreshness::Snapshot { age_ms: 0 }` as a placeholder because `EdgeReplicaManager` does not expose snapshot age through the seam.

That is acceptable for the initial seam, but not sufficient before production consumers depend on freshness.

### Required Inspection

Run:

```bash
rg "last_sync|last.*sync|snapshot|fresh|stale|age_ms|updated_at|applied|index|term|modified|mtime|SystemTime|Instant" crates/synvoid-mesh/src/mesh/raft crates/synvoid-mesh/src/mesh crates/synvoid-config/src
```

Inspect:

- `crates/synvoid-mesh/src/mesh/raft/edge_replica.rs`
- `crates/synvoid-mesh/src/mesh/raft/client.rs`
- `crates/synvoid-mesh/src/mesh/raft/consensus.rs`
- `crates/synvoid-mesh/src/mesh/config.rs`
- any `AuthorityFreshnessConfig` or stale-canonical policy structures.

### Required Outcome

Choose one of these approaches:

1. **Preferred if available**: expose real snapshot freshness from `EdgeReplicaManager` or existing snapshot metadata.
2. **Acceptable low-risk fallback**: change `SnapshotCanonicalTrustReader::new(...)` to accept a `CanonicalFreshness` argument and add `new_with_freshness(...)`, while keeping `new(...)` as explicit `Unavailable` or documented default.
3. **Do not keep silent `Snapshot { age_ms: 0 }`** unless it is backed by real metadata.

### Acceptance Criteria

`SnapshotCanonicalTrustReader::freshness()` no longer silently reports `Snapshot { age_ms: 0 }` as a fake age.

Tests cover the selected freshness behavior.

## Phase 2 — Clarify Revocation Semantics

### Problem

`is_node_revoked(node_id)` currently returns `Trusted` when a node is not in the revocation set. That can be misread as full node trust, even though the real semantic is only "not revoked by canonical state."

### Required Changes

Choose one of these options:

1. Rename the method to make semantics explicit:

```rust
fn node_revocation_status(&self, node_id: &str) -> CanonicalTrustDecision;
```

2. Or add a new method and deprecate/avoid the old one internally:

```rust
fn node_revocation_status(&self, node_id: &str) -> CanonicalTrustDecision;
```

3. Or, if renaming creates too much churn, strengthen rustdoc and tests to state that `Trusted` from `is_node_revoked` means "canonically not revoked," not "globally trusted."

Preferred: add `node_revocation_status` and keep the old method as a compatibility alias only if needed.

### Acceptance Criteria

The canonical seam no longer encourages consumers to interpret "not revoked" as complete trust.

Tests assert the exact intended semantic.

Rustdoc states the difference between revocation status and authorization/trust.

## Phase 3 — Identify `peer_auth.rs` Canonical Checks

### Required Inspection

Run:

```bash
rg "revok|GlobalNode|Authorized|SignedRaftAttestation|OrgPublicKey|org|trust|attestation|canonical|Raft|quorum|validate_peer_role" crates/synvoid-mesh/src/mesh/peer_auth.rs crates/synvoid-mesh/src/mesh/cert.rs crates/synvoid-mesh/src/mesh/organization.rs crates/synvoid-mesh/src/mesh/dht/key_policy.rs
```

In `peer_auth.rs`, identify code that answers canonical questions such as:

- is this global node authorized?
- is this node revoked?
- is this org/global authority attestation canonical?
- is this role valid because canonical state says so?

Do not migrate pure identity checks such as signature verification, certificate parsing, or key material validation unless necessary.

### Acceptance Criteria

Only canonical trust reads are targeted.

Identity verification remains identity-layer behavior.

Policy decisions remain explicit and do not disappear into the reader.

## Phase 4 — Add A Low-Churn `CanonicalTrustReader` Integration Point

### Preferred Shape

Avoid rewiring all peer-auth logic at once. Add one helper that accepts a trait object or generic reader:

```rust
pub fn validate_peer_canonical_status(
    reader: &dyn CanonicalTrustReader,
    node_id: &str,
    role: PeerRoleLike,
) -> Result<CanonicalPeerStatus, PeerAuthError> {
    // use reader.is_global_node_authorized(...)
    // use reader.node_revocation_status(...)
    // preserve existing behavior
}
```

Adjust names to match existing types.

If `peer_auth.rs` already has `validate_peer_role(...)`, either:

- add a new reader-backed variant, e.g. `validate_peer_role_with_canonical_reader(...)`; or
- refactor the canonical lookup part into a helper that can be tested independently.

Do not force all production call sites to pass a reader yet unless the change is small.

### Rules

- Signature/certificate verification must stay outside the reader.
- Reader decides only canonical state answers, not full policy outcome.
- `Unknown` must be handled explicitly.
- Freshness must be considered or consciously ignored with a comment.
- Preserve existing failure behavior unless tests show an old ambiguity.

### Acceptance Criteria

At least one peer-auth helper depends on `dyn CanonicalTrustReader` or a generic `R: CanonicalTrustReader`.

The helper compiles without importing Raft internals into the consumer-facing code path.

Runtime call sites may remain unchanged if production wiring would require broader churn.

## Phase 5 — Tests For Consumer Migration

Add focused tests for the new reader-backed peer-auth helper.

Required cases:

1. Authorized global node + not revoked => accepted / valid canonical status.
2. Unauthorized global node => rejected / not trusted.
3. Revoked node => rejected with revocation reason.
4. Canonical unavailable/unknown => existing behavior preserved or explicit degraded behavior documented.
5. Stale snapshot => behavior is explicit; do not silently treat stale as live unless existing policy says so.

Use `StaticCanonicalTrustReader` for most tests.

Avoid running a Raft cluster.

### Acceptance Criteria

Tests cover authorized, unauthorized, revoked, unavailable/unknown, and freshness handling.

No test requires network or real consensus.

## Phase 6 — Update Architecture Note

Update `architecture/mesh_trust_domains.md` with a short section:

```markdown
### Iteration 9 Consumer Migration

`peer_auth.rs` now has a reader-backed canonical status helper. It still owns identity verification, but canonical authorization/revocation answers can flow through `CanonicalTrustReader`. This is the first consumer-oriented use of the canonical seam.
```

If the pass only adds a test/helper and does not wire production call sites, state that clearly.

### Acceptance Criteria

The design note describes what was migrated and what remains deferred.

It does not claim broader module movement occurred.

## Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh peer_auth --features mesh
```

Then broader mesh checks:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If workspace checks fail for unrelated reasons, record the exact focused checks that passed and the unrelated failure.

## Completion Criteria

This iteration is complete when:

- snapshot freshness no longer uses fake `age_ms: 0` without explanation;
- revocation status semantics are clarified;
- at least one peer-auth canonical helper depends on `CanonicalTrustReader`;
- tests cover authorized, unauthorized, revoked, unknown/unavailable, and freshness behavior;
- no broad mesh module movement occurred;
- no runtime behavior changed without explicit tests and rationale;
- `architecture/mesh_trust_domains.md` documents the consumer migration.

## Follow-Up Recommendation

After this pass, migrate the next narrow policy-facing seam, likely `dht/key_policy.rs`, so DHT key authority classification can use canonical answers through `CanonicalTrustReader` rather than mixing advisory DHT/quorum/canonical concepts inline.
