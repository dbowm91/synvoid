# Mesh Key Policy Canonical Reader Migration — Iteration 11

## Goal

Migrate the next narrow consumer behind the canonical trust seam: `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`.

The objective is to separate DHT key authority classification from advisory DHT/quorum mechanics by using `CanonicalTrustReader` for canonical trust answers. This pass should keep propagation/storage behavior unchanged while making the policy boundary explicit.

The target invariant remains:

> DHT answers "what has been advertised?" Canonical/Raft answers "what is trusted?" Policy decides what may be accepted or acted on.

## Non-Goals

Do not reorganize the mesh module tree.

Do not split `synvoid-mesh` into multiple crates.

Do not rewrite DHT storage, DHT record propagation, Kademlia routing, record-store sync, or transport.

Do not migrate `threat_intel.rs`, `proxy.rs`, YARA/WASM, or service consumers in this pass.

Do not remove `RECORD_STORE_GLOBAL`.

Do not change runtime record propagation behavior unless an existing ambiguity is tested and explicitly fixed.

Do not require live Raft, DHT, networking, or cluster setup in tests.

## Phase 1 — Inventory `dht/key_policy.rs` Authority Decisions

Inspect the existing key policy module before making changes.

Run:

```bash
rg "DhtKeyPolicyTable|DhtRecordAuthorityClass|RaftOrQuorumGlobal|quorum|global|authority|canonical|remote_writes|record|Namespace|Org|Intel|Revocation|AuthorizedGlobalNodes|validate|accept" crates/synvoid-mesh/src/mesh/dht/key_policy.rs crates/synvoid-mesh/src/mesh/dht crates/synvoid-mesh/src/mesh/canonical.rs
```

Read at minimum:

- `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/quorum.rs`
- `crates/synvoid-mesh/src/mesh/canonical.rs`

Classify every authority decision in `key_policy.rs` as one of:

1. Pure advisory/DHT mechanics: TTL, key namespace, local write policy, routing/discovery hints.
2. Identity/signature mechanics: record signed by peer, signer format, envelope validity.
3. Canonical trust question: global-node authorization, org key trust, revocation, canonical intel/authority.
4. Policy composition: combines advisory input + identity + canonical answer into accept/reject/degraded decision.

### Acceptance Criteria

The pass targets only canonical trust questions and policy composition.

Pure DHT mechanics remain DHT-owned.

Signature verification remains identity/envelope-owned.

## Phase 2 — Add Reader-Backed Policy Helper Without Removing Existing API

Add a low-churn helper in `dht/key_policy.rs` that accepts `&dyn CanonicalTrustReader`.

Prefer adding a new helper rather than rewriting all existing paths immediately.

Suggested shape; adjust names/types to match existing code:

```rust
pub fn classify_key_authority_with_canonical_reader(
    policy: &DhtKeyPolicyTable,
    reader: &dyn CanonicalTrustReader,
    key: &DhtKey,
    signer_node_id: Option<&str>,
    authority_hint: Option<&DhtRecordAuthorityClass>,
) -> DhtKeyAuthorityDecision {
    // preserve existing classification where canonical reader is not relevant
}
```

If the file already has a suitable decision type, use it. Otherwise add a small internal/testable type with explicit outcomes:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtKeyAuthorityDecision {
    AcceptAdvisory,
    AcceptCanonical { freshness: CanonicalFreshness },
    Reject { reason: DhtKeyAuthorityRejectReason },
    Defer { reason: DhtKeyAuthorityDeferReason },
}
```

Avoid over-design. If existing return types are sufficient, keep them.

### Required Behavior

For keys/classes that currently require global canonical authority, use `reader.is_global_node_authorized(...)`.

For revocation-sensitive keys, use `reader.node_revocation_status(...)` where signer/node identity is available.

For org-key trust questions, use `reader.is_org_key_trusted(...)` only if `key_policy.rs` currently has the org ID/key ID context. If not, return `Unknown`/defer rather than fabricating context.

For threat-intel canonical trust questions, use `reader.is_threat_intel_canonical(...)` only when the intel ID is available.

For pure advisory keys, do not call the reader.

### Acceptance Criteria

A reader-backed policy helper exists.

Existing public APIs remain source-compatible.

No production DHT propagation path is rewired unless the call is extremely low-risk and covered by tests.

## Phase 3 — Preserve Advisory/CANONICAL Distinction In Names And Docs

Add rustdoc/comments where the helper is introduced.

The comments must state:

- DHT key policy is a policy boundary, not canonical storage.
- Advisory DHT records do not become trusted because they are signed.
- `CanonicalTrustReader` is used only for canonical trust answers.
- `Unknown` canonical answers must not be silently treated as canonical trust.
- Freshness must be surfaced in canonical accept/defer/reject paths where practical.

### Acceptance Criteria

Future contributors can see why `key_policy.rs` imports `canonical` without treating DHT records as authoritative.

## Phase 4 — Add Offline Tests With `StaticCanonicalTrustReader`

Add targeted tests in or near `dht/key_policy.rs`.

Required cases:

1. **Pure advisory key does not require canonical reader success**
   - Use a reader with no trusted entries.
   - Expected: same advisory decision as before.

2. **Global-authorized signer accepted for global-required key/class**
   - Reader contains signer in `authorized_global_nodes`.
   - Expected: canonical/global-required path accepts or returns canonical success.

3. **Unauthorized signer rejected or deferred for global-required key/class**
   - Reader lacks signer authorization.
   - Expected: explicit reject/defer, not advisory accept.

4. **Revoked signer rejected before global authorization success matters**
   - Reader contains signer in both `authorized_global_nodes` and `revoked_nodes`.
   - Expected: revoked rejection wins.

5. **Unavailable canonical state behavior explicit**
   - Reader freshness `Unavailable`.
   - For global-required key/class, expected behavior should be explicit: likely reject/defer, not accept.
   - For advisory-only key/class, expected behavior remains advisory.

6. **Stale canonical state behavior explicit**
   - Reader freshness `Stale { age_ms: ... }`.
   - If current policy accepts stale canonical trust, test that and comment future policy may tighten.
   - If current policy defers/rejects stale, test that.

7. **Unknown canonical decision not treated as trusted**
   - Use a custom mock reader if `StaticCanonicalTrustReader` cannot produce `Unknown` for a needed method.
   - Expected: explicit defer/reject, not canonical accept.

### Acceptance Criteria

Tests exercise the new helper without live Raft/DHT/networking.

Tests distinguish advisory-only keys from canonical-required keys.

Tests prove revoked and unknown canonical status are not silently accepted.

## Phase 5 — Do Not Wire Broad Production Paths Yet

This pass should generally stop at helper + tests.

If there is one obvious low-risk internal caller in `key_policy.rs` that can switch to the helper without changing behavior, it may be updated. Otherwise defer production call-site migration to the next pass.

### Acceptance Criteria

No broad behavior change in record-store ingress, sync, publish, or replication.

Any changed call site is covered by tests and documented in the architecture note.

## Phase 6 — Update Architecture Note

Update `architecture/mesh_trust_domains.md` with an Iteration 11 note.

Suggested text:

```markdown
### Iteration 11 DHT Key Policy Canonical Reader

`dht/key_policy.rs` now has a reader-backed policy helper that uses `CanonicalTrustReader` for canonical authority questions while preserving advisory DHT mechanics. Advisory records remain advisory; signed records are not automatically authorized; unknown/unavailable canonical answers are explicit and are not silently treated as trust. This pass added helper-level tests and did not broadly rewire record propagation/storage paths.
```

Adjust the note if a small production call-site was actually migrated.

### Acceptance Criteria

The architecture note accurately describes what changed and what remains deferred.

No stale follow-up language claims the canonical seam still needs to be implemented.

## Phase 7 — Clean Up Stale Follow-Up Text

While updating `architecture/mesh_trust_domains.md`, remove or correct stale wording that still says:

> The next pass should implement the chosen first seam only (`CanonicalTrustReader` + explicit advisory record types + snapshot freshness).

That seam already exists. Replace with the current next-step sequence:

1. key-policy helper and tests;
2. then optional production wiring of key-policy ingress;
3. then service consumers only after policy/advisory source boundaries are clearer.

### Acceptance Criteria

The architecture note follow-up section reflects the current state through Iteration 11.

## Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh peer_auth --features mesh
cargo test -p synvoid-mesh key_policy --features mesh
```

Then broader mesh checks:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broad workspace checks fail for unrelated reasons, record the focused checks that passed and the unrelated failure.

## Completion Criteria

This iteration is complete when:

- `dht/key_policy.rs` has a reader-backed canonical authority helper;
- helper docs preserve the advisory-vs-canonical distinction;
- tests cover advisory-only, global-authorized, unauthorized, revoked, unavailable, stale, and unknown canonical cases;
- no broad record propagation/storage behavior changes occur;
- architecture docs record Iteration 11 and remove stale follow-up wording;
- the repo is ready for a later production wiring pass if desired.

## Follow-Up Recommendation

After this pass, decide whether to wire the new key-policy helper into the actual DHT record ingress path (`record_store_message.rs` / signed-record handling) or first add an `AdvisoryRecordSource` seam. Do not move service consumers (`threat_intel.rs`, `proxy.rs`, YARA/WASM) until key-policy and advisory-source boundaries are stable.
