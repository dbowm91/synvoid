# Mesh Trust-Domain Final Wrap-Up — Iteration 15

## Goal

Close this mesh trust-domain track cleanly after the canonical-reader, peer-auth, key-policy, and DHT ingress-context work.

This is a final verification and cleanup pass, not another architecture expansion. The objective is to ensure the code, tests, docs, and handoff notes agree about the current state before moving to future work such as `AdvisoryRecordSource` or service-consumer migration.

Current intended stopping point:

- `CanonicalTrustReader` exists as the canonical trust seam.
- `peer_auth.rs` has a staged reader-backed canonical status helper with explicit tests.
- `dht/key_policy.rs` has reader-backed authority classification and an ingress adapter.
- `dht/ingress_policy.rs` carries optional `Arc<dyn CanonicalTrustReader>` for ingress policy.
- `DhtRecordIngressContext` can carry the optional policy context.
- Direct Push/Announce ingress should attach the configured context and route through `store_record_from_ingress`.
- Sync/replay/local/quorum/Raft apply paths should remain outside this gate.

## Non-Goals

Do not migrate service consumers (`threat_intel.rs`, `proxy.rs`, YARA/WASM) in this pass.

Do not introduce the full `AdvisoryRecordSource` seam in this pass.

Do not broaden the DHT ingress gate beyond the intended Push/Announce scope.

Do not reorganize the mesh module tree.

Do not remove `RECORD_STORE_GLOBAL`.

Do not refactor Raft, DHT replication, Kademlia routing, record-store sync, or transport.

Do not add new consensus behavior.

Do not tighten stale-canonical policy globally.

## Phase 1 — Verify Iteration 14 Wiring Actually Landed

Inspect the actual code, not just docs.

Run:

```bash
rg "DhtIngressPolicyContext|with_policy_context|policy_context\(|check_dht_ingress_authority|validate_dht_key_authority_for_ingress|IngressPath::Push|IngressPath::Announce|handle_record_announce|DhtRecordPush|store_record_from_ingress|set_ingress_policy_context|ingress_policy_context" crates/synvoid-mesh/src/mesh/dht crates/synvoid-mesh/src/mesh
```

Confirm:

1. A `RecordStoreManager`-level or equivalent carrier exists for `Option<DhtIngressPolicyContext>`.
2. The carrier defaults to disabled/`None`.
3. Push context construction attaches the carrier.
4. Announce context construction attaches the carrier.
5. `store_record_from_ingress` consults the gate only for non-local `Push`/`Announce`.
6. Sync/replay/local/quorum/Raft apply paths do not attach or enforce the gate.
7. No global state is used to obtain the reader.
8. No concrete `SnapshotCanonicalTrustReader` is constructed in DHT ingress files.

### Acceptance Criteria

The implementation matches the architecture note.

If it does not, fix the implementation or correct the architecture note before proceeding.

## Phase 2 — Tighten Tests Around The Final Ingress Scope

Ensure tests prove the exact intended boundary.

Required tests, either already present or added now:

1. **Disabled/default behavior**
   - Default manager/context has no reader.
   - Push/Announce-style ingress preserves legacy behavior.

2. **Configured Push rejects unauthorized canonical-required key**
   - Configured context reaches `store_record_from_ingress`.
   - Unauthorized global-required key is rejected.

3. **Configured Announce rejects unauthorized canonical-required key**
   - Same as Push, but Announce path.

4. **Configured Push/Announce accepts advisory key subject to existing validation**
   - Canonical gate does not reject advisory-only records.

5. **Configured Push/Announce rejects revoked signer**
   - Revocation wins before authorization.

6. **Configured Push/Announce treats unavailable/unknown canonical state as rejection at ingress layer**
   - Defer from policy is mapped to reject at remote ingress because there is no defer/retry queue.

7. **Sync/replay remains outside this gate**
   - SnapshotSync/SyncResponse/AntiEntropy context does not trigger the Push/Announce-only canonical gate even if a context exists.

8. **Local writes remain outside this gate**
   - `store_local_record` / local ingress does not require a canonical reader.

### Practical Test Guidance

Do not weaken signature/content-hash validation to make tests easier.

If full record construction is heavy, factor only the gate predicate into a small private or `pub(crate)` helper and test it directly:

```rust
fn should_apply_direct_ingress_canonical_gate(ctx: &DhtRecordIngressContext) -> bool { ... }
```

Then keep one integration-style test proving the helper is called from `store_record_from_ingress`.

### Acceptance Criteria

Tests prove both the enabled and disabled states.

Tests prove the boundary is exactly Push/Announce, not sync/replay/local.

## Phase 3 — Remove Or Fix Stale Comments And Overclaims

Search for stale wording introduced during Iterations 8–14.

Run:

```bash
rg "next pass should implement|first seam only|wiring remains deferred|not yet wired|Iteration 11|Iteration 12|Iteration 13|Iteration 14|stale|placeholder|age_ms: 0|NotConfigured preserves legacy" architecture docs crates/synvoid-mesh/src plans
```

Fix only stale or misleading text. Do not rewrite all docs.

Required checks:

- `architecture/mesh_trust_domains.md` accurately reflects final state.
- Any mention of Push/Announce wiring matches actual code.
- Follow-up recommendations no longer say to wire what is already wired.
- Stale `age_ms: 0` wording is gone unless referring to historical context.
- `GLOBAL_ORIGIN` exemption wording remains clear and accurate.
- Revocation wording says “not revoked” rather than “fully trusted” where applicable.

### Acceptance Criteria

Docs and comments no longer overclaim or underclaim the current state.

## Phase 4 — Public API / Export Sanity Check

Review exports and visibility.

Run:

```bash
rg "pub use ingress_policy|pub mod ingress_policy|DhtIngressPolicyContext|DhtIngressGateOutcome|DhtIngressPolicyError|DhtKeyAuthorityDecision|CanonicalTrustReader" crates/synvoid-mesh/src/mesh/dht crates/synvoid-mesh/src/mesh/mod.rs crates/synvoid-mesh/src/lib.rs
```

Confirm:

- `DhtIngressPolicyContext` and `DhtIngressGateOutcome` are exported only where useful.
- `DhtIngressPolicyError` remains in key-policy layer unless callers need it.
- DHT modules do not expose concrete canonical reader implementations unnecessarily.
- `CanonicalTrustReader` remains the abstraction consumed outside canonical internals.
- No accidental public API churn is introduced.

### Acceptance Criteria

The public surface is minimal but usable by the higher-level component that will inject the reader.

## Phase 5 — Dependency And Import Direction Audit

Run import-direction checks manually.

Search:

```bash
rg "raft::|EdgeReplicaManager|SnapshotCanonicalTrustReader|RECORD_STORE_GLOBAL|get_global_record_store|CanonicalTrustReader|DhtIngressPolicyContext" crates/synvoid-mesh/src/mesh/dht crates/synvoid-mesh/src/mesh/peer_auth.rs crates/synvoid-mesh/src/mesh/canonical.rs
```

Expected:

- `canonical.rs` may depend on Raft/edge replica internals for the snapshot adapter.
- `peer_auth.rs` may depend on `CanonicalTrustReader`, not Raft internals for the staged helper.
- `dht/key_policy.rs` and `dht/ingress_policy.rs` may depend on `CanonicalTrustReader`, not `SnapshotCanonicalTrustReader` or `EdgeReplicaManager`.
- DHT ingress files may carry `DhtIngressPolicyContext`, not concrete canonical implementations.
- No new use of `RECORD_STORE_GLOBAL` appears in this path.

### Acceptance Criteria

The intended import direction is preserved.

No concrete canonical implementation leaks into DHT ingress.

## Phase 6 — Focused Validation Matrix

Run focused tests first:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh peer_auth --features mesh
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh ingress_policy --features mesh
cargo test -p synvoid-mesh record_store_crud --features mesh
cargo test -p synvoid-mesh record_store_message --features mesh
```

Then run broader checks:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broader checks fail for unrelated existing reasons, document:

- the exact command;
- the exact failure;
- why it appears unrelated;
- which focused checks passed.

### Acceptance Criteria

Focused mesh trust-domain checks pass or unrelated failures are recorded precisely.

## Phase 7 — Final Architecture Status Note

Update `architecture/mesh_trust_domains.md` with a final status section.

Suggested text:

```markdown
### Iteration 15 Final Status

The canonical trust-domain seam is now staged through peer auth, DHT key policy, and direct DHT Push/Announce ingress. Canonical trust answers flow through `CanonicalTrustReader`; DHT policy and ingress consume the trait, not concrete Raft internals. Disabled ingress policy context preserves legacy behavior. Configured Push/Announce ingress rejects canonical-required records on unauthorized, revoked, unavailable, or unknown canonical state. Advisory-only records remain advisory. Sync/replay/local/quorum/Raft apply paths were intentionally not broadened into this gate.

This track stops here. The next architectural step should be `AdvisoryRecordSource` before migrating service consumers.
```

Adjust if the implementation differs.

### Acceptance Criteria

The architecture note clearly marks this track as complete/stopped.

Follow-up points to `AdvisoryRecordSource`, not immediate service-consumer migration.

## Completion Criteria

This wrap-up is complete when:

- implementation and architecture docs agree;
- Push/Announce context wiring is either real and tested or explicitly corrected as deferred;
- tests cover disabled/configured and boundary behavior;
- no globals or concrete canonical reader construction are introduced in DHT ingress;
- import directions remain clean;
- stale comments are removed;
- focused validation commands pass or failures are precisely documented;
- the architecture note declares this trust-domain track complete.

## Final Follow-Up Recommendation

After this wrap-up, do not continue expanding the same seam directly into service consumers. The next planned architecture track should be:

1. introduce `AdvisoryRecordSource` as a read-only advisory DHT access seam;
2. route policy composition through canonical + advisory seams;
3. only then migrate service consumers such as `threat_intel.rs`, `proxy.rs`, and YARA/WASM to consume policy outputs rather than raw DHT or Raft internals.
