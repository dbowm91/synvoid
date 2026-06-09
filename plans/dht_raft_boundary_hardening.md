# DHT/Raft Boundary Hardening Plan

## Goal

Harden Synvoid's mesh control-plane boundary so Raft remains the only source of canonical global authority state, while the DHT remains a non-authoritative discovery, cache, dissemination, and anti-entropy substrate.

The current architecture is directionally correct: Raft is used for Global Node authority state, organization key roots, revocations, authorized Global Nodes, and selected strongly consistent intelligence; DHT is used for peer/service discovery, signed record propagation, sync, and eventually consistent mesh state. The remaining work is to make this separation mechanically enforced, testable, and difficult to bypass.

## Non-negotiable invariants

1. Raft decides canonical global truth.

   Canonical authority state must be committed through the Global Node Raft cluster. This includes at minimum:

   - authorized Global Nodes
   - Global Node revocations
   - organization public-key roots / organization key authority
   - canonical tenant or namespace ownership, if present
   - global emergency policy / kill-switch records, if present
   - CA / trust-anchor epochs, if present

2. DHT never creates authority.

   DHT may store, cache, distribute, and anti-entropy-sync authority records only if those records are independently verifiable as Raft-attested, quorum-signed, owner-signed, or otherwise chained to an authorized trust root.

3. Edge and Origin nodes must verify records locally.

   A node receiving an authority-adjacent record from DHT must be able to reject it based on local verification alone. Trust must not depend on the DHT peer, route, or ingestion path.

4. Remote DHT writes must go through explicit ingress policy.

   Remote records should not be insertable into the low-level record store without an explicit `DhtRecordIngressContext` or equivalent validation context.

5. Raft attestations must be cryptographically bound.

   A `commit_index > 0`, namespace match, timestamp, and key ID match are not sufficient by themselves. A Raft attestation must be signed by an authorized Global Node, chained to the current authorized Global Node set, or verified through a comparable authority proof.

6. The low-level DHT store may remain dumb, but its remote callers may not.

   `DhtRecordStore` can remain a simple local map, but external ingestion APIs must enforce proof requirements before records reach it.

## Relevant files to inspect first

Primary architecture and design notes:

- `architecture/mesh.md`
- `architecture/mesh_deep_dive.md`
- `plans/mesh_consensus_boundary.md`
- `docs/WAF_MESH.md`
- `docs/adr/ADR-001-global-nodes-trust-anchors.md`

Raft/control-plane implementation:

- `crates/synvoid-mesh/src/mesh/raft/state_machine.rs`
- `crates/synvoid-mesh/src/mesh/raft/instance.rs`
- `crates/synvoid-mesh/src/mesh/raft/network.rs`
- `crates/synvoid-mesh/src/mesh/raft/client.rs`
- `crates/synvoid-mesh/src/mesh/raft/edge_replica.rs`
- legacy mirror, if still active: `src/mesh/raft/`

DHT implementation:

- `crates/synvoid-mesh/src/mesh/dht/signed.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store_crud.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store_sync.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store_persist.rs`
- `crates/synvoid-mesh/src/mesh/dht/capability_access.rs`
- `crates/synvoid-mesh/src/mesh/dht/capability_attestation.rs`
- `crates/synvoid-mesh/src/mesh/dht/network_policy.rs`
- `crates/synvoid-mesh/src/mesh/transport_dht.rs`
- legacy mirror, if still active: `src/mesh/dht/`

Peer and authority validation:

- `crates/synvoid-mesh/src/mesh/peer_auth.rs`
- `crates/synvoid-mesh/src/mesh/protocol.rs`
- `crates/synvoid-mesh/src/mesh/organization.rs`
- `crates/synvoid-mesh/src/mesh/cert.rs`
- `crates/synvoid-mesh/src/mesh/config.rs`

## Phase 1: Define a DHT key-family authority policy table (✅ Complete)

The policy table exists at `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`. Every DHT key family maps to an explicit `DhtKeyPolicy` with authority class, TTL requirements, immutability, remote-write permission, and required capability. Unknown key families default to deny for remote writes. `CapabilityAccessVerifier` delegates to this policy table for capability checks.

## Phase 2: Make remote DHT ingestion context mandatory (✅ Complete)

Remote ingestion now goes through `store_record_from_ingress()` which enforces key-policy and proof requirements. Raw `store_record()` is `pub(crate)` and cannot be called from outside the crate. Local creation uses `store_local_record()` which always sets `is_local_origin = true`. All callers have been updated.

## Phase 3: Finish DHT message verification gaps (✅ Complete)

The remaining weak spots identified in earlier architecture notes have been patched:

- `DhtAntiEntropyRequest`: envelope signature over `DhtAntiEntropyRequestSignable` is now verified; `signer_public_key` is validated against authorized global node keys on global nodes; unsigned requests are rejected by default with optional compatibility window.
- `DhtRecordPush`: envelope signature is enforced; records without valid signatures are rejected; optional compatibility window is config-controlled and off by default.

## Phase 4: Cryptographically bind Raft attestations (✅ Complete)

Peer-auth validation now treats Raft attestations as valid only when cryptographically signed and bound to the exact value being attested. The `SignedRaftAttestation` struct includes a `value_hash` field that must match the record's content digest. Protocol version was bumped to 2; v1 attestations (without value_hash) remain accepted for backward compatibility.

## Phase 5: Clarify Raft vs DHT ownership in docs and comments (✅ Complete)

Architecture docs have been updated to remove ambiguous language. DHT-distributed DNS zone ownership records are now explicitly classified as `RaftOrQuorumGlobal` with `remote_writes_allowed: false`. Documentation now distinguishes DNS zone ownership (authority-adjacent, proof-gated) from DNS records under an owned zone (capability-attested).

Files updated:

- `architecture/mesh.md`
- `architecture/mesh_deep_dive.md`
- `plans/mesh_consensus_boundary.md`
- `plans/dht_raft_boundary_hardening.md` (this file)

## Phase 6: Add boundary tests and adversarial regression tests

Add tests that encode the actual security boundary rather than just happy-path serialization.

Suggested test groups:

1. DHT key policy tests

- every key family maps to exactly one policy;
- unknown remote key family is denied;
- known soft-state keys require TTL;
- authority keys require Raft/quorum proof.

2. Remote ingestion tests

- remote OrgPublicKey without proof is rejected;
- remote OrgPublicKey with invalid quorum is rejected;
- remote OrgPublicKey with valid signed Raft attestation is accepted;
- remote GlobalNodeRevocation without Raft proof is rejected;
- remote AuthorizedGlobalNode without Raft proof is rejected;
- remote DNS zone ownership without authority proof is rejected;
- remote DNS record under valid ownership root is accepted only with owner signature.

3. DHT message verification tests

- unsigned `DhtRecordPush` rejected;
- tampered signed push rejected;
- replayed nonce rejected;
- stale timestamp rejected;
- signer/source mismatch rejected;
- anti-entropy request with wrong signer rejected.

4. Peer-auth and attestation tests

- unsigned `RaftAttestation` rejected;
- signed attestation from unauthorized Global Node rejected;
- signed attestation from revoked Global Node rejected;
- attestation for wrong value hash rejected;
- valid signed attestation accepted.

5. Bypass tests

- remote network handlers cannot reach raw store insertion APIs;
- raw store APIs are crate-private or clearly local-only if feasible;
- test-only helpers are gated behind `#[cfg(test)]`.

Use existing fuzz tests as a model where appropriate. The current repo already has Raft response fuzzing; similar fuzz harnesses for signed DHT envelopes and Raft attestation parsing would be useful.

Acceptance criteria:

- `cargo test -p synvoid-mesh dht` passes.
- `cargo test -p synvoid-mesh raft` passes.
- New tests fail before the hardening changes and pass after them.
- Compatibility fallbacks are explicitly tested and default-off.

## Phase 7: Reduce consensus/transport coupling without premature extraction

Do not extract `synvoid-consensus` yet. First make the internal boundary real.

Current coupling to preserve short-term:

- Raft can continue using mesh transport for AppendEntries, snapshots, votes, and health checks.
- Raft can remain inside `synvoid-mesh` until the trait boundary is proven.

Near-term cleanup:

- introduce or complete an internal `ConsensusTransport` trait;
- limit Raft's direct dependency on DHT discovery types;
- ensure Raft routing consumes resolved peer endpoints rather than initiating DHT lookups directly;
- keep peer health as transport-provided signal, not consensus-owned discovery logic;
- decouple Raft log/snapshot payload types from mesh-specific serialization where practical.

Acceptance criteria:

- Raft code sends consensus RPCs through a narrow transport trait or adapter.
- DHT discovery does not appear as a direct dependency in the Raft state machine.
- The state machine owns authority state only; transport owns reachability.
- No new crate extraction is attempted in this pass unless the trait has at least one real alternative implementation.

## Phase 8: Runtime policy decisions under stale authority state

Define fail-open/fail-closed behavior for stale authority artifacts.

Suggested defaults:

- Normal global policy updates: fail open using last valid signed epoch until grace expiry.
- Peer discovery: fail degraded using cached peers/bootstrap seeds.
- Threat intel: fail open/local; do not block traffic solely because global intel is stale.
- Revocation freshness exceeded: fail closed for Global Nodes and high-trust authority paths.
- CA/trust-root epoch stale beyond hard limit: fail closed or enter explicitly degraded mode.
- DHT soft-state stale: expire normally and remove from routing decisions.

Implementation targets:

- centralize freshness thresholds in mesh config;
- include authority epoch/validity windows in Raft-derived artifacts;
- expose metrics for stale authority state, rejected stale records, and degraded-mode entry;
- ensure logs distinguish stale soft state from stale authority state.

Acceptance criteria:

- Config exposes freshness thresholds for authority artifacts and DHT soft state separately.
- Tests cover stale but grace-valid authority records, grace-expired records, and stale soft-state expiry.
- Runtime logs/metrics make stale-state mode visible.

## Suggested implementation order

1. ~~Add key-family policy table and tests.~~ ✅ Done — `DhtKeyPolicyTable` in `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`
2. ~~Route capability checks through the policy table.~~ ✅ Done — `CapabilityAccessVerifier` delegates to policy table
3. ~~Make remote DHT ingestion use explicit context and proof validation.~~ ✅ Done — `store_record()` is `pub(crate)`, `store_local_record()` added, all callers updated
4. ~~Patch `DhtAntiEntropyRequest` and `DhtRecordPush` signature/binding gaps.~~ ✅ Done — envelope signatures enforced, signer_public_key verified against authorized global nodes
5. ~~Implement signed Raft attestations and update peer-auth validation.~~ ✅ Done — `SignedRaftAttestation` binds to exact value digest via `value_hash`, protocol version bumped to 2, v1 backward compat
6. Add adversarial regression tests.
7. Update docs to reflect enforced boundary.
8. Narrow Raft transport coupling behind a trait if time remains.

## Out of scope for this pass

- Replacing DHT with Raft.
- Extracting a new `synvoid-consensus` crate.
- Rewriting the mesh topology/discovery stack.
- Designing a new CA/key ceremony.
- Removing all compatibility modes in one pass if migration requires staged rollout.

## Final acceptance checklist

- Raft remains the only canonical authority source for global trust state. ✅
- DHT cannot create authority records independently. ✅
- Authority-adjacent DHT records require signed Raft/quorum proof. ✅
- Soft-state DHT records are TTL-bound and advisory. ✅
- Remote DHT writes require explicit ingress validation context. ✅
- `DhtAntiEntropyRequest` and `DhtRecordPush` are fully signed/bound or rejected by default. ✅
- Raft attestations are cryptographically verified, not structurally trusted. ✅
- Tests cover forged, stale, replayed, unsigned, wrong-signer, wrong-namespace, and wrong-value cases. (Phase 6 pending)
- Docs accurately describe the enforced architecture. (Phase 7 in progress)
