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

## Phase 1: Define a DHT key-family authority policy table

Create an explicit policy table that maps every DHT key family to its required proof type.

Suggested new type location:

- `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`

Suggested shape:

```rust
pub enum DhtRecordAuthorityClass {
    SoftLocal,
    SignedByRecordOwner,
    CapabilityAttested,
    QuorumSignedGlobal,
    RaftAttestedGlobal,
    RaftOrQuorumGlobal,
    LocalOnly,
}

pub struct DhtKeyPolicy {
    pub authority_class: DhtRecordAuthorityClass,
    pub ttl_required: bool,
    pub immutable_after_create: bool,
    pub remote_writes_allowed: bool,
    pub required_capability: Option<&'static str>,
}
```

Minimum classifications to encode:

- `authorized_global_nodes:*`: Raft-attested global only.
- `revocation:*` / global node revocations: Raft-attested global only.
- `org:*`, `org_public_key:*`, organization key roots: Raft or quorum global.
- DNS zone ownership and domain registration: Raft or quorum global, unless there is already a tenant-owner delegation model; in that case require owner signature plus globally attested ownership root.
- DNS records under an already-owned zone: owner-signed or tenant-capability-signed.
- YARA manifests and YARA rule content: capability-attested and signed.
- Threat indicators: source-signed with capability attestation for normal observations; Raft only for canonical global threat policy.
- `node_info:*`: signed-by-node, TTL-bound, non-authoritative.
- provider/upstream/routing hints: signed-by-node or owner-signed, TTL-bound, non-authoritative.
- peer liveness, latency, provider stats: soft local or signed-by-node, TTL-bound, never canonical.

Then route all DHT ingestion decisions through this table. Avoid scattered string-prefix decisions where possible. `CapabilityAccessVerifier::key_requires_capability` can either delegate to this policy table or be replaced by it.

Acceptance criteria:

- Every `DhtKey` variant has an explicit authority policy.
- Unknown key families default to deny for remote writes.
- Authority-adjacent key families cannot be accepted without Raft/quorum proof.
- Tests cover at least Org, DNS zone ownership, DNS records, YARA rules, threat indicators, node info, upstream/provider hints, revocations, and authorized Global Nodes.

## Phase 2: Make remote DHT ingestion context mandatory

Audit all paths that call into DHT record insertion/update APIs.

The low-level `DhtRecordStore` may remain a simple `HashMap`-backed local store, but remote ingestion should be forced through a validation layer such as:

```rust
pub fn ingest_remote_record(
    &self,
    record: SignedDhtRecord,
    context: DhtRecordIngressContext,
    verifier: &DhtRecordVerifier,
) -> Result<(), DhtError>
```

This validation layer should:

- resolve the key policy from Phase 1;
- verify envelope signature where required;
- verify record signature where required;
- verify peer/node binding where required;
- verify capability attestation where required;
- verify quorum signatures where required;
- verify Raft attestation where required;
- enforce timestamp windows and TTL;
- enforce immutable-key rules;
- reject remote writes for `LocalOnly` keys;
- emit structured audit events on rejection.

Important: local creation paths may use a separate constructor, but should still produce records that remote nodes can verify.

Acceptance criteria:

- No remote network message handler can call raw `put`, `insert`, or CRUD storage methods without passing through an ingress validation path.
- Tests prove direct remote acceptance is not possible for Org, DNS zone, revocation, and authorized Global Node records.
- Rejections include enough reason data for audit/debugging without leaking private keys or sensitive payload contents.

## Phase 3: Finish DHT message verification gaps

The current architecture notes identify two remaining weak spots:

- `DhtAntiEntropyRequest`: peer/node binding is enforced, but `signer_public_key` is still unused.
- `DhtRecordPush`: timestamp is validated, but the message has no signature field.

Patch both.

For `DhtAntiEntropyRequest`:

- include or require an envelope signature over `DhtAntiEntropyRequestSignable`;
- verify `signer_public_key` against the claimed node identity;
- bind TLS peer identity to the claimed `node_id` where strict mode or Global Node mode requires it;
- keep compatibility fallback only behind an explicit config flag, default off if this is not already the case.

For `DhtRecordPush`:

- add a signature field and signer identity if absent;
- sign over request ID, source node ID, key, value digest, timestamp, nonce, TTL/sequence metadata, and protocol version;
- verify before record validation/ingestion;
- reject unsigned pushes by default;
- add compatibility mode only if needed for migration, explicitly logged and disabled by default.

Acceptance criteria:

- `DhtAntiEntropyRequest` verifies the public key it carries or stops carrying unused public-key material.
- `DhtRecordPush` has signature coverage equivalent to the other priority DHT envelopes.
- Tests cover unsigned push rejection, tampered payload rejection, mismatched signer rejection, stale timestamp rejection, replayed nonce rejection, and strict-mode peer/node mismatch rejection.

## Phase 4: Cryptographically bind Raft attestations

Current peer-auth validation treats a Raft attestation as valid if namespace/key/timestamp/commit index look plausible. That is structurally useful but insufficient as an authority proof unless the attestation itself is signed or otherwise chained to an authorized Global Node proof.

Implement a signed Raft-attestation envelope.

Suggested structure:

```rust
pub struct SignedRaftAttestation {
    pub attestation: RaftAttestation,
    pub signer_node_id: String,
    pub signer_public_key: String,
    pub signature: Vec<u8>,
    pub protocol_version: u32,
}
```

The signable content should include at least:

- namespace;
- key ID;
- value hash or record digest, not just key ID;
- leader ID or committing node ID;
- commit index;
- term, if available;
- timestamp;
- validity window or epoch;
- protocol version.

Validation should require:

- signer is an authorized Global Node at or after the relevant epoch;
- signer is not revoked according to the locally known revocation state;
- signature verifies over canonical bytes;
- namespace/key/value digest match the DHT-delivered record;
- attestation is fresh enough for the record class;
- commit index and/or epoch is not older than local anti-rollback policy allows.

Also consider whether attestations should be issued by the Raft leader only or by any Global Node that has applied the committed entry. Either can be valid, but the semantics should be explicit.

Acceptance criteria:

- `validate_member_certificate_with_raft_attestation` no longer accepts an unsigned or structurally plausible attestation as sufficient proof.
- Tests cover forged attestation rejection, valid signed attestation acceptance, wrong namespace rejection, wrong key rejection, wrong value hash rejection, revoked signer rejection, and stale attestation rejection.

## Phase 5: Clarify Raft vs DHT ownership in docs and comments

Update architecture docs to remove ambiguous language suggesting that DHT distributes organizational keys, routing policies, or global policy as authority.

Recommended wording:

- DHT distributes signed or Raft-attested records.
- DHT does not decide trust, ownership, revocation, or global policy.
- Raft commits canonical global authority records.
- Edge nodes cache and gossip Raft-derived artifacts but independently verify them.
- Soft-state DHT records are advisory and TTL-bound.

Files to update:

- `architecture/mesh.md`
- `architecture/mesh_deep_dive.md`
- `docs/WAF_MESH.md`
- `plans/mesh_consensus_boundary.md`, if kept as living notes
- any stale references to removed `DhtRecordCommit`, `QuorumStoreRequest`, or `QuorumSignatureResp`

Acceptance criteria:

- Docs distinguish canonical authority state from DHT-distributed artifacts.
- Docs contain a table listing which state belongs to Raft, which belongs to DHT, and which belongs to local-only runtime state.
- Any mention of DHT-distributed OrgPublicKey, DNS ownership, or policy records explicitly states required proof type.

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

1. Add key-family policy table and tests.
2. Route capability checks through the policy table.
3. Make remote DHT ingestion use explicit context and proof validation.
4. Patch `DhtAntiEntropyRequest` and `DhtRecordPush` signature/binding gaps.
5. Implement signed Raft attestations and update peer-auth validation.
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

- Raft remains the only canonical authority source for global trust state.
- DHT cannot create authority records independently.
- Authority-adjacent DHT records require signed Raft/quorum proof.
- Soft-state DHT records are TTL-bound and advisory.
- Remote DHT writes require explicit ingress validation context.
- `DhtAntiEntropyRequest` and `DhtRecordPush` are fully signed/bound or rejected by default.
- Raft attestations are cryptographically verified, not structurally trusted.
- Tests cover forged, stale, replayed, unsigned, wrong-signer, wrong-namespace, and wrong-value cases.
- Docs accurately describe the enforced architecture.
