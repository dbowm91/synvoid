# DHT/Raft Boundary Follow-up Hardening Plan

## Goal

Close the remaining enforcement gaps after the first DHT/Raft boundary hardening pass.

The current repo has the right scaffolding: explicit DHT key policies, capability checks routed through the policy table, signed DHT records, signed record-push envelopes, ingress-context storage, strict signing defaults, authority freshness config, and signed Raft attestations. This follow-up pass should not redesign the architecture. It should wire enforcement consistently, remove bypass footguns, and update stale docs/tests.

## Current baseline

Already present and should be preserved:

- `DhtRecordAuthorityClass`, `DhtKeyPolicy`, and `DhtKeyPolicyTable`
- capability verification delegated through the key policy table
- direct DHT write rejection for Raft-owned keys
- `store_record_from_ingress(...)`
- signed `DhtRecordPush` envelope verification
- strict-by-default config for signed sync, anti-entropy, and record push
- `SignedRaftAttestation`
- `AuthorityFreshnessConfig`

## Non-negotiable invariants

1. Every remote DHT message that carries records must have either a verified envelope signature or an explicit, bounded, default-off compatibility mode.

2. Per-record validation does not replace envelope validation. Both are needed for DHT sync, anti-entropy, and push paths.

3. Raft attestations must bind to the exact value being attested, not just namespace/key/commit index.

4. DNS zone ownership must not be mutable through remote DHT capability alone.

5. Remote network handlers must not be able to pass an arbitrary `is_local_origin = true` into storage APIs.

6. Documentation must match the implemented verification state.

## Phase 1: Enforce inbound `DhtAntiEntropyRequest` signatures (✅ Complete)

The inbound handler now destructures `nonce`, `signature`, and `signer_public_key` and enforces `require_signed_anti_entropy_requests`. Unsigned requests are rejected by default unless an active `unsigned_anti_entropy_compat_until_unix` window exists. Signature verification uses `verify_dht_anti_entropy_request_envelope_signature()`. The verified signer is bound to the claimed `node_id` via `verify_envelope_signer_binding()`. In strict/global-node mode, peer/node mismatch is rejected.

## Phase 2: Verify `DhtAntiEntropyResponse` envelope before applying records (✅ Complete)

The anti-entropy response handler now verifies the response envelope signature before applying records. Verification covers request ID, responder node ID, root hash, record count, timestamp, and record-set digest. `record_set_digest` is recomputed from `missing_records` before verification to reject tampered record sets. Records are stored only after envelope verification passes. Empty responses are signed by default; unsigned empty responses are accepted only behind explicit compatibility mode.

## Phase 3: Bind `SignedRaftAttestation` to exact value digest (✅ Complete)

`SignedRaftAttestation` now includes a `value_hash` field in `RaftAttestation` that must match the record's content digest. The digest is included in `signable_content`. Protocol version was bumped to 2. V1 attestations without `value_hash` are rejected by default unless `allow_v1_raft_attestations` is set in config. `validate_peer_role()` accepts Raft attestation for Edge node validation, and the attestation is verified against the authorized signer.

## Phase 4: Clarify and harden DNS authority policy (✅ Complete)

`DnsZone` is now classified as `RaftOrQuorumGlobal` with `remote_writes_allowed = false` in `DhtKeyPolicyTable`. DNS zone ownership records can only be written via Raft consensus or quorum attestation, not via direct DHT capability. `DnsRecord` remains capability-mediated mutable content under an owned zone. The key policy table enforces these classifications at ingress.

## Phase 5: Seal raw record-store API footgun (✅ Complete)

`store_record(record, source_reputation, is_local_origin)` has been removed as a public API. The public surface is now `store_local_record(record, source_reputation)` for locally generated records and `store_record_from_ingress(record, &ingress_ctx, source_reputation)` for mesh/remote records. `store_record_verified_internal(...)` remains `pub(crate)` and is documented as only callable by typed wrappers. No public or crate-visible API accepts a caller-supplied `is_local_origin: bool` for general record storage.

## Phase 6: Update stale docs and verification matrix

Files to update:

- `architecture/mesh_deep_dive.md`
- `architecture/mesh.md`
- `docs/WAF_MESH.md`
- `plans/dht_raft_boundary_hardening.md`, if treated as living documentation
- any stale references to removed quorum/commit message types

Required doc corrections:

- `DhtRecordPush` now has a signature field and is verified by default.
- `DhtAntiEntropyRequest` should be marked verified only after inbound handler enforcement is wired.
- `DhtAntiEntropyResponse` should be marked verified only after envelope verification is enforced before applying records.
- Raft attestations should be described as value-bound after Phase 3.
- DNS authority semantics should be documented explicitly.
- DHT should be described as distributing signed/Raft-attested artifacts, not deciding authority.

Acceptance criteria:

- Verification matrix matches current code.
- Docs distinguish:
  - canonical Raft authority state;
  - DHT-distributed authority artifacts;
  - DHT soft state;
  - local-only runtime state.
- No docs imply that DHT creates organization, revocation, global-node, or DNS ownership authority.

## Phase 7: Add adversarial regression tests

Add focused tests rather than broad happy-path tests.

Suggested test groups:

### Anti-entropy request tests

- unsigned request rejected by default;
- unsigned request accepted only during explicit compatibility window;
- missing nonce rejected;
- bad signature rejected;
- stale timestamp rejected;
- wrong signer rejected;
- peer/node mismatch rejected in strict/global mode.

### Anti-entropy response tests

- forged response rejected;
- tampered record set rejected by digest mismatch;
- missing signature rejected by default;
- valid envelope but invalid embedded record rejected;
- valid signed response accepted.

### Raft attestation tests

- valid value-bound attestation accepted;
- wrong value hash rejected;
- wrong namespace rejected;
- wrong key ID rejected;
- unauthorized signer rejected;
- revoked signer rejected where revocation context is available;
- structurally plausible unsigned attestation rejected.

### DNS authority tests

- remote zone ownership write rejected without Raft/quorum proof;
- owner-signed DNS record under valid zone root accepted;
- DNS record under wrong zone root rejected;
- DNS zone/record policy table entries match expected classes.

### Store API bypass tests

- remote path cannot use raw `store_record(..., is_local_origin = true)`;
- authority key cannot be stored through DHT ingress without required proof;
- unknown remote key remains denied by default.

## Suggested implementation order

1. ~~Enforce inbound `DhtAntiEntropyRequest` signatures.~~ ✅ Done
2. ~~Enforce `DhtAntiEntropyResponse` envelope verification.~~ ✅ Done
3. ~~Seal raw storage API exposure.~~ ✅ Done
4. ~~Add value-hash binding to `SignedRaftAttestation`.~~ ✅ Done
5. ~~Reclassify/split DNS authority policy.~~ ✅ Done
6. Add adversarial tests.
7. Update docs and verification matrix.

## Out of scope

- Replacing DHT with Raft.
- Extracting a new consensus crate.
- Rewriting routing/discovery topology.
- Changing CA/key ceremony design.
- Removing all compatibility modes without an explicit migration decision.

## Final acceptance checklist

- inbound anti-entropy requests are signed and verified by default. ✅
- anti-entropy responses are envelope-verified before record application. ✅
- record-push remains signed and verified by default. ✅
- Raft attestations bind to exact value digest. ✅
- DNS zone ownership cannot be remotely created through capability-only DHT writes. ✅
- remote handlers cannot bypass ingress validation. ✅
- docs accurately reflect verification state. (Phase 7 pending)
- adversarial tests cover forged, unsigned, stale, replayed, wrong-signer, wrong-value, wrong-namespace, and remote-write-bypass cases. (Phase 6 pending)
