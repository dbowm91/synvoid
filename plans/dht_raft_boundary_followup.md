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

## Phase 1: Enforce inbound `DhtAntiEntropyRequest` signatures

Files to inspect:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`
- `crates/synvoid-mesh/src/mesh/config.rs`

Current issue:

`DhtAntiEntropyRequest` now has nonce/signature/signer fields and signing helpers exist, but the inbound handler appears to ignore `nonce`, `signature`, and `signer_public_key` before calling `handle_anti_entropy_request`.

Required changes:

- In the `MeshMessage::DhtAntiEntropyRequest` match arm, destructure `nonce`, `signature`, and `signer_public_key`.
- Enforce `self.config.require_signed_anti_entropy_requests`.
- If the request is unsigned and no active `unsigned_anti_entropy_compat_until_unix` window exists, reject.
- Verify with `verify_dht_anti_entropy_request_envelope_signature(...)`.
- Bind the verified signer to the claimed `node_id` where possible.
- In strict/global-node mode, reject peer/node mismatch where the transport identity does not match the claimed node.
- Log structured rejection reasons without exposing sensitive material.

Acceptance tests:

- unsigned anti-entropy request rejected by default;
- unsigned request accepted only inside explicit compatibility window;
- invalid signature rejected;
- missing nonce rejected;
- stale timestamp rejected;
- mismatched node ID rejected in strict/global mode;
- valid signed request accepted.

## Phase 2: Verify `DhtAntiEntropyResponse` envelope before applying records

Files to inspect:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`

Current issue:

`handle_anti_entropy_response` applies `missing_records` through `store_record_from_ingress`, which is good, but the response envelope signature appears ignored.

Required changes:

- Require envelope signature and signer public key for non-empty `missing_records` by default.
- Verify response signable content using:
  - request ID;
  - responder node ID;
  - root hash;
  - record count;
  - timestamp;
  - record-set digest.
- Recompute `record_set_digest` from `missing_records` before verification.
- Reject tampered record sets even if individual records pass signature validation.
- Decide whether empty/no-op anti-entropy responses must be signed. Prefer signing all responses by default; allow unsigned empty responses only behind explicit compatibility if needed.
- Store records only after response envelope verification passes.

Acceptance tests:

- forged response rejected;
- tampered record set rejected by digest mismatch;
- missing signature rejected by default;
- invalid signer rejected;
- stale response rejected;
- valid signed response accepted;
- per-record invalid signature still rejected even if envelope is valid.

## Phase 3: Bind `SignedRaftAttestation` to exact value digest

Files to inspect:

- `crates/synvoid-mesh/src/mesh/peer_auth.rs`
- `crates/synvoid-mesh/src/mesh/raft/state_machine.rs`
- `crates/synvoid-mesh/src/mesh/organization.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`

Current issue:

`SignedRaftAttestation` validates a signature over namespace, key ID, leader ID, commit index, timestamp, and protocol version. It does not appear to bind to the value being accepted.

Required changes:

- Add `value_hash` or `record_digest` to the attestation payload.
- Include the digest in `signable_content`.
- Prefer canonical serialization of the attested value before hashing.
- For organization public keys, compute the digest from the canonical `OrgPublicKey` serialization.
- If available, also include Raft term, authority epoch, and validity window.
- Update validation so the DHT-delivered value must match the attested digest.
- Reject old attestations without value digest by default unless an explicit compatibility path is configured.
- Ensure the signer is authorized and, where revocation state is available, not revoked.

Acceptance tests:

- valid signed attestation with matching value hash accepted;
- attestation with wrong value hash rejected;
- attestation signed by unauthorized global node rejected;
- attestation signed by revoked global node rejected, if revocation data is available in the validation path;
- tampered signature rejected;
- wrong namespace rejected;
- wrong key ID rejected;
- structurally plausible but unsigned/legacy attestation rejected by default.

## Phase 4: Clarify and harden DNS authority policy

Files to inspect:

- `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`
- `crates/synvoid-mesh/src/mesh/dht/keys.rs`
- DNS mesh modules and tests

Current issue:

`DnsZone` is currently capability-attested and remote-writable. That is potentially too permissive if `DnsZone` represents zone ownership or authoritative zone root state.

Required decision:

Define whether `DnsZone` means:

1. canonical zone ownership / delegation root; or
2. mutable DNS zone content under an already-proven owner.

If `DnsZone` is ownership/delegation:

- classify it as `RaftOrQuorumGlobal` or `RaftAttestedGlobal`;
- set `remote_writes_allowed = false`;
- distribute DHT copies only as Raft-attested or quorum-signed artifacts.

If `DnsZone` is mutable zone content:

- split the key namespace so ownership and record content are distinct;
- add a separate authority key for zone ownership;
- require `DnsRecord` writes to be owner-signed under an attested zone root.

Acceptance tests:

- remote `DnsZone` ownership write without authority proof rejected;
- DNS record under valid ownership root accepted with owner/capability signature;
- DNS record for unowned or mismatched zone rejected;
- stale zone ownership proof rejected;
- docs clearly distinguish zone ownership from mutable records.

## Phase 5: Seal raw record-store API footgun

Files to inspect:

- `crates/synvoid-mesh/src/mesh/dht/record_store_crud.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- all callers of `store_record(...)`

Current issue:

`store_record(record, source_reputation, is_local_origin)` is public and lets callers pass `is_local_origin` directly. This is easy to misuse from remote paths.

Required changes:

- Replace public raw storage with explicit APIs:
  - `store_local_record(...)`
  - `store_remote_record_from_ingress(...)`
- Make low-level `store_record_verified_internal(...)` private or `pub(crate)`.
- Make any method taking `is_local_origin: bool` private or crate-private.
- Ensure all network handlers call only the ingress API.
- Ensure local creation paths build `DhtRecordIngressContext::new_local(...)` or a dedicated local path.
- Add a grep/check test or compile-level visibility barrier so remote modules cannot call raw storage with arbitrary local-origin values.

Acceptance tests:

- remote handlers cannot compile if they try to call raw storage directly;
- all `DhtRecordPush`, sync, anti-entropy, and announce paths use ingress validation;
- local record creation still works;
- authority-key remote write bypass tests fail before storage.

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

1. Enforce inbound `DhtAntiEntropyRequest` signatures.
2. Enforce `DhtAntiEntropyResponse` envelope verification.
3. Seal raw storage API exposure.
4. Add value-hash binding to `SignedRaftAttestation`.
5. Reclassify/split DNS authority policy.
6. Add adversarial tests.
7. Update docs and verification matrix.

## Out of scope

- Replacing DHT with Raft.
- Extracting a new consensus crate.
- Rewriting routing/discovery topology.
- Changing CA/key ceremony design.
- Removing all compatibility modes without an explicit migration decision.

## Final acceptance checklist

- inbound anti-entropy requests are signed and verified by default;
- anti-entropy responses are envelope-verified before record application;
- record-push remains signed and verified by default;
- Raft attestations bind to exact value digest;
- DNS zone ownership cannot be remotely created through capability-only DHT writes;
- remote handlers cannot bypass ingress validation;
- docs accurately reflect verification state;
- adversarial tests cover forged, unsigned, stale, replayed, wrong-signer, wrong-value, wrong-namespace, and remote-write-bypass cases.
