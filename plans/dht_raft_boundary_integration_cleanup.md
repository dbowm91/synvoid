# DHT/Raft Boundary Integration Cleanup Plan

## Goal

Finish the last integration seams in the DHT/Raft boundary hardening work.

The repo now has the important primitives: encapsulated `DhtRecordIngressContext`, explicit local-vs-remote store APIs, signed anti-entropy request/response envelopes, signed record-push envelopes, DNS zone authority policy, signer-binding helpers, and value-bound signed Raft attestations.

This pass should wire those primitives consistently into the runtime paths. Avoid new architecture unless a compile-time boundary requires it.

## Current assessment

Strong pieces already present:

- `DhtRecordIngressContext` fields are private and exposed via accessors/builders.
- Remote record application uses `store_record_from_ingress(...)` in the inspected DHT push path.
- Anti-entropy responses are signature-gated even when empty.
- `RaftAttestation` includes `value_hash` and `SignedRaftAttestation::signable_content()` includes it.
- V2 Raft attestations reject missing or mismatched value hashes.
- `NodePublicKeyResolver` and `verify_envelope_signer_binding(...)` exist.

Remaining work is mostly integration:

- signer/node binding helper exists but is not visibly applied in the DHT message handlers;
- DHT sync request/response handlers still appear to ignore signature fields;
- edge peer validation still calls the older quorum-only certificate path before the value-bound Raft-attested path;
- tests and docs should be updated to lock in these final invariants.

## Target invariants

1. A valid DHT envelope signature is insufficient unless the signer key is bound to the claimed node identity where the node identity is authoritative.
2. DHT sync request/response paths must follow the same envelope-verification model as anti-entropy and record push.
3. Edge peer validation must use value-bound Raft attestation when quorum signatures are absent but a signed Raft attestation is supplied.
4. DHT-distributed authority artifacts cannot be accepted on the basis of a structurally plausible attestation.
5. The docs must no longer describe signer binding or Raft value binding as future work if implemented.

## Phase 1: Wire signer/node binding into DHT envelope handlers

Files to inspect:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`
- `crates/synvoid-mesh/src/mesh/peer_auth.rs`
- node registry / global-node public-key registry modules
- DHT config / peer-auth config modules

Current issue:

`verify_envelope_signer_binding(...)` exists, but the DHT handlers currently appear to verify only envelope signatures. That proves possession of the supplied key, not that the key belongs to the claimed node.

Required changes:

- Add a helper on `RecordStoreManager` or a nearby module to resolve authorized node public keys:

```rust
fn verify_dht_envelope_binding(
    &self,
    claimed_node_id: &str,
    signer_public_key: Option<&str>,
    classification: SourceClassification,
) -> Result<(), SignerBindingError>
```

- Use the existing `NodePublicKeyResolver` abstraction or adapt it to current routing/peer-auth state.
- Apply signer binding after signature verification for:
  - `DhtAntiEntropyRequest`
  - `DhtAntiEntropyResponse`
  - `DhtRecordPush`
  - `DhtRecordAnnounce`, if it carries a claimed source node and signer key
  - `DhtSyncRequest` / `DhtSyncResponse` after Phase 2
- For Global Node classified messages, fail closed on missing binding.
- For Edge/Origin soft-state messages, preserve configured permissive/TOFU behavior if needed, but reject mismatches when the binding is known.
- Log binding failures separately from signature failures.

Acceptance criteria:

- Valid signature with a signer key not registered to the claimed Global Node is rejected.
- Valid signature with correct registered key is accepted.
- Missing binding for a Global Node path is rejected.
- Soft-state permissive mode remains explicitly configurable rather than accidental.

## Phase 2: Verify DHT sync request/response envelopes

Files to inspect:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`
- `crates/synvoid-mesh/src/mesh/protocol.rs`
- `crates/synvoid-mesh/src/mesh/config.rs`

Current issue:

The `DhtSyncRequest` and `DhtSyncResponse` match arms still appear to ignore `nonce`, `signature`, and `signer_public_key` fields, then proceed to `handle_sync_request(...)` / `handle_sync_response(...)`.

Required changes:

- Enforce `require_signed_sync_requests` for `DhtSyncRequest`.
- Verify request signable content using request ID, node ID, from-version, timestamp, nonce, and protocol version.
- Verify signer/node binding after request signature validation.
- For `DhtSyncResponse`, enforce a signed response envelope by default when records are present. Prefer signing all responses, including empty responses, for invariant consistency.
- Verify response signable content using request ID, responder node ID/from peer, version, record count, timestamp, and record-set digest.
- Recompute record-set digest from received records before verification.
- Route received records through `store_record_from_ingress(...)` with `IngressPath::SyncResponse`.
- Reject unsigned sync messages by default unless a specific compatibility window is configured.

Acceptance criteria:

- Unsigned sync request rejected by default.
- Unsigned sync response rejected by default.
- Signed sync response with tampered record set rejected by digest mismatch.
- Valid signed sync request/response accepted.
- Sync records still pass per-record validation before storage.

## Phase 3: Route edge peer validation through value-bound Raft attestations

Files to inspect:

- `crates/synvoid-mesh/src/mesh/peer_auth.rs`
- all callers of `validate_peer_role(...)`
- all callers of `validate_member_certificate(...)`
- all callers of `validate_member_certificate_with_raft_attestation(...)`
- config for `allow_v1_raft_attestations`

Current issue:

`validate_member_certificate_with_raft_attestation(...)` contains the correct value-bound Raft attestation checks, but `validate_peer_role(...)` still attempts the older `validate_member_certificate(...)` path for Edge nodes. That older function rejects org keys without quorum signatures and does not consume Raft attestation.

Required changes:

- Extend `validate_peer_role(...)` parameters to optionally accept `SignedRaftAttestation` and `allow_v1_raft_attestations`, or introduce a new `PeerValidationContext` struct to avoid more parameter bloat.
- For Edge nodes with member certificate and org public key:
  - prefer `validate_member_certificate_with_raft_attestation(...)` when an attestation is available;
  - fall back to quorum-only `validate_member_certificate(...)` only when no attestation is supplied;
  - do not silently reject Raft-attested org keys because quorum signatures are absent.
- Update call sites to pass the attestation where available.
- Consider deprecating or making private the quorum-only helper if it is easy to misuse.

Acceptance criteria:

- Edge member certificate with quorum-signed org key still validates.
- Edge member certificate with value-bound Raft-attested org key validates even without quorum signatures.
- Edge member certificate with malformed/wrong-value Raft attestation rejects.
- Old V1 attestations reject by default unless compatibility is explicitly enabled.

## Phase 4: Tighten value-bound Raft attestation coverage

Files to inspect:

- `crates/synvoid-mesh/src/mesh/peer_auth.rs`
- `crates/synvoid-mesh/src/mesh/raft/state_machine.rs`
- DHT authority artifact code paths
- DNS zone authority code paths

Current status:

`OrgPublicKey` value binding appears implemented. This pass should verify whether other authority artifacts use the same discipline.

Required changes:

- Confirm value-hash binding for:
  - `OrgPublicKey`
  - member certificate/org membership roots if distributed via DHT
  - global-node authorization proofs
  - global-node revocations
  - DNS zone ownership/delegation roots
- Add canonical hash helpers for each authority artifact type that needs Raft attestation.
- Include authority epoch / term / commit index anti-rollback checks where local replica state has enough information.
- Reject structurally plausible but value-unbound attestations by default.

Acceptance criteria:

- Same namespace/key but wrong value hash rejected for every Raft-attested authority artifact.
- Stale commit/epoch rejected when local anti-rollback state is available.
- Revoked global signer rejected when revocation context is available.

## Phase 5: Add focused regression tests

Suggested test groups:

### Signer/node binding

- valid envelope signature but wrong registered key rejected;
- valid envelope signature and correct registered key accepted;
- missing binding rejected for Global Node path;
- permissive/TOFU behavior explicitly tested for non-authority soft-state paths if supported.

### Sync envelope verification

- unsigned `DhtSyncRequest` rejected by default;
- invalid sync request signature rejected;
- unsigned `DhtSyncResponse` rejected by default;
- sync response with tampered records rejected by digest mismatch;
- valid signed sync response stores records only through ingress validation.

### Edge peer Raft attestation path

- quorum-signed org key path still works;
- value-bound Raft-attested org key path works without quorum signatures;
- wrong value hash rejected;
- missing value hash on V2 rejected;
- V1 rejected unless compatibility flag is true.

### Authority artifact value binding

- wrong value hash rejected for global-node proof;
- wrong value hash rejected for revocation artifact;
- wrong value hash rejected for DNS zone authority artifact;
- stale commit index rejected when local state tracks a newer index.

## Phase 6: Documentation cleanup

Files to inspect/update:

- `architecture/mesh_deep_dive.md`
- `architecture/mesh.md`
- `docs/WAF_MESH.md`
- `docs/identity_hierarchy.md`, if present
- `docs/adr/ADR-001-global-nodes-trust-anchors.md`

Required updates:

- Mark DHT record push, anti-entropy request/response, and sync request/response verification status accurately.
- Document the signer/node binding model:
  - strict for Global Node / authority paths;
  - configurable for soft-state edge/origin paths if applicable.
- Document value-bound Raft attestations and which authority artifacts require them.
- Document that DHT distributes authority artifacts but does not create authority.
- Remove stale notes that describe implemented items as future gaps.

Acceptance criteria:

- Verification matrix matches implementation.
- DHT/Raft authority boundary is described consistently across architecture docs.
- No docs imply that unsigned sync/anti-entropy paths are acceptable by default.

## Suggested implementation order

1. Add `RecordStoreManager`-level signer-binding resolver/helper.
2. Apply signer binding to anti-entropy and record-push handlers.
3. Implement sync request/response envelope verification and ingress storage.
4. Route Edge peer validation through value-bound Raft attestation when supplied.
5. Extend value-hash binding to remaining authority artifacts.
6. Add focused adversarial tests.
7. Update documentation and verification matrix.

## Final acceptance checklist

- DHT push, anti-entropy, and sync envelopes are signed and verified by default.
- DHT envelope signer keys are bound to claimed node identity for strict/global paths.
- Sync response records cannot be applied without envelope verification and per-record ingress validation.
- Edge member validation accepts value-bound Raft-attested org keys without requiring quorum signatures.
- V2 Raft attestations require exact value hash binding.
- Authority artifacts beyond org keys use value-bound attestations where applicable.
- Tests cover wrong signer, wrong node, unsigned sync, tampered sync records, wrong attested value, and V1 compatibility behavior.
- Docs match actual enforcement.
