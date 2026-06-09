# Final DHT/Raft Boundary Hardening Plan

## Goal

Close the remaining hardening seams in Synvoid's DHT/Raft boundary after the recent DHT ingress and authority-policy improvements.

The repo now has the important pieces in place: DHT key-family authority policies, signed DHT record-push envelopes, signed anti-entropy request/response envelopes, strict-by-default signing configuration, DNS zone ownership classified as Raft/quorum authority, and remote record application routed through `store_record_from_ingress` in the critical message paths.

This pass should avoid broad redesign. It should make the current enforcement model harder to misuse and finish the last cryptographic binding points.

## Non-goals

- Do not replace DHT with Raft.
- Do not extract a new consensus crate.
- Do not rewrite mesh transport.
- Do not redesign the full CA/key ceremony.
- Do not remove compatibility windows unless a migration decision has been made.

## Target invariants

1. Remote DHT records are accepted only through typed remote-ingress APIs.
2. Callers cannot arbitrarily mark a remote DHT record as local origin.
3. `DhtRecordIngressContext` cannot be forged by arbitrary crate-internal code through direct field mutation.
4. Envelope signatures bind to node identity, not just to an arbitrary public key.
5. Empty anti-entropy responses follow the same signing invariant as non-empty responses unless an explicit compatibility mode is active.
6. Raft attestations bind to the exact value or record digest being trusted.
7. Documentation and tests encode the final boundary.

## Phase 1: Seal the raw DHT store API

Files to inspect:

- `crates/synvoid-mesh/src/mesh/dht/record_store_crud.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- all callers of `store_record(`
- all callers of `store_record_verified_internal(`

Current concern:

`store_record_verified_internal(...)` is `pub(crate)`, which is acceptable for low-level internal storage, but `store_record(record, source_reputation, is_local_origin)` still exists as a crate-visible method that accepts a raw `is_local_origin: bool`. That is a boundary footgun: any crate-internal caller can accidentally treat a remote record as local.

Required changes:

- Remove `store_record(record, source_reputation, is_local_origin)` if possible.
- Replace every caller with one of:
  - `store_local_record(record, source_reputation)` for locally generated records;
  - `store_record_from_ingress(record, &ingress_ctx, source_reputation)` for mesh/remote records;
  - a private helper only inside `record_store_crud.rs` for already-verified internal persistence.
- Keep `store_record_verified_internal(...)` private if feasible. If not feasible, keep `pub(crate)` but document that it must only be called by typed wrappers.
- Add a grep-oriented regression test or compile-time pattern test if the repo already has a suitable dev-test framework.

Acceptance criteria:

- No public or crate-visible API accepts a caller-supplied `is_local_origin: bool` for general record storage.
- Remote DHT message handlers cannot compile if they try to bypass ingress validation.
- Local record creation still works through an explicit local-only API.
- Existing tests pass.

## Phase 2: Encapsulate `DhtRecordIngressContext` (✅ Complete)

All `DhtRecordIngressContext` fields are now private. Read-only accessors (`peer_id()`, `source_node_id()`, `source_classification()`, `path()`, `requires_quorum_proof()`, `requires_trust_anchor()`, `is_immutable_key()`, `envelope_signature_valid()`, `timestamp()`, `request_id()`, `is_local_origin()`) expose state to validation code. Construction is controlled via `new_local()`, `new_remote()`, and builder methods. No generic setter allows arbitrary code to mark `is_local_origin = true`.

## Phase 3: Bind DHT envelope signer to node identity (✅ Complete)

Signer-to-node binding is enforced via `verify_envelope_signer_binding()` and `verify_signer_node_binding()` in `dht/signed.rs`. For Global Node classified paths, TLS/cert peer ID must match claimed node ID or the claimed node ID must resolve to the signer public key through an authorized global-node registry via `NodePublicKeyResolver`. `validate_peer_role()` in `peer_auth.rs` now accepts an optional `raft_attestation` parameter for Edge node validation. Binding verification is applied to `DhtRecordPush`, `DhtAntiEntropyRequest`, `DhtAntiEntropyResponse`, and `DhtSyncRequest`/`DhtSyncResponse`.

## Phase 4: Require signed empty anti-entropy responses by default

Files to inspect:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`
- `crates/synvoid-mesh/src/mesh/config.rs`

Current concern:

Non-empty anti-entropy responses are envelope-verified. Empty/no-op responses appear to skip envelope verification. This is probably low risk, but it complicates the invariant and leaves room for peer-state spoofing or sync suppression behavior later.

Required changes:

- Require anti-entropy response signatures by default regardless of `missing_records.len()`.
- Keep an explicit compatibility exception only through the existing unsigned anti-entropy compatibility config.
- For empty responses, sign over:
  - request ID;
  - responder node ID;
  - root hash;
  - record count of zero;
  - timestamp;
  - empty record-set digest.
- Ensure outbound empty responses include signature and signer public key.

Acceptance criteria:

- Unsigned empty anti-entropy response is rejected by default.
- Signed empty response is accepted.
- Unsigned empty response is accepted only during explicit compatibility window or when signing is explicitly disabled.
- Tests cover all three cases.

## Phase 5: Finish value-bound Raft attestations

Files to inspect:

- `crates/synvoid-mesh/src/mesh/peer_auth.rs`
- `crates/synvoid-mesh/src/mesh/raft/state_machine.rs`
- `crates/synvoid-mesh/src/mesh/raft/edge_replica.rs`
- `crates/synvoid-mesh/src/mesh/organization.rs`
- DHT record types that carry Raft-derived authority artifacts

Current concern:

The repo has signed Raft attestations, but this pass should confirm and enforce that attestations bind to the exact value or record digest being accepted, not just namespace/key/commit index.

Required changes:

- Ensure `SignedRaftAttestation` includes one of:
  - `value_hash`, or
  - `record_digest`, or
  - a canonical hash of the authority artifact.
- Include that digest in signable content.
- For each authority artifact, define canonical hashing:
  - `OrgPublicKey`
  - member certificate / org key root
  - global-node authorization proof
  - global-node revocation
  - DNS zone ownership / delegation root
- Verify the digest before treating the DHT-distributed artifact as Raft-attested.
- Include Raft term and/or authority epoch if available.
- Add anti-rollback checks where local edge replica state has commit index/epoch information.
- Reject legacy attestations without value binding by default unless an explicit compatibility mode is configured.

Acceptance criteria:

- Attestation for same namespace/key but wrong value hash is rejected.
- Attestation signed by unauthorized global node is rejected.
- Attestation signed by revoked global node is rejected where revocation context is available.
- Attestation below local anti-rollback commit/epoch is rejected.
- Valid value-bound attestation is accepted.

## Phase 6: Add focused adversarial tests

Suggested test groups:

### Store API sealing

- no remote-path test can call a raw API with `is_local_origin = true`;
- local record storage succeeds through `store_local_record`;
- remote record storage succeeds only through `store_record_from_ingress`;
- remote Raft-owned key write is rejected.

### Ingress context integrity

- remote context reports local origin as false;
- local context reports local origin as true;
- caller cannot mutate local-origin state directly;
- verified-envelope state can be set only through intended constructor/builder.

### Envelope signer binding

- valid signature from wrong key rejected in strict/global mode;
- valid signature from correct registered key accepted;
- claimed node ID mismatch rejected;
- missing binding rejected for Global Node paths;
- permissive/TOFU mode behavior explicitly tested if supported.

### Empty anti-entropy response

- unsigned empty response rejected by default;
- signed empty response accepted;
- unsigned empty response accepted only in explicit compatibility mode.

### Raft attestation value binding

- correct value-bound attestation accepted;
- wrong value hash rejected;
- wrong namespace rejected;
- wrong key rejected;
- stale commit/epoch rejected;
- revoked signer rejected.

## Phase 7: Documentation cleanup

Files to update:

- `architecture/mesh_deep_dive.md`
- `architecture/mesh.md`
- `docs/WAF_MESH.md`
- `docs/identity_hierarchy.md`, if present
- prior plan files only if treated as living docs

Required doc updates:

- Mark anti-entropy request and response verification as fully enforced only after Phase 4.
- Document remaining or resolved L1↔L4 signer-binding semantics.
- Document that `DnsZone` is Raft/quorum authority and `DnsRecord` is capability-mediated mutable content.
- Document that remote DHT storage must enter through ingress validation.
- Document signed value-bound Raft attestations.

Acceptance criteria:

- Verification matrix matches code.
- Docs distinguish authority state, DHT-distributed authority artifacts, DHT soft state, and local-only runtime state.
- No docs imply that DHT creates global authority.

## Suggested implementation order

1. Remove or seal raw `store_record(..., is_local_origin)`.
2. Encapsulate `DhtRecordIngressContext` fields.
3. Enforce signed empty anti-entropy responses.
4. Add signer/node binding verification helpers and apply to DHT envelopes.
5. Confirm/finish value-bound Raft attestations.
6. Add adversarial regression tests.
7. Update docs and verification matrix.

## Final acceptance checklist

- No general storage API accepts arbitrary `is_local_origin` from callers.
- Ingress context cannot be forged by public field mutation.
- DHT envelope signatures bind to claimed node identity under strict/global mode.
- Empty anti-entropy responses are signed by default.
- Raft attestations bind to exact value/record digest.
- DNS ownership remains Raft/quorum authority; DNS records remain capability-mediated.
- Tests cover wrong signer, wrong node, wrong value hash, unsigned empty response, remote local-origin bypass, and stale/rollback attestation.
- Docs match implementation state.
