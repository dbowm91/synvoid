# Focused DHT Runtime Completion Plan

## Goal

Finish the remaining DHT runtime security integration gaps without another architecture pass.

The previous passes left the codebase in good shape: value-bound Raft attestations exist, Edge peer validation now routes through the Raft-attested certificate path when supplied, DHT record push and anti-entropy paths enforce signatures by default, and remote records are routed through ingress validation.

This handoff is intentionally narrow. The main remaining work is in `record_store_message.rs`: apply signer/node binding after envelope signature verification and bring DHT sync request/response up to the same verification level as anti-entropy and record push.

## Non-goals

- Do not redesign the DHT/Raft split.
- Do not change the high-level mesh trust model.
- Do not extract new crates.
- Do not revisit DNS authority policy unless tests expose a concrete issue.
- Do not broaden into unrelated WAF/proxy work.

## Target invariants

1. A valid envelope signature is not sufficient for authority-sensitive DHT paths; the signer public key must also be bound to the claimed node identity.
2. `DhtSyncRequest` and `DhtSyncResponse` must not ignore signature fields.
3. Sync responses that carry records must verify the response envelope before applying records.
4. Sync response records must be stored through `store_record_from_ingress(...)` with `IngressPath::SyncResponse`.
5. Tests must fail if a future edit reintroduces unsigned sync acceptance or wrong-signer acceptance.

## Phase 1: Add a local DHT envelope binding helper

Files:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`
- node/global-key registry code used by `RecordStoreManager`

Current state:

`verify_envelope_signer_binding(...)` and `NodePublicKeyResolver` exist, but the inspected DHT handlers do not appear to call them.

Implementation direction:

Add a small helper near `RecordStoreManager::handle_mesh_message(...)`, or in an adjacent private impl block:

```rust
fn verify_dht_envelope_binding_for_peer(
    &self,
    claimed_node_id: &str,
    signer_public_key: Option<&str>,
    source_classification: crate::dht::signed::SourceClassification,
) -> bool
```

Suggested behavior:

- If `signer_public_key` is missing or empty, return false for strict/global paths.
- Resolve the authorized public key for `claimed_node_id` from existing mesh/global-node state.
- Call `verify_envelope_signer_binding(...)` where possible.
- Fail closed for Global Node / authority-sensitive paths.
- For soft-state Edge/Origin paths, preserve explicit permissive behavior only if there is already a config flag for it. Do not create implicit permissiveness.
- Log binding failures separately from signature failures.

Acceptance criteria:

- Helper exists and is used by DHT envelope handlers.
- Wrong registered key is rejected after a valid signature.
- Missing binding is rejected for strict/global paths.
- Correct registered key is accepted.

## Phase 2: Apply signer/node binding to already-signed DHT paths

Files:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`

Apply binding checks after successful envelope signature verification for:

- `DhtAntiEntropyRequest`
- `DhtAntiEntropyResponse`
- `DhtRecordPush`
- `DhtRecordAnnounce` if the announce path is considered authority-relevant or peer-authenticated

Implementation notes:

- Use the message's claimed node ID where present.
- For `DhtAntiEntropyResponse` and `DhtRecordPush`, current verification uses `from_node` as responder/node identity. Bind the signer to `from_node` unless the protocol carries a more precise responder node field.
- If a message is accepted under an explicit unsigned compatibility window, do not mark the ingress context as envelope-verified.
- Where records are applied after a verified envelope, set the ingress context with `.with_envelope_signature(true)`.

Acceptance criteria:

- Anti-entropy request with valid signature but wrong signer binding is rejected.
- Anti-entropy response with valid signature but wrong signer binding is rejected.
- Record push with valid signature but wrong signer binding is rejected.
- Valid signed and correctly bound messages still pass.

## Phase 3: Verify `DhtSyncRequest` envelopes

Files:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`
- `crates/synvoid-mesh/src/mesh/config.rs`
- `crates/synvoid-mesh/src/mesh/protocol.rs`

Current state:

The `DhtSyncRequest` match arm currently ignores `nonce`, `signature`, and `signer_public_key`, then calls `handle_sync_request(...)`.

Required changes:

- Destructure `node_id`, `timestamp`, `nonce`, `signature`, and `signer_public_key` as real values.
- Enforce `require_signed_sync_requests` by default.
- Add or use an existing verifier for the sync request signable content:
  - request ID;
  - node ID;
  - from-version;
  - timestamp;
  - nonce;
  - protocol version.
- Reject missing nonce/signature/public key unless an explicit sync compatibility window is active.
- After signature verification, apply signer/node binding to `node_id` or `from_node` depending on the protocol identity model.
- Only then call `handle_sync_request(...)`.

Acceptance criteria:

- Unsigned sync request rejected by default.
- Sync request with missing nonce rejected by default.
- Sync request with invalid signature rejected.
- Sync request with valid signature but wrong node binding rejected.
- Valid signed and bound sync request accepted.

## Phase 4: Verify `DhtSyncResponse` envelopes before applying records

Files:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- `crates/synvoid-mesh/src/mesh/dht/signed.rs`

Current state:

The `DhtSyncResponse` match arm currently ignores `signature` and `signer_public_key`, then calls `handle_sync_response(records.clone(), from_node)`.

Required changes:

- Destructure request ID, records, version, timestamp, signature, and signer public key as real values.
- Require signed sync responses by default. If the existing config only has `require_signed_sync_requests`, either:
  - reuse it for both request and response; or
  - add a clearly named `require_signed_sync_responses` with strict default.
- Add or use response signable content covering:
  - request ID;
  - responder node ID / from peer;
  - version;
  - record count;
  - timestamp;
  - record-set digest.
- Recompute record-set digest from received records before signature verification.
- Apply signer/node binding after signature verification.
- Apply records through `store_record_from_ingress(...)` using:
  - `IngressPath::SyncResponse`;
  - `source_classification` appropriate to the peer if known;
  - `.with_envelope_signature(true)` only after verification.
- Remove or narrow any `handle_sync_response(...)` helper that applies records without ingress validation.

Acceptance criteria:

- Unsigned sync response rejected by default.
- Sync response with tampered record set rejected by digest mismatch.
- Sync response with valid signature but wrong node binding rejected.
- Valid signed/bound sync response accepted.
- Embedded invalid record still rejected by per-record ingress validation.

## Phase 5: Focused regression tests

Add tests close to the DHT modules. Prefer precise adversarial tests over broad integration tests.

Required tests:

### Signer binding

- valid signature + wrong registered key rejected for anti-entropy request;
- valid signature + wrong registered key rejected for anti-entropy response;
- valid signature + wrong registered key rejected for record push;
- correct registered key accepted.

### Sync request

- unsigned request rejected by default;
- missing nonce rejected;
- invalid signature rejected;
- wrong signer binding rejected;
- valid signed request accepted.

### Sync response

- unsigned response rejected by default;
- tampered record set rejected;
- wrong signer binding rejected;
- valid envelope but invalid embedded record rejected;
- valid envelope and valid records accepted through ingress validation.

### Regression guard

- A test or static assertion should fail if a sync handler ignores `signature`/`signer_public_key` again.

## Phase 6: Minimal docs update

Files:

- `docs/identity_hierarchy.md`, if present
- `architecture/mesh_deep_dive.md`
- `docs/WAF_MESH.md`, if it contains DHT verification matrix

Required updates:

- Mark DHT sync request/response as signed and envelope-verified after implementation.
- Describe signer/node binding as enforced for strict/global paths.
- Keep the distinction clear:
  - envelope signature proves possession of key;
  - signer binding proves key belongs to claimed node;
  - per-record signature proves record author/source;
  - ingress validation enforces key-family policy.

Acceptance criteria:

- Verification matrix no longer says sync is unsigned/partial after implementation.
- Docs do not imply that signature-only verification is sufficient for authority paths.

## Final acceptance checklist

- `DhtAntiEntropyRequest` verifies signature and signer/node binding.
- `DhtAntiEntropyResponse` verifies signature and signer/node binding.
- `DhtRecordPush` verifies signature and signer/node binding.
- `DhtSyncRequest` verifies signature, nonce, timestamp, and signer/node binding.
- `DhtSyncResponse` verifies signature, record-set digest, timestamp, and signer/node binding before storing records.
- Sync response records use `store_record_from_ingress(...)` with `IngressPath::SyncResponse`.
- Wrong signer, unsigned sync, tampered record set, and invalid embedded records are covered by tests.
- Docs match the implemented runtime boundary.
