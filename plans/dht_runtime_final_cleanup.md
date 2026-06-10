# Final DHT Runtime Cleanup Plan

## Goal

Close the last small runtime and verification gaps after the DHT/Raft boundary hardening work.

The important runtime work appears to be in place now: DHT sync request/response signatures are verified, sync response record sets are digest-bound, signer/node binding is applied to the main DHT handlers, and verified sync response records are stored through `store_record_from_ingress(...)` with `IngressPath::SyncResponse`.

This plan is deliberately small. Do not reopen the DHT/Raft architecture. Finish the remaining compatibility bypass cleanup, add adversarial tests, and align docs.

## Non-goals

- Do not redesign consensus or mesh authority.
- Do not replace DHT with Raft.
- Do not introduce a new crate.
- Do not broaden into HTTP/WAF/proxy behavior.
- Do not refactor unrelated DHT storage internals unless required for tests.

## Current known good state

- `RecordStoreKeyResolver` resolves authorized global-node keys from the cert manager.
- `verify_dht_envelope_binding_for_peer(...)` calls `verify_envelope_signer_binding(...)`.
- `DhtSyncRequest` enforces `require_signed_sync_requests`, verifies nonce/signature/public key, and applies signer/node binding.
- `DhtSyncResponse` verifies envelope signature and record-set digest, applies signer/node binding, and stores verified records via `store_record_from_ingress(...)` with `IngressPath::SyncResponse`.
- `DhtAntiEntropyRequest`, `DhtAntiEntropyResponse`, and `DhtRecordPush` apply signer/node binding after signature verification.

## Remaining issue 1: unsigned sync-response compatibility path bypasses ingress storage

File:

- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`

Current concern:

When `DhtSyncResponse` lacks signature/auth but is accepted under `unsigned_sync_compat_until_unix` or disabled signing, the handler still calls:

```rust
self.handle_sync_response(records.clone(), from_node);
```

The signed path now stores through `store_record_from_ingress(...)` with `IngressPath::SyncResponse`; the unsigned compatibility path should not retain a broader storage path.

Required change:

- Replace the unsigned compatibility branch's `handle_sync_response(...)` call with an explicit compatibility ingress path.
- Use `DhtRecordIngressContext::new_remote(...)` with:
  - `IngressPath::SyncResponse`
  - source classification appropriate to the peer if known, otherwise `Unknown`
  - `.with_envelope_signature(false)`
- Store records via `store_record_from_ingress(...)` even in compatibility mode.
- Keep clear logging that this was an unsigned compatibility path.
- If `handle_sync_response(...)` is no longer needed or is unsafe, remove it or restrict it to an internal helper that cannot bypass ingress validation.

Acceptance criteria:

- No sync response branch applies records through a path that bypasses ingress validation.
- Unsigned sync responses, when explicitly accepted for compatibility, still undergo per-record ingress validation and key-policy enforcement.
- Signed and unsigned compatibility paths differ only in `envelope_signature_valid`, not in storage bypass behavior.

## Remaining issue 2: compatibility should be explicitly temporary and visible

Files:

- `crates/synvoid-mesh/src/mesh/config.rs`
- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs`
- relevant docs

Required change:

- Ensure `require_signed_sync_requests` defaults to `true`.
- Ensure `unsigned_sync_compat_until_unix` defaults to `None`.
- Add warning logs when unsigned sync compatibility accepts a message.
- Consider a startup warning if any unsigned DHT compatibility window is configured.
- Do not add another broad compatibility mode.

Acceptance criteria:

- Default config rejects unsigned sync request and response.
- Compatibility must be deliberately configured.
- Logs make compatibility acceptance visible.

## Remaining issue 3: add focused adversarial tests

Add or update tests close to DHT modules. Prefer narrow tests over broad integration fixtures.

Required test cases:

### DHT sync request

- unsigned request rejected by default;
- missing nonce rejected by default;
- invalid signature rejected;
- valid signature with wrong node binding rejected;
- valid signature with correct node binding accepted.

### DHT sync response

- unsigned response rejected by default;
- unsigned response accepted only when compatibility window is active;
- unsigned compatibility response still stores through ingress validation;
- tampered record set rejected by digest mismatch;
- valid signature with wrong node binding rejected;
- valid signed response with invalid embedded record rejected by `store_record_from_ingress(...)`;
- valid signed response with valid embedded record accepted.

### Existing signed DHT paths

- anti-entropy request wrong signer binding rejected;
- anti-entropy response wrong signer binding rejected;
- record push wrong signer binding rejected;
- correctly bound signed messages still accepted.

### Static/grep guard if feasible

Add a lightweight test or lint-style check that fails if `DhtSyncRequest` or `DhtSyncResponse` match arms bind `signature` or `signer_public_key` as `_` again.

Acceptance criteria:

- The tests fail against the old unsafe sync implementation.
- The tests pass against the current signed/bound implementation.
- Compatibility behavior is explicitly covered rather than implicit.

## Remaining issue 4: minimal docs update

Files to inspect/update:

- `docs/identity_hierarchy.md`, if present
- `architecture/mesh_deep_dive.md`
- `docs/WAF_MESH.md`, if it contains the DHT verification matrix
- any plan/skill file used as a living reference

Required documentation updates:

- Mark DHT sync request/response as signed, digest-bound, and signer-bound by default.
- Document that unsigned sync compatibility is temporary and still uses ingress validation.
- Document the four-layer check clearly:
  1. timestamp window;
  2. envelope signature;
  3. signer-to-node binding;
  4. per-record ingress validation and key-family policy.
- Remove stale notes saying sync signatures or signer binding are TODO, partial, or future work if now complete.

Acceptance criteria:

- Verification matrix matches code.
- Docs do not imply that compatibility paths bypass ingress validation.
- Docs distinguish signature verification from signer/node binding.

## Implementation order

1. Update unsigned `DhtSyncResponse` compatibility branch to use ingress validation.
2. Restrict or remove any helper that applies sync records without ingress validation.
3. Confirm sync signing defaults and compatibility defaults.
4. Add adversarial tests for sync request/response and signer binding.
5. Update minimal docs / verification matrix.
6. Run formatting and relevant test suite.

## Final acceptance checklist

- Signed `DhtSyncResponse` stores via `store_record_from_ingress(...)`.
- Unsigned compatibility `DhtSyncResponse` also stores via `store_record_from_ingress(...)` with `envelope_signature_valid = false`.
- Default config rejects unsigned sync request and response.
- Compatibility windows are explicit and visibly logged.
- Tests cover unsigned sync rejection, compatibility behavior, wrong signer binding, tampered record-set digest, and invalid embedded records.
- Docs reflect current runtime enforcement.
