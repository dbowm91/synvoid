# Phase 04 Plan: Message and State Authentication

Status: **PARTIAL** — 04a implemented in `ea638ff9` (Ed25519 identity re-key, identity signer, peer key registry, `verify_peer_message_signature`); 04b and 04c not started.

Registered in: `plans/roadmap.md`.
Campaign: `plans/mesh_trust_boundaries_roadmap.md`.
Predecessor: Phase 03 (identity must be derived before it can be signed over).
Depends on: Phase 01 harness (`unsigned_threat_announce_is_rejected`).

## The finding

State-bearing messages are authenticated against keys the sender chooses.

- **B1 (Critical).** The entire `ThreatAnnounce` verification block is nested
  inside `if !signature.is_empty()` (`threat_intel.rs:2691-2719`). An empty
  signature skips the Merkle root, the signature, and the `trusted_signers`
  check. The indicators are then applied (`:2793-2801`) and the message is
  relayed to random peers before per-indicator acceptance (`:2784-2794`). For a
  receiver whose role is global, `check_trusted_signer` returns `true`
  immediately (`:2423-2426`), so even a signed announce from an arbitrary
  self-minted key is accepted.
- **B2 (Critical).** With no `global_node_key`, the mesh signer secret is
  `HKDF-SHA256(ikm = node_id, info = "synvoid-mesh-signer")`
  (`init_mesh.rs:300-319`). `node_id` is public: it is advertised in every
  `Hello` and logged at startup. Anyone who sees it can derive that node's
  signing key. Signature verification also consumes the message-supplied
  `signer_public_key` (`threat_intel.rs:2729-2738`), so the check is
  self-consistent rather than authoritative.
- **B4 (Critical).** `verify_dht_record_signature` verifies against the
  record's own `signer_public_key` with no comparison to `source_node_id`
  (`signed.rs:1244-1272`). Last-writer-wins ordering is
  `(timestamp, sequence_number, source_node_id)`, all peer-controlled
  (`record_store_crud.rs:427-441`). `requires_global_node()` exists but is
  never consulted at acceptance, and the authoritative quorum verifier has no
  caller. Immutable record types reject replacement after first write
  (`:412-426`), so an attacker who writes first blocks legitimate updates.
- **C8 (High).** The leader rebuilds `ClientProposalPayload::new(namespace,
  key, &[], Set, source, 0, 0)` — empty value, zero timestamp and nonce — and
  verifies with `signer.get_public_key_bytes()`, the **receiver's** key
  (`transport_peer.rs:5283-5299`). The submitted command is the original, so
  the signature never covers the applied value; replay keys on nonce `0`
  (`:5301-5311`), so the first accepted proposal blocks all later ones.
- **D8 (Medium).** `truncate_after(None)` returns `Ok(())` without deleting
  (`raft/state_machine.rs:1128-1140`), leaving a stale divergent suffix after a
  leader change.

## Root cause

The mesh has a transport identity but no message identity. Signing was added
per message type as an optional field for compatibility, verification was
implemented against whatever key the message carried, and the "trusted signer"
list was consulted only on some paths. Because unsigned messages were accepted,
no deployment ever depended on signatures, so the defaults never tightened.

## Fix scope

### S1 — The identity key is the signer

Decision (2026-11-15, owner): re-key the node identity to Ed25519. The
published node key becomes the Ed25519 verifying key, and the same key signs
mesh messages. There is no separate subkey to distribute.

- The 32-byte file secret is an Ed25519 seed. Publish its verifying key as
  `public_key`; derive `node_id = node-<hex(sha256("public-key-from:" ||
  verifying_key)[..8])>`.
- The message signer is `MeshMessageSigner::from_secret(seed)`. Its public key
  must equal the published identity key; verify that at startup and in a test.
- Delete both `node_id` HKDF constructions
  (`src/worker/unified_server/init_mesh.rs`, `src/supervisor/mesh.rs`) and the
  ASCII truncation of `global_node_key` (`backend.rs`). `global_node_key` is
  never a signer source.
- This changes every node id. Existing `peered_wafs` entries, certificates,
  and any pinned ids must be regenerated. A peer presenting the legacy hashed
  key is rejected with a specific "re-key the node" hint.
- A signer that cannot be derived is a startup error, not a disabled signer.

### S2 — Verification resolves the key; it never accepts one

Add one entry point used by every state-bearing message:

```text
verify_peer_message_signature(from_node, message_bytes, signature) -> Result<(), AuthError>
```

- Resolve `from_node`'s public key from the local registry — the key recorded
  from the authenticated handshake (`cert.rs:1029 add_peer_public_key`,
  populated by Phase 03) or `get_global_node_key` for global nodes.
- No registered key for a known peer is an internal error, not a pass.
- A `signer_public_key` field in a message is accepted only as a hint; it must
  equal the resolved key or the message is rejected. It is never the
  verification key.
- Verify over the exact bytes that were received. Do not re-serialize a
  decoded struct for verification. If a message needs a canonical form, define
  one with length-prefixed fields, not `format!` concatenation.

### S3 — Threat intelligence

- Signature is mandatory. Delete the `if !signature.is_empty()` nesting and the
  `check_trusted_signer` global short-circuit (`threat_intel.rs:2423-2426`).
- Verify before relay; relay only messages that passed verification, and relay
  the original encoded bytes.
- `ThreatSyncResponse` applies the same rule. The audit did not confirm whether
  it has an envelope check at all; confirm and close it in the same change.
- `global_node_ips` is populated only from local configuration and the
  certificate/global-key registry, never from topology announcements. This is
  the exemption list that turns B3 into a WAF bypass.
- Clamp indicator TTL and reject timestamps beyond the accepted skew; the
  indicator map currently has no expiry path in production.

### S4 — DHT records

- `verify_dht_record_signature` becomes `verify_record_for_ingress(record,
  registry)`, which requires
  `node_id_from_public_key(record.signer_public_key) == record.source_node_id`
  **and** that the derived id is the key registered for that node.
- Enforce `requires_global_node()` for the record types that declare it; if a
  type does not need a global author, delete the method rather than leaving it
  uncalled.
- Quorum: call `verify_quorum_proof_authoritative` for the key classes that
  declare a quorum, or delete the quorum fields. A field that is never checked
  is worse than no field.
- LWW key becomes `(sequence_number, timestamp, content_hash)`. Reject future
  timestamps beyond the configured skew. Immutable types: the first writer must
  be an authorized author for that key class, otherwise "first write wins" is a
  denial-of-service primitive.
- `DhtRecordAnnounce` has no `require_signed_*` flag and its envelope block is
  skipped when the signature is empty. Confirm this shape, then make the
  envelope signature and signer binding mandatory (the push path already has
  both, gated by the peer being global; make it unconditional).

### S5 — Peer announcements

- Accept only self-announcement: `node_id == session peer`, `role == session
  role`, `address == session remote address`. Anything else is dropped with a
  warning.
- Delete third-party gossip of peer addresses. A node that moves reconnects;
  the new session carries the new address.
- `PeerGone` is self-only for the same reason.

### S6 — Raft

- Verify the proposal over the exact received fields (namespace, key, value,
  kind, source, timestamp, nonce) with the key resolved from
  `source_node_id`.
- Replay cache key is `(source_node_id, nonce)`; reject nonce `0`.
- `truncate_after(None)` deletes the whole log.
- Audit `append` for `INSERT` semantics; a re-append at an existing index must
  replace or be rejected deterministically, never wedge replication with a
  uniqueness error. Add a divergent-log convergence test.

### S7 — Migration window

Wire signature changes break mixed-version meshes. Mirror the existing DHT
compat pattern rather than inventing one:

```toml
[tunnel.mesh]
legacy_unsigned_until_unix = 0   # 0 = reject unsigned state messages now
```

- Default 0. A non-zero value must be in the future, is logged loudly at
  startup, and expires into a hard failure.
- `validate()` enforces the window (Phase 07 makes `validate()` run).
- The window covers message signatures only; it never relaxes identity
  binding, role resolution, or DHT author binding.

## Invariants

- A verification function never consumes a key supplied by the data it
  verifies.
- An empty or absent signature is a rejection on every state-bearing message.
- A message is applied only after verification, and relayed only after
  application is authorized.
- A signed payload is verified over the exact received bytes.
- Global-node privileges never bypass signature verification.
- No trust decision is derived from an announced address.

## Verification

- Un-ignore and pass `unsigned_threat_announce_is_rejected`.
- New adversarial tests: a threat announce signed with a key derived from the
  victim's `node_id` is rejected; a message-supplied `signer_public_key` that
  differs from the registry key is rejected; a global receiver rejects an
  unknown signer; a DHT record claiming a victim `source_node_id` is rejected;
  a `PeerAnnounce` claiming another node or role is dropped; a raft write from
  a non-leader is applied exactly once and its replay is rejected;
  `truncate_after(None)` deletes and a divergent follower converges.
- Negative key test: deriving a signer from `node_id` must no longer produce a
  key that any peer accepts.
- `runtime/mesh-qual/qualify.sh` still passes with signatures required; the
  harness certificates are regenerated per run, so signed messages must not
  depend on long-lived state.

## Non-goals

- Key rotation automation, HSM/TPM-backed keys, or per-message ephemeral keys.
- Redesigning quorum or consensus. This phase makes the existing checks run or
  deletes the fields.
- Enabling the DHT, YARA distribution, or ML-KEM sessions. Those remain
  separate work.
- Certificate-embedded roles or message-level capability tokens.
