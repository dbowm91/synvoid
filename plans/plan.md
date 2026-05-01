# MaluWAF Wave 13 Plan: Mesh/DHT/Raft Correctness Hardening

**Status**: COMPLETED
**Last Updated**: 2026-05-01
**Scope**: `src/mesh/`, especially DHT quorum/proof validation, DHT sync/snapshot/authentication, disk-backed DHT persistence, and Raft snapshot/log correctness.

## Implementation Summary

All priorities 0-8 have been completed:

| Priority | Description | Status |
|---------|-------------|--------|
| 0 | Regression tests proving current failures | ✅ 8 tests added |
| 1 | Cryptographic quorum proof verification | ✅ `verify_quorum_proof` now verifies signatures |
| 2 | Bind DHT payload identity to transport identity | ✅ Added `is_local_origin` parameter |
| 3 | Fix DHT snapshot/sync authentication compatibility | ✅ Unified signable content, fixed record type |
| 4 | Persist full DHT security metadata | ✅ Schema now includes all fields |
| 5 | Correct timestamp semantics | ✅ Split `validate_record_timestamp` and `validate_message_freshness` |
| 6 | Make Raft snapshot framing explicit | ✅ Added `RaftSnapshotFrame` enum |
| 7 | Preserve Raft log terms on replay | ✅ Now uses actual persisted term |
| 8 | Reduce verification drift across ingress paths | ✅ Centralized verification |

## Context

Wave 12 is complete and has been pruned from this file to save context. The next agent should treat this as the active plan.

Recent read-only review of the distributed layer found several correctness and security risks:

- `verify_quorum_proof()` currently counts distinct `node_id`s but does not cryptographically verify the quorum signatures.
- DHT ingress decides whether a record is local from payload-controlled `source_node_id`.
- DHT snapshot request signing and verification use different signable payloads.
- Verified snapshot/sync replay reconstructs records as the wrong `SignedRecordType`.
- Disk-backed DHT storage drops signatures, signer keys, and quorum proofs.
- Record timestamp validation rejects old-but-still-live records.
- Raft snapshot transfer distinguishes header vs chunk by payload length.
- Raft log replay appears to reconstruct stored log IDs with term `0` instead of persisted terms.

The goal is to make the distributed layer fail closed, converge after restarts/partitions, and have adversarial regression tests for each issue.

## Ground Rules

- Read `AGENTS.md` and `src/mesh/AGENTS.override.md` before editing.
- Keep changes scoped to mesh/DHT/Raft unless a test helper requires small adjacent changes.
- Preserve hot-path performance. Avoid extra allocation in per-request proxy paths.
- Use typed/canonical signable structs and postcard or the repo's `crate::serialization` helper for distributed signatures. Do not add JSON to distributed state paths.
- Do not trust payload identity when transport identity is available.
- Add regression tests before or alongside fixes. A fix without an adversarial test is incomplete.

## Priority 0: Prove Current Failures With Tests

Create focused tests that fail on current behavior before broad refactors.

Suggested locations:

- `src/mesh/dht/signed.rs` for low-level quorum proof tests.
- `src/mesh/dht/record_store_sync.rs` or existing DHT test modules for snapshot/sync tests.
- `src/mesh/dht/record_store_disk.rs` for disk round-trip tests.
- `src/mesh/raft/regression_tests.rs` for Raft snapshot/log tests.

Required tests:

1. Forged quorum proof with two arbitrary `node_id`s and fake signatures must be rejected for `verified_upstream:*` and `tier_claim:*`.
2. Quorum proof signatures must fail if replayed onto a different key, value hash, TTL, sequence number, origin node, or request ID.
3. A remote DHT record whose `source_node_id` equals the local node ID must be rejected unless the authenticated sender is actually local.
4. Snapshot request signature round trip: `create_snapshot_request()` output must verify in `handle_dht_snapshot_request()`.
5. Verified snapshot/sync must accept valid non-`Organization` record types such as `NodeInfo`, `DnsRecord`, and immutable/YARA records when correctly signed.
6. Disk persistence must round-trip `signature`, `signer_public_key`, `content_hash`, `quorum_proof`, `sequence_number`, status, and local origin.
7. Old-but-live records, for example timestamp `now - 600` with TTL `3600`, must be accepted during sync/storage; future-skewed records beyond the configured window must still be rejected.
8. Raft snapshot transfer must handle small snapshots and short final chunks without confusing chunks for headers.
9. Raft log reload must preserve mixed terms across restart/reopen.

## Priority 1: Cryptographic Quorum Proof Verification

Problem files:

- `src/mesh/dht/signed.rs`
- `src/mesh/dht/quorum.rs`
- `src/mesh/dht/record_store_crud.rs`
- `src/mesh/dht/record_store_message.rs`
- `src/mesh/protocol.rs`

Current risk:

`verify_quorum_proof(record, total_known_global_nodes)` only counts distinct `node_id`s in `record.quorum_proof`. It does not verify the signature bytes, confirm that the signer is an authorized global node, or bind signatures to the specific record content.

Implementation requirements:

- Define one canonical quorum-proof signable payload. It should include at least:
  - `request_id`
  - `key`
  - `value_hash` or content hash
  - `ttl_seconds`
  - `sequence_number`
  - `origin_node_id`
  - action/add-delete semantic if relevant
  - protocol version/domain separator such as `"maluwaf:dht-quorum:v1"`
- Ensure `QuorumSignatureProto` carries enough data to verify:
  - signer node ID
  - signature
  - signer public key or a resolvable reference to the global-node public key
  - timestamp if replay windows are enforced
- Verify each signature against the known public key for that global node.
- Count only verified, distinct, authorized global-node signatures.
- Pass actual known global-node count or selected regional quorum size into verification. Do not call verification with `0` unless that is explicitly the two-node test mode.
- Ensure regional quorum proofs encode or derive the selected regional voter set. Otherwise a small regional proof can be replayed as if it represented full quorum.
- Reject proofs signed for a different record, request, origin, or action.

Acceptance criteria:

- Forged proofs with fake signatures are rejected.
- Duplicate signer IDs are counted once.
- Valid proofs survive commit, gossip, sync, and disk reload.
- Sensitive namespaces still require proof by default.

## Priority 2: Bind DHT Payload Identity To Transport Identity

Problem files:

- `src/mesh/dht/record_store_crud.rs`
- `src/mesh/dht/record_store_message.rs`
- `src/mesh/transport_dht.rs`
- `src/mesh/transport_peer.rs`

Current risk:

`store_record_global()` sets `is_local_record` from `record.source_node_id == self.node_id`. Remote senders can set that field. Some ingress paths pass records onward without first proving that `from_node`, `source_node_id`, and signer identity are consistent.

Implementation requirements:

- Add an ingress-level identity check before calling local/global store logic:
  - remote sender identity must match `record.source_node_id`, or
  - the record must carry an explicit delegation/cross-signature that authorizes the sender to publish for `source_node_id`.
- For records arriving from the network, never classify as local based only on payload fields.
- Split the concept of local origin from record publisher:
  - local process-created records can bypass remote signature requirements only at creation time.
  - network-received records must always be treated as remote.
- Reject DHT announces, pushes, commits, sync records, and anti-entropy records when transport sender, source node, and signer identity conflict.

Acceptance criteria:

- Spoofed `source_node_id == self.node_id` from a remote peer cannot bypass signature checks or start local quorum flow.
- Tests cover announce, sync, commit, and push paths where practical.

## Priority 3: Fix DHT Snapshot/Sync Authentication Compatibility

Problem files:

- `src/mesh/dht/record_store_sync.rs`
- `src/mesh/transport_dht.rs`
- `src/mesh/dht/signed.rs`

Current risks:

- Snapshot requests are signed with anti-entropy request content but verified as a comma-formatted string.
- Sync/snapshot response verification paths are duplicated and easy to drift.
- Verified snapshot/sync replay reconstructs records with hard-coded `SignedRecordType::Organization` in at least one path.

Implementation requirements:

- Add a dedicated `DhtSnapshotRequestSignable` struct in `signed.rs`.
- Use the same function for snapshot request signing and verification.
- Include timestamp in snapshot requests if replay protection is needed. If wire type currently lacks timestamp, either add one with backward-compatible decode handling or explicitly document why request ID and transport layer are enough.
- Replace hard-coded record type reconstruction with key-derived type:
  - use `DhtKey::from_str(&record.key).to_signed_record_type()`
  - reject unknown privileged/signed namespaces by default
  - handle public unsigned cacheable records only where policy allows
- Prefer a single `verify_dht_record_signature()` helper for all record replay paths.

Acceptance criteria:

- Snapshot request round-trip test passes.
- Valid signed non-organization records apply from snapshot/sync.
- Invalid record signatures are rejected consistently in snapshot, sync, anti-entropy, and announce paths.

## Priority 4: Persist Full DHT Security Metadata

Problem file:

- `src/mesh/dht/record_store_disk.rs`
- also check `src/mesh/dht/record_store.rs` and `src/mesh/dht/record_store_persist.rs`

Current risk:

SQLite disk storage persists only partial `DhtRecord` fields. Reloaded records have empty `signature`, `signer_public_key`, and `quorum_proof`, so restarted global nodes lose the authenticity metadata required for safe sync/gossip/reverification.

Implementation options:

Preferred:

- Store a full canonical serialized `DhtRecord` blob plus indexed metadata columns needed for lookup, expiry, status, and version.

Acceptable:

- Add explicit columns for all missing fields:
  - `signature BLOB`
  - `signer_public_key TEXT NULL`
  - `quorum_proof BLOB`
  - any future auth metadata introduced by Priority 1

Implementation requirements:

- Add migration handling for existing DBs missing the new columns.
- Preserve backward compatibility by treating legacy rows as unverifiable remote records. Do not silently promote them into sensitive live records.
- Verify loaded records before warming the in-memory cache when they are in privileged/sensitive namespaces.
- Ensure `PendingQuorum` records retain enough proof/request metadata for recovery.

Acceptance criteria:

- Disk round-trip preserves all `DhtRecord` fields.
- Restarted nodes can still verify and reannounce valid records.
- Legacy rows without auth metadata are denied for sensitive namespaces or quarantined.

## Priority 5: Correct Timestamp Semantics

Problem file:

- `src/mesh/dht/signed.rs`
- callers in `record_store_crud.rs`, sync, snapshot, anti-entropy paths

Current risk:

`validate_record_timestamp()` rejects records whose timestamp differs from local clock by more than 300 seconds in either direction. That rejects old-but-live records during sync/recovery even when TTL has not expired.

Implementation requirements:

- Split validation into two helpers:
  - message freshness: reject too old and too far future for replay-prone envelope messages.
  - record timestamp: reject only timestamps too far in the future; expiry is handled by `timestamp + ttl_seconds`.
- Use `saturating_add` and `saturating_sub` consistently.
- Audit all callers and choose the correct helper.

Acceptance criteria:

- Old-but-live records sync successfully.
- Expired records are still rejected.
- Future-skewed records beyond the window are still rejected.

## Priority 6: Make Raft Snapshot Framing Explicit

Problem files:

- `src/mesh/raft/network.rs`
- `src/mesh/transport_peer.rs`
- `src/mesh/protocol.rs`
- proto encode/decode files if the frame is part of wire protocol

Current risk:

`transport_peer.rs` decides whether an `InstallSnapshot` payload is a header or chunk with `payload.data.len() < 100`. Small chunks or short final chunks can be misparsed as headers.

Implementation requirements:

- Add explicit framing, for example:
  - `RaftSnapshotFrame::Header(SnapshotHeader)`
  - `RaftSnapshotFrame::Chunk(SnapshotChunk)`
- Encode/decode that frame instead of guessing by length.
- Keep backward compatibility if rolling upgrades are required:
  - attempt new frame decode first
  - optionally fall back to old heuristic only for a limited compatibility window
  - add logging when fallback is used
- Ensure pending snapshot transfer state is cleaned up on timeout, decode error, or failed install.

Acceptance criteria:

- Small snapshot and short-final-chunk regression tests pass.
- No `len() < N` framing heuristic remains for snapshot header/chunk selection.

## Priority 7: Preserve Raft Log Terms On Replay

Problem file:

- `src/mesh/raft/state_machine.rs`

Current risk:

Raft log reader/log-state reconstruction appears to rebuild `LogId` with `CommittedLeaderIdOfConfig::new(0, 0)` rather than the persisted term. That can violate OpenRaft log matching after restart.

Implementation requirements:

- Inspect the `log_entries` schema and persisted fields.
- Rebuild `LogId` using the stored term and node/leader ID information required by the configured OpenRaft version.
- If node ID was not persisted, add schema support or confirm OpenRaft's expected `LeaderId` representation for this type config.
- Add a restart/reopen test with entries from multiple terms.

Acceptance criteria:

- Mixed-term logs reload with correct `LogId`s.
- OpenRaft storage tests and mesh raft regression tests pass after restart.

## Priority 8: Reduce Verification Drift Across Ingress Paths

Problem files:

- `src/mesh/dht/record_store_crud.rs`
- `src/mesh/dht/record_store_message.rs`
- `src/mesh/dht/record_store_sync.rs`
- `src/mesh/transport_dht.rs`

Current risk:

Trust-anchor checks, quorum-proof checks, timestamp checks, and signature checks are duplicated across several paths. Future fixes can easily harden one ingress path while leaving another bypassable.

Implementation requirements:

- Introduce a small internal verifier API, for example:
  - `DhtRecordIngressContext { source: Local | Remote { peer_id }, path, verified_envelope, reputation }`
  - `verify_record_for_store(record, context) -> Result<VerifiedDhtRecord, RejectReason>`
- Centralize:
  - content hash check
  - timestamp/TTL check
  - signer/public-key check
  - trust-anchor check
  - quorum-proof check
  - local-vs-remote classification
  - sensitive namespace policy
- Keep storage mutation separate from verification.

Acceptance criteria:

- Announce, push, sync, snapshot, anti-entropy, and commit paths share the same verification logic or have explicit documented exceptions.
- Tests verify each ingress path rejects the same malformed record class.

## Verification Commands

Run targeted tests during development:

```bash
cargo test --lib mesh::dht
cargo test --lib mesh::raft
cargo test --lib verify_quorum_proof
cargo test --lib snapshot
cargo test --lib record_store_disk
```

Before handoff or PR:

```bash
cargo test --lib --no-run
cargo test --lib mesh::dht
cargo test --lib mesh::raft
cargo fmt
cargo clippy --lib -- -D warnings
```

## Done Criteria

- All Priority 0 tests exist and pass.
- Priorities 1 through 7 are implemented.
- Priority 8 is implemented or at least started enough that new verification logic is not duplicated further.
- Sensitive DHT records cannot be accepted without verified quorum proof.
- Disk persistence preserves security metadata.
- DHT sync/snapshot paths recover correctly after restart.
- Raft snapshot and log replay have deterministic regression coverage.
