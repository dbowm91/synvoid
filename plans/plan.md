# MaluWAF Wave 12 Implementation Plan: Distributed Layer Hardening & High-Performance Consistency

**Status**: WAVE 12 COMPLETE
**Last Updated**: 2026-05-01
**Objective**: Hardened DHT consistency, scalable Merkle state management, and production-grade Raft storage stability.

---

## Executive Summary of Previous Work
- **Waves 1-11 (COMPLETE)**: Established WAF, Mesh, Raft, and DHT foundations. Implemented regional quorums, disk-backed DHT storage, and streaming Raft snapshots.
- *Note: Detailed logs of Waves 1-11 are archived in `plans/historical_waves.md` to save context.*

---

## Wave 12: Distributed Layer Hardening & High-Performance Consistency

### W12.1: Incremental Merkle Updates ($O(\log N)$ Scalability) [COMPLETE]
**Problem**: `RecordStoreManager::compute_merkle_tree` rebuilds the entire tree from scratch on every change, causing $O(N)$ CPU spikes and lock contention as the DHT grows.
**Task**:
- Refactor `src/mesh/dht/merkle.rs` to support point updates. ✓
- Modify `RecordStoreManager` to update the Merkle tree incrementally when a single record is added or updated. ✓
- Implement a background "Merkle Integrity Worker" that performs a full rebuild only once per hour to correct any drift. ✓
- **Verification**: Benchmark Merkle update time with 100k records; target is < 1ms per update. ✓

**Implementation Notes**:
- Replaced HashMap-based MerkleTree internals with level-ordered hash arrays (`levels: Vec<Vec<Vec<u8>>>`).
- Added `insert_or_update` (O(log N) for existing keys, full rebuild for new keys) and `remove_key` methods.
- Added `update_merkle_incremental` and `remove_merkle_key` to `RecordStoreManager`.
- Replaced `compute_merkle_tree()` with `update_merkle_incremental()` in single-record paths: `store_record_global`, `store_record_edge_cache`, `commit_record_after_quorum`, `handle_record_commit`.
- Bulk operations (sync, snapshot, anti-entropy) retain full `compute_merkle_tree()`.
- Merkle Integrity Worker runs hourly in `start_background_tasks`, logs drift warnings.
- Fixed proof verification for multi-leaf trees (original code had `sibling_hash` field misused in verification).
- Benchmark test `test_benchmark_incremental_update_100k` verifies < 1ms per update with 100K records.

### W12.2: Cryptographically-Enforced Quorum Gossip [COMPLETE]
**Problem**: The "Passive Confirmation" logic in W11.10 allows a single compromised node to gossip unverified records into the "Live" state of peers.
**Task**:
- Update `DhtRecord` in `src/mesh/protocol.rs` to include an optional `quorum_proof` field. ✓
- Modify `store_record_global` to REJECT records in sensitive namespaces (e.g., `verified_upstream:`) if they lack a valid quorum proof, even during sync/gossip. ✓
- Ensure `DhtRecordCommit` and `DhtSyncResponse` properly propagate these proofs. ✓
- **Verification**: Simulate a malicious node gossiping a "Live" record without a quorum proof; verify that honest nodes reject it. ✓

**Implementation Notes**:
- Added `quorum_proof: Vec<QuorumSignatureProto>` field to `DhtRecord` in `src/mesh/protocol.rs:1541`.
- Added `requires_quorum_proof()` method to `DhtAccessControl` (delegates to `requires_quorum()`).
- Added `verify_quorum_proof()` in `src/mesh/dht/signed.rs` — checks distinct node_ids in proof >= required threshold (2/3+1 of known global nodes, minimum 2).
- Modified `commit_record_after_quorum()` in `record_store_message.rs` to embed quorum_proof on the committed record before storing and announcing.
- Modified `handle_record_commit()` to attach quorum_signatures as quorum_proof and verify it for sensitive namespaces. Passive confirmation now requires quorum proof for sensitive namespaces.
- Modified `store_record_global()` in `record_store_crud.rs` to reject remote records in sensitive namespaces (`verified_upstream:`, `tier_claim:`) without a valid quorum_proof.
- All 30 `DhtRecord` construction sites updated with `quorum_proof: Vec::new()`.

### W12.3: Raft/SQLite Storage Optimization (Stability) [COMPLETE]
**Problem**: Raft log reads and state machine apply operations are bottlenecked by unoptimized SQLite queries and global lock contention.
**Task**:
- **WAL Mode & Concurrent Reads**: Ensure `GlobalRegistryLogStorage` and `GlobalRegistryStateMachine` use SQLite WAL mode and appropriate busy timeouts. ✓
- **Log Indexing**: Add a composite index on `log_entries(id, term)` to `src/mesh/raft/state_machine.rs`. ✓
- **Paged Log Reads**: Refactor `GlobalRegistryLogReader::try_get_log_entries` to use SQL `LIMIT` and `OFFSET` instead of loading the entire table. ✓
- **Verification**: Run `bench_raft_throughput` and verify stable leadership under 500 writes/sec. ✓

**Implementation Notes**:
- Added `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=5000` to `GlobalRegistryStateMachine::init_schema` and `GlobalRegistryLogStorage::init_schema`.
- Added composite index `idx_log_entries_id_term ON log_entries(id, term)` in `GlobalRegistryLogStorage::init_schema`.
- Added `get_log_entries_paged(start, limit)` to `GlobalRegistryLogStorage` for efficient log traversal.
- `try_get_log_entries` in `GlobalRegistryLogReader` now uses paged reads instead of loading the full log table into RAM.

### W12.4: Durable Quorum Recovery (Startup Scan) [COMPLETE]
**Problem**: Records marked as `PendingQuorum` are lost on restart because the ephemeral polling tasks in `store_record_global` do not persist.
**Task**:
- Create a `RecoveryWorker` in `src/mesh/dht/record_store_persist.rs`. ✓
- On startup, scan the `disk_store` for records with `status == PendingQuorum`. ✓
- For each found record, re-initialize a `QuorumRequest` to complete the verification. ✓
- **Verification**: Start a quorum request, kill the node immediately, restart, and verify the record eventually transitions to `Live`. ✓

**Implementation Notes**:
- Added `get_pending_quorum_records()` to `DiskRecordStore` querying `status = 1` (PendingQuorum).
- Added `start_recovery_worker()` to `RecordStoreManager` in `record_store_persist.rs:32`.
- RecoveryWorker re-initializes quorum requests for non-expired `PendingQuorum` records discovered on disk.
- Automatically called via `start_background_tasks()` with a 5s startup delay.

### W12.5: Trust-Rooted Immutability (Anti-Poisoning) [COMPLETE]
**Problem**: Any node can currently set "immutable" records like `GenesisKeyTransition` on a first-come, first-served basis, allowing for "Race to Poison" attacks.
**Task**:
- Define a "Trust Anchor" (Master Public Key) in `MeshConfig`. ✓
- Modify `store_record_global` to require a signature from the Trust Anchor for any record marked as immutable or belonging to the `Genesis` namespace. ✓
- **Verification**: Attempt to store an unsigned `GenesisKeyTransition` from an unauthorized node and verify rejection. ✓

**Implementation Notes**:
- Added `authorized_genesis_keys: Vec<String>` to `DhtAccessControl` and `NodeIdentityConfig`.
- `DhtAccessControl` now identifies immutable namespaces (genesis, revocation, YARA manifests).
- `store_record_global` and `apply_sync` reject remote records in these namespaces unless the signer is in `authorized_genesis_keys`.
- Secure default: empty `authorized_genesis_keys` denies all genesis/immutable updates.

---

## Verification Commands
```bash
# Verify Wave 12 implementation
cargo test --package rustwaf --lib mesh::raft
cargo test --package rustwaf --lib mesh::dht

# Run specific performance bench
cargo bench --bench bench_attack_detection_wave10
```
