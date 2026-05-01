# MaluWAF Wave 12 Implementation Plan: Distributed Layer Hardening & High-Performance Consistency

**Status**: W12.1-W12.5 COMPLETE
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
- Refactor `src/mesh/dht/merkle.rs` to support point updates.
- Modify `RecordStoreManager` to update the Merkle tree incrementally when a single record is added or updated.
- Implement a background "Merkle Integrity Worker" that performs a full rebuild only once per hour to correct any drift.
- **Verification**: Benchmark Merkle update time with 100k records; target is < 1ms per update.

**Implementation Notes**:
- Replaced HashMap-based MerkleTree internals with level-ordered hash arrays (`levels: Vec<Vec<Vec<u8>>>`).
- Added `insert_or_update` (O(log N) for existing keys, full rebuild for new keys) and `remove_key` methods.
- Added `update_merkle_incremental` and `remove_merkle_key` to `RecordStoreManager`.
- Replaced `compute_merkle_tree()` with `update_merkle_incremental()` in single-record paths: `store_record_global`, `store_record_edge_cache`, `commit_record_after_quorum`, `handle_record_commit`.
- Bulk operations (sync, snapshot, anti-entropy) retain full `compute_merkle_tree()`.
- Merkle Integrity Worker runs hourly in `start_background_tasks`, logs drift warnings.
- Fixed proof verification for multi-leaf trees (original code had `sibling_hash` field misused in verification).
- Benchmark test `test_benchmark_incremental_update_100k` verifies < 1ms per update with 100K records.
- All 99 DHT unit tests pass, 322 mesh tests pass.

### W12.2: Cryptographically-Enforced Quorum Gossip [COMPLETE]
**Problem**: The "Passive Confirmation" logic in W11.10 allows a single compromised node to gossip unverified records into the "Live" state of peers.
**Task**:
- Update `DhtRecord` in `src/mesh/protocol.rs` to include an optional `quorum_proof` field.
- Modify `store_record_global` to REJECT records in sensitive namespaces (e.g., `verified_upstream:`) if they lack a valid quorum proof, even during sync/gossip.
- Ensure `DhtRecordCommit` and `DhtSyncResponse` properly propagate these proofs.
- **Verification**: Simulate a malicious node gossiping a "Live" record without a quorum proof; verify that honest nodes reject it.

**Implementation Notes**:
- Added `quorum_proof: Vec<QuorumSignatureProto>` field to `DhtRecord` in `src/mesh/protocol.rs:1541`.
- Added `requires_quorum_proof()` method to `DhtAccessControl` (delegates to `requires_quorum()`).
- Added `verify_quorum_proof()` in `src/mesh/dht/signed.rs` — checks distinct node_ids in proof >= required threshold (2/3+1 of known global nodes, minimum 2).
- Modified `commit_record_after_quorum()` in `record_store_message.rs` to embed quorum_proof on the committed record before storing and announcing.
- Modified `handle_record_commit()` to attach quorum_signatures as quorum_proof and verify it for sensitive namespaces. Passive confirmation now requires quorum proof for sensitive namespaces.
- Modified `store_record_global()` in `record_store_crud.rs` to reject remote records in sensitive namespaces (`verified_upstream:`, `tier_claim:`) without a valid quorum_proof.
- Modified `apply_sync()` to skip records in sensitive namespaces that lack quorum_proof.
- Sensitive namespaces: `verified_upstream:` and `tier_claim:` (via `global_signature_required_keys` in `DhtAccessControl`).
- All 105 DHT tests pass, including 6 new quorum-proof verification tests.
- All 30 `DhtRecord` construction sites across 12 files updated with `quorum_proof: Vec::new()`.

### W12.3: Raft/SQLite Storage Optimization (Stability) [COMPLETE]
**Problem**: Raft log reads and state machine apply operations are bottlenecked by unoptimized SQLite queries and global lock contention.
**Task**:
- **WAL Mode & Concurrent Reads**: Ensure `GlobalRegistryLogStorage` and `GlobalRegistryStateMachine` use SQLite WAL mode and appropriate busy timeouts. ✓
- **Log Indexing**: Add a composite index on `log_entries(id, term)` to `src/mesh/raft/state_machine.rs`. ✓
- **Paged Log Reads**: Refactor `GlobalRegistryLogReader::try_get_log_entries` to use SQL `LIMIT` and `OFFSET` instead of loading the entire table. ✓
- **Verification**: Run `bench_raft_throughput` and verify stable leadership under 500 writes/sec. ✓

**Implementation Notes**:
- Added `db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")` in `init_schema` for both `GlobalRegistryStateMachine` and `GlobalRegistryLogStorage`.
- Added composite index `idx_log_entries_id_term` on `log_entries(id, term)`.
- Added `get_log_entries_paged(start_id, limit)` method for paged log reads.
- Refactored `try_get_log_entries` to use paged reads with LIMIT instead of loading all entries and filtering.
- All 84 raft tests pass.

### W12.4: Durable Quorum Recovery (Startup Scan) [COMPLETE]
**Problem**: Records marked as `PendingQuorum` are lost on restart because the ephemeral polling tasks in `store_record_global` do not persist.
**Task**:
- Create a `RecoveryWorker` in `src/mesh/dht/record_store_persist.rs`. ✓
- On startup, scan the `disk_store` for records with `status == PendingQuorum`. ✓
- For each found record, re-initialize a `QuorumRequest` to complete the verification. ✓
- **Verification**: Start a quorum request, kill the node immediately, restart, and verify the record eventually transitions to `Live`. ✓

**Implementation Notes**:
- Added `get_pending_quorum_records()` to `DiskRecordStore` in `record_store_disk.rs:230` which queries SQLite with `WHERE status = ?` using `DhtRecordStatus::PendingQuorum`.
- Added `start_recovery_worker()` to `RecordStoreManager` in `record_store_persist.rs:32` which scans for PendingQuorum records on disk and re-initializes quorum requests.
- RecoveryWorker checks record TTL before re-initializing; expired records are removed.
- Called from `start_background_tasks()` in `record_store_message.rs:482`.
- All 105 `mesh::dht` tests pass.

### W12.5: Trust-Rooted Immutability (Anti-Poisoning) [COMPLETE]
**Problem**: Any node can currently set "immutable" records like `GenesisKeyTransition` on a first-come, first-served basis, allowing for "Race to Poison" attacks.
**Task**:
- Define a "Trust Anchor" (Master Public Key) in `MeshConfig`. ✓
- Modify `store_record_global` to require a signature from the Trust Anchor for any record marked as immutable or belonging to the `Genesis` namespace. ✓
- **Verification**: Attempt to store an unsigned `GenesisKeyTransition` from an unauthorized node and verify rejection. ✓

**Implementation Notes**:
- Added `authorized_genesis_keys: Vec<String>` field to `DhtAccessControl` in `src/mesh/dht/mod.rs:669`.
- Config is loaded from `mesh_config.dht_access_control.authorized_genesis_keys` in `RecordStoreManager::new()`.
- Added `requires_immutability_trust_anchor()` method to `DhtAccessControl` which checks key prefixes in `immutability_required_keys`.
- Modified `store_record_global()` in `record_store_crud.rs:184-220` to check if remote records in immutable namespaces have a signer in `authorized_genesis_keys`. Rejects with warning if no authorized genesis keys configured or signer is not authorized.
- Modified `apply_sync()` in `record_store_crud.rs:810-834` to skip immutable records from unauthorized signers.
- Local records (source_node_id == self.node_id) bypass trust anchor check since they are already validated by local signing.
- All 105 `mesh::dht` tests pass.

---

## Verification Commands
```bash
# Verify Wave 12 implementation
cargo test --package rustwaf --lib mesh::raft
cargo test --package rustwaf --lib mesh::dht

# Run specific performance bench
cargo bench --bench bench_attack_detection_wave10
```
