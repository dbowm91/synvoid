# MaluWAF Wave 12 Implementation Plan: Distributed Layer Hardening & High-Performance Consistency

**Status**: WAVE 12 PLANNED
**Last Updated**: 2026-05-01
**Objective**: Hardened DHT consistency, scalable Merkle state management, and production-grade Raft storage stability.

---

## Executive Summary of Previous Work
- **Waves 1-11 (COMPLETE)**: Established WAF, Mesh, Raft, and DHT foundations. Implemented regional quorums, disk-backed DHT storage, and streaming Raft snapshots.
- *Note: Detailed logs of Waves 1-11 are archived in `plans/historical_waves.md` to save context.*

---

## Wave 12: Distributed Layer Hardening & High-Performance Consistency

### W12.1: Incremental Merkle Updates ($O(\log N)$ Scalability) [AGENT-PRECISION]
**Problem**: `RecordStoreManager::compute_merkle_tree` rebuilds the entire tree from scratch on every change, causing $O(N)$ CPU spikes and lock contention as the DHT grows.
**Task**:
- Refactor `src/mesh/dht/merkle.rs` to support point updates.
- Modify `RecordStoreManager` to update the Merkle tree incrementally when a single record is added or updated.
- Implement a background "Merkle Integrity Worker" that performs a full rebuild only once per hour to correct any drift.
- **Verification**: Benchmark Merkle update time with 100k records; target is < 1ms per update.

### W12.2: Cryptographically-Enforced Quorum Gossip [AGENT-PRECISION]
**Problem**: The "Passive Confirmation" logic in W11.10 allows a single compromised node to gossip unverified records into the "Live" state of peers.
**Task**:
- Update `DhtRecord` in `src/mesh/protocol.rs` to include an optional `quorum_proof` field.
- Modify `store_record_global` to REJECT records in sensitive namespaces (e.g., `verified_upstream:`) if they lack a valid quorum proof, even during sync/gossip.
- Ensure `DhtRecordCommit` and `DhtSyncResponse` properly propagate these proofs.
- **Verification**: Simulate a malicious node gossiping a "Live" record without a quorum proof; verify that honest nodes reject it.

### W12.3: Raft/SQLite Storage Optimization (Stability)
**Problem**: Raft log reads and state machine apply operations are bottlenecked by unoptimized SQLite queries and global lock contention.
**Task**:
- **WAL Mode & Concurrent Reads**: Ensure `GlobalRegistryLogStorage` and `GlobalRegistryStateMachine` use SQLite WAL mode and appropriate busy timeouts.
- **Log Indexing**: Add a composite index on `log_entries(id, term)` to `src/mesh/raft/state_machine.rs`.
- **Paged Log Reads**: Refactor `GlobalRegistryLogReader::try_get_log_entries` to use SQL `LIMIT` and `OFFSET` instead of loading the entire table.
- **Verification**: Run `bench_raft_throughput` and verify stable leadership under 500 writes/sec.

### W12.4: Durable Quorum Recovery (Startup Scan)
**Problem**: Records marked as `PendingQuorum` are lost on restart because the ephemeral polling tasks in `store_record_global` do not persist.
**Task**:
- Create a `RecoveryWorker` in `src/mesh/dht/record_store_persist.rs`.
- On startup, scan the `disk_store` for records with `status == PendingQuorum`.
- For each found record, re-initialize a `QuorumRequest` to complete the verification.
- **Verification**: Start a quorum request, kill the node immediately, restart, and verify the record eventually transitions to `Live`.

### W12.5: Trust-Rooted Immutability (Anti-Poisoning)
**Problem**: Any node can currently set "immutable" records like `GenesisKeyTransition` on a first-come, first-served basis, allowing for "Race to Poison" attacks.
**Task**:
- Define a "Trust Anchor" (Master Public Key) in `MeshConfig`.
- Modify `store_record_global` to require a signature from the Trust Anchor for any record marked as immutable or belonging to the `Genesis` namespace.
- **Verification**: Attempt to store an unsigned `GenesisKeyTransition` from an unauthorized node and verify rejection.

---

## Verification Commands
```bash
# Verify Wave 12 implementation
cargo test --package rustwaf --lib mesh::raft
cargo test --package rustwaf --lib mesh::dht

# Run specific performance bench
cargo bench --bench bench_attack_detection_wave10
```
