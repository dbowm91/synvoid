# MaluWAF Wave 11 Implementation Plan: Distributed Layer Optimization & Stability

**Status**: WAVE 11 IN PROGRESS
**Last Updated**: 2026-04-30
**Objective**: Transition the distributed control plane from a research prototype to a production-grade, scalable, and memory-safe architecture.

---

## Executive Summary of Previous Work
- **Waves 1-10 (COMPLETE)**: Established core WAF, Mesh, Raft, and DHT foundations.
- **Phases 1-4 (COMPLETE)**: Hardened DHT record envelopes, versioning, and Raft authorization.
- *Note: Detailed logs of Waves 1-10 are archived in `plans/historical_waves.md` to save context.*

---

## Wave 11: Distributed Layer Optimization & Stability

### W11.1: Hierarchical / Regional Quorum (Scalability) — COMPLETE
**Problem**: Current quorum requires $2/3$ majority of *all* global nodes, which doesn't scale beyond ~100 nodes due to network latency tail-end effects.
**Task**:
- Modify `src/mesh/dht/quorum.rs` and `RecordStoreConfig` to support "Regional Quorum".
- Implement `QuorumRequest::required_signatures` to use a dynamic subset of nodes (e.g., closest 20 global nodes or specific regional hubs) instead of the entire global node list.
- **Verification**: Simulate a 50-node cluster and verify that quorum completes using only the closest regional peers.

**Implementation Notes**:
- Added `QuorumMode` enum (`Full` | `Regional { max_nodes, min_nodes }`) to `quorum.rs`
- Added `QuorumRequest::with_mode()` constructor and `set_regional_nodes()` for regional subset tracking
- Added `select_regional_nodes()` function that sorts global nodes by latency and picks the closest subset
- Added `effective_node_count_for()` which returns regional subset size in regional mode, total count in full mode
- `start_quorum_request()` now constructs regional quorum when `config.regional_quorum_enabled = true`
- Quorum messages are sent only to the regional subset, not all global nodes
- `RecordStoreConfig` gained 3 new fields: `regional_quorum_enabled`, `regional_quorum_max_nodes`, `regional_quorum_min_nodes`
- Full backward compatibility: default is `Full` mode (disabled by default)
- 11 unit tests including 50-node regional quorum simulation

### W11.2: Streaming Raft Snapshots (Memory Safety)
**Problem**: `src/mesh/raft/network.rs` reads the entire state machine into a `Vec<u8>`, causing OOM on large threat feeds.
**Task**:
- Refactor `MeshRaftNetwork::full_snapshot` and `GlobalRegistryStateMachine` to use a streaming `AsyncRead` interface.
- Implement chunked serialization in `state_machine.rs` so the snapshot is never fully materialized in RAM.
- **Verification**: Run a Raft snapshot test with a 1GB dummy state and verify RSS memory remains stable (< 256MB).

### W11.3: Two-Phase Commit for DHT Quorum (Consistency)
**Problem**: Records are "leaked" via gossip before quorum is reached, leading to edge nodes acting on unconfirmed state.
**Task**:
- Introduce `DhtRecordStatus::PendingQuorum` in `src/mesh/protocol.rs`.
- Update `store_record_global` to block gossip announcements for records requiring quorum until the `Approved` result is received.
- Add a "Commit" message type to the DHT protocol to transition records from `Pending` to `Live`.
- **Verification**: Test that a record requiring quorum is NOT visible to `get_record` on non-origin nodes until quorum is approved.

### W11.4: Async PQC Verification Queue (Performance)
**Problem**: Synchronous PQC signature verification in the network hot-path increases latency floor and is vulnerable to CPU-exhaustion DDoS.
**Task**:
- Implement a dedicated `VerificationPool` (using `tokio::task::spawn_blocking` or a separate thread pool) for `ml_dsa` and `ml_kem` operations.
- Refactor `peer_auth.rs` and `record_store_crud.rs` to use this async verification.
- **Verification**: Benchmark "Mesh Message Processing" latency under high signature churn; expect ~30% reduction in P99 latency.

### W11.5: Disk-Backed DHT Storage (Persistence)
**Problem**: `ShardedRecordStore` is purely in-memory; restarts require expensive full-syncs and RAM usage scales linearly with data.
**Task**:
- Replace `BTreeMap` shards in `src/mesh/dht/record_store.rs` with a disk-backed KV store (recommend `sled` for minimal dependencies or a simple LSM-tree implementation if already present).
- Implement `record_store_persist.rs` to handle transparent recovery of DHT state on startup.
- **Verification**: Store 10k records, restart the process, and verify all records are reachable without a network sync.

---

## Verification Commands
```bash
# Verify Wave 11 implementation doesn't break existing consensus
cargo test --package rustwaf --lib mesh::raft
cargo test --package rustwaf --lib mesh::dht

# Run specific scalability bench
cargo bench --bench bench_broadcast
```
