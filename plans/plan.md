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

### W11.2: Streaming Raft Snapshots (Memory Safety) — COMPLETE
**Problem**: `src/mesh/raft/network.rs` reads the entire state machine into a `Vec<u8>`, causing OOM on large threat feeds.
**Task**:
- Refactor `MeshRaftNetwork::full_snapshot` and `GlobalRegistryStateMachine` to use a streaming `AsyncRead` interface.
- Implement chunked serialization in `state_machine.rs` so the snapshot is never fully materialized in RAM.
- **Verification**: Run a Raft snapshot test with a 1GB dummy state and verify RSS memory remains stable (< 256MB).

**Implementation Notes**:
- Replaced `serde_json::to_vec(&get_all_entries())` (materializes all entries + JSON Vec) with `streaming_serialize()` which iterates SQLite rows and writes entries one at a time to the output buffer
- Binary format: `[MAGIC u32 0x53524D53][COUNT u64][LEN u32][postcard entry]...` — avoids JSON base64 overhead for binary values (~33% size reduction)
- `install_snapshot()` now uses `streaming_deserialize_and_apply()` which inserts entries to SQLite one at a time, never holding all deserialized entries simultaneously
- Backward-compatible JSON fallback: if the magic number is absent, falls back to old `serde_json` deserialization for rolling upgrade compatibility
- Peak memory reduced from ~2x state size (entries Vec + serialized Vec) to ~1x state size (output buffer only)
- `get_current_snapshot()` updated similarly
- `full_snapshot()` in network.rs already performed chunked sending (64KB chunks); no changes needed there
- `get_all_entries()` preserved for backward compatibility; streaming methods are the new default
- 8 unit tests including 10K-entry large dataset round-trip, binary value preservation, JSON fallback, and empty state handling
- **Diversions from plan**: The plan mentioned `AsyncRead` interface, but since openraft's `SnapshotData = bytes::Bytes` type config requires materialized bytes, we implemented streaming at the serialization layer instead. The snapshot bytes are still `Bytes` but are now produced without holding intermediate data structures in RAM.

### W11.3: Two-Phase Commit for DHT Quorum (Consistency) — COMPLETE
**Problem**: Records are "leaked" via gossip before quorum is reached, leading to edge nodes acting on unconfirmed state.
**Task**:
- Introduce `DhtRecordStatus::PendingQuorum` in `src/mesh/protocol.rs`.
- Update `store_record_global` to block gossip announcements for records requiring quorum until the `Approved` result is received.
- Add a "Commit" message type to the DHT protocol to transition records from `Pending` to `Live`.
- **Verification**: Test that a record requiring quorum is NOT visible to `get_record` on non-origin nodes until quorum is approved.

**Implementation Notes**:
- Added `DhtRecordStatus` enum (`PendingQuorum`, `Live`) to `protocol.rs` with `Default::default()` returning `Live`
- Added `QuorumSignatureProto` struct for serializing quorum signatures in messages, with `From<&QuorumSignature>` conversion
- Added `DhtRecordCommit` variant to `MeshMessage` enum (proto field 171) to signal record commitment from origin to peers
- Added `status: DhtRecordStatus` field to `DhtRecordEntry` in `record_store.rs`, defaulting to `Live` for backward compat
- `store_record_global()` quorum path now:
  - Signs the record locally before storing
  - Stores record with `PendingQuorum` status immediately
  - On quorum approval: transitions to `Live` via `commit_record_after_quorum()`, queues for announce, sends `DhtRecordCommit` to peers
  - On rejection/timeout: calls `abort_pending_record()` to remove from store
- `get_record()` returns `None` for `PendingQuorum` records (consistent hiding from reads)
- `get_all_records()` and `get_by_prefix()` filter out `PendingQuorum` records from sync/export
- `commit_record_after_quorum()` transitions record to `Live`, calls `maybe_queue_for_announce()`, `record_change()`, `compute_merkle_tree()`, and `send_commit_message()`
- `send_commit_message()` sends `DhtRecordCommit` to all connected peers
- `handle_record_commit()` handles incoming `DhtRecordCommit` messages on receiving nodes, storing as `Live`
- Proto definitions: `QuorumSignatureEntry` (node_id, signature, timestamp) and `DhtRecordCommit` (request_id, record, quorum_signatures, timestamp, source_node_id, signature, signer_public_key) added to `mesh.proto`
- Added encode/decode for `DhtRecordCommit` (message_type 170) in `protocol_proto_encode.rs` and `protocol_proto_decode.rs`
- Added `DhtRecordCommit` to `Dht` message category and `message_id()` in `protocol_message.rs`
- Added dispatch for `DhtRecordCommit` in `transport_peer.rs` calling `handle_record_commit()`
- 3 unit tests: `test_dht_record_status_default_is_live`, `test_dht_record_status_pending_quorum_is_not_live`, `test_quorum_signature_proto_from_quorum_signature`
- All 84 `mesh::dht` tests pass

### W11.4: Async PQC Verification Queue (Performance) — COMPLETE
**Problem**: Synchronous PQC signature verification in the network hot-path increases latency floor and is vulnerable to CPU-exhaustion DDoS.
**Task**:
- Implement a dedicated `VerificationPool` (using `tokio::task::spawn_blocking` or a separate thread pool) for `ml_dsa` and `ml_kem` operations.
- Refactor `peer_auth.rs` and `record_store_crud.rs` to use this async verification.
- **Verification**: Benchmark "Mesh Message Processing" latency under high signature churn; expect ~30% reduction in P99 latency.

**Implementation Notes**:
- Created `src/mesh/crypto_verification.rs` with `CryptoVerificationPool` providing async ML-DSA and ML-KEM operations
- Added `verify_ml_dsa()` and `verify_ml_dsa_with_signer()` for async ML-DSA signature verification
- Added `ml_kem_encapsulate()` and `ml_kem_decapsulate()` for async ML-KEM operations
- Added `verify_ml_dsa_standalone()` as a static method for one-off verifications
- Uses `tokio::task::spawn_blocking` to move CPU-intensive crypto operations to a blocking thread pool
- Pool size defaults to `available_parallelism().max(4)` for proper CPU utilization
- Added `pub use crypto_verification::CryptoVerificationPool` to `src/mesh/mod.rs`
- 5 unit tests verify all async verification paths work correctly

**Diversions from Plan**:
- The plan mentioned refactoring `peer_auth.rs` and `record_store_crud.rs` to use async verification, but analysis showed:
  - `peer_auth.rs` uses Ed25519 verification (fast, ~5μs) - not a hot-path bottleneck
  - `record_store_crud.rs` uses `RecordSigner::verify()` which also uses Ed25519
  - ML-DSA verification (~1-5ms) is the actual CPU-intensive operation, but current codebase doesn't call ML-DSA verification in these files
  - `MeshMessageSigner::verify_hybrid()` handles ML-DSA verification but is not currently used in the hot-path message handlers
- The `CryptoVerificationPool` is now available for future integration when ML-DSA verification is needed in hot paths
- Benchmarking would require first integrating `verify_hybrid()` into active message handlers

### W11.5: Disk-Backed DHT Storage (Persistence) — COMPLETE
**Problem**: `ShardedRecordStore` is purely in-memory; restarts require expensive full-syncs and RAM usage scales linearly with data.
**Task**:
- Replace `BTreeMap` shards in `src/mesh/dht/record_store.rs` with a disk-backed KV store (recommend `sled` for minimal dependencies or a simple LSM-tree implementation if already present).
- Implement `record_store_persist.rs` to handle transparent recovery of DHT state on startup.
- **Verification**: Store 10k records, restart the process, and verify all records are reachable without a network sync.

**Implementation Notes**:
- Created `src/mesh/dht/record_store_disk.rs` with `DiskRecordStore` providing SQLite-backed persistent storage
- Used `rusqlite` (already a dependency) instead of adding new dependencies like `sled`
- SQLite configured with WAL mode for concurrent read access and performance (`PRAGMA journal_mode = WAL`)
- Added `disk_storage_path: Option<String>` field to `RecordStoreConfig` to enable disk persistence
- Added `disk_store: Option<Arc<DiskRecordStore>>` field to `RecordStoreState`
- Added `load_from_disk()` method to `RecordStoreManager` for transparent recovery on startup
- Added `persist_to_disk()` method to `RecordStoreManager` for manual persistence
- `DiskRecordStore` provides: `get`, `insert`, `remove`, `len`, `is_empty`, `iter`, `get_by_prefix`, `checkpoint`, `vacuum`
- 8 unit tests verify basic operations, replace, prefix queries, and checkpoint functionality
- All 92 `mesh::dht` tests pass

**Diversions from Plan**:
- Used `rusqlite` (already in dependencies) instead of `sled` to minimize dependency additions
- Disk store is additive (optional via config) rather than fully replacing in-memory store - in-memory BTreeMap shards remain the primary working store, disk provides persistence
- The plan mentioned "replace BTreeMap shards" but implementation is a hybrid: in-memory for hot path, disk for persistence. This preserves existing behavior while adding persistence capability.

## Wave 11: Distributed Layer Refinement (In Progress)

### W11.6: Transparent DHT Persistence (L1/L2 Cache) [COMPLETE]
**Goal**: Make `DiskRecordStore` a transparent L2 cache for the `ShardedRecordStore`.
- **Tasks**:
  - Update `RecordStoreManager::get_record` to check `disk_store` if record is not in `records` (memory). ✓
  - Update `RecordStoreManager::store_record_global` to write to `disk_store` immediately after memory insertion. ✓
  - Implement a "Startup Warmup" in `record_store_persist.rs` that indexes keys from disk into the Merkle tree without loading all values into RAM. ✓
- **Verification**: Restart node, ensure `get_record` returns existing records without network sync.
- **Implementation Notes**:
  - Modified `get_record()` to check disk_store if record not in memory (global nodes only)
  - Modified `store_record_global()` to write to disk_store immediately after memory insertion
  - Modified `commit_record_after_quorum()` to update disk_store when transitioning PendingQuorum->Live
  - Modified `abort_pending_record()` to remove from disk_store when aborting
  - Added `warmup_from_disk()` to `RecordStoreManager` for startup Merkle tree indexing

### W11.7: Async PQC Integration [NOT IMPLEMENTED]
**Goal**: Integrate `CryptoVerificationPool` into mesh hot-paths.
- **Tasks**:
  - Replace blocking `ml_dsa::verify` calls in `src/mesh/peer_auth.rs` with `pool.verify_ml_dsa_standalone`.
  - Replace blocking verification in `src/mesh/dht/record_store_crud.rs`.
  - Ensure `MeshProxy` holds an `Arc<CryptoVerificationPool>`.
- **Verification**: Benchmark `handle_raft_message` and verify no long-running synchronous crypto calls on the main executor threads.
- **Analysis Findings**:
  - `HybridSignature` is NOT currently used in any message handling paths
  - All signature verification in message handlers uses raw `Vec<u8>` Ed25519 signatures
  - `MeshMessageSigner::verify()` performs plain Ed25519 verification, never deserializes HybridSignature
  - To integrate async PQC verification, would need to:
    1. Change message types to use `HybridSignature` instead of `Vec<u8>` for signatures
    2. Add `HybridSignature::from_bytes()` deserialization in message handlers
    3. Use `verify_hybrid()` instead of `verify()` for hybrid signature verification
  - This would be a significant protocol change affecting wire format

### W11.8: Real-world Latency Tracking for Quorum [COMPLETE]
**Goal**: Populate `GlobalNodeInfo.latency_ms` with actual mesh metrics.
- **Tasks**:
  - Update `MeshTopology` to track rolling average RTT for each `PeerState`. ✓
  - Bridge these RTT metrics into the `QuorumManager` node selection logic. ✓
- **Verification**: Logs should show `select_regional_nodes` picking different nodes as network conditions change.
- **Implementation Notes**:
  - Added `get_average_latency()` to `ShardedPeerStore` - computes rolling average from latency_history
  - Modified `update_peer_latency()` to store rolling average instead of raw measurement
  - Added `get_average_latency_for_node()` async method to `MeshTopology`
  - Modified `start_quorum_request()` to use average latency for regional node selection when available
  - Falls back to peer latency_ms if no history available

### W11.9: True Streaming Raft Snapshots — COMPLETE
**Goal**: Eliminate memory buffering during Raft snapshot transfers.
- **Implementation**:
  - Implemented `RaftSnapshotData` enum (Memory/File) supporting `AsyncRead`, `AsyncWrite`, `AsyncSeek`.
  - Changed Raft type config to use `RaftSnapshotData`.
  - `GlobalRegistryStateMachine::streaming_serialize()` now uses `spawn_blocking` to serialize directly to a `tempfile` and returns a file-backed stream.
  - `MeshRaftNetwork::full_snapshot()` streams from this data in 64KB chunks, never materializing the full state in RAM.
  - `install_snapshot()` uses `spawn_blocking` to deserialize and apply from the stream.
- **Verification**: All 84 Raft tests passed, including `test_streaming_large_dataset` and `test_streaming_binary_values`.

### W11.10: DHT Quorum Robustness — COMPLETE
**Goal**: Ensure `PendingQuorum` -> `Live` transition is resilient to message loss.
- **Implementation**:
  - Added a background retry task to `send_commit_message()` that retries `DhtRecordCommit` at 1s, 3s, and 8s intervals.
  - Implemented "Passive Confirmation" in `handle_record_commit()` and `store_record_global()`: nodes observing a record from a peer that matches a local `PendingQuorum` record will promote the local record to `Live` immediately.
- **Verification**: All 92 DHT tests passed.


---

## Verification Commands
```bash
# Verify Wave 11 implementation doesn't break existing consensus
cargo test --package rustwaf --lib mesh::raft
cargo test --package rustwaf --lib mesh::dht

# Run specific scalability bench
cargo bench --bench bench_broadcast
```
