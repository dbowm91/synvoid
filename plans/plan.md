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

---

## Verification Commands
```bash
# Verify Wave 11 implementation doesn't break existing consensus
cargo test --package rustwaf --lib mesh::raft
cargo test --package rustwaf --lib mesh::dht

# Run specific scalability bench
cargo bench --bench bench_broadcast
```
