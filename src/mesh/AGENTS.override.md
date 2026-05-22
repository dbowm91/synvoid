# Mesh Module - AGENTS.override.md

Specialized guidance for mesh networking, DHT, and Raft consensus.

## Architecture Overview

### Overseer/Master/Worker IPC

The overseer/master/worker architecture uses:
- Unix domain sockets for IPC
- `Message` enum in `src/process/ipc.rs` for communication
- `ProcessManager` for worker lifecycle
- Health checks via IPC heartbeat messages

### Mesh Backend Pool

`BackendType::Mesh` variant is dispatched in the HTTP server via `mesh_backend_pool`. Key files:
- `src/mesh/backend.rs:109-303` — `MeshBackend`/`MeshBackendPool`
- `src/mesh/proxy.rs` — `MeshProxy` for routing

### Node Roles

Node roles defined at `src/mesh/config.rs:23-33`: Global, Edge, Origin, plus composites (GLOBAL_EDGE, EDGE_ORIGIN, GLOBAL_ORIGIN, GLOBAL_EDGE_ORIGIN).

## Raft Consensus

Global nodes form a Raft cluster for strong consistency. Key files:
- `src/mesh/raft/mod.rs` — Raft module exports
- `src/mesh/raft/network.rs` — MeshRaftNetwork and MeshRaftNetworkFactory with full_snapshot() support
- `src/mesh/raft/state_machine.rs` — GlobalRegistryStateMachine, GlobalRegistryLogStorage, GlobalRegistrySnapshotBuilder
- `src/mesh/raft/client.rs` — RaftAwareClient with LeaderCache (5s TTL), linearizable reads, DHT fallback
- `src/mesh/raft/instance.rs` — RaftInstance wrapping openraft::Raft
- `src/mesh/raft/regression_tests.rs` — Regression tests for Raft messages and DHT signatures

**Namespaces**: Org, Intel, Revocation (defined in `state_machine.rs`)

**DHT Fallback**: When Raft is unavailable, `RaftAwareClient::fallback_to_dht()` provides eventual consistency via DHT lookups.

**Streaming Snapshots (W11.2)**: Raft snapshots use a streaming binary format to avoid OOM on large state. Key methods:
- `GlobalRegistryStateMachine::streaming_serialize()` — iterates SQLite rows, serializes one entry at a time
- `GlobalRegistryStateMachine::streaming_deserialize_and_apply()` — deserializes and inserts one entry at a time
- Format: `[MAGIC u32 0x53524D53][COUNT u64][LEN u32][postcard entry]...`
- Backward-compatible: falls back to JSON deserialization if magic number is absent (rolling upgrades)
- Peak memory reduced from ~2x state size to ~1x state size

### Raft Command Authorization

`RaftCommand` variants (`Set`, `Delete`) include `source_node_id` and `signature` fields (Optional) to support authorization validation at the handler level before accepting proposals.

## DHT Security

DHT record signing uses canonical `DhtRecordSignable` struct with SHA256 value hashing:
- `src/mesh/dht/signed.rs` — SignedDhtRecord, DhtRecordSignable, RecordSigner/Verifier
- `src/mesh/transport_dht.rs` — handle_dht_snapshot_request/sync_response with default-deny authentication

**Default-Deny**: DHT snapshot/sync requests without valid signatures are rejected.

### DHT Record Versioning

Immutable record types cannot be replaced once stored:
- `GenesisKeyTransition` — Genesis key rotation records
- `RevokedGlobalNode` — Revocation records
- `YaraRulesManifest` — YARA rule manifests
- `YaraRuleContent` — YARA rule content

These use `SignedRecordType::is_immutable()` check in both `store_record_global()` and `apply_sync()`.

### DHT Timestamp Validation

All DHT records are validated against future timestamps using `validate_record_timestamp()` with `DHT_RECORD_TIMESTAMP_WINDOW_SECS` (300 seconds). Records with timestamps too far in the future are rejected before storage.

### DHT Ingress Verification (W14)

`DhtRecord.verify_for_ingress()` provides centralized verification for all DHT record ingress paths. However, not all ingress paths use it:

**Known Gaps** (documented at `signed.rs:42-48`):
- `DhtSyncRequest`: node_id in message is not validated against peer_id/TLS cert
- `DhtAntiEntropyRequest`: signer_public_key present but not used for verification
- `DhtRecordPush`: timestamp ignored, lacks envelope signature
- `DhtRecordCommit`: has timestamp but lacks envelope signature validation
- `QuorumStoreRequest`: no verification performed
- `QuorumSignatureResp`: no verification performed

These gaps require future architectural work to bind source_node_id to TLS/cert identity layer.

```rust
// Context types
pub enum IngressPath { Announce, SnapshotSync, SyncResponse, AntiEntropy, QuorumCommit, Push, LocalCreate }
pub enum SourceClassification { LocalNode, GlobalNode, EdgeNode, Unknown }
pub struct DhtRecordIngressContext { ... }

// Verification on DhtRecord
pub fn verify_for_ingress(&self, ctx: &DhtRecordIngressContext, access_control: &DhtAccessControl) -> Result<(), DhtRecordVerificationError>
```

Verification includes:
1. Content hash validation
2. Timestamp validation (rejects future-skewed beyond window)
3. TTL expiry check
4. Ed25519 signature verification for remote sources
5. Trust anchor verification for immutable records
6. Quorum proof presence check

Key files:
- `src/mesh/dht/signed.rs` — IngressContext, verify_for_ingress()
- `src/mesh/protocol.rs` — DhtRecordVerificationError enum

## DHT Regional Quorum (W11.1)

DHT quorum supports two modes via `QuorumMode`:
- **Full** (default): Requires 2/3+1 of ALL global nodes — doesn't scale beyond ~100 nodes.
- **Regional**: Selects closest N global nodes by latency, computes quorum from that subset only.

Key files:
- `src/mesh/dht/quorum.rs` — `QuorumMode`, `select_regional_nodes()`, `GlobalNodeInfo`, `QuorumManager` with Raft write completion via oneshot channel
- `src/mesh/dht/record_store.rs` — `RecordStoreConfig` fields: `regional_quorum_enabled`, `regional_quorum_max_nodes`, `regional_quorum_min_nodes`
- `src/mesh/dht/record_store_message.rs` — `start_quorum_request()` uses regional mode when enabled

Configuration: Set `regional_quorum_enabled = true` in `RecordStoreConfig` with `regional_quorum_max_nodes` (default 20) and `regional_quorum_min_nodes` (default 3). Disabled by default for backward compatibility.

## DHT Two-Phase Commit (W11.3)

DHT records requiring quorum use a two-phase commit to prevent gossip of unconfirmed state:

1. **Phase 1 (Pending)**: Record is stored with `DhtRecordStatus::PendingQuorum` status immediately when `store_record_global()` is called. The record is hidden from `get_record()` and `get_all_records()` but exists locally.
2. **Phase 2 (Commit)**: When quorum approves, `commit_record_after_quorum()` transitions status to `Live`, queues for announce, and sends `DhtRecordCommit` to peers.

Key types:
- `DhtRecordStatus` enum (`PendingQuorum`, `Live`) in `src/mesh/protocol.rs`
- `DhtRecordCommit` message variant in `MeshMessage` for signaling commitment to peers
- `QuorumSignatureProto` for serializing quorum signatures in commit messages

Key methods:
- `store_record_global()` — stores quorum-requiring records as `PendingQuorum` before starting quorum request
- `commit_record_after_quorum()` — transitions to `Live`, announces, sends `DhtRecordCommit` to peers
- `abort_pending_record()` — removes record on rejection/timeout
- `get_record()` / `get_all_records()` — filter out `PendingQuorum` records
- `handle_record_commit()` — handles incoming `DhtRecordCommit` messages on receiving nodes

All 84 `mesh::dht` tests pass with this implementation.

## Async PQC Verification Pool (W11.4)

CPU-intensive PQC operations (ML-DSA verification, ML-KEM encapsulation/decapsulation) can offload to a blocking thread pool to avoid blocking the async executor:

Key file: `src/mesh/crypto_verification.rs` — `CryptoVerificationPool`

```rust
use crate::mesh::CryptoVerificationPool;

let pool = CryptoVerificationPool::default_pool();

// Async ML-DSA verification
let result = pool.verify_ml_dsa(&vk_bytes, message, &signature).await;

// With Arc<MeshMlDsaSigner>
let result = pool.verify_ml_dsa_with_signer(signer_arc, message, &signature).await;

// Async ML-KEM operations
let (ct, ss) = pool.ml_kem_encapsulate(&pk_bytes).await?;
let ss = pool.ml_kem_decapsulate(&sk_bytes, &ct).await?;
```

Pool characteristics:
- Uses `tokio::task::spawn_blocking` for CPU-intensive crypto
- Default size: `available_parallelism().max(4)` threads
- Non-blocking async interface over blocking crypto operations
- Available for integration with `MeshMessageSigner::verify_hybrid()` when ML-DSA is used in hot paths

## DHT Disk-Backed Storage (W11.5)

`ShardedRecordStore` uses in-memory BTreeMap shards. For persistent storage across restarts, configure `disk_storage_path`:

Key files:
- `src/mesh/dht/record_store_disk.rs` — SQLite-backed `DiskRecordStore`
- `src/mesh/dht/record_store.rs` — `load_from_disk()`, `persist_to_disk()` methods

Configuration:
```rust
let store_config = RecordStoreConfig {
    disk_storage_path: Some("/path/to/dht.db".to_string()),
    ..Default::default()
};
```

Methods:
- `load_from_disk()` — Load all records from SQLite into in-memory store on startup
- `persist_to_disk()` — Persist all in-memory records to SQLite

SQLite schema uses WAL mode for concurrent read access. See `skills/dht_persistence.md` for full details.

## DHT L1/L2 Cache (W11.6)

`DiskRecordStore` acts as a transparent L2 cache layered over `ShardedRecordStore` L1 (in-memory):

Key files:
- `src/mesh/dht/record_store_crud.rs` — `get_record()`, `store_record_global()`
- `src/mesh/dht/record_store.rs` — `warmup_from_disk()`
- `src/mesh/dht/record_store_message.rs` — `commit_record_after_quorum()`, `abort_pending_record()`

L1 read-through: `get_record()` checks disk if record not in memory (global nodes only)
Write-through: `store_record_global()` writes to both L1 and L2
Quorum sync: `commit_record_after_quorum()` promotes to Live in both stores; `abort_pending_record()` removes from both

Startup: `warmup_from_disk()` rebuilds Merkle tree from disk keys without loading all values into RAM.

## Real-world Latency Tracking (W11.8)

Regional quorum now uses rolling average RTT instead of last measurement:

- `ShardedPeerStore::record_latency()` maintains last 20 RTT samples per node
- `update_peer_latency()` computes rolling average and updates `PeerState.latency_ms`
- `MeshTopology::get_average_latency_for_node()` exposes rolling average
- `start_quorum_request()` uses average latency for `select_regional_nodes()` when available

Key files:
- `src/mesh/topology/types.rs` — `ShardedPeerStore::update_peer_latency()`, `get_average_latency()`
- `src/mesh/topology.rs` — `MeshTopology::get_average_latency_for_node()`
- `src/mesh/dht/record_store_message.rs` — Regional node selection uses average latency

## Incremental Merkle Updates (W12.1)

`MerkleTree` uses level-ordered hash arrays for O(log N) point updates on existing keys. Key methods:
- `MerkleTree::insert_or_update(key, value)` — O(log N) if key exists, full rebuild for new keys
- `MerkleTree::remove_key(key)` — Removes key and rebuilds tree
- `RecordStoreManager::update_merkle_incremental(key, value)` — Updates tree for single record changes
- `RecordStoreManager::remove_merkle_key(key)` — Removes key from tree

Single-record paths use incremental updates; bulk operations (sync, snapshot, anti-entropy) retain full `compute_merkle_tree()`. A Merkle Integrity Worker runs hourly in `start_background_tasks` to detect and correct drift.

Key files:
- `src/mesh/dht/merkle.rs` — Level-based MerkleTree with incremental updates
- `src/mesh/dht/record_store_message.rs` — `update_merkle_incremental()`, integrity worker in `start_background_tasks()`
- `src/mesh/dht/record_store_crud.rs` — Uses incremental updates in `store_record_global()`, `store_record_edge_cache()`

## Cryptographically-Enforced Quorum Gossip (W12.2)

Records in sensitive namespaces (`verified_upstream:`, `tier_claim:`) require a `quorum_proof` to be accepted via gossip/sync/commit. This prevents a single compromised node from promoting a `PendingQuorum` record to `Live` without quorum approval.

Key concepts:
- `DhtRecord.quorum_proof: Vec<QuorumSignatureProto>` — Attached during `commit_record_after_quorum()`, propagated via `DhtRecordCommit` and sync
- `DhtAccessControl::requires_quorum_proof(key)` — Returns true for `verified_upstream:*` and `tier_claim:*`
- `signed::verify_quorum_proof(record, global_node_count)` — Checks distinct signer count >= 2/3+1 threshold (min 2)
- Passive confirmation (`PendingQuorum` → `Live` via gossip) is now quorum-proof-enforced for sensitive namespaces

Key files:
- `src/mesh/protocol.rs:1541` — `DhtRecord.quorum_proof` field
- `src/mesh/dht/signed.rs` — `verify_quorum_proof()`, `MIN_QUORUM_PROOF_SIGNATURES`
- `src/mesh/dht/record_store_crud.rs` — Quorum-proof enforcement in `store_record_global()` and `apply_sync()`
- `src/mesh/dht/record_store_message.rs` — `commit_record_after_quorum()` attaches proof, `handle_record_commit()` verifies it

## Raft/SQLite Storage Optimization (W12.3)

Raft log storage uses SQLite with WAL mode and paged reads for high throughput:

- **WAL Mode**: Both `GlobalRegistryLogStorage` and `GlobalRegistryStateMachine` enable WAL mode and `busy_timeout=5000` via `PRAGMA` in `init_schema()`
- **Log Indexing**: Composite index `idx_log_entries_id_term` on `log_entries(id, term)` for efficient range queries
- **Paged Log Reads**: `get_log_entries_paged(start_id, limit)` uses SQL `LIMIT` instead of loading entire table

Key file:
- `src/mesh/raft/state_machine.rs` — `GlobalRegistryLogStorage::init_schema()`, `GlobalRegistryLogReader::try_get_log_entries()`

## Durable Quorum Recovery (W12.4)

`RecoveryWorker` scans for `PendingQuorum` records on startup and re-initializes quorum requests:

- Scans disk store for records with `status == PendingQuorum` via `get_pending_quorum_records()`
- Re-initializes quorum requests for non-expired records
- Removes expired records during recovery

Key files:
- `src/mesh/dht/record_store_persist.rs` — `start_recovery_worker()`
- `src/mesh/dht/record_store_disk.rs:230` — `get_pending_quorum_records()`
- `src/mesh/dht/record_store_message.rs:482` — Called from `start_background_tasks()`

## Trust-Rooted Immutability (W12.5)

Immutable records (genesis keys, revocations, YARA manifests) require authorization from a configured Trust Anchor:

- `authorized_genesis_keys: Vec<String>` in `DhtAccessControl` — list of authorized public keys
- `requires_immutability_trust_anchor(key)` — checks if key prefix requires trust anchor
- Remote records in immutable namespaces must have signer in `authorized_genesis_keys`
- Local records bypass this check (already validated by local signing)

Key files:
- `src/mesh/dht/mod.rs:669` — `authorized_genesis_keys` field
- `src/mesh/dht/mod.rs:821` — `requires_immutability_trust_anchor()` method
- `src/mesh/dht/record_store_crud.rs:184-220` — Trust anchor verification in `store_record_global()`
- `src/mesh/dht/record_store_crud.rs:810-834` — Trust anchor verification in `apply_sync()`

## Security Patterns

### Trusted Signer Default Deny

When checking `trusted_signers`, always use deny-by-default for non-global nodes:

```rust
if !self.node_role.is_global() {
    if self.config.trusted_signers.is_empty() {
        tracing::warn!("No trusted signers configured - rejecting threat from non-global node");
        return Some(MeshMessage::ThreatAcknowledgement { accepted: false, ... });
    }
    if !self.check_trusted_signer(source_node_id, signer_public_key) {
        return Some(MeshMessage::ThreatAcknowledgement { accepted: false, ... });
    }
}
```

### Genesis Key Default Deny

Empty `authorized_genesis_keys` should deny by default:

```rust
pub fn is_genesis_key_authorized(&self, genesis_public_key: &str) -> bool {
    if self.authorized_genesis_keys.is_empty() {
        tracing::warn!("No authorized genesis keys configured - rejecting genesis key authentication.");
        return false;  // Changed from true (secure default)
    }
    self.authorized_genesis_keys.iter().any(|k| k == genesis_public_key)
}
```

### Composite Role Validation

For composite roles (EDGE_ORIGIN, GLOBAL_EDGE), check BOTH roles BEFORE single-role checks:

```rust
if role.is_edge() && role.is_origin() {
    let edge_result = validate_edge_node(...);
    let origin_result = validate_origin_node(...);
}
```

### YARA Rule Trust Validation

YARA rules enforce deny-by-default for non-global nodes:

```rust
if !self.node_role.is_global()
    && !self.config.trusted_signers.is_empty()
    && !self.config.trusted_signers.contains(&manifest_signer_pk.to_string())
{
    // reject
}
```

### Constant-Time Comparison Verification

**Important**: `src/mesh/security_challenge.rs:196` uses simple `!=` comparison. This is CORRECT for this use case because:
- The `expected_solution` is publicly known challenge data, not a secret
- Timing side-channels don't matter when verifying publicly-known values
- **Only use `ConstantTimeEq` for actual secrets** (keys, MACs, auth tokens, passwords)

When implementing fixes, ensure to use constant-time comparison for security-sensitive comparisons:

```rust
// CORRECT - for secrets (keys, MACs, auth tokens)
use subtle::ConstantTimeEq;
if key.ct_eq(&expected_key).unwrap_u8() == 0 { ... }

// DO NOT USE for non-secrets like puzzle solutions - simple != is fine
if solution != expected_solution { ... }
```

## Wave 15: Distributed Layer Hardening Follow-Up

All Wave 15 priorities have been implemented and committed to their respective branches.

### P1: Authorization-Aware Quorum Proof Verification

`QuorumVerifierContext` provides authorization-aware quorum verification that binds signatures to authorized global nodes:

```rust
pub struct QuorumVerifierContext<'a> {
    pub total_known_global_nodes: usize,
    pub regional_voter_set: Option<&'a HashSet<String>>,
    pub request_id: &'a str,
    pub action: &'a str,
    pub authorized_global_keys: &'a dyn Fn(&str) -> Option<String>,
}
```

Key behavior:
- `verify_quorum_proof_with_context()` validates `proof.node_id` is an authorized global node
- `proof.signer_public_key` must match the trusted key for `proof.node_id`
- Regional voter set filtering rejects signatures from nodes outside the selected set
- `verify_quorum_proof_authoritative()` gets actual global node count from topology and fails closed if unavailable

Key files:
- `src/mesh/dht/signed.rs` — `QuorumVerifierContext`, `verify_quorum_proof_with_context()`
- `src/mesh/dht/record_store.rs` — `verify_quorum_proof_authoritative()`

### P2: SQLite Schema Migration for DiskRecordStore

`DiskRecordStore::new()` now performs schema migration for existing databases:

```rust
// Migration-based initialization
let migrations_run = disk_store.run_migrations().unwrap();
// Adds missing columns: signature, signer_public_key, quorum_proof, request_id
// Sets PRAGMA user_version for future migrations
```

Key behavior:
- `run_migrations()` inspects `PRAGMA table_info(dht_records)` and ALTER TABLE missing columns
- `is_legacy_row()` detects rows without auth metadata
- Legacy sensitive records are quarantined (skipped during load)
- Legacy public records are loaded with debug logging

Key files:
- `src/mesh/dht/record_store_disk.rs` — `run_migrations()`, `is_legacy_row()`
- `src/mesh/dht/record_store.rs` — `load_from_disk()` quarantine logic

### P3: Raft Snapshot Framing Cleanup

`ALLOW_LEGACY_RAFT_SNAPSHOT_FRAMES` controls the legacy length heuristic:

```rust
// In src/mesh/transport.rs
pub const ALLOW_LEGACY_RAFT_SNAPSHOT_FRAMES: bool = false;
```

When `false` (default): InstallSnapshot decode failure results in rejection
When `true`: Falls back to `payload.data.len() < 100` heuristic with LEGACY-prefixed logging

Key files:
- `src/mesh/transport.rs` — `ALLOW_LEGACY_RAFT_SNAPSHOT_FRAMES` constant
- `src/mesh/transport_peer.rs` — Legacy fallback with telemetry

### P4: Network Ingress Identity Binding

`DhtRecord::verify_for_ingress()` now binds signer public key to source_node_id:

```rust
// Derives node ID from signer's public key and compares to record.source_node_id
// Rejects with InvalidSourceNodeId if they don't match
```

This prevents remote attackers from claiming to be a different node by setting `source_node_id` to a victim node.

Key files:
- `src/mesh/dht/signed.rs` — Signer-to-source binding validation
- `src/mesh/protocol.rs` — `InvalidSourceNodeId` error variant

### P5: Clippy Offline Reproducibility

`utoipa-swagger-ui` uses `vendored` feature to embed Swagger UI assets locally:

```toml
# In Cargo.toml
utoipa-swagger-ui = { version = "...", features = ["vendored"] }
```

This allows `cargo clippy --lib -- -D warnings` to run without network access.

### P6: Warning Cleanup

Wave 15 fixed warnings in mesh/DHT/Raft files:
- Removed unused imports (DiskRecordStore, Ed25519Signer/Verifier, bytes::Bytes, rkyv, Path, Async*Ext)
- Fixed ref pattern creating reference to reference (`Some(ref regional_set)` → `Some(regional_set)`)
- Use `std::io::Error::other()` instead of `new(ErrorKind::Other, ...)`
- Added `#[allow(dead_code)]` to `fallback_json_install`
- Use `.ok()` and `.flatten()` patterns for iterators
- Prefix unused variables with underscore (`_pool`)
- Add `#[derive(Default)]` with `#[default]` on `DhtRecordStatus`
- Collapse nested if-else blocks

## Lessons Learned (2026-05-22)

### Quorum Manager Race Condition ✅ FIXED

`src/mesh/dht/quorum.rs:339-386` - Fixed by:
- Changed `oneshot::channel()` to `oneshot::channel::<Result<(), RaftAwareClientError>>()`
- `is_request_complete()` now receives actual result via `try_recv()` and tracks success in `QuorumRequest`
- Added `raft_write_completed: bool` and `raft_write_success: bool` fields to `QuorumRequest`
- `check_quorum_completion()` at `record_store_message.rs:1319-1345` now treats successful DHT threshold but failed Raft write as timeout

### DHT Ingress Verification Gaps (Deferred - Architectural)

`src/mesh/dht/signed.rs:42-48` documents unverified paths:
- DhtSyncRequest (no auth)
- DhtAntiEntropyRequest (pk unused)
- DhtRecordPush (no ts)
- DhtRecordCommit (no envsig)
- QuorumStoreRequest (no verify)
- QuorumSignatureResp (no verify)

These L1-L5 identity hierarchy gaps require future architectural work. Known limitation.

### Role Validation Code Duplication ✅ FIXED

`src/mesh/peer_auth.rs:275-304` - Removed duplicate GLOBAL_EDGE block (was lines 318-347). The first block handles this case and returns early, making the second block unreachable dead code.

### Session Establishment Error Handling (Working As Designed)

`src/mesh/ml_kem_key_exchange.rs:143-148` - Session establishment failures are only logged. The offer is created regardless of session state since bidirectional communication is optional for key offers.

### Memory Leak in Pending Membership Changes ✅ ALREADY FIXED

`src/mesh/transport.rs:797-875` - `pending_membership_changes` Vec is properly managed. `process_pending_membership_changes()` drains via `drain(..)` at line 903. Duplicate entries prevented by `retain()` at lines 823, 831. Already verified in plan review.