# Skill: DHT Neighborhood Persistence

## Context
The codebase implements DHT neighborhood persistence to accelerate mesh warm-up and reduce bootstrap traffic.

## When to Use
Use this skill when:
- Implementing local persistence of DHT records
- Adding SHA256-based key distance calculations
- Creating atomic file writes with temp file + rename pattern
- Implementing background pruning tasks for expired records

## Key Files
- `crates/synvoid-mesh/src/mesh/dht/record_store_persist.rs` - Persistence implementation
- `crates/synvoid-mesh/src/mesh/dht/record_store.rs` - Added `persist_neighborhood()`, `load_neighborhood()`
- `crates/synvoid-mesh/src/mesh/config.rs` - Added `neighborhood_persistence_enabled`, `neighborhood_cache_size`, `persist_max_age_secs`

## Implementation Pattern

### 1. Config Fields
In `RecordStoreConfig`:
```rust
pub struct RecordStoreConfig {
    // ... existing fields ...
    pub neighborhood_persistence_enabled: bool,
    pub neighborhood_cache_size: usize,
    pub persist_max_age_secs: u64,
}
```

### 2. Key Distance Calculation
```rust
fn key_distance(key: &str, node_id: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(node_id.as_bytes());
    let result = hasher.finalize();
    u64::from_le_bytes(result[..8].try_into().unwrap())
}
```

### 3. Persistence Format
```rust
#[derive(Serialize, Deserialize)]
struct PersistedNeighborhood {
    version: u32,
    node_id: String,
    mesh_id: String,
    persisted_at: u64,
    records: Vec<PersistedRecord>,
}
```

### 4. Atomic Write Pattern
```rust
pub fn persist_neighborhood(&self, storage_path: &Path) -> Result<(), String> {
    let content = serde_json::to_string_pretty(&neighborhood)?;
    let temp_path = storage_path.with_extension("tmp");
    std::fs::write(&temp_path, &content)?;
    std::fs::rename(&temp_path, storage_path)?;
    Ok(())
}
```

### 5. Background Pruning
```rust
pub fn start_pruning_task(&self, interval_secs: u64) {
    let this = self.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            this.prune_expired_persisted_records().await;
        }
    });
}
```

### 6. Module Declaration
In `crates/synvoid-mesh/src/mesh/dht/record_store.rs`:
```rust
#[path = "record_store_persist.rs"]
mod record_store_persist;
```

## Verification
```bash
cargo test --lib record_store_persist
cargo test --test dht_integration_test
```

## Common Issues
1. **Arc<Config> doesn't have .field** - Config is `Arc<RecordStoreConfig>`, access fields directly
2. **iter() returns Vec<(&K,&V>)>** - Use `.values()` for value iteration or `.iter()` with tuple destructuring
3. **Vec<_>.filter().map().collect()** - Type inference may fail; provide explicit types

## Schema Version
Always include schema version for forward compatibility:
```rust

## DHT Record Versioning

Immutable record types cannot be replaced once stored:
- `GenesisKeyTransition` — Genesis key rotation records
- `RevokedGlobalNode` — Revocation records
- `YaraRulesManifest` — YARA rule manifests
- `YaraRuleContent` — YARA rule content

These types use `SignedRecordType::is_immutable()` check before allowing replacement.

### Timestamp Validation

All DHT records are validated against future timestamps using `validate_record_timestamp()`:
```rust
pub fn validate_record_timestamp(timestamp: u64) -> bool {
    let now = crate::mesh::safe_unix_timestamp() as i64;
    let msg_time = timestamp as i64;
    let diff = (now - msg_time).abs();
    diff <= DHT_RECORD_TIMESTAMP_WINDOW_SECS  // 300 seconds
}
```

Records with timestamps too far in the future are rejected before storage.

## Content-Addressed Integrity (record_set_digest)

Snapshot/Sync/Anti-Entropy responses include a `record_set_digest` for content-integrity verification:

```rust
pub fn compute_record_set_digest(records: &[DhtRecord]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for record in records {
        let signed = dht_record_to_signed_record(record);
        let signable_content = signed.get_signable_content();
        hasher.update(&signable_content);
    }
    hasher.finalize().to_vec()
}
```

Signable content structs for each message type:
- `DhtSnapshotResponseSignable` — includes `responder_node_id`, `version`, `record_count`, `timestamp`, `record_set_digest`
- `DhtSyncResponseSignable` — includes `request_id`, `from_peer`, `responder_node_id`, `version`, `record_count`, `timestamp`, `record_set_digest`
- `DhtAntiEntropyRequestSignable` — includes `request_id`, `node_id`, `local_root_hash`, `timestamp`
- `DhtAntiEntropyResponseSignable` — includes `request_id`, `responder_node_id`, `root_hash`, `record_count`, `timestamp`, `record_set_digest`

## Canonical DHT Record Signing

DHT records use canonical signing via `SignedDhtRecord.get_signable_content()`:

```rust
pub fn get_signable_content(&self) -> Vec<u8> {
    let value_hash = Sha256::digest(&self.value);
    let content = DhtRecordSignable {
        key: &self.key,
        value_hash: &value_hash,
        source_node_id: &self.source_node_id,
        timestamp: self.created_at,
        ttl_seconds: self.ttl_seconds,
        sequence_number: self.sequence_number,
        record_type: record_type_str,
    };
    crate::serialization::serialize(&content).unwrap_or_default()
}
```

**Important**: Only `source_node_id` is part of the signable content, NOT `publisher_id`. Tampering with `publisher_id` will NOT be detected by signature verification.

Verification functions in `crates/synvoid-mesh/src/mesh/dht/signed.rs`:
- `verify_dht_record_signature()` — verifies signature on a DhtRecord
- `verify_dht_record_signature_for_key()` — verifies with expected record type

const CURRENT_SCHEMA_VERSION: u32 = 1;
```

## DHT Two-Phase Commit (W11.3)

Records requiring quorum use a two-phase commit to prevent gossip of unconfirmed state:

1. **Phase 1 (Pending)**: Record stored with `DhtRecordStatus::PendingQuorum` in `DhtRecordEntry.status`. Hidden from `get_record()` and `get_all_records()` but exists locally.
2. **Phase 2 (Commit)**: On quorum approval, `commit_record_after_quorum()` transitions to `Live`, queues for announce, and notifies peers.

Key types:
- `DhtRecordStatus` enum (`PendingQuorum`, `Live`) in `crates/synvoid-mesh/src/mesh/protocol.rs` with `Default::default()` = `Live`
- `QuorumSignatureProto` — serializes quorum signatures attached to records

Key methods:
- `store_record_global()` — stores quorum-requiring records as `PendingQuorum` before starting quorum
- `commit_record_after_quorum()` — transitions to `Live`, announces, notifies peers
- `abort_pending_record()` — removes record on rejection/timeout
- `get_record()` / `get_all_records()` — filter out `PendingQuorum` records
- Peer notification uses standard DHT sync/gossip paths with quorum proof verification

```rust
// DhtRecordEntry now includes status
pub struct DhtRecordEntry {
    pub record: DhtRecord,
    pub local_origin: bool,
    pub version: u64,
    pub status: DhtRecordStatus,  // Default is Live for backward compat
}
```

## DHT Disk-Backed Storage (W11.5)

For full-disk persistence of DHT records (not just neighborhood subset), use `DiskRecordStore`:

### Key Files
- `crates/synvoid-mesh/src/mesh/dht/record_store_disk.rs` - SQLite-backed disk storage
- `crates/synvoid-mesh/src/mesh/dht/record_store.rs` - `load_from_disk()`, `persist_to_disk()` methods

### Configuration
In `RecordStoreConfig`, set `disk_storage_path`:
```rust
pub struct RecordStoreConfig {
    // ...
    pub disk_storage_path: Option<String>,
}
```

### Usage
```rust
// Initialize with disk storage (when path is Some)
let store_config = RecordStoreConfig {
    disk_storage_path: Some("/path/to/dht.db".to_string()),
    ..Default::default()
};

// Load records from disk on startup
let loaded = record_store_manager.load_from_disk();
tracing::info!("Loaded {} records from disk", loaded);

// Persist all in-memory records to disk
let count = record_store_manager.persist_to_disk()?;
```

### SQLite Schema
The disk store uses a single table:
```sql
CREATE TABLE dht_records (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    sequence_number INTEGER NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    source_node_id TEXT NOT NULL,
    content_hash BLOB NOT NULL,
    local_origin INTEGER NOT NULL,
    version INTEGER NOT NULL,
    status INTEGER NOT NULL
);
CREATE INDEX idx_timestamp ON dht_records(timestamp);
CREATE INDEX idx_source ON dht_records(source_node_id);
```

### Disk Store Methods
- `get(key)` - Retrieve a single record
- `insert(key, entry)` - Insert or replace a record
- `remove(key)` - Remove a record
- `len()` / `is_empty()` - Count records
- `iter()` - Iterate all records
- `get_by_prefix(prefix, limit)` - Prefix search
- `checkpoint()` - WAL checkpoint
- `vacuum()` - VACUUM the database

### DhtRecordStatus Serialization
`DhtRecordStatus` provides `to_u8()` and `from_u8()` for SQLite storage:
- `Live` = 0
- `PendingQuorum` = 1

## DHT L1/L2 Cache (W11.6)

The `DiskRecordStore` can act as an L2 cache transparent to the `ShardedRecordStore` L1 (in-memory):

### Key Files
- `crates/synvoid-mesh/src/mesh/dht/record_store_crud.rs` - Modified `get_record()`, `store_record_global()`
- `crates/synvoid-mesh/src/mesh/dht/record_store.rs` - Added `warmup_from_disk()` method
- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs` - Modified `commit_record_after_quorum()`, `abort_pending_record()`

### L1 Read-Through Cache
When `get_record()` finds a record not in memory (L1), it checks disk (L2):
```rust
pub fn get_record(&self, key: &str) -> Option<DhtRecord> {
    // First check L1 (memory)
    let record = self.record_state.read().records.get(key).cloned();
    
    // If not found and global node with disk store, check L2 (disk)
    if record.is_none() && self.is_global_node() {
        if let Some(ref disk_store) = self.record_state.read().disk_store {
            if let Some(entry) = disk_store.get(key) {
                // Promote to L1 by inserting into records
                let mut rs = self.record_state.write();
                rs.records.insert(key.to_string(), entry.clone());
                return Some(entry.record);
            }
        }
    }
    record
}
```

### Write-Through Cache
On `store_record_global()`, the record is written to both L1 and L2:
```rust
// In store_record_global() after memory insert:
if self.is_global_node() {
    if let Some(ref disk_store) = self.record_state.read().disk_store {
        disk_store.insert(record.key.clone(), entry);
    }
}
```

### Quorum Commit/Aborт
When quorum commits or aborts, disk store is updated:
```rust
// On commit_record_after_quorum():
if self.is_global_node() {
    if let Some(ref disk_store) = self.record_state.read().disk_store {
        if let Some(entry) = self.record_state.read().records.get(&record.key) {
            disk_store.insert(record.key.clone(), entry.clone());
        }
    }
}

// On abort_pending_record():
if let Some(ref disk_store) = self.record_state.read().disk_store {
    disk_store.remove(key);
}
```

### Startup Warmup
`warmup_from_disk()` rebuilds Merkle tree from disk keys without loading all values:
```rust
pub fn warmup_from_disk(&self) -> usize {
    let keys_on_disk: Vec<String> = disk_store.iter()
        .into_iter()
        .map(|(k, _): (String, DhtRecordEntry)| k)
        .collect();
    
    // Build record_map from memory only (records already loaded via load_from_disk)
    let mut record_map = std::collections::HashMap::new();
    for key in &keys_on_disk {
        if let Some(entry) = self.record_state.read().records.get(key) {
            record_map.insert(key.clone(), entry.record.value.clone());
        }
    }
    
    // Rebuild Merkle tree from disk keys
    let tree = MerkleTree::from_records(&record_map);
    let mut rs = self.record_state.write();
    rs.merkle_tree = Some(tree);
    
    keys_on_disk.len()
}
```

## DHT Regional Quorum Latency Tracking (W11.8)

Regional quorum uses actual measured latency for node selection:

### Latency Data Flow
1. Health checks record RTT → `ShardedPeerStore::record_latency()` → `latency_history`
2. `update_peer_latency()` computes rolling average and updates `PeerState.latency_ms`
3. `MeshTopology::get_average_latency_for_node()` returns rolling average
4. `start_quorum_request()` builds `GlobalNodeInfo` with average latency for `select_regional_nodes()`

### Rolling Average Computation
In `ShardedPeerStore`:
```rust
pub fn update_peer_latency(&self, node_id: &str, latency_ms: u32) {
    let mut shard = self.shard(node_id).write();
    let avg_latency = shard.latency_history.get(node_id).map_or(latency_ms, |history| {
        if history.is_empty() { latency_ms }
        else {
            let sum: u64 = history.iter().map(|(_, l)| *l as u64).sum::<u64>();
            (sum / history.len() as u64) as u32
        }
    });
    if let Some(peer) = shard.peers.get_mut(node_id) {
        peer.latency_ms = Some(avg_latency);
    }
}

pub fn get_average_latency(&self, node_id: &str) -> Option<u32> {
    let shard = self.shard(node_id).read();
    shard.latency_history.get(node_id).map(|history| {
        if history.is_empty() { return 0u32; }
        let sum: u64 = history.iter().map(|(_, l)| *l as u64).sum::<u64>();
        (sum / history.len() as u64) as u32
    })
}
```

### Regional Node Selection
In `start_quorum_request()`:
```rust
if self.config.regional_quorum_enabled {
    let node_ids: Vec<String> = global_nodes.iter().map(|p| p.node_id.clone()).collect();
    let mut global_node_infos: Vec<GlobalNodeInfo> = Vec::new();
    
    for (i, node_id) in node_ids.into_iter().enumerate() {
        // Use average latency if available, fallback to last known
        let avg_latency = topology
            .get_average_latency_for_node(&node_id)
            .await
            .or(global_nodes[i].latency_ms);
        global_node_infos.push(GlobalNodeInfo {
            node_id,
            latency_ms: avg_latency,
        });
    }
    
    let regional = select_regional_nodes(&global_node_infos, ...);
}
```

### Latency History Management
- History stores last 20 measurements per node (see `record_latency()`)
- `PeerShard::latency_history: HashMap<String, Vec<(Instant, u32)>>`
- Older measurements naturally deprioritize stale nodes in regional selection
```

## Incremental Merkle Updates (W12.1)

### Architecture
`MerkleTree` uses level-ordered hash arrays (`levels: Vec<Vec<Vec<u8>>>`) instead of HashMaps:
- `levels[0]` = leaf hashes sorted by key
- `levels[l]` = internal node hashes at level l
- `levels[h-1]` = `[root_hash]`

### Key Methods
```rust
// O(log N) update for existing key, full rebuild for new key
tree.insert_or_update(key.to_string(), value);

// Remove key (full rebuild)
tree.remove_key(&key);

// On RecordStoreManager - single record incremental update
record_store.update_merkle_incremental(&record.key, &record.value);

// On RecordStoreManager - remove key from tree
record_store.remove_merkle_key(&key);
```

### When to Use Each
- **`update_merkle_incremental`**: Single record store/update/commit paths
- **`compute_merkle_tree`**: Bulk operations (sync, snapshot, anti-entropy, integrity worker)

### Merkle Integrity Worker
Runs hourly in `start_background_tasks()`:
- Performs full `compute_merkle_tree()` rebuild
- Compares old and new root hashes
- Logs warning if drift detected

### Performance Characteristics
- Update existing key: O(log N) hash operations (~17 for 100K records)
- Insert new key: O(N) full rebuild
- Target: < 1ms per update with 100K records (verified by `test_benchmark_incremental_update_100k`)

## Raft/SQLite Storage Optimization (W12.3)

### Key Improvements
1. **WAL Mode**: Both `GlobalRegistryLogStorage` and `GlobalRegistryStateMachine` enable WAL mode
2. **busy_timeout=5000**: Prevents lock contention on concurrent access
3. **Composite Index**: `idx_log_entries_id_term` on `log_entries(id, term)` for efficient range queries
4. **Paged Log Reads**: Uses SQL `LIMIT` instead of loading entire log table

### Implementation
In `GlobalRegistryStateMachine::init_schema()` and `GlobalRegistryLogStorage::init_schema()`:
```rust
db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
```

In `GlobalRegistryLogStorage::init_schema()`:
```rust
db.execute(
    "CREATE INDEX IF NOT EXISTS idx_log_entries_id_term ON log_entries(id, term)",
    [],
)?;
```

### Paged Log Reads
```rust
pub fn get_log_entries_paged(
    &self,
    start_id: u64,
    limit: usize,
) -> Result<Vec<(u64, u64, Vec<u8>)>, rusqlite::Error> {
    let db_guard = self.db.lock().unwrap();
    let mut stmt = db_guard.prepare(
        "SELECT id, term, payload FROM log_entries WHERE id >= ?1 ORDER BY id LIMIT ?2",
    )?;
    // ...
}
```

## Durable Quorum Recovery (W12.4)

### Purpose
Records marked `PendingQuorum` are lost on restart because the ephemeral polling tasks in `store_record_global` do not persist. The `RecoveryWorker` recovers these records on startup.

### Implementation
```rust
pub fn start_recovery_worker(&self) {
    let self_arc = Arc::new(self.clone());
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Scan disk store for PendingQuorum records
        let pending_records = {
            let rs = self_arc.record_state.read();
            if let Some(ref disk_store) = rs.disk_store {
                disk_store.get_pending_quorum_records()
            } else {
                Vec::new()
            }
        };

        // Re-initialize quorum requests for non-expired records
        for (key, entry) in pending_records {
            // Check TTL, remove if expired, otherwise restart quorum
        }
    });
}
```

### Disk Store Query
```rust
pub fn get_pending_quorum_records(&self) -> Vec<(String, DhtRecordEntry)> {
    let conn = self.conn.lock();
    let mut stmt = conn.prepare(
        "SELECT ... FROM dht_records WHERE status = ?"
    ).unwrap();
    // Uses DhtRecordStatus::PendingQuorum as query parameter
}
```

Called from `start_background_tasks()` in `record_store_message.rs`.

## Trust-Rooted Immutability (W12.5)

### Purpose
Prevents "Race to Poison" attacks on immutable records (genesis keys, revocations, YARA manifests). Remote records in immutable namespaces must have a signer in `authorized_genesis_keys`.

### Configuration
In `DhtAccessControl`:
```rust
pub struct DhtAccessControl {
    // ...
    pub authorized_genesis_keys: Vec<String>,
}
```

Loaded from `mesh_config.dht_access_control.authorized_genesis_keys`.

### Trust Anchor Check
```rust
pub fn requires_immutability_trust_anchor(&self, key: &str) -> bool {
    for prefix in &self.immutability_required_keys {
        if key.starts_with(prefix) {
            return true;
        }
    }
    false
}
```

### Enforcement in store_record_global()
For remote records (non-local origin) in immutable namespaces:
```rust
if self.access_control.requires_immutability_trust_anchor(&record.key) && !is_local_record {
    if self.access_control.authorized_genesis_keys.is_empty() {
        // Reject - no trust anchors configured
        return false;
    }
    if !self.access_control.authorized_genesis_keys.contains(signer_pk) {
        // Reject - signer not in trust anchor list
        return false;
    }
}
```

### Immutable Record Types
- `GenesisKeyTransition` — Genesis key rotation records
- `RevokedGlobalNode` — Revocation records
- `YaraRulesManifest` — YARA rule manifests
- `YaraRuleContent` — YARA rule content

Local records bypass this check (already validated by local signing).

## Wave 15: Distributed Layer Hardening Follow-Up (W15)

### Authorization-Aware Quorum Proof Verification (W15-P1)

Quorum proofs are now verified against authorized global-node identity, not embedded self-asserted public keys:

```rust
pub struct QuorumVerifierContext<'a> {
    pub total_known_global_nodes: usize,
    pub regional_voter_set: Option<&'a HashSet<String>>,
    pub request_id: &'a str,
    pub action: &'a str,
    pub authorized_global_keys: &'a dyn Fn(&str) -> Option<String>,
}
```

Key behaviors:
- `verify_quorum_proof_with_context()` validates `proof.node_id` is an authorized global node
- `proof.signer_public_key` must match the trusted key for `proof.node_id`
- Regional voter set filtering rejects signatures from nodes outside the selected set
- `verify_quorum_proof_authoritative()` gets actual global node count from topology

Call sites in `store_record_global()`, `apply_sync()`, `handle_record_commit()` now use `verify_quorum_proof_authoritative()` instead of passing `0` for global node count.

### SQLite Schema Migration (W15-P2)

`DiskRecordStore::new()` performs schema migration for existing databases:

```rust
// Migration-based initialization
let migrations_run = disk_store.run_migrations().unwrap();
// Adds missing columns: signature, signer_public_key, quorum_proof, request_id
// Sets PRAGMA user_version = 1 for future migrations
```

Legacy row handling:
- `is_legacy_row()` detects rows without auth metadata
- Legacy sensitive records are quarantined (skipped during `load_from_disk()`)
- Legacy public records are loaded with debug logging

SQLite schema now includes security metadata columns:
```sql
ALTER TABLE dht_records ADD COLUMN signature BLOB;
ALTER TABLE dht_records ADD COLUMN signer_public_key TEXT;
ALTER TABLE dht_records ADD COLUMN quorum_proof BLOB;
ALTER TABLE dht_records ADD COLUMN request_id TEXT;
```

### Legacy Snapshot Framing (W15-P3)

`ALLOW_LEGACY_RAFT_SNAPSHOT_FRAMES` controls the legacy length heuristic:

```rust
pub const ALLOW_LEGACY_RAFT_SNAPSHOT_FRAMES: bool = false;  // Default: strict
```

When `false` (default): `InstallSnapshot` decode failure results in rejection
When `true`: Falls back to `payload.data.len() < 100` heuristic with LEGACY-prefixed logging

### Network Ingress Identity Binding (W15-P4)

`DhtRecord::verify_for_ingress()` binds signer public key to `source_node_id`:

```rust
// Derives node ID from signer's public key and compares to record.source_node_id
// Rejects with InvalidSourceNodeId if they don't match
```

This prevents remote attackers from claiming to be a different node by setting `source_node_id` to a victim node.

## DHT Ingress Validation (2026-06)

### Key Policy Table

**Location**: `crates/synvoid-mesh/src/mesh/dht/key_policy.rs`

All remote DHT writes are now validated against a centralized key policy table. The `DhtKeyPolicyTable` maps DHT key prefixes to policies that define:

- Which key families are authorized to write records
- Whether signatures are required
- Whether quorum proofs are required

```rust
// In store_record(), before accepting a remote record:
let policy = key_policy_table.get_policy_for_key(&record.key);
if policy.require_signature && record.signature.is_none() {
    return false; // Reject unsigned record
}
```

### AuthorityFreshnessConfig

**Location**: `crates/synvoid-mesh/src/mesh/config.rs`

Stale authority records are rejected during DHT sync and anti-entropy:

```rust
pub struct AuthorityFreshnessConfig {
    pub global_policy_grace_secs: u64,                    // Default: 3600
    pub revocation_hard_limit_secs: u64,                   // Default: 300
    pub ca_epoch_hard_limit_secs: u64,                     // Default: 86400
    pub threat_intel_stale_local: bool,                    // Default: true
    pub peer_discovery_degraded: bool,                     // Default: true
    pub dht_soft_state_ttl_secs: u64,                      // Default: 300
    pub canonical_snapshot_fresh_max_age_ms: u64,          // Default: 60_000
    pub canonical_snapshot_stale_grace_max_age_ms: u64,    // Default: 300_000
    pub canonical_snapshot_stale_mode: CanonicalSnapshotStaleMode, // Default: FailOpenDefer
}
```

Records older than the configured staleness thresholds are rejected for critical authority key families (genesis key transitions, revoked nodes). This prevents replay of stale revocations or key rotations. The `canonical_snapshot_*` fields configure the worker-side freshness policy for IPC-exported snapshots.

### store_record Visibility Change

`store_record()` is now `pub(crate)` — only callable within the mesh crate. External callers must use:
- `store_local_record()` — for locally-originated records (`is_local_origin=true`)
- `store_record_from_ingress()` — for remote/mesh writes (performs full ingress validation)

The old `store_record(record, source_reputation, is_local_origin)` method has been removed (was dead code). All remote writes go through `store_record_from_ingress()` with a typed `DhtRecordIngressContext`. All local writes go through `store_local_record()`.

`DhtRecordIngressContext` fields are now private. Use accessor methods: `peer_id()`, `source_node_id()`, `source_classification()`, `path()`, `requires_quorum_proof()`, `requires_trust_anchor()`, `is_immutable_key()`, `envelope_signature_valid()`, `timestamp()`, `request_id()`, `is_local_origin()`, `policy_context()`. Construction is controlled: `new_local()` for local writes, `new_remote()` for remote writes. (Optional carrier for direct Push/Announce added in Iteration 14; see `architecture/mesh_trust_domains.md`.)

This enforces the DHT/Raft boundary: local writes bypass ingress checks, while remote writes go through the full policy table and signature verification pipeline.

### DnsZone Remote Write Blocking

`DnsZone` records are now classified as `RaftOrQuorumGlobal` with `remote_writes_allowed=false` in the key policy table. This means:
- DNS zone records can only be written via Raft consensus or quorum attestation
- Direct DHT capability writes (e.g., `CapabilityAttested`) are rejected for `dns_zone:*` keys
- This prevents a compromised node from modifying DNS zones via DHT capability alone

### Ingress Validation Summary

| Check | Before | After |
|-------|--------|-------|
| DhtSyncRequest envelope signature | Optional (unsigned accepted) | Verified (signs request_id, node_id, from_version, timestamp, nonce); unsigned rejected by default |
| DhtSyncRequest signer binding | Not verified | Signer-to-node binding enforced via `verify_envelope_signer_binding()` |
| DhtSyncResponse envelope signature | Optional (unsigned accepted) | Verified (signs request_id, from_peer, responder_node_id, version, record_count, timestamp, record_set_digest); unsigned rejected by default |
| DhtSyncResponse signer binding | Not verified | Signer-to-node binding enforced; unsigned compat path stores via `store_record_from_ingress()` with `envelope_signature_valid=false` |
| DhtAntiEntropyRequest envelope signature | Not verified | Verified (signs request_id, node_id, root_hash, timestamp, nonce) |
| DhtAntiEntropyResponse envelope signature | Not verified | Verified for all responses (empty and non-empty); signs request_id, responder_node_id, root_hash, record_count, timestamp, record_set_digest |
| DhtAntiEntropyRequest signer | Not verified | Verified against authorized global keys |
| DhtRecordPush envelope signature | Not verified | Verified (signs request_id, node_id, records, hop_count, nonce, timestamp) |
| DhtRecordPush signature | Partially enforced | Fully enforced |
| SignedRaftAttestation | Structural-only | v2: Ed25519 signature with value_hash binding |
| DnsZone writes | CapabilityAttested | RaftOrQuorumGlobal (remote_writes_allowed=false) |
| Authority record freshness | No staleness check | Configurable staleness window |
| Key family authorization | Scattered logic | Centralized DhtKeyPolicyTable |
| store_record visibility | pub | pub(crate) with pub store_local_record for local writes |
