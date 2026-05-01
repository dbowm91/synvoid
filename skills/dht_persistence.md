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
- `src/mesh/dht/record_store_persist.rs` - Persistence implementation
- `src/mesh/dht/record_store.rs` - Added `persist_neighborhood()`, `load_neighborhood()`
- `src/mesh/config.rs` - Added `neighborhood_persistence_enabled`, `neighborhood_cache_size`, `persist_max_age_secs`

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
In `src/mesh/dht/record_store.rs`:
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

Verification functions in `src/mesh/dht/signed.rs`:
- `verify_dht_record_signature()` — verifies signature on a DhtRecord
- `verify_dht_record_signature_for_key()` — verifies with expected record type

const CURRENT_SCHEMA_VERSION: u32 = 1;
```

## DHT Two-Phase Commit (W11.3)

Records requiring quorum use a two-phase commit to prevent gossip of unconfirmed state:

1. **Phase 1 (Pending)**: Record stored with `DhtRecordStatus::PendingQuorum` in `DhtRecordEntry.status`. Hidden from `get_record()` and `get_all_records()` but exists locally.
2. **Phase 2 (Commit)**: On quorum approval, `commit_record_after_quorum()` transitions to `Live`, queues for announce, sends `DhtRecordCommit` to peers.

Key types:
- `DhtRecordStatus` enum (`PendingQuorum`, `Live`) in `src/mesh/protocol.rs` with `Default::default()` = `Live`
- `DhtRecordCommit` message (proto field 171) — sent to peers after commit
- `QuorumSignatureProto` — serializes signatures in commit messages

Key methods:
- `store_record_global()` — stores quorum-requiring records as `PendingQuorum` before starting quorum
- `commit_record_after_quorum()` — transitions to `Live`, announces, sends `DhtRecordCommit`
- `abort_pending_record()` — removes record on rejection/timeout
- `get_record()` / `get_all_records()` — filter out `PendingQuorum` records
- `handle_record_commit()` — handles incoming `DhtRecordCommit` on receiving nodes

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
- `src/mesh/dht/record_store_disk.rs` - SQLite-backed disk storage
- `src/mesh/dht/record_store.rs` - `load_from_disk()`, `persist_to_disk()` methods

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
```
