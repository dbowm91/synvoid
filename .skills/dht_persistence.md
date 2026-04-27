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
const CURRENT_SCHEMA_VERSION: u32 = 1;
```
