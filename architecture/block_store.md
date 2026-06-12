# Block Store Architecture

## 1. Purpose and Responsibility

The Block Store module (`crates/synvoid-block-store/src/lib.rs`) provides **persistent, thread-safe storage for IP and mesh-ID blocklist entries** with automatic expiration, LRU eviction, and optional kernel-level mitigation provider integration.

**Core Responsibilities:**
- Thread-safe concurrent IP block/unblock operations
- Thread-safe concurrent mesh-ID block/unblock operations
- Persistent storage with background flush to disk
- Automatic expiration of time-limited blocks
- LRU eviction when storage limits are reached
- Integration with kernel-level blocking (iptables, nftables)
- Site-scoped block isolation
- Legacy sentinel mesh-ID entry migration

---

## 2. Key Data Structures

```rust
pub struct BlockStore {
    shards: Vec<RwLock<AHashMap<String, BlockEntry>>>,      // 64-shard IP blocks
    mesh_shards: Vec<RwLock<AHashMap<String, MeshBlockEntry>>>, // 64-shard mesh-ID blocks
    enabled: bool,
    persist_path: Option<PathBuf>,
    config: DenyListLimitsConfig,
    total_entries: AtomicUsize,
    total_mesh_entries: AtomicUsize,
    persist_tx: Option<mpsc::Sender<PersistRequest>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    mitigation_provider: ArcSwapOption<SizedMitigationProvider>,
    seen_events: RwLock<SeenEventCache>,        // FIFO dedup cache (10k max)
    target_state: RwLock<TargetStateCache>,     // Per-target LWW state (10k max)
}

pub struct BlockEntry {
    pub ip: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub access_count: u64,
    pub last_access: u64,
    pub provenance: BlockProvenance,
}

pub struct MeshBlockEntry {
    pub mesh_id: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub access_count: u64,
    pub last_access: u64,
    pub provenance: BlockProvenance,
}

pub enum BlockTargetKind { Ip, MeshId }

pub struct BlockRecord {
    pub target_kind: BlockTargetKind,
    pub identifier: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub access_count: u64,
    pub last_access: u64,
    pub provenance: BlockProvenance,
}
```

---

## 3. Public API

### IP Block Methods

| Method | Description |
|--------|-------------|
| `BlockStore::new(enabled, data_dir, config)` | Load from disk, auto-migrate legacy sentinels, spawn persistence task |
| `block_ip(ip, reason, ban_expire_seconds, site_scope)` | Add IP block entry |
| `block_ip_with_provenance(ip, reason, duration, scope, provenance)` | Add IP block with provenance |
| `is_blocked(ip, site_scope) -> Option<BlockEntry>` | Check site-specific then global |
| `unblock_ip(ip, site_scope) -> bool` | Remove IP block entry |
| `add_block(ip_str, reason, duration, scope)` | Parse IP string and add block |

### Mesh-ID Block Methods

| Method | Description |
|--------|-------------|
| `block_mesh_id_with_provenance(mesh_id, reason, duration, scope, provenance)` | Add mesh-ID block |
| `is_mesh_id_blocked(mesh_id, site_scope) -> Option<MeshBlockEntry>` | Check mesh-ID block |
| `unblock_mesh_id(mesh_id, site_scope) -> bool` | Remove mesh-ID block |

### Unified Methods

| Method | Description |
|--------|-------------|
| `get_all_entries() -> Vec<BlockEntry>` | List all IP entries |
| `get_all_mesh_entries() -> Vec<MeshBlockEntry>` | List all mesh-ID entries |
| `get_all_block_records() -> Vec<BlockRecord>` | Unified listing (IP + mesh) |
| `get_stats() -> BlockStoreStats` | IP block utilization metrics |
| `get_mesh_stats() -> usize` | Mesh block count |
| `migrate_legacy_sentinel_entries() -> usize` | Migrate sentinel entries |
| `set_mitigation_provider(provider)` | Kernel-level blocking integration |
| `shutdown().await` | Flush pending data |
| `trigger_persist()` | Force immediate persistence |

### Event Application Methods

| Method | Description |
|--------|-------------|
| `apply_blocklist_event(event) -> BlocklistApplyResult` | 5-step pipeline: validate → dedup → stale check → mutate → record state |

---

## 4. Integration Points

- **WAF**: Rate limiting and attack mitigation trigger IP blocks (reads IP blocks only)
- **Admin API**: Blocklist management endpoints (IP + mesh-ID blocks)
- **Supervisor/Worker Sync**: IPC carries both IP and mesh-ID blocks
- **MitigationProvider**: Kernel-level IP blocking (iptables/nftables)
- **Metrics**: Block/unblock event tracking

---

## 5. Key Implementation Details

- **Sharded Storage**: 64-shard concurrent hashmap for minimal lock contention (separate shards for IP and mesh-ID)
- **Background Persistence**: Tokio mpsc channel triggers disk flush without blocking request path
- **Site Scoping**: Blocks can be site-specific or global; site blocks checked first
- **LRU Eviction**: When IP storage is full, least-recently-accessed entries are evicted. Overwriting an existing `(site_scope, ip)` entry does NOT trigger LRU eviction.
- **File Permissions**: Data file set to `0o600` for security
- **Separate Persistence**: IP blocks in `blocks.json`, mesh-ID blocks in `mesh_blocks.json`
- **Legacy Migration**: `migrate_legacy_sentinel_entries()` converts sentinel `0.0.0.0` entries to first-class mesh blocks. **Auto-called** by `BlockStore::new` after loading both IP and mesh files from disk.
- **Counter Correctness**: `block_ip`, `block_ip_with_provenance`, and `add_block` only increment `total_entries` on new key insertion. Overwriting an existing `(site_scope, ip)` entry updates the entry without changing the count.
- **Mesh-ID Deadlock Fix**: `block_mesh_id_with_provenance` drops the shard write lock before calling `trigger_persist()`, preventing deadlock where the persist path tries to read the same shard.
- **BlocklistEvent Propagation**: Admin ban/unban handlers emit structured `BlocklistEvent` debug logs (target `blocklist_event`). Admin unban also gossips `BlocklistEventGossip` to mesh peers and pushes `BlocklistEventUpdate` IPC to workers. Apply pipeline uses FIFO dedup (`SeenEventCache`) and per-target stale suppression (`TargetStateCache`). In-memory state; not persisted across restarts. See `architecture/blocklist_remove_consistency.md`.
