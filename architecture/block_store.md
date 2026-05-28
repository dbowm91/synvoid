# Block Store Architecture

## 1. Purpose and Responsibility

The Block Store module (`src/block_store.rs`) provides **persistent, thread-safe storage for IP blocklist entries** with automatic expiration, LRU eviction, and optional kernel-level mitigation provider integration.

**Core Responsibilities:**
- Thread-safe concurrent IP block/unblock operations
- Persistent storage with background flush to disk
- Automatic expiration of time-limited blocks
- LRU eviction when storage limits are reached
- Integration with kernel-level blocking (iptables, nftables)
- Site-scoped block isolation

---

## 2. Key Data Structures

```rust
pub struct BlockStore {
    entries: Arc<RwLock<HashMap<IpAddr, BlockEntry>>>,  // 64-shard concurrent map
    data_dir: Option<PathBuf>,
    persist_tx: mpsc::Sender<()>,                       // Background persistence
    entry_count: AtomicU64,
    mitigation_provider: ArcSwapOption<SizedMitigationProvider>,
}

pub struct BlockEntry {
    pub ip: IpAddr,
    pub reason: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub site_scope: Option<String>,
    pub access_count: u64,
    pub last_accessed: u64,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `BlockStore::new(enabled, data_dir, config)` | Load from disk, spawn persistence task |
| `block_ip(ip, reason, ban_expire_seconds, site_scope)` | Add block entry |
| `is_blocked(ip, site_scope) -> Option<BlockEntry>` | Check site-specific then global |
| `unblock_ip(ip, site_scope) -> bool` | Remove block entry |
| `add_block(ip_str, reason, duration, scope)` | Parse IP string and add block |
| `get_stats() -> BlockStoreStats` | Utilization metrics |
| `get_all_entries() -> Vec<BlockEntry>` | List all entries |
| `set_mitigation_provider(provider)` | Kernel-level blocking integration |
| `shutdown().await` | Flush pending data |
| `trigger_persist()` | Force immediate persistence |

---

## 4. Integration Points

- **WAF**: Rate limiting and attack mitigation trigger IP blocks
- **Admin API**: Blocklist management endpoints
- **MitigationProvider**: Kernel-level IP blocking (iptables/nftables)
- **Metrics**: Block/unblock event tracking

---

## 5. Key Implementation Details

- **Sharded Storage**: 64-shard concurrent hashmap for minimal lock contention
- **Background Persistence**: Tokio mpsc channel triggers disk flush without blocking request path
- **Site Scoping**: Blocks can be site-specific or global; site blocks checked first
- **LRU Eviction**: When storage is full, least-recently-accessed entries are evicted
- **File Permissions**: Data file set to `0o600` for security
