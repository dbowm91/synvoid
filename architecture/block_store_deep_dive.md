# Block Store Deep Dive

SynVoid's BlockStore provides persistent, thread-safe storage for IP and mesh-ID blocklist entries with automatic expiration, LRU eviction, and multi-node mesh propagation.

## Architecture

### Storage Model

```
BlockStore
├── IP Blocks (64 shards)
│   └── RwLock<AHashMap<String, BlockEntry>>
│       Key: "block:{scope}:{ip}"        (BlockEntry::key)
│
├── Mesh-ID Blocks (64 shards)
│   └── RwLock<AHashMap<String, MeshBlockEntry>>
│       Key: "mesh_block:{scope}:{mesh_id}"  (MeshBlockEntry::key)
│
├── Event Log
│   └── VecDeque<BlocklistEvent> (bounded, FIFO)
│
├── Event Cache
│   └── SeenEventCache (bounded, FIFO)
│
├── Target State Cache
│   └── TargetStateCache (bounded; TARGET_STATE_MAX = 10_000)
│
└── Persistence Channel
    └── Option<mpsc::Sender<PersistCommand>>   // trigger_persist()
```

### Sharding

```rust
// crates/synvoid-block-store/src/lib.rs
const NUM_SHARDS: usize = 64;

#[inline]
pub(crate) fn shard_index(key: &str) -> usize {
    // DJB2, inlined; the seed 5381 and multiplier 33 are the classic constants.
    let mut hash: u64 = 5381;
    for byte in key.as_bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
    }
    (hash as usize) % NUM_SHARDS
}
```

Callers build the key first and then shard on the whole key, e.g.
`Self::shard_index(&BlockEntry::key(site_scope, &ip))`. The same function
selects the shard for both the IP and mesh-ID maps. DJB2 provides good
distribution across shards, minimizing lock contention.

### Block Entry

```rust
pub struct BlockEntry {
    pub ip: String,
    pub reason: String,
    pub blocked_at: u64,           // Unix timestamp
    pub ban_expire_seconds: u64,   // 0 = permanent
    pub site_scope: String,       // Site-specific or "global"
    pub access_count: u64,        // LRU eviction metric
    pub last_access: u64,         // Last access timestamp
    pub provenance: BlockProvenance, // Contains kind: BlockProvenanceKind + optional source
}

pub enum BlockProvenanceKind {
    LocalWaf,                   // WAF attack detection
    LocalHoneypot,              // Honeypot detection
    LocalAsnTracker,            // ASN-based blocking
    MeshThreatIntelPolicyGated, // Mesh threat intelligence
    SupervisorSync,             // Supervisor sync
    AdminManual,                // Admin API
    SupervisorManual,           // Supervisor gRPC
    ProxyHealthProbe,           // Proxy health probe
    Test,                       // Test only
    #[default]
    LegacyUnknown,              // Backward compat / tests / mocks only
}
```

## Operations

### Blocking

```rust
// crates/synvoid-block-store/src/lib.rs
impl BlockStore {
    pub fn block_ip_with_provenance(
        &self,
        ip: IpAddr,
        reason: &str,
        ban_expire_seconds: u64,   // 0 = permanent; NOT Option<Duration>
        site_scope: &str,
        provenance: BlockProvenance, // the full struct, not BlockProvenanceKind
    ) -> bool {                   // NOT a BlockResult
        if !self.enabled {
            return false;
        }

        let entry = BlockEntry::new_with_provenance(
            ip,
            reason.to_string(),
            ban_expire_seconds,
            site_scope.to_string(),
            provenance.clone(),
        );
        let key = BlockEntry::key(site_scope, &ip);
        let idx = Self::shard_index(&key);

        {
            let _capacity_guard = self.capacity_lock.lock();
            let is_new = !self.shards[idx].read().contains_key(&key);

            if is_new {
                // Capacity is checked against a GLOBAL entry counter, not
                // per-shard length, and eviction removes exactly one entry.
                let max_entries = self.config.max_entries;
                let current = self.total_entries.load(Ordering::Relaxed);
                if current >= max_entries {
                    if !self.evict_lru() {
                        return false;
                    }
                }
            }

            self.shards[idx].write().insert(key, entry);
            if is_new {
                self.total_entries.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.trigger_persist();
        // ... record target state for stale-replay protection, return true
        true
    }
}
```

The method returns a plain `bool`. It does **not** return a `BlockResult`, and
it does not directly append a `BlocklistEvent` here — mesh propagation is
driven by the store's event-log append path, not by this method's tail.

### LRU Eviction

```rust
// crates/synvoid-block-store/src/lib.rs
fn evict_lru(&self) -> bool {          // no shard argument; one entry at a time
    // Two passes: scan under read locks for the global minimum last_access,
    // then re-check under that shard's write lock. If the entry changed since
    // the scan, `continue` retries once rather than evicting a hot entry.
    for _ in 0..2 {
        let mut min_key: Option<String> = None;
        let mut min_shard_idx: Option<usize> = None;
        let mut min_last_access: u64 = u64::MAX;

        for (idx, shard) in self.shards.iter().enumerate() {
            let store = shard.read();
            if let Some((key, entry)) = store.iter().min_by_key(|(_, e)| e.last_access) {
                if entry.last_access < min_last_access {
                    min_last_access = entry.last_access;
                    min_key = Some(key.clone());
                    min_shard_idx = Some(idx);
                }
            }
        }

        if let Some((key, idx)) = min_key.zip(min_shard_idx) {
            let mut shard = self.shards[idx].write();
            match shard.get(&key) {
                Some(entry) if entry.last_access != min_last_access => continue,
                Some(_) => { shard.remove(&key); /* dec total_entries */ return true; }
                None => continue,
            }
        }
    }
    false
}
```

Two corrections to the earlier description: the eviction metric is
`last_access`, **not** `access_count`, and eviction removes a **single** globally
-oldest entry rather than "the bottom 10%" of one shard. There is a parallel
`evict_lru_mesh()` with the same shape over `mesh_shards`, and separate
`capacity_lock` / `mesh_capacity_lock` mutexes plus `total_entries` counters.

### Persistence

Persistence is **debounced through an optional channel, not a per-command
loop**. `trigger_persist()` flattens every shard into a `(key, entry)` vector
and sends it on `self.persist_tx` (`Option<mpsc::Sender<PersistCommand>>`); the
actual write is a free `async fn` over the collected snapshot:

```rust
// crates/synvoid-block-store/src/lib.rs
async fn save_blocks_to_disk(
    path: &PathBuf,
    entries: &[(String, BlockEntry)],
    max_entries: usize,
) -> Result<(), String> {
    let entries_to_save: Vec<BlockEntry> = entries
        .iter()
        .filter(|(_, e)| !e.is_expired())   // expired entries are never persisted
        .take(max_entries)
        .map(|(_, e)| e.clone())
        .collect();

    let json = serde_json::to_string_pretty(&entries_to_save)
        .map_err(|e| format!("failed to serialize block entries: {}", e))?;
    let temp_path = path.with_extension("tmp");     // NOT format!("{}.tmp", path)
    tokio::fs::write(&temp_path, json)
        .await
        .map_err(|e| format!("failed to write blocks to disk: {}", e))?;
    tokio::fs::rename(&temp_path, path)
        .await
        .map_err(|e| format!("failed to rename temp block file: {}", e))?;
    Self::set_secure_permissions(path).await;       // 0600 on Unix
    Ok(())
}
```

Corrections to the earlier snippet: the temp path comes from
`path.with_extension("tmp")`, the writes are `tokio::fs` (not `std::fs`), the
snapshot is a flat `Vec<BlockEntry>` (not a wrapper struct), expired entries are
filtered out, the write is capped by `max_entries`, and a final
`set_secure_permissions()` call hardens the file. `blocks.json`,
`mesh_blocks.json`, and `blocklist_target_state.json` each use this same
write-temp-then-rename pattern.

### Event Log

```rust
pub struct BlocklistEventLog {
    events: VecDeque<synvoid_core::block_store::BlocklistEvent>,
    seen_ids: HashSet<String>,   // in-log dedupe, in addition to SeenEventCache
    max_events: usize,           // bounded; oldest evicted FIFO
    next_sequence: u64,
}

// crates/synvoid-core/src/block_store.rs — the event type lives in synvoid-core,
// not in the block-store crate. The log re-exports it by qualified path.
pub struct BlocklistEvent {
    pub operation: BlocklistOperation,     // Block, Unblock
    pub target_kind: BlockTargetKind,      // Ip, MeshId
    pub identifier: String,                // IP address or mesh_id
    pub site_scope: String,
    pub reason: Option<String>,
    pub provenance: BlockProvenance,
    pub timestamp: u64,
    #[serde(default)] pub source_node: Option<String>,
    #[serde(default)] pub event_id: Option<String>,
    #[serde(default)] pub ttl_secs: Option<u64>,
    #[serde(default)] pub version: Option<u64>,
    #[serde(default)] pub source_sequence: Option<u64>,
    #[serde(default)] pub logical_time: Option<u64>,
}
```

Note what is **absent**: there is no `sequence` field on `BlocklistEvent`. The
log assigns a sequence in `append()` (which returns `Option<u64>`) and keeps it
**positionally** — the deque is contiguous, so the oldest retained sequence is
recovered as `next_sequence - events.len()`. `BlocklistEvent::source_sequence`
is a different thing: the originating node's own counter, used for event
ordering across peers.

## Mesh Propagation

### Event Deduplication

```rust
struct SeenEventCache {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl SeenEventCache {
    fn contains(&self, event_id: &str) -> bool {
        self.set.contains(event_id)
    }

    fn insert(&mut self, event_id: String) {
        if self.set.contains(&event_id) {
            return;
        }
        self.set.insert(event_id.clone());
        self.order.push_back(event_id);
        while self.order.len() > SEEN_EVENTS_MAX {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            }
        }
    }
}
```

### Catchup Protocol

For offline peers reconnecting:

```rust
// crates/synvoid-block-store/src/lib.rs
pub struct BlocklistEventCursor {
    pub since_sequence: Option<u64>,  // None = from oldest retained event
    pub max_events: u32,              // NOT batch_size
}

pub struct BlocklistCatchupResult {
    pub events: Vec<synvoid_core::block_store::BlocklistEvent>,
    pub history_complete: bool,       // false => requested history was evicted
    pub latest_sequence: u64,
    pub latest_timestamp: u64,
    pub snapshot_required: bool,
}

// impl BlocklistEventLog
pub fn query_since(&self, cursor: &BlocklistEventCursor) -> BlocklistCatchupResult {
    let max = cursor.max_events as usize;
    let total = self.events.len();

    if total == 0 {
        return BlocklistCatchupResult {
            events: Vec::new(),
            history_complete: true,
            latest_sequence: cursor.since_sequence.unwrap_or(0),
            latest_timestamp: 0,
            snapshot_required: false,
        };
    }

    // The first event in the deque has sequence `oldest_seq`.
    let oldest_seq = self.next_sequence.saturating_sub(total as u64);
    // ... index into `self.events` using oldest_seq, skipping to the first
    //     event whose positional sequence > cursor.since_sequence, then
    //     collect up to `max` events oldest-first.
}
```

Corrections to the earlier snippet: the method is `query_since` (not
`catchup_since`) and takes the cursor by reference; the cursor field is
`max_events` (not `batch_size`); there is no `next_cursor` in the result — the
caller advances from `latest_sequence`; and gap detection is driven by
`oldest_seq` versus the requested `since_sequence` to set `history_complete` /
`snapshot_required`, not by an `events.is_empty()` test. Events carry no
`sequence` field, so nothing is filtered by `e.sequence`.

## Integration Points

### WAF Request Path

```rust
// The narrow trait surface is `is_blocked(&IpAddr, &str) -> Option<BlockEntry>`
// (crates/synvoid-waf/src/traits.rs, delegating to
// BlockStore::is_blocked). There is no `is_ip_blocked` method.
if block_store.is_blocked(&client_ip, site_scope).is_some() {
    return WafDecision::Block { /* ... */ };
}
```

This admission check runs at the **worker composition root**, before the WAF
pipeline — the WAF pipeline itself neither queries nor mutates block state.

### Admin API

```rust
// Block via admin API — src/admin/routes.rs
POST /mesh/ban/ip
{
    "ip": "192.168.1.100",
    "reason": "Manual block",
    "duration_seconds": 3600,      // optional; the field is NOT "ttl"
    "site_scope": "global"         // optional
}
```

`BanIpRequest` is the body type. The handler is `mesh_admin::ban_ip`, which
calls `block_ip_with_provenance(..)` with
`BlockProvenanceKind::AdminManual` / `source: Some("admin_ban_ip")`, appends a
`BlocklistEvent::block_ip(..)` to the log, and then propagates. There is no
`/api/v1/block` route; the sibling routes are `/mesh/ban/mesh-id`,
`DELETE /mesh/ban` (unban) and `GET /mesh/bans` (list).

### Mesh Control Plane

```rust
// Propagate to mesh peers — the IPC process manager serialises the event
pm.broadcast_blocklist_event(
    event_json,        // String: the BlocklistEvent serialised to JSON
    source_node,       // String
    event_id,          // String
).await;
```

The signature is `(event_json: String, source_node: String, event_id: String)`,
not a `BlocklistEvent::Block { .. }` struct literal — `BlocklistEvent` has no
enum variants, it is a flat struct with an `operation` field. The manager also
appends the event to its own `blocklist_event_log` so a reconnecting worker can
catch up.

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `BlockStore` | `crates/synvoid-block-store/src/lib.rs` | Main block store |
| `BlockEntry` | `crates/synvoid-block-store/src/lib.rs` | IP block entry |
| `MeshBlockEntry` | `crates/synvoid-block-store/src/lib.rs` | Mesh-ID block entry |
| `BlocklistEventLog` | `crates/synvoid-block-store/src/lib.rs` | Bounded event log |
| `SeenEventCache` | `crates/synvoid-block-store/src/lib.rs` | Event deduplication |
| `TargetStateCache` | `crates/synvoid-block-store/src/lib.rs` | Per-target state tracking |
| `BlockProvenanceKind` | `crates/synvoid-core/src/block_store.rs` | Block source attribution |
| `BlocklistEvent` | `crates/synvoid-core/src/block_store.rs` | Block/unblock event wire type (flat struct, not an enum) |
| `BlocklistEventCursor` | `crates/synvoid-block-store/src/lib.rs` | Peer replay cursor (`since_sequence`, `max_events`) |
