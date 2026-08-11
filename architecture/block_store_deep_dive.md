# Block Store Deep Dive

SynVoid's BlockStore provides persistent, thread-safe storage for IP and mesh-ID blocklist entries with automatic expiration, LRU eviction, and multi-node mesh propagation.

## Architecture

### Storage Model

```
BlockStore
├── IP Blocks (64 shards)
│   └── RwLock<AHashMap<String, BlockEntry>>
│       Key: "block:{scope}:{ip}"
│
├── Mesh-ID Blocks (64 shards)
│   └── RwLock<AHashMap<String, MeshBlockEntry>>
│       Key: "mesh:{scope}:{mesh_id}"
│
├── Event Log
│   └── VecDeque<BlocklistEvent> (bounded 10K)
│
├── Event Cache
│   └── SeenEventCache (bounded 10K)
│
├── Target State Cache
│   └── TargetStateCache (bounded 10K)
│
└── Persistence Channel
    └── mpsc::Sender<PersistCommand>
```

### Sharding

```rust
fn shard_key(scope: &str, identifier: &str) -> usize {
    let key = format!("{}:{}", scope, identifier);
    let hash = djb2_hash(key.as_bytes());
    hash as usize % NUM_SHARDS  // 64
}
```

DJB2 hash provides good distribution across shards, minimizing lock contention.

### Block Entry

```rust
pub struct BlockEntry {
    pub ip: IpAddr,
    pub reason: String,
    pub banned_at: u64,           // Unix timestamp
    pub expires_at: Option<u64>,  // Optional TTL
    pub site_scope: String,       // Site-specific or "global"
    pub access_count: AtomicU64,  // LRU eviction metric
    pub provenance: BlockProvenanceKind,
}

pub enum BlockProvenanceKind {
    LegacyUnknown,              // Backward compat
    AdminManual,                // Admin API
    SupervisorManual,           // Supervisor gRPC
    MeshPeer,                   // Mesh propagation
    ThreatIntel,                // Threat intelligence
    Honeypot,                   // Honeypot detection
    WafDetection,               // WAF attack detection
}
```

## Operations

### Blocking

```rust
impl BlockStore {
    pub fn block_ip_with_provenance(
        &self,
        ip: IpAddr,
        reason: &str,
        site_scope: &str,
        provenance: BlockProvenanceKind,
        ttl: Option<Duration>,
    ) -> BlockResult {
        let shard = self.ip_shards[shard_key(site_scope, &ip.to_string())];
        let mut guard = shard.write();
        
        let entry = BlockEntry {
            ip,
            reason: reason.to_string(),
            banned_at: current_timestamp(),
            expires_at: ttl.map(|d| current_timestamp() + d.as_secs()),
            site_scope: site_scope.to_string(),
            access_count: AtomicU64::new(0),
            provenance,
        };
        
        guard.insert(key, entry);
        
        // Enforce capacity
        if guard.len() > self.config.max_entries {
            self.evict_lru(&mut guard);
        }
        
        // Record event for mesh propagation
        self.record_event(BlocklistEvent::Block { ip, reason, site_scope });
        
        BlockResult::Blocked
    }
}
```

### LRU Eviction

```rust
fn evict_lru(&self, shard: &mut AHashMap<String, BlockEntry>) {
    // Sort by access_count (ascending)
    let mut entries: Vec<_> = shard.iter().collect();
    entries.sort_by_key(|(_, e)| e.access_count.load(Ordering::Relaxed));
    
    // Remove bottom 10%
    let evict_count = entries.len() / 10;
    for (key, _) in entries.into_iter().take(evict_count) {
        shard.remove(key);
    }
}
```

### Persistence

```rust
async fn persistence_loop(rx: mpsc::Receiver<PersistCommand>) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            PersistCommand::Persist => {
                // 1. Snapshot all shards
                let snapshot = self.snapshot();
                
                // 2. Write to temp file
                let tmp_path = format!("{}.tmp", self.config.path);
                let data = postcard::to_allocvec(&snapshot)?;
                std::fs::write(&tmp_path, &data)?;
                
                // 3. Atomic rename
                std::fs::rename(&tmp_path, &self.config.path)?;
            }
            PersistCommand::Shutdown => break,
        }
    }
}
```

### Event Log

```rust
pub struct BlocklistEventLog {
    events: VecDeque<BlocklistEvent>,
    next_sequence: u64,
    max_events: usize,  // Default 10K
}

pub struct BlocklistEvent {
    pub sequence: u64,
    pub timestamp: u64,
    pub event_type: BlocklistEventType,
    pub source_node: Option<String>,
}

pub enum BlocklistEventType {
    Block { ip, reason, site_scope },
    Unblock { ip, site_scope },
    MeshBlock { mesh_id, reason, site_scope },
    MeshUnblock { mesh_id, site_scope },
}
```

## Mesh Propagation

### Event Deduplication

```rust
pub struct SeenEventCache {
    seen: HashSet<Uuid>,
    max_size: usize,  // 10K
}

impl SeenEventCache {
    pub fn is_seen(&mut self, event_id: &Uuid) -> bool {
        if self.seen.contains(event_id) {
            return true;
        }
        self.seen.insert(*event_id);
        if self.seen.len() > self.max_size {
            // Evict oldest 10%
            let drain_count = self.max_size / 10;
            self.seen.drain(..drain_count);
        }
        false
    }
}
```

### Catchup Protocol

For offline peers reconnecting:

```rust
pub fn catchup_since(
    &self,
    cursor: BlocklistEventCursor,
) -> BlocklistCatchupResult {
    let events: Vec<_> = self.event_log.events
        .iter()
        .filter(|e| e.sequence > cursor.last_sequence)
        .take(cursor.batch_size)
        .cloned()
        .collect();
    
    let gap_detected = events.is_empty() 
        && self.event_log.next_sequence > cursor.last_sequence + 1;
    
    BlocklistCatchupResult {
        events,
        snapshot_required: gap_detected,
        next_cursor: BlocklistEventCursor {
            last_sequence: events.last().map(|e| e.sequence).unwrap_or(cursor.last_sequence),
            batch_size: cursor.batch_size,
        },
    }
}
```

## Integration Points

### WAF Request Path

```rust
// Via BlockListStore trait
if block_store.is_ip_blocked(client_ip, site_scope) {
    return WafDecision::Block { reason: "IP blocked" };
}
```

### Admin API

```rust
// Block via admin API
POST /api/v1/block
{
    "ip": "192.168.1.100",
    "reason": "Manual block",
    "ttl": 3600
}
```

### Mesh Control Plane

```rust
// Propagate block to mesh peers
mesh.broadcast_blocklist_event(BlocklistEvent::Block {
    ip: "192.168.1.100".parse()?,
    reason: "Threat intel".to_string(),
    site_scope: "global".to_string(),
});
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `BlockStore` | `crates/synvoid-block-store/src/lib.rs` | Main block store |
| `BlockEntry` | `crates/synvoid-block-store/src/lib.rs` | IP block entry |
| `MeshBlockEntry` | `crates/synvoid-block-store/src/lib.rs` | Mesh-ID block entry |
| `BlocklistEventLog` | `crates/synvoid-block-store/src/event_log.rs` | Bounded event log |
| `SeenEventCache` | `crates/synvoid-block-store/src/event_dedup.rs` | Event deduplication |
| `TargetStateCache` | `crates/synvoid-block-store/src/target_state.rs` | Per-target state tracking |
| `BlockProvenanceKind` | `crates/synvoid-block-store/src/lib.rs` | Block source attribution |
