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
    LegacyUnknown,              // Backward compat/tests/mocks only
    LocalWaf,                   // WAF attack detection
    LocalHoneypot,              // Honeypot detection
    LocalAsnTracker,            // ASN-based blocking
    MeshThreatIntelPolicyGated, // Mesh threat intelligence
    SupervisorSync,             // Supervisor sync
    AdminManual,                // Admin API
    SupervisorManual,           // Supervisor gRPC
    ProxyHealthProbe,           // Proxy health probe
    Test,                       // Test only
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
        
        let entry = BlockEntry::new_with_provenance(
            ip,
            reason.to_string(),
            ttl.map(|d| d.as_secs()).unwrap_or(0),
            site_scope.to_string(),
            BlockProvenance { kind: provenance, source: None },
        );
        
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
    entries.sort_by_key(|(_, e)| e.access_count);
    
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
                let data = serde_json::to_string_pretty(&snapshot)?;
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
    pub operation: BlocklistOperation,     // Block, Unblock
    pub target_kind: BlockTargetKind,     // Ip, MeshId
    pub identifier: String,               // IP address or mesh_id
    pub site_scope: String,
    pub reason: Option<String>,
    pub provenance: BlockProvenance,
    pub timestamp: u64,
    pub source_node: Option<String>,
    pub event_id: Option<String>,
    pub ttl_secs: Option<u64>,
    pub version: Option<u64>,
    pub source_sequence: Option<u64>,
    pub logical_time: Option<u64>,
}
```

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
| `BlocklistEventLog` | `crates/synvoid-block-store/src/lib.rs` | Bounded event log |
| `SeenEventCache` | `crates/synvoid-block-store/src/lib.rs` | Event deduplication |
| `TargetStateCache` | `crates/synvoid-block-store/src/lib.rs` | Per-target state tracking |
| `BlockProvenanceKind` | `crates/synvoid-core/src/block_store.rs` | Block source attribution |
