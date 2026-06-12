//! Block store for IP blocking management.
//!
//! This module provides persistent storage for IP blocklist entries,
//! supporting automatic expiration and graceful shutdown.
//!
//! # Features
//! - Thread-safe access using RwLock
//! - Automatic persistence to disk
//! - Expiration-based cleanup
//! - Graceful shutdown with data flush

use ahash::AHashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use synvoid_config::DenyListLimitsConfig;
use tokio::sync::mpsc;

pub use synvoid_core::block_store::{
    BlockProvenance, BlockProvenanceKind, BlockRecord, BlockTargetKind, BlocklistEvent,
    BlocklistOperation, BlocklistSnapshotApplyResult, BlocklistSnapshotChunk,
    BlocklistSnapshotCursor, BlocklistSnapshotOptions, BlocklistTargetStateRecord, MeshBlockEntry,
};
use synvoid_waf::mitigation::{MitigationProvider, SizedMitigationProvider};

pub type GlobalBlockHook = Arc<dyn Fn(IpAddr) + Send + Sync>;

const DEFAULT_MAX_ENTRIES: usize = 500_000;
const NUM_SHARDS: usize = 64;
const SEEN_EVENTS_MAX: usize = 10_000;

/// Result of applying a blocklist event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistApplyResult {
    Applied,
    NoopDuplicate,
    IgnoredStale,
    InvalidTarget,
    StoreDisabled,
}

const TARGET_STATE_MAX: usize = 10_000;

/// FIFO dedupe cache for seen event IDs. Evicts oldest entries one-by-one
/// instead of clearing the entire set at capacity.
struct SeenEventCache {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl SeenEventCache {
    fn new() -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
        }
    }

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

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.set.len()
    }
}

/// Target key for per-target last-applied event tracking.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BlocklistTargetKey {
    target_kind: BlockTargetKind,
    site_scope: String,
    identifier: String,
}

/// Metadata about the last-applied event for a specific target.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct LastAppliedBlocklistEvent {
    timestamp: u64,
    version: Option<u64>,
    event_id: Option<String>,
    operation: BlocklistOperation,
    source_node: Option<String>,
    provenance: BlockProvenance,
}

impl LastAppliedBlocklistEvent {
    /// Returns true if `other` should be rejected as stale compared to `self`.
    /// Higher version wins. If versions are equal or absent, higher timestamp wins.
    /// Equal timestamp + same event_id = duplicate (handled by seen_events).
    fn is_newer_than(&self, other: &LastAppliedBlocklistEvent) -> bool {
        match (self.version, other.version) {
            (Some(a), Some(b)) => a > b,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => self.timestamp > other.timestamp,
        }
    }
}

/// Bounded in-memory cache of per-target last-applied event state.
/// Hydrated from persisted target-state records on startup when enabled.
/// Runtime capacity remains bounded; persistence provides restart-safe warm start.
struct TargetStateCache {
    entries: AHashMap<BlocklistTargetKey, LastAppliedBlocklistEvent>,
    order: VecDeque<BlocklistTargetKey>,
}

impl TargetStateCache {
    fn new() -> Self {
        Self {
            entries: AHashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&self, key: &BlocklistTargetKey) -> Option<&LastAppliedBlocklistEvent> {
        self.entries.get(key)
    }

    fn insert(&mut self, key: BlocklistTargetKey, state: LastAppliedBlocklistEvent) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, state);
        while self.order.len() > TARGET_STATE_MAX {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Export all non-expired entries as (key, state) pairs for snapshot.
    fn export_entries(&self) -> Vec<(BlocklistTargetKey, LastAppliedBlocklistEvent)> {
        self.entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Check if a target state entry exists and whether the given event is newer.
    fn is_event_newer(
        &self,
        key: &BlocklistTargetKey,
        timestamp: u64,
        version: Option<u64>,
    ) -> bool {
        if let Some(last) = self.get(key) {
            let candidate = LastAppliedBlocklistEvent {
                timestamp,
                version,
                event_id: None,
                operation: BlocklistOperation::Block, // doesn't matter for comparison
                source_node: None,
                provenance: BlockProvenance::default(),
            };
            candidate.is_newer_than(last)
        } else {
            // No previous state — event is newer by default.
            true
        }
    }
}

/// Default maximum number of events retained in the event log.
const DEFAULT_EVENT_LOG_MAX: usize = 10_000;

/// A bounded in-memory event log for blocklist events.
///
/// Records locally-originated and received blocklist events after they are
/// accepted for propagation/application. Enables offline-peer catchup by
/// allowing reconnecting peers to request recent events since a cursor.
///
/// # Invariants
///
/// - Events are deduplicated by event ID before insertion.
/// - Capacity is bounded; oldest events are evicted FIFO when at capacity.
/// - The log is in-memory only; restart loses retained events.
/// - The log does not block the request path.
#[derive(Debug)]
pub struct BlocklistEventLog {
    events: VecDeque<synvoid_core::block_store::BlocklistEvent>,
    seen_ids: HashSet<String>,
    max_events: usize,
    next_sequence: u64,
}

/// Cursor for replaying events from the log.
///
/// `since_sequence` controls the starting point:
/// - `None`: replay from the oldest retained event (from start).
/// - `Some(n)`: replay events with sequence `> n` (exclusive cursor).
///
/// "From start" means from the oldest retained event, not necessarily from
/// genesis. If the caller needs genesis-complete history, it must use a
/// separate snapshot/digest path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocklistEventCursor {
    /// The sequence number to replay from (exclusive), or `None` to replay
    /// from the oldest retained event.
    pub since_sequence: Option<u64>,
    /// Optional maximum number of events to return.
    pub max_events: u32,
}

/// Result of a catchup query against the event log.
#[derive(Debug, Clone)]
pub struct BlocklistCatchupResult {
    /// Events matching the query, ordered oldest-first.
    pub events: Vec<synvoid_core::block_store::BlocklistEvent>,
    /// Whether the log contains all events since the cursor.
    /// `false` means the requested history has been evicted.
    pub history_complete: bool,
    /// The sequence number of the most recent event in the log,
    /// or `since_sequence` if the log is empty.
    pub latest_sequence: u64,
    /// The timestamp of the most recent event in the log,
    /// or 0 if the log is empty.
    pub latest_timestamp: u64,
    /// Whether the requesting peer should request a full snapshot
    /// (i.e., history is incomplete and catchup alone is insufficient).
    pub snapshot_required: bool,
}

impl BlocklistEventLog {
    /// Create a new event log with the given maximum capacity.
    pub fn new(max_events: usize) -> Self {
        Self {
            events: VecDeque::new(),
            seen_ids: HashSet::new(),
            max_events,
            next_sequence: 0,
        }
    }

    /// Create a new event log with default capacity (10,000 events).
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_EVENT_LOG_MAX)
    }

    /// Append an event to the log. Returns the assigned sequence number.
    ///
    /// If the event has an event ID that is already in the log, the insert
    /// is a no-op and returns `None`.
    pub fn append(&mut self, event: synvoid_core::block_store::BlocklistEvent) -> Option<u64> {
        if let Some(ref eid) = event.event_id {
            if self.seen_ids.contains(eid) {
                return None;
            }
            self.seen_ids.insert(eid.clone());
        }
        let seq = self.next_sequence;
        self.next_sequence += 1;
        self.events.push_back(event);
        // Evict oldest events when over capacity.
        while self.events.len() > self.max_events {
            if let Some(oldest) = self.events.pop_front() {
                if let Some(ref eid) = oldest.event_id {
                    self.seen_ids.remove(eid);
                }
            }
        }
        Some(seq)
    }

    /// Query events since a given cursor.
    ///
    /// - `since_sequence: None` returns events from the oldest retained event.
    /// - `since_sequence: Some(n)` returns events with sequence `> n`.
    ///
    /// Up to `cursor.max_events` events are returned. "From start" means from
    /// the oldest retained event, not necessarily from genesis.
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

        match cursor.since_sequence {
            None => {
                // From start: return all retained events starting at index 0.
                let mut events = Vec::new();
                for i in 0..total {
                    if events.len() >= max {
                        break;
                    }
                    events.push(self.events[i].clone());
                }
                let latest_sequence = self.next_sequence.saturating_sub(1);
                let latest_timestamp = self.events.back().map(|e| e.timestamp).unwrap_or(0);
                BlocklistCatchupResult {
                    events,
                    history_complete: true,
                    latest_sequence,
                    latest_timestamp,
                    snapshot_required: false,
                }
            }
            Some(since) => {
                // Check for gap: requested cursor is before our oldest retained
                // event, meaning some history has been evicted.
                let evicted_gap = since + 1 < oldest_seq && oldest_seq > 0;

                // Compute the index of the first event with sequence > since.
                let first_idx = if since < oldest_seq {
                    0
                } else {
                    let offset = (since - oldest_seq + 1) as usize;
                    offset.min(total)
                };

                let mut events = Vec::new();
                for i in first_idx..total {
                    if events.len() >= max {
                        break;
                    }
                    events.push(self.events[i].clone());
                }

                let latest_sequence = self.next_sequence.saturating_sub(1);
                let latest_timestamp = self.events.back().map(|e| e.timestamp).unwrap_or(0);

                BlocklistCatchupResult {
                    events,
                    history_complete: !evicted_gap,
                    latest_sequence,
                    latest_timestamp,
                    snapshot_required: evicted_gap,
                }
            }
        }
    }

    /// Return the number of events currently retained.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Return `true` if the log contains no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Return the oldest timestamp in the log, or `None` if empty.
    pub fn oldest_timestamp(&self) -> Option<u64> {
        self.events.front().map(|e| e.timestamp)
    }

    /// Return the newest timestamp in the log, or `None` if empty.
    pub fn newest_timestamp(&self) -> Option<u64> {
        self.events.back().map(|e| e.timestamp)
    }

    /// Return the current sequence counter value (the next sequence to be assigned).
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    pub ip: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub access_count: u64,
    pub last_access: u64,
    #[serde(default)]
    pub provenance: BlockProvenance,
}

impl BlockEntry {
    pub fn new(ip: IpAddr, reason: String, ban_expire_seconds: u64, site_scope: String) -> Self {
        let now = synvoid_utils::safe_unix_timestamp();
        Self {
            ip: ip.to_string(),
            reason,
            blocked_at: now,
            ban_expire_seconds,
            site_scope,
            access_count: 0,
            last_access: now,
            provenance: BlockProvenance::default(),
        }
    }

    pub fn new_with_provenance(
        ip: IpAddr,
        reason: String,
        ban_expire_seconds: u64,
        site_scope: String,
        provenance: BlockProvenance,
    ) -> Self {
        let now = synvoid_utils::safe_unix_timestamp();
        Self {
            ip: ip.to_string(),
            reason,
            blocked_at: now,
            ban_expire_seconds,
            site_scope,
            access_count: 0,
            last_access: now,
            provenance,
        }
    }

    pub fn is_permanent(&self) -> bool {
        self.ban_expire_seconds == 0
    }

    pub fn is_expired(&self) -> bool {
        if self.is_permanent() {
            return false;
        }
        let now = synvoid_utils::safe_unix_timestamp();
        now > self.blocked_at + self.ban_expire_seconds
    }

    pub fn key(site_scope: &str, ip: &IpAddr) -> String {
        format!("block:{}:{}", site_scope, ip)
    }

    pub fn update_access(&mut self) {
        let now = synvoid_utils::safe_unix_timestamp();
        self.access_count += 1;
        self.last_access = now;
    }
}

pub struct BlockStore {
    shards: Vec<RwLock<AHashMap<String, BlockEntry>>>,
    mesh_shards: Vec<RwLock<AHashMap<String, MeshBlockEntry>>>,
    enabled: bool,
    persist_path: Option<PathBuf>,
    target_state_path: Option<PathBuf>,
    config: DenyListLimitsConfig,
    total_entries: AtomicUsize,
    total_mesh_entries: AtomicUsize,
    persist_tx: Option<mpsc::Sender<PersistRequest>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    mitigation_provider: arc_swap::ArcSwapOption<SizedMitigationProvider>,
    seen_events: RwLock<SeenEventCache>,
    target_state: RwLock<TargetStateCache>,
    event_log: RwLock<BlocklistEventLog>,
}

impl BlockStore {
    #[inline]
    pub(crate) fn shard_index(key: &str) -> usize {
        let mut hash: u64 = 5381;
        for byte in key.as_bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
        }
        (hash as usize) % NUM_SHARDS
    }
}

#[derive(Debug, Clone)]
struct PersistRequest {
    entries: Vec<(String, BlockEntry)>,
    mesh_entries: Vec<(String, MeshBlockEntry)>,
}

impl BlockStore {
    pub fn new(enabled: bool, data_dir: Option<PathBuf>, config: DenyListLimitsConfig) -> Self {
        let persist_path = data_dir.map(|d| d.join("blocks.json"));
        let mesh_persist_path = persist_path.as_ref().map(|p| {
            p.parent()
                .unwrap_or(std::path::Path::new("."))
                .join("mesh_blocks.json")
        });
        let target_state_path = persist_path.as_ref().map(|p| {
            p.parent()
                .unwrap_or(std::path::Path::new("."))
                .join("blocklist_target_state.json")
        });
        let max_entries = if config.max_entries > 0 {
            config.max_entries
        } else {
            DEFAULT_MAX_ENTRIES
        };

        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(RwLock::new(AHashMap::new()));
        }
        let mut mesh_shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            mesh_shards.push(RwLock::new(AHashMap::new()));
        }

        let initial_count: usize;
        if let Some(ref path) = persist_path {
            if path.exists() {
                match std::fs::read_to_string(path) {
                    Ok(content) => match serde_json::from_str::<Vec<BlockEntry>>(&content) {
                        Ok(entries) => {
                            let mut parse_errors = 0;
                            for e in entries {
                                match e.ip.parse::<IpAddr>() {
                                    Ok(ip) => {
                                        if !e.is_expired() {
                                            let key = BlockEntry::key(&e.site_scope, &ip);
                                            let idx = Self::shard_index(&key);
                                            shards[idx].write().insert(key, e);
                                        }
                                    }
                                    Err(_) => {
                                        parse_errors += 1;
                                        tracing::warn!(
                                            "Skipping block entry with invalid IP: {}",
                                            e.ip
                                        );
                                    }
                                }
                            }
                            if parse_errors > 0 {
                                tracing::warn!(
                                    "Skipped {} block entries with invalid IPs",
                                    parse_errors
                                );
                            }
                            initial_count = shards.iter().map(|s| s.read().len()).sum();
                            tracing::info!(
                                "Loaded {} valid block entries from disk",
                                initial_count
                            );
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse blocks.json: {}, starting fresh", e);
                            initial_count = 0;
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to read blocks.json: {}, starting fresh", e);
                        initial_count = 0;
                    }
                }
            } else {
                initial_count = 0;
            }
        } else {
            initial_count = 0;
        };

        let initial_mesh_count: usize;
        if let Some(ref mesh_path) = mesh_persist_path {
            if mesh_path.exists() {
                match std::fs::read_to_string(mesh_path) {
                    Ok(content) => match serde_json::from_str::<Vec<MeshBlockEntry>>(&content) {
                        Ok(entries) => {
                            for e in entries {
                                if !e.is_expired() {
                                    let key = MeshBlockEntry::key(&e.site_scope, &e.mesh_id);
                                    let idx = Self::shard_index(&key);
                                    mesh_shards[idx].write().insert(key, e);
                                }
                            }
                            initial_mesh_count = mesh_shards.iter().map(|s| s.read().len()).sum();
                            tracing::info!(
                                "Loaded {} mesh block entries from disk",
                                initial_mesh_count
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to parse mesh_blocks.json: {}, starting fresh",
                                e
                            );
                            initial_mesh_count = 0;
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to read mesh_blocks.json: {}, starting fresh", e);
                        initial_mesh_count = 0;
                    }
                }
            } else {
                initial_mesh_count = 0;
            }
        } else {
            initial_mesh_count = 0;
        };

        // Phase 4: Load persisted target state records and hydrate TargetStateCache.
        let mut target_state_cache = TargetStateCache::new();
        let mut target_state_loaded = 0usize;
        let mut target_state_expired = 0usize;
        if config.target_state_persist {
            if let Some(ref ts_path) = target_state_path {
                if ts_path.exists() {
                    match std::fs::read_to_string(ts_path) {
                        Ok(content) => {
                            match serde_json::from_str::<Vec<BlocklistTargetStateRecord>>(&content)
                            {
                                Ok(records) => {
                                    for record in records {
                                        if record.is_expired() {
                                            target_state_expired += 1;
                                            continue;
                                        }
                                        let key = BlocklistTargetKey {
                                            target_kind: record.target_kind,
                                            site_scope: record.site_scope,
                                            identifier: record.identifier,
                                        };
                                        let state = LastAppliedBlocklistEvent {
                                            timestamp: record.timestamp,
                                            version: record.version,
                                            event_id: record.event_id,
                                            operation: record.last_operation,
                                            source_node: record.source_node,
                                            provenance: record.provenance,
                                        };
                                        target_state_cache.insert(key, state);
                                        target_state_loaded += 1;
                                    }
                                    tracing::info!(
                                        "Loaded {} persisted target state records ({} expired and dropped)",
                                        target_state_loaded,
                                        target_state_expired
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to parse blocklist_target_state.json: {}, starting fresh",
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to read blocklist_target_state.json: {}, starting fresh",
                                e
                            );
                        }
                    }
                }
            }
        }

        let (persist_tx, shutdown_tx) = if config.persist_interval_secs > 0
            && persist_path.is_some()
        {
            let (tx, mut rx): (mpsc::Sender<PersistRequest>, mpsc::Receiver<PersistRequest>) =
                mpsc::channel(100);
            let (shutdown_tx, mut shutdown_rx): (mpsc::Sender<()>, mpsc::Receiver<()>) =
                mpsc::channel(1);
            let path = persist_path.clone().unwrap();
            let mesh_path = mesh_persist_path.clone();
            let max_entries_clone = max_entries;

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                    config.persist_interval_secs,
                ));
                let mut pending: Option<PersistRequest> = None;

                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            if let Some(req) = pending.take() {
                                Self::persist_to_disk(&path, req.entries, max_entries_clone).await;
                                if let Some(ref mp) = mesh_path {
                                    Self::persist_mesh_to_disk(mp, req.mesh_entries, max_entries_clone).await;
                                }
                            }
                        }
                        Some(req) = rx.recv() => {
                            pending = Some(req);
                        }
                        _ = shutdown_rx.recv() => {
                            if let Some(req) = pending.take() {
                                Self::persist_to_disk(&path, req.entries, max_entries_clone).await;
                                if let Some(ref mp) = mesh_path {
                                    Self::persist_mesh_to_disk(mp, req.mesh_entries, max_entries_clone).await;
                                }
                            }
                            tracing::info!("Block store persistence task shutting down");
                            break;
                        }
                    }
                }
            });

            (Some(tx), Some(shutdown_tx))
        } else {
            (None, None)
        };

        let store = Self {
            shards,
            mesh_shards,
            enabled,
            persist_path,
            target_state_path,
            config,
            total_entries: AtomicUsize::new(initial_count),
            total_mesh_entries: AtomicUsize::new(initial_mesh_count),
            persist_tx,
            shutdown_tx,
            mitigation_provider: arc_swap::ArcSwapOption::const_empty(),
            seen_events: RwLock::new(SeenEventCache::new()),
            target_state: RwLock::new(target_state_cache),
            event_log: RwLock::new(BlocklistEventLog::with_defaults()),
        };

        let migrated = store.migrate_legacy_sentinel_entries();
        if migrated > 0 {
            tracing::info!(
                "Auto-migrated {} legacy sentinel mesh-ID entries during init",
                migrated
            );
        }

        store
    }

    /// Set the mitigation provider for kernel-level blocking.
    pub fn set_mitigation_provider(&self, provider: Option<Arc<dyn MitigationProvider>>) {
        self.mitigation_provider
            .store(provider.map(|p| Arc::new(SizedMitigationProvider(p))));
    }

    /// Gracefully shutdown the block store, persisting any pending data.
    pub async fn shutdown(&self) {
        // Persist target state to disk before signaling shutdown.
        if self.config.target_state_persist {
            if let Some(ref path) = self.target_state_path {
                let entries: Vec<(BlocklistTargetKey, LastAppliedBlocklistEvent)> = {
                    let ts = self.target_state.read();
                    ts.entries
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                };
                let max_records = self.config.target_state_max_records;
                let ttl_secs = self.config.target_state_ttl_secs;
                Self::persist_target_state_to_disk(path, entries, max_records, ttl_secs).await;
            }
        }
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }
    }

    pub(crate) async fn persist_to_disk(
        path: &PathBuf,
        entries: Vec<(String, BlockEntry)>,
        max_entries: usize,
    ) {
        let entries_to_save: Vec<BlockEntry> = entries
            .into_iter()
            .filter(|(_, e)| !e.is_expired())
            .take(max_entries)
            .map(|(_, e)| e)
            .collect();

        match serde_json::to_string_pretty(&entries_to_save) {
            Ok(json) => {
                let temp_path = path.with_extension("tmp");
                match tokio::fs::write(&temp_path, json).await {
                    Ok(_) => {
                        if let Err(e) = tokio::fs::rename(&temp_path, path).await {
                            tracing::warn!("Failed to rename temp block file: {}", e);
                        } else {
                            Self::set_secure_permissions(path).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to write blocks to disk: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to serialize block entries: {}", e);
            }
        }
    }

    #[cfg(unix)]
    async fn set_secure_permissions(path: &PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = tokio::fs::metadata(path).await {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            if let Err(e) = tokio::fs::set_permissions(path, perms).await {
                tracing::debug!("Failed to set secure permissions on block file: {}", e);
            }
        }
    }

    #[cfg(not(unix))]
    async fn set_secure_permissions(_path: &PathBuf) {}

    pub(crate) async fn persist_mesh_to_disk(
        path: &PathBuf,
        entries: Vec<(String, MeshBlockEntry)>,
        max_entries: usize,
    ) {
        let entries_to_save: Vec<MeshBlockEntry> = entries
            .into_iter()
            .filter(|(_, e)| !e.is_expired())
            .take(max_entries)
            .map(|(_, e)| e)
            .collect();

        match serde_json::to_string_pretty(&entries_to_save) {
            Ok(json) => {
                let temp_path = path.with_extension("tmp");
                match tokio::fs::write(&temp_path, json).await {
                    Ok(_) => {
                        if let Err(e) = tokio::fs::rename(&temp_path, path).await {
                            tracing::warn!("Failed to rename temp mesh block file: {}", e);
                        } else {
                            Self::set_secure_permissions(path).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to write mesh blocks to disk: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to serialize mesh block entries: {}", e);
            }
        }
    }

    /// Persist the current target state cache to disk as `blocklist_target_state.json`.
    ///
    /// Uses atomic rename pattern consistent with blocks.json/mesh_blocks.json.
    /// Expired records are filtered out before writing.
    pub(crate) async fn persist_target_state_to_disk(
        path: &PathBuf,
        entries: Vec<(BlocklistTargetKey, LastAppliedBlocklistEvent)>,
        max_records: usize,
        ttl_secs: u64,
    ) {
        let now = synvoid_utils::safe_unix_timestamp();
        let records: Vec<BlocklistTargetStateRecord> = entries
            .into_iter()
            .take(max_records)
            .map(|(key, state)| BlocklistTargetStateRecord {
                target_kind: key.target_kind,
                site_scope: key.site_scope,
                identifier: key.identifier,
                last_operation: state.operation,
                timestamp: state.timestamp,
                version: state.version,
                event_id: state.event_id.clone(),
                source_node: state.source_node.clone(),
                provenance: state.provenance.clone(),
                recorded_at: now,
                expires_at: Some(now.saturating_add(ttl_secs)),
            })
            .collect();

        match serde_json::to_string_pretty(&records) {
            Ok(json) => {
                let temp_path = path.with_extension("tmp");
                match tokio::fs::write(&temp_path, &json).await {
                    Ok(_) => {
                        if let Err(e) = tokio::fs::rename(&temp_path, path).await {
                            tracing::warn!("Failed to rename temp target state file: {}", e);
                        } else {
                            Self::set_secure_permissions(path).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to write target state to disk: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to serialize target state records: {}", e);
            }
        }
    }

    /// Record target state for a direct block/unblock operation (admin API paths).
    ///
    /// This ensures that admin-initiated mutations also create persisted target
    /// state records, preventing stale replay from resurrecting or removing state
    /// after restart.
    #[allow(clippy::too_many_arguments)]
    pub fn record_target_state_from_direct_op(
        &self,
        target_kind: BlockTargetKind,
        site_scope: &str,
        identifier: &str,
        operation: BlocklistOperation,
        timestamp: u64,
        source_node: Option<String>,
        provenance: BlockProvenance,
    ) {
        if !self.config.target_state_persist {
            return;
        }
        let key = BlocklistTargetKey {
            target_kind,
            site_scope: site_scope.to_string(),
            identifier: identifier.to_string(),
        };
        let state = LastAppliedBlocklistEvent {
            timestamp,
            version: None,
            event_id: None,
            operation,
            source_node,
            provenance,
        };
        {
            let mut targets = self.target_state.write();
            targets.insert(key, state);
        }
        // Persist is triggered by trigger_persist() or shutdown(), not here,
        // to avoid races between multiple spawned persist tasks.
    }

    pub fn trigger_persist(&self) {
        if let Some(ref tx) = self.persist_tx {
            let entries: Vec<(String, BlockEntry)> = self
                .shards
                .iter()
                .flat_map(|s| {
                    s.read()
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<Vec<_>>()
                })
                .collect();
            let mesh_entries: Vec<(String, MeshBlockEntry)> = self
                .mesh_shards
                .iter()
                .flat_map(|s| {
                    s.read()
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<Vec<_>>()
                })
                .collect();
            match tx.try_send(PersistRequest {
                entries,
                mesh_entries,
            }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!("Block store persist channel full, skipping persist");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    tracing::error!("Block store persist channel closed");
                }
            }
        } else if let Some(ref path) = self.persist_path {
            let entries: Vec<(String, BlockEntry)> = self
                .shards
                .iter()
                .flat_map(|s| {
                    s.read()
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<Vec<_>>()
                })
                .collect();
            let mesh_entries: Vec<(String, MeshBlockEntry)> = self
                .mesh_shards
                .iter()
                .flat_map(|s| {
                    s.read()
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<Vec<_>>()
                })
                .collect();
            let path = path.clone();
            let mesh_path = self.persist_path.as_ref().map(|p| {
                p.parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join("mesh_blocks.json")
            });
            let max_entries = self.config.max_entries;
            tokio::spawn(async move {
                Self::persist_to_disk(&path, entries, max_entries).await;
                if let Some(mp) = mesh_path {
                    Self::persist_mesh_to_disk(&mp, mesh_entries, max_entries).await;
                }
            });
        }
    }

    /// Check if block store is enabled.
    ///
    /// # Returns
    /// `true` if block store is active and accepting new blocks
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Evict the least recently accessed entry from the store.
    ///
    /// Called when the store reaches capacity to make room for new entries.
    ///
    /// # Returns
    /// `true` if an entry was evicted, `false` if the store is empty
    fn evict_lru(&self) -> bool {
        let mut min_key: Option<String> = None;
        let mut min_shard_idx: Option<usize> = None;
        let mut min_last_access: u64 = u64::MAX;

        for (idx, shard) in self.shards.iter().enumerate() {
            let store = shard.read();
            if let Some((key, entry)) = store.iter().min_by_key(|(_, entry)| entry.last_access) {
                if entry.last_access < min_last_access {
                    min_last_access = entry.last_access;
                    min_key = Some(key.clone());
                    min_shard_idx = Some(idx);
                }
            }
        }

        if let Some((key, idx)) = min_key.zip(min_shard_idx) {
            self.shards[idx].write().remove(&key);
            let _ = self
                .total_entries
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
            tracing::debug!("Evicted LRU block entry: {}", key);
            true
        } else {
            false
        }
    }

    /// Block an IP address.
    ///
    /// Adds an IP to the blocklist with the given reason and duration.
    /// If the store is at capacity, the least recently accessed entry is
    /// evicted to make room (LRU eviction).
    ///
    /// # Arguments
    /// * `ip` - The IP address to block
    /// * `reason` - Reason for blocking (e.g., "rate_limit", "attack")
    /// * `ban_expire_seconds` - Duration of block in seconds (0 = permanent)
    /// * `site_scope` - Scope of block ("global" or site-specific)
    ///
    /// # Returns
    /// `true` if the IP was successfully blocked, `false` if store is disabled
    pub fn block_ip(
        &self,
        ip: IpAddr,
        reason: &str,
        ban_expire_seconds: u64,
        site_scope: &str,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        let entry = BlockEntry::new(
            ip,
            reason.to_string(),
            ban_expire_seconds,
            site_scope.to_string(),
        );
        let key = BlockEntry::key(site_scope, &ip);
        let idx = Self::shard_index(&key);

        let is_new = !self.shards[idx].read().contains_key(&key);

        if is_new {
            let max_entries = self.config.max_entries;
            let current = self.total_entries.load(Ordering::Relaxed);
            if current >= max_entries {
                tracing::info!(
                    "Block store at capacity ({} >= {}), evicting LRU entry",
                    current,
                    max_entries
                );
                if !self.evict_lru() {
                    tracing::warn!("Failed to evict LRU entry, cannot add new block");
                    return false;
                }
            }
        }

        self.shards[idx].write().insert(key, entry);

        if is_new {
            self.total_entries.fetch_add(1, Ordering::Relaxed);
        }

        tracing::info!("Blocked IP {} for {} (scope: {})", ip, reason, site_scope);

        if site_scope == "global" {
            if let Some(wrapper) = self.mitigation_provider.load().as_ref() {
                let duration = if ban_expire_seconds == 0 {
                    Duration::from_secs(365 * 24 * 3600) // 1 year for permanent
                } else {
                    Duration::from_secs(ban_expire_seconds)
                };
                if let Err(e) = wrapper.0.block_ip(ip, reason, duration) {
                    tracing::error!(%ip, %e, "Failed to block IP via mitigation provider");
                }
            }
        }

        self.trigger_persist();

        true
    }

    /// Block an IP address with provenance metadata.
    ///
    /// Same as [`block_ip`](Self::block_ip) but records provenance for auditability.
    pub fn block_ip_with_provenance(
        &self,
        ip: IpAddr,
        reason: &str,
        ban_expire_seconds: u64,
        site_scope: &str,
        provenance: BlockProvenance,
    ) -> bool {
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

        let is_new = !self.shards[idx].read().contains_key(&key);

        if is_new {
            let max_entries = self.config.max_entries;
            let current = self.total_entries.load(Ordering::Relaxed);
            if current >= max_entries {
                tracing::info!(
                    "Block store at capacity ({} >= {}), evicting LRU entry",
                    current,
                    max_entries
                );
                if !self.evict_lru() {
                    tracing::warn!("Failed to evict LRU entry, cannot add new block");
                    return false;
                }
            }
        }

        self.shards[idx].write().insert(key, entry);

        if is_new {
            self.total_entries.fetch_add(1, Ordering::Relaxed);
        }

        tracing::info!("Blocked IP {} for {} (scope: {})", ip, reason, site_scope);

        if site_scope == "global" {
            if let Some(wrapper) = self.mitigation_provider.load().as_ref() {
                let duration = if ban_expire_seconds == 0 {
                    Duration::from_secs(365 * 24 * 3600)
                } else {
                    Duration::from_secs(ban_expire_seconds)
                };
                if let Err(e) = wrapper.0.block_ip(ip, reason, duration) {
                    tracing::error!(%ip, %e, "Failed to block IP via mitigation provider");
                }
            }
        }

        self.trigger_persist();

        // Record target state so stale replay protection survives restarts.
        self.record_target_state_from_direct_op(
            BlockTargetKind::Ip,
            site_scope,
            &ip.to_string(),
            BlocklistOperation::Block,
            synvoid_utils::safe_unix_timestamp(),
            None,
            provenance,
        );

        true
    }

    /// Check if an IP is blocked.
    ///
    /// Checks both site-specific and global blocklists.
    /// Automatically removes expired entries.
    ///
    /// # Arguments
    /// * `ip` - The IP address to check
    /// * `site_scope` - Scope to check ("global" or site-specific)
    ///
    /// # Returns
    /// `Some(BlockEntry)` if blocked, `None` otherwise
    pub fn is_blocked(&self, ip: &IpAddr, site_scope: &str) -> Option<BlockEntry> {
        if !self.enabled {
            return None;
        }

        let key = BlockEntry::key(site_scope, ip);
        let idx = Self::shard_index(&key);

        let mut store = self.shards[idx].write();

        if let Some(entry) = store.get_mut(&key) {
            if !entry.is_expired() {
                entry.update_access();
                return Some(entry.clone());
            } else {
                store.remove(&key);
                let _ =
                    self.total_entries
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
            }
        }

        if site_scope != "global" {
            let global_key = BlockEntry::key("global", ip);
            let global_idx = Self::shard_index(&global_key);

            if let Some(entry) = self.shards[global_idx].write().get_mut(&global_key) {
                if !entry.is_expired() {
                    entry.update_access();
                    return Some(entry.clone());
                } else {
                    self.shards[global_idx].write().remove(&global_key);
                    let _ = self.total_entries.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |v| v.checked_sub(1),
                    );
                }
            }
        }

        None
    }

    /// Unblock an IP address.
    ///
    /// Removes an IP from both site-specific and global blocklists.
    ///
    /// # Arguments
    /// * `ip` - The IP address to unblock
    /// * `site_scope` - Scope to unblock from
    ///
    /// # Returns
    /// `true` if the IP was found and removed
    pub fn unblock_ip(&self, ip: &IpAddr, site_scope: &str) -> bool {
        if !self.enabled {
            return false;
        }

        let mut removed_count = 0u32;

        let key = BlockEntry::key(site_scope, ip);
        let idx = Self::shard_index(&key);
        if self.shards[idx].write().remove(&key).is_some() {
            removed_count += 1;
        }

        if site_scope != "global" {
            let global_key = BlockEntry::key("global", ip);
            let idx = Self::shard_index(&global_key);
            if self.shards[idx].write().remove(&global_key).is_some() {
                removed_count += 1;
            }
        }

        for _ in 0..removed_count {
            let _ = self
                .total_entries
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        if removed_count > 0 {
            self.trigger_persist();
        }

        // Always record target state for unblock, even if the target was already
        // missing. This prevents older block events from resurrecting the target
        // via stale replay after restart.
        self.record_target_state_from_direct_op(
            BlockTargetKind::Ip,
            site_scope,
            &ip.to_string(),
            BlocklistOperation::Unblock,
            synvoid_utils::safe_unix_timestamp(),
            None,
            BlockProvenance::default(),
        );

        removed_count > 0
    }

    /// Get block store statistics.
    ///
    /// # Returns
    /// `BlockStoreStats` containing entry counts and utilization
    pub fn get_stats(&self) -> BlockStoreStats {
        let total = self.total_entries.load(Ordering::Relaxed);
        let max = self.config.max_entries;

        let mut permanent_count = 0;

        for shard in &self.shards {
            let store = shard.read();
            for entry in store.values() {
                if entry.is_permanent() {
                    permanent_count += 1;
                }
            }
        }

        BlockStoreStats {
            total_entries: total,
            max_entries: max,
            permanent_count,
            expired_count: 0,
            utilization_percent: if max > 0 {
                (total as f64 / max as f64) * 100.0
            } else {
                0.0
            },
        }
    }

    pub fn get_all_entries(&self) -> Vec<BlockEntry> {
        let mut entries = Vec::new();
        for shard in &self.shards {
            entries.extend(shard.read().values().cloned());
        }
        entries
    }

    pub fn add_block(
        &self,
        ip: &str,
        reason: &str,
        ban_expire_seconds: u64,
        site_scope: &str,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
            let key = BlockEntry::key(site_scope, &ip_addr);
            let idx = Self::shard_index(&key);

            let mut store = self.shards[idx].write();
            let is_new = !store.contains_key(&key);

            if is_new && store.len() >= self.config.max_entries {
                tracing::warn!(
                    "BlockStore max entries reached, cannot add new block for {}",
                    ip
                );
                return false;
            }

            let entry = BlockEntry::new(
                ip_addr,
                reason.to_string(),
                ban_expire_seconds,
                site_scope.to_string(),
            );

            store.insert(key, entry);

            if is_new {
                self.total_entries.fetch_add(1, Ordering::Relaxed);
            }

            // Record target state so stale replay protection survives restarts.
            self.record_target_state_from_direct_op(
                BlockTargetKind::Ip,
                site_scope,
                ip,
                BlocklistOperation::Block,
                synvoid_utils::safe_unix_timestamp(),
                None,
                BlockProvenance::default(),
            );

            return true;
        }

        false
    }

    pub fn get_all_mesh_entries(&self) -> Vec<MeshBlockEntry> {
        let mut entries = Vec::new();
        for shard in &self.mesh_shards {
            entries.extend(shard.read().values().cloned());
        }
        entries
    }

    pub fn get_all_block_records(&self) -> Vec<BlockRecord> {
        let mut records: Vec<BlockRecord> = self
            .get_all_entries()
            .into_iter()
            .map(|e| BlockRecord {
                target_kind: BlockTargetKind::Ip,
                identifier: e.ip,
                reason: e.reason,
                blocked_at: e.blocked_at,
                ban_expire_seconds: e.ban_expire_seconds,
                site_scope: e.site_scope,
                access_count: e.access_count,
                last_access: e.last_access,
                provenance: e.provenance,
            })
            .chain(
                self.get_all_mesh_entries()
                    .into_iter()
                    .map(|e| BlockRecord {
                        target_kind: BlockTargetKind::MeshId,
                        identifier: e.mesh_id,
                        reason: e.reason,
                        blocked_at: e.blocked_at,
                        ban_expire_seconds: e.ban_expire_seconds,
                        site_scope: e.site_scope,
                        access_count: e.access_count,
                        last_access: e.last_access,
                        provenance: e.provenance,
                    }),
            )
            .collect();
        records.sort_by_key(|r| std::cmp::Reverse(r.blocked_at));
        records
    }

    pub fn block_mesh_id_with_provenance(
        &self,
        mesh_id: &str,
        reason: &str,
        ban_expire_seconds: u64,
        site_scope: &str,
        provenance: BlockProvenance,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        let now = synvoid_utils::safe_unix_timestamp();
        let entry = MeshBlockEntry::new(
            mesh_id.to_string(),
            reason.to_string(),
            ban_expire_seconds,
            site_scope.to_string(),
            now,
            provenance.clone(),
        );
        let key = MeshBlockEntry::key(site_scope, mesh_id);
        let idx = Self::shard_index(&key);

        let mut store = self.mesh_shards[idx].write();
        let is_new = !store.contains_key(&key);
        store.insert(key, entry);
        if is_new {
            self.total_mesh_entries.fetch_add(1, Ordering::Relaxed);
        }
        drop(store);

        tracing::info!(
            "Blocked mesh_id {} for {} (scope: {})",
            mesh_id,
            reason,
            site_scope
        );

        self.trigger_persist();

        // Record target state so stale replay protection survives restarts.
        self.record_target_state_from_direct_op(
            BlockTargetKind::MeshId,
            site_scope,
            mesh_id,
            BlocklistOperation::Block,
            now,
            None,
            provenance,
        );

        true
    }

    pub fn is_mesh_id_blocked(&self, mesh_id: &str, site_scope: &str) -> Option<MeshBlockEntry> {
        if !self.enabled {
            return None;
        }

        let key = MeshBlockEntry::key(site_scope, mesh_id);
        let idx = Self::shard_index(&key);

        let mut store = self.mesh_shards[idx].write();

        if let Some(entry) = store.get_mut(&key) {
            if !entry.is_expired() {
                let now = synvoid_utils::safe_unix_timestamp();
                entry.access_count += 1;
                entry.last_access = now;
                return Some(entry.clone());
            } else {
                store.remove(&key);
                let _ = self.total_mesh_entries.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| v.checked_sub(1),
                );
            }
        }

        if site_scope != "global" {
            let global_key = MeshBlockEntry::key("global", mesh_id);
            let global_idx = Self::shard_index(&global_key);

            if let Some(entry) = self.mesh_shards[global_idx].write().get_mut(&global_key) {
                if !entry.is_expired() {
                    let now = synvoid_utils::safe_unix_timestamp();
                    entry.access_count += 1;
                    entry.last_access = now;
                    return Some(entry.clone());
                } else {
                    self.mesh_shards[global_idx].write().remove(&global_key);
                    let _ = self.total_mesh_entries.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |v| v.checked_sub(1),
                    );
                }
            }
        }

        None
    }

    pub fn unblock_mesh_id(&self, mesh_id: &str, site_scope: &str) -> bool {
        if !self.enabled {
            return false;
        }

        let mut removed_count = 0u32;

        let key = MeshBlockEntry::key(site_scope, mesh_id);
        let idx = Self::shard_index(&key);
        if self.mesh_shards[idx].write().remove(&key).is_some() {
            removed_count += 1;
        }

        if site_scope != "global" {
            let global_key = MeshBlockEntry::key("global", mesh_id);
            let idx = Self::shard_index(&global_key);
            if self.mesh_shards[idx].write().remove(&global_key).is_some() {
                removed_count += 1;
            }
        }

        for _ in 0..removed_count {
            let _ =
                self.total_mesh_entries
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        if removed_count > 0 {
            self.trigger_persist();
        }

        // Always record target state for unblock, even if the target was already
        // missing. This prevents older block events from resurrecting the target
        // via stale replay after restart.
        self.record_target_state_from_direct_op(
            BlockTargetKind::MeshId,
            site_scope,
            mesh_id,
            BlocklistOperation::Unblock,
            synvoid_utils::safe_unix_timestamp(),
            None,
            BlockProvenance::default(),
        );

        removed_count > 0
    }

    pub fn get_mesh_stats(&self) -> usize {
        self.total_mesh_entries.load(Ordering::Relaxed)
    }

    /// Apply a blocklist event idempotently with last-writer-wins ordering.
    ///
    /// Dispatches based on `(operation, target_kind)`:
    /// - `(Block, Ip)` → `block_ip_with_provenance`
    /// - `(Unblock, Ip)` → `unblock_ip`
    /// - `(Block, MeshId)` → `block_mesh_id_with_provenance`
    /// - `(Unblock, MeshId)` → `unblock_mesh_id`
    ///
    /// # Ordering Rules
    ///
    /// 1. Invalid target → `InvalidTarget` (no state recorded).
    /// 2. Duplicate event ID → `NoopDuplicate` (no further processing).
    /// 3. Per-target stale check: if a newer event was already applied for this
    ///    target, reject the older event as `IgnoredStale`.
    /// 4. After successful or intentional no-op application, record both the
    ///    event ID (for dedup) and the per-target last-applied state (for
    ///    stale suppression).
    pub fn apply_blocklist_event(
        &self,
        event: &synvoid_core::block_store::BlocklistEvent,
    ) -> BlocklistApplyResult {
        if !self.enabled {
            return BlocklistApplyResult::StoreDisabled;
        }

        // Step 1: Validate target before any state mutation.
        match (&event.operation, &event.target_kind) {
            (BlocklistOperation::Block, BlockTargetKind::Ip)
            | (BlocklistOperation::Unblock, BlockTargetKind::Ip) => {
                if event.identifier.parse::<IpAddr>().is_err() {
                    return BlocklistApplyResult::InvalidTarget;
                }
            }
            (BlocklistOperation::Block, BlockTargetKind::MeshId)
            | (BlocklistOperation::Unblock, BlockTargetKind::MeshId) => {
                // Mesh IDs are always valid strings.
            }
        }

        // Step 2: Check duplicate event ID.
        if let Some(ref eid) = event.event_id {
            {
                let seen = self.seen_events.read();
                if seen.contains(eid) {
                    return BlocklistApplyResult::NoopDuplicate;
                }
            }
            // Not a duplicate — acquire write lock to insert.
            let mut seen = self.seen_events.write();
            // Double-check under write lock (race guard).
            if seen.contains(eid) {
                return BlocklistApplyResult::NoopDuplicate;
            }
            seen.insert(eid.clone());
        }

        // Step 3: Per-target stale suppression check.
        let target_key = BlocklistTargetKey {
            target_kind: event.target_kind,
            site_scope: event.site_scope.clone(),
            identifier: event.identifier.clone(),
        };
        let this_event = LastAppliedBlocklistEvent {
            timestamp: event.timestamp,
            version: event.version,
            event_id: event.event_id.clone(),
            operation: event.operation,
            source_node: event.source_node.clone(),
            provenance: event.provenance.clone(),
        };

        {
            let targets = self.target_state.read();
            if let Some(last) = targets.get(&target_key) {
                if this_event.is_newer_than(last) {
                    // This event is newer — proceed with application.
                } else {
                    // This event is stale or equal — reject.
                    return BlocklistApplyResult::IgnoredStale;
                }
            }
            // No previous state — this is the first event for this target.
        }

        // Step 4: Mutate BlockStore.
        let result = match (&event.operation, &event.target_kind) {
            (BlocklistOperation::Block, BlockTargetKind::Ip) => {
                let ip = event.identifier.parse::<IpAddr>().unwrap();
                let ban_secs = event.ttl_secs.unwrap_or(3600);
                let applied = self.block_ip_with_provenance(
                    ip,
                    event.reason.as_deref().unwrap_or("mesh_event"),
                    ban_secs,
                    &event.site_scope,
                    event.provenance.clone(),
                );
                if applied {
                    BlocklistApplyResult::Applied
                } else {
                    BlocklistApplyResult::StoreDisabled
                }
            }
            (BlocklistOperation::Unblock, BlockTargetKind::Ip) => {
                let ip = event.identifier.parse::<IpAddr>().unwrap();
                let removed = self.unblock_ip(&ip, &event.site_scope);
                if removed {
                    BlocklistApplyResult::Applied
                } else {
                    // Unblock of already-missing target: still record target state
                    // to prevent older block from resurrecting via stale replay.
                    BlocklistApplyResult::Applied
                }
            }
            (BlocklistOperation::Block, BlockTargetKind::MeshId) => {
                let ban_secs = event.ttl_secs.unwrap_or(3600);
                let applied = self.block_mesh_id_with_provenance(
                    &event.identifier,
                    event.reason.as_deref().unwrap_or("mesh_event"),
                    ban_secs,
                    &event.site_scope,
                    event.provenance.clone(),
                );
                if applied {
                    BlocklistApplyResult::Applied
                } else {
                    BlocklistApplyResult::StoreDisabled
                }
            }
            (BlocklistOperation::Unblock, BlockTargetKind::MeshId) => {
                let removed = self.unblock_mesh_id(&event.identifier, &event.site_scope);
                if removed {
                    BlocklistApplyResult::Applied
                } else {
                    // Unblock of already-missing target: still record target state.
                    BlocklistApplyResult::Applied
                }
            }
        };

        // Step 5: Record per-target last-applied state (only after successful application).
        if result == BlocklistApplyResult::Applied {
            let mut targets = self.target_state.write();
            targets.insert(target_key, this_event);
            // Target state persist is handled by trigger_persist() called from
            // the block/unblock methods in step 4, and by shutdown().
        }

        // Step 6: Record event in the event log for offline-peer catchup.
        if result == BlocklistApplyResult::Applied || result == BlocklistApplyResult::NoopDuplicate
        {
            let mut log = self.event_log.write();
            log.append(event.clone());
        }

        result
    }

    /// Query the blocklist event log for catchup replay.
    pub fn query_blocklist_catchup(&self, cursor: &BlocklistEventCursor) -> BlocklistCatchupResult {
        let log = self.event_log.read();
        log.query_since(cursor)
    }

    /// Append an event directly to the event log (for externally-originated
    /// events that should be available for catchup replay).
    pub fn record_blocklist_event_for_catchup(
        &self,
        event: &synvoid_core::block_store::BlocklistEvent,
    ) -> Option<u64> {
        let mut log = self.event_log.write();
        log.append(event.clone())
    }

    /// Return event log statistics for diagnostics.
    ///
    /// Returns `(event_count, oldest_timestamp, newest_timestamp, next_sequence)`.
    pub fn event_log_stats(&self) -> (usize, Option<u64>, Option<u64>, u64) {
        let log = self.event_log.read();
        (
            log.len(),
            log.oldest_timestamp(),
            log.newest_timestamp(),
            log.next_sequence(),
        )
    }

    pub fn migrate_legacy_sentinel_entries(&self) -> usize {
        let sentinel_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        let sentinel_str = sentinel_ip.to_string();
        #[allow(unused_mut)]
        let mut migrated = 0usize;

        for shard in &self.shards {
            let mut store = shard.write();
            let keys_to_migrate: Vec<String> = store
                .iter()
                .filter(|(_, e)| e.ip == sentinel_str && e.reason.starts_with("mesh_id_ban:"))
                .map(|(k, _)| k.clone())
                .collect();

            for key in keys_to_migrate {
                if let Some(entry) = store.remove(&key) {
                    if let Some(mesh_id) = extract_mesh_id_from_reason(&entry.reason) {
                        let mesh_key = MeshBlockEntry::key(&entry.site_scope, &mesh_id);
                        let idx = Self::shard_index(&mesh_key);
                        let mesh_entry = MeshBlockEntry {
                            mesh_id,
                            reason: entry.reason,
                            blocked_at: entry.blocked_at,
                            ban_expire_seconds: entry.ban_expire_seconds,
                            site_scope: entry.site_scope,
                            access_count: entry.access_count,
                            last_access: entry.last_access,
                            provenance: entry.provenance,
                        };
                        self.mesh_shards[idx].write().insert(mesh_key, mesh_entry);
                        let _ = self.total_entries.fetch_update(
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                            |v| v.checked_sub(1),
                        );
                        self.total_mesh_entries.fetch_add(1, Ordering::Relaxed);
                        migrated += 1;
                    }
                }
            }
        }

        if migrated > 0 {
            self.trigger_persist();
            tracing::info!(
                "Migrated {} legacy sentinel mesh-ID entries to first-class",
                migrated
            );
        }

        migrated
    }

    /// Export a paged snapshot of current blocklist state for peer convergence.
    ///
    /// This is a control-plane-only reconciliation payload. It produces current
    /// known local state from this peer, is not globally linearizable, and
    /// preserves provenance metadata.
    pub fn export_blocklist_snapshot(
        &self,
        options: &BlocklistSnapshotOptions,
        cursor: &BlocklistSnapshotCursor,
    ) -> BlocklistSnapshotChunk {
        let max_items = if options.max_items == 0 {
            500
        } else {
            options.max_items as usize
        };

        // Decode page token as offset index.
        let offset: usize = cursor
            .page_token
            .as_ref()
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(0);

        let mut all_items: Vec<SnapshotItem> = Vec::new();

        // Collect IP blocks if requested.
        if options.include_ip_blocks {
            for entry in self.get_all_entries() {
                if entry.is_expired() {
                    continue;
                }
                if let Some(ref scope) = options.site_scope {
                    if entry.site_scope != *scope {
                        continue;
                    }
                }
                all_items.push(SnapshotItem::Ip(BlockRecord {
                    target_kind: BlockTargetKind::Ip,
                    identifier: entry.ip,
                    reason: entry.reason,
                    blocked_at: entry.blocked_at,
                    ban_expire_seconds: entry.ban_expire_seconds,
                    site_scope: entry.site_scope,
                    access_count: entry.access_count,
                    last_access: entry.last_access,
                    provenance: entry.provenance,
                }));
            }
        }

        // Collect mesh blocks if requested.
        if options.include_mesh_id_blocks {
            for entry in self.get_all_mesh_entries() {
                if entry.is_expired() {
                    continue;
                }
                if let Some(ref scope) = options.site_scope {
                    if entry.site_scope != *scope {
                        continue;
                    }
                }
                all_items.push(SnapshotItem::Mesh(BlockRecord {
                    target_kind: BlockTargetKind::MeshId,
                    identifier: entry.mesh_id,
                    reason: entry.reason,
                    blocked_at: entry.blocked_at,
                    ban_expire_seconds: entry.ban_expire_seconds,
                    site_scope: entry.site_scope,
                    access_count: entry.access_count,
                    last_access: entry.last_access,
                    provenance: entry.provenance,
                }));
            }
        }

        // Sort for stable pagination: by (target_kind discriminant, site_scope, identifier).
        all_items.sort_by(|a, b| {
            let a_rec = a.record();
            let b_rec = b.record();
            let a_kind = match a_rec.target_kind {
                BlockTargetKind::Ip => 0u8,
                BlockTargetKind::MeshId => 1u8,
            };
            let b_kind = match b_rec.target_kind {
                BlockTargetKind::Ip => 0u8,
                BlockTargetKind::MeshId => 1u8,
            };
            a_kind
                .cmp(&b_kind)
                .then_with(|| a_rec.site_scope.cmp(&b_rec.site_scope))
                .then_with(|| a_rec.identifier.cmp(&b_rec.identifier))
        });

        let total = all_items.len();
        let page: Vec<SnapshotItem> = all_items.into_iter().skip(offset).take(max_items).collect();

        let has_more = offset + page.len() < total;
        let next_page_token = if has_more {
            Some((offset + page.len()).to_string())
        } else {
            None
        };

        let mut ip_blocks = Vec::new();
        let mut mesh_blocks = Vec::new();
        for item in &page {
            match item {
                SnapshotItem::Ip(rec) => ip_blocks.push(rec.clone()),
                SnapshotItem::Mesh(rec) => mesh_blocks.push(rec.clone()),
            }
        }

        // Collect target state records if requested.
        let target_state_records = if options.include_target_state {
            let ts = self.target_state.read();
            let entries = ts.export_entries();
            let now = synvoid_utils::safe_unix_timestamp();
            entries
                .into_iter()
                .filter_map(|(key, state)| {
                    // Filter by site scope if requested.
                    if let Some(ref scope) = options.site_scope {
                        if key.site_scope != *scope {
                            return None;
                        }
                    }
                    // Build a BlocklistTargetStateRecord, filtering expired.
                    let recorded_at = now;
                    let ttl = self.config.target_state_ttl_secs;
                    let expires_at = Some(now.saturating_add(ttl));
                    let record = BlocklistTargetStateRecord {
                        target_kind: key.target_kind,
                        site_scope: key.site_scope,
                        identifier: key.identifier,
                        last_operation: state.operation,
                        timestamp: state.timestamp,
                        version: state.version,
                        event_id: state.event_id,
                        source_node: state.source_node,
                        provenance: state.provenance,
                        recorded_at,
                        expires_at,
                    };
                    if record.is_expired() {
                        return None;
                    }
                    Some(record)
                })
                .collect()
        } else {
            Vec::new()
        };

        let snapshot_complete =
            !has_more && target_state_records.is_empty() || !options.include_target_state;

        BlocklistSnapshotChunk {
            ip_blocks,
            mesh_blocks,
            target_state_records,
            next_page_token,
            has_more,
            snapshot_complete,
            truncated_reason: None,
        }
    }

    /// Apply a snapshot chunk to converge local blocklist state.
    ///
    /// Snapshot apply is conservative merge semantics: it adds/updates current
    /// entries without deleting entries absent from the snapshot. It preserves
    /// provenance and respects per-target LWW ordering.
    pub fn apply_blocklist_snapshot(
        &self,
        snapshot: &BlocklistSnapshotChunk,
    ) -> BlocklistSnapshotApplyResult {
        if !self.enabled {
            return BlocklistSnapshotApplyResult::default();
        }

        let mut result = BlocklistSnapshotApplyResult::default();

        // Apply IP blocks from snapshot.
        for record in &snapshot.ip_blocks {
            // Validate IP.
            let ip = match record.identifier.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => {
                    result.invalid_records_ignored += 1;
                    continue;
                }
            };

            // Check expiry.
            if record.ban_expire_seconds > 0 {
                let now = synvoid_utils::safe_unix_timestamp();
                if now > record.blocked_at + record.ban_expire_seconds {
                    result.expired_records_ignored += 1;
                    continue;
                }
            }

            // Check target state for LWW: snapshot block must not override newer unblock tombstone.
            let target_key = BlocklistTargetKey {
                target_kind: BlockTargetKind::Ip,
                site_scope: record.site_scope.clone(),
                identifier: record.identifier.clone(),
            };
            {
                let targets = self.target_state.read();
                if let Some(last) = targets.get(&target_key) {
                    // If last operation was Unblock and it's newer, skip this block.
                    if last.operation == BlocklistOperation::Unblock {
                        let candidate = LastAppliedBlocklistEvent {
                            timestamp: record.blocked_at,
                            version: None,
                            event_id: None,
                            operation: BlocklistOperation::Block,
                            source_node: None,
                            provenance: record.provenance.clone(),
                        };
                        if !candidate.is_newer_than(last) {
                            result.stale_records_ignored += 1;
                            continue;
                        }
                    }
                }
            }

            // Check if entry already exists.
            let key = BlockEntry::key(&record.site_scope, &ip);
            let idx = Self::shard_index(&key);
            let exists = self.shards[idx].read().contains_key(&key);

            // Apply the block.
            let applied = self.block_ip_with_provenance(
                ip,
                &record.reason,
                record.ban_expire_seconds,
                &record.site_scope,
                record.provenance.clone(),
            );

            if applied {
                if exists {
                    result.ip_blocks_updated += 1;
                } else {
                    result.ip_blocks_applied += 1;
                }
            }
        }

        // Apply mesh blocks from snapshot.
        for record in &snapshot.mesh_blocks {
            // Validate mesh ID is non-empty.
            if record.identifier.is_empty() {
                result.invalid_records_ignored += 1;
                continue;
            }

            // Check expiry.
            if record.ban_expire_seconds > 0 {
                let now = synvoid_utils::safe_unix_timestamp();
                if now > record.blocked_at + record.ban_expire_seconds {
                    result.expired_records_ignored += 1;
                    continue;
                }
            }

            // Check target state for LWW.
            let target_key = BlocklistTargetKey {
                target_kind: BlockTargetKind::MeshId,
                site_scope: record.site_scope.clone(),
                identifier: record.identifier.clone(),
            };
            {
                let targets = self.target_state.read();
                if let Some(last) = targets.get(&target_key) {
                    if last.operation == BlocklistOperation::Unblock {
                        let candidate = LastAppliedBlocklistEvent {
                            timestamp: record.blocked_at,
                            version: None,
                            event_id: None,
                            operation: BlocklistOperation::Block,
                            source_node: None,
                            provenance: record.provenance.clone(),
                        };
                        if !candidate.is_newer_than(last) {
                            result.stale_records_ignored += 1;
                            continue;
                        }
                    }
                }
            }

            // Check if entry already exists.
            let key = MeshBlockEntry::key(&record.site_scope, &record.identifier);
            let idx = Self::shard_index(&key);
            let exists = self.mesh_shards[idx].read().contains_key(&key);

            // Apply the block.
            let applied = self.block_mesh_id_with_provenance(
                &record.identifier,
                &record.reason,
                record.ban_expire_seconds,
                &record.site_scope,
                record.provenance.clone(),
            );

            if applied {
                if exists {
                    result.mesh_blocks_updated += 1;
                } else {
                    result.mesh_blocks_applied += 1;
                }
            }
        }

        // Apply target state records from snapshot.
        for ts_record in &snapshot.target_state_records {
            // Check expiry.
            if ts_record.is_expired() {
                result.expired_records_ignored += 1;
                continue;
            }

            let target_key = BlocklistTargetKey {
                target_kind: ts_record.target_kind,
                site_scope: ts_record.site_scope.clone(),
                identifier: ts_record.identifier.clone(),
            };

            let this_event = LastAppliedBlocklistEvent {
                timestamp: ts_record.timestamp,
                version: ts_record.version,
                event_id: ts_record.event_id.clone(),
                operation: ts_record.last_operation,
                source_node: ts_record.source_node.clone(),
                provenance: ts_record.provenance.clone(),
            };

            // LWW: only apply if this record is newer than local state.
            {
                let targets = self.target_state.read();
                if let Some(last) = targets.get(&target_key) {
                    if !this_event.is_newer_than(last) {
                        result.stale_records_ignored += 1;
                        continue;
                    }
                }
            }

            // Insert into target state cache.
            let mut targets = self.target_state.write();
            targets.insert(target_key, this_event);
            result.target_state_records_applied += 1;
        }

        tracing::info!(
            "Blocklist snapshot applied: ip_applied={}, ip_updated={}, mesh_applied={}, mesh_updated={}, target_state={}, stale_ignored={}, invalid_ignored={}, expired_ignored={}",
            result.ip_blocks_applied,
            result.ip_blocks_updated,
            result.mesh_blocks_applied,
            result.mesh_blocks_updated,
            result.target_state_records_applied,
            result.stale_records_ignored,
            result.invalid_records_ignored,
            result.expired_records_ignored,
        );

        result
    }
}

/// Internal enum for snapshot export iteration.
enum SnapshotItem {
    Ip(BlockRecord),
    Mesh(BlockRecord),
}

impl SnapshotItem {
    fn record(&self) -> &BlockRecord {
        match self {
            SnapshotItem::Ip(r) | SnapshotItem::Mesh(r) => r,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlockStoreStats {
    pub total_entries: usize,
    pub max_entries: usize,
    pub permanent_count: usize,
    pub expired_count: usize,
    pub utilization_percent: f64,
}

#[cfg(feature = "mesh")]
impl synvoid_mesh::stubs::block_store::BlockStoreApi for BlockStore {
    fn block_ip(
        &self,
        ip: std::net::IpAddr,
        reason: &str,
        ttl_secs: u64,
        site_scope: &str,
    ) -> bool {
        self.block_ip(ip, reason, ttl_secs, site_scope)
    }

    fn block_ip_with_provenance(
        &self,
        ip: std::net::IpAddr,
        reason: &str,
        ttl_secs: u64,
        site_scope: &str,
        provenance: synvoid_mesh::stubs::block_store::BlockProvenance,
    ) -> bool {
        self.block_ip_with_provenance(ip, reason, ttl_secs, site_scope, provenance)
    }

    fn is_blocked(&self, ip: &std::net::IpAddr, site_scope: &str) -> bool {
        self.is_blocked(ip, site_scope).is_some()
    }

    fn unblock_ip(&self, ip: &std::net::IpAddr, scope: &str) -> bool {
        self.unblock_ip(ip, scope)
    }

    fn get_all_entries(&self) -> Vec<synvoid_mesh::stubs::block_store::BlockEntry> {
        self.get_all_entries()
            .into_iter()
            .map(|e| synvoid_mesh::stubs::block_store::BlockEntry {
                ip: e.ip,
                reason: e.reason,
                blocked_at: e.blocked_at,
                ban_expire_seconds: e.ban_expire_seconds,
                site_scope: e.site_scope,
                access_count: e.access_count,
                last_access: e.last_access,
                provenance_kind: format!("{:?}", e.provenance.kind),
                provenance_source: e.provenance.source.clone(),
            })
            .collect()
    }

    fn block_mesh_id_with_provenance(
        &self,
        mesh_id: &str,
        reason: &str,
        ttl_secs: u64,
        site_scope: &str,
        provenance: synvoid_mesh::stubs::block_store::BlockProvenance,
    ) -> bool {
        self.block_mesh_id_with_provenance(mesh_id, reason, ttl_secs, site_scope, provenance)
    }

    fn unblock_mesh_id(&self, mesh_id: &str, site_scope: &str) -> bool {
        self.unblock_mesh_id(mesh_id, site_scope)
    }

    fn is_mesh_id_blocked(&self, mesh_id: &str, site_scope: &str) -> bool {
        self.is_mesh_id_blocked(mesh_id, site_scope).is_some()
    }

    fn get_all_mesh_entries(&self) -> Vec<synvoid_mesh::stubs::block_store::MeshBlockEntry> {
        self.get_all_mesh_entries()
            .into_iter()
            .map(|e| synvoid_mesh::stubs::block_store::MeshBlockEntry {
                mesh_id: e.mesh_id,
                reason: e.reason,
                blocked_at: e.blocked_at,
                ban_expire_seconds: e.ban_expire_seconds,
                site_scope: e.site_scope,
                access_count: e.access_count,
                last_access: e.last_access,
                provenance_kind: format!("{:?}", e.provenance.kind),
                provenance_source: e.provenance.source.clone(),
            })
            .collect()
    }

    fn get_all_block_records(&self) -> Vec<synvoid_core::block_store::BlockRecord> {
        self.get_all_block_records()
    }

    fn apply_blocklist_event(
        &self,
        event: &synvoid_core::block_store::BlocklistEvent,
    ) -> synvoid_mesh::stubs::block_store::BlocklistApplyResult {
        match self.apply_blocklist_event(event) {
            BlocklistApplyResult::Applied => {
                synvoid_mesh::stubs::block_store::BlocklistApplyResult::Applied
            }
            BlocklistApplyResult::NoopDuplicate => {
                synvoid_mesh::stubs::block_store::BlocklistApplyResult::NoopDuplicate
            }
            BlocklistApplyResult::IgnoredStale => {
                synvoid_mesh::stubs::block_store::BlocklistApplyResult::IgnoredStale
            }
            BlocklistApplyResult::InvalidTarget => {
                synvoid_mesh::stubs::block_store::BlocklistApplyResult::InvalidTarget
            }
            BlocklistApplyResult::StoreDisabled => {
                synvoid_mesh::stubs::block_store::BlocklistApplyResult::StoreDisabled
            }
        }
    }

    fn query_blocklist_catchup(
        &self,
        cursor: &synvoid_mesh::stubs::block_store::BlocklistEventCursor,
    ) -> synvoid_mesh::stubs::block_store::BlocklistCatchupResult {
        let real_cursor = BlocklistEventCursor {
            since_sequence: cursor.since_sequence,
            max_events: cursor.max_events,
        };
        let result = self.query_blocklist_catchup(&real_cursor);
        synvoid_mesh::stubs::block_store::BlocklistCatchupResult {
            events: result.events,
            history_complete: result.history_complete,
            latest_sequence: result.latest_sequence,
            latest_timestamp: result.latest_timestamp,
            snapshot_required: result.snapshot_required,
        }
    }

    fn record_blocklist_event_for_catchup(
        &self,
        event: &synvoid_core::block_store::BlocklistEvent,
    ) -> Option<u64> {
        self.record_blocklist_event_for_catchup(event)
    }

    fn event_log_stats(&self) -> (usize, Option<u64>, Option<u64>, u64) {
        self.event_log_stats()
    }

    fn export_blocklist_snapshot(
        &self,
        options: &synvoid_mesh::stubs::block_store::BlocklistSnapshotOptions,
        cursor: &synvoid_mesh::stubs::block_store::BlocklistSnapshotCursor,
    ) -> synvoid_mesh::stubs::block_store::BlocklistSnapshotChunk {
        let real_options = BlocklistSnapshotOptions {
            include_ip_blocks: options.include_ip_blocks,
            include_mesh_id_blocks: options.include_mesh_id_blocks,
            include_target_state: options.include_target_state,
            site_scope: options.site_scope.clone(),
            max_items: options.max_items,
        };
        let real_cursor = BlocklistSnapshotCursor {
            page_token: cursor.page_token.clone(),
        };
        let result = self.export_blocklist_snapshot(&real_options, &real_cursor);
        synvoid_mesh::stubs::block_store::BlocklistSnapshotChunk {
            ip_blocks: result.ip_blocks,
            mesh_blocks: result.mesh_blocks,
            target_state_records: result.target_state_records,
            next_page_token: result.next_page_token,
            has_more: result.has_more,
            snapshot_complete: result.snapshot_complete,
            truncated_reason: result.truncated_reason,
        }
    }

    fn apply_blocklist_snapshot(
        &self,
        snapshot: &synvoid_mesh::stubs::block_store::BlocklistSnapshotChunk,
    ) -> synvoid_mesh::stubs::block_store::BlocklistSnapshotApplyResult {
        let real_snapshot = BlocklistSnapshotChunk {
            ip_blocks: snapshot.ip_blocks.clone(),
            mesh_blocks: snapshot.mesh_blocks.clone(),
            target_state_records: snapshot.target_state_records.clone(),
            next_page_token: snapshot.next_page_token.clone(),
            has_more: snapshot.has_more,
            snapshot_complete: snapshot.snapshot_complete,
            truncated_reason: snapshot.truncated_reason.clone(),
        };
        let result = self.apply_blocklist_snapshot(&real_snapshot);
        synvoid_mesh::stubs::block_store::BlocklistSnapshotApplyResult {
            ip_blocks_applied: result.ip_blocks_applied,
            ip_blocks_updated: result.ip_blocks_updated,
            mesh_blocks_applied: result.mesh_blocks_applied,
            mesh_blocks_updated: result.mesh_blocks_updated,
            target_state_records_applied: result.target_state_records_applied,
            stale_records_ignored: result.stale_records_ignored,
            invalid_records_ignored: result.invalid_records_ignored,
            expired_records_ignored: result.expired_records_ignored,
        }
    }
}

fn extract_mesh_id_from_reason(reason: &str) -> Option<String> {
    let prefix = "mesh_id_ban:";
    if let Some(rest) = reason.strip_prefix(prefix) {
        if let Some(colon_pos) = rest.find(':') {
            return Some(rest[..colon_pos].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::IpAddr;
    use tempfile::TempDir;

    fn default_config() -> DenyListLimitsConfig {
        DenyListLimitsConfig {
            max_entries: 1000,
            persist_interval_secs: 0,
            target_state_persist: false,
            target_state_max_records: 100_000,
            target_state_ttl_secs: 604_800,
        }
    }

    proptest::proptest! {
        #[test]
        fn test_block_entry_key(site_scope: String, ip: String) {
            let ip = ip.parse::<IpAddr>().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let key = BlockEntry::key(&site_scope, &ip);
            prop_assert!(key.starts_with("block:"));
            prop_assert!(key.contains(&site_scope));
            prop_assert!(key.contains(&ip.to_string()));
        }

        #[test]
        fn test_block_entry_new_creates_valid_entry(ip: String, reason: String, ban_expire: u64, scope: String) {
            let ip = ip.parse::<IpAddr>().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let entry = BlockEntry::new(ip, reason.clone(), ban_expire, scope.clone());
            prop_assert_eq!(entry.ip, ip.to_string());
            prop_assert_eq!(entry.reason, reason);
            prop_assert_eq!(entry.ban_expire_seconds, ban_expire);
            prop_assert_eq!(entry.site_scope, scope);
            prop_assert_eq!(entry.access_count, 0);
        }

        #[test]
        fn test_block_entry_is_permanent(ban_expire: u64) {
            let ip: IpAddr = "127.0.0.1".parse().unwrap();
            let entry = BlockEntry::new(ip, "test".to_string(), ban_expire, "global".to_string());
            prop_assert_eq!(entry.is_permanent(), ban_expire == 0);
        }

        #[test]
        fn test_block_entry_update_access(access_count: u64) {
            let ip: IpAddr = "127.0.0.1".parse().unwrap();
            let mut entry = BlockEntry::new(ip, "test".to_string(), 0, "global".to_string());
            entry.access_count = access_count;
            let prev_access = entry.last_access;
            entry.update_access();
            prop_assert_eq!(entry.access_count, access_count + 1);
            prop_assert!(entry.last_access >= prev_access);
        }

        #[test]
        fn test_block_entry_is_expired_for_permanent(ban_expire: u64) {
            if ban_expire == 0 {
                let ip: IpAddr = "127.0.0.1".parse().unwrap();
                let entry = BlockEntry::new(ip, "test".to_string(), 0, "global".to_string());
                prop_assert!(!entry.is_expired());
            }
        }
    }

    #[tokio::test]
    async fn test_block_store_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(false, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!store.is_enabled());
        assert!(!store.block_ip(ip, "test", 3600, "global"));
        assert!(store.is_blocked(&ip, "global").is_none());
    }

    #[tokio::test]
    async fn test_block_store_block_and_check() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(store.block_ip(ip, "test_reason", 3600, "global"));

        let blocked = store.is_blocked(&ip, "global");
        assert!(blocked.is_some());
        let entry = blocked.unwrap();
        assert_eq!(entry.reason, "test_reason");
        assert!(!entry.is_permanent());
    }

    #[tokio::test]
    async fn test_block_store_unblock() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(store.block_ip(ip, "test", 3600, "global"));
        assert!(store.is_blocked(&ip, "global").is_some());

        store.unblock_ip(&ip, "global");
        assert!(store.is_blocked(&ip, "global").is_none());
    }

    #[tokio::test]
    async fn test_block_store_permanent_block() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(store.block_ip(ip, "permanent", 0, "global"));

        let blocked = store.is_blocked(&ip, "global");
        assert!(blocked.is_some());
        assert!(blocked.unwrap().is_permanent());
    }

    #[tokio::test]
    async fn test_block_store_stats() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        store.block_ip(ip1, "test", 0, "global");
        store.block_ip(ip2, "test", 3600, "global");

        let stats = store.get_stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.permanent_count, 1);
        assert_eq!(stats.max_entries, 1000);
    }

    #[tokio::test]
    async fn test_block_store_site_specific() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(store.block_ip(ip, "site_a_only", 3600, "site_a"));
        assert!(store.is_blocked(&ip, "site_a").is_some());
        assert!(store.is_blocked(&ip, "site_b").is_none());
        assert!(store.is_blocked(&ip, "global").is_none());
    }

    #[tokio::test]
    async fn test_block_store_global_fallback() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(store.block_ip(ip, "global_block", 3600, "global"));
        assert!(store.is_blocked(&ip, "site_a").is_some());
    }

    #[tokio::test]
    async fn test_block_store_add_block() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let result = store.add_block("192.168.1.100", "rate_limit", 1800, "global");
        assert!(result);

        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let blocked = store.is_blocked(&ip, "global");
        assert!(blocked.is_some());
        assert_eq!(blocked.unwrap().reason, "rate_limit");
    }

    #[tokio::test]
    async fn test_block_store_add_block_invalid_ip() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let result = store.add_block("not_an_ip", "test", 3600, "global");
        assert!(!result);
    }

    #[tokio::test]
    async fn test_block_store_get_all_entries() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.add_block("10.0.0.1", "test", 0, "global");
        store.add_block("10.0.0.2", "test", 0, "global");

        let entries = store.get_all_entries();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn test_block_store_shutdown() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(
            true,
            Some(temp_dir.path().to_path_buf()),
            DenyListLimitsConfig {
                max_entries: 1000,
                persist_interval_secs: 0,
                target_state_persist: false,
                target_state_max_records: 100_000,
                target_state_ttl_secs: 604_800,
            },
        );

        store.add_block("10.0.0.1", "test", 0, "global");
        store.shutdown().await;
    }

    #[tokio::test]
    async fn test_block_store_ipv6() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(store.block_ip(ip, "ipv6_test", 3600, "global"));
        assert!(store.is_blocked(&ip, "global").is_some());
    }

    #[tokio::test]
    async fn test_block_store_lru_eviction() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(
            true,
            Some(temp_dir.path().to_path_buf()),
            DenyListLimitsConfig {
                max_entries: 2,
                persist_interval_secs: 0,
                target_state_persist: false,
                target_state_max_records: 100_000,
                target_state_ttl_secs: 604_800,
            },
        );

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();

        // Fill to capacity with distinct entries
        assert!(store.block_ip(ip1, "test", 3600, "global"));
        assert!(store.block_ip(ip2, "test", 3600, "global"));

        // Verify both are blocked
        assert!(store.is_blocked(&ip1, "global").is_some());
        assert!(store.is_blocked(&ip2, "global").is_some());

        // Adding a third entry should evict ONE entry (either ip1 or ip2)
        // The one evicted is the LRU based on last_access ordering
        assert!(store.block_ip(ip3, "test", 3600, "global"));

        // Exactly 2 entries should remain
        let stats = store.get_stats();
        assert_eq!(stats.total_entries, 2);

        // One of ip1/ip2 should be evicted, ip3 should remain
        let ip1_blocked = store.is_blocked(&ip1, "global").is_some();
        let ip2_blocked = store.is_blocked(&ip2, "global").is_some();
        let ip3_blocked = store.is_blocked(&ip3, "global").is_some();

        assert!(ip3_blocked, "ip3 should always remain");
        assert!(
            ip1_blocked || ip2_blocked,
            "at least one of ip1/ip2 should remain"
        );

        // The one that wasn't accessed via is_blocked should be evicted
        // (since is_blocked updates last_access and makes the other more recently used)
        // But due to second-level timestamp precision, this is not guaranteed
        // So we just verify exactly 2 entries remain and ip3 is one of them
    }

    #[test]
    fn test_block_entry_deserialize_without_provenance() {
        let json = r#"{
            "ip": "10.0.0.1",
            "reason": "old_entry",
            "blocked_at": 1700000000,
            "ban_expire_seconds": 3600,
            "site_scope": "global",
            "access_count": 5,
            "last_access": 1700000001
        }"#;
        let entry: BlockEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.ip, "10.0.0.1");
        assert_eq!(entry.reason, "old_entry");
        assert_eq!(entry.provenance.kind, BlockProvenanceKind::LegacyUnknown);
        assert!(entry.provenance.source.is_none());
    }

    #[test]
    fn test_block_entry_new_defaults_to_legacy_unknown_provenance() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let entry = BlockEntry::new(ip, "test".to_string(), 3600, "global".to_string());
        assert_eq!(entry.provenance.kind, BlockProvenanceKind::LegacyUnknown);
        assert!(entry.provenance.source.is_none());
    }

    #[tokio::test]
    async fn test_block_ip_with_provenance() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.99".parse().unwrap();
        let provenance = BlockProvenance {
            kind: BlockProvenanceKind::MeshThreatIntelPolicyGated,
            source: Some("mesh:node-1".to_string()),
        };
        assert!(store.block_ip_with_provenance(ip, "mesh_threat", 3600, "global", provenance,));

        let entry = store.is_blocked(&ip, "global").unwrap();
        assert_eq!(
            entry.provenance.kind,
            BlockProvenanceKind::MeshThreatIntelPolicyGated
        );
        assert_eq!(entry.provenance.source.as_deref(), Some("mesh:node-1"));
    }

    #[tokio::test]
    async fn test_admin_manual_provenance() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let result = store.block_ip_with_provenance(
            ip,
            "admin_ban",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_ip".to_string()),
            },
        );
        assert!(result);
        let entries = store.get_all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].provenance.kind, BlockProvenanceKind::AdminManual);
        assert_eq!(
            entries[0].provenance.source.as_deref(),
            Some("admin_ban_ip")
        );
    }

    #[tokio::test]
    async fn test_supervisor_manual_provenance() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        let result = store.block_ip_with_provenance(
            ip,
            "grpc_block",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::SupervisorManual,
                source: Some("grpc_block_ip".to_string()),
            },
        );
        assert!(result);
        let entries = store.get_all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].provenance.kind,
            BlockProvenanceKind::SupervisorManual
        );
        assert_eq!(
            entries[0].provenance.source.as_deref(),
            Some("grpc_block_ip")
        );
    }

    #[tokio::test]
    async fn test_supervisor_sync_provenance() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.3".parse().unwrap();
        let result = store.block_ip_with_provenance(
            ip,
            "blocklist_sync",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::SupervisorSync,
                source: Some("blocklist_update".to_string()),
            },
        );
        assert!(result);
        let entries = store.get_all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].provenance.kind,
            BlockProvenanceKind::SupervisorSync
        );
        assert_eq!(
            entries[0].provenance.source.as_deref(),
            Some("blocklist_update")
        );
    }

    #[tokio::test]
    async fn test_legacy_block_ip_defaults_to_legacy_unknown() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.4".parse().unwrap();
        let result = store.block_ip(ip, "legacy_call", 3600, "global");
        assert!(result);
        let entries = store.get_all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].provenance.kind,
            BlockProvenanceKind::LegacyUnknown
        );
        assert!(entries[0].provenance.source.is_none());
    }

    #[tokio::test]
    async fn test_provenance_survives_serialization_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        store.block_ip_with_provenance(
            ip,
            "roundtrip_test",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("test_source".to_string()),
            },
        );
        // Trigger persist and reload
        store.trigger_persist();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let store2 = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());
        let entries = store2.get_all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].provenance.kind, BlockProvenanceKind::AdminManual);
        assert_eq!(entries[0].provenance.source.as_deref(), Some("test_source"));
    }

    #[tokio::test]
    async fn test_unblock_ip_returns_true_when_entry_exists() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        store.block_ip(ip, "test", 3600, "global");
        assert!(store.is_blocked(&ip, "global").is_some());
        assert!(store.unblock_ip(&ip, "global"));
        assert!(store.is_blocked(&ip, "global").is_none());
    }

    #[tokio::test]
    async fn test_unblock_ip_returns_false_when_no_entry() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.99".parse().unwrap();
        assert!(!store.unblock_ip(&ip, "global"));
    }

    #[tokio::test]
    async fn test_unblock_ip_removes_from_both_scopes() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        store.block_ip(ip, "test", 3600, "global");
        assert!(store.is_blocked(&ip, "global").is_some());
        assert!(store.is_blocked(&ip, "site_a").is_some());

        assert!(store.unblock_ip(&ip, "site_a"));
        assert!(store.is_blocked(&ip, "global").is_none());
        assert!(store.is_blocked(&ip, "site_a").is_none());
    }

    #[tokio::test]
    async fn test_sentinel_ip_mesh_id_ban_and_unban() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let sentinel: IpAddr = "0.0.0.0".parse().unwrap();
        let reason = "mesh_id_ban:test-mesh-1:manual_admin_ban";

        store.block_ip_with_provenance(
            sentinel,
            reason,
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_mesh_id".to_string()),
            },
        );

        let entry = store.is_blocked(&sentinel, "global");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.reason, reason);
        assert_eq!(entry.provenance.kind, BlockProvenanceKind::AdminManual);

        assert!(store.unblock_ip(&sentinel, "global"));
        assert!(store.is_blocked(&sentinel, "global").is_none());
    }

    #[tokio::test]
    async fn test_sentinel_ip_mesh_id_unban_returns_false_when_missing() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let sentinel: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(!store.unblock_ip(&sentinel, "global"));
    }

    #[tokio::test]
    async fn test_multiple_mesh_id_bans_overwrite_sentinel() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let sentinel: IpAddr = "0.0.0.0".parse().unwrap();

        store.block_ip_with_provenance(
            sentinel,
            "mesh_id_ban:mesh-1:reason1",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_mesh_id".to_string()),
            },
        );

        store.block_ip_with_provenance(
            sentinel,
            "mesh_id_ban:mesh-2:reason2",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_mesh_id".to_string()),
            },
        );

        let entries = store.get_all_entries();
        let sentinel_entries: Vec<_> = entries.iter().filter(|e| e.ip == "0.0.0.0").collect();
        assert_eq!(sentinel_entries.len(), 1);
        assert_eq!(sentinel_entries[0].reason, "mesh_id_ban:mesh-2:reason2");
    }

    // Phase 1 regression: IP counter must not drift on overwrite

    #[tokio::test]
    async fn test_block_ip_counter_no_drift_on_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(store.block_ip(ip, "first", 3600, "global"));
        assert_eq!(store.get_stats().total_entries, 1);

        assert!(store.block_ip(ip, "second", 3600, "global"));
        assert_eq!(store.get_stats().total_entries, 1);

        let entries = store.get_all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason, "second");
    }

    #[tokio::test]
    async fn test_block_ip_with_provenance_counter_no_drift_on_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "192.168.1.101".parse().unwrap();
        let prov = BlockProvenance {
            kind: BlockProvenanceKind::AdminManual,
            source: Some("test".to_string()),
        };

        assert!(store.block_ip_with_provenance(ip, "first", 3600, "global", prov.clone()));
        assert_eq!(store.get_stats().total_entries, 1);

        assert!(store.block_ip_with_provenance(ip, "second", 3600, "global", prov));
        assert_eq!(store.get_stats().total_entries, 1);

        let entries = store.get_all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason, "second");
    }

    #[tokio::test]
    async fn test_add_block_counter_no_drift_on_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        assert!(store.add_block("192.168.1.102", "first", 3600, "global"));
        assert_eq!(store.get_stats().total_entries, 1);

        assert!(store.add_block("192.168.1.102", "second", 3600, "global"));
        assert_eq!(store.get_stats().total_entries, 1);

        let entries = store.get_all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason, "second");
    }

    #[tokio::test]
    async fn test_block_ip_overwrite_does_not_trigger_eviction() {
        let config = DenyListLimitsConfig {
            max_entries: 2,
            persist_interval_secs: 0,
            target_state_persist: false,
            target_state_max_records: 100_000,
            target_state_ttl_secs: 604_800,
        };
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        store.block_ip(ip1, "reason1", 3600, "global");
        store.block_ip(ip2, "reason2", 3600, "global");
        assert_eq!(store.get_stats().total_entries, 2);

        store.block_ip(ip1, "updated", 3600, "global");
        assert_eq!(store.get_stats().total_entries, 2);

        let entries = store.get_all_entries();
        assert_eq!(entries.len(), 2);
        let ip1_entry = entries.iter().find(|e| e.ip == "10.0.0.1").unwrap();
        assert_eq!(ip1_entry.reason, "updated");
    }

    // Phase 2: Mesh-ID counter semantics

    #[tokio::test]
    async fn test_mesh_id_counter_new_entry() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        assert!(store.block_mesh_id_with_provenance(
            "mesh-1",
            "reason",
            3600,
            "global",
            BlockProvenance::default(),
        ));
        assert_eq!(store.get_mesh_stats(), 1);
    }

    #[tokio::test]
    async fn test_mesh_id_counter_overwrite_no_increment() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        assert!(store.block_mesh_id_with_provenance(
            "mesh-1",
            "first",
            3600,
            "global",
            BlockProvenance::default(),
        ));
        assert_eq!(store.get_mesh_stats(), 1);

        assert!(store.block_mesh_id_with_provenance(
            "mesh-1",
            "second",
            3600,
            "global",
            BlockProvenance::default(),
        ));
        assert_eq!(store.get_mesh_stats(), 1);

        let entries = store.get_all_mesh_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason, "second");
    }

    #[tokio::test]
    async fn test_mesh_id_counter_unblock_existing() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.block_mesh_id_with_provenance(
            "mesh-1",
            "reason",
            3600,
            "global",
            BlockProvenance::default(),
        );
        assert_eq!(store.get_mesh_stats(), 1);

        assert!(store.unblock_mesh_id("mesh-1", "global"));
        assert_eq!(store.get_mesh_stats(), 0);
    }

    #[tokio::test]
    async fn test_mesh_id_counter_unblock_missing_no_decrement() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        assert_eq!(store.get_mesh_stats(), 0);
        assert!(!store.unblock_mesh_id("nonexistent", "global"));
        assert_eq!(store.get_mesh_stats(), 0);
    }

    #[tokio::test]
    async fn test_multiple_concurrent_mesh_ids() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.block_mesh_id_with_provenance(
            "mesh-a",
            "reason-a",
            3600,
            "global",
            BlockProvenance::default(),
        );
        store.block_mesh_id_with_provenance(
            "mesh-b",
            "reason-b",
            3600,
            "global",
            BlockProvenance::default(),
        );
        store.block_mesh_id_with_provenance(
            "mesh-c",
            "reason-c",
            3600,
            "global",
            BlockProvenance::default(),
        );
        assert_eq!(store.get_mesh_stats(), 3);

        assert!(store.unblock_mesh_id("mesh-b", "global"));
        assert_eq!(store.get_mesh_stats(), 2);

        let entries = store.get_all_mesh_entries();
        let ids: Vec<&str> = entries.iter().map(|e| e.mesh_id.as_str()).collect();
        assert!(ids.contains(&"mesh-a"));
        assert!(!ids.contains(&"mesh-b"));
        assert!(ids.contains(&"mesh-c"));
    }

    #[tokio::test]
    async fn test_unblock_mesh_id_removes_from_both_scopes() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.block_mesh_id_with_provenance(
            "mesh-x",
            "reason",
            3600,
            "global",
            BlockProvenance::default(),
        );
        assert!(store.is_mesh_id_blocked("mesh-x", "global").is_some());
        assert!(store.is_mesh_id_blocked("mesh-x", "site_a").is_some());

        assert!(store.unblock_mesh_id("mesh-x", "site_a"));
        assert!(store.is_mesh_id_blocked("mesh-x", "global").is_none());
        assert!(store.is_mesh_id_blocked("mesh-x", "site_a").is_none());
    }

    // Phase 4: Legacy sentinel migration with real persisted data

    #[tokio::test]
    async fn test_migration_on_load_from_disk() {
        let temp_dir = TempDir::new().unwrap();

        let sentinel_entry = serde_json::json!({
            "ip": "0.0.0.0",
            "reason": "mesh_id_ban:migrated-mesh:manual",
            "blocked_at": 1000,
            "ban_expire_seconds": 0,
            "site_scope": "global",
            "access_count": 0,
            "last_access": 1000,
        });
        let blocks_json = serde_json::to_string_pretty(&vec![sentinel_entry]).unwrap();
        std::fs::write(temp_dir.path().join("blocks.json"), blocks_json).unwrap();

        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip_entries = store.get_all_entries();
        let sentinel_entries: Vec<_> = ip_entries.iter().filter(|e| e.ip == "0.0.0.0").collect();
        assert_eq!(
            sentinel_entries.len(),
            0,
            "sentinel IP entry should be removed"
        );

        let mesh_entries = store.get_all_mesh_entries();
        assert_eq!(mesh_entries.len(), 1);
        assert_eq!(mesh_entries[0].mesh_id, "migrated-mesh");
        assert_eq!(mesh_entries[0].site_scope, "global");

        assert_eq!(store.get_stats().total_entries, 0);
        assert_eq!(store.get_mesh_stats(), 1);
    }

    #[tokio::test]
    async fn test_migration_persists_to_mesh_blocks_json() {
        let temp_dir = TempDir::new().unwrap();

        let sentinel_entry = serde_json::json!({
            "ip": "0.0.0.0",
            "reason": "mesh_id_ban:persist-mesh:attack",
            "blocked_at": 1000,
            "ban_expire_seconds": 0,
            "site_scope": "global",
            "access_count": 5,
            "last_access": 1000,
        });
        let blocks_json = serde_json::to_string_pretty(&vec![sentinel_entry]).unwrap();
        std::fs::write(temp_dir.path().join("blocks.json"), blocks_json).unwrap();

        let config = DenyListLimitsConfig {
            max_entries: 1000,
            persist_interval_secs: 1,
            target_state_persist: false,
            target_state_max_records: 100_000,
            target_state_ttl_secs: 604_800,
        };
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config);
        store.trigger_persist();
        store.shutdown().await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mesh_path = temp_dir.path().join("mesh_blocks.json");
        assert!(mesh_path.exists(), "mesh_blocks.json should be created");

        let mesh_content = std::fs::read_to_string(&mesh_path).unwrap();
        let mesh_entries: Vec<serde_json::Value> = serde_json::from_str(&mesh_content).unwrap();
        assert_eq!(mesh_entries.len(), 1);
        assert_eq!(mesh_entries[0]["mesh_id"], "persist-mesh");
    }

    #[tokio::test]
    async fn test_migration_skips_non_mesh_sentinel_entries() {
        let temp_dir = TempDir::new().unwrap();

        let entries = vec![
            serde_json::json!({
                "ip": "0.0.0.0",
                "reason": "just_a_regular_ban",
                "blocked_at": 1000,
                "ban_expire_seconds": 0,
                "site_scope": "non_mesh_scope",
                "access_count": 0,
                "last_access": 1000,
            }),
            serde_json::json!({
                "ip": "0.0.0.0",
                "reason": "mesh_id_ban:valid-mesh:reason",
                "blocked_at": 1000,
                "ban_expire_seconds": 0,
                "site_scope": "mesh_scope",
                "access_count": 0,
                "last_access": 1000,
            }),
        ];
        let blocks_json = serde_json::to_string_pretty(&entries).unwrap();
        std::fs::write(temp_dir.path().join("blocks.json"), blocks_json).unwrap();

        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip_entries = store.get_all_entries();
        let sentinel_entries: Vec<_> = ip_entries.iter().filter(|e| e.ip == "0.0.0.0").collect();
        assert_eq!(
            sentinel_entries.len(),
            1,
            "non-mesh sentinel entry should remain"
        );
        assert_eq!(sentinel_entries[0].reason, "just_a_regular_ban");

        let mesh_entries = store.get_all_mesh_entries();
        assert_eq!(mesh_entries.len(), 1);
        assert_eq!(mesh_entries[0].mesh_id, "valid-mesh");
    }

    #[tokio::test]
    async fn test_old_blocks_json_without_provenance_defaults_to_legacy_unknown() {
        let temp_dir = TempDir::new().unwrap();

        let entry = serde_json::json!({
            "ip": "192.168.5.5",
            "reason": "test",
            "blocked_at": 1000,
            "ban_expire_seconds": 0,
            "site_scope": "global",
            "access_count": 0,
            "last_access": 1000,
        });
        let blocks_json = serde_json::to_string_pretty(&vec![entry]).unwrap();
        std::fs::write(temp_dir.path().join("blocks.json"), blocks_json).unwrap();

        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());
        let entries = store.get_all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].provenance.kind,
            BlockProvenanceKind::LegacyUnknown
        );
    }

    // Phase 5: Unified BlockRecord invariant tests

    #[tokio::test]
    async fn test_block_records_ip_target_kind() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.1.1.1".parse().unwrap();
        store.block_ip(ip, "test", 3600, "global");

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target_kind, BlockTargetKind::Ip);
        assert_eq!(records[0].identifier, "10.1.1.1");
    }

    #[tokio::test]
    async fn test_block_records_mesh_target_kind() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.block_mesh_id_with_provenance(
            "test-mesh",
            "reason",
            3600,
            "global",
            BlockProvenance::default(),
        );

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target_kind, BlockTargetKind::MeshId);
        assert_eq!(records[0].identifier, "test-mesh");
    }

    #[tokio::test]
    async fn test_block_records_preserve_provenance() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let prov = BlockProvenance {
            kind: BlockProvenanceKind::AdminManual,
            source: Some("admin_ban_ip".to_string()),
        };
        let ip: IpAddr = "10.2.2.2".parse().unwrap();
        store.block_ip_with_provenance(ip, "test", 3600, "global", prov);

        let records = store.get_all_block_records();
        assert_eq!(records[0].provenance.kind, BlockProvenanceKind::AdminManual);
        assert_eq!(
            records[0].provenance.source,
            Some("admin_ban_ip".to_string())
        );
    }

    #[tokio::test]
    async fn test_block_records_sorted_by_blocked_at_descending() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip1: IpAddr = "10.3.3.1".parse().unwrap();
        let ip2: IpAddr = "10.3.3.2".parse().unwrap();
        store.block_ip(ip1, "first", 3600, "global");
        store.block_ip(ip2, "second", 3600, "global");

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 2);
        assert!(records[0].blocked_at >= records[1].blocked_at);
    }

    #[tokio::test]
    async fn test_block_records_unified_count() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip1: IpAddr = "10.4.4.1".parse().unwrap();
        let ip2: IpAddr = "10.4.4.2".parse().unwrap();
        store.block_ip(ip1, "reason1", 3600, "global");
        store.block_ip(ip2, "reason2", 3600, "global");
        store.block_mesh_id_with_provenance(
            "mesh-1",
            "reason3",
            3600,
            "global",
            BlockProvenance::default(),
        );
        store.block_mesh_id_with_provenance(
            "mesh-2",
            "reason4",
            3600,
            "global",
            BlockProvenance::default(),
        );

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 4);

        let ip_count = records
            .iter()
            .filter(|r| r.target_kind == BlockTargetKind::Ip)
            .count();
        let mesh_count = records
            .iter()
            .filter(|r| r.target_kind == BlockTargetKind::MeshId)
            .count();
        assert_eq!(ip_count, 2);
        assert_eq!(mesh_count, 2);
    }

    #[tokio::test]
    async fn test_migration_records_appear_as_mesh_not_ip() {
        let temp_dir = TempDir::new().unwrap();

        let sentinel_entry = serde_json::json!({
            "ip": "0.0.0.0",
            "reason": "mesh_id_ban:legacy-mesh:reason",
            "blocked_at": 3000,
            "ban_expire_seconds": 0,
            "site_scope": "global",
            "access_count": 0,
            "last_access": 3000,
        });
        let blocks_json = serde_json::to_string_pretty(&vec![sentinel_entry]).unwrap();
        std::fs::write(temp_dir.path().join("blocks.json"), blocks_json).unwrap();

        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target_kind, BlockTargetKind::MeshId);
        assert_eq!(records[0].identifier, "legacy-mesh");
    }

    // Phase 6: Admin-level regression tests (block-store-backed)

    #[tokio::test]
    async fn test_admin_two_mesh_ids_ban_and_list() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.block_mesh_id_with_provenance(
            "admin-mesh-1",
            "reason1",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_mesh_id".to_string()),
            },
        );
        store.block_mesh_id_with_provenance(
            "admin-mesh-2",
            "reason2",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_mesh_id".to_string()),
            },
        );

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 2);
        let ids: Vec<&str> = records.iter().map(|r| r.identifier.as_str()).collect();
        assert!(ids.contains(&"admin-mesh-1"));
        assert!(ids.contains(&"admin-mesh-2"));
    }

    #[tokio::test]
    async fn test_admin_unban_one_mesh_id_removes_only_that_one() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.block_mesh_id_with_provenance(
            "keep-me",
            "r1",
            3600,
            "global",
            BlockProvenance::default(),
        );
        store.block_mesh_id_with_provenance(
            "remove-me",
            "r2",
            3600,
            "global",
            BlockProvenance::default(),
        );

        assert!(store.unblock_mesh_id("remove-me", "global"));
        assert_eq!(store.get_mesh_stats(), 1);

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].identifier, "keep-me");
    }

    #[tokio::test]
    async fn test_admin_unban_missing_mesh_id_returns_false() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        assert!(!store.unblock_mesh_id("nonexistent", "global"));
    }

    #[tokio::test]
    async fn test_admin_ip_ban_unban_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(store.block_ip_with_provenance(
            ip,
            "admin_test",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_ip".to_string()),
            },
        ));
        assert!(store.is_blocked(&ip, "global").is_some());
        assert!(store.unblock_ip(&ip, "global"));
        assert!(store.is_blocked(&ip, "global").is_none());
    }

    #[tokio::test]
    async fn test_ip_and_mesh_counters_independent() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.5.5.5".parse().unwrap();
        store.block_ip(ip, "ip-reason", 3600, "global");
        store.block_mesh_id_with_provenance(
            "mesh-1",
            "mesh-reason",
            3600,
            "global",
            BlockProvenance::default(),
        );

        assert_eq!(store.get_stats().total_entries, 1);
        assert_eq!(store.get_mesh_stats(), 1);

        store.unblock_ip(&ip, "global");
        assert_eq!(store.get_stats().total_entries, 0);
        assert_eq!(store.get_mesh_stats(), 1);

        store.unblock_mesh_id("mesh-1", "global");
        assert_eq!(store.get_stats().total_entries, 0);
        assert_eq!(store.get_mesh_stats(), 0);
    }

    // Phase 5+6: apply_blocklist_event and dedup tests

    #[tokio::test]
    async fn test_apply_blocklist_event_block_ip() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "apply_test",
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("test".to_string()),
            },
            1000,
        );

        let result = store.apply_blocklist_event(&event);
        assert_eq!(result, BlocklistApplyResult::Applied);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let entry = store.is_blocked(&ip, "global");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().reason, "apply_test");
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_unblock_ip() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        store.block_ip(ip, "test", 3600, "global");
        assert!(store.is_blocked(&ip, "global").is_some());

        let event =
            BlocklistEvent::unblock_ip("10.0.0.2", "global", BlockProvenance::default(), 1001);
        let result = store.apply_blocklist_event(&event);
        assert_eq!(result, BlocklistApplyResult::Applied);
        assert!(store.is_blocked(&ip, "global").is_none());
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_block_mesh_id() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let event = BlocklistEvent::block_mesh_id(
            "mesh-apply",
            "apply_mesh_test",
            "global",
            BlockProvenance::default(),
            1002,
        );

        let result = store.apply_blocklist_event(&event);
        assert_eq!(result, BlocklistApplyResult::Applied);
        assert!(store.is_mesh_id_blocked("mesh-apply", "global").is_some());
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_unblock_mesh_id() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.block_mesh_id_with_provenance(
            "mesh-unapply",
            "test",
            3600,
            "global",
            BlockProvenance::default(),
        );
        assert!(store.is_mesh_id_blocked("mesh-unapply", "global").is_some());

        let event = BlocklistEvent::unblock_mesh_id(
            "mesh-unapply",
            "global",
            BlockProvenance::default(),
            1003,
        );
        let result = store.apply_blocklist_event(&event);
        assert_eq!(result, BlocklistApplyResult::Applied);
        assert!(store.is_mesh_id_blocked("mesh-unapply", "global").is_none());
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_invalid_ip() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let mut event = BlocklistEvent::block_ip(
            "not_an_ip",
            "test",
            "global",
            BlockProvenance::default(),
            1004,
        );
        event.event_id = Some("test-event-1".to_string());

        let result = store.apply_blocklist_event(&event);
        assert_eq!(result, BlocklistApplyResult::InvalidTarget);
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_dedup() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let mut event = BlocklistEvent::block_ip(
            "10.0.0.50",
            "dedup_test",
            "global",
            BlockProvenance::default(),
            1005,
        );
        event.event_id = Some("dedup-event-1".to_string());

        let result1 = store.apply_blocklist_event(&event);
        assert_eq!(result1, BlocklistApplyResult::Applied);

        let result2 = store.apply_blocklist_event(&event);
        assert_eq!(result2, BlocklistApplyResult::NoopDuplicate);
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_dedup_unblock() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.51".parse().unwrap();
        store.block_ip(ip, "test", 3600, "global");

        let mut event =
            BlocklistEvent::unblock_ip("10.0.0.51", "global", BlockProvenance::default(), 1006);
        event.event_id = Some("dedup-unblock-1".to_string());

        let result1 = store.apply_blocklist_event(&event);
        assert_eq!(result1, BlocklistApplyResult::Applied);

        let result2 = store.apply_blocklist_event(&event);
        assert_eq!(result2, BlocklistApplyResult::NoopDuplicate);
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_no_event_id_no_dedup() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let event = BlocklistEvent::block_ip(
            "10.0.0.52",
            "no_dedup_test",
            "global",
            BlockProvenance::default(),
            1007,
        );
        assert!(event.event_id.is_none());

        let result1 = store.apply_blocklist_event(&event);
        assert_eq!(result1, BlocklistApplyResult::Applied);

        // Without an event_id, dedup is skipped. However, per-target stale
        // suppression rejects the replay since the same target already has
        // an applied event at the same timestamp.
        let result2 = store.apply_blocklist_event(&event);
        assert_eq!(result2, BlocklistApplyResult::IgnoredStale);
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_disabled_store() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(false, Some(temp_dir.path().to_path_buf()), default_config());

        let event = BlocklistEvent::block_ip(
            "10.0.0.53",
            "disabled_test",
            "global",
            BlockProvenance::default(),
            1008,
        );

        let result = store.apply_blocklist_event(&event);
        assert_eq!(result, BlocklistApplyResult::StoreDisabled);
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_dedup_eviction() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        // Insert 10001 events to exceed capacity.
        for i in 0..10001u64 {
            let mut event = BlocklistEvent::block_ip(
                "10.0.0.1",
                "eviction_test",
                "global",
                BlockProvenance::default(),
                2000 + i,
            );
            event.event_id = Some(format!("evict-{}", i));
            store.apply_blocklist_event(&event);
        }

        // After FIFO eviction, cache should be at or below capacity.
        let seen = store.seen_events.read();
        assert!(seen.len() <= SEEN_EVENTS_MAX);

        // The oldest event (evict-0) should have been evicted and no longer deduped.
        // The most recent events should still be present.
        drop(seen);

        // Re-apply the oldest event — it should apply again (was evicted from dedup).
        let mut oldest = BlocklistEvent::block_ip(
            "10.0.0.1",
            "eviction_test",
            "global",
            BlockProvenance::default(),
            2000,
        );
        oldest.event_id = Some("evict-0".to_string());
        let result = store.apply_blocklist_event(&oldest);
        // Should NOT be NoopDuplicate since evict-0 was evicted from the seen set.
        assert_ne!(result, BlocklistApplyResult::NoopDuplicate);

        // Re-apply a recent event — it should still be deduped.
        let mut recent = BlocklistEvent::block_ip(
            "10.0.0.1",
            "eviction_test",
            "global",
            BlockProvenance::default(),
            2000 + 10000,
        );
        recent.event_id = Some("evict-10000".to_string());
        let result = store.apply_blocklist_event(&recent);
        assert_eq!(result, BlocklistApplyResult::NoopDuplicate);
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_ttl_passthrough() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let mut event = BlocklistEvent::block_ip(
            "10.0.0.60",
            "ttl_test",
            "global",
            BlockProvenance::default(),
            1010,
        );
        event.ttl_secs = Some(7200);

        let result = store.apply_blocklist_event(&event);
        assert_eq!(result, BlocklistApplyResult::Applied);

        let ip: IpAddr = "10.0.0.60".parse().unwrap();
        let entry = store.is_blocked(&ip, "global").unwrap();
        assert_eq!(entry.ban_expire_seconds, 7200);
    }

    #[test]
    fn test_blocklist_event_postcard_roundtrip() {
        let event = BlocklistEvent {
            operation: BlocklistOperation::Unblock,
            target_kind: BlockTargetKind::MeshId,
            identifier: "test-mesh-42".to_string(),
            site_scope: "us-east-1".to_string(),
            reason: None,
            provenance: BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_unban_mesh_id".to_string()),
            },
            timestamp: 1700000000,
            source_node: Some("node-1".to_string()),
            event_id: Some(
                "node-1:1700000000:unblock:mesh_id:us-east-1:test-mesh-42:abc123".to_string(),
            ),
            ttl_secs: None,
            version: Some(5),
        };

        let json = serde_json::to_string(&event).expect("serialize");
        let decoded: BlocklistEvent = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.operation, BlocklistOperation::Unblock);
        assert_eq!(decoded.target_kind, BlockTargetKind::MeshId);
        assert_eq!(decoded.identifier, "test-mesh-42");
        assert_eq!(decoded.site_scope, "us-east-1");
        assert!(decoded.reason.is_none());
        assert_eq!(decoded.provenance.kind, BlockProvenanceKind::AdminManual);
        assert_eq!(
            decoded.provenance.source,
            Some("admin_unban_mesh_id".to_string())
        );
        assert_eq!(decoded.timestamp, 1700000000);
        assert_eq!(decoded.source_node, Some("node-1".to_string()));
        assert!(decoded.event_id.is_some());
        assert_eq!(decoded.version, Some(5));
    }

    #[test]
    fn test_blocklist_event_postcard_backward_compat() {
        // Simulate an old event without the new fields (ttl_secs, version)
        // by serializing only the old fields
        let event = BlocklistEvent::block_ip(
            "192.168.1.100",
            "test",
            "global",
            BlockProvenance::default(),
            9999,
        );
        // The constructors set ttl_secs=None and version=None by default
        assert!(event.ttl_secs.is_none());
        assert!(event.version.is_none());

        let json = serde_json::to_string(&event).unwrap();
        let decoded: BlocklistEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.operation, BlocklistOperation::Block);
        assert_eq!(decoded.identifier, "192.168.1.100");
        assert!(decoded.ttl_secs.is_none());
        assert!(decoded.version.is_none());
    }

    #[test]
    fn test_blocklist_event_generate_event_id_deterministic() {
        let e1 = BlocklistEvent::unblock_ip(
            "10.0.0.1",
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("test".to_string()),
            },
            1000,
        )
        .with_source_node("node-1".to_string());

        let e2 = BlocklistEvent::unblock_ip(
            "10.0.0.1",
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("test".to_string()),
            },
            1000,
        )
        .with_source_node("node-1".to_string());

        let id1 = e1.generate_event_id();
        let id2 = e2.generate_event_id();
        assert_eq!(id1, id2, "Same inputs should produce same event ID");
    }

    #[test]
    fn test_blocklist_event_generate_event_id_unique_per_target() {
        let e1 = BlocklistEvent::unblock_ip("10.0.0.1", "global", BlockProvenance::default(), 1000)
            .with_source_node("node-1".to_string());

        let e2 = BlocklistEvent::unblock_ip("10.0.0.2", "global", BlockProvenance::default(), 1000)
            .with_source_node("node-1".to_string());

        let id1 = e1.generate_event_id();
        let id2 = e2.generate_event_id();
        assert_ne!(
            id1, id2,
            "Different targets should produce different event IDs"
        );
    }

    // === Iteration 47: Per-target stale suppression tests ===

    #[tokio::test]
    async fn test_stale_suppression_older_block_after_newer_unblock_ip() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        // First: unblock at timestamp 2000 (newer event).
        let unblock =
            BlocklistEvent::unblock_ip("10.0.100.1", "global", BlockProvenance::default(), 2000)
                .with_event_id("unblock-1".to_string());
        let r = store.apply_blocklist_event(&unblock);
        assert_eq!(r, BlocklistApplyResult::Applied);

        // Second: block at timestamp 1000 (older event) — should be rejected as stale.
        let block = BlocklistEvent::block_ip(
            "10.0.100.1",
            "test",
            "global",
            BlockProvenance::default(),
            1000,
        )
        .with_event_id("block-old-1".to_string());
        let r = store.apply_blocklist_event(&block);
        assert_eq!(r, BlocklistApplyResult::IgnoredStale);

        // Target should remain unblocked.
        let ip: IpAddr = "10.0.100.1".parse().unwrap();
        assert!(store.is_blocked(&ip, "global").is_none());
    }

    #[tokio::test]
    async fn test_stale_suppression_older_block_after_newer_unblock_mesh_id() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let unblock = BlocklistEvent::unblock_mesh_id(
            "mesh-stale-1",
            "global",
            BlockProvenance::default(),
            2000,
        )
        .with_event_id("unblock-mesh-1".to_string());
        let r = store.apply_blocklist_event(&unblock);
        assert_eq!(r, BlocklistApplyResult::Applied);

        let block = BlocklistEvent::block_mesh_id(
            "mesh-stale-1",
            "test",
            "global",
            BlockProvenance::default(),
            1000,
        )
        .with_event_id("block-mesh-old-1".to_string());
        let r = store.apply_blocklist_event(&block);
        assert_eq!(r, BlocklistApplyResult::IgnoredStale);
        assert!(store.is_mesh_id_blocked("mesh-stale-1", "global").is_none());
    }

    #[tokio::test]
    async fn test_stale_suppression_older_unblock_after_newer_block_ip() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        // First: block at timestamp 2000 (newer event).
        let block = BlocklistEvent::block_ip(
            "10.0.100.2",
            "test",
            "global",
            BlockProvenance::default(),
            2000,
        )
        .with_event_id("block-new-1".to_string());
        let r = store.apply_blocklist_event(&block);
        assert_eq!(r, BlocklistApplyResult::Applied);

        // Second: unblock at timestamp 1000 (older event) — should be rejected.
        let unblock =
            BlocklistEvent::unblock_ip("10.0.100.2", "global", BlockProvenance::default(), 1000)
                .with_event_id("unblock-old-1".to_string());
        let r = store.apply_blocklist_event(&unblock);
        assert_eq!(r, BlocklistApplyResult::IgnoredStale);

        // Target should remain blocked.
        let ip: IpAddr = "10.0.100.2".parse().unwrap();
        assert!(store.is_blocked(&ip, "global").is_some());
    }

    #[tokio::test]
    async fn test_stale_suppression_older_unblock_after_newer_block_mesh_id() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let block = BlocklistEvent::block_mesh_id(
            "mesh-stale-2",
            "test",
            "global",
            BlockProvenance::default(),
            2000,
        )
        .with_event_id("block-mesh-new-2".to_string());
        let r = store.apply_blocklist_event(&block);
        assert_eq!(r, BlocklistApplyResult::Applied);

        let unblock = BlocklistEvent::unblock_mesh_id(
            "mesh-stale-2",
            "global",
            BlockProvenance::default(),
            1000,
        )
        .with_event_id("unblock-mesh-old-2".to_string());
        let r = store.apply_blocklist_event(&unblock);
        assert_eq!(r, BlocklistApplyResult::IgnoredStale);
        assert!(store.is_mesh_id_blocked("mesh-stale-2", "global").is_some());
    }

    #[tokio::test]
    async fn test_stale_suppression_version_beats_timestamp() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        // First: block with version=5, timestamp=1000.
        let mut block_with_ver = BlocklistEvent::block_ip(
            "10.0.100.3",
            "test",
            "global",
            BlockProvenance::default(),
            1000,
        );
        block_with_ver.event_id = Some("block-v5".to_string());
        block_with_ver.version = Some(5);
        let r = store.apply_blocklist_event(&block_with_ver);
        assert_eq!(r, BlocklistApplyResult::Applied);

        // Second: unblock with version=3, timestamp=2000 — older version, should be stale.
        let mut unblock =
            BlocklistEvent::unblock_ip("10.0.100.3", "global", BlockProvenance::default(), 2000);
        unblock.event_id = Some("unblock-v3".to_string());
        unblock.version = Some(3);
        let r = store.apply_blocklist_event(&unblock);
        assert_eq!(r, BlocklistApplyResult::IgnoredStale);

        let ip: IpAddr = "10.0.100.3".parse().unwrap();
        assert!(store.is_blocked(&ip, "global").is_some());
    }

    #[tokio::test]
    async fn test_stale_suppression_equal_timestamp_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        // First event.
        let block = BlocklistEvent::block_ip(
            "10.0.100.4",
            "test",
            "global",
            BlockProvenance::default(),
            1000,
        )
        .with_event_id("event-a".to_string());
        let r = store.apply_blocklist_event(&block);
        assert_eq!(r, BlocklistApplyResult::Applied);

        // Second event with same timestamp, different event_id — should be stale
        // (equal timestamp, neither version present → not newer).
        let block2 = BlocklistEvent::block_ip(
            "10.0.100.4",
            "test2",
            "global",
            BlockProvenance::default(),
            1000,
        )
        .with_event_id("event-b".to_string());
        let r = store.apply_blocklist_event(&block2);
        assert_eq!(r, BlocklistApplyResult::IgnoredStale);
    }

    #[tokio::test]
    async fn test_unblock_missing_target_records_state() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        // Unblock a target that was never blocked — should still record target state.
        let unblock =
            BlocklistEvent::unblock_ip("10.0.100.5", "global", BlockProvenance::default(), 1000)
                .with_event_id("unblock-missing-1".to_string());
        let r = store.apply_blocklist_event(&unblock);
        assert_eq!(r, BlocklistApplyResult::Applied);

        // Now an older block should be rejected as stale.
        let block = BlocklistEvent::block_ip(
            "10.0.100.5",
            "test",
            "global",
            BlockProvenance::default(),
            500,
        )
        .with_event_id("block-old-missing-1".to_string());
        let r = store.apply_blocklist_event(&block);
        assert_eq!(r, BlocklistApplyResult::IgnoredStale);
    }

    #[tokio::test]
    async fn test_invalid_target_no_state_recorded() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let mut event = BlocklistEvent::block_ip(
            "not_an_ip",
            "test",
            "global",
            BlockProvenance::default(),
            1000,
        );
        event.event_id = Some("invalid-target-1".to_string());
        let r = store.apply_blocklist_event(&event);
        assert_eq!(r, BlocklistApplyResult::InvalidTarget);

        // The event_id should NOT have been recorded (invalid targets are not deduped).
        let mut event2 = BlocklistEvent::block_ip(
            "not_an_ip",
            "test",
            "global",
            BlockProvenance::default(),
            1000,
        );
        event2.event_id = Some("invalid-target-1".to_string());
        let r = store.apply_blocklist_event(&event2);
        assert_eq!(r, BlocklistApplyResult::InvalidTarget);
    }

    #[tokio::test]
    async fn test_target_state_eviction_fifo() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        // Fill target state cache to capacity.
        for i in 0..TARGET_STATE_MAX as u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.{}.{}", (i / 256) % 256, i % 256),
                "fill_test",
                "global",
                BlockProvenance::default(),
                1000 + i,
            )
            .with_event_id(format!("fill-{}", i));
            store.apply_blocklist_event(&event);
        }

        // Add one more to trigger eviction of the oldest.
        let overflow = BlocklistEvent::block_ip(
            "10.0.200.1",
            "overflow_test",
            "global",
            BlockProvenance::default(),
            1000 + TARGET_STATE_MAX as u64,
        )
        .with_event_id(format!("overflow-{}", TARGET_STATE_MAX));
        let r = store.apply_blocklist_event(&overflow);
        assert_eq!(r, BlocklistApplyResult::Applied);

        // The cache should be at capacity.
        let targets = store.target_state.read();
        assert_eq!(targets.len(), TARGET_STATE_MAX);
    }

    #[test]
    fn test_blocklist_event_log_append_and_query() {
        let mut log = BlocklistEventLog::new(100);
        let mut event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        );
        event = event.with_event_id("evt-1".to_string());
        let seq = log.append(event);
        assert_eq!(seq, Some(0));
        assert_eq!(log.len(), 1);

        // From start: returns the event at sequence 0.
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 10,
        });
        assert_eq!(result.events.len(), 1);
        assert!(result.history_complete);

        // After sequence 0: skips event at sequence 0.
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(0),
            max_events: 10,
        });
        assert_eq!(result.events.len(), 0);
        assert!(result.history_complete);
    }

    #[test]
    fn test_blocklist_event_log_dedup() {
        let mut log = BlocklistEventLog::new(100);
        let event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        )
        .with_event_id("evt-1".to_string());
        assert_eq!(log.append(event.clone()), Some(0));
        // Duplicate event ID should be rejected.
        assert_eq!(log.append(event), None);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_blocklist_event_log_capacity_eviction() {
        let mut log = BlocklistEventLog::new(3);
        for i in 0..5u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.0.{}", i),
                "test",
                "global",
                BlockProvenance::default(),
                i * 100,
            )
            .with_event_id(format!("evt-{}", i));
            log.append(event);
        }
        assert_eq!(log.len(), 3);
        // The oldest two (evt-0, evt-1) should have been evicted.
        // From start returns all 3 retained events.
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 100,
        });
        assert_eq!(result.events.len(), 3);
        // First returned event should be evt-2 (seq 2)
        assert_eq!(result.events[0].event_id.as_deref(), Some("evt-2"));
    }

    #[test]
    fn test_blocklist_event_log_query_since_with_gap() {
        let mut log = BlocklistEventLog::new(3);
        // Add 5 events, but log only retains 3 (the last 3).
        for i in 0..5u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.0.{}", i),
                "test",
                "global",
                BlockProvenance::default(),
                i * 100,
            )
            .with_event_id(format!("evt-{}", i));
            log.append(event);
        }
        // Log has sequences 2,3,4. From start returns all 3 retained (no gap from start).
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 100,
        });
        assert!(result.history_complete);
        assert!(!result.snapshot_required);
        assert_eq!(result.events.len(), 3);

        // After sequence 0 detects the gap (seq 0,1 evicted).
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(0),
            max_events: 100,
        });
        assert!(!result.history_complete);
        assert!(result.snapshot_required);
        assert_eq!(result.events.len(), 3);
    }

    #[test]
    fn test_blocklist_event_log_query_within_retained() {
        let mut log = BlocklistEventLog::new(10);
        for i in 0..5u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.0.{}", i),
                "test",
                "global",
                BlockProvenance::default(),
                i * 100,
            )
            .with_event_id(format!("evt-{}", i));
            log.append(event);
        }
        // All 5 events retained. After seq 2 returns events 3,4.
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(2),
            max_events: 100,
        });
        assert!(result.history_complete);
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.events[0].event_id.as_deref(), Some("evt-3"));
        assert_eq!(result.events[1].event_id.as_deref(), Some("evt-4"));
    }

    #[test]
    fn test_blocklist_event_log_query_max_events() {
        let mut log = BlocklistEventLog::new(10);
        for i in 0..10u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.0.{}", i),
                "test",
                "global",
                BlockProvenance::default(),
                i * 100,
            )
            .with_event_id(format!("evt-{}", i));
            log.append(event);
        }
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 3,
        });
        assert_eq!(result.events.len(), 3);
    }

    #[test]
    fn test_blocklist_event_log_timestamps() {
        let mut log = BlocklistEventLog::new(10);
        assert!(log.oldest_timestamp().is_none());
        assert!(log.newest_timestamp().is_none());

        let e1 = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        );
        let e2 = BlocklistEvent::block_ip(
            "10.0.0.2",
            "test",
            "global",
            BlockProvenance::default(),
            200,
        );
        log.append(e1);
        log.append(e2);
        assert_eq!(log.oldest_timestamp(), Some(100));
        assert_eq!(log.newest_timestamp(), Some(200));
    }

    #[test]
    fn test_blocklist_event_log_no_event_id() {
        let mut log = BlocklistEventLog::new(10);
        // Events without event_id are not deduped by ID.
        let e1 = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        );
        let e2 = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        );
        log.append(e1);
        log.append(e2);
        assert_eq!(log.len(), 2);
    }

    // === Event log tests ===

    #[test]
    fn test_blocklist_event_log_replay_block_then_unblock() {
        let mut log = BlocklistEventLog::new(100);
        let block_event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        )
        .with_event_id("block-1".to_string());
        let unblock_event =
            BlocklistEvent::unblock_ip("10.0.0.1", "global", BlockProvenance::default(), 200)
                .with_event_id("unblock-1".to_string());

        log.append(block_event);
        log.append(unblock_event);

        assert_eq!(log.len(), 2);
        assert_eq!(log.next_sequence(), 2);

        // From start returns both events.
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 10,
        });
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.events[0].operation, BlocklistOperation::Block);
        assert_eq!(result.events[1].operation, BlocklistOperation::Unblock);
        assert!(result.history_complete);

        // After seq 0 returns just the unblock at seq 1.
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(0),
            max_events: 10,
        });
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].operation, BlocklistOperation::Unblock);
        assert!(result.history_complete);

        // After seq 1 returns nothing (no events with seq > 1).
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(1),
            max_events: 10,
        });
        assert_eq!(result.events.len(), 0);
        assert!(result.history_complete);
    }

    #[test]
    fn test_blocklist_event_log_replay_duplicate_events() {
        let mut log = BlocklistEventLog::new(100);
        let event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        )
        .with_event_id("dup-1".to_string());

        assert_eq!(log.append(event.clone()), Some(0));
        assert_eq!(log.append(event), None);
        assert_eq!(log.len(), 1);
    }

    #[tokio::test]
    async fn test_blocklist_event_log_replay_stale_event() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        // Apply newer event first (via apply_blocklist_event which records to log).
        let newer = BlocklistEvent::block_ip(
            "10.0.0.1",
            "newer",
            "global",
            BlockProvenance::default(),
            200,
        )
        .with_event_id("newer-1".to_string());
        let r = store.apply_blocklist_event(&newer);
        assert_eq!(r, BlocklistApplyResult::Applied);

        // Apply older event — should be ignored by stale suppression.
        let older = BlocklistEvent::block_ip(
            "10.0.0.1",
            "older",
            "global",
            BlockProvenance::default(),
            100,
        )
        .with_event_id("older-1".to_string());
        let r = store.apply_blocklist_event(&older);
        assert_eq!(r, BlocklistApplyResult::IgnoredStale);

        // Only the newer (applied) event appears in the log; stale events are not recorded.
        let log = store.event_log.read();
        assert_eq!(log.len(), 1);
        assert_eq!(log.events[0].event_id.as_deref(), Some("newer-1"));
    }

    #[tokio::test]
    async fn test_blocklist_event_log_replay_mesh_id_unblock() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        // Block a mesh ID.
        let block = BlocklistEvent::block_mesh_id(
            "mesh-1",
            "attack",
            "global",
            BlockProvenance::default(),
            100,
        )
        .with_event_id("block-mesh-1".to_string());
        let r = store.apply_blocklist_event(&block);
        assert_eq!(r, BlocklistApplyResult::Applied);
        assert!(store.is_mesh_id_blocked("mesh-1", "global").is_some());

        // Unblock it.
        let unblock =
            BlocklistEvent::unblock_mesh_id("mesh-1", "global", BlockProvenance::default(), 200)
                .with_event_id("unblock-mesh-1".to_string());
        let r = store.apply_blocklist_event(&unblock);
        assert_eq!(r, BlocklistApplyResult::Applied);
        assert!(store.is_mesh_id_blocked("mesh-1", "global").is_none());
    }

    #[test]
    fn test_blocklist_event_log_full_lifecycle() {
        let mut log = BlocklistEventLog::new(5);
        for i in 0..3u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.0.{}", i),
                "test",
                "global",
                BlockProvenance::default(),
                100 + i,
            )
            .with_event_id(format!("evt-{}", i));
            log.append(event);
        }

        // Query within retained range — after seq 1 returns event at seq 2 (evt-2).
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(1),
            max_events: 10,
        });
        assert!(result.history_complete);
        assert!(!result.snapshot_required);
        assert_eq!(result.events.len(), 1);

        // Append more events to cause eviction.
        for i in 3..7u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.0.{}", i),
                "test",
                "global",
                BlockProvenance::default(),
                100 + i,
            )
            .with_event_id(format!("evt-{}", i));
            log.append(event);
        }

        // From start: no gap detected (returns all retained from oldest).
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 10,
        });
        assert!(result.history_complete);
        assert!(!result.snapshot_required);

        // After seq 0: gap detected (seq 0,1 evicted).
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(0),
            max_events: 10,
        });
        assert!(!result.history_complete);
        assert!(result.snapshot_required);
    }

    #[test]
    fn test_blocklist_event_log_empty_query() {
        let log = BlocklistEventLog::new(100);
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 10,
        });
        assert!(result.history_complete);
        assert!(!result.snapshot_required);
        assert_eq!(result.events.len(), 0);
        assert_eq!(result.latest_timestamp, 0);
    }

    #[test]
    fn test_blocklist_event_log_boundary_conditions() {
        let mut log = BlocklistEventLog::new(3);

        // Fill to exact capacity.
        for i in 0..3u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.0.{}", i),
                "test",
                "global",
                BlockProvenance::default(),
                100 + i,
            )
            .with_event_id(format!("evt-{}", i));
            log.append(event);
        }

        // After seq 1 returns events at seq 2.
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(1),
            max_events: 3,
        });
        assert_eq!(result.events.len(), 1);
        assert!(result.history_complete);

        // At the last sequence — should return nothing.
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(2),
            max_events: 10,
        });
        assert_eq!(result.events.len(), 0);
        assert!(result.history_complete);

        // From start returns all 3 retained events (no gap since oldest_seq=0).
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 10,
        });
        assert!(result.history_complete);
        assert_eq!(result.events.len(), 3);
    }

    // === Apply replay tests ===

    #[tokio::test]
    async fn test_apply_replay_block_then_unblock_converges() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let block_event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        )
        .with_event_id("block-1".to_string());
        let r = store.apply_blocklist_event(&block_event);
        assert_eq!(r, BlocklistApplyResult::Applied);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(store.is_blocked(&ip, "global").is_some());

        let unblock_event =
            BlocklistEvent::unblock_ip("10.0.0.1", "global", BlockProvenance::default(), 200)
                .with_event_id("unblock-1".to_string());
        let r = store.apply_blocklist_event(&unblock_event);
        assert_eq!(r, BlocklistApplyResult::Applied);
        assert!(store.is_blocked(&ip, "global").is_none());
    }

    #[tokio::test]
    async fn test_apply_replay_duplicate_does_not_mutate_twice() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        )
        .with_event_id("dup-1".to_string());

        let r1 = store.apply_blocklist_event(&event);
        assert_eq!(r1, BlocklistApplyResult::Applied);

        let r2 = store.apply_blocklist_event(&event);
        assert_eq!(r2, BlocklistApplyResult::NoopDuplicate);
    }

    #[tokio::test]
    async fn test_apply_replay_stale_event_returns_ignored() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        // Apply newer event first.
        let newer = BlocklistEvent::block_ip(
            "10.0.0.1",
            "newer",
            "global",
            BlockProvenance::default(),
            200,
        )
        .with_event_id("newer-1".to_string());
        let r = store.apply_blocklist_event(&newer);
        assert_eq!(r, BlocklistApplyResult::Applied);

        // Apply older event — should be rejected.
        let older = BlocklistEvent::block_ip(
            "10.0.0.1",
            "older",
            "global",
            BlockProvenance::default(),
            100,
        )
        .with_event_id("older-1".to_string());
        let r = store.apply_blocklist_event(&older);
        assert_eq!(r, BlocklistApplyResult::IgnoredStale);
    }

    #[tokio::test]
    async fn test_apply_replay_mesh_id_unblock_removes_only_that_id() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.block_mesh_id_with_provenance(
            "mesh-1",
            "reason1",
            3600,
            "global",
            BlockProvenance::default(),
        );
        store.block_mesh_id_with_provenance(
            "mesh-2",
            "reason2",
            3600,
            "global",
            BlockProvenance::default(),
        );
        assert_eq!(store.get_mesh_stats(), 2);

        let unblock =
            BlocklistEvent::unblock_mesh_id("mesh-1", "global", BlockProvenance::default(), 100)
                .with_event_id("unblock-mesh-1".to_string());
        let r = store.apply_blocklist_event(&unblock);
        assert_eq!(r, BlocklistApplyResult::Applied);

        assert!(store.is_mesh_id_blocked("mesh-1", "global").is_none());
        assert!(store.is_mesh_id_blocked("mesh-2", "global").is_some());
        assert_eq!(store.get_mesh_stats(), 1);
    }

    // === Catchup message roundtrip tests ===

    #[test]
    fn test_blocklist_event_data_from_event_roundtrip() {
        let event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "roundtrip_test",
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("test_source".to_string()),
            },
            1000,
        )
        .with_event_id("rt-1".to_string())
        .with_source_node("node-1".to_string());

        let json = serde_json::to_string(&event).expect("serialize");
        let decoded: BlocklistEvent = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.operation, event.operation);
        assert_eq!(decoded.target_kind, event.target_kind);
        assert_eq!(decoded.identifier, event.identifier);
        assert_eq!(decoded.site_scope, event.site_scope);
        assert_eq!(decoded.reason, event.reason);
        assert_eq!(decoded.provenance.kind, event.provenance.kind);
        assert_eq!(decoded.provenance.source, event.provenance.source);
        assert_eq!(decoded.timestamp, event.timestamp);
        assert_eq!(decoded.event_id, event.event_id);
        assert_eq!(decoded.source_node, event.source_node);
        assert_eq!(decoded.ttl_secs, event.ttl_secs);
        assert_eq!(decoded.version, event.version);
    }

    #[test]
    fn test_blocklist_event_data_with_all_fields() {
        let mut event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "all_fields_test",
            "site-a",
            BlockProvenance {
                kind: BlockProvenanceKind::MeshThreatIntelPolicyGated,
                source: Some("mesh:node-1".to_string()),
            },
            5000,
        );
        event.ttl_secs = Some(7200);
        event.version = Some(10);
        event = event
            .with_event_id("all-fields-1".to_string())
            .with_source_node("node-1".to_string());

        let json = serde_json::to_string(&event).expect("serialize");
        let decoded: BlocklistEvent = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.operation, BlocklistOperation::Block);
        assert_eq!(decoded.target_kind, BlockTargetKind::Ip);
        assert_eq!(decoded.identifier, "10.0.0.1");
        assert_eq!(decoded.site_scope, "site-a");
        assert_eq!(decoded.reason, Some("all_fields_test".to_string()));
        assert_eq!(
            decoded.provenance.kind,
            BlockProvenanceKind::MeshThreatIntelPolicyGated
        );
        assert_eq!(decoded.provenance.source, Some("mesh:node-1".to_string()));
        assert_eq!(decoded.timestamp, 5000);
        assert_eq!(decoded.ttl_secs, Some(7200));
        assert_eq!(decoded.version, Some(10));
        assert_eq!(decoded.event_id, Some("all-fields-1".to_string()));
        assert_eq!(decoded.source_node, Some("node-1".to_string()));
    }

    // === Iteration 49: Cursor semantics tests ===

    #[test]
    fn from_start_includes_sequence_zero() {
        let mut log = BlocklistEventLog::new(100);
        let event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        )
        .with_event_id("evt-0".to_string());
        log.append(event);

        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 10,
        });
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].event_id.as_deref(), Some("evt-0"));
        assert!(result.history_complete);
        assert!(!result.snapshot_required);
    }

    #[test]
    fn after_sequence_zero_skips_sequence_zero() {
        let mut log = BlocklistEventLog::new(100);
        let e1 = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            100,
        )
        .with_event_id("evt-0".to_string());
        let e2 = BlocklistEvent::block_ip(
            "10.0.0.2",
            "test",
            "global",
            BlockProvenance::default(),
            200,
        )
        .with_event_id("evt-1".to_string());
        log.append(e1);
        log.append(e2);

        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(0),
            max_events: 10,
        });
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].event_id.as_deref(), Some("evt-1"));
    }

    #[test]
    fn from_start_empty_log_complete() {
        let log = BlocklistEventLog::new(100);
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 10,
        });
        assert!(result.history_complete);
        assert!(!result.snapshot_required);
        assert_eq!(result.events.len(), 0);
        assert_eq!(result.latest_timestamp, 0);
    }

    #[test]
    fn after_evicted_sequence_sets_snapshot_required() {
        let mut log = BlocklistEventLog::new(3);
        for i in 0..5u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.0.{}", i),
                "test",
                "global",
                BlockProvenance::default(),
                i * 100,
            )
            .with_event_id(format!("evt-{}", i));
            log.append(event);
        }
        // Log retains sequences 2,3,4. Requesting after seq 0 → gap detected.
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(0),
            max_events: 100,
        });
        assert!(result.snapshot_required);
        assert!(!result.history_complete);
        assert_eq!(result.events.len(), 3);
    }

    #[test]
    fn max_events_limits_from_start() {
        let mut log = BlocklistEventLog::new(100);
        for i in 0..10u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.0.{}", i),
                "test",
                "global",
                BlockProvenance::default(),
                i * 100,
            )
            .with_event_id(format!("evt-{}", i));
            log.append(event);
        }
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 3,
        });
        assert_eq!(result.events.len(), 3);
        assert_eq!(result.events[0].event_id.as_deref(), Some("evt-0"));
        assert_eq!(result.events[2].event_id.as_deref(), Some("evt-2"));
    }

    #[test]
    fn latest_sequence_reports_newest_sequence() {
        let mut log = BlocklistEventLog::new(100);
        for i in 0..5u64 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.0.{}", i),
                "test",
                "global",
                BlockProvenance::default(),
                i * 100,
            )
            .with_event_id(format!("evt-{}", i));
            log.append(event);
        }
        // From start: latest_sequence should be 4 (last assigned).
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: None,
            max_events: 100,
        });
        assert_eq!(result.latest_sequence, 4);

        // After seq 2: latest_sequence should still be 4.
        let result = log.query_since(&BlocklistEventCursor {
            since_sequence: Some(2),
            max_events: 100,
        });
        assert_eq!(result.latest_sequence, 4);
    }

    // ── Iteration 50: IPC provenance preservation tests ──────────────

    #[tokio::test]
    async fn test_block_records_preserve_provenance_after_block_with_admin_manual() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let ip: IpAddr = "10.0.0.50".parse().unwrap();
        store.block_ip_with_provenance(
            ip,
            "admin ban",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_ip".to_string()),
            },
        );

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].provenance.kind, BlockProvenanceKind::AdminManual);
        assert_eq!(
            records[0].provenance.source.as_deref(),
            Some("admin_ban_ip")
        );
    }

    #[tokio::test]
    async fn test_block_records_preserve_provenance_after_mesh_block_with_admin_manual() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        store.block_mesh_id_with_provenance(
            "node-xyz",
            "admin ban",
            3600,
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_mesh_id".to_string()),
            },
        );

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].provenance.kind, BlockProvenanceKind::AdminManual);
        assert_eq!(
            records[0].provenance.source.as_deref(),
            Some("admin_ban_mesh_id")
        );
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_preserves_admin_manual_provenance() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let event = BlocklistEvent::block_ip(
            "10.0.0.60",
            "admin ban via event",
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_ip".to_string()),
            },
            1000,
        )
        .with_event_id("test-event-1".to_string());

        let result = store.apply_blocklist_event(&event);
        assert!(matches!(result, BlocklistApplyResult::Applied));

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].provenance.kind, BlockProvenanceKind::AdminManual);
        assert_eq!(
            records[0].provenance.source.as_deref(),
            Some("admin_ban_ip")
        );
    }

    #[tokio::test]
    async fn test_apply_blocklist_event_preserves_threat_intel_provenance() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), default_config());

        let event = BlocklistEvent::block_ip(
            "10.0.0.70",
            "threat intel block",
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::MeshThreatIntelPolicyGated,
                source: Some("threat_sync".to_string()),
            },
            1000,
        )
        .with_event_id("test-event-2".to_string());

        let result = store.apply_blocklist_event(&event);
        assert!(matches!(result, BlocklistApplyResult::Applied));

        let records = store.get_all_block_records();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].provenance.kind,
            BlockProvenanceKind::MeshThreatIntelPolicyGated
        );
        assert_eq!(records[0].provenance.source.as_deref(), Some("threat_sync"));
    }

    #[test]
    fn test_block_entry_serde_roundtrip_preserves_provenance() {
        let entry = BlockEntry {
            ip: "10.0.0.80".to_string(),
            reason: "test".to_string(),
            blocked_at: 1000,
            ban_expire_seconds: 3600,
            site_scope: "global".to_string(),
            access_count: 0,
            last_access: 1000,
            provenance: BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin_ban_ip".to_string()),
            },
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: BlockEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(
            deserialized.provenance.kind,
            BlockProvenanceKind::AdminManual
        );
        assert_eq!(
            deserialized.provenance.source.as_deref(),
            Some("admin_ban_ip")
        );
    }

    #[test]
    fn test_mesh_block_entry_serde_roundtrip_preserves_provenance() {
        let entry = MeshBlockEntry {
            mesh_id: "node-abc".to_string(),
            reason: "test".to_string(),
            blocked_at: 1000,
            ban_expire_seconds: 3600,
            site_scope: "global".to_string(),
            access_count: 0,
            last_access: 1000,
            provenance: BlockProvenance {
                kind: BlockProvenanceKind::SupervisorManual,
                source: Some("grpc_block_ip".to_string()),
            },
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: MeshBlockEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(
            deserialized.provenance.kind,
            BlockProvenanceKind::SupervisorManual
        );
        assert_eq!(
            deserialized.provenance.source.as_deref(),
            Some("grpc_block_ip")
        );
    }

    #[test]
    fn test_block_entry_legacy_json_defaults_to_unknown_provenance() {
        // Legacy JSON without provenance field should default to LegacyUnknown
        let json = r#"{"ip":"10.0.0.90","reason":"old","blocked_at":0,"ban_expire_seconds":3600,"site_scope":"global","access_count":0,"last_access":0}"#;
        let entry: BlockEntry = serde_json::from_str(json).unwrap();

        assert_eq!(entry.provenance.kind, BlockProvenanceKind::LegacyUnknown);
        assert_eq!(entry.provenance.source, None);
    }

    #[test]
    fn test_mesh_block_entry_legacy_json_defaults_to_unknown_provenance() {
        let json = r#"{"mesh_id":"node-old","reason":"old","blocked_at":0,"ban_expire_seconds":3600,"site_scope":"global","access_count":0,"last_access":0}"#;
        let entry: MeshBlockEntry = serde_json::from_str(json).unwrap();

        assert_eq!(entry.provenance.kind, BlockProvenanceKind::LegacyUnknown);
        assert_eq!(entry.provenance.source, None);
    }

    // ============================================================
    // Iteration 52: Persisted target state / tombstone tests
    // ============================================================

    fn target_state_config() -> DenyListLimitsConfig {
        DenyListLimitsConfig {
            max_entries: 1000,
            persist_interval_secs: 0,
            target_state_persist: true,
            target_state_max_records: 100_000,
            target_state_ttl_secs: 604_800,
        }
    }

    #[test]
    fn test_target_state_record_serialization_roundtrip() {
        let record = BlocklistTargetStateRecord {
            target_kind: BlockTargetKind::Ip,
            site_scope: "global".to_string(),
            identifier: "10.0.0.1".to_string(),
            last_operation: BlocklistOperation::Unblock,
            timestamp: 1000,
            version: Some(5),
            event_id: Some("evt-123".to_string()),
            source_node: Some("node-a".to_string()),
            provenance: BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin".to_string()),
            },
            recorded_at: 1100,
            expires_at: Some(605800),
        };

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: BlocklistTargetStateRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.target_kind, BlockTargetKind::Ip);
        assert_eq!(deserialized.site_scope, "global");
        assert_eq!(deserialized.identifier, "10.0.0.1");
        assert_eq!(deserialized.last_operation, BlocklistOperation::Unblock);
        assert_eq!(deserialized.timestamp, 1000);
        assert_eq!(deserialized.version, Some(5));
        assert_eq!(deserialized.event_id, Some("evt-123".to_string()));
        assert_eq!(deserialized.source_node, Some("node-a".to_string()));
        assert_eq!(
            deserialized.provenance.kind,
            BlockProvenanceKind::AdminManual
        );
    }

    #[test]
    fn test_target_state_record_backward_compat() {
        // Legacy JSON without optional fields should deserialize with defaults
        let json = r#"{
            "target_kind": "ip",
            "site_scope": "global",
            "identifier": "10.0.0.1",
            "last_operation": "block",
            "timestamp": 500,
            "provenance": {"kind": "legacy_unknown"},
            "recorded_at": 600
        }"#;
        let record: BlocklistTargetStateRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.version, None);
        assert_eq!(record.event_id, None);
        assert_eq!(record.source_node, None);
        assert_eq!(record.expires_at, None);
        assert!(!record.is_expired());
    }

    #[test]
    fn test_target_state_record_is_expired() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Not expired: expires_at is in the future
        let record = BlocklistTargetStateRecord {
            target_kind: BlockTargetKind::Ip,
            site_scope: "global".to_string(),
            identifier: "10.0.0.1".to_string(),
            last_operation: BlocklistOperation::Block,
            timestamp: now - 100,
            version: None,
            event_id: None,
            source_node: None,
            provenance: BlockProvenance::default(),
            recorded_at: now - 100,
            expires_at: Some(now + 3600),
        };
        assert!(!record.is_expired());

        // Expired: expires_at is in the past
        let record_expired = BlocklistTargetStateRecord {
            expires_at: Some(now - 1),
            ..record.clone()
        };
        assert!(record_expired.is_expired());

        // No expires_at: never expires
        let record_no_expiry = BlocklistTargetStateRecord {
            expires_at: None,
            ..record
        };
        assert!(!record_no_expiry.is_expired());
    }

    #[tokio::test]
    async fn test_target_state_persist_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        // Create store, apply an event, shutdown.
        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let event = BlocklistEvent::block_ip(
                "10.0.0.50",
                "persist_test",
                "global",
                BlockProvenance::default(),
                1000,
            );
            let result = store.apply_blocklist_event(&event);
            assert_eq!(result, BlocklistApplyResult::Applied);
            store.shutdown().await;
        }

        // Verify the target state file was created.
        let ts_path = temp_dir.path().join("blocklist_target_state.json");
        assert!(ts_path.exists(), "target state file should exist");

        // Create a new store from the same directory — should hydrate.
        let store2 = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config);

        // Apply an older event for the same target — should be rejected as stale.
        let old_event = BlocklistEvent::block_ip(
            "10.0.0.50",
            "old_stale_event",
            "global",
            BlockProvenance::default(),
            999, // older timestamp
        );
        let result = store2.apply_blocklist_event(&old_event);
        assert_eq!(result, BlocklistApplyResult::IgnoredStale);
    }

    #[tokio::test]
    async fn test_restart_ip_unblock_prevents_stale_block_resurrection() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        // Phase 1: Block IP, then unblock it (newer event).
        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let block_event = BlocklistEvent::block_ip(
                "10.0.0.60",
                "initial_block",
                "global",
                BlockProvenance::default(),
                1000,
            );
            assert_eq!(
                store.apply_blocklist_event(&block_event),
                BlocklistApplyResult::Applied
            );
            let unblock_event = BlocklistEvent::unblock_ip(
                "10.0.0.60",
                "global",
                BlockProvenance::default(),
                2000, // newer timestamp
            );
            assert_eq!(
                store.apply_blocklist_event(&unblock_event),
                BlocklistApplyResult::Applied
            );
            store.shutdown().await;
        }

        // Allow any in-flight async persist tasks to complete.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Phase 2: Restart. Replay the older block event.
        let store2 = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config);
        let stale_block = BlocklistEvent::block_ip(
            "10.0.0.60",
            "stale_block",
            "global",
            BlockProvenance::default(),
            500, // much older than the unblock (2000)
        );
        let result = store2.apply_blocklist_event(&stale_block);
        assert_eq!(
            result,
            BlocklistApplyResult::IgnoredStale,
            "Stale block should be rejected after restart"
        );
        // IP should NOT be blocked.
        let ip: IpAddr = "10.0.0.60".parse().unwrap();
        assert!(
            store2.is_blocked(&ip, "global").is_none(),
            "IP should remain unblocked after stale block rejection"
        );
    }

    #[tokio::test]
    async fn test_restart_mesh_id_unblock_prevents_stale_block_resurrection() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        // Phase 1: Block mesh ID, then unblock it.
        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let block_event = BlocklistEvent::block_mesh_id(
                "mesh-abc",
                "initial_block",
                "global",
                BlockProvenance::default(),
                1000,
            );
            assert_eq!(
                store.apply_blocklist_event(&block_event),
                BlocklistApplyResult::Applied
            );
            let unblock_event = BlocklistEvent::unblock_mesh_id(
                "mesh-abc",
                "global",
                BlockProvenance::default(),
                2000,
            );
            assert_eq!(
                store.apply_blocklist_event(&unblock_event),
                BlocklistApplyResult::Applied
            );
            store.shutdown().await;
        }

        // Phase 2: Restart. Replay the older block event.
        let store2 = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config);
        let stale_block = BlocklistEvent::block_mesh_id(
            "mesh-abc",
            "stale_block",
            "global",
            BlockProvenance::default(),
            500,
        );
        let result = store2.apply_blocklist_event(&stale_block);
        assert_eq!(
            result,
            BlocklistApplyResult::IgnoredStale,
            "Stale mesh-ID block should be rejected after restart"
        );
        assert!(
            store2.is_mesh_id_blocked("mesh-abc", "global").is_none(),
            "Mesh ID should remain unblocked after stale block rejection"
        );
    }

    #[tokio::test]
    async fn test_restart_ip_block_prevents_stale_unblock() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        // Phase 1: Block IP (newer event).
        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let block_event = BlocklistEvent::block_ip(
                "10.0.0.70",
                "newer_block",
                "global",
                BlockProvenance::default(),
                2000,
            );
            assert_eq!(
                store.apply_blocklist_event(&block_event),
                BlocklistApplyResult::Applied
            );
            store.shutdown().await;
        }

        // Allow any in-flight async persist tasks to complete.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Phase 2: Restart. Replay an older unblock event.
        let store2 = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config);
        let stale_unblock = BlocklistEvent::unblock_ip(
            "10.0.0.70",
            "global",
            BlockProvenance::default(),
            1000, // older than the block (2000)
        );
        let result = store2.apply_blocklist_event(&stale_unblock);
        assert_eq!(
            result,
            BlocklistApplyResult::IgnoredStale,
            "Stale unblock should be rejected after restart"
        );
        // IP should still be blocked.
        let ip: IpAddr = "10.0.0.70".parse().unwrap();
        assert!(
            store2.is_blocked(&ip, "global").is_some(),
            "IP should remain blocked after stale unblock rejection"
        );
    }

    #[tokio::test]
    async fn test_restart_mesh_id_block_prevents_stale_unblock() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        // Phase 1: Block mesh ID (newer event).
        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let block_event = BlocklistEvent::block_mesh_id(
                "mesh-xyz",
                "newer_block",
                "global",
                BlockProvenance::default(),
                2000,
            );
            assert_eq!(
                store.apply_blocklist_event(&block_event),
                BlocklistApplyResult::Applied
            );
            store.shutdown().await;
        }

        // Allow any in-flight async persist tasks to complete.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Phase 2: Restart. Replay an older unblock event.
        let store2 = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config);
        let stale_unblock =
            BlocklistEvent::unblock_mesh_id("mesh-xyz", "global", BlockProvenance::default(), 1000);
        let result = store2.apply_blocklist_event(&stale_unblock);
        assert_eq!(
            result,
            BlocklistApplyResult::IgnoredStale,
            "Stale mesh-ID unblock should be rejected after restart"
        );
        assert!(
            store2.is_mesh_id_blocked("mesh-xyz", "global").is_some(),
            "Mesh ID should remain blocked after stale unblock rejection"
        );
    }

    #[tokio::test]
    async fn test_direct_unblock_records_target_state() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());

        let ip: IpAddr = "10.0.0.80".parse().unwrap();
        // Unblock a missing target — should still record target state.
        let removed = store.unblock_ip(&ip, "global");
        assert!(!removed, "IP was never blocked");

        // Verify target state was recorded by applying an older block event.
        let old_block = BlocklistEvent::block_ip(
            "10.0.0.80",
            "old_block",
            "global",
            BlockProvenance::default(),
            0, // very old timestamp
        );
        let result = store.apply_blocklist_event(&old_block);
        assert_eq!(
            result,
            BlocklistApplyResult::IgnoredStale,
            "Old block should be rejected because unblock recorded target state"
        );
    }

    #[tokio::test]
    async fn test_direct_mesh_id_unblock_records_target_state() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());

        // Unblock a missing mesh ID — should still record target state.
        let removed = store.unblock_mesh_id("mesh-missing", "global");
        assert!(!removed, "Mesh ID was never blocked");

        // Verify target state was recorded.
        let old_block = BlocklistEvent::block_mesh_id(
            "mesh-missing",
            "old_block",
            "global",
            BlockProvenance::default(),
            0,
        );
        let result = store.apply_blocklist_event(&old_block);
        assert_eq!(
            result,
            BlocklistApplyResult::IgnoredStale,
            "Old mesh-ID block should be rejected because unblock recorded target state"
        );
    }

    #[tokio::test]
    async fn test_target_state_covers_both_ip_and_mesh_id() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());

        // Block an IP and a mesh ID.
        let ip_event = BlocklistEvent::block_ip(
            "10.0.0.90",
            "test_ip",
            "global",
            BlockProvenance::default(),
            1000,
        );
        assert_eq!(
            store.apply_blocklist_event(&ip_event),
            BlocklistApplyResult::Applied
        );

        let mesh_event = BlocklistEvent::block_mesh_id(
            "mesh-90",
            "test_mesh",
            "global",
            BlockProvenance::default(),
            1000,
        );
        assert_eq!(
            store.apply_blocklist_event(&mesh_event),
            BlocklistApplyResult::Applied
        );

        // Both stale replays should be rejected.
        let stale_ip = BlocklistEvent::block_ip(
            "10.0.0.90",
            "stale",
            "global",
            BlockProvenance::default(),
            500,
        );
        assert_eq!(
            store.apply_blocklist_event(&stale_ip),
            BlocklistApplyResult::IgnoredStale
        );

        let stale_mesh = BlocklistEvent::block_mesh_id(
            "mesh-90",
            "stale",
            "global",
            BlockProvenance::default(),
            500,
        );
        assert_eq!(
            store.apply_blocklist_event(&stale_mesh),
            BlocklistApplyResult::IgnoredStale
        );
    }

    #[tokio::test]
    async fn test_target_state_site_scope_isolation() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());

        // Block same IP in different scopes.
        let event_a = BlocklistEvent::block_ip(
            "10.0.0.95",
            "scope_a_block",
            "site_a",
            BlockProvenance::default(),
            1000,
        );
        assert_eq!(
            store.apply_blocklist_event(&event_a),
            BlocklistApplyResult::Applied
        );

        let event_b = BlocklistEvent::block_ip(
            "10.0.0.95",
            "scope_b_block",
            "site_b",
            BlockProvenance::default(),
            1000,
        );
        assert_eq!(
            store.apply_blocklist_event(&event_b),
            BlocklistApplyResult::Applied
        );

        // Stale replay for site_a should be rejected.
        let stale_a = BlocklistEvent::block_ip(
            "10.0.0.95",
            "stale",
            "site_a",
            BlockProvenance::default(),
            500,
        );
        assert_eq!(
            store.apply_blocklist_event(&stale_a),
            BlocklistApplyResult::IgnoredStale
        );
    }

    #[tokio::test]
    async fn test_target_state_persist_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let config = DenyListLimitsConfig {
            max_entries: 1000,
            persist_interval_secs: 0,
            target_state_persist: false,
            target_state_max_records: 100_000,
            target_state_ttl_secs: 604_800,
        };
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config);

        let event = BlocklistEvent::block_ip(
            "10.0.0.99",
            "no_persist",
            "global",
            BlockProvenance::default(),
            1000,
        );
        store.apply_blocklist_event(&event);

        // No target state file should be created.
        let ts_path = temp_dir.path().join("blocklist_target_state.json");
        assert!(!ts_path.exists());
    }

    #[tokio::test]
    async fn test_target_state_no_file_hydrates_cleanly() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        // First store: create and use.
        let store1 = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
        let event = BlocklistEvent::block_ip(
            "10.0.0.100",
            "first_use",
            "global",
            BlockProvenance::default(),
            1000,
        );
        assert_eq!(
            store1.apply_blocklist_event(&event),
            BlocklistApplyResult::Applied
        );
        store1.shutdown().await;

        // Second store: should load from disk.
        let store2 = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
        // Stale event should be rejected.
        let stale = BlocklistEvent::block_ip(
            "10.0.0.100",
            "stale",
            "global",
            BlockProvenance::default(),
            500,
        );
        assert_eq!(
            store2.apply_blocklist_event(&stale),
            BlocklistApplyResult::IgnoredStale
        );

        // Third store: no file exists — should start fresh without errors.
        let temp_dir2 = TempDir::new().unwrap();
        let store3 = BlockStore::new(true, Some(temp_dir2.path().to_path_buf()), config);
        let event2 = BlocklistEvent::block_ip(
            "10.0.0.101",
            "fresh",
            "global",
            BlockProvenance::default(),
            1000,
        );
        assert_eq!(
            store3.apply_blocklist_event(&event2),
            BlocklistApplyResult::Applied
        );
    }

    // ============================================================
    // Iteration 53: Provenance preservation in target-state persistence
    // ============================================================

    #[tokio::test]
    async fn test_event_apply_preserves_provenance_through_persist_reload() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        // Phase 1: Apply a block event with specific provenance, shutdown.
        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let provenance = BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin-api".to_string()),
            };
            let event = BlocklistEvent {
                operation: BlocklistOperation::Block,
                target_kind: BlockTargetKind::Ip,
                identifier: "10.0.0.99".to_string(),
                site_scope: "global".to_string(),
                reason: Some("admin ban".to_string()),
                provenance,
                timestamp: 5000,
                source_node: Some("node-alpha".to_string()),
                event_id: Some("evt-prov-1".to_string()),
                ttl_secs: Some(3600),
                version: Some(10),
            };
            assert_eq!(
                store.apply_blocklist_event(&event),
                BlocklistApplyResult::Applied
            );
            store.shutdown().await;
        }

        // Phase 2: Restart and verify the persisted JSON carries provenance.
        let ts_path = temp_dir.path().join("blocklist_target_state.json");
        let content = std::fs::read_to_string(&ts_path).unwrap();
        let records: Vec<BlocklistTargetStateRecord> = serde_json::from_str(&content).unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.identifier, "10.0.0.99");
        assert_eq!(record.source_node, Some("node-alpha".to_string()));
        assert_eq!(record.provenance.kind, BlockProvenanceKind::AdminManual);
        assert_eq!(record.provenance.source, Some("admin-api".to_string()));
        assert_eq!(record.version, Some(10));
        assert_eq!(record.event_id, Some("evt-prov-1".to_string()));
    }

    #[tokio::test]
    async fn test_event_unblock_preserves_provenance_through_persist_reload() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let provenance = BlockProvenance {
                kind: BlockProvenanceKind::SupervisorSync,
                source: Some("supervisor".to_string()),
            };
            let event = BlocklistEvent {
                operation: BlocklistOperation::Unblock,
                target_kind: BlockTargetKind::MeshId,
                identifier: "mesh-prov-test".to_string(),
                site_scope: "global".to_string(),
                reason: None,
                provenance,
                timestamp: 6000,
                source_node: Some("supervisor-node".to_string()),
                event_id: Some("evt-unblock-prov".to_string()),
                ttl_secs: None,
                version: Some(20),
            };
            assert_eq!(
                store.apply_blocklist_event(&event),
                BlocklistApplyResult::Applied
            );
            store.shutdown().await;
        }

        let ts_path = temp_dir.path().join("blocklist_target_state.json");
        let content = std::fs::read_to_string(&ts_path).unwrap();
        let records: Vec<BlocklistTargetStateRecord> = serde_json::from_str(&content).unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.identifier, "mesh-prov-test");
        assert_eq!(record.source_node, Some("supervisor-node".to_string()));
        assert_eq!(record.provenance.kind, BlockProvenanceKind::SupervisorSync);
        assert_eq!(record.provenance.source, Some("supervisor".to_string()));
    }

    #[tokio::test]
    async fn test_stale_event_does_not_overwrite_stored_provenance() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        // Phase 1: Apply a block with AdminManual provenance (newer).
        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let event = BlocklistEvent {
                operation: BlocklistOperation::Block,
                target_kind: BlockTargetKind::Ip,
                identifier: "10.0.0.101".to_string(),
                site_scope: "global".to_string(),
                reason: Some("newer ban".to_string()),
                provenance: BlockProvenance {
                    kind: BlockProvenanceKind::AdminManual,
                    source: Some("admin".to_string()),
                },
                timestamp: 5000,
                source_node: Some("admin-node".to_string()),
                event_id: Some("evt-newer".to_string()),
                ttl_secs: Some(3600),
                version: Some(5),
            };
            assert_eq!(
                store.apply_blocklist_event(&event),
                BlocklistApplyResult::Applied
            );
            store.shutdown().await;
        }

        // Phase 2: Restart, apply an older block with different provenance.
        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let stale_event = BlocklistEvent {
                operation: BlocklistOperation::Block,
                target_kind: BlockTargetKind::Ip,
                identifier: "10.0.0.101".to_string(),
                site_scope: "global".to_string(),
                reason: Some("stale ban".to_string()),
                provenance: BlockProvenance {
                    kind: BlockProvenanceKind::MeshThreatIntelPolicyGated,
                    source: Some("mesh-peer".to_string()),
                },
                timestamp: 1000,
                source_node: Some("other-node".to_string()),
                event_id: Some("evt-stale".to_string()),
                ttl_secs: Some(3600),
                version: Some(1),
            };
            assert_eq!(
                store.apply_blocklist_event(&stale_event),
                BlocklistApplyResult::IgnoredStale
            );
            store.shutdown().await;
        }

        // Phase 3: Verify the persisted record still has the newer provenance.
        let ts_path = temp_dir.path().join("blocklist_target_state.json");
        let content = std::fs::read_to_string(&ts_path).unwrap();
        let records: Vec<BlocklistTargetStateRecord> = serde_json::from_str(&content).unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(
            record.provenance.kind,
            BlockProvenanceKind::AdminManual,
            "Stale event should not overwrite stored provenance"
        );
        assert_eq!(
            record.source_node,
            Some("admin-node".to_string()),
            "Stale event should not overwrite stored source_node"
        );
    }

    #[tokio::test]
    async fn test_direct_block_ip_with_provenance_persists_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());

        let ip: IpAddr = "10.0.0.200".parse().unwrap();
        let provenance = BlockProvenance {
            kind: BlockProvenanceKind::AdminManual,
            source: Some("admin-dashboard".to_string()),
        };
        store.block_ip_with_provenance(ip, "admin block", 3600, "global", provenance.clone());

        // Verify target state was recorded with provenance by checking
        // that a stale event from a different source is rejected.
        let stale_event = BlocklistEvent {
            operation: BlocklistOperation::Block,
            target_kind: BlockTargetKind::Ip,
            identifier: "10.0.0.200".to_string(),
            site_scope: "global".to_string(),
            reason: Some("stale".to_string()),
            provenance: BlockProvenance {
                kind: BlockProvenanceKind::MeshThreatIntelPolicyGated,
                source: None,
            },
            timestamp: 1, // very old
            source_node: None,
            event_id: None,
            ttl_secs: Some(3600),
            version: None,
        };
        assert_eq!(
            store.apply_blocklist_event(&stale_event),
            BlocklistApplyResult::IgnoredStale,
            "Direct block should have recorded target state preventing stale replay"
        );

        // Shutdown and verify persisted JSON carries the provenance.
        store.shutdown().await;
        let ts_path = temp_dir.path().join("blocklist_target_state.json");
        let content = std::fs::read_to_string(&ts_path).unwrap();
        let records: Vec<BlocklistTargetStateRecord> = serde_json::from_str(&content).unwrap();
        let record = records
            .iter()
            .find(|r| r.identifier == "10.0.0.200")
            .unwrap();
        assert_eq!(record.provenance.kind, BlockProvenanceKind::AdminManual);
        assert_eq!(
            record.provenance.source,
            Some("admin-dashboard".to_string())
        );
    }

    #[tokio::test]
    async fn test_direct_block_mesh_id_with_provenance_persists_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();
        let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());

        let provenance = BlockProvenance {
            kind: BlockProvenanceKind::SupervisorManual,
            source: Some("supervisor".to_string()),
        };
        store.block_mesh_id_with_provenance(
            "mesh-prov-direct",
            "supervisor block",
            3600,
            "global",
            provenance.clone(),
        );

        // Verify via stale event rejection.
        let stale_event = BlocklistEvent {
            operation: BlocklistOperation::Block,
            target_kind: BlockTargetKind::MeshId,
            identifier: "mesh-prov-direct".to_string(),
            site_scope: "global".to_string(),
            reason: Some("stale".to_string()),
            provenance: BlockProvenance::default(),
            timestamp: 1,
            source_node: None,
            event_id: None,
            ttl_secs: Some(3600),
            version: None,
        };
        assert_eq!(
            store.apply_blocklist_event(&stale_event),
            BlocklistApplyResult::IgnoredStale,
            "Direct mesh-ID block should have recorded target state"
        );

        // Shutdown and verify persisted JSON.
        store.shutdown().await;
        let ts_path = temp_dir.path().join("blocklist_target_state.json");
        let content = std::fs::read_to_string(&ts_path).unwrap();
        let records: Vec<BlocklistTargetStateRecord> = serde_json::from_str(&content).unwrap();
        let record = records
            .iter()
            .find(|r| r.identifier == "mesh-prov-direct")
            .unwrap();
        assert_eq!(
            record.provenance.kind,
            BlockProvenanceKind::SupervisorManual
        );
    }

    #[tokio::test]
    async fn test_hydration_restores_provenance_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        // Phase 1: Apply event with provenance, shutdown.
        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let event = BlocklistEvent {
                operation: BlocklistOperation::Block,
                target_kind: BlockTargetKind::Ip,
                identifier: "10.0.0.201".to_string(),
                site_scope: "global".to_string(),
                reason: Some("hydration test".to_string()),
                provenance: BlockProvenance {
                    kind: BlockProvenanceKind::LocalWaf,
                    source: Some("waf-engine".to_string()),
                },
                timestamp: 7000,
                source_node: Some("waf-node".to_string()),
                event_id: Some("evt-hydration".to_string()),
                ttl_secs: Some(3600),
                version: Some(3),
            };
            assert_eq!(
                store.apply_blocklist_event(&event),
                BlocklistApplyResult::Applied
            );
            store.shutdown().await;
        }

        // Phase 2: Restart and verify the hydrated state still rejects stale.
        let store2 = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config);
        let stale = BlocklistEvent::block_ip(
            "10.0.0.201",
            "stale",
            "global",
            BlockProvenance::default(),
            1000,
        );
        assert_eq!(
            store2.apply_blocklist_event(&stale),
            BlocklistApplyResult::IgnoredStale,
            "Hydrated target state should preserve freshness"
        );
    }

    #[tokio::test]
    async fn test_catchup_after_restart_uses_persisted_target_state() {
        let temp_dir = TempDir::new().unwrap();
        let config = target_state_config();

        // Phase 1: Apply an unblock, shutdown.
        {
            let store = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config.clone());
            let unblock = BlocklistEvent::unblock_ip(
                "10.0.0.110",
                "global",
                BlockProvenance::default(),
                2000,
            );
            assert_eq!(
                store.apply_blocklist_event(&unblock),
                BlocklistApplyResult::Applied
            );
            store.shutdown().await;
        }

        // Phase 2: Restart. Replay an older block via catchup (simulated).
        let store2 = BlockStore::new(true, Some(temp_dir.path().to_path_buf()), config);
        let stale_block = BlocklistEvent::block_ip(
            "10.0.0.110",
            "catchup_stale_block",
            "global",
            BlockProvenance::default(),
            1000, // older than unblock (2000)
        )
        .with_event_id("catchup-evt-1".to_string());

        // This simulates what transport_peer.rs does for catchup replay.
        let result = store2.apply_blocklist_event(&stale_block);
        assert_eq!(
            result,
            BlocklistApplyResult::IgnoredStale,
            "Stale block from catchup should be rejected after restart"
        );
    }

    // ==================== Blocklist Snapshot Tests (Iteration 56) ====================

    #[test]
    fn test_export_snapshot_includes_ip_blocks_with_provenance() {
        let store = BlockStore::new(true, None, default_config());
        let prov = BlockProvenance {
            kind: BlockProvenanceKind::AdminManual,
            source: Some("admin".to_string()),
        };
        store.block_ip_with_provenance(
            "10.0.0.1".parse().unwrap(),
            "test_block",
            3600,
            "global",
            prov.clone(),
        );

        let options = BlocklistSnapshotOptions {
            include_ip_blocks: true,
            include_mesh_id_blocks: true,
            include_target_state: false,
            site_scope: None,
            max_items: 100,
        };
        let chunk = store.export_blocklist_snapshot(&options, &BlocklistSnapshotCursor::default());
        assert_eq!(chunk.ip_blocks.len(), 1);
        assert_eq!(chunk.ip_blocks[0].identifier, "10.0.0.1");
        assert_eq!(
            chunk.ip_blocks[0].provenance.kind,
            BlockProvenanceKind::AdminManual
        );
    }

    #[test]
    fn test_export_snapshot_includes_mesh_blocks_with_provenance() {
        let store = BlockStore::new(true, None, default_config());
        let prov = BlockProvenance {
            kind: BlockProvenanceKind::MeshThreatIntelPolicyGated,
            source: Some("mesh".to_string()),
        };
        store.block_mesh_id_with_provenance("mesh-1", "attack", 3600, "global", prov);

        let options = BlocklistSnapshotOptions {
            include_ip_blocks: true,
            include_mesh_id_blocks: true,
            include_target_state: false,
            site_scope: None,
            max_items: 100,
        };
        let chunk = store.export_blocklist_snapshot(&options, &BlocklistSnapshotCursor::default());
        assert_eq!(chunk.mesh_blocks.len(), 1);
        assert_eq!(chunk.mesh_blocks[0].identifier, "mesh-1");
        assert_eq!(
            chunk.mesh_blocks[0].provenance.kind,
            BlockProvenanceKind::MeshThreatIntelPolicyGated
        );
    }

    #[test]
    fn test_export_snapshot_respects_page_size() {
        let store = BlockStore::new(true, None, default_config());
        for i in 0..10 {
            store.add_block(&format!("10.0.0.{}", i), "test", 3600, "global");
        }

        let options = BlocklistSnapshotOptions {
            include_ip_blocks: true,
            include_mesh_id_blocks: false,
            include_target_state: false,
            site_scope: None,
            max_items: 3,
        };
        let chunk = store.export_blocklist_snapshot(&options, &BlocklistSnapshotCursor::default());
        assert_eq!(chunk.ip_blocks.len(), 3);
        assert!(chunk.has_more);
        assert!(chunk.next_page_token.is_some());
    }

    #[test]
    fn test_export_snapshot_produces_stable_next_page_token() {
        let store = BlockStore::new(true, None, default_config());
        for i in 0..5 {
            store.add_block(&format!("10.0.0.{}", i), "test", 3600, "global");
        }

        let options = BlocklistSnapshotOptions {
            include_ip_blocks: true,
            include_mesh_id_blocks: false,
            include_target_state: false,
            site_scope: None,
            max_items: 2,
        };
        let page1 = store.export_blocklist_snapshot(&options, &BlocklistSnapshotCursor::default());
        assert!(page1.has_more);
        let token = page1.next_page_token.clone().unwrap();

        let cursor = BlocklistSnapshotCursor {
            page_token: Some(token),
        };
        let page2 = store.export_blocklist_snapshot(&options, &cursor);
        assert_eq!(page2.ip_blocks.len(), 2);

        let cursor2 = BlocklistSnapshotCursor {
            page_token: page2.next_page_token.clone(),
        };
        let page3 = store.export_blocklist_snapshot(&options, &cursor2);
        assert_eq!(page3.ip_blocks.len(), 1);
        assert!(!page3.has_more);
    }

    #[test]
    fn test_export_snapshot_filters_by_site_scope() {
        let store = BlockStore::new(true, None, default_config());
        store.add_block("10.0.0.1", "test", 3600, "site-a");
        store.add_block("10.0.0.2", "test", 3600, "site-b");

        let options = BlocklistSnapshotOptions {
            include_ip_blocks: true,
            include_mesh_id_blocks: false,
            include_target_state: false,
            site_scope: Some("site-a".to_string()),
            max_items: 100,
        };
        let chunk = store.export_blocklist_snapshot(&options, &BlocklistSnapshotCursor::default());
        assert_eq!(chunk.ip_blocks.len(), 1);
        assert_eq!(chunk.ip_blocks[0].site_scope, "site-a");
    }

    #[test]
    fn test_apply_snapshot_adds_ip_block_entry() {
        let store = BlockStore::new(true, None, default_config());
        let chunk = BlocklistSnapshotChunk {
            ip_blocks: vec![BlockRecord {
                target_kind: BlockTargetKind::Ip,
                identifier: "10.0.0.99".to_string(),
                reason: "snapshot_test".to_string(),
                blocked_at: synvoid_utils::safe_unix_timestamp(),
                ban_expire_seconds: 3600,
                site_scope: "global".to_string(),
                access_count: 0,
                last_access: 0,
                provenance: BlockProvenance::default(),
            }],
            mesh_blocks: Vec::new(),
            target_state_records: Vec::new(),
            next_page_token: None,
            has_more: false,
            snapshot_complete: true,
            truncated_reason: None,
        };

        let result = store.apply_blocklist_snapshot(&chunk);
        assert_eq!(result.ip_blocks_applied, 1);
        assert!(store
            .is_blocked(&"10.0.0.99".parse().unwrap(), "global")
            .is_some());
    }

    #[test]
    fn test_apply_snapshot_adds_mesh_block_entry() {
        let store = BlockStore::new(true, None, default_config());
        let chunk = BlocklistSnapshotChunk {
            ip_blocks: Vec::new(),
            mesh_blocks: vec![BlockRecord {
                target_kind: BlockTargetKind::MeshId,
                identifier: "mesh-snap-1".to_string(),
                reason: "snapshot_test".to_string(),
                blocked_at: synvoid_utils::safe_unix_timestamp(),
                ban_expire_seconds: 3600,
                site_scope: "global".to_string(),
                access_count: 0,
                last_access: 0,
                provenance: BlockProvenance::default(),
            }],
            target_state_records: Vec::new(),
            next_page_token: None,
            has_more: false,
            snapshot_complete: true,
            truncated_reason: None,
        };

        let result = store.apply_blocklist_snapshot(&chunk);
        assert_eq!(result.mesh_blocks_applied, 1);
        assert!(store.is_mesh_id_blocked("mesh-snap-1", "global").is_some());
    }

    #[test]
    fn test_apply_snapshot_preserves_provenance() {
        let store = BlockStore::new(true, None, default_config());
        let prov = BlockProvenance {
            kind: BlockProvenanceKind::SupervisorSync,
            source: Some("supervisor".to_string()),
        };
        let chunk = BlocklistSnapshotChunk {
            ip_blocks: vec![BlockRecord {
                target_kind: BlockTargetKind::Ip,
                identifier: "10.0.0.50".to_string(),
                reason: "provenance_test".to_string(),
                blocked_at: synvoid_utils::safe_unix_timestamp(),
                ban_expire_seconds: 3600,
                site_scope: "global".to_string(),
                access_count: 0,
                last_access: 0,
                provenance: prov.clone(),
            }],
            mesh_blocks: Vec::new(),
            target_state_records: Vec::new(),
            next_page_token: None,
            has_more: false,
            snapshot_complete: true,
            truncated_reason: None,
        };

        store.apply_blocklist_snapshot(&chunk);
        let records = store.get_all_block_records();
        let record = records
            .iter()
            .find(|r| r.identifier == "10.0.0.50")
            .unwrap();
        assert_eq!(record.provenance.kind, BlockProvenanceKind::SupervisorSync);
        assert_eq!(record.provenance.source, Some("supervisor".to_string()));
    }

    #[test]
    fn test_apply_snapshot_ignores_invalid_ip_records() {
        let store = BlockStore::new(true, None, default_config());
        let chunk = BlocklistSnapshotChunk {
            ip_blocks: vec![BlockRecord {
                target_kind: BlockTargetKind::Ip,
                identifier: "not-an-ip".to_string(),
                reason: "test".to_string(),
                blocked_at: synvoid_utils::safe_unix_timestamp(),
                ban_expire_seconds: 3600,
                site_scope: "global".to_string(),
                access_count: 0,
                last_access: 0,
                provenance: BlockProvenance::default(),
            }],
            mesh_blocks: Vec::new(),
            target_state_records: Vec::new(),
            next_page_token: None,
            has_more: false,
            snapshot_complete: true,
            truncated_reason: None,
        };

        let result = store.apply_blocklist_snapshot(&chunk);
        assert_eq!(result.invalid_records_ignored, 1);
        assert_eq!(result.ip_blocks_applied, 0);
    }

    #[test]
    fn test_apply_snapshot_ignores_expired_records() {
        let store = BlockStore::new(true, None, default_config());
        let chunk = BlocklistSnapshotChunk {
            ip_blocks: vec![BlockRecord {
                target_kind: BlockTargetKind::Ip,
                identifier: "10.0.0.1".to_string(),
                reason: "test".to_string(),
                blocked_at: 100,          // very old timestamp
                ban_expire_seconds: 3600, // expired long ago
                site_scope: "global".to_string(),
                access_count: 0,
                last_access: 0,
                provenance: BlockProvenance::default(),
            }],
            mesh_blocks: Vec::new(),
            target_state_records: Vec::new(),
            next_page_token: None,
            has_more: false,
            snapshot_complete: true,
            truncated_reason: None,
        };

        let result = store.apply_blocklist_snapshot(&chunk);
        assert_eq!(result.expired_records_ignored, 1);
        assert_eq!(result.ip_blocks_applied, 0);
    }

    #[test]
    fn test_apply_snapshot_does_not_overwrite_newer_unblock_with_older_block() {
        let store = BlockStore::new(true, None, default_config());
        let now = synvoid_utils::safe_unix_timestamp();

        // First: unblock via event (creates a newer target state entry).
        let unblock =
            BlocklistEvent::unblock_ip("10.0.0.1", "global", BlockProvenance::default(), now);
        store.apply_blocklist_event(&unblock);

        // Now: try to apply a snapshot with an older block (but not expired).
        let chunk = BlocklistSnapshotChunk {
            ip_blocks: vec![BlockRecord {
                target_kind: BlockTargetKind::Ip,
                identifier: "10.0.0.1".to_string(),
                reason: "old_block".to_string(),
                blocked_at: now - 100, // older than unblock but still valid
                ban_expire_seconds: 3600,
                site_scope: "global".to_string(),
                access_count: 0,
                last_access: 0,
                provenance: BlockProvenance::default(),
            }],
            mesh_blocks: Vec::new(),
            target_state_records: Vec::new(),
            next_page_token: None,
            has_more: false,
            snapshot_complete: true,
            truncated_reason: None,
        };

        let result = store.apply_blocklist_snapshot(&chunk);
        assert_eq!(result.stale_records_ignored, 1);
        assert!(store
            .is_blocked(&"10.0.0.1".parse().unwrap(), "global")
            .is_none());
    }

    #[test]
    fn test_apply_snapshot_respects_site_scope() {
        let store = BlockStore::new(true, None, default_config());
        let chunk = BlocklistSnapshotChunk {
            ip_blocks: vec![BlockRecord {
                target_kind: BlockTargetKind::Ip,
                identifier: "10.0.0.1".to_string(),
                reason: "test".to_string(),
                blocked_at: synvoid_utils::safe_unix_timestamp(),
                ban_expire_seconds: 3600,
                site_scope: "site-a".to_string(),
                access_count: 0,
                last_access: 0,
                provenance: BlockProvenance::default(),
            }],
            mesh_blocks: Vec::new(),
            target_state_records: Vec::new(),
            next_page_token: None,
            has_more: false,
            snapshot_complete: true,
            truncated_reason: None,
        };

        store.apply_blocklist_snapshot(&chunk);
        assert!(store
            .is_blocked(&"10.0.0.1".parse().unwrap(), "site-a")
            .is_some());
        assert!(store
            .is_blocked(&"10.0.0.1".parse().unwrap(), "site-b")
            .is_none());
    }

    #[test]
    fn test_apply_snapshot_empty_mesh_id_ignored() {
        let store = BlockStore::new(true, None, default_config());
        let chunk = BlocklistSnapshotChunk {
            ip_blocks: Vec::new(),
            mesh_blocks: vec![BlockRecord {
                target_kind: BlockTargetKind::MeshId,
                identifier: "".to_string(), // empty mesh ID
                reason: "test".to_string(),
                blocked_at: synvoid_utils::safe_unix_timestamp(),
                ban_expire_seconds: 3600,
                site_scope: "global".to_string(),
                access_count: 0,
                last_access: 0,
                provenance: BlockProvenance::default(),
            }],
            target_state_records: Vec::new(),
            next_page_token: None,
            has_more: false,
            snapshot_complete: true,
            truncated_reason: None,
        };

        let result = store.apply_blocklist_snapshot(&chunk);
        assert_eq!(result.invalid_records_ignored, 1);
        assert_eq!(result.mesh_blocks_applied, 0);
    }

    #[test]
    fn test_catchup_history_gap_sets_snapshot_required() {
        let store = BlockStore::new(true, None, default_config());

        // Append enough events to exceed the log capacity.
        for i in 0..15000 {
            let event = BlocklistEvent::block_ip(
                &format!("10.0.{}.{}", (i / 256) % 256, i % 256),
                "gap_test",
                "global",
                BlockProvenance::default(),
                i as u64,
            );
            store.record_blocklist_event_for_catchup(&event);
        }

        // Query with a cursor that refers to an evicted sequence.
        let cursor = BlocklistEventCursor {
            since_sequence: Some(100), // well before the oldest retained
            max_events: 500,
        };
        let result = store.query_blocklist_catchup(&cursor);
        assert!(
            result.snapshot_required,
            "History gap should set snapshot_required"
        );
        assert!(!result.history_complete);
    }
}
