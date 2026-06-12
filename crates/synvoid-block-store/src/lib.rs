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
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use synvoid_config::DenyListLimitsConfig;
use tokio::sync::mpsc;

pub use synvoid_core::block_store::{BlockProvenance, BlockProvenanceKind};
use synvoid_waf::mitigation::{MitigationProvider, SizedMitigationProvider};

pub type GlobalBlockHook = Arc<dyn Fn(IpAddr) + Send + Sync>;

const DEFAULT_MAX_ENTRIES: usize = 500_000;
const NUM_SHARDS: usize = 64;

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
    enabled: bool,
    persist_path: Option<PathBuf>,
    config: DenyListLimitsConfig,
    total_entries: AtomicUsize,
    persist_tx: Option<mpsc::Sender<PersistRequest>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    mitigation_provider: arc_swap::ArcSwapOption<SizedMitigationProvider>,
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
}

impl BlockStore {
    pub fn new(enabled: bool, data_dir: Option<PathBuf>, config: DenyListLimitsConfig) -> Self {
        let persist_path = data_dir.map(|d| d.join("blocks.json"));
        let max_entries = if config.max_entries > 0 {
            config.max_entries
        } else {
            DEFAULT_MAX_ENTRIES
        };

        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(RwLock::new(AHashMap::new()));
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

        let (persist_tx, shutdown_tx) =
            if config.persist_interval_secs > 0 && persist_path.is_some() {
                let (tx, mut rx): (mpsc::Sender<PersistRequest>, mpsc::Receiver<PersistRequest>) =
                    mpsc::channel(100);
                let (shutdown_tx, mut shutdown_rx): (mpsc::Sender<()>, mpsc::Receiver<()>) =
                    mpsc::channel(1);
                let path = persist_path.clone().unwrap();
                let max_entries_clone = max_entries;

                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                        config.persist_interval_secs,
                    ));
                    let mut pending: Option<Vec<(String, BlockEntry)>> = None;

                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                if let Some(entries) = pending.take() {
                                    Self::persist_to_disk(&path, entries, max_entries_clone).await;
                                }
                            }
                            Some(req) = rx.recv() => {
                                pending = Some(req.entries);
                            }
                            _ = shutdown_rx.recv() => {
                                if let Some(entries) = pending.take() {
                                    Self::persist_to_disk(&path, entries, max_entries_clone).await;
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

        Self {
            shards,
            enabled,
            persist_path,
            config,
            total_entries: AtomicUsize::new(initial_count),
            persist_tx,
            shutdown_tx,
            mitigation_provider: arc_swap::ArcSwapOption::const_empty(),
        }
    }

    /// Set the mitigation provider for kernel-level blocking.
    pub fn set_mitigation_provider(&self, provider: Option<Arc<dyn MitigationProvider>>) {
        self.mitigation_provider
            .store(provider.map(|p| Arc::new(SizedMitigationProvider(p))));
    }

    /// Gracefully shutdown the block store, persisting any pending data.
    pub async fn shutdown(&self) {
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
            match tx.try_send(PersistRequest { entries }) {
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
            let path = path.clone();
            let max_entries = self.config.max_entries;
            tokio::spawn(async move {
                Self::persist_to_disk(&path, entries, max_entries).await;
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

        let entry = BlockEntry::new(
            ip,
            reason.to_string(),
            ban_expire_seconds,
            site_scope.to_string(),
        );
        let key = BlockEntry::key(site_scope, &ip);
        let idx = Self::shard_index(&key);

        self.shards[idx].write().insert(key, entry);
        self.total_entries.fetch_add(1, Ordering::Relaxed);

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

        let entry = BlockEntry::new_with_provenance(
            ip,
            reason.to_string(),
            ban_expire_seconds,
            site_scope.to_string(),
            provenance,
        );
        let key = BlockEntry::key(site_scope, &ip);
        let idx = Self::shard_index(&key);

        self.shards[idx].write().insert(key, entry);
        self.total_entries.fetch_add(1, Ordering::Relaxed);

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

    fn remove_entry(&self, key: &str) {
        let idx = Self::shard_index(key);
        let removed = self.shards[idx].write().remove(key).is_some();
        if removed {
            let _ = self
                .total_entries
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
            self.trigger_persist();
        }
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

        let key = BlockEntry::key(site_scope, ip);
        self.remove_entry(&key);

        let global_key = BlockEntry::key("global", ip);
        self.remove_entry(&global_key);

        true
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

            if store.len() >= self.config.max_entries {
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
            self.total_entries.fetch_add(1, Ordering::Relaxed);

            return true;
        }

        false
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
}
