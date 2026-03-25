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

use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use crate::config::DenyListLimitsConfig;

const DEFAULT_MAX_ENTRIES: usize = 500_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    pub ip: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub access_count: u64,
    pub last_access: u64,
}

impl BlockEntry {
    pub fn new(ip: IpAddr, reason: String, ban_expire_seconds: u64, site_scope: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        Self {
            ip: ip.to_string(),
            reason,
            blocked_at: now,
            ban_expire_seconds,
            site_scope,
            access_count: 0,
            last_access: now,
        }
    }

    pub fn is_permanent(&self) -> bool {
        self.ban_expire_seconds == 0
    }

    pub fn is_expired(&self) -> bool {
        if self.is_permanent() {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        now > self.blocked_at + self.ban_expire_seconds
    }

    pub fn key(site_scope: &str, ip: &IpAddr) -> String {
        format!("block:{}:{}", site_scope, ip)
    }

    pub fn update_access(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        self.access_count += 1;
        self.last_access = now;
    }
}

pub struct BlockStore {
    store: Arc<RwLock<HashMap<String, BlockEntry>>>,
    enabled: bool,
    persist_path: Option<PathBuf>,
    config: DenyListLimitsConfig,
    total_entries: AtomicUsize,
    persist_tx: Option<mpsc::Sender<PersistRequest>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

#[derive(Debug, Clone)]
struct PersistRequest {
    entries: HashMap<String, BlockEntry>,
}

impl BlockStore {
    pub fn new(enabled: bool, data_dir: Option<PathBuf>, config: DenyListLimitsConfig) -> Self {
        let persist_path = data_dir.map(|d| d.join("blocks.json"));
        let max_entries = if config.max_entries > 0 {
            config.max_entries
        } else {
            DEFAULT_MAX_ENTRIES
        };

        let store: HashMap<String, BlockEntry> = if let Some(ref path) = persist_path {
            if path.exists() {
                match std::fs::read_to_string(path) {
                    Ok(content) => {
                        match serde_json::from_str::<Vec<BlockEntry>>(&content) {
                            Ok(entries) => {
                                let mut validated = HashMap::new();
                                let mut parse_errors = 0;
                                for e in entries {
                                    match e.ip.parse::<IpAddr>() {
                                        Ok(ip) => {
                                            if !e.is_expired() {
                                                validated.insert(BlockEntry::key(&e.site_scope, &ip), e);
                                            }
                                        }
                                        Err(_) => {
                                            parse_errors += 1;
                                            tracing::warn!("Skipping block entry with invalid IP: {}", e.ip);
                                        }
                                    }
                                }
                                if parse_errors > 0 {
                                    tracing::warn!("Skipped {} block entries with invalid IPs", parse_errors);
                                }
                                tracing::info!("Loaded {} valid block entries from disk", validated.len());
                                validated
                            }
                            Err(e) => {
                                tracing::warn!("Failed to parse blocks.json: {}, starting fresh", e);
                                HashMap::new()
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to read blocks.json: {}, starting fresh", e);
                        HashMap::new()
                    }
                }
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        };

        let initial_count = store.len();
        let (persist_tx, shutdown_tx) = if config.persist_interval_secs > 0 && persist_path.is_some() {
            let (tx, mut rx): (mpsc::Sender<PersistRequest>, mpsc::Receiver<PersistRequest>) = mpsc::channel(100);
            let (shutdown_tx, mut shutdown_rx): (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel(1);
            let path = persist_path.clone().unwrap();
            let max_entries_clone = max_entries;
            
            let _ = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(config.persist_interval_secs));
                let mut pending: Option<HashMap<String, BlockEntry>> = None;
                
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
            store: Arc::new(RwLock::new(store)),
            enabled,
            persist_path,
            config,
            total_entries: AtomicUsize::new(initial_count),
            persist_tx,
            shutdown_tx,
        }
    }

    /// Gracefully shutdown the block store, persisting any pending data.
    pub async fn shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }
    }

    pub(crate) async fn persist_to_disk(path: &PathBuf, entries: HashMap<String, BlockEntry>, max_entries: usize) {
        let entries_to_save: Vec<BlockEntry> = entries
            .values()
            .filter(|e| !e.is_expired())
            .take(max_entries)
            .cloned()
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
            let store = self.store.read().clone();
            match tx.try_send(PersistRequest { entries: store }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!("Block store persist channel full, skipping persist");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    tracing::error!("Block store persist channel closed");
                }
            }
        } else if let Some(ref path) = self.persist_path {
            let store = self.store.read().clone();
            let path = path.clone();
            let max_entries = self.config.max_entries;
            let _ = tokio::spawn(async move {
                Self::persist_to_disk(&path, store, max_entries).await;
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

    /// Block an IP address.
    ///
    /// Adds an IP to the blocklist with the given reason and duration.
    ///
    /// # Arguments
    /// * `ip` - The IP address to block
    /// * `reason` - Reason for blocking (e.g., "rate_limit", "attack")
    /// * `ban_expire_seconds` - Duration of block in seconds (0 = permanent)
    /// * `site_scope` - Scope of block ("global" or site-specific)
    ///
    /// # Returns
    /// `true` if the IP was successfully blocked, `false` if store is full or disabled
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
            tracing::warn!(
                "Block store at capacity ({} >= {}), cannot add new block",
                current,
                max_entries
            );
            return false;
        }

        let entry = BlockEntry::new(
            ip,
            reason.to_string(),
            ban_expire_seconds,
            site_scope.to_string(),
        );
        let key = BlockEntry::key(site_scope, &ip);

        self.store.write().insert(key, entry);
        self.total_entries.fetch_add(1, Ordering::Relaxed);
        
        tracing::info!("Blocked IP {} for {} (scope: {})", ip, reason, site_scope);

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
        
        // First try with read lock for quick path
        {
            let store = self.store.read();
            if let Some(entry) = store.get(&key) {
                if !entry.is_expired() {
                    return Some(entry.clone());
                }
            }
        }
        
        // Need write lock for modification/cleanup
        let mut store = self.store.write();
        
        if let Some(entry) = store.get_mut(&key) {
            if !entry.is_expired() {
                entry.update_access();
                return Some(entry.clone());
            } else {
                store.remove(&key);
                self.total_entries.fetch_sub(1, Ordering::Relaxed);
            }
        }

        if site_scope != "global" {
            let global_key = BlockEntry::key("global", ip);
            
            // Quick read check for global
            {
                let store = self.store.read();
                if let Some(entry) = store.get(&global_key) {
                    if !entry.is_expired() {
                        return Some(entry.clone());
                    }
                }
            }
            
            if let Some(entry) = store.get_mut(&global_key) {
                if !entry.is_expired() {
                    entry.update_access();
                    return Some(entry.clone());
                } else {
                    store.remove(&global_key);
                    self.total_entries.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }

        None
    }

    fn remove_entry(&self, key: &str) {
        let removed = self.store.write().remove(key).is_some();
        if removed {
            self.total_entries.fetch_sub(1, Ordering::Relaxed);
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
        
        {
            let store = self.store.read();
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
            utilization_percent: if max > 0 { (total as f64 / max as f64) * 100.0 } else { 0.0 },
        }
    }

    pub fn get_all_entries(&self) -> Vec<BlockEntry> {
        let store = self.store.read();
        store.values().cloned().collect()
    }

    pub fn add_block(&self, ip: &str, reason: &str, ban_expire_seconds: u64, site_scope: &str) -> bool {
        if !self.enabled {
            return false;
        }
        
        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
            let key = BlockEntry::key(site_scope, &ip_addr);
            
            let mut store = self.store.write();
            
            if store.len() >= self.config.max_entries {
                tracing::warn!("BlockStore max entries reached, cannot add new block for {}", ip);
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
}
