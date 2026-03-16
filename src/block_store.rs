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
            .unwrap_or_else(|_| std::time::Duration::ZERO)
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
            .unwrap_or_else(|_| std::time::Duration::ZERO)
            .as_secs();
        now > self.blocked_at + self.ban_expire_seconds
    }

    pub fn key(site_scope: &str, ip: &IpAddr) -> String {
        format!("block:{}:{}", site_scope, ip)
    }

    pub fn update_access(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::ZERO)
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
            
            tokio::spawn(async move {
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

    async fn persist_to_disk(path: &PathBuf, entries: HashMap<String, BlockEntry>, max_entries: usize) {
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
                        Self::set_secure_permissions(&temp_path).await;
                        if let Err(e) = tokio::fs::rename(&temp_path, path).await {
                            tracing::warn!("Failed to rename temp block file: {}", e);
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
            tokio::spawn(async move {
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
