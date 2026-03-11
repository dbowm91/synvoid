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
    total_entries: RwLock<usize>,
    persist_tx: Option<mpsc::Sender<PersistRequest>>,
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
                                let validated: HashMap<String, BlockEntry> = entries
                                    .into_iter()
                                    .filter(|e| !e.is_expired())
                                    .map(|e| {
                                        let ip: IpAddr = e.ip.parse().ok().unwrap_or_else(|| "0.0.0.0".parse().unwrap());
                                        (BlockEntry::key(&e.site_scope, &ip), e)
                                    })
                                    .collect();
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
        let persist_tx = if config.persist_interval_secs > 0 && persist_path.is_some() {
            let (tx, mut rx): (mpsc::Sender<PersistRequest>, mpsc::Receiver<PersistRequest>) = mpsc::channel(100);
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
                    }
                }
            });
            
            Some(tx)
        } else {
            None
        };

        Self {
            store: Arc::new(RwLock::new(store)),
            enabled,
            persist_path,
            config,
            total_entries: RwLock::new(initial_count),
            persist_tx,
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

    fn trigger_persist(&self) {
        if let Some(ref tx) = self.persist_tx {
            let store = self.store.read().clone();
            let _ = tx.try_send(PersistRequest { entries: store });
        } else if let Some(ref path) = self.persist_path {
            let store = self.store.read().clone();
            let path = path.clone();
            let max_entries = self.config.max_entries;
            tokio::spawn(async move {
                Self::persist_to_disk(&path, store, max_entries).await;
            });
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

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
        let current = *self.total_entries.read();
        
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
        *self.total_entries.write() = self.store.read().len();
        
        tracing::info!("Blocked IP {} for {} (scope: {})", ip, reason, site_scope);

        self.trigger_persist();

        true
    }

    pub fn is_blocked(&self, ip: &IpAddr, site_scope: &str) -> Option<BlockEntry> {
        if !self.enabled {
            return None;
        }

        let key = BlockEntry::key(site_scope, ip);
        let mut store = self.store.write();
        
        if let Some(entry) = store.get_mut(&key) {
            if !entry.is_expired() {
                entry.update_access();
                return Some(entry.clone());
            } else {
                store.remove(&key);
                *self.total_entries.write() = store.len();
            }
        }

        if site_scope != "global" {
            let global_key = BlockEntry::key("global", ip);
            if let Some(entry) = store.get_mut(&global_key) {
                if !entry.is_expired() {
                    entry.update_access();
                    return Some(entry.clone());
                } else {
                    store.remove(&global_key);
                    *self.total_entries.write() = store.len();
                }
            }
        }

        None
    }

    fn remove_entry(&self, key: &str) {
        let removed = self.store.write().remove(key).is_some();
        if removed {
            *self.total_entries.write() = self.store.read().len();
            self.trigger_persist();
        }
    }

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

    pub fn get_stats(&self) -> BlockStoreStats {
        let total = *self.total_entries.read();
        let max = self.config.max_entries;
        
        let mut permanent_count = 0;
        let mut expired_count = 0;
        
        {
            let store = self.store.read();
            for entry in store.values() {
                if entry.is_permanent() {
                    permanent_count += 1;
                }
                if entry.is_expired() {
                    expired_count += 1;
                }
            }
        }

        BlockStoreStats {
            total_entries: total,
            max_entries: max,
            permanent_count,
            expired_count,
            utilization_percent: if max > 0 { (total as f64 / max as f64) * 100.0 } else { 0.0 },
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
