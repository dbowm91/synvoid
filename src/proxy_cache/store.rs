use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use parking_lot::RwLock;
use thiserror::Error;

use super::config::ProxyCacheSettings;
use super::key::CacheKey;

#[derive(Error, Debug)]
pub enum CacheError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cache disabled")]
    Disabled,
    #[error("Entry not found: {0}")]
    NotFound(String),
    #[error("Entry expired: {0}")]
    Expired(String),
    #[error("Response not cacheable")]
    NotCacheable,
}

#[derive(Clone)]
pub struct ProxyCacheEntry {
    pub content: Bytes,
    pub status: u16,
    pub headers: HeaderMap,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub expires_at: Option<Instant>,
    pub content_length: Option<usize>,
    pub is_fresh: bool,
}

impl ProxyCacheEntry {
    pub fn new(content: Bytes, status: u16, headers: HeaderMap, max_age: Option<Duration>) -> Self {
        let now = Instant::now();
        let expires_at = max_age.map(|age| now + age);

        Self {
            content,
            status,
            headers,
            created_at: now,
            last_accessed: now,
            expires_at,
            content_length: None,
            is_fresh: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            return Instant::now() > expires_at;
        }
        false
    }

    pub fn is_stale(&self) -> bool {
        self.is_expired()
    }

    pub fn age(&self) -> Duration {
        self.last_accessed.duration_since(self.created_at)
    }

    pub fn update_access(&mut self) {
        self.last_accessed = Instant::now();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheHit {
    Hit,
    Miss,
    Expired,
    Stale,
}

pub struct ProxyCache {
    entries: RwLock<HashMap<CacheKey, CacheEntryInner>>,
    settings: ProxyCacheSettings,
    access_order: RwLock<VecDeque<CacheKey>>,
    current_memory_size: RwLock<usize>,
    disk_path: PathBuf,
}

impl Clone for ProxyCache {
    fn clone(&self) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            settings: self.settings.clone(),
            access_order: RwLock::new(VecDeque::new()),
            current_memory_size: RwLock::new(0),
            disk_path: self.disk_path.clone(),
        }
    }
}

struct CacheEntryInner {
    entry: ProxyCacheEntry,
    size: usize,
    on_disk: bool,
    disk_path: Option<PathBuf>,
    checksum: u64,
}

impl CacheEntryInner {
    fn compute_checksum(content: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        hasher.finish()
    }

    fn validate(&self, content: &[u8]) -> bool {
        Self::compute_checksum(content) == self.checksum
    }
}

impl ProxyCache {
    pub fn new(settings: ProxyCacheSettings) -> Self {
        let disk_path = settings.path.clone();

        if settings.enabled && settings.path.exists() {
            if let Err(e) = std::fs::create_dir_all(&settings.path) {
                tracing::warn!("Failed to create cache directory: {}", e);
            }
        }

        Self {
            entries: RwLock::new(HashMap::new()),
            settings,
            access_order: RwLock::new(VecDeque::new()),
            current_memory_size: RwLock::new(0),
            disk_path,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.settings.enabled
    }

    pub fn settings(&self) -> &ProxyCacheSettings {
        &self.settings
    }

    pub fn start_background_cleanup(&self, interval_secs: u64) {
        let cache = Arc::new(self.clone_inner());
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                let removed = cache.cleanup_expired();
                if removed > 0 {
                    tracing::debug!("Cache cleanup: removed {} expired entries", removed);
                }
            }
        });
    }

    fn clone_inner(&self) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            settings: self.settings.clone(),
            access_order: RwLock::new(VecDeque::new()),
            current_memory_size: RwLock::new(0),
            disk_path: self.disk_path.clone(),
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<ProxyCacheEntry> {
        if !self.settings.enabled {
            return None;
        }

        let mut entries = self.entries.write();
        let entry_inner = entries.get(key)?;

        if entry_inner.on_disk {
            if let Some(path) = &entry_inner.disk_path {
                if let Ok(content) = std::fs::read(path) {
                    if !entry_inner.validate(&content) {
                        tracing::warn!("Cache entry checksum mismatch, removing corrupted entry");
                        drop(entries);
                        self.invalidate(key);
                        return None;
                    }
                    let mut entry = entry_inner.entry.clone();
                    entry.content = Bytes::from(content);
                    entry.update_access();
                    drop(entries);
                    self.update_access_order(key);
                    return Some(entry);
                }
            }
        }

        let mut entry = entry_inner.entry.clone();
        
        if entry.is_expired() {
            drop(entries);
            let mut access_order = self.access_order.write();
            access_order.retain(|k| k != key);
            return None;
        }

        entry.update_access();
        drop(entries);
        self.update_access_order(key);
        Some(entry)
    }

    pub fn get_or_fetch<F, Fut>(&self, key: &CacheKey, fetch: F) -> Option<ProxyCacheEntry>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<(Bytes, StatusCode, HeaderMap, Option<Duration>)>>,
    {
        if let Some(entry) = self.get(key) {
            return Some(entry);
        }

        None
    }

    pub fn insert(
        &self,
        key: CacheKey,
        content: Bytes,
        status: u16,
        headers: HeaderMap,
        max_age: Option<Duration>,
    ) -> Result<(), CacheError> {
        if !self.settings.enabled {
            return Err(CacheError::Disabled);
        }

        if !self.is_status_cacheable(status) {
            return Err(CacheError::NotCacheable);
        }

        let size = content.len();
        let entry = ProxyCacheEntry::new(content.clone(), status, headers, max_age);

        let mut should_store_disk = false;
        let mut disk_path = None;

        if size > self.settings.max_memory_size {
            if self.settings.use_temp_file {
                should_store_disk = true;
            } else {
                return Err(CacheError::NotCacheable);
            }
        }

        if should_store_disk {
            let disk_path_clone = self.disk_path.clone();
            let key_clone = key.clone();
            let content_clone = content.clone();
            
            tokio::spawn(async move {
                let filename = Self::key_to_filename(&key_clone);
                let path = disk_path_clone.join(&filename);
                if let Some(parent) = path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                let _ = tokio::fs::write(&path, content_clone).await;
            });
            
            disk_path = Some(self.write_to_disk(&key, &content));
        }

        let checksum = CacheEntryInner::compute_checksum(&content);
        
        let entry_inner = CacheEntryInner {
            entry,
            size,
            on_disk: should_store_disk,
            disk_path,
            checksum,
        };

        let mut entries = self.entries.write();
        let mut current_size = self.current_memory_size.write();

        if let Some(old) = entries.insert(key.clone(), entry_inner) {
            *current_size = current_size.saturating_sub(old.size);
        }

        if !should_store_disk {
            *current_size = current_size.saturating_add(size);
        }

        drop(entries);
        drop(current_size);

        let mut access_order = self.access_order.write();
        if !access_order.contains(&key) {
            access_order.push_back(key);
        }

        self.evict_if_needed();

        Ok(())
    }

    pub fn invalidate(&self, key: &CacheKey) {
        let mut entries = self.entries.write();

        if let Some(entry) = entries.remove(key) {
            if entry.on_disk {
                if let Some(path) = entry.disk_path {
                    let _ = std::fs::remove_file(path);
                }
            }

            let mut current_size = self.current_memory_size.write();
            *current_size = current_size.saturating_sub(entry.size);
        }

        drop(entries);

        let mut access_order = self.access_order.write();
        access_order.retain(|k| k != key);
    }

    pub fn invalidate_by_pattern(&self, pattern: &str) -> usize {
        let mut entries = self.entries.write();
        let mut current_size = self.current_memory_size.write();
        let mut access_order = self.access_order.write();

        let to_remove: Vec<CacheKey> = entries
            .keys()
            .filter(|k| k.uri.contains(pattern))
            .cloned()
            .collect();

        for key in &to_remove {
            if let Some(entry) = entries.remove(key) {
                if entry.on_disk {
                    if let Some(path) = entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                *current_size = current_size.saturating_sub(entry.size);
            }
            access_order.retain(|k| k != key);
        }

        to_remove.len()
    }

    pub fn invalidate_by_host(&self, host: &str) -> usize {
        let mut entries = self.entries.write();
        let mut current_size = self.current_memory_size.write();
        let mut access_order = self.access_order.write();

        let to_remove: Vec<CacheKey> = entries.keys().filter(|k| k.host == host).cloned().collect();

        for key in &to_remove {
            if let Some(entry) = entries.remove(key) {
                if entry.on_disk {
                    if let Some(path) = entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                *current_size = current_size.saturating_sub(entry.size);
            }
            access_order.retain(|k| k != key);
        }

        to_remove.len()
    }

    pub fn clear(&self) {
        let mut entries = self.entries.write();
        let mut current_size = self.current_memory_size.write();

        for (_, entry) in entries.drain() {
            if entry.on_disk {
                if let Some(path) = entry.disk_path {
                    let _ = std::fs::remove_file(path);
                }
            }
        }

        *current_size = 0;

        drop(entries);
        drop(current_size);

        let mut access_order = self.access_order.write();
        access_order.clear();
    }

    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.read();
        let current_size = self.current_memory_size.read();

        let mut hit_count = 0u64;
        let mut miss_count = 0u64;

        for (_, entry) in entries.iter() {
            if entry.entry.is_fresh {
                hit_count += 1;
            }
        }

        miss_count = (entries.len() as u64).saturating_sub(hit_count);

        CacheStats {
            entries: entries.len(),
            memory_size: *current_size,
            disk_size: self.calculate_disk_size(),
            hits: hit_count,
            misses: miss_count,
        }
    }

    fn is_status_cacheable(&self, status: u16) -> bool {
        self.settings.valid_status.contains(&status)
    }

    fn write_to_disk(&self, key: &CacheKey, content: &[u8]) -> PathBuf {
        let filename = Self::key_to_filename(key);
        let path = self.disk_path.join(&filename);

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let _ = std::fs::write(&path, content);

        path
    }

    pub async fn write_to_disk_async(&self, key: &CacheKey, content: Bytes) -> PathBuf {
        let filename = Self::key_to_filename(key);
        let path = self.disk_path.join(&filename);
        let parent = path.parent().map(|p| p.to_path_buf());
        let path_clone = path.clone();

        let disk_path = self.disk_path.clone();
        
        tokio::spawn(async move {
            if let Some(parent) = parent {
                let _ = tokio::fs::create_dir_all(&parent).await;
            }
            let _ = tokio::fs::write(&path_clone, content).await;
        });

        path
    }

    fn key_to_filename(key: &CacheKey) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    fn update_access_order(&self, key: &CacheKey) {
        let mut access_order = self.access_order.write();
        access_order.retain(|k| k != key);
        access_order.push_back(key.clone());
    }

    fn evict_if_needed(&self) {
        loop {
            let current_size = self.current_memory_size.read();
            if *current_size <= self.settings.max_memory_size {
                break;
            }
            drop(current_size);

            let mut access_order = self.access_order.write();
            if let Some(lru_key) = access_order.pop_front() {
                drop(access_order);

                let mut entries = self.entries.write();
                if let Some(entry) = entries.remove(&lru_key) {
                    let mut size_guard = self.current_memory_size.write();
                    *size_guard = size_guard.saturating_sub(entry.size);
                    drop(size_guard);

                    if entry.on_disk {
                        if let Some(path) = entry.disk_path {
                            let _ = std::fs::remove_file(path);
                        }
                    }
                }
                drop(entries);
            } else {
                break;
            }
        }
    }

    fn calculate_disk_size(&self) -> usize {
        if !self.disk_path.exists() {
            return 0;
        }

        std::fs::read_dir(&self.disk_path)
            .map(|dir| {
                dir.filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                    .filter_map(|e| e.metadata().ok())
                    .map(|m| m.len() as usize)
                    .sum()
            })
            .unwrap_or(0)
    }

    pub fn cleanup_expired(&self) -> usize {
        let mut entries = self.entries.write();
        let mut current_size = self.current_memory_size.write();
        let mut access_order = self.access_order.write();

        let now = Instant::now();
        let inactive = self.settings.inactive;

        let to_remove: Vec<CacheKey> = entries
            .iter()
            .filter(|(_, v)| {
                let age = now.duration_since(v.entry.created_at);
                age > inactive || v.entry.is_expired()
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in &to_remove {
            if let Some(entry) = entries.remove(key) {
                if entry.on_disk {
                    if let Some(path) = entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                *current_size = current_size.saturating_sub(entry.size);
            }
            access_order.retain(|k| k != key);
        }

        to_remove.len()
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub memory_size: usize,
    pub disk_size: usize,
    pub hits: u64,
    pub misses: u64,
}
