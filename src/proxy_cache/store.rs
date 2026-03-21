use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHashMap;
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
    pub stale_while_revalidate: Option<Instant>,
    pub stale_if_error: Option<Instant>,
    pub content_length: Option<usize>,
    pub is_fresh: bool,
}

impl ProxyCacheEntry {
    pub fn new(content: Bytes, status: u16, headers: HeaderMap, max_age: Option<Duration>, swr: Option<Duration>, sie: Option<Duration>) -> Self {
        let now = Instant::now();
        let expires_at = max_age.map(|age| now + age);
        let stale_while_revalidate = swr.and_then(|d| expires_at.map(|e| e + d));
        let stale_if_error = sie.and_then(|d| expires_at.map(|e| e + d));

        Self {
            content,
            status,
            headers,
            created_at: now,
            last_accessed: now,
            expires_at,
            stale_while_revalidate,
            stale_if_error,
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

    pub fn is_stale_while_revalidate(&self) -> bool {
        if let Some(swr) = self.stale_while_revalidate {
            return Instant::now() <= swr && self.is_expired();
        }
        false
    }

    pub fn is_stale_if_error(&self) -> bool {
        if let Some(sie) = self.stale_if_error {
            return Instant::now() <= sie && self.is_expired();
        }
        false
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
    StaleWhileRevalidate,
}

pub struct ProxyCache {
    state: RwLock<CacheState>,
    settings: ProxyCacheSettings,
    disk_path: PathBuf,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

struct CacheState {
    entries: AHashMap<CacheKey, CacheEntryInner>,
    access_order: VecDeque<CacheKey>,
    current_memory_size: usize,
}

impl Clone for ProxyCache {
    fn clone(&self) -> Self {
        let state = self.state.read();
        Self {
            state: RwLock::new(CacheState {
                entries: state.entries.clone(),
                access_order: state.access_order.clone(),
                current_memory_size: state.current_memory_size,
            }),
            settings: self.settings.clone(),
            disk_path: self.disk_path.clone(),
            cache_hits: AtomicU64::new(self.cache_hits.load(Ordering::Relaxed)),
            cache_misses: AtomicU64::new(self.cache_misses.load(Ordering::Relaxed)),
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

impl Clone for CacheEntryInner {
    fn clone(&self) -> Self {
        Self {
            entry: self.entry.clone(),
            size: self.size,
            on_disk: self.on_disk,
            disk_path: self.disk_path.clone(),
            checksum: self.checksum,
        }
    }
}

impl CacheEntryInner {
    fn compute_checksum(content: &[u8]) -> u64 {
        use ahash::AHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = AHasher::default();
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
            state: RwLock::new(CacheState {
                entries: AHashMap::new(),
                access_order: VecDeque::new(),
                current_memory_size: 0,
            }),
            settings,
            disk_path,
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.settings.enabled
    }

    pub fn settings(&self) -> &ProxyCacheSettings {
        &self.settings
    }

    pub fn start_background_cleanup(&self, interval_secs: u64) {
        let cache = Arc::new(self.clone());
        
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

    #[inline]
    pub fn get(&self, key: &CacheKey) -> Option<ProxyCacheEntry> {
        if !self.settings.enabled {
            return None;
        }

        let mut state = self.state.write();
        let entry_inner = state.entries.get(key)?.clone();

        if entry_inner.on_disk {
            if let Some(path) = &entry_inner.disk_path {
                if let Ok(content) = std::fs::read(path) {
                    if !entry_inner.validate(&content) {
                        tracing::warn!("Cache entry checksum mismatch, removing corrupted entry");
                        drop(state);
                        self.invalidate(key);
                        return None;
                    }
                    let mut entry = entry_inner.entry;
                    entry.content = Bytes::from(content);
                    entry.update_access();
                    
                    state.access_order.retain(|k| k != key);
                    state.access_order.push_back(key.clone());
                    return Some(entry);
                }
            }
        }

        let mut entry = entry_inner.entry;
        
        if entry.is_expired() {
            if entry.is_stale_while_revalidate() {
                entry.is_fresh = false;
                entry.update_access();
                state.access_order.retain(|k| k != key);
                state.access_order.push_back(key.clone());
                return Some(entry);
            }
            if entry.is_stale_if_error() {
                entry.is_fresh = false;
                entry.update_access();
                state.access_order.retain(|k| k != key);
                state.access_order.push_back(key.clone());
                return Some(entry);
            }
            state.access_order.retain(|k| k != key);
            return None;
        }

        entry.update_access();
        state.access_order.retain(|k| k != key);
        state.access_order.push_back(key.clone());
        Some(entry)
    }

    #[inline]
    pub fn get_hit_status(&self, key: &CacheKey) -> Option<CacheHit> {
        if !self.settings.enabled {
            return None;
        }

        let state = self.state.read();
        let entry_inner = state.entries.get(key)?;

        if entry_inner.entry.is_fresh {
            return Some(CacheHit::Hit);
        }

        if entry_inner.entry.is_stale_while_revalidate() {
            return Some(CacheHit::StaleWhileRevalidate);
        }

        if entry_inner.entry.is_stale_if_error() {
            return Some(CacheHit::Stale);
        }

        if entry_inner.entry.is_expired() {
            return Some(CacheHit::Expired);
        }

        None
    }

    pub fn get_or_fetch<F, Fut>(&self, key: &CacheKey, _fetch: F) -> Option<ProxyCacheEntry>
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
        let swr = self.settings.stale_while_revalidate;
        let sie = self.settings.stale_if_error;
        let entry = ProxyCacheEntry::new(content.clone(), status, headers, max_age, swr, sie);

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
            
            disk_path = Some(self.disk_path.join(Self::key_to_filename(&key)));
        }

        let checksum = CacheEntryInner::compute_checksum(&content);
        
        let entry_inner = CacheEntryInner {
            entry,
            size,
            on_disk: should_store_disk,
            disk_path,
            checksum,
        };

        let mut state = self.state.write();

        if let Some(old) = state.entries.insert(key.clone(), entry_inner) {
            state.current_memory_size = state.current_memory_size.saturating_sub(old.size);
        }

        if !should_store_disk {
            state.current_memory_size = state.current_memory_size.saturating_add(size);
        }

        if !state.access_order.contains(&key) {
            state.access_order.push_back(key);
        }

        drop(state);

        self.evict_if_needed();

        Ok(())
    }

    pub fn invalidate(&self, key: &CacheKey) {
        let mut state = self.state.write();

        if let Some(entry) = state.entries.remove(key) {
            if entry.on_disk {
                if let Some(path) = entry.disk_path {
                    let _ = std::fs::remove_file(path);
                }
            }

            state.current_memory_size = state.current_memory_size.saturating_sub(entry.size);
        }

        state.access_order.retain(|k| k != key);
    }

    pub fn invalidate_by_pattern(&self, pattern: &str) -> usize {
        let mut state = self.state.write();

        let to_remove: Vec<CacheKey> = state.entries
            .keys()
            .filter(|k| k.uri.contains(pattern))
            .cloned()
            .collect();

        for key in &to_remove {
            if let Some(entry) = state.entries.remove(key) {
                if entry.on_disk {
                    if let Some(path) = entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                state.current_memory_size = state.current_memory_size.saturating_sub(entry.size);
            }
            state.access_order.retain(|k| k != key);
        }

        to_remove.len()
    }

    pub fn invalidate_by_host(&self, host: &str) -> usize {
        let mut state = self.state.write();

        let to_remove: Vec<CacheKey> = state.entries.keys().filter(|k| k.host == host).cloned().collect();

        for key in &to_remove {
            if let Some(entry) = state.entries.remove(key) {
                if entry.on_disk {
                    if let Some(path) = entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                state.current_memory_size = state.current_memory_size.saturating_sub(entry.size);
            }
            state.access_order.retain(|k| k != key);
        }

        to_remove.len()
    }

    pub fn clear(&self) {
        let mut state = self.state.write();

        for (_, entry) in state.entries.drain() {
            if entry.on_disk {
                if let Some(path) = entry.disk_path {
                    let _ = std::fs::remove_file(path);
                }
            }
        }

        state.current_memory_size = 0;
        state.access_order.clear();
    }

    pub fn stats(&self) -> CacheStats {
        let state = self.state.read();

        let mut hit_count = 0u64;

        for (_, entry) in state.entries.iter() {
            if entry.entry.is_fresh {
                hit_count += 1;
            }
        }

        let miss_count = (state.entries.len() as u64).saturating_sub(hit_count);

        CacheStats {
            entries: state.entries.len(),
            memory_size: state.current_memory_size,
            disk_size: self.calculate_disk_size(),
            hits: hit_count,
            misses: miss_count,
        }
    }

    pub fn is_status_cacheable(&self, status: u16) -> bool {
        self.settings.valid_status.contains(&status)
    }

    pub async fn write_to_disk_async(&self, key: &CacheKey, content: Bytes) -> PathBuf {
        let filename = Self::key_to_filename(key);
        let path = self.disk_path.join(&filename);
        let parent = path.parent().map(|p| p.to_path_buf());
        let path_clone = path.clone();

        let _disk_path = self.disk_path.clone();
        
        tokio::spawn(async move {
            if let Some(parent) = parent {
                let _ = tokio::fs::create_dir_all(&parent).await;
            }
            let _ = tokio::fs::write(&path_clone, content).await;
        });

        path
    }

    fn key_to_filename(key: &CacheKey) -> String {
        use ahash::AHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = AHasher::default();
        key.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    fn evict_if_needed(&self) {
        let mut state = self.state.write();
        
        while state.current_memory_size > self.settings.max_memory_size {
            let lru_key = match state.access_order.pop_front() {
                Some(k) => k,
                None => break,
            };

            if let Some(entry) = state.entries.remove(&lru_key) {
                state.current_memory_size = state.current_memory_size.saturating_sub(entry.size);

                if entry.on_disk {
                    if let Some(path) = entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
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
        let mut state = self.state.write();

        let now = Instant::now();
        let inactive = self.settings.inactive;

        let to_remove: Vec<CacheKey> = state.entries
            .iter()
            .filter(|(_, v)| {
                let age = now.duration_since(v.entry.created_at);
                age > inactive || v.entry.is_expired()
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in &to_remove {
            if let Some(entry) = state.entries.remove(key) {
                if entry.on_disk {
                    if let Some(path) = entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                state.current_memory_size = state.current_memory_size.saturating_sub(entry.size);
            }
            state.access_order.retain(|k| k != key);
        }

        to_remove.len()
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn cache_hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    pub fn cache_misses(&self) -> u64 {
        self.cache_misses.load(Ordering::Relaxed)
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        }
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
