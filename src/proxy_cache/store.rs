use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use moka::sync::Cache;
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
    pub fn new(
        content: Bytes,
        status: u16,
        headers: HeaderMap,
        max_age: Option<Duration>,
        swr: Option<Duration>,
        sie: Option<Duration>,
    ) -> Self {
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

    #[allow(dead_code)] // Reserved for cache integrity verification
    fn validate(&self, content: &[u8]) -> bool {
        Self::compute_checksum(content) == self.checksum
    }
}

pub struct ProxyCache {
    entries: Cache<CacheKey, CacheEntryInner>,
    settings: ProxyCacheSettings,
    disk_path: PathBuf,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    current_memory_size: AtomicU64,
}

impl Clone for ProxyCache {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            settings: self.settings.clone(),
            disk_path: self.disk_path.clone(),
            cache_hits: AtomicU64::new(self.cache_hits.load(Ordering::Relaxed)),
            cache_misses: AtomicU64::new(self.cache_misses.load(Ordering::Relaxed)),
            current_memory_size: AtomicU64::new(self.current_memory_size.load(Ordering::Relaxed)),
        }
    }
}

impl ProxyCache {
    pub fn new(settings: ProxyCacheSettings) -> Self {
        let disk_path = settings.path.clone();
        let max_memory = settings.max_memory_size as u64;

        let cache: Cache<CacheKey, CacheEntryInner> = Cache::builder()
            .weigher(|_, v: &CacheEntryInner| -> u32 {
                if v.on_disk {
                    1 // Disk-backed entries have minimal memory footprint
                } else {
                    v.size.min(u32::MAX as usize) as u32
                }
            })
            .max_capacity(max_memory)
            .build();

        if settings.enabled && settings.path.exists() {
            if let Err(e) = std::fs::create_dir_all(&settings.path) {
                tracing::warn!("Failed to create cache directory: {}", e);
            }
        }

        Self {
            entries: cache,
            settings,
            disk_path,
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            current_memory_size: AtomicU64::new(0),
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
    pub async fn get(&self, key: &CacheKey) -> Option<ProxyCacheEntry> {
        if !self.settings.enabled {
            return None;
        }

        let inner = self.entries.get(key)?;

        if inner.on_disk {
            drop(inner);
            return self.get_async(key).await;
        }

        let mut entry = inner.entry;

        if entry.is_expired() {
            if entry.is_stale_while_revalidate() {
                entry.is_fresh = false;
                entry.update_access();
                return Some(entry);
            }
            if entry.is_stale_if_error() {
                entry.is_fresh = false;
                entry.update_access();
                return Some(entry);
            }
            self.entries.invalidate(key);
            return None;
        }

        entry.update_access();
        Some(entry)
    }

    #[inline]
    async fn get_async(&self, key: &CacheKey) -> Option<ProxyCacheEntry> {
        let inner = self.entries.get(key)?;

        let disk_path = inner.disk_path.clone()?;
        let checksum = inner.checksum;
        let entry = inner.entry.clone();
        drop(inner);

        let content = tokio::task::spawn_blocking(move || std::fs::read(&disk_path))
            .await
            .ok()
            .and_then(|r| r.ok())?;

        if checksum != CacheEntryInner::compute_checksum(&content) {
            tracing::warn!("Cache entry checksum mismatch, removing corrupted entry");
            self.invalidate(key);
            return None;
        }

        let mut entry = entry;
        entry.content = Bytes::from(content);
        entry.update_access();
        Some(entry)
    }

    #[inline]
    pub fn get_hit_status(&self, key: &CacheKey) -> Option<CacheHit> {
        if !self.settings.enabled {
            return None;
        }

        let entry_inner = self.entries.get(key)?;

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

    pub async fn get_or_fetch<F, Fut>(&self, key: &CacheKey, fetch: F) -> Option<ProxyCacheEntry>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<(Bytes, StatusCode, HeaderMap, Option<Duration>)>>,
    {
        if let Some(entry) = self.get(key).await {
            return Some(entry);
        }

        let (content, status, headers, max_age) = fetch().await?;

        if self
            .insert(key.clone(), content, status.as_u16(), headers, max_age)
            .is_ok()
        {
            self.get(key).await
        } else {
            None
        }
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

        // Update memory size tracking atomically
        if let Some(old) = self.entries.get(&key) {
            if !old.on_disk {
                self.current_memory_size
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        v.checked_sub(old.size as u64)
                    })
                    .ok();
            }
        }

        if !should_store_disk {
            self.current_memory_size
                .fetch_add(size as u64, Ordering::Relaxed);
        }

        self.entries.insert(key, entry_inner);

        Ok(())
    }

    pub fn invalidate(&self, key: &CacheKey) {
        if let Some(entry) = self.entries.get(key) {
            if entry.on_disk {
                if let Some(path) = &entry.disk_path {
                    let _ = std::fs::remove_file(path);
                }
            }
            if !entry.on_disk {
                self.current_memory_size
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        v.checked_sub(entry.size as u64)
                    })
                    .ok();
            }
            self.entries.invalidate(key);
        }
    }

    pub fn invalidate_by_pattern(&self, pattern: &str) -> usize {
        let to_remove: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(k, _)| k.uri.contains(pattern))
            .map(|(k, _)| (*k).clone())
            .collect();

        let count = to_remove.len();

        for key in &to_remove {
            if let Some(entry) = self.entries.get(key) {
                if entry.on_disk {
                    if let Some(path) = &entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                if !entry.on_disk {
                    self.current_memory_size
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            v.checked_sub(entry.size as u64)
                        })
                        .ok();
                }
                self.entries.invalidate(key);
            }
        }

        count
    }

    pub fn invalidate_by_host(&self, host: &str) -> usize {
        let to_remove: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(k, _)| k.host == host)
            .map(|(k, _)| (*k).clone())
            .collect();

        let count = to_remove.len();

        for key in &to_remove {
            if let Some(entry) = self.entries.get(key) {
                if entry.on_disk {
                    if let Some(path) = &entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                if !entry.on_disk {
                    self.current_memory_size
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            v.checked_sub(entry.size as u64)
                        })
                        .ok();
                }
                self.entries.invalidate(key);
            }
        }

        count
    }

    pub fn clear(&self) {
        for (_, entry) in self.entries.iter() {
            if entry.on_disk {
                if let Some(path) = &entry.disk_path {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        self.entries.invalidate_all();
        self.current_memory_size.store(0, Ordering::Relaxed);
    }

    pub fn stats(&self) -> CacheStats {
        let hit_count = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.entry.is_fresh)
            .count() as u64;

        let total = self.entries.entry_count();
        let miss_count = total.saturating_sub(hit_count);

        CacheStats {
            entries: total as usize,
            memory_size: self.current_memory_size.load(Ordering::Relaxed) as usize,
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
        let now = Instant::now();
        let inactive = self.settings.inactive;

        let to_remove: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, v)| {
                let age = now.duration_since(v.entry.created_at);
                age > inactive || v.entry.is_expired()
            })
            .map(|(k, _)| (*k).clone())
            .collect();

        let count = to_remove.len();

        for key in &to_remove {
            if let Some(entry) = self.entries.get(key) {
                if entry.on_disk {
                    if let Some(path) = &entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                if !entry.on_disk {
                    self.current_memory_size
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            v.checked_sub(entry.size as u64)
                        })
                        .ok();
                }
                self.entries.invalidate(key);
            }
        }

        count
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
