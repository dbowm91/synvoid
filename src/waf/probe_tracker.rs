#![allow(unused_mut)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time;

const DEFAULT_MAX_RECORDS: usize = 1000;
const DEFAULT_RETENTION_DAYS: u64 = 7;
const DEFAULT_WINDOW_SECS: u64 = 300;
const DEFAULT_MAX_ENDPOINTS: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeEvent {
    pub endpoint: String,
    pub user_agent: Option<String>,
    pub timestamp: u64,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRecord {
    pub ip: String,
    pub events: Vec<ProbeEvent>,
    pub event_count: u32,
    pub unique_endpoints: Vec<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub user_agent: Option<String>,
}

impl ProbeRecord {
    pub fn new(ip: IpAddr, event: ProbeEvent) -> Self {
        let ip_str = ip.to_string();
        let unique = vec![event.endpoint.clone()];
        Self {
            ip: ip_str,
            events: vec![event.clone()],
            event_count: 1,
            unique_endpoints: unique,
            first_seen: event.timestamp,
            last_seen: event.timestamp,
            user_agent: event.user_agent.clone(),
        }
    }

    pub fn add_event(&mut self, event: ProbeEvent) {
        let timestamp = event.timestamp;
        let user_agent = event.user_agent.clone();
        let endpoint = event.endpoint.clone();

        if !self.unique_endpoints.contains(&endpoint) {
            self.unique_endpoints.push(endpoint);
        }
        self.events.push(event);
        self.event_count += 1;
        self.last_seen = timestamp;
        if self.user_agent.is_none() {
            self.user_agent = user_agent;
        }
    }

    pub fn is_expired(&self, now: u64, retention_secs: u64) -> bool {
        now > self.first_seen + retention_secs
    }

    pub fn key(ip: &IpAddr) -> String {
        format!("probe:{}", ip)
    }
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub enabled: bool,
    pub max_endpoints_per_window: usize,
    pub window_secs: u64,
    pub retention_days: u64,
    pub max_records: usize,
    pub auto_ban_elevated_threat: bool,
    pub elevated_threat_threshold: u8,
    pub elevated_ban_duration: u64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_endpoints_per_window: DEFAULT_MAX_ENDPOINTS,
            window_secs: DEFAULT_WINDOW_SECS,
            retention_days: DEFAULT_RETENTION_DAYS,
            max_records: DEFAULT_MAX_RECORDS,
            auto_ban_elevated_threat: true,
            elevated_threat_threshold: 3,
            elevated_ban_duration: 900,
        }
    }
}

pub struct ProbeTracker {
    store: Arc<RwLock<HashMap<String, ProbeRecord>>>,
    config: ProbeConfig,
    persist_path: Option<PathBuf>,
    persist_tx: Option<mpsc::Sender<PersistRequest>>,
    total_records: RwLock<usize>,
}

#[derive(Debug, Clone)]
struct PersistRequest {
    entries: HashMap<String, ProbeRecord>,
}

impl ProbeTracker {
    pub fn new(config: ProbeConfig, data_dir: Option<PathBuf>) -> Arc<Self> {
        let persist_path = data_dir.map(|d| d.join("probes.json"));
        let max_records = if config.max_records > 0 {
            config.max_records
        } else {
            DEFAULT_MAX_RECORDS
        };

        let store: HashMap<String, ProbeRecord> = if let Some(ref path) = persist_path {
            if path.exists() {
                match std::fs::read_to_string(path) {
                    Ok(content) => match serde_json::from_str::<Vec<ProbeRecord>>(&content) {
                        Ok(entries) => {
                            let now = current_timestamp();
                            let retention_secs = config.retention_days * 86400;
                            let validated: HashMap<String, ProbeRecord> = entries
                                .into_iter()
                                .filter(|e| !e.is_expired(now, retention_secs))
                                .take(max_records)
                                .map(|e| {
                                    let ip: IpAddr = e.ip.parse().unwrap_or_else(|_| {
                                        "0.0.0.0".parse().expect("valid IPv4 literal")
                                    });
                                    (ProbeRecord::key(&ip), e)
                                })
                                .collect();
                            tracing::info!(
                                "Loaded {} valid probe records from disk",
                                validated.len()
                            );
                            validated
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse probes.json: {}, starting fresh", e);
                            HashMap::new()
                        }
                    },
                    Err(_) => HashMap::new(),
                }
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        };

        let initial_count = store.len();
        let persist_tx = if persist_path.is_some() {
            let (tx, mut rx): (mpsc::Sender<PersistRequest>, mpsc::Receiver<PersistRequest>) =
                mpsc::channel(100);
            let path = persist_path.clone().expect("checked is_some above");
            let config_clone = config.clone();

            tokio::spawn(async move {
                let mut interval = time::interval(Duration::from_secs(60));

                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            // Periodic persist handled elsewhere
                        }
                        Some(req) = rx.recv() => {
                            Self::persist_to_disk(&path, req.entries, config_clone.max_records).await;
                        }
                    }
                }
            });

            Some(tx)
        } else {
            None
        };

        Arc::new(Self {
            store: Arc::new(RwLock::new(store)),
            config,
            persist_path,
            persist_tx,
            total_records: RwLock::new(initial_count),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn get_config(&self) -> &ProbeConfig {
        &self.config
    }

    pub fn record_event(
        &self,
        ip: IpAddr,
        endpoint: String,
        method: String,
        user_agent: Option<String>,
    ) -> ProbeResult {
        if !self.config.enabled {
            return ProbeResult::Ignored {
                reason: "disabled".to_string(),
            };
        }

        let now = current_timestamp();
        let window_start = now.saturating_sub(self.config.window_secs);
        let event = ProbeEvent {
            endpoint: endpoint.clone(),
            user_agent: user_agent.clone(),
            timestamp: now,
            method,
        };

        let probing_detected;
        {
            let mut store = self.store.write();

            let key = ProbeRecord::key(&ip);
            if let Some(record) = store.get_mut(&key) {
                record.add_event(event);

                let recent_events: Vec<_> = record
                    .events
                    .iter()
                    .filter(|e| e.timestamp >= window_start)
                    .collect();

                let unique_recent: Vec<_> = recent_events
                    .iter()
                    .map(|e| &e.endpoint)
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                probing_detected = unique_recent.len() >= self.config.max_endpoints_per_window;
            } else {
                if *self.total_records.read() >= self.config.max_records {
                    tracing::warn!("Probe store at capacity, cannot add new probe record");
                    return ProbeResult::Ignored {
                        reason: "at_capacity".to_string(),
                    };
                }

                let record = ProbeRecord::new(ip, event);
                probing_detected = false;
                store.insert(key, record);
                *self.total_records.write() = store.len();
            }
        }

        self.trigger_persist();

        if probing_detected {
            ProbeResult::ProbingDetected {
                unique_endpoints: self.get_unique_endpoints(ip),
                event_count: self.get_event_count(ip),
            }
        } else {
            ProbeResult::Recorded
        }
    }

    pub fn check_probing(&self, ip: IpAddr) -> bool {
        let now = current_timestamp();
        let window_start = now.saturating_sub(self.config.window_secs);

        let store = self.store.read();
        if let Some(record) = store.get(&ProbeRecord::key(&ip)) {
            let unique_recent: std::collections::HashSet<_> = record
                .events
                .iter()
                .filter(|e| e.timestamp >= window_start)
                .map(|e| &e.endpoint)
                .collect();

            unique_recent.len() >= self.config.max_endpoints_per_window
        } else {
            false
        }
    }

    fn get_unique_endpoints(&self, ip: IpAddr) -> Vec<String> {
        self.store
            .read()
            .get(&ProbeRecord::key(&ip))
            .map(|r| r.unique_endpoints.clone())
            .unwrap_or_default()
    }

    fn get_event_count(&self, ip: IpAddr) -> u32 {
        self.store
            .read()
            .get(&ProbeRecord::key(&ip))
            .map(|r| r.event_count)
            .unwrap_or(0)
    }

    pub fn get_record(&self, ip: &IpAddr) -> Option<ProbeRecord> {
        self.store.read().get(&ProbeRecord::key(ip)).cloned()
    }

    pub fn list_records(&self, limit: usize, offset: usize) -> Vec<ProbeRecord> {
        let store = self.store.read();
        let mut records: Vec<_> = store.values().cloned().collect();
        records.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

        records.into_iter().skip(offset).take(limit).collect()
    }

    pub fn get_stats(&self) -> ProbeStats {
        let store = self.store.read();
        let now = current_timestamp();
        let retention_secs = self.config.retention_days * 86400;

        let active = store
            .values()
            .filter(|r| !r.is_expired(now, retention_secs))
            .count();

        let total_events: u32 = store.values().map(|r| r.event_count).sum();

        let mut endpoint_counts: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for record in store.values() {
            for endpoint in &record.unique_endpoints {
                *endpoint_counts.entry(endpoint.clone()).or_insert(0) += 1;
            }
        }

        let mut top_endpoints_vec: Vec<_> = endpoint_counts
            .into_iter()
            .map(|(endpoint, count)| ProbeEndpointStats { endpoint, count })
            .collect();

        top_endpoints_vec.sort_by(|a, b| b.count.cmp(&a.count));
        let top_endpoints: Vec<_> = top_endpoints_vec.into_iter().take(10).collect();

        ProbeStats {
            total_records: store.len(),
            active_records: active,
            total_events,
            top_endpoints,
        }
    }

    pub fn clear_record(&self, ip: &IpAddr) -> bool {
        let removed = self.store.write().remove(&ProbeRecord::key(ip)).is_some();
        if removed {
            *self.total_records.write() = self.store.read().len();
            self.trigger_persist();
        }
        removed
    }

    pub fn cleanup_expired(&self) {
        let now = current_timestamp();
        let retention_secs = self.config.retention_days * 86400;

        let mut store = self.store.write();
        store.retain(|_, record| !record.is_expired(now, retention_secs));
        *self.total_records.write() = store.len();

        drop(store);
        self.trigger_persist();
    }

    fn trigger_persist(&self) {
        if let Some(ref tx) = self.persist_tx {
            let store = self.store.read().clone();
            let _ = tx.try_send(PersistRequest { entries: store });
        } else if let Some(ref path) = self.persist_path {
            let store = self.store.read().clone();
            let path = path.clone();
            let max_records = self.config.max_records;
            tokio::spawn(async move {
                Self::persist_to_disk(&path, store, max_records).await;
            });
        }
    }

    async fn persist_to_disk(
        path: &PathBuf,
        entries: HashMap<String, ProbeRecord>,
        max_records: usize,
    ) {
        let entries_to_save: Vec<ProbeRecord> = entries.into_values().take(max_records).collect();

        match serde_json::to_string_pretty(&entries_to_save) {
            Ok(json) => {
                let temp_path = path.with_extension("tmp");
                match tokio::fs::write(&temp_path, json).await {
                    Ok(_) => {
                        if let Err(e) = tokio::fs::rename(&temp_path, path).await {
                            tracing::warn!("Failed to rename temp probe file: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to write probes to disk: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to serialize probe entries: {}", e);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProbeResult {
    Recorded,
    Ignored {
        reason: String,
    },
    ProbingDetected {
        unique_endpoints: Vec<String>,
        event_count: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeStats {
    pub total_records: usize,
    pub active_records: usize,
    pub total_events: u32,
    pub top_endpoints: Vec<ProbeEndpointStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeEndpointStats {
    pub endpoint: String,
    pub count: u32,
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const MAX_WORD_TRACKER_IPS: usize = 500;

#[derive(Debug, Clone)]
pub struct SuspiciousWordRecord {
    pub ip: IpAddr,
    pub matched_word: String,
    pub endpoint: String,
    pub user_agent: Option<String>,
    pub timestamp: u64,
}

#[allow(dead_code)] // access_order reserved for future LRU eviction
pub struct SuspiciousWordTracker {
    store: Arc<RwLock<HashMap<IpAddr, Vec<SuspiciousWordRecord>>>>,
    config: crate::config::SuspiciousWordsConfig,
    total_matches: std::sync::atomic::AtomicU64,
    access_order: RwLock<Vec<IpAddr>>,
}

impl SuspiciousWordTracker {
    pub fn new(config: crate::config::SuspiciousWordsConfig) -> Arc<Self> {
        Arc::new(Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            config,
            total_matches: std::sync::atomic::AtomicU64::new(0),
            access_order: RwLock::new(Vec::new()),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn check_and_record(
        &self,
        ip: IpAddr,
        path: &str,
        query: Option<&str>,
        user_agent: Option<&str>,
    ) -> Option<SuspiciousWordRecord> {
        if !self.config.enabled {
            return None;
        }

        let search_text = if let Some(q) = query {
            format!("{}?{}", path, q)
        } else {
            path.to_string()
        };

        let search_lower = search_text.to_lowercase();

        for word in &self.config.words {
            let word_lower = word.to_lowercase();
            if search_lower.contains(&word_lower) {
                let record = SuspiciousWordRecord {
                    ip,
                    matched_word: word.clone(),
                    endpoint: path.to_string(),
                    user_agent: user_agent.map(String::from),
                    timestamp: current_timestamp(),
                };

                {
                    let mut store = self.store.write();

                    let entry = store.entry(ip).or_default();

                    if entry.len() >= 10 {
                        entry.remove(0);
                    }
                    entry.push(record.clone());

                    if store.len() >= MAX_WORD_TRACKER_IPS {
                        let mut keys_to_remove: Vec<IpAddr> =
                            store.keys().cloned().take(1).collect();
                        for key in keys_to_remove {
                            store.remove(&key);
                        }
                    }
                }

                self.total_matches
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                return Some(record);
            }
        }

        None
    }

    pub fn get_record(&self, ip: &IpAddr) -> Option<Vec<SuspiciousWordRecord>> {
        self.store.read().get(ip).cloned()
    }

    pub fn list_records(&self, limit: usize) -> Vec<(IpAddr, Vec<SuspiciousWordRecord>)> {
        let store = self.store.read();
        store
            .iter()
            .take(limit)
            .map(|(ip, records)| (*ip, records.clone()))
            .collect()
    }

    pub fn get_stats(&self) -> SuspiciousWordStats {
        let store = self.store.read();
        let total_ips = store.len();
        let total_matches = self
            .total_matches
            .load(std::sync::atomic::Ordering::Relaxed);

        let mut word_counts: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for records in store.values() {
            for record in records {
                *word_counts.entry(record.matched_word.clone()).or_insert(0) += 1;
            }
        }

        let mut top_words: Vec<_> = word_counts
            .into_iter()
            .map(|(word, count)| SuspiciousWordCount { word, count })
            .collect();
        top_words.sort_by(|a, b| b.count.cmp(&a.count));
        let top_words: Vec<_> = top_words.into_iter().take(10).collect();

        SuspiciousWordStats {
            total_ips,
            total_matches,
            top_words,
        }
    }

    pub fn clear_record(&self, ip: &IpAddr) -> bool {
        self.store.write().remove(ip).is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousWordStats {
    pub total_ips: usize,
    pub total_matches: u64,
    pub top_words: Vec<SuspiciousWordCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousWordCount {
    pub word: String,
    pub count: u32,
}

#[derive(Debug, Clone)]
pub struct UpstreamErrorRecord {
    pub ip: IpAddr,
    pub endpoint: String,
    pub status_code: u16,
    pub timestamp: u64,
}

pub struct UpstreamErrorTracker {
    store: Arc<RwLock<HashMap<IpAddr, Vec<UpstreamErrorRecord>>>>,
    config: crate::config::UpstreamErrorsConfig,
    total_errors: std::sync::atomic::AtomicU64,
}

impl UpstreamErrorTracker {
    pub fn new(config: crate::config::UpstreamErrorsConfig) -> Arc<Self> {
        Arc::new(Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            config,
            total_errors: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn get_config(&self) -> &crate::config::UpstreamErrorsConfig {
        &self.config
    }

    pub fn record_error(&self, ip: IpAddr, path: &str, status_code: u16) -> UpstreamErrorResult {
        if !self.config.enabled {
            return UpstreamErrorResult::Ignored {
                reason: "disabled".to_string(),
            };
        }

        if !self.config.error_codes.contains(&status_code) {
            return UpstreamErrorResult::Ignored {
                reason: "status_not_tracked".to_string(),
            };
        }

        let now = current_timestamp();
        let window_start = now.saturating_sub(self.config.window_secs);

        let record = UpstreamErrorRecord {
            ip,
            endpoint: path.to_string(),
            status_code,
            timestamp: now,
        };

        let probing_detected;
        let error_count;
        {
            let mut store = self.store.write();

            let entry = store.entry(ip).or_default();
            entry.retain(|r| r.timestamp >= window_start);

            if entry.len() >= 20 {
                entry.remove(0);
            }

            entry.push(record.clone());
            error_count = entry.len();

            let unique_endpoints: std::collections::HashSet<_> =
                entry.iter().map(|r| r.endpoint.clone()).collect();

            probing_detected = unique_endpoints.len() >= self.config.min_error_endpoints;

            if store.len() >= MAX_WORD_TRACKER_IPS {
                let mut keys_to_remove: Vec<IpAddr> = store.keys().cloned().take(1).collect();
                for key in keys_to_remove {
                    store.remove(&key);
                }
            }
        }

        self.total_errors
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if probing_detected {
            let unique_endpoints: Vec<String> = {
                let store = self.store.read();
                store
                    .get(&ip)
                    .map(|entries| {
                        entries
                            .iter()
                            .filter(|e| e.timestamp >= window_start)
                            .map(|e| e.endpoint.clone())
                            .collect::<std::collections::HashSet<_>>()
                            .into_iter()
                            .collect()
                    })
                    .unwrap_or_default()
            };

            UpstreamErrorResult::ProbingDetected {
                unique_endpoints,
                error_count,
            }
        } else {
            UpstreamErrorResult::Recorded
        }
    }

    pub fn get_record(&self, ip: &IpAddr) -> Option<Vec<UpstreamErrorRecord>> {
        self.store.read().get(ip).cloned()
    }

    pub fn list_records(&self, limit: usize) -> Vec<(IpAddr, Vec<UpstreamErrorRecord>)> {
        let store = self.store.read();
        store
            .iter()
            .take(limit)
            .map(|(ip, records)| (*ip, records.clone()))
            .collect()
    }

    pub fn get_stats(&self) -> UpstreamErrorStats {
        let store = self.store.read();
        let total_errors = self.total_errors.load(std::sync::atomic::Ordering::Relaxed);

        let mut endpoint_counts: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for records in store.values() {
            for record in records {
                *endpoint_counts.entry(record.endpoint.clone()).or_insert(0) += 1;
            }
        }

        let mut top_endpoints: Vec<_> = endpoint_counts
            .into_iter()
            .map(|(endpoint, count)| UpstreamEndpointErrorCount { endpoint, count })
            .collect();
        top_endpoints.sort_by(|a, b| b.count.cmp(&a.count));
        let top_endpoints: Vec<_> = top_endpoints.into_iter().take(10).collect();

        UpstreamErrorStats {
            total_ips: store.len(),
            total_errors,
            top_endpoints,
        }
    }

    pub fn clear_record(&self, ip: &IpAddr) -> bool {
        self.store.write().remove(ip).is_some()
    }
}

#[derive(Debug, Clone)]
pub enum UpstreamErrorResult {
    Recorded,
    Ignored {
        reason: String,
    },
    ProbingDetected {
        unique_endpoints: Vec<String>,
        error_count: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamErrorStats {
    pub total_ips: usize,
    pub total_errors: u64,
    pub top_endpoints: Vec<UpstreamEndpointErrorCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamEndpointErrorCount {
    pub endpoint: String,
    pub count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_record_creation() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let event = ProbeEvent {
            endpoint: "/wp-admin".to_string(),
            user_agent: Some("curl".to_string()),
            timestamp: 1000,
            method: "GET".to_string(),
        };

        let record = ProbeRecord::new(ip, event);
        assert_eq!(record.ip, "1.2.3.4");
        assert_eq!(record.event_count, 1);
        assert_eq!(record.unique_endpoints.len(), 1);
    }

    #[test]
    fn test_probe_record_add_event() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let event1 = ProbeEvent {
            endpoint: "/wp-admin".to_string(),
            user_agent: None,
            timestamp: 1000,
            method: "GET".to_string(),
        };

        let mut record = ProbeRecord::new(ip, event1);

        let event2 = ProbeEvent {
            endpoint: "/.git/config".to_string(),
            user_agent: Some("curl".to_string()),
            timestamp: 1001,
            method: "GET".to_string(),
        };

        record.add_event(event2);

        assert_eq!(record.event_count, 2);
        assert_eq!(record.unique_endpoints.len(), 2);
    }
}
