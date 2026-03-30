use crate::config::ThreatLevelEscalation;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationEntry {
    pub ip: String,
    pub reason: String,
    pub threat_level_at_violation: u8,
    pub violations_count: u32,
    pub first_violation_at: u64,
    pub last_violation_at: u64,
    pub expires_at: u64,
}

impl ViolationEntry {
    pub fn new(ip: IpAddr, reason: String, threat_level: u8, window_secs: u64) -> Self {
        let now = crate::utils::safe_unix_timestamp();

        Self {
            ip: ip.to_string(),
            reason,
            threat_level_at_violation: threat_level,
            violations_count: 1,
            first_violation_at: now,
            last_violation_at: now,
            expires_at: now + window_secs,
        }
    }

    pub fn increment(&mut self, threat_level: u8, window_secs: u64) {
        let now = crate::utils::safe_unix_timestamp();

        self.violations_count += 1;
        self.last_violation_at = now;
        self.threat_level_at_violation = threat_level;
        self.expires_at = now + window_secs;
    }

    pub fn is_expired(&self) -> bool {
        let now = crate::utils::safe_unix_timestamp();
        now > self.expires_at
    }

    pub fn key(ip: &IpAddr) -> String {
        format!("violation:{}", ip)
    }
}

pub struct ViolationTracker {
    store: Arc<RwLock<HashMap<String, ViolationEntry>>>,
    config: ThreatLevelEscalation,
    #[allow(dead_code)] // Retained for future periodic persistence
    persist_path: Option<PathBuf>,
    persist_tx: Option<mpsc::Sender<PersistRequest>>,
    #[allow(dead_code)] // Retained for future periodic persistence
    persist_interval: Duration,
    is_attack_mode: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone)]
struct PersistRequest {
    entries: HashMap<String, ViolationEntry>,
}

impl ViolationTracker {
    pub fn new(
        config: ThreatLevelEscalation,
        data_dir: Option<PathBuf>,
        normal_interval_secs: u32,
        attack_interval_secs: u32,
    ) -> Arc<Self> {
        let persist_path = data_dir.map(|d| d.join("violations.json"));
        let is_attack_mode = Arc::new(RwLock::new(false));

        let path_for_load =
            persist_path
                .as_ref()
                .and_then(|p| if p.exists() { Some(p.clone()) } else { None });

        let store: HashMap<String, ViolationEntry> = if let Some(path) = path_for_load {
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<Vec<ViolationEntry>>(&content) {
                    Ok(entries) => {
                        let validated: HashMap<String, ViolationEntry> = entries
                            .into_iter()
                            .filter(|e| !e.is_expired())
                            .map(|e| {
                                let ip: IpAddr =
                                    e.ip.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
                                (ViolationEntry::key(&ip), e)
                            })
                            .collect();
                        tracing::info!("Loaded {} valid violation entries", validated.len());
                        validated
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse violations.json: {}", e);
                        HashMap::new()
                    }
                },
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };

        let store = Arc::new(RwLock::new(store));
        let store_clone = store.clone();
        let is_attack_mode_clone = is_attack_mode.clone();

        let persist_tx = persist_path.as_ref().map(|path| {
            let path = path.clone();
            let (tx, mut rx) = mpsc::channel::<PersistRequest>(100);

            tokio::spawn(async move {
                let mut current_interval_secs = normal_interval_secs;

                loop {
                    tokio::select! {
                        _ = time::sleep(Duration::from_secs(current_interval_secs.into())) => {
                            let is_attack = *is_attack_mode_clone.read();
                            current_interval_secs = if is_attack { attack_interval_secs } else { normal_interval_secs };

                            let entries = store_clone.read().clone();
                            if !entries.is_empty() {
                                Self::persist_to_disk(&path, entries).await;
                            }
                        }
                        Some(req) = rx.recv() => {
                            let entries = req.entries;
                            Self::persist_to_disk(&path, entries).await;
                        }
                    }
                }
            });

            tx
        });

        Arc::new(Self {
            store,
            config,
            persist_path: persist_path.clone(),
            persist_tx,
            persist_interval: Duration::from_secs(attack_interval_secs as u64),
            is_attack_mode,
        })
    }

    pub fn record_violation(&self, ip: IpAddr, reason: &str, threat_level: u8) -> u32 {
        if self.is_excluded(ip) {
            return 0;
        }

        let key = ViolationEntry::key(&ip);
        let count = {
            let mut store = self.store.write();

            if let Some(entry) = store.get_mut(&key) {
                entry.increment(threat_level, self.config.violation_window_secs as u64);
                entry.violations_count
            } else {
                let entry = ViolationEntry::new(
                    ip,
                    reason.to_string(),
                    threat_level,
                    self.config.violation_window_secs as u64,
                );
                let count = entry.violations_count;
                store.insert(key, entry);
                count
            }
        };

        self.schedule_persist();

        count
    }

    pub fn check_violations(&self, ip: IpAddr) -> u32 {
        if self.is_excluded(ip) {
            return 0;
        }

        let key = ViolationEntry::key(&ip);
        let mut store = self.store.write();

        if let Some(entry) = store.get_mut(&key) {
            if entry.is_expired() {
                store.remove(&key);
                return 0;
            }
            entry.violations_count
        } else {
            0
        }
    }

    pub fn should_block(&self, ip: IpAddr) -> bool {
        if !self.config.enabled {
            return false;
        }

        let violations = self.check_violations(ip);
        violations >= self.config.violations_before_block
    }

    pub fn clear_violations(&self, ip: IpAddr) {
        let key = ViolationEntry::key(&ip);
        self.store.write().remove(&key);
        self.schedule_persist();
    }

    pub fn set_attack_mode(&self, is_attack: bool) {
        *self.is_attack_mode.write() = is_attack;
    }

    fn is_excluded(&self, ip: IpAddr) -> bool {
        let ip_str = ip.to_string();
        self.config.excluded_ips.iter().any(|e| e == &ip_str)
    }

    fn schedule_persist(&self) {
        if let Some(ref tx) = self.persist_tx {
            let entries = self.store.read().clone();
            if let Err(e) = tx.try_send(PersistRequest { entries }) {
                if matches!(e, tokio::sync::mpsc::error::TrySendError::Closed(_)) {
                    tracing::warn!("Violation tracker persist channel closed");
                }
            }
        }
    }

    async fn persist_to_disk(path: &PathBuf, entries: HashMap<String, ViolationEntry>) {
        let values: Vec<ViolationEntry> = entries.into_values().collect();

        match serde_json::to_string_pretty(&values) {
            Ok(json) => {
                if let Err(e) = tokio::fs::write(path, json).await {
                    tracing::error!("Failed to persist violations: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to serialize violations: {}", e);
            }
        }
    }

    pub fn get_stats(&self) -> ViolationStats {
        let store = self.store.read();
        let total = store.len();
        let expired = store.values().filter(|e| e.is_expired()).count();

        ViolationStats {
            total,
            expired,
            active: total - expired,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ViolationStats {
    pub total: usize,
    pub expired: usize,
    pub active: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_violation_expiry() {
        let entry = ViolationEntry::new("1.2.3.4".parse().unwrap(), "test".to_string(), 1, 1);

        assert!(!entry.is_expired());
    }

    #[test]
    fn test_violation_multiple_entries() {
        let config = ThreatLevelEscalation::default();
        let tracker = ViolationTracker::new(config, None, 60, 10);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let count1 = tracker.record_violation(ip, "first", 1);
        assert_eq!(count1, 1);

        let count2 = tracker.record_violation(ip, "second", 1);
        assert_eq!(count2, 2);

        let count3 = tracker.record_violation(ip, "third", 1);
        assert_eq!(count3, 3);

        let violations = tracker.check_violations(ip);
        assert_eq!(violations, 3);
    }

    #[test]
    fn test_violation_threshold_breach() {
        let config = ThreatLevelEscalation {
            enabled: true,
            violations_before_block: 3,
            violation_window_secs: 300,
            excluded_ips: vec![],
        };
        let tracker = ViolationTracker::new(config, None, 60, 10);

        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(!tracker.should_block(ip));

        tracker.record_violation(ip, "v1", 1);
        assert!(!tracker.should_block(ip));

        tracker.record_violation(ip, "v2", 1);
        assert!(!tracker.should_block(ip));

        tracker.record_violation(ip, "v3", 1);
        assert!(tracker.should_block(ip));
    }

    #[test]
    fn test_violation_cleanup_expired() {
        let config = ThreatLevelEscalation {
            enabled: true,
            violations_before_block: 3,
            violation_window_secs: 300,
            excluded_ips: vec![],
        };
        let tracker = ViolationTracker::new(config, None, 60, 10);

        let ip: IpAddr = "10.0.0.3".parse().unwrap();
        let mut entry = ViolationEntry::new(ip, "test".to_string(), 1, 0);
        entry.expires_at = 0;

        let key = ViolationEntry::key(&ip);
        tracker.store.write().insert(key, entry);

        let violations = tracker.check_violations(ip);
        assert_eq!(violations, 0);
    }

    #[test]
    fn test_violation_different_ips_independent() {
        let config = ThreatLevelEscalation {
            enabled: true,
            violations_before_block: 2,
            violation_window_secs: 300,
            excluded_ips: vec![],
        };
        let tracker = ViolationTracker::new(config, None, 60, 10);

        let ip1: IpAddr = "10.0.0.4".parse().unwrap();
        let ip2: IpAddr = "10.0.0.5".parse().unwrap();

        tracker.record_violation(ip1, "v1", 1);
        tracker.record_violation(ip1, "v2", 1);

        assert!(tracker.should_block(ip1));
        assert!(!tracker.should_block(ip2));

        let violations_ip1 = tracker.check_violations(ip1);
        let violations_ip2 = tracker.check_violations(ip2);
        assert_eq!(violations_ip1, 2);
        assert_eq!(violations_ip2, 0);
    }

    #[test]
    fn test_violation_increment_updates_threat_level() {
        let mut entry = ViolationEntry::new("1.2.3.4".parse().unwrap(), "test".to_string(), 1, 300);
        assert_eq!(entry.threat_level_at_violation, 1);
        assert_eq!(entry.violations_count, 1);

        entry.increment(5, 300);
        assert_eq!(entry.threat_level_at_violation, 5);
        assert_eq!(entry.violations_count, 2);
    }

    #[test]
    fn test_violation_clear() {
        let config = ThreatLevelEscalation::default();
        let tracker = ViolationTracker::new(config, None, 60, 10);

        let ip: IpAddr = "10.0.0.6".parse().unwrap();
        tracker.record_violation(ip, "test", 1);
        assert_eq!(tracker.check_violations(ip), 1);

        tracker.clear_violations(ip);
        assert_eq!(tracker.check_violations(ip), 0);
    }

    #[test]
    fn test_violation_disabled_config() {
        let config = ThreatLevelEscalation {
            enabled: false,
            violations_before_block: 1,
            violation_window_secs: 300,
            excluded_ips: vec![],
        };
        let tracker = ViolationTracker::new(config, None, 60, 10);

        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        tracker.record_violation(ip, "test", 1);
        tracker.record_violation(ip, "test", 1);
        assert!(!tracker.should_block(ip));
    }

    #[test]
    fn test_violation_excluded_ip() {
        let config = ThreatLevelEscalation {
            enabled: true,
            violations_before_block: 1,
            violation_window_secs: 300,
            excluded_ips: vec!["10.0.0.8".to_string()],
        };
        let tracker = ViolationTracker::new(config, None, 60, 10);

        let ip: IpAddr = "10.0.0.8".parse().unwrap();
        let count = tracker.record_violation(ip, "test", 1);
        assert_eq!(count, 0);
    }
}
