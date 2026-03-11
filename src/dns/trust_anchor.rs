use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAnchorState {
    Valid,
    Pending,
    Revoked,
    Missing,
}

#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub key_id: String,
    pub key_tag: u16,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
    pub state: TrustAnchorState,
    pub added_at: u64,
    pub last_seen: u64,
    pub trust_point: u64,
}

impl TrustAnchor {
    pub fn new(key_id: String, key_tag: u16, algorithm: u8, public_key: Vec<u8>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            key_id,
            key_tag,
            algorithm,
            public_key,
            state: TrustAnchorState::Valid,
            added_at: now,
            last_seen: now,
            trust_point: now,
        }
    }

    pub fn is_expired(&self, max_age_days: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let max_age_secs = max_age_days * 86400;
        now.saturating_sub(self.last_seen) > max_age_secs
    }

    pub fn refresh(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_seen = now;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchorConfig {
    pub enabled: bool,
    pub anchor_file_path: String,
    pub refresh_interval_secs: u64,
    pub trust_anchor_retention_days: u64,
    pub allow_key_rotation: bool,
}

impl Default for TrustAnchorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            anchor_file_path: "/var/lib/maluwaf/dns/trust-anchors.json".to_string(),
            refresh_interval_secs: 86400,
            trust_anchor_retention_days: 30,
            allow_key_rotation: true,
        }
    }
}

pub struct TrustAnchorManager {
    config: TrustAnchorConfig,
    anchors: RwLock<HashMap<String, TrustAnchor>>,
    pending_keys: RwLock<HashMap<String, TrustAnchor>>,
    last_refresh: RwLock<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchorStore {
    pub version: u32,
    pub anchors: Vec<TrustAnchor>,
    pub last_updated: u64,
}

impl TrustAnchorManager {
    pub fn new(config: TrustAnchorConfig) -> Self {
        Self {
            config: config.clone(),
            anchors: RwLock::new(HashMap::new()),
            pending_keys: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(0),
        }
    }

    pub fn add_anchor(
        &self,
        key_id: String,
        key_tag: u16,
        algorithm: u8,
        public_key: Vec<u8>,
    ) -> Result<(), String> {
        let mut anchors = self.anchors.write();

        if anchors.contains_key(&key_id) {
            return Err(format!("Anchor {} already exists", key_id));
        }

        let anchor = TrustAnchor::new(key_id.clone(), key_tag, algorithm, public_key);
        anchors.insert(key_id, anchor);

        self.save_anchors(&anchors)?;

        Ok(())
    }

    pub fn remove_anchor(&self, key_id: &str) -> Result<(), String> {
        let mut anchors = self.anchors.write();

        if let Some(anchor) = anchors.get_mut(key_id) {
            anchor.state = TrustAnchorState::Revoked;
        } else {
            return Err(format!("Anchor {} not found", key_id));
        }

        self.save_anchors(&anchors)?;

        Ok(())
    }

    pub fn get_anchors(&self) -> Vec<TrustAnchor> {
        let anchors = self.anchors.read();
        anchors
            .values()
            .filter(|a| a.state == TrustAnchorState::Valid)
            .cloned()
            .collect()
    }

    pub fn get_anchor_by_keytag(&self, key_tag: u16) -> Option<TrustAnchor> {
        let anchors = self.anchors.read();
        anchors
            .values()
            .find(|a| a.key_tag == key_tag && a.state == TrustAnchorState::Valid)
            .cloned()
    }

    pub fn process_ds_record(
        &self,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: &[u8],
    ) -> Result<TrustAnchorEvent, String> {
        let anchors = self.anchors.read();

        if anchors
            .values()
            .any(|a| a.key_tag == key_tag && a.state == TrustAnchorState::Valid)
        {
            return Ok(TrustAnchorEvent::KeySeen { key_tag });
        }

        drop(anchors);

        let mut pending = self.pending_keys.write();

        let key_id = format!("pending-{}", key_tag);

        if pending.contains_key(&key_id) {
            if let Some(anchor) = pending.get_mut(&key_id) {
                anchor.refresh();
                return Ok(TrustAnchorEvent::KeyPending { key_tag });
            }
        }

        let new_anchor = TrustAnchor::new(key_id.clone(), key_tag, algorithm, digest.to_vec());

        pending.insert(key_id, new_anchor);

        Ok(TrustAnchorEvent::NewKeyDetected { key_tag })
    }

    pub fn verify_and_promote_keys(&self) -> Result<Vec<String>, String> {
        let mut pending = self.pending_keys.write();
        let mut promoted = Vec::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut to_promote = Vec::new();

        for (key_id, anchor) in pending.iter() {
            if now.saturating_sub(anchor.last_seen)
                >= self.config.trust_anchor_retention_days * 86400
            {
                to_promote.push(key_id.clone());
            }
        }

        for key_id in to_promote {
            if let Some(anchor) = pending.remove(&key_id) {
                let mut anchors = self.anchors.write();
                anchors.insert(anchor.key_id.clone(), anchor);
                promoted.push(anchor.key_id);
            }
        }

        if !promoted.is_empty() {
            let anchors = self.anchors.read();
            self.save_anchors(&anchors)?;
        }

        Ok(promoted)
    }

    pub fn check_for_revoked_keys(&self, revoked_key_tags: &[u16]) -> Vec<u16> {
        let mut anchors = self.anchors.write();
        let mut revoked = Vec::new();

        for key_tag in revoked_key_tags {
            if let Some(anchor) = anchors.values_mut().find(|a| a.key_tag == *key_tag) {
                anchor.state = TrustAnchorState::Revoked;
                revoked.push(*key_tag);
            }
        }

        if !revoked.is_empty() {
            let _ = self.save_anchors(&anchors);
        }

        revoked
    }

    pub fn needs_refresh(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let last = *self.last_refresh.read();

        now.saturating_sub(last) >= self.config.refresh_interval_secs
    }

    pub fn mark_refreshed(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        *self.last_refresh.write() = now;
    }

    fn save_anchors(&self, anchors: &HashMap<String, TrustAnchor>) -> Result<(), String> {
        if !self.config.allow_key_rotation {
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let store = TrustAnchorStore {
            version: 1,
            anchors: anchors.values().cloned().collect(),
            last_updated: now,
        };

        let json = serde_json::to_string_pretty(&store)
            .map_err(|e| format!("Failed to serialize anchors: {}", e))?;

        std::fs::create_dir_all(
            std::path::Path::new(&self.config.anchor_file_path)
                .parent()
                .unwrap(),
        )
        .map_err(|e| format!("Failed to create directory: {}", e))?;

        std::fs::write(&self.config.anchor_file_path, json)
            .map_err(|e| format!("Failed to write anchors: {}", e))?;

        Ok(())
    }

    pub fn load_anchors(&self) -> Result<(), String> {
        let path = std::path::Path::new(&self.config.anchor_file_path);

        if !path.exists() {
            return Ok(());
        }

        let contents =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read anchors: {}", e))?;

        let store: TrustAnchorStore = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse anchors: {}", e))?;

        let mut anchors = self.anchors.write();
        for anchor in store.anchors {
            anchors.insert(anchor.key_id.clone(), anchor);
        }

        Ok(())
    }

    pub fn get_status(&self) -> TrustAnchorStatus {
        let anchors = self.anchors.read();

        TrustAnchorStatus {
            total_anchors: anchors.len(),
            valid_anchors: anchors
                .values()
                .filter(|a| a.state == TrustAnchorState::Valid)
                .count(),
            revoked_anchors: anchors
                .values()
                .filter(|a| a.state == TrustAnchorState::Revoked)
                .count(),
            pending_anchors: *self.pending_keys.read().len(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TrustAnchorEvent {
    KeySeen { key_tag: u16 },
    NewKeyDetected { key_tag: u16 },
    KeyPending { key_tag: u16 },
    KeyPromoted { key_id: String },
    KeyRevoked { key_tag: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchorStatus {
    pub total_anchors: usize,
    pub valid_anchors: usize,
    pub revoked_anchors: usize,
    pub pending_anchors: usize,
}

pub struct TrustAnchorManagerFactory;

impl TrustAnchorManagerFactory {
    pub fn create(config: TrustAnchorConfig) -> Option<Arc<TrustAnchorManager>> {
        if !config.enabled {
            return None;
        }

        let manager = Arc::new(TrustAnchorManager::new(config));

        if let Err(e) = manager.load_anchors() {
            tracing::warn!("Failed to load trust anchors: {}", e);
        }

        Some(manager)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_anchor_creation() {
        let anchor = TrustAnchor::new("test-key".to_string(), 12345, 8, vec![1, 2, 3, 4]);

        assert_eq!(anchor.key_tag, 12345);
        assert_eq!(anchor.state, TrustAnchorState::Valid);
    }

    #[test]
    fn test_process_new_key() {
        let config = TrustAnchorConfig::default();
        let manager = TrustAnchorManager::new(config);

        let result = manager.process_ds_record(12345, 8, 2, &[1, 2, 3, 4]);
        assert!(matches!(
            result,
            Ok(TrustAnchorEvent::NewKeyDetected { .. })
        ));
    }

    #[test]
    fn test_key_promotion() {
        let config = TrustAnchorConfig {
            trust_anchor_retention_days: 0,
            ..TrustAnchorConfig::default()
        };

        let manager = TrustAnchorManager::new(config);

        manager
            .process_ds_record(12345, 8, 2, &[1, 2, 3, 4])
            .unwrap();

        let promoted = manager.verify_and_promote_keys().unwrap();
        assert!(!promoted.is_empty());
    }
}
