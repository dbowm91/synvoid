use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use flate2::read::GzDecoder;
use flate2::{write::GzEncoder, Compression};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use tokio::sync::mpsc;

use crate::mesh::config::{MeshNodeRole, YaraRulesMeshConfig};
use crate::mesh::dht::keys::DhtKey;
use crate::mesh::protocol::MeshMessage;
use crate::upload::yara_rule_feed::YaraRuleFeedManager;

const MAX_PENDING_SUBMISSIONS: usize = 1000;
const SUBMISSION_EXPIRY_SECS: u64 = 86400 * 7;
const YARA_TIMESTAMP_PAST_BOUND_SECS: u64 = 86400;
const YARA_TIMESTAMP_FUTURE_BOUND_SECS: u64 = 60;
const YARA_RULE_CHUNK_SIZE: usize = 32 * 1024;
const YARA_COMPRESSION_LEVEL: u32 = 6;

#[derive(Debug, Clone)]
pub struct BroadcastAckTracker {
    pub request_id: String,
    pub sent_peers: Vec<String>,
    pub acked_peers: Vec<String>,
    pub failed_peers: Vec<String>,
    pub sent_at: Instant,
    pub completed_at: Option<Instant>,
}

impl BroadcastAckTracker {
    pub fn new(request_id: String, sent_peers: Vec<String>) -> Self {
        Self {
            request_id,
            sent_peers,
            acked_peers: Vec::new(),
            failed_peers: Vec::new(),
            sent_at: Instant::now(),
            completed_at: None,
        }
    }

    pub fn record_ack(&mut self, node_id: &str) {
        if !self.acked_peers.contains(&node_id.to_string()) {
            self.acked_peers.push(node_id.to_string());
        }
        if self.is_complete() {
            self.completed_at = Some(Instant::now());
        }
    }

    pub fn record_failure(&mut self, node_id: &str) {
        if !self.failed_peers.contains(&node_id.to_string()) {
            self.failed_peers.push(node_id.to_string());
        }
    }

    pub fn is_complete(&self) -> bool {
        self.acked_peers.len() + self.failed_peers.len() >= self.sent_peers.len()
    }

    pub fn pending_count(&self) -> usize {
        self.sent_peers.len() - self.acked_peers.len() - self.failed_peers.len()
    }

    pub fn ack_rate(&self) -> f64 {
        if self.sent_peers.is_empty() {
            return 1.0;
        }
        self.acked_peers.len() as f64 / self.sent_peers.len() as f64
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BroadcastAckStatus {
    pub request_id: String,
    pub total_peers: usize,
    pub acked_count: usize,
    pub pending_count: usize,
    pub failed_count: usize,
    pub ack_rate: f64,
    pub duration_secs: f64,
    pub is_complete: bool,
}

#[derive(Debug, Clone)]
pub struct RuleChangeTracker {
    pub last_version: Option<String>,
    pub last_full_sync: Option<Instant>,
    pub changes_since_full: usize,
    pub incremental_versions: Vec<String>,
}

impl Default for RuleChangeTracker {
    fn default() -> Self {
        Self {
            last_version: None,
            last_full_sync: Some(Instant::now()),
            changes_since_full: 0,
            incremental_versions: Vec::new(),
        }
    }
}

impl RuleChangeTracker {
    pub fn record_change(&mut self, new_version: &str) {
        if self.last_version.is_none() {
            self.last_full_sync = Some(Instant::now());
            self.changes_since_full = 0;
        } else {
            self.changes_since_full += 1;
        }
        self.last_version = Some(new_version.to_string());
        self.incremental_versions.push(new_version.to_string());
        if self.incremental_versions.len() > 100 {
            self.incremental_versions.remove(0);
        }
    }

    pub fn should_send_full(&self, current_rules_size: usize, delta_size: usize) -> bool {
        if self.changes_since_full == 0 {
            return true;
        }
        if delta_size == 0 {
            return true;
        }
        let ratio = delta_size as f64 / current_rules_size as f64;
        ratio > 0.5
    }

    pub fn get_incremental_versions(&self, count: usize) -> Vec<String> {
        self.incremental_versions
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleSubmission {
    pub submission_id: String,
    pub rules: String,
    pub description: String,
    pub submitted_by: String,
    pub submitted_at: u64,
    pub status: YaraRuleSubmissionStatus,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<u64>,
    pub review_notes: Option<String>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum YaraRuleSubmissionStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleVersionInfo {
    pub version: String,
    pub rules: String,
    pub created_at: u64,
    pub created_by: String,
    pub source: YaraRuleSource,
    pub is_approved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum YaraRuleSource {
    Local,
    Feed,
    MeshGlobal,
    MeshEdgeApproved,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraRulesManagerConfig {
    #[serde(default = "default_yara_manager_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub rules_dir: Option<String>,
    #[serde(default = "default_yara_mesh_broadcast_enabled")]
    pub mesh_broadcast_enabled: bool,
}

fn default_yara_manager_enabled() -> bool {
    true
}

fn default_yara_mesh_broadcast_enabled() -> bool {
    true
}

impl Default for YaraRulesManagerConfig {
    fn default() -> Self {
        Self {
            enabled: default_yara_manager_enabled(),
            rules_dir: None,
            mesh_broadcast_enabled: default_yara_mesh_broadcast_enabled(),
        }
    }
}

impl From<YaraRulesManagerConfig> for YaraRulesMeshConfig {
    fn from(config: YaraRulesManagerConfig) -> Self {
        YaraRulesMeshConfig {
            enabled: config.enabled,
            sync_interval_secs: 3600,
            re_announce_interval_secs: 300,
            allow_edge_submissions: false,
            require_global_approval: true,
            require_signature: true,
            trusted_signers: Vec::new(),
            max_rules_size_kb: 1024,
        }
    }
}

impl From<YaraRulesMeshConfig> for YaraRulesManagerConfig {
    fn from(config: YaraRulesMeshConfig) -> Self {
        YaraRulesManagerConfig {
            enabled: config.enabled,
            rules_dir: None,
            mesh_broadcast_enabled: true,
        }
    }
}

pub struct YaraRulesManager {
    config: Arc<YaraRulesMeshConfig>,
    node_id: String,
    node_role: MeshNodeRole,
    signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
    current_version: Arc<RwLock<Option<String>>>,
    local_rules: Arc<RwLock<Option<String>>>,
    submissions: Arc<RwLock<HashMap<String, YaraRuleSubmission>>>,
    submission_hashes: Arc<RwLock<HashMap<String, String>>>,
    last_sync: RwLock<Instant>,
    feed_manager: Option<Arc<YaraRuleFeedManager>>,
    mesh_sender: Arc<RwLock<Option<mpsc::Sender<MeshMessage>>>>,
    data_dir: Option<std::path::PathBuf>,
    broadcast_tracker: Arc<RwLock<Option<BroadcastAckTracker>>>,
    rule_change_tracker: Arc<RwLock<RuleChangeTracker>>,
    record_store: Arc<RwLock<Option<Arc<crate::mesh::dht::RecordStoreManager>>>>,
}

impl YaraRulesManager {
    pub fn new(
        config: YaraRulesManagerConfig,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
        feed_manager: Option<Arc<YaraRuleFeedManager>>,
        data_dir: Option<std::path::PathBuf>,
    ) -> Self {
        let mesh_config: YaraRulesMeshConfig = config.into();
        let manager = Self {
            config: Arc::new(mesh_config),
            node_id,
            node_role,
            signer,
            current_version: Arc::new(RwLock::new(None)),
            local_rules: Arc::new(RwLock::new(None)),
            submissions: Arc::new(RwLock::new(HashMap::new())),
            submission_hashes: Arc::new(RwLock::new(HashMap::new())),
            last_sync: RwLock::new(Instant::now()),
            feed_manager,
            mesh_sender: Arc::new(RwLock::new(None)),
            data_dir,
            broadcast_tracker: Arc::new(RwLock::new(None)),
            rule_change_tracker: Arc::new(RwLock::new(RuleChangeTracker::default())),
            record_store: Arc::new(RwLock::new(None)),
        };

        if manager.node_role.is_global() || manager.node_role.contains(MeshNodeRole::GLOBAL) {
            let _ = manager.load_submissions_from_disk();
            let _ = manager.load_rules_from_disk();
        }

        manager
    }

    fn rules_dir(&self) -> Option<std::path::PathBuf> {
        self.data_dir.as_ref().map(|d| d.join("yara_rules"))
    }

    fn load_rules_from_disk(&self) -> Result<(), String> {
        let Some(dir) = self.rules_dir() else {
            return Ok(());
        };

        let rules_path = dir.join("current_rules.yar");
        if !rules_path.exists() {
            return Ok(());
        }

        let version_path = dir.join("version.txt");
        let version = if version_path.exists() {
            std::fs::read_to_string(&version_path)
                .ok()
                .map(|v| v.trim().to_string())
        } else {
            None
        };

        let rules_content = std::fs::read_to_string(&rules_path)
            .map_err(|e| format!("Failed to read rules file: {}", e))?;

        if rules_content.is_empty() {
            return Ok(());
        }

        {
            let mut local = self.local_rules.write();
            *local = Some(rules_content.clone());
        }

        if let Some(v) = version {
            let mut current = self.current_version.write();
            *current = Some(v.clone());
            tracing::info!("Loaded YARA rules from disk, version: {}", v);
        } else {
            tracing::info!("Loaded YARA rules from disk (unknown version)");
        }

        Ok(())
    }

    fn save_rules_to_disk(&self) -> Result<(), String> {
        let Some(dir) = self.rules_dir() else {
            return Ok(());
        };

        let rules = match self.local_rules.read().clone() {
            Some(r) => r,
            None => return Ok(()),
        };

        let version = self.current_version.read().clone();

        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create rules dir: {}", e))?;

        let rules_path = dir.join("current_rules.yar");
        std::fs::write(&rules_path, &rules)
            .map_err(|e| format!("Failed to write rules file: {}", e))?;

        if let Some(v) = version {
            let version_path = dir.join("version.txt");
            std::fs::write(&version_path, &v)
                .map_err(|e| format!("Failed to write version file: {}", e))?;
        }

        tracing::debug!("Saved YARA rules to disk");
        Ok(())
    }

    pub fn set_mesh_sender(&self, sender: mpsc::Sender<MeshMessage>) {
        let mut sender_guard = self.mesh_sender.write();
        *sender_guard = Some(sender);
    }

    pub fn set_record_store(&self, record_store: Arc<crate::mesh::dht::RecordStoreManager>) {
        let mut rs = self.record_store.write();
        *rs = Some(record_store);
    }

    fn compress_rules(&self, rules: &str) -> Result<Vec<u8>, String> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(YARA_COMPRESSION_LEVEL));
        encoder
            .write_all(rules.as_bytes())
            .map_err(|e| format!("Compression write error: {}", e))?;
        encoder
            .finish()
            .map_err(|e| format!("Compression finish error: {}", e))
    }

    fn split_into_chunks(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        let mut start = 0;
        while start < data.len() {
            let end = (start + YARA_RULE_CHUNK_SIZE).min(data.len());
            chunks.push(data[start..end].to_vec());
            start = end;
        }
        chunks
    }

    fn reassemble_chunks(&self, chunks: &[Vec<u8>]) -> Result<String, String> {
        let mut decompressed = Vec::new();
        for chunk in chunks {
            let mut decoder = GzDecoder::new(chunk.as_slice());
            std::io::copy(&mut decoder, &mut decompressed)
                .map_err(|e| format!("Decompression error: {}", e))?;
        }
        String::from_utf8(decompressed).map_err(|e| format!("UTF-8 error: {}", e))
    }

    pub fn publish_rules_to_dht(&self) {
        if !self.config.enabled {
            return;
        }

        if !self.is_global() {
            tracing::debug!("Skipping DHT publish for non-global node");
            return;
        }

        let record_store_opt = self.record_store.read().clone();
        let Some(record_store) = record_store_opt else {
            tracing::debug!("Record store not available for DHT publish");
            return;
        };

        let rules = match self.local_rules.read().clone() {
            Some(r) => r,
            None => {
                tracing::debug!("No local rules to publish to DHT");
                return;
            }
        };

        let version = match self.current_version.read().clone() {
            Some(v) => v,
            None => {
                tracing::debug!("No version to publish to DHT");
                return;
            }
        };

        let content_hash = self.compute_rules_hash(&rules);
        let timestamp = crate::mesh::safe_unix_timestamp();

        let compressed = match self.compress_rules(&rules) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to compress rules: {}", e);
                return;
            }
        };

        let chunks = self.split_into_chunks(&compressed);
        let chunk_count = chunks.len();
        let is_chunked = chunk_count > 1;
        let uncompressed_size = rules.len();
        let compressed_size = compressed.len();

        tracing::debug!(
            "YARA rules: {} bytes -> {} bytes ({} chunks, chunked={})",
            uncompressed_size,
            compressed_size,
            chunk_count,
            is_chunked
        );

        let chunk_hashes: Vec<String> = chunks
            .iter()
            .map(|c| {
                let mut hasher = Sha256::new();
                hasher.update(c);
                format!("{:x}", hasher.finalize())[..16].to_string()
            })
            .collect();

        let (manifest_signature, manifest_signer_pk) = if let Some(ref signer) = self.signer {
            let content = format!(
                "{}:{}:{}:{}:{}:{}",
                version,
                content_hash,
                self.node_id,
                timestamp,
                chunk_count,
                is_chunked
            );
            let sig = signer.sign(&content);
            let pk = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                signer.get_public_key_bytes(),
            );
            (sig, Some(pk))
        } else {
            (Vec::new(), None)
        };

        let manifest_value = serde_json::json!({
            "version": version,
            "content_hash": content_hash,
            "node_id": self.node_id,
            "timestamp": timestamp,
            "signature": manifest_signature,
            "signer_public_key": manifest_signer_pk,
            "is_chunked": is_chunked,
            "chunk_count": chunk_count,
            "uncompressed_size": uncompressed_size,
            "compressed_size": compressed_size,
            "chunk_hashes": chunk_hashes,
        });

        let manifest_key = DhtKey::yara_rules_manifest(&self.node_id);
        let manifest_key_str = manifest_key.as_str();

        if let Ok(bytes) = serde_json::to_vec(&manifest_value) {
            if record_store.store_and_announce(manifest_key_str.to_string(), bytes, 86400) {
                tracing::debug!(
                    "Published YARA manifest to DHT: {} -> {} (chunked={})",
                    manifest_key_str,
                    version,
                    is_chunked
                );
            } else {
                tracing::warn!("Failed to store YARA manifest in DHT");
            }
        }

        if is_chunked {
            for (i, chunk) in chunks.iter().enumerate() {
                let chunk_key = format!("yara_chunk:{}:{}", content_hash, i);
                let chunk_signature = if let Some(ref signer) = self.signer {
                    let content = format!(
                        "{}:{}:{}:{}:{}",
                        content_hash, i, chunk.len(), self.node_id, timestamp
                    );
                    signer.sign(&content)
                } else {
                    Vec::new()
                };

                let chunk_value = serde_json::json!({
                    "chunk_index": i,
                    "total_chunks": chunk_count,
                    "content_hash": content_hash,
                    "node_id": self.node_id,
                    "timestamp": timestamp,
                    "compressed_data": base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        chunk
                    ),
                    "signature": chunk_signature,
                });

                if let Ok(bytes) = serde_json::to_vec(&chunk_value) {
                    let _ = record_store.store_and_announce(chunk_key, bytes, 86400);
                }
            }
            tracing::info!(
                "Published YARA rules as {} chunks to DHT (version: {})",
                chunk_count,
                version
            );
        } else {
            if let Some(_existing) = record_store.get(&DhtKey::yara_rule_content(&content_hash).as_str()) {
                tracing::debug!("YARA rule content already in DHT: {}", content_hash);
                return;
            }

            let (rule_signature, rule_signer_pk) = if let Some(ref signer) = self.signer {
                let content = format!(
                    "{}:{}:{}:{}:{}",
                    version, rules, content_hash, self.node_id, timestamp
                );
                let sig = signer.sign(&content);
                let pk = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    signer.get_public_key_bytes(),
                );
                (sig, Some(pk))
            } else {
                (Vec::new(), None)
            };

            let rule_value = serde_json::json!({
                "version": version,
                "rules": rules,
                "content_hash": content_hash,
                "node_id": self.node_id,
                "timestamp": timestamp,
                "signature": rule_signature,
                "signer_public_key": rule_signer_pk,
                "is_chunked": false,
            });

            if let Ok(bytes) = serde_json::to_vec(&rule_value) {
                if record_store.store_and_announce(
                    DhtKey::yara_rule_content(&content_hash).as_str().to_string(),
                    bytes,
                    86400,
                ) {
                    tracing::info!(
                        "Published YARA rules to DHT: {} (version: {})",
                        content_hash,
                        version
                    );
                } else {
                    tracing::warn!("Failed to store YARA rules in DHT");
                }
            }
        }
    }

    fn fetch_rules_from_dht(
        &self,
        content_hash: &str,
        record_store: &Arc<crate::mesh::dht::RecordStoreManager>,
    ) -> Option<(String, String, u64)> {
        let rule_key = DhtKey::yara_rule_content(content_hash);
        let Some(rule_record) = record_store.get(&rule_key.as_str()) else {
            tracing::debug!("YARA sync: no rule record found for hash {}", content_hash);
            return None;
        };

        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&rule_record.value) else {
            tracing::warn!("YARA sync: failed to parse rule record");
            return None;
        };

        let rules_str = value.get("rules").and_then(|v| v.as_str())?.to_string();
        let version_str = value.get("version").and_then(|v| v.as_str())?.to_string();
        let timestamp_str = value.get("timestamp").and_then(|v| v.as_str()).unwrap_or("0");
        let timestamp: u64 = timestamp_str.parse().unwrap_or(0);

        let is_chunked = value.get("is_chunked").and_then(|v| v.as_bool()).unwrap_or(false);
        if is_chunked {
            tracing::debug!("YARA sync: expected chunked data but got single record for hash {}", content_hash);
            return None;
        }

        Some((version_str, rules_str, timestamp))
    }

    fn fetch_chunks_from_dht(
        &self,
        content_hash: &str,
        chunk_count: usize,
        record_store: &Arc<crate::mesh::dht::RecordStoreManager>,
    ) -> Option<(String, String, u64)> {
        let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(chunk_count);
        let mut version_str = None;
        let mut timestamp: u64 = 0;

        for i in 0..chunk_count {
            let chunk_key = format!("yara_chunk:{}:{}", content_hash, i);
            let Some(chunk_record) = record_store.get(&chunk_key) else {
                tracing::warn!("YARA sync: missing chunk {} for hash {}", i, content_hash);
                return None;
            };

            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&chunk_record.value) else {
                tracing::warn!("YARA sync: failed to parse chunk record");
                return None;
            };

            let compressed_b64 = value.get("compressed_data").and_then(|v| v.as_str())?;
            let compressed_data = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                compressed_b64,
            )
            .ok()?;

            if version_str.is_none() {
                version_str = value.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());
            }

            let ts_str = value.get("timestamp").and_then(|v| v.as_str()).unwrap_or("0");
            let ts: u64 = ts_str.parse().unwrap_or(0);
            if ts > timestamp {
                timestamp = ts;
            }

            chunks.push(compressed_data);
        }

        let version_str = version_str?;

        let rules_str = match self.reassemble_chunks(&chunks) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("YARA sync: failed to reassemble chunks: {}", e);
                return None;
            }
        };

        Some((version_str, rules_str, timestamp))
    }

    pub fn sync_from_dht(&self) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        let record_store_opt = self.record_store.read().clone();
        let Some(record_store) = record_store_opt else {
            return Err("Record store not set".to_string());
        };

        let dht_records = record_store.get_by_prefix("yara_rules_manifest:");
        let local_rules = self.local_rules.read().clone();
        let local_hash = local_rules.as_ref().map(|r| self.compute_rules_hash(r));

        let mut best_version: Option<String> = None;
        let mut best_rules: Option<String> = None;
        let mut best_hash: Option<String> = None;
        let mut best_timestamp: Option<u64> = None;

        for record in &dht_records {
            if record.key.starts_with("yara_rules_manifest:") {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&record.value) {
                    let manifest_node_id =
                        value.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
                    if manifest_node_id == self.node_id {
                        continue;
                    }

                    let peer_hash = value
                        .get("content_hash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    let manifest_version =
                        value.get("version").and_then(|v| v.as_str()).unwrap_or("");
                    let manifest_timestamp_str = value
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0");
                    let manifest_timestamp: u64 = manifest_timestamp_str.parse().unwrap_or(0);
                    let now = crate::utils::current_timestamp();
                    if manifest_timestamp > now + YARA_TIMESTAMP_FUTURE_BOUND_SECS {
                        tracing::warn!(
                            "YARA DHT sync: manifest timestamp {} is too far in the future (now: {}) from {}",
                            manifest_timestamp,
                            now,
                            manifest_node_id
                        );
                        continue;
                    }
                    if now > manifest_timestamp
                        && now - manifest_timestamp > YARA_TIMESTAMP_PAST_BOUND_SECS
                    {
                        tracing::warn!(
                            "YARA DHT sync: manifest timestamp {} is too old (now: {}) from {}",
                            manifest_timestamp,
                            now,
                            manifest_node_id
                        );
                        continue;
                    }

                    let is_chunked = value.get("is_chunked").and_then(|v| v.as_bool()).unwrap_or(false);
                    let chunk_count = value.get("chunk_count").and_then(|v| v.as_u64()).unwrap_or(1) as usize;

                    let manifest_signature = value
                        .get("signature")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let manifest_signer_pk = value
                        .get("signer_public_key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    let signature_content = if is_chunked {
                        format!(
                            "{}:{}:{}:{}:{}:{}",
                            manifest_version, peer_hash, manifest_node_id, manifest_timestamp, chunk_count, is_chunked
                        )
                    } else {
                        format!(
                            "{}:{}:{}:{}",
                            manifest_version, peer_hash, manifest_node_id, manifest_timestamp
                        )
                    };

                    if !manifest_signature.is_empty() && !manifest_signer_pk.is_empty() {
                        let sig_bytes = match base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            manifest_signature,
                        ) {
                            Ok(s) => s,
                            Err(_) => {
                                tracing::warn!(
                                    "YARA DHT sync: invalid manifest signature base64 from {}",
                                    manifest_node_id
                                );
                                continue;
                            }
                        };
                        let pk_bytes = match base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            manifest_signer_pk,
                        ) {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::warn!(
                                    "YARA DHT sync: invalid manifest signer pk base64 from {}",
                                    manifest_node_id
                                );
                                continue;
                            }
                        };

                        let signer = crate::mesh::protocol::MeshMessageSigner::new(
                            pk_bytes.clone().try_into().unwrap_or([0u8; 32]),
                        );
                        if !signer.verify(&signature_content, &sig_bytes, &pk_bytes) {
                            tracing::warn!(
                                "YARA DHT sync: manifest signature verification failed for record from {}",
                                manifest_node_id
                            );
                            continue;
                        }
                        if !self.config.trusted_signers.is_empty()
                            && !self
                                .config
                                .trusted_signers
                                .contains(&manifest_signer_pk.to_string())
                        {
                            tracing::warn!(
                                "YARA DHT sync: manifest signer pk {} is not in trusted signers list for record from {}",
                                manifest_signer_pk,
                                manifest_node_id
                            );
                            continue;
                        }
                    }

                    if let Some(ref local_h) = local_hash {
                        if local_h == peer_hash {
                            tracing::debug!(
                                "DHT sync: peer {} has same rules hash {}",
                                manifest_node_id,
                                peer_hash
                            );
                            continue;
                        }
                    }

                    let rules_str = if is_chunked {
                        self.fetch_chunks_from_dht(peer_hash, chunk_count, &record_store)
                    } else {
                        self.fetch_rules_from_dht(peer_hash, &record_store)
                    };

                    let Some((version_str, rules_string, timestamp)) = rules_str else {
                        continue;
                    };

                    if rules_string.is_empty() {
                        continue;
                    }

                    match &best_timestamp {
                        None => {
                            best_version = Some(version_str.to_string());
                            best_rules = Some(rules_string);
                            best_hash = Some(peer_hash.to_string());
                            best_timestamp = Some(timestamp);
                        }
                        Some(current_best) => {
                            if timestamp > *current_best {
                                best_version = Some(version_str.to_string());
                                best_rules = Some(rules_string);
                                best_hash = Some(peer_hash.to_string());
                                best_timestamp = Some(timestamp);
                            }
                        }
                    }
                }
            }
        }

        if let Some(new_version) = best_version {
            if let Some(new_rules) = best_rules {
                if let Some(new_hash) = best_hash {
                    let current_rules = self.local_rules.read().clone();
                    let should_apply = match &current_rules {
                        Some(r) => {
                            let current_hash = self.compute_rules_hash(r);
                            current_hash != new_hash
                        }
                        None => true,
                    };

                    if should_apply {
                        tracing::info!(
                            "DHT sync: applying newer rules version {} from peer",
                            new_version
                        );
                        self.apply_rules(
                            new_rules,
                            new_version.clone(),
                            YaraRuleSource::MeshGlobal,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn get_current_version(&self) -> Option<String> {
        self.current_version.read().clone()
    }

    pub fn get_current_rules(&self) -> Option<String> {
        self.local_rules.read().clone()
    }

    pub fn has_feed_manager(&self) -> bool {
        self.feed_manager.is_some()
    }

    pub fn get_feed_manager(
        &self,
    ) -> Option<Arc<crate::upload::yara_rule_feed::YaraRuleFeedManager>> {
        self.feed_manager.clone()
    }

    pub fn is_global(&self) -> bool {
        self.node_role.is_global() || self.node_role.contains(MeshNodeRole::GLOBAL)
    }

    pub fn apply_rules_from_feed(&self) -> Result<String, String> {
        if let Some(ref feed_manager) = self.feed_manager {
            let version = feed_manager.apply_rules()?;
            if let Some(rules) = feed_manager.get_rules_for_scanner() {
                *self.local_rules.write() = Some(rules.clone());
                *self.current_version.write() = Some(version.clone());
                tracing::info!("Applied YARA rules from feed, version: {}", version);

                let _ = self.save_rules_to_disk();

                if self.node_role.is_global() {
                    let _ = self.broadcast_approved_rules(&version);
                }

                return Ok(version);
            }
        }
        Err("No feed manager or no applied rules".to_string())
    }

    pub fn apply_rules(
        &self,
        rules: String,
        version: String,
        source: YaraRuleSource,
    ) -> Result<String, String> {
        let current_rules = self.local_rules.read().clone();
        let current_hash = current_rules.as_ref().map(|r| self.compute_rules_hash(r));
        let new_hash = self.compute_rules_hash(&rules);

        if current_hash.as_ref() == Some(&new_hash) {
            tracing::debug!("Rules unchanged (hash {}), skipping publish", &new_hash[..8]);
            *self.current_version.write() = Some(version.clone());
            return Ok(version);
        }

        *self.local_rules.write() = Some(rules.clone());
        *self.current_version.write() = Some(version.clone());

        let _ = self.save_rules_to_disk();

        if let Some(ref fm) = self.feed_manager {
            let source_str = match source {
                YaraRuleSource::Local => "Local",
                YaraRuleSource::Feed => "Feed",
                YaraRuleSource::MeshGlobal => "Mesh",
                YaraRuleSource::MeshEdgeApproved => "MeshApproved",
            };
            fm.add_to_history_inline(version.clone(), rules, source_str.to_string());
        }

        self.rule_change_tracker.write().record_change(&version);

        match source {
            YaraRuleSource::Local
            | YaraRuleSource::Feed
            | YaraRuleSource::MeshEdgeApproved
            | YaraRuleSource::MeshGlobal => {
                self.publish_rules_to_dht();
            }
        }

        tracing::info!("Applied YARA rules version {} from {:?}", version, source);
        Ok(version)
    }

    pub fn submit_rule_for_approval(
        &self,
        rules: String,
        description: String,
    ) -> Result<String, String> {
        if !self.config.allow_edge_submissions {
            return Err("Edge submissions are disabled".to_string());
        }

        if !self.node_role.is_edge() && !self.node_role.contains(MeshNodeRole::EDGE) {
            return Err("Only edge nodes can submit rules".to_string());
        }

        self.validate_rules_content(&rules)?;

        let content_hash = self.compute_rules_hash(&rules);
        if let Some(existing_id) = self.find_duplicate_submission(&content_hash) {
            tracing::info!(
                "Duplicate YARA submission detected: {} -> {}",
                content_hash,
                existing_id
            );
            return Ok(existing_id);
        }

        self.validate_rules_syntax(&rules)?;

        let submission_id = uuid::Uuid::new_v4().to_string();
        let submission_id_clone = submission_id.clone();
        let now = crate::mesh::safe_unix_timestamp();

        let mut signature = Vec::new();
        if let Some(ref signer) = self.signer {
            let content = format!("{}:{}:{}:{}", submission_id, rules.len(), self.node_id, now);
            signature = signer.sign(&content);
        }

        let submission = YaraRuleSubmission {
            submission_id: submission_id.clone(),
            rules,
            submitted_by: self.node_id.clone(),
            submitted_at: now,
            description,
            status: YaraRuleSubmissionStatus::Pending,
            reviewed_by: None,
            reviewed_at: None,
            review_notes: None,
            signature,
        };

        let submission_clone = submission.clone();
        self.submissions
            .write()
            .insert(submission_id.clone(), submission);

        self.submission_hashes
            .write()
            .insert(content_hash, submission_id.clone());

        if let Err(e) = self.save_submission_to_disk(&submission_clone) {
            tracing::warn!("Failed to save submission to disk: {}", e);
        }

        self.broadcast_submission(&submission_clone)?;

        tracing::info!("Submitted YARA rules for approval: {}", submission_id_clone);
        Ok(submission_id_clone)
    }

    fn compute_rules_hash(&self, rules: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(rules.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn find_duplicate_submission(&self, content_hash: &str) -> Option<String> {
        self.submission_hashes.read().get(content_hash).cloned()
    }

    fn validate_rules_content(&self, rules: &str) -> Result<(), String> {
        let max_size = (self.config.max_rules_size_kb as usize) * 1024;
        if rules.len() > max_size {
            return Err(format!(
                "Rules size {} exceeds maximum allowed size {}KB",
                rules.len(),
                self.config.max_rules_size_kb
            ));
        }

        if !rules.contains("rule ") {
            return Err("Rules must contain at least one 'rule' declaration".to_string());
        }

        let rule_count = rules.matches("rule ").count();
        if rule_count > 100 {
            tracing::warn!(
                "Submission contains {} rules, which is unusually high",
                rule_count
            );
        }

        Ok(())
    }

    fn validate_rules_syntax(&self, rules: &str) -> Result<(), String> {
        match yara_x::compile(rules) {
            Ok(_) => {
                tracing::debug!("YARA rules syntax validation passed");
                Ok(())
            }
            Err(e) => {
                tracing::warn!("YARA rules syntax validation failed: {}", e);
                Err(format!("Invalid YARA syntax: {}", e))
            }
        }
    }

    fn broadcast_submission(&self, submission: &YaraRuleSubmission) -> Result<(), String> {
        let sender = self.mesh_sender.read();
        if let Some(ref sender) = *sender {
            let signer_public_key = self
                .signer
                .as_ref()
                .map(|s| s.get_public_key())
                .unwrap_or_default();

            let message = MeshMessage::YaraRuleSubmission {
                request_id: submission.submission_id.clone().into(),
                submission_id: submission.submission_id.clone().into(),
                node_id: submission.submitted_by.clone().into(),
                timestamp: submission.submitted_at,
                signature: submission.signature.clone(),
                rules: submission.rules.clone(),
                description: submission.description.clone(),
                signer_public_key,
            };

            let sender_clone = sender.clone();
            let request_id = submission.submission_id.clone();
            tokio::spawn(async move {
                Self::send_with_retry(sender_clone, message, 3, request_id).await;
            });
        }
        Ok(())
    }

    async fn send_with_retry(
        sender: mpsc::Sender<MeshMessage>,
        message: MeshMessage,
        max_retries: u32,
        request_id: String,
    ) {
        let mut attempt = 0;
        loop {
            match sender.send(message.clone()).await {
                Ok(()) => {
                    tracing::debug!("Broadcast sent successfully for request_id: {}", request_id);
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= max_retries {
                        tracing::warn!(
                            "Broadcast failed after {} attempts for request_id: {}: {}",
                            max_retries,
                            request_id,
                            e
                        );
                        crate::metrics::record_dropped_yara_broadcast();
                        break;
                    }
                    let backoff_ms = 100 * 2u64.pow(attempt - 1);
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    tracing::debug!(
                        "Broadcast attempt {} failed for request_id: {}, retrying in {}ms",
                        attempt,
                        request_id,
                        backoff_ms
                    );
                }
            }
        }
    }

    pub fn approve_submission(
        &self,
        submission_id: &str,
        review_notes: Option<String>,
    ) -> Result<String, String> {
        if !self.node_role.is_global() && !self.node_role.contains(MeshNodeRole::GLOBAL) {
            return Err("Only global nodes can approve submissions".to_string());
        }

        let mut submissions = self.submissions.write();
        let submission = submissions
            .get_mut(submission_id)
            .ok_or("Submission not found")?;

        if submission.status != YaraRuleSubmissionStatus::Pending {
            return Err("Submission already processed".to_string());
        }

        let now = crate::mesh::safe_unix_timestamp();

        submission.status = YaraRuleSubmissionStatus::Approved;
        submission.reviewed_by = Some(self.node_id.clone());
        submission.reviewed_at = Some(now);
        submission.review_notes = review_notes;

        let rules = submission.rules.clone();
        let submission_id_str = submission.submission_id.clone();
        let version = format!("edge-{}-{}", &submission_id_str[..8], now);

        drop(submissions);

        self.apply_rules(rules, version.clone(), YaraRuleSource::MeshEdgeApproved)?;

        let _ = self.delete_submission_from_disk(submission_id);

        self.broadcast_approved_rules(&version)?;

        tracing::info!("Approved YARA rule submission: {}", version);
        Ok(version)
    }

    pub fn reject_submission(
        &self,
        submission_id: &str,
        review_notes: String,
    ) -> Result<(), String> {
        if !self.node_role.is_global() && !self.node_role.contains(MeshNodeRole::GLOBAL) {
            return Err("Only global nodes can reject submissions".to_string());
        }

        let mut submissions = self.submissions.write();
        let submission = submissions
            .get_mut(submission_id)
            .ok_or("Submission not found")?;

        if submission.status != YaraRuleSubmissionStatus::Pending {
            return Err("Submission already processed".to_string());
        }

        let now = crate::mesh::safe_unix_timestamp();

        submission.status = YaraRuleSubmissionStatus::Rejected;
        submission.reviewed_by = Some(self.node_id.clone());
        submission.reviewed_at = Some(now);
        submission.review_notes = Some(review_notes);

        let _ = self.delete_submission_from_disk(submission_id);

        tracing::info!("Rejected YARA rule submission: {}", submission_id);
        Ok(())
    }

    pub fn get_pending_submissions(&self) -> Vec<YaraRuleSubmission> {
        self.submissions
            .read()
            .values()
            .filter(|s| s.status == YaraRuleSubmissionStatus::Pending)
            .cloned()
            .collect()
    }

    pub fn cleanup_expired_submissions(&self) {
        let now = crate::mesh::safe_unix_timestamp();
        let expiry_time = now.saturating_sub(SUBMISSION_EXPIRY_SECS);

        let mut submissions = self.submissions.write();
        let expired_ids: Vec<String> = submissions
            .iter()
            .filter(|(_, s)| {
                s.status == YaraRuleSubmissionStatus::Pending && s.submitted_at < expiry_time
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in &expired_ids {
            submissions.remove(id);
        }

        if !expired_ids.is_empty() {
            tracing::info!(
                "Cleaned up {} expired YARA rule submissions",
                expired_ids.len()
            );
        }

        if submissions.len() >= MAX_PENDING_SUBMISSIONS {
            let mut pending: Vec<_> = submissions
                .iter()
                .filter(|(_, s)| s.status == YaraRuleSubmissionStatus::Pending)
                .map(|(id, s)| (id.clone(), s.submitted_at))
                .collect();
            pending.sort_by_key(|(_, ts)| *ts);
            let to_remove = pending.len().saturating_sub(MAX_PENDING_SUBMISSIONS / 2);
            for (id, _) in pending.into_iter().take(to_remove) {
                submissions.remove(&id);
            }
            tracing::warn!(
                "Trimmed {} old pending submissions to stay within limit",
                to_remove
            );
        }
    }

    pub fn get_all_submissions(&self) -> Vec<YaraRuleSubmission> {
        self.submissions.read().values().cloned().collect()
    }

    pub fn get_submission(&self, submission_id: &str) -> Option<YaraRuleSubmission> {
        self.submissions.read().get(submission_id).cloned()
    }

    pub fn apply_rules_direct(&self, rules: String, version: String) -> Result<String, String> {
        if !self.is_global() {
            return Err("Only global nodes can apply rules directly".to_string());
        }
        self.apply_rules(rules, version, YaraRuleSource::Local)
    }

    pub fn delete_submission(&self, submission_id: &str) -> Result<(), String> {
        let mut submissions = self.submissions.write();
        let submission = submissions
            .get(submission_id)
            .ok_or("Submission not found")?;

        if submission.status != YaraRuleSubmissionStatus::Pending
            && submission.status != YaraRuleSubmissionStatus::Rejected
        {
            return Err("Can only delete Pending or Rejected submissions".to_string());
        }

        submissions.remove(submission_id);
        drop(submissions);

        self.delete_submission_from_disk(submission_id)?;
        tracing::info!("Deleted YARA rule submission: {}", submission_id);
        Ok(())
    }

    pub fn broadcast_approved_rules(&self, version: &str) -> Result<(), String> {
        let sender = self.mesh_sender.read();
        if let Some(ref sender) = *sender {
            let rules = self.local_rules.read().clone().ok_or("No local rules")?;

            let signer_public_key = self
                .signer
                .as_ref()
                .map(|s| s.get_public_key())
                .unwrap_or_default();

            let signature = if let Some(ref signer) = self.signer {
                let sign_content = format!("{}:{}", version, rules);
                signer.sign(&sign_content)
            } else {
                Vec::new()
            };

            let message = MeshMessage::YaraRuleAnnounce {
                request_id: uuid::Uuid::new_v4().to_string().into(),
                version: version.into(),
                rules,
                timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                source_node_id: self.node_id.clone().into(),
                source_role: self.node_role,
                signature,
                signer_public_key,
            };

            let sender_clone = sender.clone();
            let request_id = version.to_string();
            tokio::spawn(async move {
                Self::send_with_retry(sender_clone, message, 3, request_id).await;
            });
        }
        Ok(())
    }

    pub fn start_broadcast_tracking(&self, request_id: String, sent_peers: Vec<String>) {
        let peer_count = sent_peers.len();
        let tracker = BroadcastAckTracker::new(request_id, sent_peers);
        *self.broadcast_tracker.write() = Some(tracker);
        tracing::debug!("Started broadcast tracking with {} peers", peer_count);
    }

    pub fn record_broadcast_ack(&self, node_id: &str) {
        if let Some(ref mut tracker) = *self.broadcast_tracker.write() {
            tracker.record_ack(node_id);
            tracing::debug!(
                "Recorded ACK from {} for broadcast {} ({}/{} acked)",
                node_id,
                tracker.request_id,
                tracker.acked_peers.len(),
                tracker.sent_peers.len()
            );
        }
    }

    pub fn record_broadcast_failure(&self, node_id: &str) {
        if let Some(ref mut tracker) = *self.broadcast_tracker.write() {
            tracker.record_failure(node_id);
            tracing::debug!(
                "Recorded failure for {} in broadcast {} ({}/{} acked)",
                node_id,
                tracker.request_id,
                tracker.acked_peers.len(),
                tracker.sent_peers.len()
            );
        }
    }

    pub fn get_broadcast_status(&self) -> Option<BroadcastAckStatus> {
        self.broadcast_tracker.read().as_ref().map(|tracker| {
            let duration = tracker
                .completed_at
                .map(|c| c.saturating_duration_since(tracker.sent_at))
                .unwrap_or_else(|| tracker.sent_at.elapsed());
            BroadcastAckStatus {
                request_id: tracker.request_id.clone(),
                total_peers: tracker.sent_peers.len(),
                acked_count: tracker.acked_peers.len(),
                pending_count: tracker.pending_count(),
                failed_count: tracker.failed_peers.len(),
                ack_rate: tracker.ack_rate(),
                duration_secs: duration.as_secs_f64(),
                is_complete: tracker.is_complete(),
            }
        })
    }

    pub fn clear_broadcast_tracker(&self) {
        *self.broadcast_tracker.write() = None;
    }

    pub fn should_sync(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        let last = *self.last_sync.read();
        last.elapsed() > Duration::from_secs(self.config.sync_interval_secs)
    }

    pub fn record_sync(&self) {
        *self.last_sync.write() = Instant::now();
    }

    fn submissions_dir(&self) -> Option<std::path::PathBuf> {
        self.data_dir.as_ref().map(|d| d.join("yara_submissions"))
    }

    fn save_submission_to_disk(&self, submission: &YaraRuleSubmission) -> Result<(), String> {
        let Some(dir) = self.submissions_dir() else {
            return Ok(());
        };

        let path = dir.join(format!("{}.json", submission.submission_id));

        let json = serde_json::to_string_pretty(submission)
            .map_err(|e| format!("Failed to serialize submission: {}", e))?;

        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create submissions dir: {}", e))?;

        std::fs::write(&path, json).map_err(|e| format!("Failed to write submission: {}", e))?;

        tracing::debug!("Saved submission {} to disk", submission.submission_id);
        Ok(())
    }

    fn load_submissions_from_disk(&self) -> Result<(), String> {
        let Some(dir) = self.submissions_dir() else {
            return Ok(());
        };

        if !dir.exists() {
            return Ok(());
        }

        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("Failed to read submissions dir: {}", e))?;

        let mut loaded = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                match std::fs::read_to_string(&path) {
                    Ok(content) => match serde_json::from_str::<YaraRuleSubmission>(&content) {
                        Ok(submission) => {
                            if submission.status == YaraRuleSubmissionStatus::Pending {
                                self.submissions
                                    .write()
                                    .insert(submission.submission_id.clone(), submission);
                                loaded += 1;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse submission {:?}: {}", path, e);
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to read submission {:?}: {}", path, e);
                    }
                }
            }
        }

        if loaded > 0 {
            tracing::info!("Loaded {} pending YARA rule submissions from disk", loaded);
        }

        Ok(())
    }

    pub fn delete_submission_from_disk(&self, submission_id: &str) -> Result<(), String> {
        let Some(dir) = self.submissions_dir() else {
            return Ok(());
        };

        let path = dir.join(format!("{}.json", submission_id));

        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("Failed to delete submission: {}", e))?;
            tracing::debug!("Deleted submission {} from disk", submission_id);
        }

        Ok(())
    }

    pub fn request_sync_from_global(&self) -> Option<MeshMessage> {
        if !self.config.enabled {
            return None;
        }

        Some(MeshMessage::YaraRuleSyncRequest {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            node_id: self.node_id.clone().into(),
            version: self.current_version.read().clone(),
        })
    }

    pub fn send_sync_request_to_global(&self) {
        if !self.config.enabled {
            return;
        }

        let sender = self.mesh_sender.read();
        if let Some(ref sender) = *sender {
            let msg = MeshMessage::YaraRuleSyncRequest {
                request_id: uuid::Uuid::new_v4().to_string().into(),
                node_id: self.node_id.clone().into(),
                version: self.current_version.read().clone(),
            };
            if sender.try_send(msg).is_err() {
                tracing::warn!("Failed to send YARA rules sync message");
            }
        }
    }

    pub fn handle_incoming_rules(
        &self,
        version: String,
        rules: String,
        _from_node: &str,
    ) -> Result<String, String> {
        if rules.len() > (self.config.max_rules_size_kb as usize) * 1024 {
            return Err("Rules size exceeds limit".to_string());
        }

        let current = self.current_version.read();
        if let Some(ref current_ver) = *current {
            if !crate::utils::is_newer_version(&version, current_ver) {
                if let Some(ref current_rules) = *self.local_rules.read() {
                    let incoming_hash = self.compute_rules_hash(&rules);
                    let current_hash = self.compute_rules_hash(current_rules);
                    if incoming_hash == current_hash {
                        tracing::debug!("Received rules have same content as current (version {}), treating as idempotent", version);
                        return Ok(current_ver.clone());
                    }
                }
                return Err("Received rules are not newer".to_string());
            }
        }
        drop(current);

        self.apply_rules(rules, version, YaraRuleSource::MeshGlobal)
    }

    pub fn handle_mesh_message(
        &self,
        message: &MeshMessage,
        from_node: &str,
    ) -> Option<MeshMessage> {
        match message {
            MeshMessage::YaraRuleAnnounce {
                request_id,
                version,
                rules,
                timestamp: _,
                source_node_id: _,
                source_role: _,
                signature,
                signer_public_key,
            } => {
                tracing::info!(
                    "Received YARA rule announce from {}: version {}",
                    from_node,
                    version
                );

                // Verify signature if the sender provided one and we have a signer
                if !signature.is_empty() && !signer_public_key.is_empty() {
                    if let Some(ref signer) = self.signer {
                        let sign_content = format!("{}:{}", version, rules);
                        let pk_bytes = base64::engine::general_purpose::STANDARD
                            .decode(signer_public_key)
                            .unwrap_or_default();
                        if !signer.verify(&sign_content, signature, &pk_bytes) {
                            tracing::warn!(
                                "YARA rule signature verification failed from {}, rejecting rules",
                                from_node
                            );
                            return Some(MeshMessage::YaraRuleAcknowledgement {
                                original_request_id: request_id.clone(),
                                node_id: self.node_id.clone().into(),
                                accepted: false,
                                reason: "Signature verification failed".into(),
                                timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                            });
                        }
                        tracing::debug!("YARA rule signature verified from {}", from_node);
                    } else {
                        tracing::warn!(
                            "Received signed YARA rules from {} but no local signer configured, rejecting",
                            from_node
                        );
                        return Some(MeshMessage::YaraRuleAcknowledgement {
                            original_request_id: request_id.clone(),
                            node_id: self.node_id.clone().into(),
                            accepted: false,
                            reason: "No local signer to verify signature".into(),
                            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                        });
                    }
                } else if self.config.require_signature {
                    tracing::warn!(
                        "YARA rule announce from {} has no signature but require_signature is enabled, rejecting",
                        from_node
                    );
                    return Some(MeshMessage::YaraRuleAcknowledgement {
                        original_request_id: request_id.clone(),
                        node_id: self.node_id.clone().into(),
                        accepted: false,
                        reason: "Signature required but not provided".into(),
                        timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                    });
                } else {
                    tracing::debug!(
                        "YARA rules from {} have no signature, accepting without verification",
                        from_node
                    );
                }

                if let Err(e) =
                    self.handle_incoming_rules(version.clone(), rules.clone(), from_node)
                {
                    tracing::warn!("Failed to apply incoming YARA rules: {}", e);
                }

                Some(MeshMessage::YaraRuleAcknowledgement {
                    original_request_id: request_id.clone(),
                    node_id: self.node_id.clone().into(),
                    accepted: true,
                    reason: "Rules applied".into(),
                    timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                })
            }
            MeshMessage::YaraRuleSyncRequest {
                request_id,
                node_id: _,
                version,
            } => {
                tracing::debug!(
                    "Received YARA rule sync request from {} (current: {:?})",
                    from_node,
                    version
                );

                if let Some(rules) = self.local_rules.read().clone() {
                    let ver = self.current_version.read().clone();
                    let signer_public_key = self
                        .signer
                        .as_ref()
                        .map(|s| s.get_public_key())
                        .unwrap_or_default();

                    let is_full = version
                        .as_ref()
                        .map(|v| {
                            crate::utils::is_newer_version(&ver.clone().unwrap_or_default(), v)
                        })
                        .unwrap_or(true);

                    let signature = if let Some(ref signer) = self.signer {
                        let ver_for_sign = ver.clone().unwrap_or_default();
                        let sign_content = format!("{}:{}", ver_for_sign, rules);
                        signer.sign(&sign_content)
                    } else {
                        Vec::new()
                    };

                    Some(MeshMessage::YaraRuleSyncResponse {
                        request_id: request_id.clone(),
                        version: ver.unwrap_or_default(),
                        rules,
                        is_full,
                        timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                        signature,
                        signer_public_key,
                    })
                } else {
                    None
                }
            }
            MeshMessage::YaraRuleSyncResponse {
                request_id: _,
                version,
                rules,
                is_full: _,
                timestamp: _,
                signature,
                signer_public_key,
            } => {
                tracing::info!(
                    "Received YARA rule sync response from {}: version {}",
                    from_node,
                    version
                );

                if self.config.require_signature {
                    if !signature.is_empty() && !signer_public_key.is_empty() {
                        if let Some(ref signer) = self.signer {
                            let sign_content = format!("{}:{}", version, rules);
                            let pk_bytes = base64::engine::general_purpose::STANDARD
                                .decode(signer_public_key)
                                .unwrap_or_default();
                            if !signer.verify(&sign_content, signature, &pk_bytes) {
                                tracing::warn!(
                                    "YARA rule sync response signature verification failed from {}, rejecting rules",
                                    from_node
                                );
                                return None;
                            }
                            tracing::debug!(
                                "YARA rule sync response signature verified from {}",
                                from_node
                            );
                        } else {
                            tracing::warn!(
                                "YARA rule sync response from {} has signature but no local signer configured, rejecting",
                                from_node
                            );
                            return None;
                        }
                    } else {
                        tracing::warn!(
                            "YARA rule sync response from {} has no signature but require_signature is enabled, rejecting",
                            from_node
                        );
                        return None;
                    }
                }

                if let Err(e) =
                    self.handle_incoming_rules(version.clone(), rules.clone(), from_node)
                {
                    tracing::warn!("Failed to apply synced YARA rules: {}", e);
                }

                None
            }
            MeshMessage::YaraRuleSubmission {
                request_id,
                submission_id,
                node_id,
                timestamp: _,
                signature,
                rules,
                description,
                signer_public_key: _,
            } => {
                tracing::info!(
                    "Received YARA rule submission from {}: {}",
                    from_node,
                    submission_id
                );

                if self.node_role.is_global() || self.node_role.contains(MeshNodeRole::GLOBAL) {
                    let submission = YaraRuleSubmission {
                        submission_id: submission_id.to_string(),
                        rules: rules.clone(),
                        description: description.clone(),
                        submitted_by: node_id.to_string(),
                        submitted_at: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                        status: YaraRuleSubmissionStatus::Pending,
                        reviewed_by: None,
                        reviewed_at: None,
                        review_notes: None,
                        signature: signature.clone(),
                    };

                    let submission_id_str = submission.submission_id.clone();
                    self.submissions
                        .write()
                        .insert(submission_id_str.clone(), submission.clone());

                    if let Err(e) = self.save_submission_to_disk(&submission) {
                        tracing::warn!("Failed to save submission to disk: {}", e);
                    }

                    tracing::info!(
                        "Stored YARA rule submission {} for review",
                        submission_id_str
                    );

                    Some(MeshMessage::YaraRuleSubmissionResponse {
                        original_request_id: request_id.clone(),
                        submission_id: submission_id.clone(),
                        node_id: self.node_id.clone().into(),
                        status: "pending".into(),
                        timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
                    })
                } else {
                    None
                }
            }
            MeshMessage::YaraRuleAcknowledgement {
                original_request_id: _,
                node_id: _,
                accepted,
                reason,
                timestamp: _,
            } => {
                tracing::debug!(
                    "YARA rule ack from {}: accepted={}, reason={}",
                    from_node,
                    accepted,
                    reason
                );
                if *accepted {
                    self.record_broadcast_ack(from_node);
                } else {
                    self.record_broadcast_failure(from_node);
                }
                None
            }
            MeshMessage::YaraRuleSubmissionResponse {
                original_request_id: _,
                submission_id: _,
                node_id: _,
                status: _,
                timestamp: _,
            } => None,
            _ => None,
        }
    }

    pub fn start_background_tasks(&self) {
        let config = self.config.clone();
        let yara_rules = Arc::new(self.clone());
        let is_global = self.is_global();
        let sync_interval_secs = config.sync_interval_secs;
        let re_announce_interval_secs = config.re_announce_interval_secs;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            let mut last_sync = Instant::now();

            loop {
                interval.tick().await;

                if !config.enabled {
                    continue;
                }

                if last_sync.elapsed().as_secs() > sync_interval_secs {
                    tracing::debug!("YARA rules sync interval reached, syncing from DHT");

                    if let Err(e) = yara_rules.sync_from_dht() {
                        tracing::debug!("YARA DHT sync failed: {}", e);
                    } else {
                        yara_rules.record_sync();
                    }

                    last_sync = Instant::now();
                }
            }
        });

        if re_announce_interval_secs > 0 && is_global {
            let yara_rules_reannounce = Arc::new(self.clone());
            let re_announce_interval = Duration::from_secs(re_announce_interval_secs);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(re_announce_interval);
                loop {
                    ticker.tick().await;
                    yara_rules_reannounce.publish_rules_to_dht();
                }
            });
            tracing::info!(
                "YARA rules re-announce task started (interval: {}s)",
                re_announce_interval_secs
            );
        }

        tracing::info!("YARA rules background tasks started");
    }

    pub fn get_stats(&self) -> YaraRulesStats {
        YaraRulesStats {
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            current_version: self.current_version.read().clone(),
            pending_submissions: self
                .submissions
                .read()
                .values()
                .filter(|s| s.status == YaraRuleSubmissionStatus::Pending)
                .count(),
            total_submissions: self.submissions.read().len(),
            last_sync: *self.last_sync.read(),
            is_global: self.node_role.is_global() || self.node_role.contains(MeshNodeRole::GLOBAL),
            broadcast_status: self.get_broadcast_status(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct YaraRulesStats {
    pub node_id: String,
    pub node_role: MeshNodeRole,
    pub current_version: Option<String>,
    pub pending_submissions: usize,
    pub total_submissions: usize,
    #[serde(skip_serializing)]
    pub last_sync: Instant,
    pub is_global: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast_status: Option<BroadcastAckStatus>,
}

impl Clone for YaraRulesManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            signer: self.signer.clone(),
            current_version: Arc::clone(&self.current_version),
            local_rules: Arc::clone(&self.local_rules),
            submissions: Arc::clone(&self.submissions),
            submission_hashes: Arc::clone(&self.submission_hashes),
            last_sync: RwLock::new(*self.last_sync.read()),
            feed_manager: self.feed_manager.clone(),
            mesh_sender: Arc::clone(&self.mesh_sender),
            data_dir: self.data_dir.clone(),
            broadcast_tracker: Arc::clone(&self.broadcast_tracker),
            rule_change_tracker: Arc::clone(&self.rule_change_tracker),
            record_store: Arc::clone(&self.record_store),
        }
    }
}
