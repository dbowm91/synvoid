use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tokio::sync::mpsc;

use crate::behavioral::{BehavioralFeatures, BehavioralFingerprint};
use crate::config::MeshNodeRole;
use crate::protocol::{MeshMessage, MeshMessageSigner};
use crate::stubs::metrics;

const MAX_FINGERPRINTS: usize = 10000;
const DEFAULT_MIN_SAMPLES: u64 = 10;
const DEFAULT_FINGERPRINT_TTL_SECS: u64 = 3600;
const DEFAULT_HIGH_SEVERITY_THRESHOLD: u32 = 70;
const LSH_BUCKET_COUNT: u32 = 1024;
const SIMILARITY_THRESHOLD: f32 = 0.85;
const BROADCAST_BATCH_SIZE: usize = 50;

#[derive(Debug, Clone)]
pub struct BehavioralConfig {
    pub enabled: bool,
    pub min_samples_for_fingerprint: u64,
    pub fingerprint_ttl_secs: u64,
    pub high_severity_threshold: u32,
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_samples_for_fingerprint: DEFAULT_MIN_SAMPLES,
            fingerprint_ttl_secs: DEFAULT_FINGERPRINT_TTL_SECS,
            high_severity_threshold: DEFAULT_HIGH_SEVERITY_THRESHOLD,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestFeatures {
    pub header_timing_variance_ms: u32,
    pub request_sequence_entropy: f32,
    pub byte_length_distribution: Vec<u32>,
    pub inter_request_timing_ms: u32,
    pub suspicious_header_count: u8,
    pub url_entropy: f32,
    pub body_to_header_ratio: f32,
}

impl From<&RequestFeatures> for BehavioralFeatures {
    fn from(req: &RequestFeatures) -> Self {
        BehavioralFeatures {
            header_timing_variance_ms: req.header_timing_variance_ms,
            request_sequence_entropy: req.request_sequence_entropy,
            byte_length_distribution: req.byte_length_distribution.clone(),
            inter_request_timing_ms: req.inter_request_timing_ms,
            suspicious_header_count: req.suspicious_header_count,
            url_entropy: req.url_entropy,
            body_to_header_ratio: req.body_to_header_ratio,
        }
    }
}

pub struct BehavioralIntelligenceManager {
    fingerprints: RwLock<HashMap<String, BehavioralFingerprint>>,
    lsh_buckets: RwLock<Vec<Vec<String>>>,
    pending_announces: RwLock<VecDeque<BehavioralFingerprint>>,
    local_version: RwLock<u64>,
    config: Arc<BehavioralConfig>,
    node_id: String,
    node_role: MeshNodeRole,
    signer: Option<Arc<MeshMessageSigner>>,
    mesh_sender: Arc<RwLock<Option<mpsc::Sender<MeshMessage>>>>,
    transport: Arc<RwLock<Option<Arc<crate::transport::MeshTransport>>>>,
    sample_collectors: RwLock<HashMap<String, Vec<RequestFeatures>>>,
    last_cleanup: RwLock<Instant>,
}

impl BehavioralIntelligenceManager {
    pub fn new(
        config: BehavioralConfig,
        node_id: String,
        node_role: MeshNodeRole,
        signer: Option<Arc<MeshMessageSigner>>,
    ) -> Self {
        let mut lsh_buckets = Vec::with_capacity(LSH_BUCKET_COUNT as usize);
        for _ in 0..LSH_BUCKET_COUNT {
            lsh_buckets.push(Vec::new());
        }

        Self {
            fingerprints: RwLock::new(HashMap::new()),
            lsh_buckets: RwLock::new(lsh_buckets),
            pending_announces: RwLock::new(VecDeque::new()),
            local_version: RwLock::new(1),
            config: Arc::new(config),
            node_id,
            node_role,
            signer,
            mesh_sender: Arc::new(RwLock::new(None)),
            transport: Arc::new(RwLock::new(None)),
            sample_collectors: RwLock::new(HashMap::new()),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    pub fn set_transport(&self, transport: Arc<crate::transport::MeshTransport>) {
        let mut t = self.transport.write();
        *t = Some(transport);
    }

    pub fn set_mesh_sender(&self, sender: mpsc::Sender<MeshMessage>) {
        let mut sender_guard = self.mesh_sender.write();
        *sender_guard = Some(sender);
    }

    pub fn analyze_request(&self, features: &RequestFeatures) -> Option<BehavioralFingerprint> {
        if !self.config.enabled {
            return None;
        }

        let behavioral_features: BehavioralFeatures = features.into();
        let bucket = behavioral_features.compute_lsh_bucket() % LSH_BUCKET_COUNT;

        let lsh_buckets = self.lsh_buckets.read();
        let bucket_fingerprints: Vec<_> = lsh_buckets
            .get(bucket as usize)?
            .iter()
            .filter_map(|id| self.fingerprints.read().get(id).cloned())
            .collect();
        drop(lsh_buckets);

        for fp in &bucket_fingerprints {
            let similarity = behavioral_features.similarity(&fp.features);
            if similarity >= SIMILARITY_THRESHOLD {
                let now = synvoid_utils::safe_unix_timestamp();
                let mut fingerprints = self.fingerprints.write();
                if let Some(existing) = fingerprints.get_mut(&fp.fingerprint_id) {
                    existing.last_seen = now;
                    existing.sample_count += 1;
                    existing.confidence = (existing.confidence + similarity).min(1.0);
                    return Some(existing.clone());
                }
            }
        }

        None
    }

    pub fn adjust_paranoia_level(&self, features: &RequestFeatures, base_paranoia: u8) -> u8 {
        if !self.config.enabled {
            return base_paranoia;
        }

        if let Some(fingerprint) = self.analyze_request(features) {
            if fingerprint.severity_score >= self.config.high_severity_threshold {
                return (base_paranoia + 1).min(4);
            }
        }

        let behavioral_features: BehavioralFeatures = features.into();
        let mut suspicion_score: u32 = 0;

        if behavioral_features.header_timing_variance_ms > 5000 {
            suspicion_score += 20;
        }
        if behavioral_features.request_sequence_entropy < 0.1 {
            suspicion_score += 15;
        }
        if behavioral_features.suspicious_header_count > 2 {
            suspicion_score += 25;
        }
        if behavioral_features.url_entropy > 5.0 {
            suspicion_score += 15;
        }

        if suspicion_score >= 50 {
            return (base_paranoia + 1).min(4);
        }

        base_paranoia
    }

    pub fn record_request_features(&self, request_id: &str, features: RequestFeatures) {
        if !self.config.enabled {
            return;
        }

        let mut collectors = self.sample_collectors.write();
        let collector = collectors
            .entry(request_id.to_string())
            .or_insert_with(Vec::new);
        collector.push(features);

        if collector.len() >= self.config.min_samples_for_fingerprint as usize {
            let aggregated = Self::aggregate_features(collector);
            self.create_fingerprint_from_aggregated(request_id, &aggregated);
            collectors.remove(request_id);
        }
    }

    fn aggregate_features(samples: &[RequestFeatures]) -> BehavioralFeatures {
        if samples.is_empty() {
            return BehavioralFeatures::default();
        }

        let avg_timing: u32 = samples
            .iter()
            .map(|s| s.header_timing_variance_ms)
            .sum::<u32>()
            / samples.len() as u32;
        let avg_entropy: f32 = samples
            .iter()
            .map(|s| s.request_sequence_entropy)
            .sum::<f32>()
            / samples.len() as f32;
        let avg_inter: u32 = samples
            .iter()
            .map(|s| s.inter_request_timing_ms)
            .sum::<u32>()
            / samples.len() as u32;
        let avg_suspicious: u8 = (samples
            .iter()
            .map(|s| s.suspicious_header_count as u32)
            .sum::<u32>()
            / samples.len() as u32) as u8;
        let avg_url_entropy: f32 =
            samples.iter().map(|s| s.url_entropy).sum::<f32>() / samples.len() as f32;
        let avg_ratio: f32 =
            samples.iter().map(|s| s.body_to_header_ratio).sum::<f32>() / samples.len() as f32;

        let mut combined_distribution = vec![0u32; 10];
        for sample in samples {
            for (i, &count) in sample.byte_length_distribution.iter().enumerate() {
                if i < combined_distribution.len() {
                    combined_distribution[i] += count;
                }
            }
        }

        BehavioralFeatures {
            header_timing_variance_ms: avg_timing,
            request_sequence_entropy: avg_entropy,
            byte_length_distribution: combined_distribution,
            inter_request_timing_ms: avg_inter,
            suspicious_header_count: avg_suspicious,
            url_entropy: avg_url_entropy,
            body_to_header_ratio: avg_ratio,
        }
    }

    fn create_fingerprint_from_aggregated(&self, request_id: &str, features: &BehavioralFeatures) {
        let severity_score = Self::compute_severity_from_features(features);
        if severity_score < 30 {
            return;
        }

        let now = synvoid_utils::safe_unix_timestamp();
        let fingerprint_id = format!("fp:{}_{}", request_id, now);

        let mut signature = Vec::new();
        if let Some(ref signer) = self.signer {
            let content = format!(
                "{}:{}:{}:{}:{}",
                fingerprint_id,
                severity_score,
                features.header_timing_variance_ms,
                features.url_entropy,
                now
            );
            signature = signer.sign(content.as_bytes());
        }

        let fingerprint = BehavioralFingerprint {
            fingerprint_id: fingerprint_id.clone(),
            features: features.clone(),
            severity_score,
            confidence: 0.5,
            sample_count: self.config.min_samples_for_fingerprint,
            first_seen: now,
            last_seen: now,
            ttl_seconds: self.config.fingerprint_ttl_secs,
            mesh_node_id: self.node_id.clone(),
            signature,
        };

        self.add_fingerprint(fingerprint);
    }

    fn compute_severity_from_features(features: &BehavioralFeatures) -> u32 {
        let mut score: u32 = 0;

        if features.header_timing_variance_ms > 10000 {
            score += 30;
        } else if features.header_timing_variance_ms > 5000 {
            score += 20;
        } else if features.header_timing_variance_ms > 1000 {
            score += 10;
        }

        if features.request_sequence_entropy < 0.05 {
            score += 25;
        } else if features.request_sequence_entropy < 0.2 {
            score += 15;
        }

        if features.suspicious_header_count >= 3 {
            score += 30;
        } else if features.suspicious_header_count >= 1 {
            score += 15;
        }

        if features.url_entropy > 6.0 {
            score += 20;
        } else if features.url_entropy > 4.0 {
            score += 10;
        }

        score.min(100)
    }

    fn add_fingerprint(&self, fingerprint: BehavioralFingerprint) {
        let bucket = fingerprint.features.compute_lsh_bucket() % LSH_BUCKET_COUNT;

        {
            let mut fingerprints = self.fingerprints.write();

            if fingerprints.len() >= MAX_FINGERPRINTS {
                if let Some((_, oldest)) = fingerprints.iter().min_by_key(|(_, fp)| fp.last_seen) {
                    let removed_id = oldest.fingerprint_id.clone();
                    drop(fingerprints);

                    let mut fp_map = self.fingerprints.write();
                    fp_map.remove(&removed_id);
                    drop(fp_map);

                    let mut buckets = self.lsh_buckets.write();
                    if let Some(bucket_vec) = buckets.get_mut(bucket as usize) {
                        bucket_vec.retain(|id| id != &removed_id);
                    }
                    return;
                }
            }

            fingerprints.insert(fingerprint.fingerprint_id.clone(), fingerprint.clone());
        }

        let mut buckets = self.lsh_buckets.write();
        if let Some(bucket_vec) = buckets.get_mut(bucket as usize) {
            bucket_vec.push(fingerprint.fingerprint_id.clone());
        }
    }

    pub fn broadcast_fingerprints(&self) -> Option<MeshMessage> {
        let mut queue = self.pending_announces.write();
        let fingerprints: Vec<BehavioralFingerprint> = queue
            .drain(..)
            .take(BROADCAST_BATCH_SIZE)
            .map(|fp| fp.anonymized())
            .collect();
        drop(queue);

        if fingerprints.is_empty() {
            return None;
        }

        let mut signature = Vec::new();
        let mut signer_public_key = None;

        if let Some(ref signer) = self.signer {
            let content = serde_json::to_vec(&fingerprints).unwrap_or_default();
            signature = signer.sign(&content);
            signer_public_key = Some(signer.get_public_key());
        }

        Some(MeshMessage::BehavioralFingerprintAnnounce {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            fingerprints,
            timestamp: synvoid_utils::safe_unix_timestamp(),
            source_node_id: self.node_id.clone().into(),
            signature,
            signer_public_key,
        })
    }

    pub fn publish_fingerprint_to_dht(&self, fingerprint: &BehavioralFingerprint) {
        if !self.config.enabled {
            return;
        }

        let transport_opt = self.transport.read().clone();
        let Some(transport) = transport_opt else {
            tracing::debug!("Transport not available for behavioral fingerprint publish");
            return;
        };

        let Some(record_store) = transport.get_record_store() else {
            tracing::debug!("Record store not available for behavioral fingerprint publish");
            return;
        };

        let key = fingerprint.to_dht_key();
        let key_str = key.as_str();

        if let Ok(bytes) = serde_json::to_vec(fingerprint) {
            if record_store.store_and_announce(key_str.to_string(), bytes, fingerprint.ttl_seconds)
            {
                metrics::record_behavioral_fingerprint_dht_publish();
                tracing::debug!(
                    "Published behavioral fingerprint to DHT: {} (severity: {})",
                    fingerprint.fingerprint_id,
                    fingerprint.severity_score
                );
            }
        }
    }

    pub fn cleanup_expired(&self) {
        let now = synvoid_utils::safe_unix_timestamp();

        let mut fingerprints = self.fingerprints.write();
        let expired_ids: Vec<_> = fingerprints
            .iter()
            .filter(|(_, fp)| fp.is_expired(now))
            .map(|(id, _)| id.clone())
            .collect();

        for id in &expired_ids {
            if let Some(fp) = fingerprints.remove(id) {
                let bucket = fp.features.compute_lsh_bucket() % LSH_BUCKET_COUNT;
                drop(fp);
                if let Some(bucket_vec) = self.lsh_buckets.read().get(bucket as usize) {
                    let bucket_vec = bucket_vec.clone();
                    drop(bucket_vec);
                    let mut buckets = self.lsh_buckets.write();
                    if let Some(bucket_vec) = buckets.get_mut(bucket as usize) {
                        bucket_vec.retain(|bid| bid != id);
                    }
                }
            }
        }

        if !expired_ids.is_empty() {
            tracing::debug!(
                "Cleaned up {} expired behavioral fingerprints",
                expired_ids.len()
            );
        }

        *self.last_cleanup.write() = Instant::now();
    }

    pub fn get_fingerprint_count(&self) -> usize {
        self.fingerprints.read().len()
    }

    pub fn get_version(&self) -> u64 {
        *self.local_version.read()
    }

    pub fn get_config(&self) -> BehavioralConfig {
        BehavioralConfig {
            enabled: self.config.enabled,
            min_samples_for_fingerprint: self.config.min_samples_for_fingerprint,
            fingerprint_ttl_secs: self.config.fingerprint_ttl_secs,
            high_severity_threshold: self.config.high_severity_threshold,
        }
    }

    pub fn sync_from_dht(&self) -> Result<usize, String> {
        let transport = self.transport.read().clone();
        let record_store = match transport {
            Some(t) => t.get_record_store(),
            None => return Err("Transport not set".to_string()),
        };
        let record_store = match record_store {
            Some(rs) => rs,
            None => return Err("Record store not available".to_string()),
        };

        let dht_records = record_store.get_by_prefix("behavior_fingerprint:", 1000);
        let mut added = 0;

        for record in dht_records {
            if let Ok(fingerprint) = serde_json::from_slice::<BehavioralFingerprint>(&record.value)
            {
                let now = synvoid_utils::safe_unix_timestamp();
                if fingerprint.is_expired(now) {
                    continue;
                }

                let mut fingerprints = self.fingerprints.write();
                if !fingerprints.contains_key(&fingerprint.fingerprint_id) {
                    fingerprints.insert(fingerprint.fingerprint_id.clone(), fingerprint.clone());
                    added += 1;

                    let bucket = fingerprint.features.compute_lsh_bucket() % LSH_BUCKET_COUNT;
                    drop(fingerprints);
                    let mut buckets = self.lsh_buckets.write();
                    if let Some(bucket_vec) = buckets.get_mut(bucket as usize) {
                        if !bucket_vec.contains(&fingerprint.fingerprint_id) {
                            bucket_vec.push(fingerprint.fingerprint_id);
                        }
                    }
                }
            }
        }

        *self.local_version.write() += 1;
        tracing::debug!("Synced {} behavioral fingerprints from DHT", added);
        Ok(added)
    }

    pub fn create_sync_request(&self) -> MeshMessage {
        MeshMessage::BehavioralFingerprintSyncRequest {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            node_id: self.node_id.clone().into(),
            from_version: *self.local_version.read(),
            prefer_delta: true,
        }
    }

    pub fn create_sync_response(&self, request_id: &str, from_version: u64) -> Option<MeshMessage> {
        let fingerprints: Vec<BehavioralFingerprint> = self
            .fingerprints
            .read()
            .values()
            .filter(|fp| fp.last_seen > from_version as u64)
            .map(|fp| fp.anonymized())
            .take(100)
            .collect();

        if fingerprints.is_empty() {
            return None;
        }

        let mut signature = Vec::new();
        let mut signer_public_key = None;

        if let Some(ref signer) = self.signer {
            let content = format!(
                "{},{},{},{}",
                request_id,
                *self.local_version.read(),
                fingerprints.len(),
                synvoid_utils::safe_unix_timestamp()
            );
            signature = signer.sign(content.as_bytes());
            signer_public_key = Some(signer.get_public_key());
        }

        Some(MeshMessage::BehavioralFingerprintSyncResponse {
            request_id: request_id.into(),
            fingerprints,
            version: *self.local_version.read(),
            is_delta: true,
            removed_fingerprint_ids: Vec::new(),
            signature,
            signer_public_key,
        })
    }

    pub fn handle_incoming_fingerprint(
        &self,
        fingerprint: BehavioralFingerprint,
        from_node: &str,
        signer: Option<&Arc<MeshMessageSigner>>,
    ) -> bool {
        if let Some(signer) = signer {
            if !fingerprint.signature.is_empty() {
                let content = format!(
                    "{}:{}:{}:{}:{}",
                    fingerprint.fingerprint_id,
                    fingerprint.severity_score,
                    fingerprint.features.header_timing_variance_ms,
                    fingerprint.features.url_entropy,
                    fingerprint.first_seen
                );
                let pk = signer.get_public_key_bytes();
                if !signer.verify(content.as_bytes(), &fingerprint.signature, &pk) {
                    tracing::warn!(
                        "Behavioral fingerprint signature verification failed from {}",
                        from_node
                    );
                    return false;
                }
            }
        }

        if fingerprint.mesh_node_id == self.node_id {
            return false;
        }

        let now = synvoid_utils::safe_unix_timestamp();
        if fingerprint.is_expired(now) {
            tracing::warn!("Received expired behavioral fingerprint from {}", from_node);
            return false;
        }

        let mut fingerprints = self.fingerprints.write();
        if let Some(existing) = fingerprints.get(&fingerprint.fingerprint_id) {
            if existing.last_seen >= fingerprint.last_seen {
                return false;
            }
        }

        let fingerprint_id = fingerprint.fingerprint_id.clone();
        let severity_score = fingerprint.severity_score;

        fingerprints.insert(fingerprint_id.clone(), fingerprint.clone());
        drop(fingerprints);

        let bucket = fingerprint.features.compute_lsh_bucket() % LSH_BUCKET_COUNT;
        let mut buckets = self.lsh_buckets.write();
        if let Some(bucket_vec) = buckets.get_mut(bucket as usize) {
            if !bucket_vec.contains(&fingerprint_id) {
                bucket_vec.push(fingerprint_id.clone());
            }
        }

        metrics::record_behavioral_fingerprint_received();
        tracing::debug!(
            "Accepted behavioral fingerprint from {}: {} (severity: {})",
            from_node,
            fingerprint_id,
            severity_score
        );
        true
    }

    pub fn handle_mesh_message(
        &self,
        message: &MeshMessage,
        from_node: &str,
        signer: Option<&Arc<MeshMessageSigner>>,
    ) -> Option<MeshMessage> {
        match message {
            MeshMessage::BehavioralFingerprintAnnounce {
                request_id: _,
                fingerprints,
                timestamp: _,
                source_node_id: _,
                signature: _,
                signer_public_key: _,
            } => {
                tracing::debug!(
                    "Received BehavioralFingerprintAnnounce from {} with {} fingerprints",
                    from_node,
                    fingerprints.len()
                );

                let mut accepted_count = 0;
                for fp in fingerprints {
                    if self.handle_incoming_fingerprint(fp.clone(), from_node, signer) {
                        accepted_count += 1;
                    }
                }

                tracing::debug!(
                    "Accepted {}/{} behavioral fingerprints from {}",
                    accepted_count,
                    fingerprints.len(),
                    from_node
                );
                None
            }
            MeshMessage::BehavioralFingerprintSyncRequest {
                request_id,
                node_id: _,
                from_version: _,
                prefer_delta: _,
            } => {
                tracing::debug!(
                    "Received BehavioralFingerprintSyncRequest from {}",
                    from_node
                );
                self.create_sync_response(request_id, *self.local_version.read())
            }
            MeshMessage::BehavioralFingerprintSyncResponse {
                request_id: _,
                fingerprints,
                version: _,
                is_delta: _,
                removed_fingerprint_ids: _,
                signature: _,
                signer_public_key: _,
            } => {
                for fp in fingerprints {
                    self.handle_incoming_fingerprint(fp.clone(), from_node, signer);
                }
                None
            }
            _ => None,
        }
    }
}

impl Clone for BehavioralIntelligenceManager {
    fn clone(&self) -> Self {
        Self {
            fingerprints: RwLock::new(self.fingerprints.read().clone()),
            lsh_buckets: RwLock::new(self.lsh_buckets.read().clone()),
            pending_announces: RwLock::new(self.pending_announces.read().clone()),
            local_version: RwLock::new(*self.local_version.read()),
            config: self.config.clone(),
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            signer: self.signer.clone(),
            mesh_sender: self.mesh_sender.clone(),
            transport: self.transport.clone(),
            sample_collectors: RwLock::new(self.sample_collectors.read().clone()),
            last_cleanup: RwLock::new(*self.last_cleanup.read()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_features() -> RequestFeatures {
        RequestFeatures {
            header_timing_variance_ms: 150,
            request_sequence_entropy: 0.45,
            byte_length_distribution: vec![5, 10, 15, 20, 25],
            inter_request_timing_ms: 300,
            suspicious_header_count: 2,
            url_entropy: 3.2,
            body_to_header_ratio: 0.6,
        }
    }

    #[test]
    fn test_analyze_request_no_match() {
        let manager = BehavioralIntelligenceManager::new(
            BehavioralConfig::default(),
            "test-node".to_string(),
            MeshNodeRole::GLOBAL,
            None,
        );

        let features = create_test_features();
        let result = manager.analyze_request(&features);
        assert!(result.is_none());
    }

    #[test]
    fn test_adjust_paranoia_level_base() {
        let manager = BehavioralIntelligenceManager::new(
            BehavioralConfig::default(),
            "test-node".to_string(),
            MeshNodeRole::GLOBAL,
            None,
        );

        let features = create_test_features();
        let paranoia = manager.adjust_paranoia_level(&features, 2);
        assert_eq!(paranoia, 2);
    }

    #[test]
    fn test_fingerprint_count() {
        let manager = BehavioralIntelligenceManager::new(
            BehavioralConfig::default(),
            "test-node".to_string(),
            MeshNodeRole::GLOBAL,
            None,
        );

        assert_eq!(manager.get_fingerprint_count(), 0);
    }

    #[test]
    fn test_aggregate_features() {
        let samples = vec![
            RequestFeatures {
                header_timing_variance_ms: 100,
                request_sequence_entropy: 0.5,
                byte_length_distribution: vec![10, 20],
                inter_request_timing_ms: 500,
                suspicious_header_count: 1,
                url_entropy: 2.0,
                body_to_header_ratio: 0.5,
            },
            RequestFeatures {
                header_timing_variance_ms: 200,
                request_sequence_entropy: 0.3,
                byte_length_distribution: vec![15, 25],
                inter_request_timing_ms: 700,
                suspicious_header_count: 2,
                url_entropy: 3.0,
                body_to_header_ratio: 0.7,
            },
        ];

        let aggregated = BehavioralIntelligenceManager::aggregate_features(&samples);
        assert_eq!(aggregated.header_timing_variance_ms, 150);
        assert!((aggregated.request_sequence_entropy - 0.4).abs() < 0.01);
        assert_eq!(aggregated.inter_request_timing_ms, 600);
    }

    #[test]
    fn test_severity_computation() {
        let _manager = BehavioralIntelligenceManager::new(
            BehavioralConfig::default(),
            "test-node".to_string(),
            MeshNodeRole::GLOBAL,
            None,
        );

        let low_severity_features = BehavioralFeatures {
            header_timing_variance_ms: 100,
            request_sequence_entropy: 0.8,
            byte_length_distribution: vec![],
            inter_request_timing_ms: 100,
            suspicious_header_count: 0,
            url_entropy: 1.0,
            body_to_header_ratio: 0.1,
        };
        let low_score =
            BehavioralIntelligenceManager::compute_severity_from_features(&low_severity_features);
        assert!(low_score < 30);

        let high_severity_features = BehavioralFeatures {
            header_timing_variance_ms: 15000,
            request_sequence_entropy: 0.02,
            byte_length_distribution: vec![],
            inter_request_timing_ms: 100,
            suspicious_header_count: 5,
            url_entropy: 7.0,
            body_to_header_ratio: 0.1,
        };
        let high_score =
            BehavioralIntelligenceManager::compute_severity_from_features(&high_severity_features);
        assert!(high_score >= 70);
    }
}
