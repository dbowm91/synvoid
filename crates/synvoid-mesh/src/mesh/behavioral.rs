use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct BehavioralFingerprint {
    pub fingerprint_id: String,
    pub features: BehavioralFeatures,
    pub severity_score: u32,
    pub confidence: f32,
    pub sample_count: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub ttl_seconds: u64,
    pub mesh_node_id: String,
    pub signature: Vec<u8>,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Default, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct BehavioralFeatures {
    pub header_timing_variance_ms: u32,
    pub request_sequence_entropy: f32,
    pub byte_length_distribution: Vec<u32>,
    pub inter_request_timing_ms: u32,
    pub suspicious_header_count: u8,
    pub url_entropy: f32,
    pub body_to_header_ratio: f32,
}

impl BehavioralFingerprint {
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.fingerprint_id.as_bytes());
        hasher.update(self.features.header_timing_variance_ms.to_le_bytes());
        hasher.update(self.features.request_sequence_entropy.to_le_bytes());
        hasher.update(self.features.inter_request_timing_ms.to_le_bytes());
        hasher.update(self.features.url_entropy.to_le_bytes());
        hasher.update(self.features.body_to_header_ratio.to_le_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn to_dht_key(&self) -> String {
        format!("behavior_fingerprint:{}", self.compute_hash())
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        self.last_seen + self.ttl_seconds < current_time
    }

    pub fn anonymized(&self) -> Self {
        let mut anon = self.clone();
        anon.mesh_node_id = Self::anonymize_node_id(&self.mesh_node_id);
        anon
    }

    fn anonymize_node_id(node_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"anonymous");
        hasher.update(node_id.as_bytes());
        hex::encode(&hasher.finalize()[..8])
    }
}

impl BehavioralFeatures {
    pub fn compute_lsh_bucket(&self) -> u32 {
        let mut hasher = Sha256::new();
        hasher.update(self.header_timing_variance_ms.to_le_bytes());
        hasher.update(self.request_sequence_entropy.to_le_bytes());
        hasher.update(self.inter_request_timing_ms.to_le_bytes());
        hasher.update(self.url_entropy.to_le_bytes());
        let result = hasher.finalize();
        u32::from_le_bytes(result[..4].try_into().unwrap())
    }

    pub fn similarity(&self, other: &BehavioralFeatures) -> f32 {
        let timing_diff =
            (self.header_timing_variance_ms as f32 - other.header_timing_variance_ms as f32).abs()
                / 1000.0;
        let entropy_diff = (self.request_sequence_entropy - other.request_sequence_entropy).abs();
        let inter_diff =
            (self.inter_request_timing_ms as f32 - other.inter_request_timing_ms as f32).abs()
                / 10000.0;
        let url_diff = (self.url_entropy - other.url_entropy).abs();
        let ratio_diff = (self.body_to_header_ratio - other.body_to_header_ratio).abs();

        let similarity =
            1.0 - (timing_diff + entropy_diff + inter_diff + url_diff + ratio_diff).min(1.0);
        similarity.max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behavioral_fingerprint_hash() {
        let features = BehavioralFeatures {
            header_timing_variance_ms: 100,
            request_sequence_entropy: 0.5,
            byte_length_distribution: vec![10, 20, 30],
            inter_request_timing_ms: 500,
            suspicious_header_count: 1,
            url_entropy: 2.5,
            body_to_header_ratio: 0.8,
        };

        let fingerprint = BehavioralFingerprint {
            fingerprint_id: "test-fp-1".to_string(),
            features,
            severity_score: 75,
            confidence: 0.9,
            sample_count: 100,
            first_seen: 1000,
            last_seen: 2000,
            ttl_seconds: 3600,
            mesh_node_id: "node-123".to_string(),
            signature: Vec::new(),
        };

        let hash = fingerprint.compute_hash();
        assert_eq!(hash.len(), 64);

        let dht_key = fingerprint.to_dht_key();
        assert!(dht_key.starts_with("behavior_fingerprint:"));
    }

    #[test]
    fn test_feature_similarity() {
        let features1 = BehavioralFeatures {
            header_timing_variance_ms: 100,
            request_sequence_entropy: 0.5,
            byte_length_distribution: vec![10, 20, 30],
            inter_request_timing_ms: 500,
            suspicious_header_count: 1,
            url_entropy: 2.5,
            body_to_header_ratio: 0.8,
        };

        let features2 = BehavioralFeatures {
            header_timing_variance_ms: 110,
            request_sequence_entropy: 0.52,
            byte_length_distribution: vec![12, 22, 32],
            inter_request_timing_ms: 520,
            suspicious_header_count: 2,
            url_entropy: 2.6,
            body_to_header_ratio: 0.85,
        };

        let similarity = features1.similarity(&features2);
        assert!(
            similarity > 0.8,
            "Similar features should have high similarity"
        );
    }

    #[test]
    fn test_lsh_bucket() {
        let features = BehavioralFeatures::default();
        let bucket1 = features.compute_lsh_bucket();

        let different_features = BehavioralFeatures {
            header_timing_variance_ms: 10000,
            ..Default::default()
        };
        let bucket2 = different_features.compute_lsh_bucket();

        assert_ne!(
            bucket1, bucket2,
            "Different features should produce different buckets"
        );
    }

    #[test]
    fn test_anonymized_fingerprint() {
        let fingerprint = BehavioralFingerprint {
            fingerprint_id: "test".to_string(),
            features: BehavioralFeatures::default(),
            severity_score: 50,
            confidence: 0.5,
            sample_count: 10,
            first_seen: 1000,
            last_seen: 2000,
            ttl_seconds: 3600,
            mesh_node_id: "original-node-id".to_string(),
            signature: Vec::new(),
        };

        let anon = fingerprint.anonymized();
        assert_ne!(anon.mesh_node_id, fingerprint.mesh_node_id);
        assert_eq!(anon.fingerprint_id, fingerprint.fingerprint_id);
    }

    #[test]
    fn test_expired_fingerprint() {
        let fingerprint = BehavioralFingerprint {
            fingerprint_id: "test".to_string(),
            features: BehavioralFeatures::default(),
            severity_score: 50,
            confidence: 0.5,
            sample_count: 10,
            first_seen: 1000,
            last_seen: 2000,
            ttl_seconds: 600,
            mesh_node_id: "node".to_string(),
            signature: Vec::new(),
        };

        assert!(!fingerprint.is_expired(2500));
        assert!(fingerprint.is_expired(3000));
    }
}
