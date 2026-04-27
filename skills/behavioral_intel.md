# Skill: Federated Behavioral Intelligence

## Context
The codebase implements federated behavioral intelligence for sharing anonymized attack patterns across the mesh based on behavioral fingerprints.

## When to Use
Use this skill when:
- Implementing behavioral fingerprint analysis
- Adding LSH (locality-sensitive hashing) for approximate matching
- Creating privacy-first designs (no client IP storage)
- Integrating with AttackDetector for paranoia level elevation

## Key Files
- `src/mesh/behavioral.rs` - `BehavioralFingerprint` and `BehavioralFeatures` types
- `src/mesh/behavioral_intel.rs` - `BehavioralIntelligenceManager`
- `src/mesh/dht/keys.rs` - Added `behavior_fingerprint:` DHT key prefix
- `src/mesh/protocol.rs` - Added `BehavioralFingerprintAnnounce` message variants

## Implementation Pattern

### 1. BehavioralFeatures Structure
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehavioralFeatures {
    pub header_timing_variance_ms: u32,
    pub request_sequence_entropy: f32,
    pub byte_length_distribution: Vec<u32>,
    pub inter_request_timing_ms: u32,
    pub suspicious_header_count: u8,
    pub url_entropy: f32,
    pub body_to_header_ratio: f32,
}
```

### 2. BehavioralFingerprint Structure
```rust
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
```

### 3. Privacy-First Design
- NEVER store client IPs in fingerprints
- Use only timing and structural features
- Anonymize source_node_id in shared fingerprints
- Apply differential privacy noise where needed

### 4. LSH Approximate Matching
```rust
fn compute_lsh_bucket(features: &BehavioralFeatures) -> u64 {
    let mut hasher = SipHasher::new();
    hasher.update(&features.header_timing_variance_ms.to_le_bytes());
    hasher.update(&(features.url_entropy * 100.0) as u32).to_le_bytes());
    // Combine multiple features into bucket
    hasher.finish()
}
```

### 5. Integration with AttackDetector
```rust
// In check_request():
if let Some(bf_manager) = self.behavioral_intel.as_ref() {
    let features = self.extract_behavioral_features(...);
    if let Some(fingerprint) = bf_manager.analyze_request(&features) {
        if fingerprint.severity_score > 70 {
            return self.check_request_with_paranoia(..., 3);
        }
    }
}
```

### 6. DHT Message Types
```rust
BehavioralFingerprintAnnounce {
    request_id: ArcStr,
    fingerprints: Vec<BehavioralFingerprint>,
    timestamp: u64,
    source_node_id: ArcStr,
    signature: Vec<u8>,
    signer_public_key: String,
}
```

## Configuration
In `ThreatIntelligenceConfig`:
```rust
pub behavioral_enabled: bool,
pub min_samples_for_fingerprint: u64,
pub fingerprint_ttl_secs: u64,
pub high_severity_threshold: u32,
```

## Verification
```bash
cargo test --lib -- behavioral
cargo test --test integration_test -- behavioral
```

## Common Issues
1. **LSH bucket collisions** - Use multiple hash functions for better accuracy
2. **Feature normalization** - Ensure features are on comparable scales
3. **Privacy leakage** - Audit fingerprint data to ensure no PII

## Scalability
At 500K RPS:
- HashMap with 10K max fingerprints
- LSH buckets for O(1) approximate lookup
- Periodic cleanup of expired fingerprints
