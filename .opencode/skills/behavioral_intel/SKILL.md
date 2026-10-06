---
name: behavioral_intel
description: Federated behavioral intelligence for sharing anonymized attack patterns across the mesh via behavioral fingerprints and LSH.
---

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
- `crates/synvoid-mesh/src/mesh/behavioral.rs` - `BehavioralFingerprint` and `BehavioralFeatures` types, `compute_lsh_bucket()`, `similarity()`, `compute_hash()`, `anonymized()` / `anonymize_node_id()`
- `crates/synvoid-mesh/src/mesh/behavioral_intel.rs` - `BehavioralIntelligenceManager`, `BehavioralConfig`, `RequestFeatures`, `LSH_BUCKET_COUNT`, `SIMILARITY_THRESHOLD`
- `crates/synvoid-mesh/src/mesh/dht/keys.rs` - `DhtKey::behavior_fingerprint(fingerprint_id)` + the `behavior_fingerprint:` DHT key prefix
- `crates/synvoid-mesh/src/mesh/protocol.rs` - `MeshMessage::BehavioralFingerprintAnnounce` (and `…SyncRequest`) message variants

**Composition (root, `mesh` feature only)**:
- `src/worker/context.rs` - the narrow `BehavioralIntelLookup` trait
  (`analyze_request`, `adjust_paranoia_level`) carried on `RequestServices`
- `src/worker/unified_server/services.rs` - `BehavioralIntelLookupAdapter`
  wrapping the concrete `BehavioralIntelligenceManager`

**Reachability gap (verified)**: `RequestServices.behavioral_intel` is built and
stored, but **nothing reads it**. `analyze_request` / `adjust_paranoia_level` are
only called from the adapter's trait impl and from unit tests inside
`crates/synvoid-mesh`; no WAF detector, request-path module, or dispatch layer
consults the field. The only live consumers are the admin stats/config handlers
(`src/admin/handlers/behavioral_intel.rs` via
`AdminState::behavioral_intel_manager`). So federation, DHT announce, LSH
bucket matching, and the paranoia elevation below are **implemented and
admin-visible but not enforced on the request path**. Do not describe the
`check_request_with_paranoia` snippet as current behavior — it is the intended
integration, not shipped code.

## Implementation Pattern

### 1. BehavioralFeatures Structure
```rust
// rkyv + serde derives (distributed state contract: no serde_json::Value)
#[derive(Debug, Clone, Serialize, Deserialize, Default, Archive, RkyvSerialize, RkyvDeserialize)]
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
- NEVER store client IPs in fingerprints (the `BehavioralFeatures` struct has
  no IP field — only timing/entropy/shape features)
- `BehavioralFingerprint::anonymized()` replaces `mesh_node_id` with
  `anonymize_node_id()` before broadcast/announce
- Differential privacy noise is **not** implemented — do not claim it

### 4. LSH Approximate Matching

`BehavioralFeatures::compute_lsh_bucket(&self) -> u32` hashes four timing/entropy
features with SHA-256 and truncates to a `u32` (not SipHash, not `u64`):

```rust
// crates/synvoid-mesh/src/mesh/behavioral.rs
pub fn compute_lsh_bucket(&self) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(self.header_timing_variance_ms.to_le_bytes());
    hasher.update(self.request_sequence_entropy.to_le_bytes());
    hasher.update(self.inter_request_timing_ms.to_le_bytes());
    hasher.update(self.url_entropy.to_le_bytes());
    let result = hasher.finalize();
    u32::from_le_bytes(result[..4].try_into().unwrap())
}
```

`BehavioralIntelligenceManager` buckets with
`compute_lsh_bucket() % LSH_BUCKET_COUNT` (`LSH_BUCKET_COUNT = 1024`) and matches
via `BehavioralFeatures::similarity()` against `SIMILARITY_THRESHOLD` (`0.85`).

### 5. Integration with AttackDetector

**Intended** integration — not currently wired (see the reachability gap above):

```rust
// Intended: in the WAF attack stage, behind the narrow BehavioralIntelLookup
if let Some(bf_manager) = self.behavioral_intel.as_ref() {
    let features = self.extract_behavioral_features(...);
    if let Some(fingerprint) = bf_manager.analyze_request(&features) {
        if fingerprint.severity_score > 70 {
            return self.check_request_with_paranoia(..., 3);
        }
    }
}
```

On the mesh side, `BehavioralIntelligenceManager::adjust_paranoia_level` returns
`base` unchanged when `config.enabled` is false or the fingerprint bucket is
unpopulated, and otherwise returns `(base + 1).min(4)`.

### 6. DHT Message Types
```rust
// crates/synvoid-mesh/src/mesh/protocol.rs
BehavioralFingerprintAnnounce {
    request_id: ArcStr,
    fingerprints: Vec<crate::behavioral::BehavioralFingerprint>,
    timestamp: u64,
    source_node_id: ArcStr,
    signature: Vec<u8>,
    signer_public_key: Option<String>,
}

BehavioralFingerprintSyncRequest {
    request_id: ArcStr,
    node_id: ArcStr,
    from_version: u64,
    prefer_delta: bool,
}
```

## Configuration

`behavioral_enabled` lives in the mesh threat-intel config
(`crates/synvoid-mesh/src/mesh/threat_intel.rs`, `ThreatIntelligenceConfig` and
its runtime twin) — **not** in `BehavioralConfig`. The fingerprint knobs live in
`crates/synvoid-mesh/src/mesh/behavioral_intel.rs`:

```rust
pub struct BehavioralConfig {
    pub enabled: bool,                    // default true
    pub min_samples_for_fingerprint: u64, // default 10
    pub fingerprint_ttl_secs: u64,        // default 3600
    pub high_severity_threshold: u32,     // default 70
}
```

Composition reads `behavioral_enabled` when building the manager
(`src/worker/unified_server/init_mesh.rs`).

## Verification
```bash
cargo test -p synvoid-mesh --lib -- behavioral
```

## Common Issues
1. **LSH bucket collisions** - Use multiple hash functions for better accuracy
2. **Feature normalization** - Ensure features are on comparable scales
3. **Privacy leakage** - Audit fingerprint data to ensure no PII

## Scalability
- `MAX_FINGERPRINTS = 10000` caps the store; the oldest entry is evicted when
  the cap is reached
- 1024 LSH buckets give approximate (not O(1) exact) lookup: the bucket is
  scanned and each candidate compared with `similarity()`
- `cleanup_expired()` drops fingerprints past `last_seen + ttl_seconds` and
  prunes the bucket vectors
