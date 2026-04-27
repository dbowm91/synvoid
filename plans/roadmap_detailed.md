# MaluWAF Strategic Roadmap - Detailed Implementation Plan

**Status**: Active
**Last Updated**: 2026-04-27
**Based on**: roadmap.md (2026-04-26)
**Verification Commands**: See AGENTS.md

---

## Executive Summary

This plan provides comprehensive implementation guidance for the MaluWAF strategic roadmap spanning 2026-2027. Each wave contains features that build upon the decentralized, high-performance architecture already present in the codebase. The implementation prioritizes:

1. **Zero-allocation hot paths** per AGENTS.md constraints
2. **Decentralized-first design** (no Raft, no leader nodes)
3. **Fail-closed security** for streaming and behavioral features

---

## Wave 1: Performance & Low-Latency Foundation

### 1.1 Streaming WAF Engine

**Goal**: Scan request bodies incrementally instead of collecting them in full, enabling near-zero memory overhead for large requests and dramatically lower latency.

#### Current State Analysis

The `AttackDetector` in `src/waf/attack_detection/mod.rs:45-62` currently has:
- A `check_request()` method that takes `body: Option<&[u8]>`
- Individual detectors (`SqliDetector`, `XssDetector`, etc.) that receive the full body as a single chunk
- `check_body_only()` at line 580 which processes the entire body at once

The `SqliDetector` (`src/waf/attack_detection/sqli.rs:8-11`) and `XssDetector` (`src/waf/attack_detection/xss.rs:8-11`) use `BasePatternDetector` with Aho-Corasick and libinjection for detection.

HTTP servers already stream data:
- `src/http3/server.rs:264-281` accumulates body chunks into `body_bytes: Vec<u8>`
- `src/http/server.rs` uses chunked reading through `collect_body_with_chunk_waf_impl`

#### Implementation Guide

**1. Add `StreamingWafCore` struct** (new file: `src/waf/streaming.rs`)

```rust
pub struct StreamingWafCore {
    inner: Arc<AttackDetector>,
    chunk_size: usize,
    max_buffered_chunks: usize,
    state: RwLock<StreamingState>,
}

pub struct StreamingState {
    pending_chunks: VecDeque<Vec<u8>>,
    current_input: Option<String>,
    chunks_processed: usize,
    last_result: Option<AttackDetectionResult>,
}

impl StreamingWafCore {
    pub fn scan_chunk(&mut self, chunk: &[u8]) -> StreamingWafDecision {
        // Buffer chunk
        // Update running Aho-Corasick state if pattern spans chunks
        // Check libinjection on complete tokens
        // Return decision or continue buffering
    }
}
```

**2. Windowed Aho-Corasick Implementation**

The existing `aho-corasick` crate (version 1.1 in Cargo.toml:102) supports streaming via the `start` method. The pattern is:
- Create automaton with `AhoCorasick::new(patterns)`
- Use `automaton.is_match()` for stateful matching across chunks
- Maintain buffer of `chunk_size * 2` characters to catch cross-boundary patterns

Reference the existing `build_pattern_automaton()` in `src/waf/attack_detection/detector_common.rs:493-515`.

**3. HTTP/3 Integration**

In `src/http3/server.rs`, replace the body accumulation loop (lines 264-281) with:
```rust
// Instead of accumulating full body:
let mut streaming_waf = self.waf.streaming();
let mut response_started = false;

while let Ok(Some(chunk)) = request_stream.recv_data().await {
    let decision = streaming_waf.scan_chunk(&chunk);
    match decision {
        StreamingWafDecision::Block(code, reason) => {
            // Return block response immediately
            return self.send_block_response(code, reason).await;
        }
        StreamingWafDecision::Continue => {
            // Forward chunk to upstream while scanning continues
            upstream_stream.send_data(chunk).await?;
            if !response_started {
                response_started = true;
            }
        }
        StreamingWafDecision::NeedMore => {
            // Continue buffering
        }
    }
}
```

**4. HTTP/1 Integration**

Add a new handler in `src/http/server.rs` that uses `hyper::body::HttpBody` streaming:
```rust
async fn handle_streaming(
    self: Arc<Self>,
    mut request: Request<Body>,
    client_ip: IpAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut streaming_waf = self.waf.streaming();
    let mut upstream_body = BytesMut::new();

    while let Some(chunk) = request.body().frame().await {
        let frame = chunk?;
        if let Some(bytes) = frame.data_ref() {
            match streaming_waf.scan_chunk(bytes) {
                StreamingWafDecision::Block(..) => { /* handle */ }
                StreamingWafDecision::Continue => {
                    upstream_body.extend_from_slice(bytes);
                }
            }
        }
    }
}
```

**5. Memory Budget**

At 500K RPS target:
- If each request buffers 4KB average body: 500K * 4KB = 2GB per second
- Target: chunk buffer max 256KB per request, total concurrent 1000 requests = 256MB

**6. Fail-Closed Requirements**

If the internal buffer exceeds `max_buffered_chunks` (configurable, default 64 chunks = ~64KB for typical 1KB chunks), the system must:
1. Block the request with HTTP 413 (Payload Too Large)
2. Increment `maluwaf.streaming.buffer_overflow` metric
3. Log a warning with client IP and request path

#### Dependencies

- `aho-crasick` 1.1 (already in Cargo.toml:102)
- Existing `AttackDetector` architecture
- Existing `WafCore` in `src/waf/mod.rs:164-190`

#### Files to Modify

| File | Change |
|------|--------|
| `src/waf/mod.rs` | Add `StreamingWafCore` to `WafCore` |
| `src/waf/streaming.rs` | New file for streaming WAF logic |
| `src/http3/server.rs` | Integrate streaming scan into request handling |
| `src/http/server.rs` | Add streaming handler variant |
| `src/waf/attack_detection/detector_common.rs` | Add windowed Aho-Corasick support |

#### Verification

```bash
# Test streaming with large body
cargo test --lib streaming

# Benchmark memory allocation
cargo bench -- streaming_waf

# Verify HTTP/3 integration
cargo test --test integration_test -- http3
```

---

### 1.2 DHT Neighborhood Persistence

**Goal**: Accelerate mesh "warm-up" and reduce bootstrap traffic by persisting the "closest" DHT records locally.

#### Current State Analysis

The `RecordStoreManager` in `src/mesh/dht/record_store.rs:252-263` already has:
- `RecordStoreConfig` with `enabled`, `sync_interval_secs`, etc.
- `RecordStoreState` containing `records: ShardedRecordStore`
- Persistence pattern exists in `ThreatIntelligenceManager` (`src/mesh/threat_intel.rs:251-294`)

Existing persistence patterns in codebase:
- `src/mesh/threat_intel.rs:251-294` uses `save_to_file()` / `load_from_file()` with JSON
- `src/waf/rule_feed.rs:337-365` uses `serde_json::to_string_pretty()` and `from_str()`
- `src/admin/handlers/config.rs` uses `toml::to_string_pretty()` for config persistence

DHT record structure at `src/mesh/dht/record_store.rs:275-279`:
```rust
pub struct DhtRecordEntry {
    pub record: DhtRecord,
    pub local_origin: bool,
    pub version: u64,
}
```

`DhtRecord` at `src/mesh/protocol.rs:1373-1383`:
```rust
pub struct DhtRecord {
    pub key: String,
    pub value: Vec<u8>,
    pub timestamp: u64,
    pub sequence_number: u64,
    pub ttl_seconds: u64,
    pub source_node_id: String,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
    pub content_hash: Vec<u8>,
}
```

#### Implementation Guide

**1. Add Neighborhood Persistence Configuration**

In `src/mesh/config.rs`, add to `MeshPersistenceConfig` (around line 1367):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MeshPersistenceConfig {
    // ... existing fields ...
    #[serde(default)]
    pub neighborhood_persistence_enabled: bool,
    #[serde(default = "default_neighborhood_cache_size")]
    pub neighborhood_cache_size: usize,  // Max records to persist
    #[serde(default = "default_persist_max_age_secs")]
    pub persist_max_age_secs: u64,       // TTL for persisted records
}
```

**2. Create Persistence Module** (new file: `src/mesh/dht/record_store_persist.rs`)

```rust
const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct PersistedNeighborhood {
    version: u32,
    node_id: String,
    mesh_id: String,
    persisted_at: u64,
    records: Vec<PersistedRecord>,
}

#[derive(Serialize, Deserialize)]
struct PersistedRecord {
    key: String,
    value: Vec<u8>,
    timestamp: u64,
    ttl_seconds: u64,
    source_node_id: String,
}

impl RecordStoreManager {
    pub fn persist_neighborhood(&self, storage_path: &Path) -> Result<(), String> {
        // 1. Get node's neighborhood (closest records based on MeshID distance)
        // 2. Filter out expired records
        // 3. Serialize to JSON with temp file + rename pattern
        // 4. Update last_persisted timestamp
    }

    pub fn load_neighborhood(&self, storage_path: &Path) -> Result<usize, String> {
        // 1. Read persisted file
        // 2. Validate schema version
        // 3. Insert records into ShardedRecordStore
        // 4. Return count of loaded records
    }

    fn get_neighborhood_records(&self) -> Vec<DhtRecordEntry> {
        // Calculate distance between local node_id and record keys
        // Sort by distance and take closest N records
    }

    fn should_persist_record(&self, record: &DhtRecordEntry) -> bool {
        // Not expired
        // Not local_origin (local records don't need persistence)
        // Within configured TTL
    }
}
```

**3. Key Distance Calculation**

The MeshID distance calculation for "closest" records:
```rust
fn key_distance(key: &str, node_id: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(node_id.as_bytes());
    let result = hasher.finalize();
    u64::from_le_bytes(result[..8].try_into().unwrap())
}
```

Records with smallest distance to local node are most relevant for persistence.

**4. Background Pruning Task**

In `RecordStoreManager`, add:
```rust
pub fn start_pruning_task(&self, interval_secs: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            self.prune_expired_persisted_records().await;
        }
    });
}

async fn prune_expired_persisted_records(&self) {
    // Remove persisted records older than persist_max_age_secs
    // Update persisted index file
}
```

**5. Startup Integration**

In `src/mesh/transport.rs` or `src/startup/master.rs`, after record store initialization:
```rust
if config.mesh.persistence.neighborhood_persistence_enabled {
    let storage_path = config.mesh.persistence.data_dir.join("dht_neighborhood.json");
    let loaded = record_store.load_neighborhood(&storage_path)?;
    tracing::info!("Loaded {} DHT records from neighborhood persistence", loaded);
}
```

#### Existing Patterns to Follow

1. **JSON Persistence** (from `ThreatIntelligenceManager`):
   - Write to temp file with `.tmp` extension
   - Rename to final path (atomic)
   - Location: `src/mesh/threat_intel.rs:277-294`

2. **Error Handling**:
   - Return `Result<(), String>` for errors
   - Log warnings on failure but don't crash
   - Use `tracing::warn!` for recoverable errors

3. **Postcard Serialization** (for binary records):
   - Use `crate::serialization::serialize()` / `deserialize()` for binary data
   - Location: `src/mesh/dht/record_store_crud.rs:49-54`

#### Files to Create/Modify

| File | Change |
|------|--------|
| `src/mesh/dht/record_store_persist.rs` | New file for persistence logic |
| `src/mesh/config.rs` | Add neighborhood persistence config fields |
| `src/mesh/dht/record_store.rs` | Add `persist_neighborhood()`, `load_neighborhood()`, `start_pruning_task()` |
| `src/mesh/transport.rs` | Call persistence at startup |
| `src/startup/master.rs` | Initialize persistence after record store creation |

#### Verification

```bash
# Run DHT integration tests
cargo test --test dht_integration_test

# Verify persistence doesn't break existing functionality
cargo test --lib -- dht

# Check no regression in mesh sync
cargo test --test integration_test -- mesh
```

---

## Wave 2: Security Hardening & Platform Maturity

### 2.1 Hybrid Post-Quantum Mesh Signatures

**Goal**: Secure internal mesh orchestration against quantum adversaries using hybrid Ed25519 + ML-DSA signatures.

#### Current State Analysis

**Existing ML-KEM Infrastructure:**

ML-KEM-768 already implemented at `src/mesh/kem/ml_kem.rs:1-151`:
- Uses `pqc::MlKem768` crate
- Public key size: 1184 bytes, Secret key: 2400 bytes, Ciphertext: 1088 bytes

**Existing Key Exchange:**
`src/mesh/passover_key_exchange.rs:705-840` already supports ML-KEM encapsulation with:
- `perform_ml_kem_encapsulation()` function
- `combine_secrets()` to merge X25519 + ML-KEM secrets

**GlobalNodeConfig** at `src/mesh/config.rs:852-889` has:
- `ml_kem_private_key_base64: Option<String>`
- `ml_dsa_private_key_base64: Option<String>`
- Corresponding public key fields

**Current Signature System:**
`MeshMessageSigner` at `src/mesh/protocol.rs:90-151`:
- Uses Ed25519 (32-byte public key, 64-byte signature)
- `sign()`, `verify()`, `get_public_key()` methods

**Message Types Needing Hybrid Signature:**

From `src/mesh/protocol.rs`:
- `ThreatAnnounce` (line 564-574) - `signature: Vec<u8>, signer_public_key: String`
- `OrgKeyAnnounce` (line 294-298) - `signature: Vec<u8>`
- `DhtRecord` (line 1373-1383) - embedded in `DhtRecordAnnounce`

#### Implementation Guide

**1. Define HybridSignature Type** (new file: `src/mesh/hybrid_signature.rs`)

```rust
#[derive(Clone, Debug)]
pub struct HybridSignature {
    pub ed25519_signature: Vec<u8>,
    pub ml_dsa_signature: Vec<u8>,
    pub signer_public_key: String,
}

impl HybridSignature {
    pub const ED25519_SIZE: usize = 64;
    pub const ML_DSA_SIZE: usize = 2420;  // ML-DSA-65

    pub fn new(ed25519_sig: Vec<u8>, ml_dsa_sig: Vec<u8>, signer_pk: String) -> Self {
        Self {
            ed25519_signature: ed25519_sig,
            ml_dsa_signature: ml_dsa_sig,
            signer_public_key: signer_pk,
        }
    }

    pub fn serialized_size(&self) -> usize {
        4 + self.ed25519_signature.len() +
        4 + self.ml_dsa_signature.len() +
        4 + self.signer_public_key.len()
    }
}
```

**2. Add ML-DSA Support**

The `aws-lc-rs` crate already in Cargo.toml (line 150) with `unstable` feature supports ML-DSA. Create wrapper in `src/mesh/ml_dsa.rs`:

```rust
use aws_lc_rs::sign::ML_DSA;

pub structMlDsaSigner {
    key: [u8; 32],  // Seed for MLSAG
}

implMlDsaSigner {
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        // Use aws-lc-rs ML-DSA implementation
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        // Verify ML-DSA signature
    }

    pub fn public_key(&self) -> Vec<u8> {
        // Derive public key from seed
    }
}
```

**3. Extend MeshMessageSigner** (`src/mesh/protocol.rs`)

Add to `MeshMessageSigner`:
```rust
pub struct MeshMessageSigner {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key_bytes: Vec<u8>,
    ml_dsa_signer: Option<Box<dyn MlDsaSigner>>,
}

impl MeshMessageSigner {
    pub fn sign_hybrid(&self, content: &[u8]) -> HybridSignature {
        let ed25519_sig = self.sign(content);
        let ml_dsa_sig = self.ml_dsa_signer.as_ref()
            .map(|s| s.sign(content))
            .unwrap_or_default();
        HybridSignature::new(ed25519_sig, ml_dsa_sig, self.get_public_key())
    }

    pub fn verify_hybrid(&self, content: &[u8], hybrid: &HybridSignature) -> bool {
        // Verify both signatures
        let ed25519_valid = self.verify(content, &hybrid.ed25519_signature,
            &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &hybrid.signer_public_key).unwrap());

        let ml_dsa_valid = hybrid.ml_dsa_signature.is_empty() ||
            self.ml_dsa_verifier.as_ref()
                .map(|v| v.verify(content, &hybrid.ml_dsa_signature))
                .unwrap_or(false);

        ed25519_valid && (hybrid.ml_dsa_signature.is_empty() || ml_dsa_valid)
    }
}
```

**4. Add Feature Flag** (`Cargo.toml`)

```toml
[features]
pqc-mesh = ["dep:rustls-post-quantum", "dep:aws-lc-rs"]
```

**5. Update Message Types** (`src/mesh/protocol.rs`)

For `ThreatAnnounce` and other critical messages:
```rust
ThreatAnnounce {
    // ...
    signature: Vec<u8>,           // Ed25519 (backward compat)
    signer_public_key: String,
    #[cfg(feature = "pqc-mesh")]
    ml_dsa_signature: Option<Vec<u8>>,
}
```

**6. Signature Verification Flow**

In `src/mesh/threat_intel.rs:752-793` (`handle_incoming_threat()`):
```rust
fn verify_threat_signature(indicator: &ThreatIndicator, signer: &MeshMessageSigner) -> bool {
    let content = format!("{}:{}:{}:{}:{}",
        indicator.indicator_value,
        indicator.threat_type as u8,
        indicator.severity as u8,
        indicator.timestamp,
        indicator.source_node_id
    );

    #[cfg(feature = "pqc-mesh")] {
        if let Some(ref ml_dsa_sig) = indicator.ml_dsa_signature {
            let hybrid = HybridSignature {
                ed25519_signature: indicator.signature.clone(),
                ml_dsa_signature: ml_dsa_sig.clone(),
                signer_public_key: indicator.signer_public_key.clone(),
            };
            return signer.verify_hybrid(content.as_bytes(), &hybrid);
        }
    }

    // Fallback to Ed25519-only verification
    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&indicator.signer_public_key).unwrap();
    signer.verify(content.as_bytes(), &indicator.signature, &pk_bytes)
}
```

#### Key Size Reference

| Algorithm | Public Key | Signature |
|-----------|------------|-----------|
| Ed25519 | 32 bytes | 64 bytes |
| ML-KEM-768 | 1184 bytes | 1088 bytes (ciphertext) |
| ML-DSA-65 | 32 bytes (seed) | 2420 bytes |

#### Configuration Fields to Add

In `src/mesh/config.rs` → `GlobalNodeConfig`:
```rust
pub struct GlobalNodeConfig {
    // ... existing fields ...
    #[cfg(feature = "pqc-mesh")]
    pub ml_dsa_private_key_base64: Option<String>,
    #[cfg(feature = "pqc-mesh")]
    pub ml_dsa_public_key_base64: Option<String>,
    #[cfg(feature = "pqc-mesh")]
    pub hybrid_signing_enabled: bool,
}
```

#### Files to Create/Modify

| File | Change |
|------|--------|
| `src/mesh/hybrid_signature.rs` | New - HybridSignature type |
| `src/mesh/ml_dsa.rs` | New - ML-DSA wrapper |
| `src/mesh/protocol.rs` | Add `sign_hybrid()`, `verify_hybrid()` |
| `src/mesh/threat_intel.rs` | Update signature verification |
| `Cargo.toml` | Add `pqc-mesh` feature |
| `src/mesh/config.rs` | Add ML-DSA config fields |

#### Verification

```bash
# Test with pqc-mesh feature
cargo test --features pqc-mesh --lib -- hybrid

# Verify backward compatibility (no feature flag)
cargo test --lib -- threat_intel

# Test signature sizes
cargo test --features pqc-mesh -- test_ml_dsa_key_sizes
```

---

### 2.2 Windows Service & DX Improvement

**Goal**: Make MaluWAF a first-class citizen on Windows with proper service integration.

#### Current State Analysis

**Windows Platform Structure:**
- `src/platform/service/mod.rs:1-11` has stub for `windows_service` module
- `src/platform/windows.rs` exists (referenced in AGENTS.md for `cargo fmt`)
- Windows WFP support exists in `src/icmp_filter/wfp.rs`
- Windows TUN support in `src/tunnel/tun.rs`

**Current stub** (`src/platform/service/mod.rs`):
```rust
#[cfg(windows)]
pub mod windows_service;

#[cfg(windows)]
pub use windows_service::*;

#[cfg(not(windows))]
pub mod stub_service;
```

#### Implementation Guide

**1. Create Windows Service Implementation** (new file: `src/platform/service/windows_service.rs`)

```rust
#[cfg(windows)]
use windows_service::{
    define_main_function,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

pub struct MaluWafService {
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl MaluWafService {
    pub fn new() -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self { shutdown_tx }
    }

    pub fn run(&self) -> Result<(), windows_service::Error> {
        service_dispatcher::start(SERVICE_NAME, self)?;
        Ok(())
    }

    fn handle_service_control(&self, control: ServiceControl) -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop => {
                let _ = self.shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    }
}

define_main_function!(malwaf_service_main);

fn maluwaf_service_main() -> Result<(), windows_service::Error> {
    let service = MaluWafService::new();
    service.run()
}
```

**2. Interface Resolver Implementation** (new file: `src/platform/windows/interface_resolver.rs`)

```rust
use std::collections::HashMap;

pub struct WindowsInterfaceResolver;

impl WindowsInterfaceResolver {
    pub fn resolve(interface_name: &str) -> Result<u32, String> {
        // Use Windows API to get InterfaceIndex from friendly name
        // netadapterinfo or GetAdaptersInfo
    }

    pub fn get_all_interfaces() -> HashMap<String, u32> {
        // Map friendly names (e.g., "Ethernet 1") to InterfaceIndex
    }

    pub fn get_interface_by_index(index: u32) -> Option<String> {
        // Reverse lookup
    }
}
```

**3. Firewall Rule Injection** (`src/platform/windows/firewall.rs`)

```rust
pub fn inject_quic_firewall_rule(port: u16) -> Result<(), String> {
    // Use netsh advfirewall or PowerShell Set-NetFirewallRule
    let rule_name = format!("MaluWAF HTTP/3 QUIC Port {}", port);

    // Check if rule exists
    // Add rule if not exists:
    // netsh advfirewall firewall add rule name="MaluWAF HTTP/3" dir=in action=allow protocol=UDP localport=443

    Ok(())
}
```

**4. Service Installation/Uninstallation**

```rust
#[cfg(windows)]
pub fn install_service() -> Result<(), String> {
    // Use sc create or InstallUtil
    windows_service::service_manager::ServiceManager::local()
        .and_then(|manager| {
            manager.create_service(
                SERVICE_NAME,
                SERVICE_DISPLAY_NAME,
                ServiceType::OWN_PROCESS,
                // ... other params
            )
        })
}

#[cfg(windows)]
pub fn uninstall_service() -> Result<(), String> {
    // Use sc delete or service_manager.remove_service()
}
```

**5. Integrate with Startup**

In `src/startup/master.rs` or `src/overseer/spawn.rs`:
```rust
#[cfg(windows)]
pub fn run_as_windows_service() -> Result<(), String> {
    MaluWafService::new().run()
}

#[cfg(not(windows))]
pub fn run_as_windows_service() -> Result<(), String> {
    Err("Windows service mode is only available on Windows".to_string())
}
```

#### Configuration Fields

In `src/config/main.rs` or appropriate config location:
```rust
#[cfg(windows)]
pub struct WindowsServiceConfig {
    pub service_name: String,
    pub display_name: String,
    pub auto_start: bool,
    pub firewall_enabled: bool,
    pub quic_port: u16,
    pub interface_name: Option<String>,  // e.g., "Ethernet 1"
}

#[cfg(not(windows))]
pub struct WindowsServiceConfig;
```

#### Interface Index for WFP

The WFP (Windows Filtering Platform) requires `InterfaceIndex` for interface-specific filtering as mentioned in AGENTS.md. The `ConditionField::InterfaceIndex` in `src/icmp_filter/wfp.rs` is already implemented.

#### Files to Create/Modify

| File | Change |
|------|--------|
| `src/platform/service/windows_service.rs` | New - Windows service implementation |
| `src/platform/windows/interface_resolver.rs` | New - Interface resolution |
| `src/platform/windows/firewall.rs` | New - Firewall rule management |
| `src/platform/service/mod.rs` | Update with real Windows implementation |
| `src/startup/master.rs` | Add Windows service entry point |
| `src/config/mod.rs` | Add WindowsServiceConfig |

#### Verification

```bash
# Build on Windows
cargo build --target x86_64-pc-windows-msvc

# Test service installation (requires Windows)
# sc create maluwaf binPath= "C:\path\to\maluwaf.exe --service"
```

---

## Wave 3: Intelligent & Autonomous Mesh

### 3.1 Federated Behavioral Intelligence

**Goal**: Share anonymized attack patterns across the mesh based on behavioral fingerprints rather than just static IPs.

#### Current State Analysis

**Existing Threat Intelligence:**
`src/mesh/threat_intel.rs` already implements:
- `ThreatIndicator` struct with `threat_type`, `indicator_value`, `severity`, etc.
- `ThreatIntelligenceManager` with DHT synchronization
- `publish_indicator_to_dht()` for sharing
- `handle_incoming_threat()` for processing

**Existing Reputation System:**
`src/mesh/reputation.rs` contains `ReputationManager` for peer scoring.

**Existing DHT Key Patterns:**
`DhtKey::threat_indicator()` used at `src/mesh/dht/keys.rs`.

**Existing Behavioral Scoring:**
`src/waf/threat_level/scorer.rs` contains `ThreatScorer` for per-request scoring.

**Existing Paranoia Level:**
`AttackDetectionConfig.paranoia_level` in `src/waf/attack_detection/config.rs`.

#### Implementation Guide

**1. Define BehavioralFingerprint** (new file: `src/mesh/behavioral.rs`)

```rust
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFingerprint {
    pub fingerprint_id: String,
    pub特征向量: BehavioralFeatures,
    pub severity_score: u32,        // 0-100
    pub confidence: f32,             // 0.0-1.0
    pub sample_count: u64,           // Number of requests that contributed
    pub first_seen: u64,            // Unix timestamp
    pub last_seen: u64,
    pub ttl_seconds: u64,
    pub mesh_node_id: String,       // Origin node
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehavioralFeatures {
    pub header_timing_variance_ms: u32,
    pub request_sequence_entropy: f32,
    pub byte_length_distribution: Vec<u32>,  // Histogram bins
    pub inter_request_timing_ms: u32,
    pub suspicious_header_count: u8,
    pub url_entropy: f32,
    pub body_to_header_ratio: f32,
}

impl BehavioralFingerprint {
    pub fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.fingerprint_id.as_bytes());
        // Add feature bytes
        format!("{:016x}", hasher.finalize().len())
    }

    pub fn to_dht_key(&self) -> String {
        format!("behavior_fingerprint:{}", self.compute_hash())
    }
}
```

**2. Add to DHT Message Types** (`src/mesh/protocol.rs`)

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MeshMessage {
    // ... existing variants ...

    BehavioralFingerprintAnnounce {
        request_id: ArcStr,
        fingerprints: Vec<BehavioralFingerprint>,
        timestamp: u64,
        source_node_id: ArcStr,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    BehavioralFingerprintSyncRequest {
        request_id: ArcStr,
        node_id: ArcStr,
        from_version: u64,
        prefer_delta: bool,
    },
    BehavioralFingerprintSyncResponse {
        request_id: ArcStr,
        fingerprints: Vec<BehavioralFingerprint>,
        version: u64,
        is_delta: bool,
        removed_fingerprint_ids: Vec<ArcStr>,
        signature: Vec<u8>,
        signer_public_key: String,
    },
}
```

**3. Create BehavioralIntelligenceManager** (new file: `src/mesh/behavioral_intel.rs`)

```rust
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

const MAX_FINGERPRINTS: usize = 10000;
const SYNC_INTERVAL_SECS: u64 = 60;

pub struct BehavioralIntelligenceManager {
    fingerprints: RwLock<HashMap<String, BehavioralFingerprint>>,
    pending_announces: RwLock<VecDeque<BehavioralFingerprint>>,
    local_version: RwLock<u64>,
    config: Arc<BehavioralConfig>,
    signer: Option<Arc<MeshMessageSigner>>,
}

impl BehavioralIntelligenceManager {
    pub fn analyze_request(&self, request_features: &RequestFeatures) -> Option<BehavioralFingerprint> {
        // 1. Compute feature vector from request
        // 2. Compare against known fingerprints
        // 3. If match found above threshold, return fingerprint
        // 4. If novel high-severity pattern detected, create new fingerprint
    }

    pub fn adjust_paranoia_level(&self, client_ip: IpAddr) -> u8 {
        // Check if client's behavioral fingerprint matches known bad patterns
        // Return elevated paranoia level (e.g., 3 instead of 2)
    }

    fn compute_fingerprint(features: &BehavioralFeatures) -> String {
        // Use locality-sensitive hashing (LSH) for approximate matching
        // Return bucket ID
    }
}
```

**4. Integration with AttackDetector**

In `src/waf/attack_detection/mod.rs`, modify `AttackDetector::check_request()`:
```rust
#[inline]
pub fn check_request(
    &self,
    method: &http::Method,
    path: &str,
    query_string: Option<&str>,
    headers: &http::HeaderMap,
    body: Option<&[u8]>,
) -> Option<AttackDetectionResult> {
    // Existing checks...

    // NEW: Check behavioral fingerprint for elevated paranoia
    if let Some(bf_manager) = self.behavioral_intel.as_ref() {
        let features = self.extract_behavioral_features(method, path, query_string, headers, body);
        if let Some(fingerprint) = bf_manager.analyze_request(&features) {
            if fingerprint.severity_score > 70 {
                // Use higher paranoia level for this request
                return self.check_request_with_paranoia(
                    method, path, query_string, headers, body,
                    3,  // elevated paranoia
                );
            }
        }
    }

    None
}
```

**5. DHT Broadcasting**

```rust
impl BehavioralIntelligenceManager {
    pub fn broadcast_fingerprints(&self) -> Option<MeshMessage> {
        let mut queue = self.pending_announces.write();
        let fingerprints: Vec<BehavioralFingerprint> = queue.drain(..).take(50).collect();
        drop(queue);

        if fingerprints.is_empty() {
            return None;
        }

        let signature = self.signer.as_ref()
            .map(|s| s.sign(&serde_json::to_vec(&fingerprints).unwrap()));

        Some(MeshMessage::BehavioralFingerprintAnnounce {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            fingerprints,
            timestamp: current_timestamp(),
            source_node_id: self.node_id.clone().into(),
            signature: signature.unwrap_or_default(),
            signer_public_key: self.signer.as_ref()
                .map(|s| s.get_public_key())
                .unwrap_or_default(),
        })
    }
}
```

**6. Privacy Considerations**

- Never store client IPs in fingerprints
- Use only timing and structural features (no PII)
- Anonymize source_node_id in shared fingerprints
- Apply differential privacy noise to feature vectors

#### Configuration Fields

In `src/mesh/config.rs` → `ThreatIntelligenceConfig`:
```rust
pub struct ThreatIntelligenceConfig {
    // ... existing fields ...
    #[serde(default)]
    pub behavioral_enabled: bool,
    #[serde(default = "default_min_fingerprint_samples")]
    pub min_samples_for_fingerprint: u64,
    #[serde(default = "default_fingerprint_ttl_secs")]
    pub fingerprint_ttl_secs: u64,
    #[serde(default = "default_high_severity_threshold")]
    pub high_severity_threshold: u32,
}
```

#### Files to Create/Modify

| File | Change |
|------|--------|
| `src/mesh/behavioral.rs` | New - BehavioralFingerprint type |
| `src/mesh/behavioral_intel.rs` | New - BehavioralIntelligenceManager |
| `src/mesh/protocol.rs` | Add BehavioralFingerprint message variants |
| `src/mesh/threat_intel.rs` | Add handling for behavioral messages |
| `src/waf/attack_detection/mod.rs` | Integrate behavioral analysis |
| `src/mesh/dht/keys.rs` | Add behavioral key prefix |

#### Verification

```bash
# Test behavioral fingerprinting
cargo test --lib -- behavioral

# Test mesh integration
cargo test --test integration_test -- behavioral

# Verify no regression in threat intel
cargo test --test integration_test -- threat
```

---

### 3.2 Real-time Topology Visualizer

**Goal**: Provide a "God's eye view" of the decentralized mesh health via Admin API.

#### Current State Analysis

**Existing Topology Module:**
`src/mesh/topology.rs:28-50` already has `MeshTopology` with:
- `peer_store: ShardedPeerStore` (64 shards)
- `global_nodes: RwLock<HashSet<String>>`
- `route_cache: MokaCache`
- Various peer tracking methods

**Existing Admin API:**
`src/admin/handlers/mesh_admin.rs` contains mesh-related handlers.

**Existing Admin UI:**
`admin-ui/` directory exists for web interface.

**Existing Topology Types:**
`src/mesh/topology/types.rs` contains `PeerState`, `PeerScore`, `BandwidthStats`, etc.

#### Implementation Guide

**1. Create Topology Endpoint** (`src/admin/handlers/mesh_topology.rs`)

```rust
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct TopologyResponse {
    pub version: u64,
    pub total_peers: usize,
    pub global_nodes: Vec<GlobalNodeInfo>,
    pub edge_nodes: Vec<EdgeNodeInfo>,
    pub connections: Vec<ConnectionInfo>,
    pub metrics: TopologyMetrics,
}

#[derive(Debug, Serialize)]
pub struct GlobalNodeInfo {
    pub node_id: String,
    pub address: String,
    pub geo: Option<String>,
    pub latency_ms: Option<u32>,
    pub peer_count: usize,
    pub uptime_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct EdgeNodeInfo {
    pub node_id: String,
    pub parent_global_node: String,
    pub geo: Option<String>,
    pub latency_ms: Option<u32>,
    pub connected_upstreams: usize,
}

#[derive(Debug, Serialize)]
pub struct ConnectionInfo {
    pub from_node: String,
    pub to_node: String,
    pub latency_ms: u32,
    pub bandwidth_mbps: f64,
    pub connection_status: String,
}

#[derive(Debug, Serialize)]
pub struct TopologyMetrics {
    pub total_requests: u64,
    pub mesh_messages_per_sec: f64,
    pub average_peer_latency_ms: f32,
    pub trust_chain_coverage: f32,
}
```

**2. Handler Implementation**

```rust
pub async fn get_mesh_topology(
    State(state): State<Arc<AdminState>>,
) -> Json<TopologyResponse> {
    let mesh = state.mesh.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    let version = mesh.get_topology_version().await;
    let peers = mesh.get_all_peers().await;

    let (global_nodes, edge_nodes): (Vec<_>, Vec<_>) = peers
        .into_iter()
        .partition(|p| p.role.is_global());

    let connections = build_connection_graph(&peers).await;

    let metrics = TopologyMetrics {
        total_requests: get_total_requests(),
        mesh_messages_per_sec: get_mesh_throughput(),
        average_peer_latency_ms: calculate_avg_latency(&peers),
        trust_chain_coverage: calculate_trust_coverage(mesh).await,
    };

    Json(TopologyResponse {
        version,
        total_peers: global_nodes.len() + edge_nodes.len(),
        global_nodes,
        edge_nodes,
        connections,
        metrics,
    })
}
```

**3. Graph Data for D3.js**

```rust
#[derive(Debug, Serialize)]
pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String,  // "global", "edge", "origin"
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub color: String,
    pub size: f64,
}

#[derive(Debug, Serialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub weight: f64,        // Based on latency/bandwidth
    pub label: Option<String>,
}

pub async fn get_topology_graph() -> Json<GraphData> {
    // Return nodes/edges in D3-compatible format
}
```

**4. WebSocket for Real-time Updates**

```rust
pub async fn topology_ws_handler(
    ws: WebSocket,
    State(state): State<Arc<AdminState>>,
) {
    let mesh = state.mesh.as_ref()?;
    let mut receiver = mesh.subscribe_topology_changes().await;

    let (mut write, mut read) = ws.split();

    loop {
        tokio::select! {
            Some(update) = receiver.recv() => {
                let json = serde_json::to_string(&update).unwrap();
                write.send(Message::Text(json)).await?;
            }
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) => break,
                    _ => {}
                }
            }
        }
    }
}
```

**5. Admin UI Integration**

In `admin-ui/`:
```
src/
  components/
    MeshTopology/
      TopologyGraph.tsx     # D3.js force-directed graph
      TopologyStats.tsx     # Metrics panel
      NodeDetails.tsx       # Click to view node info
  hooks/
    useTopology.ts          # WebSocket subscription
    useTopologyGraph.ts     # Graph data processing
  pages/
    topology.tsx            # Main topology page
```

**6. Visualization Features**

Force-directed graph showing:
- **Regional hubs**: Global nodes as larger circles with geographic labels
- **Peer latencies**: Edge thickness = latency (thicker = lower latency)
- **Trust-chain propagation**: Color gradient showing trust level
- **Health status**: Green (healthy), yellow (degraded), red (unhealthy)

#### Admin API Route

In `src/admin/mod.rs`:
```rust
router = router
    .route("/api/mesh/topology", get(get_mesh_topology))
    .route("/api/mesh/topology/graph", get(get_topology_graph))
    .route("/api/mesh/topology/ws", ws(topology_ws_handler));
```

#### Files to Create/Modify

| File | Change |
|------|--------|
| `src/admin/handlers/mesh_topology.rs` | New - Topology handlers |
| `src/mesh/topology.rs` | Add `subscribe_topology_changes()` |
| `src/admin/mod.rs` | Add routes |
| `admin-ui/src/components/MeshTopology/` | New - UI components |
| `admin-ui/src/hooks/useTopology.ts` | New - WebSocket hook |

#### Verification

```bash
# Test API endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/mesh/topology

# Verify JSON response structure
cargo test --test integration_test -- topology

# Check WebSocket connection
cargo test --test integration_test -- ws_topology
```

---

## Cross-Cutting Concerns

### A. Fail-Closed Security

All streaming and behavioral features must default to blocking if internal buffers overflow:

```rust
pub enum FailClosedDecision {
    Block {
        code: u16,
        reason: String,
    }
}

impl StreamingWafCore {
    pub fn scan_chunk(&mut self, chunk: &[u8]) -> Result<StreamingWafDecision, FailClosedError> {
        if self.state.read().pending_chunks.len() >= self.max_buffered_chunks {
            return Err(FailClosedError::BufferOverflow {
                client_ip: self.client_ip,
                path: self.path.clone(),
                chunks_buffered: self.max_buffered_chunks,
            });
        }
        // ... continue processing
    }
}
```

Metrics to track:
- `maluwaf.streaming.buffer_overflow`
- `maluwaf.behavioral.buffer_overflow`
- `maluwaf.dht.persist.buffer_overflow`

### B. Zero-Allocation Hot Paths

Per AGENTS.md scalability targets (500K+ RPS), every allocation in hot paths matters:

1. **Streaming WAF**: Use `Bytes` instead of `Vec<u8>` for chunks
2. **DHT Persistence**: Pre-allocate record vectors with capacity
3. **Behavioral Fingerprints**: Use fixed-size feature arrays

```rust
// GOOD: Stack-allocated buffer for small chunks
let mut buf = [0u8; 256];
buf[..chunk.len()].copy_from_slice(chunk);

// BAD: Heap allocation per chunk
let mut buf = Vec::new();
buf.extend_from_slice(chunk);
```

### C. Decentralized Design Constraints

- No leader election or primary node
- All consensus via DHT quorum (2/3 Byzantine fault tolerance)
- Trust chain: Genesis Key → Global Nodes → Org Keys → Edge Nodes
- Regional autonomy for edge nodes during network partition

### D. Testing Requirements

Each implementation must include:
1. Unit tests for core logic
2. Integration tests for mesh communication
3. Benchmark tests for hot path performance
4. Fail-closed behavior tests (buffer overflow scenarios)

---

## Implementation Order Recommendations

### Phase 1 (Q2 2026)
1. DHT Neighborhood Persistence (1.2) - Lower risk, improves startup
2. Streaming WAF Engine (1.1) - Core performance improvement

### Phase 2 (Q3 2026)
3. Hybrid Post-Quantum Signatures (2.1) - Security hardening
4. Windows Service (2.2) - Platform maturity

### Phase 3 (Q4 2026 - Q1 2027)
5. Federated Behavioral Intelligence (3.1) - Advanced feature
6. Real-time Topology Visualizer (3.2) - UX improvement

---

## Verification Commands

```bash
# All tests (no DNS feature)
cargo test

# Targeted tests
cargo test --lib <module_name>
cargo test --test integration_test

# Performance benchmarks
cargo bench --bench bench_streaming
cargo bench --bench bench_dht

# Lint and format
cargo fmt
cargo clippy -- -D warnings

# Build with specific features
cargo build --features pqc-mesh
cargo build --features dns
```

---

**Last Updated**: 2026-04-27
**Status**: ACTIVE - Implementation Phase