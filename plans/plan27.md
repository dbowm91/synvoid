# Plan 27: YARA Rules & Threat Intelligence Mesh Distribution Improvements

## Context

This plan addresses security and operational gaps in the mesh-based YARA rules and Threat Intelligence distribution system identified during code review.

### Current System Overview

| Component | Global → DHT | Non-Global → DHT | Non-Global Sync | Notes |
|-----------|-------------|------------------|-----------------|-------|
| **YARA Rules** | ✅ Working | ❌ Should be blocked | ✅ Working | Only global nodes should publish |
| **Threat Intel** | ✅ Working | ✅ Working | ✅ Working | Both can publish |

### Key Findings

1. **Capability Verifier NOT Wired**: `CapabilityAccessVerifier` exists but `RecordStoreManager` is created with `capability_verifier: None`, bypassing all capability checks.

2. **Event-Driven YARA Refresh Missing**: FileManager uses wasteful timer-based polling (every N seconds regardless of uploads).

3. **HTTP FileManager Scan**: Review revealed `scan_on_upload: false` at `src/http/file_manager.rs:381` is **test-only** — production paths default to `true`. **No CHANGE NEEDED**.

4. **ThreatIntel Missing Defenses**: No content hash verification, no timestamp bounds, no trusted_signers allowlist.

5. **YARA Content Signing**: Analysis shows manifest signature + content_hash verification already provides equivalent protection. Content signing is redundant and not recommended.

---

## Decisions

1. **YARA rules publishing**: Global nodes ONLY. Non-global nodes cannot publish to DHT (they can sync and use locally).

2. **Threat Intel publishing**: Both global and non-global nodes can publish. Non-global nodes publish their own local observations (honeypot hits, suspicious activity).

3. **YARA rule refresh**: Event-driven via broadcast channel, but with periodic fallback at **longer intervals** (e.g., every 5 minutes instead of every 60 seconds).

4. **ThreatIntel timestamp bounds**: Apply to both DHT sync (`sync_from_dht()`) AND incoming mesh messages (`handle_incoming_threat()`).

---

## Implementation Phases

### Phase 1: Capability Verifier Wiring (Security Critical)

**Goal**: Ensure only authorized nodes can publish YARA rules (global only) and Threat Intel to DHT.

#### 1.1 Fix Interior Mutability for `capability_verifier`

**File**: `src/mesh/dht/record_store.rs`

The `capability_verifier` field on `RecordStoreManager` is `Option<Arc<CapabilityAccessVerifier>>` but needs to be wrapped in `RwLock` for interior mutability since `RecordStoreManager` is behind `Arc`.

```rust
// CURRENT (line ~359):
capability_verifier: Option<Arc<CapabilityAccessVerifier>>,

// CHANGE TO:
capability_verifier: parking_lot::RwLock<Option<Arc<CapabilityAccessVerifier>>>,
```

Update `set_capability_verifier()` and `verify_capability_for_key()` to use the `RwLock`.

#### 1.2 Wire Verifier in Backend

**File**: `src/mesh/backend.rs`

After creating `RecordStoreManager`, create the `verify_fn` closure and call `set_capability_verifier()`:

```rust
let record_store_for_closure = Arc::clone(&rs);

let verifier = CapabilityAccessVerifier::new(move |node_id: &str, capability: &str| {
    let key = crate::mesh::dht::keys::DhtKey::capability_attestation(node_id, capability);
    let key_str = key.as_str();
    if let Some(record) = record_store_for_closure.get(&key_str) {
        serde_json::from_slice::<crate::mesh::dht::CapabilityAttestation>(&record.value).ok()
    } else {
        None
    }
});

rs.set_capability_verifier(Some(Arc::new(verifier)));
```

#### 1.3 Exempt ThreatIntel from Capability Check

**File**: `src/mesh/dht/record_store_crud.rs`

The `key_requires_capability()` function returns `"threat_intel"` for `threat_indicator:*` keys. Since non-global nodes must be able to publish threat intel, we need to **explicitly exempt** threat intel keys from capability verification:

In `store_record()` where capability verification occurs (~line 142), modify:
```rust
if let Some(ref verifier) = self.capability_verifier {
    // Skip capability check for threat_intel keys - any node can publish
    if !record.key.starts_with("threat_indicator:") {
        if !verifier.verify_capability_for_key(&record.source_node_id, &record.key) {
            tracing::warn!("Capability verification failed for node {} on key {}",
                record.source_node_id, record.key);
            return false;
        }
    }
}
```

**Note**: YARA keys (`yara_rule:*`, `yara_rules_manifest:*`) will still require the "waf" capability, which only global nodes have via self-attestation. Non-global nodes cannot publish YARA rules to DHT.

This approach:
- ✅ YARA rules: Global-only (requires "waf" capability)
- ✅ Threat Intel: Any node can publish (capability check skipped)
- ✅ Minimal code change
- ✅ Follows principle of least privilege

#### 1.4 Global Nodes Self-Attest "waf" on Startup

**File**: `src/mesh/backend.rs`

Global nodes need the "waf" capability to publish YARA rules. Since they're the authority, they self-attest:

```rust
if config.role.is_global() {
    // Self-attest "waf" capability (for YARA rules publishing)
    let waf_attestation = CapabilityAttestation::new(
        config.node_id(),
        "waf".to_string(),
        config.node_id(),  // attested_by = self
        signer.get_public_key(),
        signer.sign(format!("{},waf,{},{}", config.node_id(), config.node_id(), timestamp).as_bytes()),
        timestamp,
    );

    let key = DhtKey::capability_attestation(config.node_id(), "waf");
    rs.store_and_announce(key.as_str(), serde_json::to_vec(&waf_attestation).unwrap(), 86400);

    // Note: threat_intel does NOT require capability (exempt per 1.3), so no self-attestation needed
}
```

**Why not self-attest "threat_intel"?** Because threat_intel keys are exempt from capability checks (Phase 1.3), so any node can publish them without attestation.

#### 1.5 Add Admin API for Capability Attestation

**Files**: `src/admin/handlers/mesh.rs` (new or existing)

```rust
// POST /api/mesh/attest-capability
pub async fn attest_capability(
    // Request: { "node_id": "...", "capability": "waf" | "threat_intel" }
) -> Result<Json<AttestCapabilityResponse>, StatusCode> {
    // Verify requester is global node
    // Call transport.attest_capability(node_id, capability)
}
```

---

### Phase 2: Event-Driven YARA Rule Refresh

**Goal**: Eliminate wasteful timer polling in FileManager while ensuring rules stay current.

#### 2.1 Add Broadcast Channel to YaraRulesManager

**File**: `src/mesh/yara_rules.rs`

```rust
// Add to struct definition (~line 286):
rules_update_tx: Arc<parking_lot::RwLock<Option<tokio::sync::broadcast::Sender<YaraRulesUpdate>>>>,

// Add notification payload:
#[derive(Debug, Clone)]
pub struct YaraRulesUpdate {
    pub version: String,
    pub timestamp: u64,
}

// Initialize in new() (~line 320):
let (rules_update_tx, _) = tokio::sync::broadcast::channel(16);
rules_update_tx: Arc::new(parking_lot::RwLock::new(Some(rules_update_tx))),
```

#### 2.2 Emit Notifications on Rule Changes

**File**: `src/mesh/yara_rules.rs`

After successful rule application in `apply_rules()` (~line 1138):
```rust
if let Some(tx) = self.rules_update_tx.read().as_ref() {
    let _ = tx.send(YaraRulesUpdate {
        version: version.clone(),
        timestamp: crate::utils::current_timestamp(),
    });
}
```

Similarly in `apply_rules_from_feed()` (~line 1077) after `*self.local_rules.write() = Some(rules.clone());`.

#### 2.3 Add Subscribe API

**File**: `src/mesh/yara_rules.rs`

```rust
pub fn subscribe_to_rules_updates(&self) -> tokio::sync::broadcast::Receiver<YaraRulesUpdate> {
    if let Some(tx) = self.rules_update_tx.read().as_ref() {
        tx.subscribe()
    } else {
        let (_, rx) = tokio::sync::broadcast::channel(1);
        rx
    }
}
```

#### 2.4 Add Dropped Event Metric

**File**: `src/metrics/mod.rs`

```rust
static DROPPED_YARA_RULES_UPDATE_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

pub fn record_dropped_yara_rules_update() {
    DROPPED_YARA_RULES_UPDATE_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dropped_yara_rules_update_events() -> u64 {
    DROPPED_YARA_RULES_UPDATE_EVENTS.load(Ordering::Relaxed)
}
```

#### 2.5 Replace Timer with Event Listener

**File**: `src/static_files/file_manager.rs`

Replace `start_periodic_yara_refresh()` (~line 298):

```rust
pub fn start_yara_rules_listener(file_manager: Arc<Self>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(yara_rules) = crate::waf::get_yara_rules() else {
            tracing::warn!("YARA rules not available for FileManager listener");
            return;
        };

        let mut rx = yara_rules.subscribe_to_rules_updates();

        loop {
            match rx.recv().await {
                Ok(update) => {
                    tracing::debug!("Received YARA rules update: version={}", update.version);
                    if let Err(e) = file_manager.reload_yara_rules_if_needed() {
                        tracing::warn!("YARA rules update reload failed: {}", e);
                    }
                }
                Err(broadcast::RecvError::Lagged(_)) => {
                    if let Err(e) = file_manager.reload_yara_rules_if_needed() {
                        tracing::warn!("YARA rules catch-up reload failed: {}", e);
                    }
                }
                Err(broadcast::RecvError::Closed) => {
                    tracing::info!("YARA rules update channel closed");
                    break;
                }
            }
        }
    })
}
```

#### 2.6 Add Periodic Fallback with Longer Interval

**File**: `src/static_files/file_manager.rs`

Add a safety net that runs every **5 minutes** (300 seconds) instead of the current shorter intervals:

```rust
pub fn start_periodic_yara_refresh_fallback(
    file_manager: Arc<Self>,
    interval_secs: u64,  // Default: 300
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            if let Err(e) = file_manager.reload_yara_rules_if_needed() {
                tracing::debug!("Periodic YARA refresh failed: {}", e);
            }
        }
    })
}
```

#### 2.7 Wire Both Listeners in UnifiedServer

**File**: `src/worker/unified_server.rs` (~line 935)

```rust
// Start event-driven listener
let fm_handle = crate::static_files::file_manager::FileManager::start_yara_rules_listener(fm.clone());

// Start periodic fallback (every 5 minutes)
let fm_fallback = fm.clone();
let fallback_handle = crate::static_files::file_manager::FileManager::start_periodic_yara_refresh_fallback(
    fm_fallback,
    300,  // 5 minutes
);
```

---

### Phase 3: ThreatIntel Enhancements

#### 3.1 Add Timestamp Bounds Validation

**File**: `src/mesh/threat_intel.rs`

Add constants (~line 148):
```rust
const THREAT_TIMESTAMP_FUTURE_BOUND_SECS: u64 = 60;   // 1 minute
const THREAT_TIMESTAMP_PAST_BOUND_SECS: u64 = 86400;  // 24 hours
```

Add bounds check in `sync_from_dht()` (~line 1261, after parsing, before signature verification):
```rust
let now = crate::utils::current_timestamp();
if indicator.timestamp > now + THREAT_TIMESTAMP_FUTURE_BOUND_SECS {
    tracing::warn!(
        "Threat intel DHT sync: indicator timestamp {} is too far in future (now: {})",
        indicator.timestamp, now
    );
    continue;
}
if now > indicator.timestamp && now - indicator.timestamp > THREAT_TIMESTAMP_PAST_BOUND_SECS {
    tracing::warn!(
        "Threat intel DHT sync: indicator timestamp {} is too old (now: {})",
        indicator.timestamp, now
    );
    continue;
}
```

Add same bounds check in `handle_incoming_threat()` (~line 754, after parsing, before signature verification). This protects against replay attacks where an attacker re-sends old indicators via mesh QUIC transport.

**Note**: `handle_incoming_threat()` receives threat intel from mesh peers (QUIC streams), not from DHT. It is separate from `sync_from_dht()` which pulls from local DHT cache.

#### 3.2 Add Content Hash Verification

**File**: `src/mesh/threat_intel.rs`

Add `content_hash` to published indicators in `publish_indicator_to_dht()` (~line 700-714):
```rust
let content_for_hash = format!(
    "{}:{}:{}:{}:{}",
    indicator.indicator_value,
    indicator.threat_type as u8,
    indicator.severity as u8,
    indicator.timestamp,
    indicator.source_node_id
);
let content_hash = sha2::Sha256::digest(content_for_hash.as_bytes());

let value = serde_json::json!({
    "indicator": indicator,
    "signature": signature,
    "signer_public_key": signer_public_key,
    "content_hash": hex::encode(content_hash),
    "published_at": crate::utils::current_timestamp(),
});
```

Add verification in `sync_from_dht()` (after line 1339, after signature verification):
```rust
if let Some(stored_hash) = value.get("content_hash").and_then(|v| v.as_str()) {
    let computed = format!(
        "{}:{}:{}:{}:{}",
        indicator.indicator_value,
        indicator.threat_type as u8,
        indicator.severity as u8,
        indicator.timestamp,
        indicator.source_node_id
    );
    let computed_hash = sha2::Sha256::digest(computed.as_bytes());
    if hex::encode(computed_hash) != stored_hash {
        tracing::warn!("Threat intel DHT sync: content hash mismatch for {}", key);
        continue;
    }
}
```

#### 3.3 Add `trusted_signers` Config

**File**: `src/mesh/threat_intel.rs`

Add to `ThreatIntelligenceConfig` (~line 31-56):
```rust
#[serde(default)]
pub trusted_signers: Vec<String>,
```

Add to `ThreatIntelligenceConfigInternal` (~line 113-127):
```rust
pub trusted_signers: Vec<String>,
```

Initialize in Default impl (~line 129-146):
```rust
trusted_signers: Vec::new(),
```

Add verification in `sync_from_dht()` (after line 1317, after signature verification):

**Order of verification in `sync_from_dht()`**:
1. Parse indicator
2. **Validate timestamp bounds** (Phase 3.1)
3. Verify Ed25519 signature
4. **Check trusted_signers allowlist** (Phase 3.3)
5. Check source is global node

```rust
if !self.config.trusted_signers.is_empty()
    && !self.config.trusted_signers.contains(&signer_pk.to_string())
{
    tracing::warn!(
        "Threat intel DHT sync: signer pk {} not in trusted signers list",
        signer_pk
    );
    continue;
}
```

---

## Backward Compatibility

| Change | Strategy |
|--------|----------|
| Capability verifier | Global nodes self-attest "waf" for YARA on startup; threat_intel is exempt (any node can publish) |
| Event-driven refresh | Periodic fallback ensures no regression if channel missed |
| ThreatIntel content_hash | Records without hash accepted with warning |
| ThreatIntel timestamp bounds | Records failing bounds logged and skipped; existing valid records remain |
| trusted_signers | Empty list = accept all (backward compatible) |

---

## Testing Plan

### Unit Tests

1. **Capability Verifier**: Test that global nodes can publish YARA (requires "waf" self-attestation); non-global nodes blocked for YARA but can publish threat_intel (exempt).

2. **YARA Event Notification**: Test that `apply_rules()` emits notification; FileManager listener receives and reloads.

3. **ThreatIntel Timestamp Bounds**: Test indicators with future/past timestamps rejected.

4. **ThreatIntel Content Hash**: Test mismatch detection.

5. **ThreatIntel Trusted Signers**: Test allowlist enforcement.

### Integration Tests

1. Mesh network with global + edge nodes: Verify YARA rules flow only from global.

2. Edge node publishes threat intel; global and other edges receive it.

3. FileManager receives YARA update via event; periodic fallback triggers reload.

---

## Files Modified

| File | Changes |
|------|---------|
| `src/mesh/dht/record_store.rs` | Change `capability_verifier` to `RwLock<Option<...>>` |
| `src/mesh/backend.rs` | Wire verifier; add self-attestation for global nodes |
| `src/mesh/yara_rules.rs` | Add broadcast channel; emit notifications; add subscribe API |
| `src/static_files/file_manager.rs` | Replace timer with event listener; add periodic fallback |
| `src/mesh/threat_intel.rs` | Add timestamp bounds; content hash; trusted_signers |
| `src/metrics/mod.rs` | Add `DROPPED_YARA_RULES_UPDATE_EVENTS` counter |
| `src/worker/unified_server.rs` | Wire both listeners |
| `src/admin/handlers/mesh.rs` | Add `POST /api/mesh/attest-capability` |

---

## Not Recommended

### YARA Rule Content Signing

**Decision**: Do not implement.

**Rationale**: The manifest signature + content_hash verification already provides equivalent protection. A compromised global node with a valid signing key can publish false content regardless of whether content is separately signed — both would use the same key.

**Dead Code Found**: The `rule_signature` field in non-chunked YARA records (line 616-628) is populated but never verified in `fetch_rules_from_dht()`. This is dead code but not a security vulnerability since content_hash check provides equivalent protection.

**Alternative**: M-of-N threshold signatures or independent feed verification (e.g., VirusTotal) if protection against compromised global nodes is required.

---

## Open Questions

1. **Capability Attestation TTL**: Should attestations auto-expire and require renewal? Currently 24h TTL but no auto-renewal.

2. **YARA Rule Source Priority**: When multiple sources (feed, mesh global, mesh edge approved) provide rules, is there a priority order? Currently newest timestamp wins.

3. **ThreatIntel Indicator TTL**: What should determine indicator TTL — severity? Type? Config?
