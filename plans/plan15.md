# MaluWAF Implementation Plan 15 - YARA Rules & Threat Intelligence Distribution

**Status**: Planning
**Created**: 2026-04-27
**Last Updated**: 2026-04-27
**Priority**: High
**Estimated Duration**: 2-3 weeks (phased)

---

## Executive Summary

This plan addresses findings from a comprehensive review of the YARA rules distribution system, threat intelligence sharing, and file upload security in the MaluWAF mesh mode. The review identified gaps in:

1. **Critical gap**: Threat intel uses probabilistic fanout (50% of nodes) even for CRITICAL severity threats
2. **Sync latency**: New nodes joining mid-incident don't receive immediate YARA/threat intel updates
3. **Approval latency**: Edge nodes cannot bypass global approval during emergencies
4. **Security inconsistency**: YARA rules trusted_signer enforcement differs from threat intel
5. **Configuration safety**: No validation preventing re-announce interval from exceeding TTL

The file upload security system was found to be comprehensive with multi-layer protection. The focus here is on ensuring global nodes can effectively distribute YARA rules and threat intelligence to all nodes as required.

---

## Current Architecture Assessment

### YARA Rules Distribution (Operational)

| Mechanism | Status | Location |
|-----------|--------|----------|
| DHT publishing | ✅ Working | `yara_rules.rs:454-654` |
| Direct broadcast to peers | ✅ Working | `yara_rules.rs:1484-1524` |
| DHT sync on timer | ✅ Working | `yara_rules.rs:2018-2067` |
| Chunked storage for large rules | ✅ Working | `yara_rules.rs:555-597` |
| Signature verification | ⚠️ Bug | `yara_rules.rs:942-954` (no global bypass) |
| Edge submission workflow | ✅ Working | `yara_rules.rs:1141-1361` |

### Threat Intelligence Distribution (Operational)

| Mechanism | Status | Location |
|-----------|--------|----------|
| DHT publishing | ✅ Working | `threat_intel.rs:680-782` |
| Critical/High DHT differentiation | ✅ Working | `threat_intel.rs:755-767` |
| P2P push broadcast | ⚠️ Bug | `threat_intel.rs:1507-1535` (no severity differentiation) |
| Periodic DHT sync | ✅ Working | `threat_intel.rs:1691-1754` |
| Trusted signer enforcement | ✅ Working | `threat_intel.rs:1296-1306`, `1606-1621` |

### File Upload Security (Comprehensive)

| Component | Status | Location |
|-----------|--------|----------|
| MIME validation | ✅ Working | `upload/mod.rs:160-228` |
| YARA-X scanning | ✅ Working | `upload/yara_scanner.rs` |
| Malware scanner | ✅ Working | `upload/malware_scanner.rs` |
| Quarantine system | ✅ Working | `upload/sandbox.rs:201-244` |
| IP blocking on malware | ✅ Working | `http/server.rs:2454-2530` |

---

## Identified Issues Summary

| ID | Issue | Category | Severity | Priority |
|----|-------|----------|----------|----------|
| 1 | Threat intel probabilistic fanout for CRITICAL threats | Security | High | P0 |
| 2 | No sync-on-join for YARA/threat intel | Scalability | High | P1 |
| 3 | Edge submission has no emergency bypass | Robustness | High | P1 |
| 4 | YARA trusted_signer lacks global bypass (bug) | Security | Medium | P2 |
| 5 | No TTL > re_announce interval validation | Configuration | Medium | P2 |
| 6 | YARA TTL hardcoded (not configurable) | Configuration | Low | P3 |

---

## Phase 1: P0 Critical - Deterministic Broadcast for Critical Threats

**Target**: Complete within 3 days
**Risk**: Low

### 1.1: Severity-Aware Threat Broadcast

**File**: `src/mesh/threat_intel.rs:1507-1535`

**Issue**: `broadcast_pending_threats()` uses same `fanout_factor=0.5` for all severities. Critical CVE indicators only reach ~50% of nodes immediately.

**Current Code** (`threat_intel.rs:1533`):
```rust
let (success, fail) = transport
    .broadcast_to_random_peers(message, fanout_factor, None)  // Always 50%
    .await;
```

**Problem**: The `highest_severity` field is calculated but never used to select broadcast strategy:
```rust
let highest_severity = indicators
    .iter()
    .map(|i| i.severity)
    .max_by_key(|s| *s as u32)
    .unwrap_or(ThreatSeverity::Unspecified);
// highest_severity is set but never used to select broadcast method!
```

**DHT path correctly differentiates** (`threat_intel.rs:755-767`):
```rust
let is_critical_threat = indicator.severity == ThreatSeverity::Critical
    || indicator.severity == ThreatSeverity::High;

let stored = if is_critical_threat && self.node_role.is_global() {
    record_store.store_and_announce_critical(...)  // Higher replication
} else {
    record_store.store_and_announce(...)
};
```

**Implementation**:
```rust
// In broadcast_pending_threats(), after creating the message:
// Extract highest severity from indicators
let highest_severity = indicators
    .iter()
    .map(|i| i.severity)
    .max_by_key(|s| *s as u32)
    .unwrap_or(ThreatSeverity::Unspecified);

// Determine if this is a critical/high threat (matches DHT path logic)
let is_critical_or_high = highest_severity == ThreatSeverity::Critical
    || highest_severity == ThreatSeverity::High;

// Select broadcast method based on severity
let transport_opt = self.transport.read().clone();
if let Some(transport) = transport_opt {
    let (success, fail) = if is_critical_or_high {
        // Deterministic broadcast for Critical/High threats - ALL peers
        // (matches store_and_announce_critical logic in DHT path)
        tracing::debug!("Broadcasting {:?} threat to all peers", highest_severity);
        transport.broadcast_to_all_peers(message, None).await
    } else {
        // Probabilistic for lower severity (Medium, Low, Unspecified)
        transport.broadcast_to_random_peers(message, fanout_factor, None).await
    };
    // ... existing logging ...
}
```

**Note**: Using `Critical || High` to match the DHT path logic at `threat_intel.rs:755-767`.

**Verification**:
```bash
# Add test: Send Critical threat, verify broadcast_to_all_peers called
# Add test: Send Low threat, verify broadcast_to_random_peers called
cargo test --lib threat_intel
```

---

### 1.2: Add Metrics for Broadcast Coverage

**File**: `src/metrics/mod.rs`

**Purpose**: Track what percentage of peers receive critical threats.

**Implementation**:
```rust
// Add to metrics
pub static CRITICAL_THREAT_BROADCAST_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub static CRITICAL_THREAT_PEER_COVERAGE: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

// In broadcast_pending_threats():
if highest_severity == ThreatSeverity::Critical {
    CRITICAL_THREAT_BROADCAST_COUNT.fetch_add(1, Ordering::Relaxed);
    // track coverage via success count vs total peers
}
```

---

## Phase 2: P1 High Priority - Sync-on-Join and Emergency Bypass

**Target**: Complete within 1 week
**Risk**: Medium

### 2.1: Trigger Sync on Peer Connection

**Files**:
- `src/mesh/transport_connection.rs:212-253` (`dht_on_peer_connected`)
- `src/mesh/yara_rules.rs` (YaraRulesManager)
- `src/mesh/threat_intel.rs` (ThreatIntelligenceManager)

**Issue**: YARA rules and threat intel only sync on periodic timers. New nodes joining mid-incident wait for next tick.

**What exists**: `warm_up_on_connect` syncs DHT records via snapshot request (`transport_connection.rs:304-331`).

**Gap**: YARA/threat sync is NOT triggered on peer connection.

**Current sync triggers**:
| Component | Trigger | Interval |
|-----------|---------|----------|
| YARA DHT sync | Timer only | 3600s default |
| Threat intel DHT sync | Timer only | 60s default |
| DHT snapshot (warm_up) | On connect | One-time |

**Implementation**:
```rust
// In dht_on_peer_connected() after adding peer to routing:
// Trigger immediate YARA and threat intel sync for newly connected peer

// Spawn async sync tasks to avoid blocking the connection handler
if let Some(yara_manager) = crate::waf::get_yara_rules_manager() {
    let yara_clone = yara_manager.clone();
    tokio::spawn(async move {
        if let Err(e) = yara_clone.sync_from_dht() {
            tracing::debug!("YARA sync from peer connection failed: {}", e);
        }
    });
}

if let Some(threat_intel) = crate::mesh::get_threat_intel_manager() {
    let threat_clone = threat_intel.clone();
    tokio::spawn(async move {
        // Note: sync_from_dht returns Result<(), String>
        if let Err(e) = threat_clone.sync_from_dht().await {
            tracing::debug!("Threat intel sync from peer connection failed: {}", e);
        }
    });
}
```

**Note**: `sync_from_dht()` for YARA returns `Result<(), YaraRulesError>` and for threat intel returns `Result<(), String>`. Both are non-blocking and safe to call.

**Alternative - Use message-based sync**:
Instead of calling sync methods directly, send a sync request message to the newly connected peer:
```rust
// Send sync request to newly connected peer
let yara_sync_msg = MeshMessage::YaraRuleSyncRequest {
    current_version: current_yara_version,
    // ...
};

let threat_sync_msg = MeshMessage::ThreatSyncRequest {
    // ...
};

self.send_message_to_peer(peer_node_id, yara_sync_msg).await;
self.send_message_to_peer(peer_node_id, threat_sync_msg).await;
```

**Consideration**: This adds latency to the connection handshake. Consider making it optional via config:
```rust
pub struct YaraRulesMeshConfig {
    // ... existing fields ...
    #[serde(default = "default_sync_on_connect")]
    pub sync_on_connect: bool,  // NEW - default true
}
```

**Verification**:
```bash
# Add test: Node connects to peer, verify sync_from_dht called
# Add test: Verify sync happens before normal interval
cargo test --lib yara_rules
cargo test --lib threat_intel
```

---

### 2.2: Emergency Bypass for Edge Submissions

**File**: `src/mesh/yara_rules.rs:1141-1208`

**Issue**: Edge nodes must wait for global admin approval even during active incidents. No emergency bypass exists.

**Current Flow**:
```
Edge Node → submit_rule_for_approval() → Global Admin approves → broadcast_approved_rules()
                                           ↑
                                      Minutes to hours delay
```

**Current Config** (`config.rs:124-143`):
```rust
pub struct YaraRulesMeshConfig {
    pub allow_edge_submissions: bool,  // Default: false
    pub require_global_approval: bool, // Default: true
    // ...
}
```

**Implementation Options**:

**Option A - Pre-approved Categories** (Recommended):
Allow global nodes to pre-approve rule categories that edge nodes can self-publish:
```rust
pub struct YaraRulesMeshConfig {
    // ... existing fields ...
    #[serde(default)]
    pub emergency_allow_categories: Vec<String>,  // e.g., ["webshell", "ransomware"]
}

// In submit_rule_for_approval():
if let Some(category) = self.detect_rule_category(&rules) {
    if config.emergency_allow_categories.contains(&category) {
        // Skip approval, apply and broadcast immediately
        let version = format!("emergency-{}-{}", category, timestamp);
        return self.apply_and_broadcast_emergency(rules, version, category);
    }
}
```

**Option B - Time-Bounded Emergency Mode**:
When mesh is in "emergency mode" (triggered by global node), bypass approval:
```rust
pub struct YaraRulesMeshConfig {
    // ... existing fields ...
    #[serde(default)]
    pub emergency_bypass_until: Option<u64>,  // Unix timestamp
}

// In submit_rule_for_approval():
if let Some(until) = config.emergency_bypass_until {
    if current_timestamp() < until {
        // Bypass approval
        return self.apply_and_broadcast_emergency(rules, ...);
    }
}
```

**Option C - Direct Global Invocation**:
Allow edge nodes to call a global node directly for emergency approval via fast-path:
```rust
// Edge calls emergency_approve endpoint on global
POST /mesh/emergency/approve
{
    "rules": "...",
    "emergency": true
}

// Global responds within seconds with signed approval
```

**Implementation (Option A)**:
```rust
// Add to YaraRulesMeshConfig
pub emergency_allow_categories: Vec<String>,  // Default: empty

// Add method to detect rule category
fn detect_rule_category(&self, rules: &str) -> Option<String> {
    if rules.contains("webshell") || rules.contains("php") {
        Some("webshell".to_string())
    } else if rules.contains("macro") || rules.contains("autoopen") {
        Some("macro".to_string())
    }
    // ... etc
    None
}

// Modify submit_rule_for_approval
pub fn submit_rule_for_approval(&self, rules: String, description: String) -> Result<String, YaraRulesError> {
    // ... existing validation ...

    // Check for emergency bypass
    if !self.config.emergency_allow_categories.is_empty() {
        if let Some(category) = self.detect_rule_category(&rules) {
            if self.config.emergency_allow_categories.contains(&category) {
                tracing::warn!("Emergency rule category '{}' - bypassing approval", category);
                let version = format!("emergency-{}-{}", category, crate::mesh::safe_unix_timestamp());
                let source = YaraRuleSource::MeshEmergency(category);
                return self.apply_rules(rules, version, source);
            }
        }
    }

    // ... rest of existing logic ...
}
```

**Verification**:
```bash
# Add test: Edge submits emergency category rule, verify immediate apply
# Add test: Non-emergency category still requires approval
cargo test --lib yara_rules
```

---

## Phase 3: P2 Medium Priority - Security and Configuration Fixes

**Target**: Complete within 2 weeks
**Risk**: Low

### 3.1: Fix YARA Trusted Signer Global Bypass

**Files**:
- `src/mesh/yara_rules.rs:942-954` (DHT sync trusted_signer check)
- `src/mesh/yara_rules.rs:1761-1812` (Mesh message trusted_signer check)

**Issue**: YARA rules enforce `trusted_signers` even for global nodes, unlike threat intel which bypasses for global.

**Current DHT sync code** (`yara_rules.rs:942-954`):
```rust
if !self.config.trusted_signers.is_empty()
    && !self.config.trusted_signers.contains(&manifest_signer_pk.to_string())
{
    tracing::warn!(
        "YARA DHT sync: manifest signer pk {} is not in trusted signers list",
        manifest_signer_pk
    );
    continue;  // Rejects even if node is global!
}
```

**Should be** (like threat_intel):
```rust
if self.is_global() {
    // Global nodes bypass trusted_signer for YARA
    continue;
}

if !self.config.trusted_signers.is_empty()
    && !self.config.trusted_signers.contains(&manifest_signer_pk.to_string())
{
    // ... existing warning ...
    continue;
}
```

**Current mesh message handler** (`yara_rules.rs:1761-1812`):
```rust
if !signature.is_empty() && !signer_public_key.is_empty() {
    if let Some(ref signer) = self.signer {
        let sign_content = format!("{}:{}", version, rules);
        let pk_bytes = URL_SAFE_NO_PAD.decode(signer_public_key).unwrap_or_default();
        if !signer.verify(sign_content.as_bytes(), signature, &pk_bytes) {
            // ... reject ...
        }
        // NO trusted_signer check here at all!
    }
}
```

**Missing**: No trusted_signer check at all in mesh message path for non-global nodes.

**Implementation**:

**Fix 1 - DHT sync** (`yara_rules.rs:942-954`):
```rust
// Add global bypass at start of check
if self.is_global() {
    tracing::debug!("YARA DHT sync: global node bypasses trusted_signer check");
    // Continue processing without trusted_signer restriction
} else if !self.config.trusted_signers.is_empty()
    && !self.config.trusted_signers.contains(&manifest_signer_pk.to_string())
{
    tracing::warn!(
        "YARA DHT sync: manifest signer pk {} is not in trusted signers list for record from {}",
        manifest_signer_pk,
        manifest_node_id
    );
    continue;
}
```

**Fix 2 - Mesh message handler** (`yara_rules.rs` around line 1761):
```rust
// Add trusted_signer check after signature verification
if !self.node_role.is_global() && !self.config.trusted_signers.is_empty() {
    // Check if signer is in trusted_signers or is a global node
    let is_trusted = self.config.trusted_signers.contains(signer_public_key)
        || self.is_global_node(signer_public_key);

    if !is_trusted {
        tracing::warn!(
            "YaraRuleAnnounce rejected: signer {} not in trusted_signers list",
            signer_public_key
        );
        return Some(MeshMessage::YaraRuleAcknowledgement {
            accepted: false,
            reason: "Signer not in trusted_signers list".to_string(),
            request_id: version.to_string(),
            timestamp: crate::mesh::safe_unix_timestamp(),
        });
    }
}
```

**Verification**:
```bash
# Add test: Global node sends YARA rules, verified even if not in trusted_signers
# Add test: Non-global with trusted_signers populated - verify check works
cargo test --lib yara_rules
```

---

### 3.2: Add TTL > Re-announce Interval Validation

**Files**:
- `src/mesh/yara_rules.rs` (YaraRulesMeshConfig)
- `src/mesh/threat_intel.rs` (ThreatIntelligenceConfig)

**Issue**: No guard prevents `re_announce_interval_secs > TTL`. If misconfigured, records expire before re-announce fires.

**Current checks**:
```rust
// yara_rules.rs - only checks > 0
if re_announce_interval_secs > 0 && is_global {
    // spawn re-announce task
}

// threat_intel.rs - only checks > 0
if re_announce_interval_secs > 0 {
    // spawn re-announce task
}
```

**Implementation**:

**Option A - Build-time validation** (in `new()` or `validate()`):
```rust
impl YaraRulesMeshConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        // YARA TTL is hardcoded at 86400s
        const YARA_TTL_SECS: u64 = 86400;

        if self.re_announce_interval_secs > YARA_TTL_SECS / 2 {
            return Err(ConfigError::InvalidValue(format!(
                "re_announce_interval_secs ({}) must be less than TTL/2 ({})",
                self.re_announce_interval_secs,
                YARA_TTL_SECS / 2
            )));
        }
        Ok(())
    }
}
```

**Option B - Runtime warning**:
```rust
const YARA_TTL_SECS: u64 = 86400;

if re_announce_interval_secs > YARA_TTL_SECS {
    tracing::warn!(
        "YARA re_announce_interval_secs ({}) exceeds TTL ({}). Records may expire before re-announce.",
        re_announce_interval_secs,
        YARA_TTL_SECS
    );
}
```

**For threat intel** (TTL varies by severity):
```rust
// Check against TTL for each severity level (from threat_intel.rs:606-612)
const fn default_min_ttl_seconds() -> u64 { 60 }

// For each severity level:
// Critical: 7200s, High: 3600s, Medium: 1800s, Low: 900s, Unspecified: 300s

// Validate re_announce_interval against minimum TTL
if self.config.re_announce_interval_secs > default_min_ttl_seconds() * 2 {
    tracing::warn!(
        "re_announce_interval_secs ({}) should be < min_ttl_seconds * 2 ({}) for proper refresh",
        self.config.re_announce_interval_secs,
        default_min_ttl_seconds() * 2
    );
}
```

**Recommendation**: Option A (build-time validation) is safer.

**Verification**:
```bash
# Add test: Create config with re_announce > TTL, verify error
# Add test: Valid config passes
cargo test --lib yara_rules
```

---

### 3.3: Make YARA TTL Configurable

**File**: `src/mesh/yara_rules.rs:555,597,642`

**Issue**: YARA TTL is hardcoded at 86400s (24 hours) and not configurable.

**Current**:
```rust
record_store.store_and_announce(manifest_key_str.to_string(), bytes, 86400)  // Hardcoded
record_store.store_and_announce(chunk_key, bytes, 86400)  // Hardcoded
```

**Implementation**:
```rust
// In YaraRulesMeshConfig
pub struct YaraRulesMeshConfig {
    // ... existing fields ...
    #[serde(default = "default_yara_ttl_secs")]
    pub ttl_secs: u64,  // NEW: default 86400
}

const fn default_yara_ttl_secs() -> u64 { 86400 }

// In publish_rules_to_dht():
let ttl = self.config.ttl_secs;
record_store.store_and_announce(manifest_key_str.to_string(), bytes, ttl)
```

**Verification**:
```bash
# Add test: Custom TTL value is used in DHT store
cargo test --lib yara_rules
```

---

## Phase 4: P3 Low Priority - Future Enhancements

**Target**: Deferred

### 4.1: Acknowledgement Tracking for Threat Intel

**Issue**: YARA rules have `BroadcastAckTracker`, threat intel has no ACK mechanism.

**Status**: Deferred - requires more design work

---

### 4.2: Incremental Delta Sync

**Issue**: Full sync on each interval even when only small changes.

**Status**: Deferred - DHT anti-entropy handles this partially

---

## Implementation Order Recommendation

| Phase | Item | Priority | Complexity | Est. Time |
|-------|------|----------|------------|-----------|
| 1.1 | Severity-aware threat broadcast | P0 | Low | ~2 hrs |
| 1.2 | Broadcast metrics | P0 | Low | ~1 hr |
| 2.1 | Sync-on-join for YARA/threat | P1 | Medium | ~4 hrs |
| 2.2 | Emergency bypass for edge | P1 | Medium | ~4 hrs |
| 3.1 | YARA trusted_signer fix | P2 | Low | ~2 hrs |
| 3.2 | TTL > re_announce validation | P2 | Low | ~2 hrs |
| 3.3 | YARA TTL configurable | P3 | Low | ~1 hr |

---

## File Changes Summary

| File | Changes |
|------|---------|
| `src/mesh/threat_intel.rs` | 1.1: Severity-aware broadcast, 1.2: Metrics |
| `src/mesh/yara_rules.rs` | 2.1: Sync-on-join, 2.2: Emergency bypass, 3.1: Trusted signer fix, 3.3: Configurable TTL |
| `src/mesh/transport_connection.rs` | 2.1: Trigger sync on peer connect |
| `src/mesh/config.rs` | 2.1: sync_on_connect config, 2.2: emergency_allow_categories, 3.3: ttl_secs |
| `src/metrics/mod.rs` | 1.2: Broadcast coverage metrics |

---

## Testing Strategy

### Unit Tests
- Severity-aware broadcast selection
- YARA trusted_signer global bypass
- Emergency bypass category detection
- TTL/re-announce validation

### Integration Tests
```bash
# Run YARA tests
cargo test --lib yara_rules

# Run threat intel tests
cargo test --lib threat_intel

# Run integration tests
cargo test --test integration_test
```

---

## Verification Commands

```bash
# Verify tests compile
cargo test --lib --no-run

# Run targeted tests
cargo test --lib threat_intel
cargo test --lib yara_rules

# Run integration tests
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```

---

## References

- YARA rules implementation: `src/mesh/yara_rules.rs`
- Threat intel implementation: `src/mesh/threat_intel.rs`
- File upload security: `src/upload/`
- Mesh DHT architecture: `plans/plan11.md`
- Main plan: `plans/plan.md`

---

## Appendix A: Key Code Locations

| Item | Search Pattern | File |
|------|---------------|------|
| 1.1 | `broadcast_pending_threats` | threat_intel.rs:1507 |
| 1.1 | `broadcast_to_random_peers` | transport.rs:2862 |
| 1.1 | `broadcast_to_all_peers` | transport.rs:2921 |
| 2.1 | `dht_on_peer_connected` | transport_connection.rs:212 |
| 2.2 | `submit_rule_for_approval` | yara_rules.rs:1141 |
| 3.1 | `trusted_signer` check in DHT sync | yara_rules.rs:942 |
| 3.1 | `handle_incoming_rules` | yara_rules.rs:1745 |

---

## Appendix B: Comparison of YARA vs Threat Intel Distribution

| Aspect | YARA Rules | Threat Intel |
|--------|------------|--------------|
| Broadcast method | `broadcast_to_all_peers()` (deterministic) | `broadcast_to_random_peers()` (probabilistic) |
| Severity differentiation | N/A (always full) | **BUG**: Same for all severities |
| DHT TTL | 86400s (hardcoded) | 300-7200s (severity-based) |
| Re-announce interval | 300s default | 300s default |
| Global trusted_signer bypass | **BUG**: No bypass | ✅ Correct |
| Mesh message trusted_signer check | **BUG**: Missing | ✅ Correct |
| Edge submission | ✅ Working | Via global only |

---

*Plan created: 2026-04-27*
*Review status: PENDING*