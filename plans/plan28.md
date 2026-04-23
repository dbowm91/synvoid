# Plan 28: Honeypot & Threat Intelligence Sharing Improvements

## Context

MaluWAF's honeypot and threat intelligence sharing architecture has five confirmed bugs affecting distributed threat intel propagation. The issues were discovered during architecture review:

1. **Re-Announcement Bug** - Received indicators not re-announced to DHT
2. **Threat Type Parsing Bug** - Types 4-8 become `Unspecified` during sync
3. **Honeypot Announcement Inconsistency** - `block_ip_with_threat_intel` uses unsigned path
4. **No Fallback for Unsigned Records** - No config option for backward compatibility
5. **Blocking Call in Async Context** - Anti-pattern `block_in_place` + `block_on`

Additionally, documentation at `docs/THREAT_INTEL.md` contradicts implementation.

---

## Background: Architecture Overview

### Components

| Component | Location | Purpose |
|-----------|----------|---------|
| HTTP Honeypot | `src/challenge/honeypot.rs` | IP-bound trap paths in challenge pages |
| Port Honeypot | `src/honeypot_port/` | TCP listeners emulating vulnerable services |
| Threat Intelligence | `src/mesh/threat_intel.rs` | DHT-based indicator storage and mesh distribution |
| Block Store | `src/block_store.rs` | Local IP blocking |

### Data Flow

```
HTTP Honeypot:
Request → check_honeypot() → is_honeypot_hit() →
handle_probe_event() → block_ip_with_threat_intel() →
BlockStore.block_ip() + announce_local_block()

Port Honeypot:
TCP Connection → PortHoneypotListener → SQLite storage →
start_mesh_threat_publishing() (every 30s) →
extract_indicators() → announce_honeypot_indicator() →
DHT publish + local block
```

### Standalone Mode Support

Honeypots work WITHOUT mesh connectivity:
- `ThreatIntelligenceManager::new_for_standalone()` creates local-only manager
- Local blocking via `BlockStore` works regardless of mesh
- Indicators persist to JSON file (`threat_intel.json`)
- `publish_indicator_to_dht()` logs "Transport not available" gracefully

---

## Phase 1: Critical Bugs (Data Loss / Broken Distribution)

### 1.1: Re-Announcement Bug — CRITICAL

**Problem**: Indicators received from other nodes are NOT re-announced when their TTL is refreshed. The documentation at `docs/THREAT_INTEL.md:327` states "ALL non-expired indicators are re-announced (not just local_origin)" but code only re-announces `local_origin` indicators.

**Root Cause** (`src/mesh/threat_intel.rs:1787-1790`):
```rust
for (_key, entry) in indicators.iter() {
    if !entry.local_origin {  // BUG: Skips received indicators
        continue;
    }
    // ...
}
```

**Impact**: When a global node publishes an indicator and goes offline, the indicator expires from DHT after TTL. Other nodes have the indicator but cannot re-announce it because `local_origin=false`. This breaks distributed redundancy.

**Data Flow Analysis**:
- `local_origin=true` set by: `announce_local_block()`, `announce_honeypot_indicator()`, `announce_custom_indicator()`
- `local_origin=false` set by: `handle_threat_indicator_message()` (received from peers), `sync_from_dht()` (synced from DHT)

**Fix**: Remove the `local_origin` check at lines 1788-1790:

```rust
// REMOVE these lines (1788-1790):
if !entry.local_origin {
    continue;
}
```

This allows ALL non-expired indicators to be re-announced, matching documented behavior.

**File**: `src/mesh/threat_intel.rs`
**Lines**: 1787-1790
**Effort**: Low (1 line removal)

---

### 1.2: Threat Type Parsing Bug — HIGH

**Problem**: Two JSON parsing locations and one protobuf mapping location are missing cases for ThreatType variants 4-8. Additionally, ordinal 0 incorrectly maps to `IpBlock` instead of `Unspecified`.

**Affected Types**: `IpThrottle` (2), `SuspiciousActivity` (4), `DomainBlock` (6), `UrlBlock` (7), `CertBlock` (8)

**Impact**: Indicators synced from DHT with these types become `Unspecified` and are effectively lost (wrong key, wrong lookup behavior).

#### Location 1: `lookup_threat_indicator_in_dht()` (`threat_intel.rs:1019-1025`)

```rust
// CURRENT (BUGGY - ordinals are offset by 1 for non-zero values):
let threat_type = match value.get("threat_type")?.as_u64()? {
    0 => ThreatType::IpBlock,           // WRONG: 0 is Unspecified
    1 => ThreatType::RateLimitViolation, // WRONG: 1 is IpBlock
    2 => ThreatType::SuspiciousActivity, // WRONG: 2 is IpThrottle
    3 => ThreatType::AsnBlock,          // WRONG: 3 is RateLimitViolation
    _ => ThreatType::Unspecified,        // Types 4-8 lost (should be DomainBlock, UrlBlock, CertBlock)
};

// FIXED:
let threat_type = match value.get("threat_type")?.as_u64()? {
    0 => ThreatType::Unspecified,
    1 => ThreatType::IpBlock,
    2 => ThreatType::IpThrottle,
    3 => ThreatType::RateLimitViolation,
    4 => ThreatType::SuspiciousActivity,
    5 => ThreatType::AsnBlock,
    6 => ThreatType::DomainBlock,
    7 => ThreatType::UrlBlock,
    8 => ThreatType::CertBlock,
    _ => ThreatType::Unspecified,
};
```

#### Location 2: `parse_dht_record_value()` (`threat_intel.rs:1383-1389`)

Same fix as above.

#### Location 3: Protobuf mapping (`protocol_types.rs:535-541`)

The protobuf `ThreatType` enum (defined in `mesh.proto:576-581`) only has 4 values (0-3), but the Rust `ThreatType` has 9 values (0-8). The mapping has offset errors.

**Protobuf definition:**
```protobuf
enum ThreatType {
    THREAT_TYPE_UNSPECIFIED = 0;
    THREAT_TYPE_IP_BLOCK = 1;
    THREAT_TYPE_RATE_LIMIT_VIOLATION = 2;
    THREAT_TYPE_SUSPICIOUS_ACTIVITY = 3;
}
```

**Rust enum ordinals:**
```rust
pub enum ThreatType {
    Unspecified,        // 0
    IpBlock,           // 1
    IpThrottle,        // 2
    RateLimitViolation, // 3
    SuspiciousActivity,  // 4
    AsnBlock,          // 5
    DomainBlock,       // 6
    UrlBlock,          // 7
    CertBlock,         // 8
}
```

```rust
// CURRENT (BUGGY - ordinals don't match Rust ThreatType):
threat_type: match pb.threat_type {
    1 => ThreatType::IpBlock,
    2 => ThreatType::RateLimitViolation,  // WRONG: protobuf 2 is RATE_LIMIT, but maps to Rust ordinal 2 (IpThrottle)
    3 => ThreatType::SuspiciousActivity,  // WRONG: protobuf 3 is SUSPICIOUS, but maps to Rust ordinal 3 (RateLimitViolation)
    4 => ThreatType::AsnBlock,            // WRONG: protobuf 4 doesn't exist; Rust AsnBlock is ordinal 5
    _ => ThreatType::Unspecified,
},

// FIXED (correct ordinal mapping, but limited to protobuf's 0-3):
threat_type: match pb.threat_type {
    0 => ThreatType::Unspecified,
    1 => ThreatType::IpBlock,              // protobuf 1 = IP_BLOCK → Rust ordinal 1 = IpBlock ✓
    2 => ThreatType::RateLimitViolation,   // protobuf 2 = RATE_LIMIT → Rust ordinal 3 = RateLimitViolation ✓
    3 => ThreatType::SuspiciousActivity,   // protobuf 3 = SUSPICIOUS → Rust ordinal 4 = SuspiciousActivity ✓
    _ => ThreatType::Unspecified,          // Rust types 2,5,6,7,8 (IpThrottle,AsnBlock,DomainBlock,UrlBlock,CertBlock) can't be represented
},
```

**Note**: The Rust types `IpThrottle`, `AsnBlock`, `DomainBlock`, `UrlBlock`, and `CertBlock` cannot be represented in protobuf messages since protobuf only defines values 0-3. These types would need a protobuf enum extension to be fully supported.

**ThreatType Enum** (for reference, `src/mesh/protocol.rs:1301-1311`):
```rust
pub enum ThreatType {
    Unspecified,        // 0
    IpBlock,           // 1
    IpThrottle,        // 2
    RateLimitViolation, // 3
    SuspiciousActivity,  // 4
    AsnBlock,          // 5
    DomainBlock,       // 6
    UrlBlock,          // 7
    CertBlock,         // 8
}
```

**Files**: `src/mesh/threat_intel.rs`, `src/mesh/protocol_types.rs`
**Lines**: 1019-1025, 1383-1389, 535-541
**Effort**: Medium (fix 3 locations)

---

### 1.3: Honeypot Announcement Inconsistency — MEDIUM-HIGH

**Problem**: HTTP honeypot probe detections use `block_ip_with_threat_intel()` which calls `announce_local_block()`. This creates **unsigned** indicators that fail DHT sync silently.

**Call Sites of `block_ip_with_threat_intel`**:
| Location | Reason | Should Publish |
|----------|--------|----------------|
| `waf/mod.rs:605` | "probe_auto_ban" | Yes |
| `waf/mod.rs:642` | "honeypot" | Yes |
| `waf/mod.rs:673` | violation_reason | Yes |
| `waf/mod.rs:1119` | "ip_feed" | Yes |
| `http/server.rs:2457` | "malware_upload" | Yes |
| `tls/server.rs:905` | "malware_upload" | Yes |

**Key Difference**:

| Function | Type | Severity | Signature | DHT Publishing |
|----------|------|----------|-----------|---------------|
| `announce_local_block()` | `IpBlock` | `High` | **UNSIGNED** | Fails silently |
| `announce_honeypot_indicator()` | Configurable | Configurable | **SIGNED** | Works |

**Root Cause** (`src/mesh/threat_intel.rs:662-665`):
```rust
if self.signer.is_none() {
    tracing::warn!("Cannot publish threat indicator: no signer configured");
    return;  // Fails silently!
}
```

**Fix**: Change `block_ip_with_threat_intel()` to use `announce_honeypot_indicator()`:

**File**: `src/waf/mod.rs:546-564`
```rust
// CURRENT:
if let Some(ref threat_intel) = get_threat_intel() {
    threat_intel.announce_local_block(
        client_ip,
        reason.to_string(),
        duration,
        scope.to_string(),
    );
}

// FIXED:
if let Some(ref threat_intel) = get_threat_intel() {
    threat_intel.announce_honeypot_indicator(
        client_ip,
        ThreatType::IpBlock,
        ThreatSeverity::High,
        reason.to_string(),
        Some(duration),
        scope,
    );
}
```

**Impact**: Low - only affects mesh distribution. Local blocking remains identical.

**Effort**: Low-Medium

---

## Phase 2: Medium Priority (Resiliency / Code Quality)

### 2.1: No Fallback for Unsigned Records — MEDIUM

**Problem**: No `require_signature` config option exists for threat intel. All unsigned indicators are rejected during DHT sync with no fallback. YARA rules already have this pattern.

**Impact**: Legacy unsigned indicators cannot sync, and nodes without signers cannot distribute threat intel.

**Comparison with YARA** (`src/mesh/yara_rules.rs:1796-1813`):
```rust
} else if self.config.require_signature {
    tracing::warn!("YARA rule from {} has no signature but require_signature is enabled, rejecting", from_node);
    // reject
} else {
    tracing::debug!("YARA rules from {} have no signature, accepting without verification", from_node);
    // accept
}
```

**Fix**:

1. **Add config field** (`src/mesh/threat_intel.rs:30-56`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ThreatIntelligenceConfig {
    // ... existing fields ...
    #[serde(default = "default_require_signature")]
    pub require_signature: bool,
}

fn default_require_signature() -> bool {
    true  // Default to secure behavior
}
```

2. **Add to internal config** (`src/mesh/threat_intel.rs:113-127`):
```rust
pub struct ThreatIntelligenceConfigInternal {
    // ... existing fields ...
    pub require_signature: bool,
}
```

3. **Propagate in `to_internal()`** (`src/mesh/threat_intel.rs:88-110`):
```rust
pub fn to_internal(&self) -> ThreatIntelligenceConfigInternal {
    ThreatIntelligenceConfigInternal {
        // ... existing fields ...
        require_signature: self.require_signature,
    }
}
```

4. **Modify sync logic** (`src/mesh/threat_intel.rs:1333-1339`):
```rust
} else if self.config.require_signature {
    tracing::warn!(
        "Threat intel DHT sync: missing signature or signer pk for {}",
        key
    );
    continue;
} else {
    tracing::debug!(
        "Threat intel DHT sync: accepting unsigned indicator for {} (require_signature=false)",
        key
    );
    // Continue WITHOUT signature verification
}
```

**Documentation Update** at `docs/THREAT_INTEL.md`:
```toml
require_signature = true  # Reject unsigned indicators (default: true for security)
```

**Files**: `src/mesh/threat_intel.rs`, `src/mesh/config.rs`, `docs/THREAT_INTEL.md`
**Effort**: Medium

---

### 2.2: Blocking Call in Async Context — LOW-MEDIUM

**Problem**: Anti-pattern of `block_in_place(|| block_on(...))` at `src/mesh/threat_intel.rs:1321-1324` to call async `get_global_nodes()` from sync `sync_from_dht()`.

```rust
// CURRENT (ANTI-PATTERN):
if let Some(ref transport) = *self.transport.read() {
    let topology = transport.get_topology();
    let global_nodes = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(topology.get_global_nodes())
    });
```

**Impact**: Could cause thread starvation under extreme conditions; latent bug. Current severity is LOW because the operation is fast and runs in background.

**Fix**: Add synchronous getter method to `MeshTopology`:

1. **Add to `src/mesh/topology.rs`** (after line 621):
```rust
pub fn get_global_nodes_sync(&self) -> Vec<String> {
    let global = self.global_nodes.blocking_read();
    global.iter().cloned().collect()
}
```

2. **Update `src/mesh/threat_intel.rs`** (lines 1319-1324):
```rust
// AFTER:
if let Some(ref transport) = *self.transport.read() {
    let topology = transport.get_topology();
    let global_nodes = topology.get_global_nodes_sync();
    if !global_nodes.contains(&indicator.source_node_id) {
```

**Effort**: Low

---

## Phase 3: Documentation Fix

### 3.1: Documentation Discrepancy — LOW

**Problem**: `docs/THREAT_INTEL.md:327` claims "ALL non-expired indicators are re-announced" but code only re-announces `local_origin` indicators.

**Fix Options**:

**Option A (Recommended)**: Remove `local_origin` check in code (matches Phase 1.1 fix)
**Option B**: Update documentation to match code:
```diff
- **Scope**: ALL non-expired indicators are re-announced (not just local_origin)
+ **Scope**: Only locally-originated indicators are re-announced (not received from peers)
```

If Phase 1.1 is implemented, no documentation change needed (code already matches intent).

---

## Implementation Order

| Order | Item | Priority | Reason |
|-------|------|----------|--------|
| 1 | Phase 1.2: Threat Type Parsing | HIGH | Data loss - types 4-8 are lost |
| 2 | Phase 1.1: Re-Announcement | HIGH | Distributed redundancy broken |
| 3 | Phase 1.3: Honeypot Announcement | MEDIUM-HIGH | Mesh distribution fails silently |
| 4 | Phase 2.2: Blocking Call | LOW-MEDIUM | Code quality, latent bug |
| 5 | Phase 2.1: Unsigned Records | MEDIUM | Backward compatibility |
| 6 | Phase 3: Documentation | LOW | Only if keeping code behavior |

---

## File Change Summary

| File | Changes |
|------|---------|
| `src/mesh/threat_intel.rs` | Fix re-announcement (line 1788); Fix threat type parsing (lines 1019-1025, 1383-1389); Change block_ip path (lines 556-562); Add require_signature config (lines 30-56, 113-127, 88-110); Add require_signature check (lines 1333-1339) |
| `src/mesh/protocol_types.rs` | Fix protobuf mapping (lines 535-541) |
| `src/mesh/topology.rs` | Add `get_global_nodes_sync()` method (after line 621) |
| `src/waf/mod.rs` | Change `block_ip_with_threat_intel` to use `announce_honeypot_indicator` (lines 546-564) |
| `src/config/mod.rs` | Add `require_signature` field to `ThreatIntelligenceConfig` |
| `docs/THREAT_INTEL.md` | Add `require_signature` config option documentation |

---

## Testing Requirements

### Unit Tests

1. **`test_re_announce_local_indicators_with_received`**
   - Create local indicator (local_origin=true)
   - Create received indicator (local_origin=false)
   - Call `re_announce_local_indicators()`
   - Verify BOTH are re-announced (not just local_origin)

2. **`test_parse_dht_record_value_all_types`**
   - Create JSON with each ThreatType ordinal (0-8)
   - Parse via `parse_dht_record_value()`
   - Verify correct type returned for each

3. **`test_lookup_threat_indicator_in_dht_all_types`**
   - Store indicator with each ThreatType in mock DHT
   - Lookup via `lookup_threat_indicator_in_dht()`
   - Verify correct type returned for each

4. **`test_require_signature_config`**
   - Set `require_signature=false`
   - Sync unsigned indicator
   - Verify indicator is accepted
   - Set `require_signature=true`
   - Sync unsigned indicator
   - Verify indicator is rejected

5. **`test_block_ip_creates_signed_indicator`**
   - Call `block_ip_with_threat_intel()`
   - Verify indicator has non-empty signature

### Integration Tests

1. **`test_honeypot_indicator_propagates_via_dht`**
   - Start two nodes (global + edge)
   - Trigger HTTP honeypot detection on global
   - Verify edge receives and applies indicator

2. **`test_received_indicator_survives_origin_offline`**
   - Global publishes indicator
   - Global goes offline
   - Verify indicator is re-announced by edge before TTL expires

---

## Related Work

### YARA Rules Comparison

YARA rules (`src/mesh/yara_rules.rs`) handle similar concerns differently:
- No `local_origin` equivalent - all synced rules go through `apply` workflow
- Has `require_signature` config option
- Re-announces all rules (not just local)

This suggests the threat intel `local_origin` pattern may be overly restrictive and could be simplified.

### Standalone Mode Verification

All changes must maintain standalone mode functionality:
- `ThreatIntelligenceManager::new_for_standalone()` must still work
- Local blocking must remain functional
- JSON persistence must work without mesh

---

## Verification Steps

After implementation, verify:

1. **Compilation**: `cargo check --lib` passes
2. **Tests**: `cargo test --lib` passes
3. **Clippy**: `cargo clippy --lib -- -D warnings` passes
4. **Format**: `cargo fmt` produces no changes
5. **Standalone Mode**: Start WAF without mesh config, verify honeypots work

---

## Rollback Plan

If issues arise, each phase can be reverted independently:

| Phase | Revert Action |
|-------|---------------|
| 1.1 | Re-add `local_origin` check |
| 1.2 | Revert match statements to original |
| 1.3 | Revert to `announce_local_block` call |
| 2.1 | Remove `require_signature` field and check |
| 2.2 | Revert to `block_in_place` pattern |
