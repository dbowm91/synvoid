# Plan 16: Honeypot & Threat Intelligence Architecture Improvements

**Status**: Planning
**Created**: 2026-04-27
**Last Updated**: 2026-04-27
**Priority**: High (Bug fixes), Medium (Enhancements)
**Estimated Duration**: 2-3 weeks (phased)

---

## Executive Summary

A code review of the honeypot and threat intelligence sharing architecture revealed several issues:

1. **CRITICAL BUG**: Duplicate detection key mismatch causing incoming mesh threats to be stored with different key format than local threats, breaking duplicate detection
2. **Asymmetry**: URL honeypot and port honeypot have different mesh sharing guarantees
3. **Multi-tenant issue**: DHT keys for threat indicators don't include `site_scope`, causing potential collisions in multi-tenant deployments
4. **Working as intended**: DHT sync signature requirement is correct security design

This plan addresses the fixes and improvements needed.

---

## Current Architecture Analysis

### What's Working

| Component | Location | Status |
|-----------|----------|--------|
| Port honeypot runner | `src/honeypot_port/runner.rs` | ✅ Functional |
| ThreatIntelligenceManager | `src/mesh/threat_intel.rs` | ✅ Core logic sound |
| DHT key format | `src/mesh/dht/keys.rs` | ✅ Consistent |
| Signature verification | `src/mesh/threat_intel.rs:792-814` | ✅ Security correct |
| Standalone mode | `src/worker/unified_server.rs:541-579` | ✅ Works correctly |
| Trusted signer enforcement | `src/mesh/threat_intel.rs:1607-1621` | ✅ Security correct |

### Issues Identified

| Issue | Severity | Location |
|-------|----------|----------|
| Duplicate detection key mismatch | HIGH | `src/mesh/threat_intel.rs:831` |
| URL vs Port honeypot asymmetry | MEDIUM | `src/mesh/threat_intel.rs`, `runner.rs` |
| Site scope missing from DHT key | MEDIUM | `src/mesh/dht/keys.rs:178-180` |
| Port rotation predictability | LOW | `src/honeypot_port/runner.rs:248-252` |

---

## Issue 1: Duplicate Detection Key Mismatch (CRITICAL BUG)

**File**: `src/mesh/threat_intel.rs:831`

### Problem

The `handle_incoming_threat` function constructs the wrong key at line 831 for duplicate detection and storage:

```rust
// Line 831 - WRONG: constructs key with just the IP (no ThreatType)
let key = indicator.indicator_value.clone();

// Lines 841-848 - Lookup uses wrong key, then checks threat_type
if let Some(existing) = self.indicators.read().get(&key) {
    if existing.indicator.indicator_value == indicator.indicator_value
        && existing.indicator.threat_type == indicator.threat_type
```

The key is later used at **line 1004** for storage:
```rust
// Line 1004 - Stores using the wrong key format
indicators.insert(
    key,  // "1.2.3.4" instead of "threat_indicator:1.2.3.4:IpBlock"
    ...
);
```

But `announce_honeypot_indicator` (line 497) stores with:
```rust
let key = make_indicator_key(&ip.to_string(), threat_type);  // "threat_indicator:1.2.3.4:IpBlock"
```

### Impact

1. **Incoming mesh threats** are stored at key `"1.2.3.4"` (raw IP format)
2. **Local threats** are stored at key `"threat_indicator:1.2.3.4:IpBlock"` (full format)
3. **Duplicate detection never works** for incoming threats because lookup uses wrong key
4. **Two entries can exist** for same IP: one local, one from mesh

### Scenario Analysis

The bug causes two related problems:

**Problem 1: Incoming threats stored at wrong key**

When `handle_incoming_threat` processes an incoming indicator:
1. Creates key as just IP: `"1.2.3.4"`
2. Stores at that key: `indicators.insert("1.2.3.4", ...)`
3. But `announce_honeypot_indicator` stores at: `"threat_indicator:1.2.3.4:IpBlock"`

**Result**: Local and mesh entries never use the same key format.

**Problem 2: Duplicate detection fails for true duplicates**

If an identical indicator arrives via mesh:
1. First request: `handle_incoming_threat(IpBlock for "1.2.3.4")` → stores at `"1.2.3.4"`
2. Second identical request: lookup at `"1.2.3.4"` → **FOUND**
3. Second check compares `threat_type` → `IpBlock == IpBlock` → **TRUE**
4. Returns "duplicate skipped" - this actually works!

But if local announcement happened first:
1. Local: `announce_honeypot_indicator()` → stores at `"threat_indicator:1.2.3.4:IpBlock"`
2. Mesh: `handle_incoming_threat()` → lookup at `"1.2.3.4"` → **NOT FOUND**
3. Two entries exist: `"threat_indicator:1.2.3.4:IpBlock"` AND `"1.2.3.4"`

| Scenario | Expected | Actual |
|----------|----------|--------|
| Same IP+Type from mesh twice | Second skipped as duplicate | ✅ Works (both use "1.2.3.4") |
| Local then mesh same IP/Type | Should recognize duplicate | ❌ NOT detected (different keys) |
| Different ThreatType same IP | Both stored | ✅ Works correctly |
| Mesh then local same IP/Type | Should merge/recognize | ❌ NOT detected (different keys) |

### Solution

Change line 831 to use the proper key format (same as `announce_honeypot_indicator`):

```rust
// Before (line 831):
let key = indicator.indicator_value.clone();

// After:
let key = make_indicator_key(&indicator.indicator_value, indicator.threat_type);
```

**Note**: Line 1004 that uses this key for storage will also use the correct format after this fix, ensuring consistency.

### Files to Modify

| File | Line(s) | Change |
|------|---------|--------|
| `src/mesh/threat_intel.rs` | 831 | Use `make_indicator_key()` instead of raw IP |

### Verification

```rust
// Test: Same IP+ThreatType from mesh should be detected as duplicate
#[test]
fn test_incoming_duplicate_key_format() {
    let threat_intel = ThreatIntelligenceManager::new_for_testing();

    // Simulate incoming threat from mesh (handle_incoming_threat)
    let indicator = create_test_indicator("1.2.3.4", ThreatType::IpBlock);
    threat_intel.handle_incoming_threat(indicator.clone(), "node1", MeshNodeRole::GLOBAL, None);

    // Second identical indicator should be detected as duplicate
    let result = threat_intel.handle_incoming_threat(indicator, "node1", MeshNodeRole::GLOBAL, None);
    assert!(result); // Returns true = skipped as duplicate
}
```

---

## Issue 2: URL vs Port Honeypot Mesh Sharing Asymmetry (MEDIUM)

### Problem

| Aspect | Port Honeypot | URL Honeypot (WAF) |
|--------|-------------|-------------------|
| **Mesh publishing task** | Dedicated `start_mesh_threat_publishing()` | Generic `broadcast_pending_threats()` |
| **Interval** | 30 seconds | 60 seconds |
| **Threshold** | None (publishes all) | Requires 3+ pending |
| **Data durability** | SQLite cursor persisted | In-memory only |

### Root Cause

Port honeypot has a dedicated background task (`runner.rs:140-246`) that:
1. Runs every 30 seconds
2. Reads from persistent SQLite storage
3. Calls `announce_honeypot_indicator()` for each unique IP
4. Tracks cursor to avoid re-announcing

URL honeypot relies on the generic `broadcast_pending_threats()` task which:
1. Runs every 60 seconds
2. Only broadcasts if `pending_count >= 3`
3. Drains ALL pending indicators into one message
4. Has no persistence (in-memory queue only)

### Implications

1. **URL honeypot threats may be delayed** - if < 3 hits occur in 60 seconds, they won't be broadcast
2. **No durability for URL honeypot** - pending queue lost on restart
3. **Different reliability guarantees** for same system

### Solution Options

**Option A: Add dedicated URL honeypot mesh publishing (Recommended)**

Create a dedicated publishing path for URL honeypot similar to port honeypot:

```rust
// In WafCore or via global threat_intel
pub fn start_url_honeypot_mesh_publishing(
    threat_intel: Arc<ThreatIntelligenceManager>,
    publish_interval_secs: u64,  // Default: 30 seconds
) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(publish_interval_secs));
        loop {
            interval.tick().await;

            // Get URL honeypot probe tracker data
            if let Some(tracker) = get_probe_tracker() {
                let events = tracker.get_recent_events();
                for event in events {
                    threat_intel.announce_honeypot_indicator(
                        event.ip,
                        ThreatType::SuspiciousActivity,
                        ThreatSeverity::High,
                        format!("URL honeypot probe: {}", event.path),
                        Some(3600),
                        &event.scope,
                    );
                }
            }
        }
    });
}
```

**Option B: Lower threshold and ensure timely broadcast**

Modify `broadcast_pending_threats()`:
1. Reduce threshold from 3 to 1
2. Ensure 60-second maximum delay even with 0 pending

```rust
// In src/mesh/threat_intel.rs:broadcast_pending_threats
pub async fn broadcast_pending_threats(&self) {
    // ... existing logic ...

    // Remove the threshold check entirely - broadcast whatever we have
    if pending_count == 0 {
        return;  // Only skip if nothing to send
    }

    // OR keep threshold but ensure we broadcast within max_delay
}
```

**Option C: Persist URL honeypot indicators**

Add persistence for URL honeypot probe events similar to port honeypot SQLite storage.

### Files to Modify

| File | Change |
|------|--------|
| `src/waf/mod.rs` | Add dedicated mesh publishing for URL honeypot OR wire probe tracker |
| `src/mesh/threat_intel.rs` | Option B: Lower threshold |

### Recommendation

Implement **Option A** - add dedicated URL honeypot mesh publishing. This gives:
- Consistent 30-second interval for both honeypot types
- No threshold requirements
- Better observability and control

---

## Issue 3: Site Scope Missing from DHT Key (MEDIUM - Multi-tenant)

**File**: `src/mesh/dht/keys.rs:178-180`

### Problem

Current DHT key format: `threat_indicator:<ip>:<ThreatType>`

Missing `site_scope` in key means **multi-tenant deployments can have key collisions**:

| Tenant | IP | ThreatType | DHT Key | Value site_scope |
|--------|-----|------------|---------|------------------|
| site_a | 192.168.1.1 | IpBlock | `threat_indicator:192.168.1.1:IpBlock` | site_a |
| site_b | 192.168.1.1 | IpBlock | `threat_indicator:192.168.1.1:IpBlock` | site_b |

**Second write overwrites first** - tenant A's indicator is lost.

### Note: BlockStore Correctly Handles site_scope

```rust
// src/block_store.rs:61-62
pub fn key(site_scope: &str, ip: &IpAddr) -> String {
    format!("block:{}:{}", site_scope, ip)  // ✅ Correctly scoped
}
```

### Existing Patterns for Site-Scoped Keys

The codebase already has site-scoped DHT keys:

| Key Type | Format |
|----------|--------|
| `UpstreamImageProtection` | `upstream_image_protection:<site_id>` |
| `SiteImagePoisonConfig` | `site_image_poison_config:<site_id>` |
| `TransformedContent` | `transformed:<site_id>:<content_hash>:<transform_flags>` |
| `PoisonedImage` | `poisoned_image:<site_id>:<original_hash>` |

### Solution

Change `DhtKey::ThreatIndicator` from 2-field to 3-field tuple:
```rust
// Current
ThreatIndicator(String, String),  // indicator_id, threat_type

// New
ThreatIndicator(String, String, String),  // site_scope, indicator_id, threat_type
```

Update key format to: `threat_indicator:<site_scope>:<ip>:<ThreatType>`

### Migration Strategy

1. Add version field to DHT value: `"key_version": 2`
2. On read, detect old format vs new format
3. Rewrite old entries to new format on next write
4. TTL ensures old entries expire naturally

### Files to Modify

| File | Changes |
|------|---------|
| `src/mesh/dht/keys.rs` | Add site_scope to ThreatIndicator variant, update `as_str()`/`from_str()` |
| `src/mesh/threat_intel.rs` | Update `make_indicator_key()` to include site_scope |
| `src/mesh/protocol.rs` | Add site_scope to ThreatIndicator if not present |

### Complexity

**HIGH** - This is an API change that affects:
- DHT key serialization/deserialization
- All code constructing ThreatIndicator keys
- Existing DHT data (needs migration)

**Recommendation**: Plan for next release cycle, not immediate fix.

---

## Issue 4: DHT Sync Signature Requirement (WORKING AS INTENDED)

### Finding

This is **correct security behavior**, not a bug.

| Behavior | Reason |
|----------|--------|
| Unsigned DHT records rejected | Prevents DHT pollution attacks |
| `local_origin: true` protects local data | Local indicators never overwritten |
| Nodes without signers cannot publish | Cannot prove identity to others |

### Conclusion

**No change needed.** The security design is sound.

---

## Issue 5: Port Rotation Predictability (LOW)

**File**: `src/honeypot_port/runner.rs:248-252`

### Problem

Simple random selection without history:
```rust
fn select_random_port(&self) -> u16 {
    let mut rng = rand::rng();
    let range = self.config.max_port - self.config.min_port;
    self.config.min_port + rng.random_range(0..=range)
}
```

No history tracking means **same port could be immediately reselected**.

### Note: PortManager Has Better Design

The `PortManager` in `rotation.rs:190-216` uses duplicate-free selection:
```rust
let mut ports: Vec<u16> = (min_port..=max_port).collect();
let port = ports.remove(idx);  // Remove to prevent duplicates
```

But `PortManager` appears to be a **separate system** from `PortHoneypotRunner`.

### Risk Assessment

| Factor | Assessment |
|--------|------------|
| Honeypot purpose | Attracts attacks - pattern learning doesn't expose protected data |
| RNG quality | rand 0.9 uses OsRng (CSPRNG) |
| Actual risk | Low for standard honeypot, Medium for active defense use |

### Solution (Optional Improvement)

Add history tracking to exclude last N ports:

```rust
struct PortRotationState {
    history: VecDeque<u16>,
    history_size: usize,  // Configurable, default: 3
}

impl PortHoneypotRunner {
    fn select_random_port_excluding(&self, state: &mut PortRotationState) -> u16 {
        let range = self.config.max_port - self.config.min_port;

        // Try to find a port not in history
        for _ in 0..100 {  // Max attempts
            let port = self.config.min_port + rand::rng().random_range(0..=range);
            if !state.history.contains(&port) {
                state.history.push_back(port);
                if state.history.len() > state.history_size {
                    state.history.pop_front();
                }
                return port;
            }
        }

        // Fallback: just return random
        self.config.min_port + rand::rng().random_range(0..=range)
    }
}
```

### Recommendation

**Accept for now** - not critical for honeypot functionality. Consider improvement in future release if honeypot is used for active defense.

---

## Implementation Phases

### Phase 1: Critical Bug Fix

**Duration**: 1 day
**Risk**: Low

#### 1.1 Fix Duplicate Detection Key Mismatch

**File**: `src/mesh/threat_intel.rs:831`

**Change**:
```rust
// Before (line 831):
let key = indicator.indicator_value.clone();

// After:
let key = make_indicator_key(&indicator.indicator_value, indicator.threat_type);
```

**Verification**:
```bash
cargo test --lib threat_intel
cargo test --lib handle_incoming_threat
```

---

### Phase 2: URL Honeypot Mesh Publishing Enhancement

**Duration**: 3-5 days
**Risk**: Low

#### 2.1 Add Dedicated URL Honeypot Publishing Task

Create a dedicated task for URL honeypot similar to port honeypot:

**New method in `src/waf/mod.rs`**:
```rust
pub fn start_url_honeypot_mesh_publishing(
    self: &Arc<Self>,
    threat_intel: Arc<ThreatIntelligenceManager>,
    publish_interval_secs: u64,
) {
    let waf = self.clone();
    let threat_intel = threat_intel.clone();

    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(publish_interval_secs));
        loop {
            interval.tick().await;

            // Get URL honeypot probe events
            if let Some(tracker) = waf.probe_tracker() {
                let events = tracker.get_and_clear_recent_events();
                for event in events {
                    threat_intel.announce_honeypot_indicator(
                        event.ip,
                        ThreatType::SuspiciousActivity,
                        ThreatSeverity::High,
                        format!("URL honeypot: {}", event.path),
                        Some(3600),
                        "global",
                    );
                }
            }
        }
    });
}
```

**Wire from unified_server.rs** (similar to port honeypot at line 1088-1097):
```rust
// Wire up URL honeypot threat publishing
if let Some(ref waf) = _waf {
    if let Some(ref threat_intel) = _threat_intel_manager {
        waf.start_url_honeypot_mesh_publishing(threat_intel.clone(), 30);
    }
}
```

#### 2.2 Add ProbeTracker Event Persistence (Optional)

For durability, add SQLite storage for probe events similar to port honeypot storage.

---

### Phase 3: Site Scope in DHT Key (Future Release)

**Duration**: 5-7 days
**Risk**: Medium

#### 3.1 Update DhtKey::ThreatIndicator

Change variant and all related methods.

#### 3.2 Update make_indicator_key()

Include site_scope in key construction.

#### 3.3 Add Migration Logic

Handle both v1 and v2 key formats during transition.

---

## File Changes Summary

| File | Phase | Changes |
|------|-------|---------|
| `src/mesh/threat_intel.rs` | 1 | Fix line 831 key construction |
| `src/waf/mod.rs` | 2 | Add `start_url_honeypot_mesh_publishing()` |
| `src/mesh/dht/keys.rs` | 3 | Add site_scope to ThreatIndicator variant |
| `src/worker/unified_server.rs` | 2 | Wire URL honeypot publishing task |

---

## Testing Strategy

### Unit Tests

```rust
// Test duplicate detection with incoming threats
#[test]
fn test_duplicate_key_format_consistency() {
    // 1. Local announcement
    // 2. Same indicator from mesh
    // 3. Verify duplicate detected
}

// Test URL honeypot publishing interval
#[test]
fn test_url_honeypot_publishes_within_interval() {
    // 1. Trigger honeypot event
    // 2. Wait for interval
    // 3. Verify indicator published
}
```

### Integration Tests

```bash
# Test threat intel in integration tests
cargo test --test integration_test threat

# Test DHT key format
cargo test --lib keys
```

---

## Verification Commands

```bash
# Verify test compilation
cargo test --lib --no-run

# Run threat intel tests
cargo test --lib threat_intel
cargo test --lib honeypot

# Run integration tests
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|-------------|
| Key mismatch fix breaks existing indicators | Low | Medium | `local_origin` protects local data; DHT entries expire via TTL |
| URL publishing creates duplicate announcements | Medium | Low | Use dedup tracking like port honeypot |
| DHT key change breaks existing records | High | High | Phase 3 for future release with proper migration |

---

## Rollback Plan

1. **Phase 1 fix**: Revert single line change - local data protected by `local_origin`
2. **Phase 2 enhancement**: Feature-gated, can disable without breaking core functionality
3. **Phase 3 change**: TTL-based expiration for old records; phased rollout

---

## Success Criteria

1. ✅ Duplicate detection works correctly for incoming mesh threats
2. ✅ URL honeypot threats published within 30 seconds (same as port honeypot)
3. ✅ No threshold required for URL honeypot broadcasting
4. ✅ All existing tests pass
5. ✅ New unit tests cover duplicate detection logic
6. ✅ Site scope DHT key change planned for future release

---

## Dependencies

### Internal
- `ThreatIntelligenceManager` for threat handling
- `ProbeTracker` for URL honeypot events
- `HoneypotStorage` for port honeypot (reference implementation)

### External
- `rand` with `OsRng` (already in use)
- `tokio` for async tasks (already in use)

---

## References

- Related plan: [Plan 14](./plan14.md) - Serverless Architecture (contains related mesh infrastructure)
- DHT key patterns: `src/mesh/dht/keys.rs`
- Threat intel: `src/mesh/threat_intel.rs`
- Honeypot port: `src/honeypot_port/runner.rs`
