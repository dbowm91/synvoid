# MaluWAF Admin Panel Improvement Plan

**Status**: Planning Phase
**Last Updated**: 2026-04-27
**Review Phase**: Pending User Review

---

## Executive Summary

Based on a comprehensive deep-dive investigation of the admin panel and configuration system, this plan addresses:
- **Critical Security**: Sensitive field masking for rule feeds and YARA feeds
- **High Priority**: Admin UI completeness for DNS configuration
- **Medium Priority**: Runtime behavior fixes (honeypot hot-reload, overseer config bugs)
- **Medium Priority**: New endpoints for behavioral intelligence
- **Low Priority**: Dead code cleanup and process manager internals

**Key Finding**: The backend admin handlers are more complete than initially expected. Most configuration IS accessible via API. Primary issues are:
1. Admin UI only shows ~20% of available DNS fields
2. Sensitive fields (public_key, storage_dir) need masking
3. Some fields are dead code (overseer IPC timeouts never wired)
4. Runtime behavior issues (honeypot port changes don't hot-reload)
5. Missing dedicated endpoints (behavioral intel has no admin endpoint)

**Investigation Status**: All findings in this plan have been verified against actual code via grep and file reads. Line numbers and code snippets reflect actual implementation.

---

## Architecture Context

The admin panel follows the **overseer/master/worker** architecture:

```
Admin API (Port 8081)
    ↓
AdminState (central state management)
    ↓ (via IPC)
Master Process (ProcessManager, config management)
    ↓
Worker Processes (request handling, WAF, mesh)
```

Configuration flows:
1. **Read**: AdminState → config.main → serde_json → API response
2. **Write**: API request → validate → write config.main → persist_to_toml → broadcast_reload

---

## Phase 1: Security Fixes (Critical)

### 1.1 Rule Feed Sensitive Field Masking

**Issue**: `GET /config/rule-feed` returns full `public_key` (base64) and `storage_dir` (filesystem path).

**Risk**:
- `public_key`: Exposing full key helps attackers target specific signing keys
- `storage_dir`: Exposes internal filesystem structure

**Current Code**: `src/admin/handlers/config.rs:2195-2203`
```rust
pub async fn get_rule_feed_config(...) -> Result<Json<RuleFeedConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(RuleFeedConfigResponse {
        config: config.main.rule_feed.clone(),  // Full struct exposed!
    }))
}
```

**Recommended Response Structure**:
```rust
pub struct RuleFeedConfigReadOnly {
    pub enabled: bool,
    pub url: String,
    pub update_interval_hours: u32,
    pub auto_apply: bool,
    pub allow_downgrade: bool,
    pub public_key_prefix: Option<String>,      // First 4-8 chars of key
    pub public_key_configured: bool,            // True if key is set (not placeholder)
    pub storage_dir: Option<String>,            // REMOVE or mask to show only trailing path
    // NOTE: public_key field REMOVED - use prefix + configured flag
}
```

**Files to Modify**:
- `src/admin/handlers/config.rs` - Create `RuleFeedConfigReadOnly` response struct, modify `get_rule_feed_config`
- `src/admin/openapi.rs` - Add `RuleFeedConfigReadOnly` schema

**Implementation Notes**:
1. For `public_key_prefix`: Return first 4 chars + `...` if key exists (e.g., `"Ab3..."`)
2. For `public_key_configured`: Check if key is not empty AND not the placeholder (`DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER`)
3. For `storage_dir`: Either remove entirely OR return only last path component (e.g., `"/rules"` from `"/var/lib/maluwaf/rules"`)

**Verification**:
```bash
# Test GET returns masked values
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/config/rule-feed
# Should see "public_key_prefix" not "public_key"
# Should see "storage_dir" as just directory name or not present
```

---

### 1.2 YARA Rule Feed Sensitive Field Masking

**Issue**: `GET /config/yara-feed` returns full `signer_public_key`.

**Current Code**: `src/admin/handlers/config.rs:2253-2261`
```rust
pub async fn get_yara_feed_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<YaraFeedConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(YaraFeedConfigResponse {
        config: config.main.yara_feed.clone(),  // Full struct exposed!
    }))
}
```

Note: The config field is `yara_feed` (not `yara_rule_feed`) as defined in `src/config/main.rs:96`.

**Recommended Response Structure**:
```rust
pub struct YaraFeedConfigReadOnly {
    pub enabled: bool,
    pub url: String,
    pub update_interval_hours: u32,
    pub elevated_interval_hours: u32,
    pub auto_apply: bool,
    pub allow_downgrade: bool,
    pub signer_public_key_prefix: Option<String>,  // First 4-8 chars
    pub signer_public_key_configured: bool,        // True if key is set
    pub max_rules_size_kb: u32,
}
```

**Files to Modify**:
- `src/admin/handlers/config.rs` - Create `YaraFeedConfigReadOnly` response struct, modify `get_yara_feed_config`
- `src/admin/openapi.rs` - Add `YaraFeedConfigReadOnly` schema

---

### 1.3 Overseer Config Bug Fix: drain_check_interval_ms

**Issue**: `drain_check_interval_ms` is sourced from `upgrade.drain_check_interval_ms` instead of `overseer.drain_check_interval_ms`.

**Bug Location**: `src/startup/master.rs:156-160`
```rust
// CURRENT (WRONG) - uses upgrade config field
drain_check_interval_ms: main_config
    .upgrade
    .as_ref()
    .map(|u| u.drain_check_interval_ms)
    .unwrap_or(100),

// SHOULD BE - use overseer config field
drain_check_interval_ms: main_config.overseer.drain_check_interval_ms,
```

**Impact**: OverseerConfig has its own `drain_check_interval_ms` field (default 100) but the overseer process receives the value from UpgradeConfig's `drain_check_interval_ms` instead. This means if a user sets `overseer.drain_check_interval_ms = 50` in TOML, it would be ignored in favor of `upgrade.drain_check_interval_ms`.

**Note**: Both `UpgradeConfig` (`src/config/upgrade.rs:18`) and `OverseerConfig` (`src/config/process.rs:121`) have this field. The overseer's `DrainManager` at `src/overseer/process.rs:99` correctly uses the field passed from startup, but startup passes the wrong source.

**Files to Modify**:
- `src/startup/master.rs` - Fix config path

**Verification**:
```bash
# After fix, verify overseer config changes for drain_check_interval_ms take effect
```

---

## Phase 2: Admin UI Completeness (High)

### 2.1 DNS Admin UI Enhancement

**Issue**: Backend handlers exist and work, but Admin UI (`admin-ui/src/pages/dns.rs`) only shows ~20% of fields and has a field name bug.

**Field Name Bug**: UI uses `bind_addresses` but backend returns `bind_address`.

**Current UI Sections** (incomplete):
- Basic: `enabled`, `port`, `bind_addresses` (wrong name)
- Forwarding: `allow_recursive`, `forwarders`, `block_tld`
- Security: `dnssec_enabled`, `nxdomain_redirect`, `rpz_enabled`

**Missing UI Sections**:
1. **Mode & Network**: `mode` (Standalone/Mesh)
2. **Rate Limiting**: `ratelimit` sub-config (per_second, per_minute, mode)
3. **Response Rate Limiting (RRL)**: `rrl` sub-config
4. **DNS Firewall**: `firewall` sub-config
5. **Settings**: `settings` sub-config (cache, ECS filtering, padding, IXFR, qname privacy)
6. **Mesh DNS**: `mesh` sub-config
7. **Zones**: `zones` sub-config (zone definitions with records)
8. **Limits**: `limits` sub-config
9. **DNSSEC**: `dnssec` sub-config (algorithm, key paths, HSM, TSIG keys)
10. **Encrypted DNS**: `dot` (853), `doh` (443), `doq` (853)
11. **RPZ**: `rpz` sub-config (Response Policy Zones)
12. **DNS64**: `dns64` sub-config
13. **Prefetch**: `prefetch` sub-config
14. **Trust Anchors**: `trust_anchors` sub-config (RFC 5011)
15. **Anycast**: `anycast` sub-config
16. **Recursive**: `recursive` sub-config

**Admin UI Files to Modify**:
- `admin-ui/src/pages/dns.rs` - Fix field name, add missing sections

**Backend (No Changes Needed)**:
- `src/admin/handlers/config.rs:1656-1724` - Already correctly implemented
- `src/admin/openapi.rs` - Already correctly documented

**Implementation Approach**:
1. Fix `bind_addresses` → `bind_address`
2. Group fields into collapsible sections matching the config structure
3. Use nested form components for sub-configs (ratelimit, rrl, firewall, etc.)
4. Add conditional rendering for feature-gated sections (dnssec requires `dns` feature)

---

## Phase 3: Runtime Behavior Fixes (Medium)

### 3.1 Honeypot Port Hot-Reload Support

**Issue**: Updating `/honeypot/config` only writes to `main.toml`. The `PortHoneypotRunner` doesn't hot-reload - it continues with old config until worker restart.

**Current Pattern** (from `src/admin/handlers/honeypot.rs:84-96`):
```rust
// CURRENT - Just replaces config and persists
config.main.honeypot_port = req.config;
persist_with_snapshot(&state, "honeypot port config updated").await?;
```

**Note**: `PortHoneypotController` does not exist in the codebase. The `PortHoneypotRunner` is created directly in `UnifiedServer` (`src/worker/unified_server.rs:473-512`). A controller abstraction would need to be created.

**Components Needed**:
1. Create `PortHoneypotController` wrapper around `PortHoneypotRunner` with `update_config()` method
2. Register controller in `AdminState`
3. `HoneypotPortConfig::validate()` method (may already exist)
4. Follow ICMP handler pattern: validate → apply → persist on success

**Files to Modify/Create**:
- `src/honeypot_port/` - Create `controller.rs` with `PortHoneypotController`
- `src/worker/unified_server.rs` - Use controller instead of direct runner
- `src/admin/state.rs` - Add controller to AdminState
- `src/admin/handlers/honeypot.rs` - Follow ICMP validate → apply → persist pattern

**Reference Implementation**: ICMP handler at `src/admin/handlers/icmp.rs:177-230` demonstrates the validate → apply → persist pattern.

---

### 3.2 Process Manager: Document Internal Fields

**Issue**: `unified_server_workers` is returned in API but can't be changed dynamically.

**Recommendation**: Document these fields as internal-only:

| Field | Reason to Keep Internal |
|-------|------------------------|
| `unified_server_workers` | Doesn't improve throughput; requires restart |
| `worker_port_base` | Requires restart; changing breaks existing connections |

**Consider Exposing** (with documentation):
- `pre_spawn_workers` - Dynamic, legitimate tuning
- `warm_workers_target` - Dynamic, legitimate tuning
- `heartbeat_timeout_secs` - Dynamic, note about failure detection delay

**Files to Modify**:
- `src/admin/handlers/config.rs` - In `get_process_manager_config`, add comment or separate response excluding internal fields
- OR create `ProcessManagerConfigPublic` struct that only exposes legitimate tuning parameters

**Note**: This is lower priority - the fields are already accessible but may confuse users.

---

## Phase 4: New Endpoints (Medium)

### 4.1 Behavioral Intelligence Admin Endpoint

**Issue**: `BehavioralIntelligenceManager` exists (`src/mesh/behavioral_intel.rs:65`) with public methods but is not accessible via admin API.

**Manager Access Pattern**: The manager is currently accessed via `AttackDetector` (`src/waf/attack_detection/mod.rs:66`) not via `AdminState`. Direct access would require adding it to AdminState or creating a getter mechanism.

**Manager Methods Available**:
- `get_fingerprint_count()` - Number of stored fingerprints (line 454)
- `get_version()` - Manager version (line 458)
- `get_stats()` - Could provide fingerprint statistics
- `get_lsh_bucket_distribution()` - Internal LSH state (not currently exposed)

**Recommended Endpoints**:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/mesh/behavioral/stats` | GET | Get fingerprint statistics (count, version) |
| `/mesh/behavioral/config` | GET | Get behavioral intelligence config |

**New File**: `src/admin/handlers/behavioral_intel.rs`

**Response Structure**:
```rust
pub struct BehavioralStatsResponse {
    pub fingerprint_count: u64,
    pub version: String,
    // LSH parameters (hardcoded in manager, could expose)
    pub lsh_bucket_count: u32,        // 1024
    pub similarity_threshold: f32,    // 0.85
}

pub struct BehavioralConfigResponse {
    pub enabled: bool,
    pub min_samples_for_fingerprint: u64,
    pub fingerprint_ttl_secs: u64,
    pub high_severity_threshold: u32,
}
```

**Files to Modify/Create**:
- `src/admin/handlers/behavioral_intel.rs` - NEW file with handlers
- `src/admin/handlers/mod.rs` - Export new module
- `src/admin/state.rs` - Add manager reference to AdminState (or use shared config)
- `src/admin/mod.rs` - Wire up routes
- `src/admin/openapi.rs` - Document endpoints

**Implementation Note**: Since `BehavioralIntelligenceManager` lives in `AttackDetector` (worker-local), we may need to:
1. Add `behavioral_intel: Option<Arc<BehavioralIntelligenceManager>>` to `AdminState`
2. Wire it up during worker startup to propagate to admin state
3. OR use a message-passing approach via IPC to query worker-local manager

**Privacy Note**: Fingerprint listings should always use `fingerprint.anonymized()` - never expose raw fingerprints. The stats endpoint should only return aggregate counts, not individual fingerprint data.

---

### 4.2 Mesh DHT/Persistence Dedicated Endpoints (Optional)

**Current State**: All mesh config is accessed via `/config/mesh` (full config blob).

**Options**:

**Option A: Keep Current** - Current approach works if UI handles nested JSON properly.

**Option B: Add Dedicated Endpoints**:
- `GET/PUT /config/mesh/persistence` - MeshPersistenceConfig only
- `GET/PUT /config/mesh/dht` - MeshDhtConfig only

**Recommendation**: Keep current approach (Option A). The nested structure is manageable if Admin UI properly handles the JSON. Adding dedicated endpoints increases API surface area without significant benefit.

---

## Phase 5: Dead Code Cleanup (Low)

### 5.1 Overseer IPC Timeout Fields

**Finding**: `ipc_read_timeout_ms`, `ipc_write_timeout_ms`, `master_startup_timeout_secs` are stored but **never used** in code.

**Options**:

**Option A: Remove Fields** - Simplify OverseerConfig
**Option B: Wire Up** - Implement actual timeout behavior

**Recommendation**: Option B for `ipc_read_timeout_ms` and `ipc_write_timeout_ms` (useful for slow networks). Option A for `master_startup_timeout_secs` (the health check loop handles this reactively).

**Files to Investigate**:
- `src/config/process.rs` - OverseerConfig struct
- `src/overseer/process.rs` - reload_config() method
- `src/process/ipc.rs` - IPC stream handling

**Note**: This is low priority - these are currently harmless dead fields.

---

## Implementation Order

```
Phase 1: Security Fixes (Critical)
├── 1.1 Rule Feed sensitive field masking
├── 1.2 YARA Rule Feed sensitive field masking
└── 1.3 Overseer drain_check_interval_ms bug fix

Phase 2: Admin UI Completeness (High)
└── 2.1 DNS Admin UI enhancement (field fix + missing sections)

Phase 3: Runtime Behavior Fixes (Medium)
├── 3.1 Honeypot port hot-reload
└── 3.2 Document internal Process Manager fields

Phase 4: New Endpoints (Medium)
├── 4.1 Behavioral intelligence admin endpoint
└── 4.2 (Optional) Mesh DHT dedicated endpoints

Phase 5: Dead Code Cleanup (Low)
└── 5.1 Overseer IPC timeout fields (wire up or remove)
```

---

## Files Summary

| Phase | Action | Files Modified/Created |
|-------|--------|----------------------|
| 1.1 | Rule feed masking | `src/admin/handlers/config.rs`, `src/admin/openapi.rs` |
| 1.2 | YARA feed masking | `src/admin/handlers/config.rs`, `src/admin/openapi.rs` |
| 1.3 | Overseer bug fix | `src/startup/master.rs` |
| 2.1 | DNS UI fix | `admin-ui/src/pages/dns.rs` |
| 3.1 | Honeypot hot-reload | NEW: `src/honeypot_port/controller.rs`, `src/worker/unified_server.rs`, `src/admin/state.rs`, `src/admin/handlers/honeypot.rs` |
| 3.2 | Document internal PM fields | `src/admin/handlers/config.rs` |
| 4.1 | Behavioral endpoint | NEW: `src/admin/handlers/behavioral_intel.rs`, `src/admin/handlers/mod.rs`, `src/admin/state.rs`, `src/admin/mod.rs`, `src/admin/openapi.rs` |

---

## Risk Assessment

| Item | Risk | Mitigation |
|------|------|------------|
| Sensitive field masking | Low - improves security | Test that masked values still allow config updates |
| Overseer config bug fix | Low - fixes existing bug | Verify drain timing behavior unchanged |
| DNS UI enhancement | Medium - UI changes | Test with DNS feature enabled |
| Honeypot hot-reload | Medium - runtime behavior | Verify runner properly handles reconfig |
| Behavioral endpoint | Low - new feature | Ensure manager is accessible in AdminState |

---

## Verification Commands

```bash
# Security fixes - verify masking works
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/config/rule-feed | grep -v "public_key"
# Should show "public_key_prefix" and "public_key_configured", NOT "public_key"

# Overseer fix - verify drain interval uses correct config
grep -n "drain_check_interval_ms" src/startup/master.rs
# Should show "overseer.drain_check_interval_ms" not "upgrade.drain_check_interval_ms"

# Full verification after changes
cargo fmt
cargo clippy -- -D warnings
cargo test --lib --no-run
cargo test --test integration_test
```

---

## Dependencies

- **Feature Gating**: DNS endpoints are `#[cfg(feature = "dns")]` - tests need feature flag
- **AdminState Access**: Behavioral intelligence manager must be added to AdminState before endpoint creation
- **Config Validation**: HoneypotPortConfig needs `validate()` method for proper error handling

---

## Notes

1. **Architecture Preserved**: All changes maintain overseer/master/worker architecture. Admin API remains the management interface, process management via IPC unchanged.

2. **Backward Compatibility**: Sensitive field masking is a breaking change for clients expecting full field names. Consider versioning or documenting as breaking change.

3. **Hot-Reload Pattern**: The ICMP handler (`src/admin/handlers/icmp.rs:177-230`) is the reference implementation for validate → apply → persist pattern.

4. **Public Key Security**: Public keys (for signature verification) are not secrets, but exposing the full key allows attackers to target specific key material. The prefix + configured flag approach provides security hardening without breaking signature verification capability.

---

**Plan Created**: 2026-04-27
**Review Status**: Pending user review before implementation