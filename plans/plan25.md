# MaluWAF Code Quality Improvement Plan

**Plan ID**: 25
**Date**: 2026-04-23
**Status**: Draft
**Priority**: High (Security + Reliability)
**Target**: Production hardening for high-throughput deployment

---

## Executive Summary

This plan addresses 20 code quality issues identified through comprehensive review targeting production hardening. Issues span security (cryptographic RNG, SSRF), reliability (error handling, async patterns), performance (allocations in hot paths), and maintainability (code duplication, API design).

### Summary Table

| Tier | Count | Category | Risk Level |
|------|-------|----------|------------|
| **CRITICAL** | 3 | Deadlock, Admin token RNG, Zero-key fallback | HIGH (Security) |
| **HIGH** | 7 | RNG, error handling, performance | HIGH |
| **MEDIUM** | 6 | Code duplication, async, error swallowing | MEDIUM |
| **LOW** | 4 | Minor improvements | LOW |

---

## Tier 1: CRITICAL (Fix Immediately)

### Issue C1: Blocking Call Deadlock Risk

**Severity**: CRITICAL
**Location**: `src/honeypot_port/responders/mod.rs:159-160`
**Type**: Async deadlock
**Exploitability**: HIGH - Will deadlock if `respond_async()` called on `AiHoneypotResponder`

**Problem**: The sync `respond()` method calls `Handle::current().block_on()` which will deadlock if called from within a Tokio async context (which is the normal case).

```rust
// Current code - DEADLOCK RISK
fn respond(&self, payload: &[u8], context: &HoneypotContext) -> HoneypotResponse {
    let response_text = tokio::runtime::Handle::current()
        .block_on(self.ai_responder.generate_response(&prompt, context))
```

**Root Cause**: The `HoneypotResponder` trait has both `respond()` (sync) and `respond_async()` (async) methods. The default `respond_async()` implementation calls `respond()`. When `respond_async()` is called on `AiHoneypotResponder`, it deadlocks because `block_on` blocks the current async task waiting for itself.

**Impact**: Under normal async operation, calling `respond_async()` on `AiHoneypotResponder` causes deadlock and request hang.

**Fix Plan**:
1. Override `respond_async()` in `AiHoneypotResponder` to avoid calling the sync `respond()`
2. The async implementation already exists at lines 171-200 - just needs to be the actual implementation
3. Alternatively, change the sync path to use `spawn_blocking` if sync `respond()` is needed

**Files to modify**:
- `src/honeypot_port/responders/mod.rs` - Add `respond_async()` override (~15 lines)

**Est. lines**: 15
**Risk**: Low (fixes deadlock, no behavioral change for correct usage)

---

### Issue C2: Admin Token Uses Weak RNG

**Severity**: CRITICAL (Security)
**Location**: `src/config/admin.rs:86-101, 184-198`
**Type**: Insufficient entropy for authentication secret
**Impact**: Theoretical prediction attack if ThreadRng state compromised

**Problem**: Admin authentication tokens are generated using `rand::rng()` (ThreadRng) instead of `OsRng`. Admin tokens are secrets with indefinite lifetime used for bearer authentication.

```rust
// Current code - WEAK RNG
fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();  // ThreadRng - not cryptographically secure
    let token: String = (0..48)
        .map(|_| {
            let idx = rng.random_range(0..64);
            CHARSET[idx] as char
        })
        .collect();
    token
}
```

**Root Cause**: ThreadRng (ChaCha12) provides forward secrecy issues - if process memory is leaked, past outputs can be predicted. OsRng uses OS entropy source directly.

**Fix Plan**:
1. Change to `rand::rngs::OsRng` with `try_fill_bytes()`
2. Update both `generate_token()` and `default_admin_token()`

**Code change**:
```rust
fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 48];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    const CHARSET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    bytes
        .iter()
        .map(|&b| {
            let idx = (b as usize) % 62;
            CHARSET[idx] as char
        })
        .collect()
}
```
*Note*: `fill_bytes()` panics on RNG failure which is appropriate for OS-level entropy.

**Files to modify**:
- `src/config/admin.rs` - `generate_token()` (~12 lines)
- `src/config/admin.rs` - `default_admin_token()` (~15 lines)

**Est. lines**: 30
**Risk**: Low (RNG change, API unchanged)

---

### Issue C3: Zero-Key Fallback in YARA Signature Verification

**Severity**: CRITICAL (Defensive)
**Location**: `src/mesh/yara_rules.rs:771,934`
**Type**: Silent error masking
**Impact**: Hides programming errors; could mask key corruption

**Problem**: When public key bytes cannot be converted to 32-byte array, silently falls back to zero key. Signature verification then always fails, masking the root cause.

```rust
// Current code - ZERO KEY FALLBACK
let signer = crate::mesh::protocol::MeshMessageSigner::new(
    pk_bytes.clone().try_into().unwrap_or([0u8; 32]),
);
```

**Analysis**: Not exploitable for forgery (verification uses actual `pk_bytes` parameter), but masks bugs and makes debugging harder.

**Fix Plan**:
1. Return error explicitly instead of fallback to zero key
2. Add warning log for visibility
3. Both locations (fetch_chunks_from_dht and sync_from_dht)

**Code change**:
```rust
let signer_pk_array: [u8; 32] = match pk_bytes.clone().try_into() {
    Ok(arr) => arr,
    Err(_) => {
        tracing::warn!("YARA sync: invalid signer pk length for chunk {}", i);
        return None;
    }
};
let signer = crate::mesh::protocol::MeshMessageSigner::new(signer_pk_array);
```

**Files to modify**:
- `src/mesh/yara_rules.rs` - `fetch_chunks_from_dht()` (~10 lines)
- `src/mesh/yara_rules.rs` - `sync_from_dht()` (~10 lines)

**Est. lines**: 20
**Risk**: Low (defensive fix, no security impact)

---

## Tier 2: HIGH (Fix This Sprint)

### Issue H1: HMAC Session Key Uses ThreadRng

**Severity**: HIGH (Security)
**Location**: `src/process/ipc_signed.rs:555`
**Type**: Cryptographic key uses insufficient entropy

**Problem**: The HMAC session key (THE secret for IPC message authentication) is generated with ThreadRng.

**Fix Plan**: Change to `OsRng`

**Files to modify**:
- `src/process/ipc_signed.rs` - `generate_session_key()` (~5 lines)

**Est. lines**: 5
**Risk**: Low

---

### Issue H2: Tier Key Uses ThreadRng

**Severity**: HIGH (Security)
**Location**: `src/mesh/transport_org.rs:132-135`
**Type**: Authorization key uses insufficient entropy

**Problem**: Tier keys authorize organization membership and should use OsRng.

**Fix Plan**: Change to `OsRng`

**Files to modify**:
- `src/mesh/transport_org.rs` - Key generation (~5 lines)

**Est. lines**: 5
**Risk**: Low

---

### Issue H3: Lock Poisoning Causes Process Panic

**Severity**: HIGH (Reliability)
**Location**: `src/process/ipc_signed.rs:69`
**Type**: Disproportionate error handling

**Problem**: If a previous thread panicked while holding the NONCE_CACHE lock, the entire process crashes on any subsequent IPC message handling.

```rust
// Current code - PANICS ON POISON
let mut cache = NONCE_CACHE
    .lock()
    .expect("NONCE_CACHE lock poisoned - previous holder panicked");
```

**Fix Plan**: Use `match` with `into_inner()` recovery (pattern already exists at `src/upload/config.rs:214`)

**Code change**:
```rust
let mut cache = match NONCE_CACHE.lock() {
    Ok(c) => c,
    Err(poisoned) => {
        tracing::warn!("NONCE_CACHE poisoned, recovering...");
        poisoned.into_inner()
    }
};
```

**Files to modify**:
- `src/process/ipc_signed.rs` - `check_and_insert_nonce()` (~8 lines)

**Est. lines**: 8
**Risk**: Low (already proven pattern)

---

### Issue H4: O(n) Vec Contains in Probe Tracker

**Severity**: HIGH (Performance)
**Location**: `src/waf/probe_tracker.rs:55-62`
**Type**: Algorithmic - O(n) instead of O(1)
**Impact**: 1.5M string comparisons/sec at 500K rps

**Problem**: `unique_endpoints.contains()` is O(n) on every probe event. Maximum ~10 entries, but compounds at scale.

```rust
// Current code - O(n)
if !self.unique_endpoints.contains(&endpoint) {
    self.unique_endpoints.push(endpoint);
}
```

**Fix Plan**:
1. Change `unique_endpoints: Vec<String>` to `HashSet<String>` in `ProbeRecord`
2. Use `insert()` which returns `bool` (true if new)

**Code change**:
```rust
use std::collections::HashSet;

pub unique_endpoints: HashSet<String>,

// In add_event():
self.unique_endpoints.insert(endpoint);  // O(1), returns bool indicating if new

// In get_unique_endpoints() - convert back to Vec for API compatibility:
fn get_unique_endpoints(&self, ip: IpAddr) -> Vec<String> {
    self.store
        .read()
        .get(&ProbeRecord::key(&ip))
        .map(|r| r.unique_endpoints.iter().cloned().collect())
        .unwrap_or_default()
}
```

**Files to modify**:
- `src/waf/probe_tracker.rs` - `ProbeRecord` struct definition (~1 line type change)
- `src/waf/probe_tracker.rs` - `add_event()` method (~5 lines)
- `src/waf/probe_tracker.rs` - `get_unique_endpoints()` (~5 lines to convert)
- `src/waf/probe_tracker.rs` - JSON serialization (if applicable, ~5 lines)

**Est. lines**: 20
**Risk**: Low (HashSet is drop-in replacement for small N)

---

### Issue H5: to_lowercase() Per Header Per Request

**Severity**: HIGH (Performance)
**Location**: `src/proxy/headers.rs:136`
**Type**: Allocation in hot path
**Impact**: ~13M alloc/sec at 500K rps (26 allocations per request)

**Problem**: `build_headers_to_filter()` calls `to_lowercase()` on every header name on every proxied request.

```rust
// Current code - ALLOCATION PER HEADER
for header in global_headers {
    let lower = header.to_lowercase();  // NEW STRING
    to_filter.insert(lower);
}
```

**Fix Plan**:
1. Pre-lowercase headers at config load time
2. Use `http::header::HeaderName` for O(1) hash lookup instead of String
3. Modify `build_headers_to_filter()` to accept pre-parsed headers

**Files to modify**:
- `src/config/site/security.rs` - Add `more_clear_headers_lower: Vec<HeaderName>` field
- `src/config/main.rs` or site parsing - Populate at config load
- `src/proxy/headers.rs` - Change signature to use `&[HeaderName]` (~20 lines)

**Est. lines**: 40
**Risk**: Medium (config struct change, needs validation)

---

### Issue H6: URL format!() Per Proxied Request

**Severity**: HIGH (Performance)
**Location**: `src/http/server.rs:2528`
**Type**: Allocation in hot path
**Impact**: ~50K alloc/sec at 10% proxy rate

**Problem**: `format!("{}{}", target.upstream, path)` allocates String on every proxied request.

**Fix Plan**:
1. Pre-parse `Uri` at config load time in `RouteTarget`
2. Store `upstream_uri: Uri` alongside `upstream: Arc<str>`
3. Use `Uri` builder with pre-parsed base + path

**Files to modify**:
- `src/router.rs` - `RouteTarget` struct (~1 field)
- `src/router.rs` - `RouteTarget::new()` (~5 lines)
- `src/http/server.rs` - Usage in `handle_request()` (~5 lines change)

**Est. lines**: 15
**Risk**: Medium (Uri parsing at startup vs per-request)

---

### Issue H7: Redundant block_in_place + block_on

**Severity**: HIGH (Performance)
**Location**: `src/mesh/threat_intel.rs:1321-1323`
**Type**: Unnecessary async wrapping
**Impact**: Thread pool starvation under high load

**Problem**: `block_in_place` wraps `block_on` which wraps a trivial async read. This exhausts the blocking thread pool for no benefit.

```rust
// Current code - REDUNDANT
let global_nodes = tokio::task::block_in_place(|| {
    tokio::runtime::Handle::current()
        .block_on(topology.get_global_nodes())
});
```

**Fix Plan**:
1. Add `get_global_nodes_sync()` to `MeshTopology` that uses synchronous parking_lot RwLock
2. Call sync method directly without async wrappers

**Files to modify**:
- `src/mesh/topology.rs` - Add `get_global_nodes_sync()` method (~10 lines)
- `src/mesh/threat_intel.rs` - Remove async wrappers (~5 lines)

**Est. lines**: 15
**Risk**: Low (adds sync alternative, doesn't break existing)

---

## Tier 3: MEDIUM (Next Sprint)

### Issue M1: Attack Detection Check Function Duplication

**Severity**: MEDIUM (Maintainability)
**Location**: `src/waf/attack_detection/mod.rs:285-908`
**Type**: Code duplication (~500 lines)
**Pattern**: 11 functions with identical structure, differ only in detector name

**Problem**: Functions `check_sqli`, `check_xss`, `check_ssti`, `check_cmd_injection`, `check_path_traversal`, `check_rfi`, `check_ssrf`, `check_xxe`, `check_ldap_injection`, `check_xpath_injection`, `check_open_redirect` all follow identical template.

**Fix Plan**:
1. Add `InstanceDetector` trait with `check_inputs()` default implementation
2. Detectors that can use the default pattern become ~3-line wrappers
3. Detectors with custom logic (SSRF, RFI) override specific methods

**Code structure**:
```rust
pub trait InstanceDetector: Send + Sync {
    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult>;

    fn check_inputs(
        &self,
        path: Option<&str>,
        query_string: Option<&str>,
        headers: &[(Arc<str>, NormalizedInput)],
        body: Option<&str>,
    ) -> Option<AttackDetectionResult> {
        // Default implementation - handles Path, QS, Headers, Body
        // Detectors override for custom behavior (skip path, etc.)
    }
}

// Usage in mod.rs:
fn check_ssti(&self, inputs: &NormalizedInputs) -> Option<AttackDetectionResult> {
    self.ssti_detector.check_inputs(...)
}
```

**Files to modify**:
- `src/waf/attack_detection/detector_common.rs` - Add trait (~80 lines)
- `src/waf/attack_detection/mod.rs` - Reduce 11 × 35-line functions to 11 × 3-line wrappers (~350 lines removed)

**Est. lines**: +80, -350 (net -270)
**Risk**: Medium (trait design, requires testing all detectors)

---

### Issue M2: Buffer Pool Expect Calls

**Severity**: MEDIUM (Defensive)
**Location**: `src/buffer/pool.rs:377,381,434`
**Type**: Panic on programming error

**Problem**: `.expect()` on buffer consumption indicates programming error (double-use), but could crash worker process.

**Fix Plan**:
1. Replace with `debug_assert!()` for release builds
2. Remove dead `as_bytes_mut()` method (never called)

**Files to modify**:
- `src/buffer/pool.rs` - `as_slice()`, `as_mut_slice()` (~5 lines)
- `src/buffer/pool.rs` - Remove `as_bytes_mut()` (~5 lines)

**Est. lines**: 10
**Risk**: Low (defensive change)

---

### Issue M3: HTTP Status Code Expect to unwrap_or

**Severity**: MEDIUM (Defensive)
**Location**: `src/http/file_manager.rs:113,128` (11 occurrences)
**Type**: Unnecessary panic risk

**Problem**: `StatusCode::from_u16(e.status_code()).expect()` could panic if invalid code (though source is trusted).

**Fix Plan**: Use `unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)`

**Files to modify**:
- `src/http/file_manager.rs` - 11 handler functions (~11 lines)

**Est. lines**: 11
**Risk**: Low (defensive change)

---

### Issue M4: Silent File Rename Errors in Cert Rotation

**Severity**: MEDIUM (Reliability)
**Location**: `src/mesh/cert.rs:655,659`
**Type**: Silent error swallowing

**Problem**: Certificate rotation rename failures are silently ignored. Could leave stale files.

**Fix Plan**: Add warning log for visibility

**Code change**:
```rust
if let Err(e) = std::fs::rename(old_cert, &rotated) {
    tracing::warn!("Failed to rotate certificate {}: {}", old_cert.display(), e);
}
```

**Files to modify**:
- `src/mesh/cert.rs` - `rotate_cert()` (~4 lines each)

**Est. lines**: 8
**Risk**: Low (logging change)

---

### Issue M5: Silent JSON Deserialization in DHT

**Severity**: MEDIUM (Debugability)
**Location**: `src/mesh/transport.rs:802`
**Type**: Silent error swallowing

**Problem**: Deserialization failures return `None` silently, making debugging difficult.

**Fix Plan**: Add warning log

**Files to modify**:
- `src/mesh/transport.rs` - `get_capability_attestation()` (~5 lines)

**Est. lines**: 5
**Risk**: Low (logging change)

---

### Issue M6: Encryption Nonce Uses ThreadRng

**Severity**: MEDIUM (Security)
**Location**: `src/mesh/config_identity.rs:391-392`
**Type**: Cryptographic nonce uses insufficient entropy

**Problem**: GCM nonce for private key encryption uses ThreadRng.

**Fix Plan**: Change to `OsRng`

**Files to modify**:
- `src/mesh/config_identity.rs` - Nonce generation (~3 lines)

**Est. lines**: 3
**Risk**: Low

---

## Tier 4: LOW (Backlog)

### Issue L1: InputLocation Arc Clone Overhead (Low Priority)

**Severity**: LOW (Performance)
**Location**: `src/waf/attack_detection/mod.rs:302`
**Analysis**: `Arc::clone()` is cheap (ref count only). Real allocation is in `detector_common.rs` SECURITY_HEADERS `.into()` pattern. Not worth fixing.

**Recommendation**: Ignore

---

### Issue L2: TLS skip_verify Documentation

**Severity**: LOW (Security Documentation)
**Location**: Multiple files
**Analysis**: Documented trade-off with warnings. Not exploitable in normal use.

**Recommendation**: Ensure `skip_verify_reason` is validated at config load time.

**Est. lines**: 10

---

### Issue L3: ConfigManager Encapsulation

**Severity**: LOW (API Design)
**Location**: `src/config/mod.rs:102-107`
**Analysis**: Direct field access is intentional for admin API flexibility. Dumb container pattern.

**Recommendation**: Add update methods with validation if desired.

**Est. lines**: 30 (if pursued)

---

### Issue L4: HMAC Nonce ThreadRng

**Severity**: LOW (Defense-in-depth)
**Location**: `src/process/ipc_signed.rs:83`
**Analysis**: Nonce has HMAC protection, so ThreadRng is acceptable. Change for defense-in-depth if desired.

**Recommendation**: Change to `OsRng` for belt-and-suspenders

**Est. lines**: 5

---

## Implementation Order

### Week 1: Security-Critical
1. **Issue C1** - Fix blocking call deadlock (deadlock risk)
2. **Issue C2** - Fix admin token RNG (authentication secret)
3. **Issue C3** - Fix zero-key fallback (defensive)

### Week 2: High Priority
4. **Issue H1** - Fix HMAC session key RNG
5. **Issue H2** - Fix tier key RNG
6. **Issue H3** - Fix lock poisoning panic
7. **Issue H4** - Fix O(n) probe tracker
8. **Issue H5** - Fix to_lowercase allocation
9. **Issue H6** - Fix URL format allocation
10. **Issue H7** - Fix redundant block_in_place

### Week 3: Medium Priority
11. **Issue M1** - Attack detection duplication refactor
12. **Issue M2** - Buffer pool debug_assert
13. **Issue M3** - HTTP status unwrap_or
14. **Issue M4** - Cert rotation logging
15. **Issue M5** - DHT deserialization logging
16. **Issue M6** - Encryption nonce RNG

### Week 4: Low Priority (Optional)
17. **Issue L2** - TLS skip_verify documentation
18. **Issue L3** - ConfigManager encapsulation
19. **Issue L4** - HMAC nonce RNG (defense-in-depth)

---

## Risk Assessment

| Change | Risk | Reason |
|--------|------|--------|
| C1: Deadlock fix | LOW | Fixes bug, doesn't change behavior |
| C2: Admin token RNG | LOW | RNG change, same API |
| C3: Zero-key fallback | LOW | Defensive, no security impact |
| H1-H2: RNG fixes | LOW | Same API, better RNG |
| H3: Lock poisoning | LOW | Proven pattern in codebase |
| H4: HashSet probe | LOW | Drop-in replacement |
| H5-H6: Pre-compute headers/URL | MEDIUM | Config struct changes |
| H7: Sync getter | LOW | Adds alternative, doesn't break |
| M1: Trait refactor | MEDIUM | Behavioral change, needs testing |
| M2-M5: Logging | LOW | No behavior change |

---

## Testing Requirements

1. **Unit tests** for:
   - `AiHoneypotResponder::respond_async()` deadlock scenario
   - `NonceCache` poison recovery
   - `ProbeRecord::add_event()` with HashSet

2. **Integration tests** for:
   - Admin token generation (verify OsRng)
   - YARA rule sync with invalid key handling

3. **Performance tests** for:
   - HashSet vs Vec in probe tracker (benchmark)
   - Header lowercase allocation reduction

---

## Files Summary

| Category | Files | Est. Lines |
|----------|-------|-------------|
| Security (RNG, keys) | 5 | 55 |
| Async/Threading | 2 | 20 |
| Error Handling | 5 | 35 |
| Performance | 4 | 80 |
| Maintainability | 2 | 290 (net -220) |
| **Total** | ~15 | **~480 (net ~190)** |

---

## Dependencies

- Issue H5 (to_lowercase fix) depends on config struct changes
- Issue M1 (trait refactor) is independent but large
- All other issues are independent

---

## Rollback Plan

Each change is self-contained and can be reverted by reverting the file change:
1. RNG changes: Revert to `rand::rng()`
2. Async fixes: Revert to `block_on`
3. Duplication refactor: Restore duplicated functions if needed

**No database migrations or state changes required.**