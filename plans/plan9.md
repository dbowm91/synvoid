# MaluWAF Security Audit Remediation Plan

**Status**: Active - Planning Phase
**Last Updated**: 2026-04-27
**Audit Completed**: 2026-04-27

---

## Audit Scope and Methodology

**Audited Components**:
- IPC communication (`src/process/`)
- Mesh networking (`src/mesh/`)
- WAF engine (`src/waf/attack_detection/`)
- Admin API (`src/admin/`)
- WASM plugin runtime (`src/plugin/`)
- DNS/DNSSEC (`src/dns/`)
- Upload security (`src/upload/`)
- Challenge/PoW systems (`src/challenge/`)

**Audit Approach**:
1. Multi-agent parallel exploration of each security-critical module
2. Deep-dive investigation of each identified issue with code-level analysis
3. Web research for vulnerability classification and best practices
4. Threat modeling based on MaluWAF's >500K rps scalability target

**12 issues** were identified and prioritized into this remediation plan.

---

## Critical Priority (Fix Before Production)

### 1. WASM `table_growing` Unbounded Growth

**Severity**: Critical | **Effort**: 1-2 hours | **Complexity**: Low

**Location**: `src/plugin/wasm_runtime.rs:319-326`

**Problem**:
The `ResourceLimiter::table_growing()` callback unconditionally returns `Ok(true)`, allowing unlimited table element growth regardless of the `desired` size or `maximum` bound. While `memory_growing()` correctly enforces `max_memory` limits, `table_growing()` has no equivalent protection.

**Attack Vector**: A malicious or buggy WASM plugin could call `table.grow` repeatedly to exhaust server memory. Each table element is a pointer (8 bytes on 64-bit), so 10M elements = 80MB per plugin. At 500K requests/second, this compounds rapidly.

**Fix Required**:
1. Add `max_table_elements: usize` field to `WasmResourceLimits` struct
2. Add `max_table_elements: usize` field to `RequestContext` struct
3. Fix `table_growing()` implementation to return `Ok(desired <= self.max_table_elements)`
4. Propagate limit from `WasmResourceLimits` to `RequestContext` in store creation
5. Update warmup context in `instance_pool.rs` to include `max_table_elements`

**Files to Modify**:
- `src/plugin/wasm_runtime.rs` (~10 lines)
- `src/plugin/instance_pool.rs` (~2 lines)
- `src/plugin/global.rs` (if exists, for default values)

---

### 2. WASM Instance Pool DHT Prefix Leakage

**Severity**: Critical | **Effort**: 2-3 hours | **Complexity**: Low-Medium

**Location**: `src/plugin/instance_pool.rs:148-159`, `src/plugin/pool.rs:14-27`

**Problem**:
The `prepare_for_request()` method updates `start`, `timeout`, and `env` fields, but does **NOT** reset `allowed_dht_prefixes`. When pooled WASM instances are reused, they retain the DHT access permissions from the **previous request**.

**Impact**: Cross-tenant/function permission leakage. A plugin with limited DHT access in request 1 could inherit broader access from a subsequent request's pool configuration. Sensitive prefixes like `threat_indicator:`, `yara_rule:`, `edge_attestation:` require explicit allowlisting.

**Attack Scenario**:
1. Instance A (request 1): `allowed_dht_prefixes: ["threat_indicator:special"]`
2. Instance A returned to pool
3. Instance A (request 2): Reuses instance with same prefixes still set

**Fix Required**:
1. Add `allowed_dht_prefixes: Vec<String>` field to `WasmPooledInstance` struct
2. Update `WasmRuntime` to pass configured prefixes when creating pooled instances
3. Update `prepare_for_request()` to restore `allowed_dht_prefixes` from stored configuration
4. Ensure warmup creates instances with empty prefixes as secure default

**Alternative (Simpler)**: Reset `allowed_dht_prefixes` to empty in `prepare_for_request()`, requiring callers to explicitly set it per-request if needed.

**Files to Modify**:
- `src/plugin/instance_pool.rs` (~15 lines)
- `src/plugin/pool.rs` (~10 lines)
- `src/plugin/wasm_runtime.rs` (~5 lines)

---

### 3. Serverless Functions Ignore Limits

**Severity**: Critical | **Effort**: 30-60 minutes | **Complexity**: Low

**Location**: `src/serverless/manager.rs:479-491`, `src/serverless/manager.rs:506-518`

**Problem**:
The `_limits` variable (underscore prefix indicates intentional non-use) is created with proper function-specific values from `func_def` but is **never passed** to `load_plugin()` or `load_plugin_from_memory()`. Both methods use `WasmPluginManager`'s default limits (64MB memory, 1M fuel, 30s timeout) instead of function-specific values.

**Impact**: All serverless functions run with identical resource limits regardless of their configuration. A function configured with 256MB memory and 10M CPU fuel gets the same limits as one with 64MB/1M defaults.

**Fix Required**:
1. Add `load_plugin_from_memory_with_limits(name: &str, data: &[u8], limits: WasmResourceLimits)` method to `WasmPluginManager`
2. Update `load_function_wasm()` in `src/serverless/manager.rs` to use new method instead of `load_plugin_from_memory()`
3. Ensure `load_plugin()` also accepts limits or is updated to use `load_plugin_with_limits()`

**Files to Modify**:
- `src/plugin/wasm_runtime.rs` (new method, ~15 lines)
- `src/serverless/manager.rs` (~5 lines)

---

### 4. Threat Intel Trusted Signer Bypass

**Severity**: Critical | **Effort**: 30 minutes | **Complexity**: Low

**Location**: `src/mesh/threat_intel.rs:1606-1621`

**Problem**:
The `ThreatAnnounce` handler condition at line 1607 is:
```rust
if !self.node_role.is_global() && !self.config.trusted_signers.is_empty() {
```

When `trusted_signers` is empty (the default), the entire trusted signer check is **skipped**. The DHT sync path correctly calls `check_trusted_signer()` which falls back to topology-based trust when `trusted_signers` is empty.

**Attack Scenario**:
1. Attacker identifies a non-global node with `trusted_signers` empty (default)
2. Attacker crafts a `ThreatAnnounce` message with arbitrary threat indicators
3. Signature verification passes (attacker signs with their key)
4. At line 1607, since `trusted_signers` is empty, check is bypassed entirely
5. Malicious indicators accepted into threat intelligence database

**Fix Required**:
Remove the `&& !self.config.trusted_signers.is_empty()` condition:
```rust
// Change from:
if !self.node_role.is_global() && !self.config.trusted_signers.is_empty() {
// To:
if !self.node_role.is_global() {
```

The `check_trusted_signer()` function already handles both cases correctly:
- When `trusted_signers` is empty: falls back to topology-based trust
- When `trusted_signers` is populated: checks signer's public key

**Files to Modify**:
- `src/mesh/threat_intel.rs` (~2 lines)

---

## High Priority (Fix Soon)

### 5. WAF Unicode Bypass

**Severity**: High | **Effort**: 1-2 days | **Complexity**: Medium

**Audit Classification Note**: Initially classified as "Medium" in raw findings due to requiring specific encoding conditions, but elevated to "High" because:
- Affects core WAF detection (SQLi, XSS, path traversal) - the primary security function
- UTF-8 overlong bypass is a well-known WAF evasion technique documented since 2005
- No special configuration needed to be vulnerable - default behavior is weak
- Can be chained with other attacks for amplified impact

**Location**: `src/waf/attack_detection/normalizer.rs:44-57`, `src/waf/attack_detection/utils.rs`

**Problem**:
The URL decoder only decodes **ASCII bytes** (0x00-0x7F). Non-ASCII UTF-8 continuation bytes pass through unchanged, allowing UTF-8 overlong encoding bypass:

| Input | Decoded Output | Notes |
|-------|---------------|-------|
| `%2F` | `/` | ASCII, correctly decoded |
| `%C0%AE` | ` bytes` | NOT decoded (continuation byte not ASCII) |

**Bypass Examples**:
- Path traversal: `%c0%ae%c0%ae%c0%af` (overlong `../`) may bypass detection
- SQLi: Unicode quotes `'` (U+2018), `'` (U+FF07) not normalized to ASCII
- XSS: Zero-width characters between `<script` and `alert()` survive normalization

**Fix Required**:
1. Add UTF-8 validation step before decoding
2. Add overlong encoding detection and rejection:
```rust
fn is_overlong(bytes: &[u8]) -> bool {
    match bytes {
        [0xC0, _, _] | [0xC1, _, _] => true,  // 2-byte overlong
        [0xE0, _, _, _] if bytes[1] < 0xA0 => true,  // 3-byte overlong
        [0xF0, _, _, _, _] if bytes[1] < 0x90 => true,  // 4-byte overlong
        _ => false,
    }
}
```
3. Reorder NFC Unicode normalization to happen **before** pattern matching
4. Add explicit Unicode homoglyph normalization for quote characters

**Files to Modify**:
- `src/waf/attack_detection/normalizer.rs` (~40 lines)
- Add integration tests for bypass payloads

---

### 6. Admin Regex DoS Endpoint

**Severity**: High | **Effort**: 2-4 hours | **Complexity**: Medium

**Audit Classification Note**: Initially classified as "Medium" but elevated to "High" due to:
- Attacker can cause CPU exhaustion with trivial ReDoS patterns (e.g., `(a+)+`)
- Static validation is easily bypassed - the hardcoded pattern list only catches 4 specific cases
- The vulnerability is in the Admin API which requires authentication but no special position
- Exponential backtracking on certain inputs can freeze a CPU core for seconds per match attempt

**Location**: `src/admin/handlers/config.rs:497-509`, `src/utils.rs:708-763`

**Problem**:
The `/config/check-regex` endpoint only performs **static analysis** via `check_regex_complexity()`. It does NOT actually compile or execute the regex with timeout protection. Many dangerous patterns pass validation:

| Pattern | Why Dangerous | Passes Validation? |
|---------|--------------|-------------------|
| `(a+)+` | Overlapping matches | YES |
| `(a*)*` | Zero-width repetition | YES |
| `(a\|a)+` | Alternation stacking | YES |
| `([a-zA-Z]+)+` | Char class + quantifier | YES |

**Fix Required**:
1. Use `RegexBuilder` with `match_timeout()` and `size_limit()`:
```rust
use regex::RegexBuilder;
let re = RegexBuilder::new(&pattern)
    .size_limit(100_000)  // 100KB max compiled size
    .match_timeout(Duration::from_millis(100))
    .build()?;
```
2. Actually compile and test the regex with a timeout mechanism
3. Consider using `regex-syntax` crate for proper AST analysis of complexity
4. Add ReDoS pattern tests to integration suite

**Files to Modify**:
- `src/admin/handlers/config.rs` (~10 lines)
- `src/utils.rs` (~20 lines)

---

## Medium Priority

### 7. IPC Key Fallback to Environment Variable

**Severity**: Medium | **Effort**: 2-4 hours | **Complexity**: Medium

**Audit Classification Note**: While the vulnerability is real, it's mitigated by secure defaults:
- `allow_insecure_ipc_key` defaults to `false` - the system panics rather than falling back
- Users must explicitly opt into the insecure behavior with full warning logs
- Risk is primarily on misconfigured systems or multi-tenant shared infrastructure
- The real fix (memfd_create) is more about defense-in-depth than closing an active exploit

**Location**: `src/process/manager.rs:343-376`

**Problem**:
When tempfile creation fails for IPC session key and `allow_insecure_ipc_key=true`, the key is passed via `MALUWAF_IPC_KEY` environment variable. This is visible via:
- `/proc/<pid>/environ` (world-readable on multi-user systems)
- `ps aux` process listings

**Attack Scenario**: On shared systems, any local user can read `/proc/<pid>/environ` and obtain the IPC signing key, enabling full IPC spoofing.

**Fix Required**:
1. Implement `memfd_create()` with `MFD_CLOEXEC` for Linux-based IPC key passing
2. Child reads key via `/proc/self/fd/<fd>`, then closes immediately
3. Keep tempfile method as fallback on non-Linux platforms
4. Consider removing `allow_insecure_ipc_key` fallback entirely

**Recommended Approach**:
```rust
#[cfg(unix)]
fn create_ipc_key_memfd(key: &[u8; 32]) -> std::io::Result<std::os::unix::io::RawFd> {
    use libc::SYS_memfd_create;
    let fd = unsafe { libc::syscall(SYS_memfd_create, b"maluwaf_ipc_key\0", libc::MFD_CLOEXEC) };
    // Write key, seal to prevent reading, return fd
}
```

**Files to Modify**:
- `src/process/manager.rs` (~80-120 lines)
- Possibly new helper module for secure key passing

---

### 8. DNS TSIG Timing Side Channel

**Severity**: Medium | **Effort**: 30 minutes | **Complexity**: Low

**Audit Classification Note**: Theoretically a real vulnerability per RFC 4635, but practically difficult to exploit:
- Requires precise timing measurements (~100ns resolution) from attacker-controlled network position
- DNS responses may be cached/proxied, adding network jitter that masks timing differences
- Attacker needs to be on same LAN or have direct server access
- 32-byte key requires 256 adaptive measurements to fully extract
- Defense-in-depth fix using existing `subtle::ConstantTimeEq` in codebase - low risk, correct approach

**Location**: `src/dns/tsig.rs:237-244`

**Problem**:
Manual byte comparison via `diff |= a ^ b` loop does not operate in constant time:
- Short-circuit on first difference (iterates fewer operations when bytes differ early)
- Early length check exit leaks whether expected length is shorter/longer

**RFC 4635 Requirement**: "The HMAC computation must be computed in a constant-time manner."

**Fix Required**:
The codebase already uses `subtle::ConstantTimeEq` correctly in other places (e.g., `cookie.rs:86`, `ipc_signed.rs:199-202`). Apply the same pattern:

```rust
use subtle::ConstantTimeEq;
if !computed_mac.ct_eq(original_mac).into() {
    return Err(TsigError::MacVerificationFailed);
}
```

**Files to Modify**:
- `src/dns/tsig.rs` (~6 lines)

---

### 9. DNS Cache Source Validation Unused

**Severity**: Medium | **Effort**: 8-10 hours | **Complexity**: Medium

**Location**: `src/dns/cache.rs:587-596`

**Problem**:
The `SecureDnsCache::insert()` method accepts `source_ip: Option<IpAddr>` and `is_dnssec_signed: bool` parameters but **completely ignores them** (underscore prefix). The `enable_source_validation` field exists but is never checked during insertion.

**Impact**: Without source tracking, a poisoned entry from one authoritative server can be served for queries. This enables birthday attack-style DNS cache poisoning.

**Fix Required**:
1. Add `insert_with_metadata()` to `DnsCache` that stores `source_ip` and `is_dnssec_signed`
2. Modify `validate_response()` to check source IP consistency when `enable_source_validation` is true
3. Store and return DNSSEC validation status with cached responses
4. Add source validation to `CachedResponse.get_with_metadata()`

**Reference Implementation**: `ShardedDnsCache` in `sharded_cache.rs:127-128` already stores these fields - can use as reference.

**Files to Modify**:
- `src/dns/cache.rs` (~100-120 lines across several methods)

---

## Low Priority / Deferred

### 10. Threat Intel Signature Scope Weakness

**Severity**: Low | **Effort**: 0.5-1 day | **Complexity**: Medium

**Location**: `src/mesh/dht/record_store_message.rs:95-118`

**Problem**:
The envelope signature only covers metadata (`source_node_id`, `records.len()`, `role.bits()`, `timestamp`), NOT the actual record keys and values. However, per-record signatures in `store_record()` provide partial mitigation.

**Fix Required**:
Include record content hashes in envelope signature:
```rust
let records_content_hash = {
    let mut hasher = Sha256::new();
    for record in records {
        hasher.update(record.key.as_bytes());
        hasher.update(&record.value);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
};
```

**Note**: This requires version bump since signatures will be different.

---

### 11. IPC Path Traversal Validation

**Severity**: Low | **Effort**: 1-2 hours | **Complexity**: Low

**Location**: `src/process/ipc.rs:979-1010`

**Problem**:
`OverseerUpgradePrepare`, `OverseerDualMasterPrepare`, and `MasterConfigReload` messages only check string length, not canonicalization or `..` detection. Path traversal payloads like `../../etc/passwd` pass validation.

**Fix Required**:
Add path validation using pattern from `static_files/mod.rs:364`:
```rust
fn validate_path(path: &str, allowed_root: &Path) -> Result<(), IpcValidationError> {
    let canonical = std::fs::canonicalize(&full_path)?;
    let canonical_root = std::fs::canonicalize(allowed_root)?;
    if !canonical.starts_with(&canonical_root) {
        return Err(IpcValidationError { message: "path traversal detected" });
    }
    Ok(())
}
```

---

### 12. Nonce Cache O(n) Eviction Performance

**Severity**: Low | **Effort**: 3-4 hours | **Complexity**: Low

**Location**: `src/process/ipc_signed.rs:24-59`

**Problem**:
Vec-based `NonceCache` causes O(n) operations at 500K rps scale:
- `contains()`: O(n) linear search through 10,000 entries per signed message
- `evict_oldest()`: O(n) linear scan to find minimum timestamp

At 500K signed IPC operations/second, this compounds to ~10M ops/sec and causes CPU spikes.

**Fix Required**:
Replace with `HashMap<Nonce, Timestamp>` + `BTreeSet<(Timestamp, Nonce)>`:
- `contains()`: O(1) via HashMap lookup
- `evict_oldest()`: O(log n) via BTreeSet iterator (first = minimum)

**Complexity Improvement**:
| Operation | Current | Fixed |
|-----------|---------|-------|
| `contains()` | O(n) | **O(1)** |
| `insert()` | O(1) | **O(log n)** |
| `evict_oldest()` | O(n) | **O(log n)** |

---

## Implementation Order Recommendation

| Phase | Issues | Timeline |
|-------|--------|----------|
| **Immediate** | 4, 8, 11 | 1-2 days (small fixes, high impact) |
| **This Week** | 1, 2, 3, 6 | 1 week (plugin security, DoS prevention) |
| **Next Week** | 5, 7, 9 | 1-2 weeks (larger changes) |
| **Future** | 10, 12 | Can defer (performance improvements) |

---

## Summary Table

| # | Issue | Severity | Effort | Files |
|---|-------|----------|--------|-------|
| 1 | WASM table_growing | Critical | 1-2h | 3-5 |
| 2 | WASM pool DHT leak | Critical | 2-3h | 3 |
| 3 | Serverless ignore limits | Critical | 30-60m | 2 |
| 4 | Threat intel signer bypass | Critical | 30m | 1 |
| 5 | WAF Unicode bypass | High | 1-2d | 2 |
| 6 | Admin regex DoS | High | 2-4h | 2 |
| 7 | IPC key env fallback | Medium | 2-4h | 2 |
| 8 | DNS TSIG timing | Medium | 30m | 1 |
| 9 | DNS cache validation | Medium | 8-10h | 1 |
| 10 | Threat sig scope | Low | 0.5-1d | 1 |
| 11 | IPC path traversal | Low | 1-2h | 1 |
| 12 | Nonce cache O(n) | Low | 3-4h | 1 |

---

## Verification Commands

```bash
# Verify tests compile (not just cargo check)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Run full test suite (3-5 min)
cargo test
```

---

## Key Security Principles Applied

1. **Fail-closed defaults**: Empty `trusted_signers` should deny, not skip verification
2. **Complete context reset**: Pooled instances must reset ALL request-scoped data
3. **Constant-time comparison**: Cryptographic MACs must use `subtle::ConstantTimeEq`
4. **Input validation**: Canonicalize paths before checking boundary
5. **Defense in depth**: Multiple layers of validation better than single point

---

## Rollback and Safety Considerations

For each fix, the following rollback strategy applies:

| Fix | Rollback Mechanism | Safety Check |
|-----|-------------------|--------------|
| 1. WASM table_growing | Feature flag to disable table limits | WASM plugins continue to work without limits |
| 2. DHT prefix reset | Revert reset line, prefixes persist (secure default) | Test plugin DHT access works when explicitly allowed |
| 3. Serverless limits | Revert to `_limits` being unused | Functions load with manager defaults |
| 4. Threat intel signer | Revert condition change | Non-global nodes skip check when trusted_signers empty |
| 5. Unicode bypass | Disable overlong rejection | All inputs processed normally |
| 6. Regex DoS | Disable timeout, use static only | Patterns still validated statically |
| 7. IPC key memfd | Use tempfile fallback | Key passed via temp file |
| 8. DNS TSIG timing | Revert to XOR loop | MAC comparison still works |
| 9. DNS cache validation | Make source_ip check optional | Cache poisoning protection disabled |
| 10. Threat sig scope | Revert content hash | Envelope signature unchanged |
| 11. IPC path traversal | Revert path validation | All paths accepted |
| 12. Nonce cache O(n) | Revert to Vec-based | Performance degrades but correctness unchanged |

**Key Principle**: All fixes are additive - they add security constraints without changing the fundamental behavior of valid operations. Rolling back any fix returns the system to its pre-fix state without introducing new bugs.

---

## Test Coverage Requirements

Each fix should have corresponding tests added:

| Fix | Required Test Coverage |
|-----|----------------------|
| 1. WASM table_growing | Verify table.grow beyond limit is rejected |
| 2. DHT prefix reset | Verify pooled instance has correct prefixes per request |
| 3. Serverless limits | Verify configured limits are actually applied |
| 4. Threat intel signer | Verify ThreatAnnounce with empty trusted_signers still validates |
| 5. Unicode bypass | Verify overlong encodings and Unicode quotes are normalized |
| 6. Regex DoS | Verify ReDoS patterns cause timeout/validation failure |
| 7. IPC key memfd | Verify key not visible in /proc/<pid>/environ |
| 8. DNS TSIG timing | Timing-resistant test if possible, or code review |
| 9. DNS cache validation | Verify source IP mismatch is detected and blocked |
| 10. Threat sig scope | Verify tampered record content fails envelope verification |
| 11. IPC path traversal | Verify `../../etc/passwd` is rejected |
| 12. Nonce cache O(n) | Benchmark to confirm O(log n) performance |
