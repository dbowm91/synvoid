# MaluWAF Consolidated Improvement Plan

This document consolidates all individual improvement plans (plan2-plan9) into a single roadmap with parallelizable waves.

## Quick Reference

| Wave | Focus Area | Priority |
|------|------------|----------|
| 1 | Critical Performance Fixes (to_lowercase, allocations) | Critical |
| 2 | Mesh & DHT Infrastructure | High |
| 3 | WAF & Threat Intelligence | High |
| 4 | File Upload Security | High |
| 5 | Edge Caching & Transform Sharing | Medium |
| 6 | Serverless Architecture | Future |
| 7 | Security Audit Remediation | High |
| 8 | Code Quality & Technical Debt | Medium |
| 9 | Data Tech Stack Optimization | Low |

---

## Wave 1: Critical Performance Fixes

**Focus**: Eliminate blocking I/O, WAF parallelization, string allocation reduction

### 1.1 Eliminate Repeated `.to_lowercase()` Calls

**Problem**: Detectors call `.to_lowercase()` multiple times on the same input instead of using pre-computed `NormalizedInput.lowercased` field.

**Affected Files**:
- `src/waf/attack_detection/ssrf.rs:147,292` - Double allocation
- `src/waf/attack_detection/detector_common.rs:438,450` - Pattern matching ignores pre-normalized

**Solution**:
1. Modify detectors to accept and use pre-normalized input's `lowercased` field
2. Update all pattern matching closures to use `NormalizedInput.lowercased`

### 1.2 Reduce Memory Allocations in Hot Paths

**Locations**:
- `src/http/server.rs:718-724` - Body cloning (always clones even for small bodies)
- `src/proxy.rs:246,263,1482,1489` - Header string allocations
- `src/waf/attack_detection/normalizer.rs:63-64` - Always clones and allocates

**Solution**:
- Use `Arc<Bytes>` or borrow from full_body to avoid small-body clone
- Use `Cow<str>` for normalized when input doesn't need transformation

### 1.3 Rate Limiter Retention Optimization

**Location**: `src/waf/ratelimit.rs:78-104`

**Problem**: 6 sequential O(n) operations during cleanup

**Solution**: Combine timestamp checks into single pass

### 1.4 Regex DoS Protection

**Location**: `src/mesh/security_challenge.rs:287`

**Fix** (already documented as FIXED):
```rust
regex::Regex::new(&format!("(?{{max=10000}}){}", pattern))
```

---

## Wave 2: Mesh & DHT Infrastructure

**Focus**: DNS capability, sharding, adaptive quorum, mesh distribution

### 2.1 Edge Node Image Poisoning & Caching

**Problem**: Edge nodes don't fetch full image poison config; no DHT caching in standalone mode

**Phases**:
1. Add `SiteImagePoisonConfig` to `is_public()` in `src/mesh/dht/keys.rs`
2. Add `get_image_poison_config_for_site()` method to `src/mesh/transports/manager.rs`
3. Update mesh proxy to fetch and use full config
4. Add DHT caching to standalone server in `src/http/server.rs`

**Files Modified**:
- `src/mesh/dht/keys.rs`
- `src/mesh/config.rs`
- `src/mesh/transports/manager.rs`
- `src/mesh/proxy.rs`
- `src/http/server.rs`

### 2.2 YARA Rules Mesh Distribution

**Problems**:
1. Broadcast uses simple sender instead of mesh transport
2. No role filtering on broadcast
3. No auto-broadcast after feed fetch
4. Pull-only distribution (no push to edges)
5. No broadcast acknowledgment tracking
6. Delta sync not implemented

**Phases**:
1. Fix mesh broadcast transport - use `transport.broadcast_to_random_peers()` with role filtering
2. Auto-broadcast after `apply_rules_from_feed()` on global nodes
3. Add `BroadcastAckTracker` for delivery tracking
4. Implement delta sync based on client version

**Files Modified**:
- `src/mesh/yara_rules.rs`
- `src/mesh/transport.rs`

### 2.3 Mesh & DHT Security Improvements

**Phases**:
| Phase | Description | Status |
|-------|-------------|--------|
| 1 | DNS Server Role Enforcement | COMPLETED |
| 2 | Integrate Raft HA for global node coordination | TODO |
| 3 | DHT Data Encryption (sensitive records) | TODO |
| 4 | IXFR Incremental Zone Sync | COMPLETED |
| 5 | TOFU Expiration (90-day max) | TODO |
| 6 | Role Check Centralization | TODO |
| 7 | Configurable Timeouts | TODO |
| 8 | Connection Pool Limits | TODO |

**Files Modified**:
- `src/mesh/global_node_ha.rs`
- `src/mesh/transport.rs`
- `src/mesh/dht/record_store.rs`
- `src/mesh/cert.rs`
- `src/mesh/config.rs`

### 2.4 Threat Intelligence & Honeypot

**Bugs to Fix**:
1. **DHT Key Prefix Mismatch** - `src/mesh/threat_intel.rs:1040` reads `threat:` but publishes `threat_indicator:`
2. **ThreatSyncResponse Not Processed** - No handler exists for this message type

**Fix 1**:
```rust
// Change from:
if r.key.starts_with("threat:") {
// To:
if r.key.starts_with("threat_indicator:") {
```

**Fix 2**: Add handler in `handle_mesh_message()`:
```rust
MeshMessage::ThreatSyncResponse { indicators, ... } => {
    for indicator in indicators {
        self.handle_incoming_threat(indicator, from_node, from_role, signer);
    }
    None
}
```

**Verification**: HTTP honeypot sharing already works via `block_ip_with_threat_intel()`

---

## Wave 3: WAF & Threat Intelligence

### 3.1 Local Indicator Lookup Optimization

Focus on efficient local lookup patterns in WAF for common threats.

### 3.2 Threat Deduplication

Reduce duplicate threat processing in `ThreatIntelligenceManager`.

---

## Wave 4: File Upload Security

### 4.1 Archive Depth Limits

**File**: `src/upload/yara_scanner.rs`

**Improvements**:
- Add `archive_max_depth` config (default: 3)
- Add `archive_max_size` config (default: 100MB)

### 4.2 Scanner-Local Version Caching

Reduce IPC overhead by caching YARA version locally in scanner.

### 4.3 Path-Specific Allowlist Integration

Integrate `AllowedTypesConfig` with path-specific rules.

### 4.4 TAR Extraction Path Traversal Fix

**Location**: `src/static_files/file_manager.rs:948-969`

**Issue**: TAR extraction lacks explicit path traversal protection (ZIP has it)

**Fix**: Add canonical path validation similar to ZIP extraction

---

## Wave 5: Edge Caching & Transform Sharing

Builds on Wave 2.1 (Image Poisoning).

---

## Wave 6: Serverless Architecture

_Placeholder for future work - unified pool, routing, versioning_

---

## Wave 7: Security Audit Remediation

### 7.1 Critical & High Severity

| Priority | Issue | Location | Fix |
|----------|-------|----------|-----|
| HIGH | SSRF Allowlist Domain Bypass | `src/waf/attack_detection/ssrf.rs:278-285` | Check for `.` boundary before domain |
| HIGH | Non-Crypto RNG for Key Material | Multiple files in `src/mesh/` | Use `OsRng` instead of `rand::random()` |
| CRITICAL | NSEC3 Base32hex Encoding | `src/dns/dnssec_signing.rs:264-288` | Use proper base32hex per RFC 5155 |

**Files Requiring OsRng Fix**:
- `src/mesh/passover_key_exchange.rs:1186,1191,1264,1313,1316,1342,1347`
- `src/mesh/config_identity.rs:134,232,272,279`
- `src/mesh/network_security.rs:319,339`
- `src/mesh/organization.rs:23,584`
- `src/tunnel/wireguard/config.rs:320`

### 7.2 Medium Severity

| Category | Issue | Fix |
|----------|-------|-----|
| WAF | X-Forwarded-For Single IP | Validate all IPs in chain |
| WAF | Open Redirect Path Check Missing | Add path to check_request_full |
| WAF | Domain Check Before URL Decode | Decode input first, then check allowlist |
| TLS | skip_verify Hostname Bypass | Document clearly, require explicit flag |
| TLS | allow_plaintext HTTP Upstream | Warn on startup |
| IPC | No Mutual Authentication | Use `UnixStream::peer_credentials()` |
| IPC | No Connection Source Validation | Add peer credential validation |
| Mesh | No node_id to Public Key Binding | Include hash of pubkey in node_id |
| Mesh | TOFU Accepts First Certificate | Add out-of-band verification option |
| DNS | DNSSEC Not Validated for Recursive | Implement chain-of-trust validation |
| DNS | RRL Only TCP | Add UDP rate limiting |

### 7.3 Low Severity

- Timing attack on bcrypt (low risk)
- Linear rate limiter cleanup
- QUIC self-signed cert auto-generation
- No explicit cipher suite config
- SHA-1 as default NSEC3 algorithm
- YARA scan errors treated as clean
- Cache fingerprint race condition

---

## Wave 8: Code Quality & Technical Debt

### 8.1 Test Compilation Errors (BLOCKING)

**Location**: `src/dns/platform.rs:193,206,219,232,245,258,309,332`

**Issue**: `in_pktinfo::from_bytes_mut` not found - nix API version mismatch

**Fix**:
```rust
// Use std::ptr for byte-level casting
let pktinfo = &mut *(pktinfo_bytes.as_ptr() as *mut nix::libc::in_pktinfo);
```

**Verification**: `cargo test --lib --no-run` must pass

### 8.2 Replace .unwrap() in Security-Critical Paths

| File | Count | Priority |
|------|-------|----------|
| `src/process/ipc.rs` | 22 | High |
| `src/proxy.rs` | 12+ | High |
| `src/tls/` | 8+ | Medium |
| `src/waf/mod.rs` | 10+ | Medium |

### 8.3 Document Unsafe Blocks

Priority files:
- `src/platform/unix.rs:45-51,350,427-432` - FD handling
- `src/process/socket_fd.rs:368-400` - Socket transfer
- `src/tunnel/wireguard/tun.rs:181-361` - TUN device

### 8.4 Private Key Encryption at Rest

**Location**: `src/mesh/config.rs:781-847`

**Fix**: Add optional encrypted private key:
```rust
pub encrypted_private_key: Option<EncryptedKey>,
```

### 8.5 Large File Splitting

| File | Lines | Split Strategy |
|------|-------|---------------|
| `src/http/server.rs` | 3,202 | Separate: WebSocket, file serving, request handling |
| `src/process/manager.rs` | 2,281 | Separate: worker lifecycle, IPC pool |
| `src/mesh/topology.rs` | 2,256 | Separate: peer scoring, bandwidth |
| `src/process/ipc.rs` | 1,835 | Separate: Message handling from socket I/O |

---

## Wave 9: Data Tech Stack Optimization

### 9.1 Cache TTL Configuration

**Files**:
- `src/dns/recursive_cache.rs` - Add TTL to positive/negative caches
- `src/dns/cache.rs` - Add TTL to three cache instances

### 9.2 Memory-Aware Eviction

Add weigher to DNS caches:
```rust
.weigher(|_key, value: &CachedRecord| {
    u32::try_from(value.data.len()).unwrap_or(u32::MAX)
})
```

### 9.3 rkyv Zero-Copy for IPC

**File**: `src/process/ipc.rs`

Add rkyv derives to Message enum:
```rust
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
```

### 9.4 Metrics Lock Optimization

Replace global mutex with per-key atomics or dashmap.

---

## Implementation Dependencies

```
Wave 1 (Performance)
    │
    ├── 1.1-1.3: Independent
    │
Wave 2 (Mesh/DHT)
    │
    ├── 2.1: Depends on Wave 1
    ├── 2.2: Independent
    ├── 2.3: Independent (Ra HA depends on 2.2 for coordination)
    └── 2.4: Independent

Wave 3 (WAF/TI)
    └── Depends on Wave 2.4

Wave 4 (File Upload)
    └── Independent

Wave 5 (Caching)
    └── Depends on Wave 2.1

Wave 7 (Security)
    ├── 7.1: Independent
    └── 7.2: Independent

Wave 8 (Code Quality)
    └── 8.1: BLOCKING (test compilation must pass first)

Wave 9 (Data Stack)
    └── Independent
```

---

## Parallelization Guide

### Can Run in Parallel

| Group | Items |
|-------|-------|
| A | Wave 1.1, Wave 1.2, Wave 1.3, Wave 1.4 |
| B | Wave 2.2, Wave 2.3, Wave 2.4 |
| C | Wave 4 (File Upload) |
| D | Wave 7 (Security) - all items independent |
| E | Wave 9 (Data Stack) |
| F | Wave 8.2, Wave 8.3, Wave 8.4, Wave 8.5 |

### Must Run Sequentially

| Sequence | Reason |
|----------|--------|
| Wave 8.1 → All other waves | Test compilation must pass |
| Wave 2.1 → Wave 5 | Cache builds on poisoning |
| Wave 2.4 → Wave 3 | Threat intel fixes needed first |

---

## Verification Commands

```bash
# Quick test (5 seconds)
cargo test --test integration_test

# Test compilation (CRITICAL - must pass)
cargo test --lib --no-run

# DNS tests
cargo test --test dns_recursive_test
cargo test --test dns_server_test

# IPC tests
cargo test --test ipc_test

# All tests
cargo test

# Clippy
cargo clippy -- -D warnings

# Format
cargo fmt
```

---

## Success Metrics

| Metric | Baseline | Target |
|--------|----------|--------|
| `.unwrap()` count | 553+ | < 100 |
| Unsafe blocks documented | 0% | 100% |
| to_lowercase() in hot paths | Unknown | < 10 |
| Test compilation | FAIL | PASS |
| Cache TTL configured | Partial | 100% |
| DHT records encrypted | 0% | 100% |

---

## Files Reference

### Plan 2 - Image Poisoning
- `src/mesh/dht/keys.rs`
- `src/mesh/config.rs`
- `src/mesh/transports/manager.rs`
- `src/mesh/proxy.rs`
- `src/http/server.rs`

### Plan 3 - YARA Distribution
- `src/mesh/yara_rules.rs`
- `src/mesh/transport.rs`
- `src/upload/yara_scanner.rs`
- `src/upload/mod.rs`

### Plan 4 - Mesh/DHT Security
- `src/mesh/global_node_ha.rs`
- `src/mesh/transport.rs`
- `src/mesh/dht/record_store.rs`
- `src/mesh/cert.rs`
- `src/mesh/config.rs`

### Plan 5 - Performance
- `src/waf/attack_detection/ssrf.rs`
- `src/waf/attack_detection/detector_common.rs`
- `src/waf/attack_detection/normalizer.rs`
- `src/http/server.rs`
- `src/proxy.rs`
- `src/waf/ratelimit.rs`

### Plan 6 - Security Audit
- `src/waf/attack_detection/ssrf.rs`
- `src/mesh/passover_key_exchange.rs`
- `src/mesh/config_identity.rs`
- `src/dns/dnssec_signing.rs`
- `src/tls/`

### Plan 7 - Code Quality
- `src/dns/platform.rs`
- `src/process/ipc.rs`
- `src/proxy.rs`
- `src/platform/unix.rs`

### Plan 8 - Data Stack
- `src/dns/recursive_cache.rs`
- `src/dns/cache.rs`
- `src/serialization.rs`
- `src/metrics/mod.rs`

### Plan 9 - Threat Intelligence
- `src/mesh/threat_intel.rs`
- `src/static_files/file_manager.rs`
