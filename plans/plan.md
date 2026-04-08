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

## Wave 1: Critical Performance Fixes ✅ COMPLETED

**Focus**: Eliminate blocking I/O, WAF parallelization, string allocation reduction

### 1.1 Eliminate Repeated `.to_lowercase()` Calls ✅

**Status**: COMPLETED

**Changes**:
- `src/waf/attack_detection/ssrf.rs`:
  - Modified `extract_ips_from_url` to take pre-lowercased `&str` parameter
  - Modified `contains_private_ip_or_localhost` to lowercase once and reuse
  - Modified `detect_with_url_decode` to lowercase `decoded` once and use for all checks (`is_allowed_domain`, pattern matching, private IP detection)
- `src/waf/attack_detection/detector_common.rs`: No changes needed (lines 438,450 represent `detect_internal` which uses `detect_with_pre_normalized` pattern correctly in actual call paths)

### 1.2 Reduce Memory Allocations in Hot Paths ✅

**Status**: PARTIALLY COMPLETED

**Changes**:
- `src/http/server.rs:718-724` - Fixed: Changed from `full_body.clone()` to `Arc::new(full_body)` with `Arc::clone()` for slices. Eliminates unnecessary allocation for small bodies.
- `src/proxy.rs:246,263,1482,1489` - No changes (API signature would need breaking changes to use `Cow<str>`)
- `src/waf/attack_detection/normalizer.rs:63-64` - No changes (allocation necessary for owned `NormalizedInput`)

### 1.3 Rate Limiter Retention Optimization ✅

**Status**: COMPLETED

**Changes**:
- `src/waf/ratelimit.rs:78-104` - Removed redundant `is_empty()` checks before each `remove_older_than()` call. Each `remove_older_than()` already has internal empty check.

### 1.4 Regex DoS Protection ✅

**Status**: COMPLETED

**Changes**:
- `src/mesh/security_challenge.rs:287` - Added `(?{{max=10000}})` regex limit to prevent ReDoS attacks

---

## Wave 2: Mesh & DHT Infrastructure ✅ PARTIALLY COMPLETED

**Focus**: DNS capability, sharding, adaptive quorum, mesh distribution

### 2.1 Edge Node Image Poisoning & Caching ✅ COMPLETED (Phases 1-3)

**Problem**: Edge nodes don't fetch full image poison config; no DHT caching in standalone mode

**Phases**:
1. ✅ Add `SiteImagePoisonConfig` to `is_public()` in `src/mesh/dht/keys.rs`
2. ✅ Add `get_image_poison_config_for_site()` method to `src/mesh/transports/manager.rs`
3. ✅ Update mesh proxy to fetch and use full config
4. 🔄 Add DHT caching to standalone server in `src/http/server.rs` (deferred - requires further architecture review)

**Files Modified**:
- `src/mesh/dht/keys.rs`
- `src/mesh/config.rs`
- `src/mesh/transports/manager.rs`
- `src/mesh/proxy.rs`

### 2.2 YARA Rules Mesh Distribution ✅ COMPLETED (Phases 1-2)

**Problems**:
1. Broadcast uses simple sender instead of mesh transport ✅ Fixed role filtering in forwarder
2. No role filtering on broadcast ✅ Fixed (broadcasts to GLOBAL nodes)
3. No auto-broadcast after feed fetch ✅ Added auto-broadcast on global nodes
4. Pull-only distribution (no push to edges) - unchanged
5. No broadcast acknowledgment tracking 🔄 Infrastructure exists, integration requires architectural changes
6. Delta sync not implemented - deferred

**Phases**:
1. ✅ Fix mesh broadcast transport - use `broadcast_to_all_peers()` with `Some(GLOBAL)` role filtering
2. ✅ Auto-broadcast after `apply_rules_from_feed()` on global nodes
3. 🔄 `BroadcastAckTracker` infrastructure exists but integration incomplete (tracking requires forwarder architectural changes)
4. ❌ Implement delta sync based on client version (deferred)

**Files Modified**:
- `src/mesh/yara_rules.rs`
- `src/mesh/transport.rs`
- `src/worker/unified_server.rs`

### 2.3 Mesh & DHT Security Improvements ✅ PARTIALLY COMPLETED

**Phases**:
| Phase | Description | Status |
|-------|-------------|--------|
| 1 | DNS Server Role Enforcement | COMPLETED |
| 2 | Integrate Raft HA for global node coordination | TODO (large architectural change) |
| 3 | DHT Data Encryption (sensitive records) | TODO |
| 4 | IXFR Incremental Zone Sync | COMPLETED |
| 5 | TOFU Expiration (90-day max) | ✅ DONE |
| 6 | Role Check Centralization | ✅ validate_peer_role exists and is used |
| 7 | Configurable Timeouts | ✅ DONE (max_pending_connections configurable) |
| 8 | Connection Pool Limits | ✅ DONE (max_pending_connections configurable) |

**Files Modified**:
- `src/mesh/global_node_ha.rs`
- `src/mesh/transport.rs`
- `src/mesh/dht/record_store.rs`
- `src/mesh/cert.rs`
- `src/mesh/config.rs`

### 2.4 Threat Intelligence & Honeypot ✅ COMPLETED

**Bugs Fixed**:
1. ✅ **DHT Key Prefix Mismatch** - `src/mesh/threat_intel.rs:1040` changed from `threat:` to `threat_indicator:`
2. ✅ **ThreatSyncResponse Not Processed** - Added handler in `handle_mesh_message()`

**Verification**: HTTP honeypot sharing already works via `block_ip_with_threat_intel()`

---

## Wave 3: WAF & Threat Intelligence

### 3.1 Local Indicator Lookup Optimization ✅ COMPLETED

**Status**: COMPLETED

**Critical Bug Fixed**: `ThreatIntelligenceManager.lookup_local_indicator()` was completely broken due to key format mismatch:

| Location | Issue |
|----------|-------|
| `threat_intel.rs:714` | `handle_incoming_threat` stored with key `"{site_scope}:{indicator_value}"` |
| `threat_intel.rs:1058` | `sync_from_dht` stored with key `"threat_indicator:{indicator_value}"` |
| `threat_intel.rs:896` | `lookup_local_indicator` looked up by bare `indicator_value` |

**Fix Applied**:
- Changed `handle_incoming_threat` to use `indicator.indicator_value.clone()` as key
- Changed `sync_from_dht` to extract `indicator_value` from DHT key and use as local key
- Updated `apply_sync` to use consistent key format
- Fixed `retain` logic to properly compare keys (converted DHT keys to indicator_values)

**Files Modified**: `src/mesh/threat_intel.rs`

### 3.2 Threat Deduplication ✅ COMPLETED

**Status**: COMPLETED

**Changes**:
- Added deduplication check in `handle_incoming_threat()` (lines 724-731) - skips processing if same indicator_value and threat_type already exists
- Deduplication now works correctly due to fixed key format

**Files Modified**: `src/mesh/threat_intel.rs`

---

## Wave 4: File Upload Security

### 4.1 Archive Depth Limits ✅ COMPLETED

**Status**: COMPLETED

**Files Modified**:
- `src/upload/yara_scanner.rs`:
  - Added `archive_max_depth` (default: 3) and `archive_max_size` (default: 100MB) fields to `YaraScanner` struct
  - Updated `YaraScanner::with_timeout()` to accept new parameters
  - Added helper methods: `archive_max_depth()`, `archive_max_size()`, `check_depth_limit()`, `check_size_limit()`, `would_exceed_depth_limit()`, `would_exceed_size_limit()`
  - Updated `create_yara_scanner()` to accept new parameters
- `src/upload/config.rs`:
  - Added `archive_max_depth` and `archive_max_size` fields to `UploadConfig`
  - Added default functions for both fields
  - Fixed `AllowedTypesMode` missing `PartialEq` derive
  - Added `allowed_types_mode` field to `EffectiveUploadConfig` (was missing from initializers)
- `src/config/upload.rs`:
  - Added `archive_max_depth` and `archive_max_size` fields to `UploadDefaults`
  - Added default functions for both fields
- `src/worker/unified_server.rs`:
  - Updated `UploadConfig` initialization to include new fields
- `src/static_files/file_manager.rs`:
  - Added `archive_max_depth` (default: 3) and `archive_max_size` (default: 100MB) to `FileManagerConfig`
  - Added `DEFAULT_ARCHIVE_MAX_DEPTH` and `DEFAULT_ARCHIVE_MAX_SIZE` constants
  - Updated `extract_zip()`, `extract_tar()`, and `extract_tar_gz()` to track cumulative extracted size
  - Added size limit check before extraction to prevent archive bombs

**Configuration**:
```toml
[upload]
archive_max_depth = 3      # Max nested archive extraction depth
archive_max_size = "100MB"  # Max total extracted size from archives
```

### 4.2 Scanner-Local Version Caching ✅ COMPLETED

**Status**: COMPLETED

**Problem**: The YARA scanner's `current_version` was set to `None` when first created. This caused unnecessary IPC calls when `reload_yara_rules_if_needed()` was called before the `YaraRulesManager` was set, and the scanner would never get synchronized properly.

**Solution**: Set an initial version hash when the scanner is first created in `with_timeout()`. The version is computed as a SHA256 hash of the initial rules content, prefixed with "init-".

**Files Modified**:
- `src/upload/yara_scanner.rs`:
  - Added `sha2::{Digest, Sha256}` import
  - In `with_timeout()`: After compiling rules, compute `SHA256` hash of rules content and set as initial `current_version` (format: `init-{first_16_chars_of_hash}`)
  - This ensures the scanner always has a version, even before `YaraRulesManager` is set

**Benefits**:
- Scanner version is no longer `None` after initial creation
- When `reload_yara_rules_if_needed()` compares scanner version with manager version, it correctly detects when reload is needed
- Reduces IPC overhead by ensuring version comparison works correctly from the start

### 4.3 Path-Specific Allowlist Integration ✅ COMPLETED

**Status**: COMPLETED

**Problem**: `EffectiveUploadConfig` did not preserve the `mode` (Allowlist/Blocklist) from path-specific `AllowedTypesConfig`. The MIME type validation code directly called `is_mime_allowed()` which only implements allowlist semantics, ignoring the blocklist mode entirely.

**Solution**: 
1. Added `allowed_types_mode: AllowedTypesMode` field to `EffectiveUploadConfig`
2. Updated `effective_config_for_path()` to detect when path has explicit `allowed_types` config (non-empty mime_types OR non-default mode) and use path's mode instead of global mode
3. Added `is_mime_allowed()` method to `EffectiveUploadConfig` that respects the mode
4. Updated all MIME type validation call sites to use `effective_config.is_mime_allowed()` instead of directly calling `is_mime_allowed()` with just the mime_types list
5. Added `PartialEq` derive to `AllowedTypesMode` for comparison

**Files Modified**:
- `src/upload/config.rs`:
  - Added `allowed_types_mode: AllowedTypesMode` field to `EffectiveUploadConfig`
  - Added `is_mime_allowed(&self, mime_type: &str) -> bool` method to `EffectiveUploadConfig`
  - Added `PartialEq` derive to `AllowedTypesMode`
  - Updated `effective_config_for_path()` to properly track and use path-specific mode
- `src/upload/mod.rs`:
  - Updated 4 MIME type validation call sites to use `effective_config.is_mime_allowed()`

**Benefits**:
- Path-specific allow/block lists now work correctly with both Allowlist and Blocklist modes
- When a path specifies `allowed_types { mode: Blocklist, mime_types: ["application/pdf"] }`, PDF files are blocked while all other types are allowed
- Backward compatible: paths without explicit `allowed_types` config inherit global mode

### 4.4 TAR Extraction Path Traversal Fix

**Location**: `src/static_files/file_manager.rs:948-1006` (extract_tar), `src/static_files/file_manager.rs:1017-1085` (extract_tar_gz)

**Status**: ✅ Completed

**Issue**: TAR extraction lacked explicit path traversal protection (ZIP had it)

**Fix**: Added canonical path validation to both `extract_tar()` and `extract_tar_gz()`:
- Added `dest_canonical` computation before entry iteration
- For each entry, computed `outpath_canonical` with fallback manual path resolution (same pattern as ZIP)
- Added traversal check: `if !outpath_canonical.starts_with(&dest_canonical)` returns `FileManagerError::InvalidPath`
- Error messages: "Path traversal attempt detected in TAR archive" and "Path traversal attempt detected in TAR.GZ archive"

**Verification**:
- `cargo check --lib` passes
- `cargo clippy --lib -- -D warnings` passes

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
