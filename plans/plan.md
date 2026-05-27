# SynVoid Implementation Plan

> **Note**: This file contains implementation plans for remaining items.
> Completed items have been pruned. See git history for completed item details.

---

## Priority Key

- **P0**: Critical security/regression bugs
- **P1**: High-impact bugs or architectural issues
- **P2**: Medium-priority improvements
- **P3**: Low-priority documentation/accuracy fixes

---

## Wave 1: Critical Security Fixes (P0/P1 - Execute Sequentially)

These items have security implications or are blocking other work.

### BUG-DNS-1: HickoryRecursor DNSSEC Policy Always SecurityUnaware

**Priority**: HIGH
**Status**: Active
**Location**: `src/dns/server.rs` or `src/dns/recursive.rs`

**Issue**: Even when `enable_dnssec=true` is configured, the HickoryRecursor uses `SecurityUnaware` policy, meaning DNSSEC validation is not actually performed.

**Analysis**:
- Check `hickory_proto::config::SecOpts` for `authentic_data` / `check_dnssec` settings
- HickoryRecursor may need `with_security_policy()` builder method
- Requires investigation of hickory 0.26+ API for DNSSEC policy configuration

**Verification**:
```bash
cargo test --lib dns
# Also manual testing with dnsviz or dig +dnssec
```

---

### BUG-DNS-4: HickoryResolver always returns is_dnssec_validated: false

**Priority**: HIGH
**Status**: Active
**Location**: `src/dns/resolver.rs` or similar

**Issue**: The resolver unconditionally returns `is_dnssec_validated: false` regardless of actual DNSSEC validation results.

**Required Fix**: Wire actual DNSSEC validation status from hickory into the response.

---

## Wave 2: High-Priority Bugs (P2 - Can Parallelize)

### HTTP Server Improvements

#### IMPROVE-1: Consolidate HTTP/3 Body Collection with HTTP/1.1

**Priority**: P2
**Status**: Active
**Location**: `src/http3/` and `src/http/server.rs:4662`

**Issue**: HTTP/3 uses ad-hoc body collection implementation while HTTP/1.1 uses `collect_body_with_chunk_waf()`. This inconsistency makes error handling and WAF enforcement unpredictable.

**Required Fix**:
1. Extract `collect_body_with_chunk_waf()` to a shared location if not already shared
2. Ensure HTTP/3 path uses the same body collection logic
3. Standardize error responses for body collection failures

**Files to examine**:
- `src/http/server.rs:4662` - `collect_body_with_chunk_waf`
- `src/http3/` - HTTP/3 request handling
- `src/waf/mod.rs` - WAF integration

---

#### BUG-HTTP-4: request_body_size double assignment

**Priority**: P2
**Status**: Active
**Location**: `src/http/server.rs:1579`

**Issue**: `request_body_size` is assigned twice - first by `collect_body_with_chunk_waf()` then overwritten at line 1579.

**Required Fix**: Remove the double assignment or ensure only one source sets `request_body_size`.

---

### Auth Module

#### BUG-AUTH-1/2: Username Validation Missing

**Priority**: P2
**Status**: Active
**Location**: `src/auth/` module

**Issue**: No username length or character validation. Missing validation could allow:
- Empty usernames
- Excessively long usernames (DoS vector)
- Special characters that could enable injection attacks

**Required Fix**:
1. Add minimum username length validation (recommend: 1-255 characters)
2. Add character restrictions (alphanumeric, underscore, hyphen, dot - common patterns)
3. Document the validation rules

---

#### BUG-AUTH Config: Align max_failed_attempts default

**Priority**: P2
**Status**: Active
**Location**: `src/waf/mod.rs` vs documentation

**Issue**: WafCore uses default of 5 failed attempts, but documentation says 3.

**Resolution**: Either change WafCore default to 3 OR update documentation to reflect 5.

---

### Proxy Module

#### EWMA Weighting Direction Investigation

**Priority**: P2
**Status**: Active
**Location**: `src/upstream/pool.rs` or `src/proxy/`

**Issue**: Documentation claims 90% weight to historical latency, but implementation may give 90% to OLD value instead of 90% to historical.

**Required Fix**:
1. Verify actual formula in `PeakEwma` calculation
2. If incorrect, fix the weighting direction
3. Update documentation to match actual implementation

**Formula under review**:
```rust
// Current claim: 90% to historical
// Actual implementation may be: 90% to old value (opposite)
```

---

### Platform Module

#### BUG-PL-3: Windows Socket FD Passing Not Functional

**Priority**: P2
**Status**: Active
**Location**: `src/platform/windows_impl.rs:71-99`

**Issue**: `WindowsSocketFDPassing` returns `NotSupported`. Port-swap upgrade mode may not work on Windows.

**Options**:
1. Implement proper Windows socket FD passing using `DuplicateHandle()`
2. OR update documentation to clarify Windows limitation for port-swap mode

---

### WAF Module

#### BUG-WAF-3: SiteConnectionLimiter Not Wired into WafCore

**Priority**: P2
**Status**: Active
**Location**: `src/waf/mod.rs:332-334`

**Issue**: `SiteConnectionLimiter` is dead code - never instantiated and not wired into WafCore. Per-site connection limiting may not work.

**Required Fix**:
1. Wire `SiteConnectionLimiter` into WafCore pipeline, OR
2. Remove the dead code (`src/waf/traffic_shaper/limiter.rs:306-346`)

---

## Wave 3: Documentation & Consistency Fixes (P3 - Can Parallelize)

### Documentation Fixes

#### Auth Module Documentation
- [ ] Fix hardcoded constants documentation (min_password_length: 8, session_refresh_threshold: 0.5)
- [ ] Add password complexity validation
- [ ] Add min_password_length configuration option
- [ ] Add session_refresh_threshold configuration option
- [ ] Document update_password session invalidation behavior
- [ ] Add password_last_changed_at tracking

#### Proxy Module Documentation
- [ ] Update HTTP/2 documentation (configurable via `with_http2()`)
- [ ] Fix `calculate_backoff` documentation (missing jitter, 30s cap)
- [ ] Fix line references in `proxy_deep_dive.md`
- [ ] Update `BackendType` documentation (shows Single/Pool/Fallback vs actual 11 variants)

#### HTTP Server Documentation
- [ ] Document `serve()` mesh-only limitation
- [ ] Clarify backend dispatch boundary
- [ ] Add metrics for `collect_body_with_chunk_waf`
- [ ] Standardize error responses for body collection failures

#### Worker Module Documentation
- [ ] Update HTTP/2 "hardcoded" claim (actually configurable)
- [ ] Fix BufferPool tier count (doc says 3, actual has 4 tiers)
- [ ] Reorganize health endpoint documentation
- [ ] Document mesh control plane decision (runs in Supervisor, not worker)

#### DNS Module Documentation
- [ ] Clarify recursive DNSSEC limitation (security unaware)
- [ ] Document ECDSA algorithm gap
- [ ] Add NAPTR/CERT/DNAME AXFR support
- [ ] Add TrustAnchorState unit tests for RFC 5011 transitions

#### Mesh Module Documentation
- [ ] Fix `src/heap/raft/` → `src/mesh/raft/` typo in `architecture/mesh.md:109`
- [ ] Update file listing with missing files (cert_dist.rs, org_key_manager.rs, etc.)
- [ ] Clarify DhtSyncRequest verification status
- [ ] Add MESH-14 reference to deferred items

#### Spin Documentation
- [ ] Fix spin cold-start line reference (line 289-303, not 258)
- [ ] Document JSON header serialization for Spin vs binary for raw WASM
- [ ] Fix module organization description
- [ ] Document lock acquisition order consistency

#### Layer 3.5 Documentation
- [ ] Update ACME DNS path in `architecture/layer_3_5_deep_dive.md:176` (wrong path)

#### WAF Documentation
- [ ] Update bot detection line count (~494 → ~580)
- [ ] Document StreamingWafCore chunk size constants
- [ ] Document multipart state machine transitions

#### Config Documentation
- [ ] Fix "27 sections" → "28 sections" in config documentation
- [ ] Add GranianConfig field coverage verification

---

## Wave 4: Feature Enhancements (Lower Priority)

### Serverless Module

#### Missing Documentation
- [ ] Document `scheduler.rs` module (`ServerlessScheduler`, `TimerEntry`, `TimerPayload`)
- [ ] Add `mesh` feature gate notes to `handle_serverless_function`
- [ ] Document event subscription system
- [ ] Document streaming API (`handle_serverless_function_streaming`)
- [ ] Add missing return types to documented functions
- [ ] Document Async Compilation API
- [ ] Document `get_global_serverless_registry`

#### BUG-SL-1: handle_serverless_function feature-gated
- Location: `src/serverless/mod.rs:13-18`
- Issue: Function only exported when `#[cfg(feature = "mesh")]`
- Fix: Document this limitation clearly

#### BUG-SL-3: Non-existent shutdown method documented
- Location: `architecture/serverless.md:284`
- Issue: Documentation references `pub async fn shutdown(&self)` on ServerlessManager but it doesn't exist
- Fix: Remove from docs or implement actual method

### Plugin Module

#### Missing Documentation
- [ ] Document `invoke_handler_streaming` in deep dive
- [ ] Add `ServerlessManager` compilation manager to deep dive
- [ ] Add `PooledInstance` conversion diagram
- [ ] Verify Spin v2 TOML support (may only support JSON manifests)
- [ ] Consider adding global metrics for serverless similar to `get_all_wasm_metrics()`
- [ ] Document `SERVERLESS_ENGINE_POOL` global static

#### BUG-PLUGIN-3: No global metrics for serverless
- Location: `src/serverless/instance_pool.rs`
- Issue: No equivalent to `wasm_metrics.rs` global aggregation
- Fix: Add `get_all_serverless_metrics()` function

### App Handlers

#### APP-15: Remove "Known limitation" note
- Issue: FastCGI streaming marked as limitation but is FIXED (2026-05-27)
- Fix: Update `app_handlers.md` and `plugin_deep_dive.md`

#### QuicTunnel reference fix
- Issue: Doc says `src/tunnel/upstream.rs:120` but actual handling is via `UpstreamAddress::QuicTunnel`
- Fix: Update to `src/upstream/address.rs:27`

#### Spin Instance Pooling Clarification
- Issue: Doc conflates Spin `cached_instances` (5-min timeout) with Serverless `InstancePool`
- Fix: Document difference clearly

---

## Deferred Items (Architectural Changes Required)

These items require significant architectural work and are tracked separately:

| ID | Issue | Reason |
|----|-------|--------|
| **MESH-14** | Source Node ID Binding Validation | Fundamental TLS/cert identity binding - requires breaking changes |
| **HTTP2-POOL** | ErasedHttpClient HTTP/2 support | Requires hyper-util API investigation |
| **SUP-1** | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS |
| **MR-4** | DhtSyncRequest has no auth | Breaking protobuf protocol change |
| **DNS-2** | QueryCoalescer max_wait_ms | DNS-2 - documented limitation, may not be fixable |
| **PR-6** | ProxyHeadersConfig not passed through send_single_request | Enhancement, not a bug |

---

## HTTP/2 Pooling Implementation Plan (When Resolved)

**Status**: DEFERRED - hyper-util API incompatible

When the hyper-util API issue is resolved, implement HTTP/2 pooling:

### Step 1: HTTP2-POOL-1
- Location: `src/http_client/erased_pool.rs:125-127`
- Add connection fields: `io`, `sender`, `driver` task
- Implement proper HTTP/2 connection handshake

### Step 2: HTTP2-POOL-2
- Location: `src/http_client/erased_pool.rs`
- Add `inner_h2` HashMap for HTTP/2 connections
- Update `checkout()` to route based on `key.is_http2`

### Step 3: HTTP2-POOL-3
- Location: `src/http_client/erased_pool.rs:426-450`
- Use `is_http2` to select HTTP/1.1 or HTTP/2 pool

### Step 4: HTTP2-POOL-4
- Location: `src/http_client/mod.rs:374,420`
- Remove hardcoded `http2_only(false)` or make configurable

---

## Quick Reference: Key Files

| Component | File | Lines |
|-----------|------|-------|
| QuorumManager | `src/mesh/dht/quorum.rs` | 316-437 |
| RaftClient | `src/mesh/raft/client.rs` | 186-213 |
| FastCGI Client | `src/fastcgi/mod.rs` | 98-164 |
| DrainManager | `src/overseer/drain_manager.rs` | 20-368 |
| SupervisorProcess | `src/supervisor/process.rs` | 186-249 |
| ProxyServer | `src/proxy/mod.rs` | 73-226 |
| ErasedHttpClient | `src/http_client/erased_pool.rs` | 415-456 |
| ML-KEM Key Exchange | `src/mesh/ml_kem_key_exchange.rs` | 204-265 |
| Spin Runtime | `src/spin/runtime.rs` | 289-303 |
| WafCore | `src/waf/mod.rs` | 1-400+ |

---

## Implementation Status (2026-05-27)

### Completed Items (Pruned - See Git History)

| ID | Item | Status | Notes |
|----|------|--------|-------|
| MESH-15-FIX-1 | is_request_complete() lock release | ✅ DONE | Fixed with early return using read lock |
| MESH-15-FIX-4 | MeshRaftNetwork::send_raw() retry | ✅ DONE | Added exponential backoff (100ms/200ms/400ms) |
| WRK-BUG-1-FIX-1 | HTTP/2 config wiring to ProxyServer | ✅ DONE | site_config.proxy.http2 now wired |
| WRK-BUG-1-FIX-2/3 | is_http2 to executor/dispatch paths | ✅ DONE | Uses send_request_erased_streaming |
| PL-5-FIX-1-4 | DrainManager port to Supervisor | ✅ DONE | Drain-aware shutdown implemented |
| APP-15-FIX-1-4 | FastCGI Streaming | ✅ DONE | New streaming.rs module, feature flag added |
| TUNNEL-FIX | Deprecated TunnelBackend removal | ✅ DONE | Struct removed from upstream.rs |
| Spin cold-start | Instance reuse with 5-min idle | ✅ DONE | get_or_create_instance() caching |
| DNS Cookie Server | Wired at query.rs:640-662 | ✅ DONE | validate_cookie() integration |
| PooledInstance DHT | Fixed allowed_dht_prefixes | ✅ DONE | pool.rs:15-26 properly resets |
| BUG-ROUTER-1 | Hardcoded port 80 | ✅ DONE | Uses server_port parameter |
| BUG-PROXY-1 | retry_config applied | ✅ DONE | Uses parameter value not None |
| is_admin_required_for_tun | Fixed | ✅ DONE | Returns false for Unix, true for Windows |

### Deferred/Cancelled Items

| ID | Item | Reason |
|----|------|--------|
| MESH-15-FIX-2 | Partition detection in start_request() | Not feasible - QuorumManager has no topology access |
| MESH-15-FIX-3 | Background cleanup for stale requests | Not needed - existing timeout handles cleanup |
| HTTP2-POOL-1-4 | ErasedHttpClient HTTP/2 pooling | Deferred - hyper http2_client::handshake() API incompatible |

---

## Parallelization Waves Summary

| Wave | Items | Parallelizable | Priority |
|------|-------|----------------|----------|
| **Wave 1** | BUG-DNS-1, BUG-DNS-4 | No (sequential) | P0/P1 |
| **Wave 2** | HTTP improvements, Auth fixes, EWMA, PL-3, WAF-3 | Yes | P2 |
| **Wave 3** | All documentation fixes | Yes | P3 |
| **Wave 4** | Feature enhancements | Yes | Low |

---

*Last Updated: 2026-05-27*
*Plan consolidated from review plans*