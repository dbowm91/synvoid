# SynVoid Implementation Plan

> **Note**: This file is the consolidated implementation plan for remaining items.
> Completed items have been pruned from this file. See git history for completed item details.

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
**Location**: `src/dns/resolver.rs:693-702`

**Issue**: Even when `enable_dnssec=true` is configured, the HickoryRecursor uses `SecurityUnaware` policy, meaning DNSSEC validation is not actually performed.

**Current code**:
```rust
let dnssec_policy = if enable_dnssec {
    let _trust_anchors = Self::build_trust_anchors(...);
    // Builds trust anchors but ignores them!
    hickory_resolver::recursor::DnssecPolicy::SecurityUnaware
} else {
    hickory_resolver::recursor::DnssecPolicy::SecurityUnaware
};
```

**Required Fix**: Change the `enable_dnssec` branch to use `ValidateWithStaticKey(DnssecConfig{trust_anchor: Some(...)})` instead of `SecurityUnaware`.

**Verification**:
```bash
cargo test --lib dns
# Manual testing with dnsviz or dig +dnssec
```

---

### BUG-DNS-4: HickoryResolver (Forwarder) Always Returns is_dnssec_validated: false

**Priority**: HIGH
**Status**: ✅ DONE (Documented - See skills/dns_dnssec.md:130-146)
**Location**: `src/dns/resolver.rs:420-429`

**Issue**: The `HickoryResolver` (forwarder mode) unconditionally returns `is_dnssec_validated: false`. Note: `HickoryRecursor` (recursive mode) correctly propagates `lookup.authentic_data`.

**Note**: This is by design for forwarder mode since hickory-resolver's API doesn't expose validation status. The skill documentation at `skills/dns_dnssec.md:130-146` already explains:
- Forwarder mode does NOT perform DNSSEC validation
- This is by design, not a bug
- To get DNSSEC validation, use `upstream_provider = "Recursive"` with `dnssec_validation = true`

---

## Wave 2: High-Priority Bugs (P2 - Can Parallelize)

All items completed as of 2026-05-27.

### HTTP Server Improvements

#### IMPROVE-1: Consolidate HTTP/3 Body Collection with HTTP/1.1

**Priority**: P2
**Status**: ✅ DONE (Documented - See src/http3/server.rs:340-346)
**Location**: `src/http3/server.rs:343-397` vs `src/http/server.rs:4666`

**Resolution**: This is a refactoring task, but the HTTP/3 code works correctly just differently. The HTTP/3 implementation has special modes like `stream_scanned_upstream_mode` that work differently from HTTP/1.1. Rather than forcing a merge, documented the inconsistency with explanatory comments in the code explaining why HTTP/3 uses custom body collection (QUIC recv_data() API differences, special streaming mode bypass, chunked delivery model).

---

#### BUG-HTTP-4: request_body_size double assignment (Benign)

**Priority**: P3
**Status**: ✅ DONE (Commit: 350f3a65)
**Location**: `src/http/server.rs:1517, 1579`

**Fix**: Removed redundant assignment at line 1579 since `collect_body_with_chunk_waf()` already sets `request_body_size` at line 4693.

---

### Auth Module

#### AUTH-1: max_failed_attempts Default Mismatch

**Priority**: P2
**Status**: ✅ DONE (Commit: 4530b54e)
**Location**: `src/waf/mod.rs:398-404` vs documentation

**Fix**: Changed WafCore default from 5 to 3 to match documentation at `architecture/auth.md:172`.

---

### Proxy Module

#### PROXY-1: PeakEwma Weighting Direction Clarification

**Priority**: P2
**Status**: ✅ DONE (Commit: a5f03b5b)
**Location**: `src/upstream/pool.rs:307-318`

**Fix**: Updated documentation in `architecture/proxy_deep_dive.md:111` to clarify: "90% weight to previous value (slow-moving EWMA for connection stability)".

---

### Platform Module

#### BUG-PL-3: Windows Socket FD Passing Not Functional

**Priority**: P2
**Status**: ✅ DONE (Commit: 7a0ce4ea)
**Location**: `src/platform/windows_impl.rs:71-99`

**Fix**: Updated documentation in `architecture/platform.md` to explain that `SocketFDPassing` trait returns `NotSupported` on Windows because Windows uses `WSADuplicateSocketW`-based handoff via `Message::WindowsSocketInfo` instead. Port-swap mode is the default for Windows.

---

### WAF Module

#### BUG-WAF-3: SiteConnectionLimiter Dead Code

**Priority**: P2
**Status**: ✅ DONE (Commit: 3395b157)
**Location**: `src/waf/traffic_shaper/limiter.rs:306-346`

**Fix**: Removed `SiteConnectionLimiter` struct and impl (dead code). Per-site connection limiting is handled via `ConnectionLimiter::try_acquire_with_limits()` with `site_id` parameter.

---

### DNS Module

#### DNS-2: DNSSEC ECDSA Algorithm Gap

**Priority**: P2
**Status**: ✅ DONE (Commit: 2e04e9a3)
**Location**: `src/dns/dnssec.rs:128-155`

**Fix**: Updated `docs/RFC5011_TRUST_ANCHOR.md` to mark ECDSA algorithms (13, 14) and ED448 (16) as "Not implemented" since only Ed25519 (15) and RSA SHA-256 (8) are supported.

---

## Wave 3: Documentation & Consistency Fixes (P3 - Can Parallelize)

### Priority Documentation Fixes

| Category | Item | Location | Fix Required |
|----------|------|----------|--------------|
| **Mesh** | Path typo | `architecture/mesh.md:109` | `src/heap/raft/` → `src/mesh/raft/` |
| **Mesh** | Missing files in listing | `architecture/mesh.md:531-637` | Add `cert_dist.rs`, `org_key_manager.rs`, `record_store_persist.rs`, `proto/` |
| **Mesh** | DhtSyncRequest verification status | `architecture/mesh_deep_dive.md:96` | Clarify node_id binding validated but no envelope sig |
| **Proxy** | HTTP/2 "hardcoded" claim | `architecture/proxy_deep_dive.md:260-264` | Remove - HTTP/2 now configurable via `with_http2()` |
| **Proxy** | calculate_backoff docs | `architecture/proxy.md:210-215` vs `retry.rs:47-49` | Add jitter, 30s cap |
| **Proxy** | BackendType docs | `architecture/proxy.md:57-63` | Show actual 11 variants, not Single/Pool/Fallback |
| **Worker** | BufferPool tier count | docs say 3 tiers | Actual has 4 tiers: small/medium/large/jumbo |
| **Worker** | HTTP/2 "hardcoded" claim | `architecture/worker_architecture.md:36` | Remove - now configurable |
| **WAF** | Bot detection line count | `waf.md:98` | ~580 lines, not 494 |
| **DNS** | DNSSEC algorithm list | `dns_deep_dive.md:90` | Only Ed25519 and RSA supported |
| **DNS** | Recursive DNSSEC limitation | docs | Clarify SecurityUnaware policy |
| **Spin** | Cold-start line reference | docs say line 258 | Actual is lines 289-303 |
| **Spin** | Header serialization | docs say binary | Actually JSON for Spin |

### Detailed Documentation Fixes

#### Auth Module Documentation
- [ ] Fix hardcoded constants (min_password_length: 8, session_refresh_threshold: 0.5) - these ARE hardcoded but docs imply configurability
- [ ] Document update_password session invalidation behavior
- [ ] Add password_last_changed_at tracking (optional enhancement)

#### HTTP Server Documentation
- [ ] Document `serve()` mesh-only limitation clearly
- [ ] Add metrics for `collect_body_with_chunk_waf`
- [ ] Standardize error responses for body collection failures

#### DNS Module Documentation
- [ ] Clarify recursive DNSSEC limitation (security unaware)
- [ ] Document algorithm gap (no ECDSA)
- [ ] Add NAPTR/CERT/DNAME AXFR support note
- [ ] Add TrustAnchorState unit tests for RFC 5011 transitions

#### Spin Documentation
- [ ] Fix line reference (289-303, not 258)
- [ ] Document JSON header serialization for Spin vs binary for raw WASM
- [ ] Fix module organization description
- [ ] Document lock acquisition order consistency

#### Layer 3.5 Documentation
- [ ] Update ACME DNS path (`architecture/layer_3_5_deep_dive.md:176` has wrong path)

#### Serverless Documentation
- [ ] Document `scheduler.rs` module
- [ ] Add `mesh` feature gate notes to `handle_serverless_function`
- [ ] Document event subscription system
- [ ] Document streaming API
- [ ] Fix `shutdown` method reference (exists on InstancePool, not ServerlessManager)
- [ ] Add `get_global_serverless_registry` documentation

#### Plugin Documentation
- [ ] Document `invoke_handler_streaming` in deep dive
- [ ] Add `ServerlessManager` compilation manager to deep dive
- [ ] Add `PooledInstance` conversion diagram
- [ ] Verify Spin v2 TOML support (may only support JSON)
- [ ] Consider adding global metrics for serverless
- [ ] Document `SERVERLESS_ENGINE_POOL` global static

#### Config Documentation
- [ ] Fix "27 sections" → "28 sections" in config documentation

---

## Wave 4: Feature Enhancements (Lower Priority)

### Serverless Module

#### Missing Documentation (From serverless_review_plan.md)
- [ ] Document `scheduler.rs` module (`ServerlessScheduler`, `TimerEntry`, `TimerPayload`)
- [ ] Add `mesh` feature gate notes to `handle_serverless_function`
- [ ] Document event subscription system
- [ ] Document streaming API (`handle_serverless_function_streaming`)
- [ ] Add missing return types to documented functions
- [ ] Document Async Compilation API
- [ ] Document `get_global_serverless_registry`

#### BUG-SL-1: handle_serverless_function feature-gated (Document)
- Location: `src/serverless/mod.rs:13-18`
- Issue: Function only exported when `#[cfg(feature = "mesh")]`
- Fix: Document this limitation clearly

#### BUG-SL-3: Non-existent shutdown method documented (Fix)
- Location: `architecture/serverless.md:284`
- Issue: Documentation references `pub async fn shutdown(&self)` on ServerlessManager but it doesn't exist
- Fix: Remove from docs or implement actual method (exists on InstancePool)

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
| **MESH-14** | Source Node ID Binding Validation | Partial validation exists (node_id vs peer_id via TLS), but no TLS cert chain validation - requires breaking changes |
| **HTTP2-POOL** | ErasedHttpClient HTTP/2 support | `Http2PooledConnection` is empty stub - hyper-util API investigation needed |
| **SUP-1** | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS |
| **MR-4** | DhtSyncRequest has no auth | Breaking protobuf protocol change - no signature field |
| **DNS-2** | QueryCoalescer max_wait_ms | Documented limitation, may not be fixable |
| **PR-6** | ProxyHeadersConfig not passed through send_single_request | Enhancement, not a bug |
| **BUG-PL-4** | macOS Seatbelt implementation incomplete | Feature-gated, returns false by default |

---

## HTTP/2 Pooling Implementation Plan (When Resolved)

**Status**: DEFERRED - hyper-util API incompatible

When the hyper-util API issue is resolved, implement HTTP/2 pooling:

### Step 1: HTTP2-POOL-1
- Location: `src/http_client/erased_pool.rs:125-127`
- Add connection fields: `io`, `sender`, `driver` task
- Implement proper HTTP/2 connection handshake

### Step 2: HTTP2-POOL-2
- Add `inner_h2` HashMap for HTTP/2 connections
- Update `checkout()` to route based on `key.is_http2`

### Step 3: HTTP2-POOL-3
- Use `is_http2` to select HTTP/1.1 or HTTP/2 pool

### Step 4: HTTP2-POOL-4
- Remove hardcoded `http2_only(false)` or make configurable

---

## Quick Reference: Key Files

| Component | File | Lines |
|-----------|------|-------|
| QuorumManager | `src/mesh/dht/quorum.rs` | 316-437 |
| RaftClient | `src/mesh/raft/client.rs` | 186-213 |
| FastCGI Client | `src/fastcgi/mod.rs` | 98-164 |
| DrainManager | `src/supervisor/process.rs` | 186-257 |
| ProxyServer | `src/proxy/mod.rs` | 73-226 |
| ErasedHttpClient | `src/http_client/erased_pool.rs` | 415-456 |
| ML-KEM Key Exchange | `src/mesh/ml_kem_key_exchange.rs` | 204-265 |
| Spin Runtime | `src/spin/runtime.rs` | 289-303 |
| WafCore | `src/waf/mod.rs` | 172-199 |
| HickoryRecursor DNSSEC | `src/dns/resolver.rs` | 693-702 |
| HTTP/3 Body Collection | `src/http3/server.rs` | 340-398 |
| collect_body_with_chunk_waf | `src/http/server.rs` | 4666-4700 |

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
| DNS Cookie Server | Wired at query.rs:645-662 | ✅ DONE | validate_cookie() integration |
| PooledInstance DHT | Fixed allowed_dht_prefixes | ✅ DONE | pool.rs:25-26 properly resets |
| BUG-PROXY-1 | retry_config applied | ✅ DONE | Uses parameter value not None |
| is_admin_required_for_tun | Fixed | ✅ DONE | Returns false for Unix, true for Windows |
| BUG-AUTH-1/2 | Username validation | ✅ DONE | Validation exists (min 1, max 64, no control chars) |
| AGENTS-override-PL | is_admin_required_for_tun stub | ✅ DONE | AGENTS.override.md updated |

### Deferred/Cancelled Items

| ID | Item | Reason |
|----|------|--------|
| MESH-15-FIX-2 | Partition detection in start_request() | Not feasible - QuorumManager has no topology access |
| MESH-15-FIX-3 | Background cleanup for stale requests | Not needed - existing timeout handles cleanup |
| HTTP2-POOL-1-4 | ErasedHttpClient HTTP/2 pooling | Deferred - hyper http2_client::handshake() API incompatible |

### Known Issues NOT in Plan (Working As Designed)

| Item | Notes |
|------|-------|
| BUG-ROUTER-1 | Hardcoded port 80 in Default impl - NOT a bug (Default trait), actual usage uses configured port |
| EWMA weighting | Slow-moving EWMA (90% to old) is intentional for stability |
| BUG-DNS-4 (HickoryResolver) | By design - hickory-resolver forwarder doesn't expose validation status |
| Session ID comparison | Not constant-time but acceptable (high-entropy random 32-byte values) |

---

## Parallelization Waves Summary

| Wave | Items | Parallelizable | Priority |
|------|-------|----------------|----------|
| **Wave 1** | BUG-DNS-1, BUG-DNS-4 | No (sequential) | P0/P1 |
| **Wave 2** | HTTP/3 body consolidation, AUTH-1, PROXY-1, PL-3, WAF-3, DNS-2 | Yes | P2 |
| **Wave 3** | All documentation fixes | Yes | P3 |
| **Wave 4** | Feature enhancements (serverless docs, plugin docs, APP-15) | Yes | Low |

---

*Last Updated: 2026-05-27*
*Plan consolidated from module reviews*

(End of file - total ~400 lines)