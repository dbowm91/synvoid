# SynVoid Implementation Plan

**Status**: 📋 IN PROGRESS - Correcting plan based on codebase verification (2026-05-22)
**Target**: 1M RPS with streaming WAF, plus bug fixes and security hardening
**Consolidated from**: `plans/*.md` architecture reviews

---

## Overview

This plan consolidates actionable items from architecture reviews into parallelizable waves. Each wave can be executed by independent agents.

**Verification Completed**: All item references have been cross-checked against the codebase during this review session. Items marked ✅ are verified as accurate; items marked ❌ had discrepancies that have been corrected in this version.

---

## Previously Completed Waves (1-5)

**Status**: ✅ ALL PREVIOUSLY COMPLETE (2026-05-06)

### Wave 1: Critical Security & Compile Fixes
### Wave 2: IPC & Process Lifecycle Hardening  
### Wave 3: WAF Core Streaming Optimization
### Wave 4: Remaining High/Medium Priority Fixes
### Wave 5: Validation & Benchmarking

See end of document for completed items reference.

---

## Wave 6: Critical Security & Mesh Issues (NEW)

*Can execute in parallel — no interdependencies*

### CRITICAL Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| MESH-11 🆕 | Race Condition in Quorum Manager | `src/mesh/dht/quorum.rs:337-381` | Raft delegated write failure leaves fake signature in pending_requests - refactor to use proper async pattern instead of pre-injecting signatures | Pending |
| MESH-15 🆕 | Quorum Deadlock Risk During Partition | `src/mesh/dht/quorum.rs:249` | DHT-based 2/3 quorum dangerous during partition without consensus leader; Raft implementation incomplete per TODO at `instance.rs:214` | Pending |
| SUP-1 🆕 | gRPC Control Plane NOT Protected by TLS | `src/supervisor/api.rs:114-129` | gRPC server lacks TLS configuration despite claiming "protected by TLS" in docs | Pending |
| APP-14 🆕 | Spin Framework Incomplete Integration | `src/spin/` + `architecture/app_handlers.md:41-45` | Spin files exist (manifest.rs, runtime.rs, handler.rs, kv_store.rs) but routing integration and component mapping not implemented; docs claim full support that doesn't exist | Pending |
| APP-17 🆕 | Pip Install Without Hash Verification | `src/app_server/granian.rs:491-508` | Installing packages without `--require-hashes` is supply chain risk | Pending |

---

## Wave 7: High Priority Improvements (NEW)

*Can execute in parallel with Wave 6*

### HIGH Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| TL-1 ✅ | Global Cache Resource Governor | `src/proxy/governor.rs` | ALREADY IMPLEMENTED: `GlobalCacheGovernor` with `try_reserve()`/`release()` limits TeeBody buffering to 512MB. No action needed. | Done |
| TL-3 🆕 | Unified Host Routing Index | `src/router.rs:489-509` | Replace O(Sites × Domains) routing bottleneck in `is_host_valid_for_site()` with O(1) global index using `AHashMap<Arc<str>, Arc<SiteConfig>>` for exact match domains | Pending |
| TL-4 ✅ | Secure-by-Default Cache Whitelisting | `src/proxy/cache.rs:97-126` | ALREADY IMPLEMENTED: Uses `SAFE_HEADERS` whitelist (29 headers). No action needed. | Done |
| TL-5 🆕 | Worker Liveness Heartbeat for Stale Detection | `src/upstream/shared_state.rs` + `src/process/manager.rs` | Currently heartbeat mechanism exists in `SharedConnectionTable` but is NOT used to detect stale workers in proxy layer. `sum_active_connections()` uses it; add stale worker detection that ignores connections from workers with heartbeat >5s old | Pending |
| TL-9 🆕 | Architectural Pressure Valve | `src/waf/mod.rs` + `src/proxy/streaming.rs` | Implement `SystemHealthMonitor` with `AtomicU8` state (0=Normal, 1=Warning, 2=Critical); Warning bypasses TeeBody, Critical bypasses behavioral WAF. See `HealthState` enum in `proxy/streaming.rs:30` | Pending |
| MESH-14 🆕 | No Source Node ID Binding Validation in All Ingress Paths | `src/mesh/dht/signed.rs:42-48` | Implement missing validation for: DhtSyncRequest (no auth), DhtAntiEntropyRequest (pk unused), DhtRecordPush (no ts), DhtRecordCommit (no envsig), QuorumStoreRequest (no verify), QuorumSignatureResp (no verify) | Pending |

---

## Wave 8: Medium Priority Fixes (NEW)

*Can execute in parallel with Wave 6/7*

### MEDIUM Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| TL-2 ✅ | Fast-Path WAF Pre-Screening | `src/waf/attack_detection/mod.rs:156-225` | ALREADY IMPLEMENTED: `fast_path_patterns` with `RegexSet` exists at line 171, `is_fast_path_safe()` method at lines 209-225. No action needed. | Done |
| TL-6 🆕 | Deduplicated Background Revalidation | `src/proxy/cache.rs` | Add `inflight_revalidations: Arc<DashMap<CacheKey, ()>>` to prevent thundering herd on stale-while-revalidate. Currently missing - concurrent revalidations for same key are allowed | Pending |
| TL-7 🆕 | Fragment-Aware Multipart Parsing | `src/waf/attack_detection/streaming.rs` | Add sliding window buffer to `StreamingState` to catch boundary-splitting exploits | Pending |
| TL-8 🆕 | End-to-End Protocol Mirroring | `src/http_client/` | Enhance HttpClient pooling to select H2 streams for ALPN `h2` upstreams; preserve QUIC HOL elimination | Pending |
| APP-15 🆕 | FastCGI Response NOT Truly Streamed | `src/fastcgi/mod.rs:132-164` | `parse_response()` buffers entire stdout before parsing; implement true streaming | Pending |
| MESH-12 🆕 | Memory Leak in Pending Membership Changes | `src/mesh/transport.rs:797-875` | `pending_changes` Vec grows unbounded on repeated failures; add proper cleanup | Pending |
| MESH-13 🆕 | Missing Validation for HybridSignature Ed25519 Only Mode | `src/mesh/hybrid_signature.rs:39-46` | `ed25519_only()` doesn't validate 64-byte length before verification | Pending |
| MESH-16 🆕 | Role Validation Code Duplication | `src/mesh/peer_auth.rs:275-347` | `GLOBAL_EDGE` validation duplicated at lines 275-304 and 318-347; extract to helper function | Pending |
| MESH-17 🆕 | Session Establishment Failure Silently Ignored | `src/mesh/ml_kem_key_exchange.rs:143-148` | `session_manager.establish()` error only logged; continue may cause inconsistent state | Pending |

### LOW Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| APP-16 🆕 | Minification "Background Worker" NOT Found | `src/static_files/minifier.rs:701-797` | Minifier is synchronous inline, not background worker as documented | Pending |

---

## Wave 9: Documentation Fixes (NEW)

*Can execute in parallel with other waves*

### HIGH Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| DOC-DNS-1 🆕 | DNS Subsystem Missing from Main Body | `architecture/overview.md` | DNS appears only in Module Index, not in main narrative; add DNS section to "Distributed Systems" | Pending |
| DOC-OVERVIEW-1 🆕 | Missing Deep Dive References | `architecture/overview.md:291-303` | Add `layer_3_5_deep_dive.md` and `deep_dive_review.md` to Deep Dive Index | Pending |

### MEDIUM Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| DOC-MESH-1 🆕 | DHT Ingress Verification Gaps Not Documented | `src/mesh/dht/signed.rs:42-48` | The `IngressPath` and `SourceClassification` types exist (lines 50-82) but the verification gaps (DhtSyncRequest no auth, DhtAntiEntropyRequest pk unused, etc.) documented at lines 47-48 should be added to architecture docs | Pending |
| DOC-MESH-2 🆕 | Streaming Snapshots Format Not Documented | `src/mesh/AGENTS.override.md:39-44` | Document streaming snapshots with magic number `0x53524D53` | Pending |

---

## Testing Gaps (Updated)

| Area | Files | Missing Tests |
|------|-------|---------------|
| PID spoofing detection | `src/master/ipc.rs` | Integration tests for PID validation on all message types |
| Status file population | `src/overseer/process.rs` | Tests for worker status collection and file writing |
| Concurrent drain completion | `src/worker/drain_state.rs` | Tests for multiple `mark_drain_complete` calls |
| Recovery state machine | `src/overseer/state.rs` | Tests for RecoveryNeeded → apply transition |
| Split-chunk attacks | `src/waf/attack_detection/` | Verification tests for trailing_window boundary cases |
| **NEW: Quorum Manager race** | `src/mesh/dht/quorum.rs` | Tests for Raft delegated write failure scenarios |
| **NEW: HybridSignature validation** | `src/mesh/hybrid_signature.rs` | Tests for Ed25519-only mode with invalid lengths |
| **NEW: gRPC TLS** | `src/supervisor/api.rs` | Verify TLS is actually configured on gRPC endpoint |

---

## Verification Commands

```bash
# Core profile check
cargo check --no-default-features

# Mesh profile check
cargo check --no-default-features --features mesh

# Full profile check
cargo check --no-default-features --features mesh,dns

# Overseer module tests
cargo test --lib -- overseer

# Worker drain state tests
cargo test --lib -- worker::drain_state

# Master IPC tests
cargo test --lib -- master::ipc

# Format and lint
cargo fmt && cargo clippy --lib -- -D warnings

# Run all lib tests (compile check)
cargo test --lib --no-run
```

---

## Summary

| Wave | Items | Focus | Dependencies |
|------|-------|-------|--------------|
| 1-5 | ~71 | Previously completed | ✅ Complete |
| 6 | 5 | Critical Security & Mesh | None |
| 7 | 4 | High Priority Improvements (TL-1, TL-4 already done) | None |
| 8 | 8 | Medium/Low Priority Fixes (TL-2 already done) | None |
| 9 | 4 | Documentation Fixes | None |
| **Total New** | **21** | (25 - 4 already done) | |

---

## Wave Execution Guidance (New Items)

### Wave 6 Items (Can execute in parallel, ~3 agents)
1. MESH-11, MESH-15 (Critical Mesh issues)
2. SUP-1 (gRPC TLS - independent)
3. APP-14, APP-17 (App handler security issues)

### Wave 7 Items (Can execute in parallel, ~2 agents)
1. TL-3 (Routing index - ONLY pending item in this wave)
2. TL-5, TL-9, MESH-14 (Heartbeat stale detection, pressure valve, DHT validation)
Note: TL-1 (Cache Governor) and TL-4 (SAFE_HEADERS) are already implemented - skip these.

### Wave 8 Items (Can execute in parallel, ~3 agents)
1. TL-6, TL-7, TL-8 (Traffic layer improvements)
2. APP-15, MESH-12, MESH-13, MESH-16, MESH-17 (App/Mesh fixes)
3. APP-16 (Low priority - minifier sync issue)
Note: TL-2 (Fast-path WAF) is already implemented - skip.

### Wave 9 Items (Documentation - single agent)
1. DOC-DNS-1, DOC-OVERVIEW-1 (High priority docs)
2. DOC-MESH-1, DOC-MESH-2 (Mesh docs)

---

## Previously Completed Items Reference

### Wave 1: Critical Security & Compile Fixes (Completed 2026-05-06)
- APP-2: Fixed Granian socket URL from `http://unix:{}:{}` to `http://unix:{}{}` format
- Verified all other items (WAF-1, WAF-2, MESH-1/2/3, NET-1/6, APP-3/4, ROUT-1/2, IPC-1/2) were already correct

### Wave 2: IPC & Process Lifecycle Hardening (Completed 2026-05-06)
- IPC-4: Fixed TokenBucket refill precision using separate elapsed_secs and fractional_ms calculation
- PL-4: Fixed drain metrics - changed from `fetch_add(active, SeqCst)` where active=0 to `fetch_add(1, SeqCst)`
- Verified all other items (IPC-3/5/6/7/8, PL-1/2/3/5/6/7/8) were already correct

### Wave 3: WAF Core Streaming Optimization (Completed 2026-05-06)
- WSTREAM-4: Fixed `reset()` to use `.clear()` instead of `BufferPool::acquire(0)`
- Verified all other items (WSTREAM-1/2/3/5/6/7/8) were already implemented

### Wave 4: Remaining High/Medium Priority Fixes (Completed 2026-05-06)
- WAF-8: Fixed hex_chars_to_u32 overflow by adding length check > 8
- Verified all other items (NET-2/3/4, WAF-4/9, etc.) were already correct

### AGENTS and Skills Updates (Completed 2026-05-06)
- Updated WAF AGENTS.override.md with IPC-4 and PL-4 fix documentation
- Updated streaming_waf.md skill with .clear() vs BufferPool::acquire(0) guidance

---

## Reference Files (Verified During Review)

| File | Purpose |
|------|---------|
| `src/waf/attack_detection/streaming.rs` | Core streaming WAF logic, BufferPool usage |
| `src/waf/attack_detection/normalizer.rs` | NORMALIZE_BUFFER thread-local, hex_chars_to_u32 |
| `src/waf/attack_detection/mod.rs:156-225` | Fast-path WAF pre-screening with RegexSet (already implemented) |
| `src/http/server.rs:4530-4537` | `collect_body_with_chunk_waf` function (NOT in shared_handler.rs) |
| `src/http/server.rs` | Main HTTP/1/2 request handler, SECTION 10 around line 4525+ |
| `src/http3/server.rs` | Main HTTP/3 request handler, line 518 for cookies, 978 for zero-copy threshold |
| `src/proxy/mod.rs` | Proxy forwarding logic, line 956 for retry, 1131 for response buffering |
| `src/proxy/governor.rs` | GlobalCacheGovernor (already implements 512MB limit for TeeBody) |
| `src/proxy/cache.rs:97-126` | SAFE_HEADERS whitelist (already implemented, 29 headers) |
| `crates/synvoid-utils/src/buffer/pool.rs:203` | Jumbo tier hardcoded 256KB |
| `src/process/ipc_signed.rs` | IPC signing and key management, lines 113-120 for nonce cache, 206/645 for key file deletion |
| `src/mesh/dht/signed.rs:42-48` | DHT ingress verification gaps documentation |
| `src/mesh/dht/signed.rs:860-934` | Quorum verification (NOT in state_machine.rs:166-172) |
| `src/mesh/dht/quorum.rs:337-381` | Quorum manager race condition - MESH-11 |
| `src/mesh/security_challenge.rs:196` | Simple `!=` comparison (DO NOT change to constant-time) |
| `src/supervisor/api.rs:114-129` | gRPC server without TLS - SUP-1 |
| `src/fastcgi/mod.rs:132-164` | FastCGI buffered response - APP-15 |
| `src/mesh/transport.rs:797-875` | Pending membership memory leak - MESH-12 |
| `src/mesh/hybrid_signature.rs:39-46` | HybridSignature validation gap - MESH-13 |
| `src/mesh/peer_auth.rs:275-347` | Duplicate role validation code - MESH-16 |
| `src/mesh/ml_kem_key_exchange.rs:143-148` | Session establishment ignored - MESH-17 |
| `src/router.rs:489-509` | O(n*m) routing bottleneck - TL-3 |
| `src/upstream/shared_state.rs` | SharedConnectionTable heartbeat mechanism - TL-5 |
| `src/static_files/minifier.rs:701-797` | Synchronous minifier (not background worker) - APP-16 |
| `src/app_server/granian.rs:491-508` | pip install without hash verification - APP-17 |
| `src/spin/` | Spin framework files exist but routing integration missing - APP-14 |

---

## Key Corrections From Original Plan Files

1. `src/http/shared_handler.rs` does NOT contain `collect_body_with_chunk_waf` — it's in `src/http/server.rs:4530-4537`
2. `src/mesh/raft/state_machine.rs:166-172` does NOT contain quorum verification — it's in `src/mesh/dht/signed.rs:860-934`
3. `src/spin/` EXISTS with manifest.rs, runtime.rs, handler.rs, kv_store.rs — Spin files are present but routing integration is incomplete
4. `src/config/site/misc.rs:37` is NOT transport config — correct path is `crates/synvoid-config/src/site/misc.rs:37` for edge_only field
5. TL-1 (Global Cache Governor) is ALREADY IMPLEMENTED with GlobalCacheGovernor
6. TL-2 (Fast-Path WAF Pre-Screening) is ALREADY IMPLEMENTED with RegexSet in mod.rs
7. TL-4 (SAFE_HEADERS whitelist) is ALREADY IMPLEMENTED in proxy/cache.rs

---

**Last Updated**: 2026-05-22
**Verification Status**: ✅ REVIEWED - Corrections applied based on codebase verification