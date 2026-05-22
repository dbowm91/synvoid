# SynVoid Implementation Plan

**Status**: 📋 IN PROGRESS - Adding new items from architecture reviews (2026-05-22)
**Target**: 1M RPS with streaming WAF, plus bug fixes and security hardening
**Consolidated from**: `plans/*.md` review

---

## Overview

This plan consolidates actionable items from architecture reviews into parallelizable waves. Each wave can be executed by independent agents.

**Verification Completed**: All item references have been cross-checked against the codebase. Items marked ✅ are verified; items marked ❌ had discrepancies (noted in Comments). Items marked 🆕 are newly added from review sessions.

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
| APP-14 🆕 | Spin Framework NOT Implemented | N/A | `architecture/app_handlers.md:41-45` claims Spin support but `src/spin/` module doesn't exist | Pending |
| APP-17 🆕 | Pip Install Without Hash Verification | `src/app_server/granian.rs:491-508` | Installing packages without `--require-hashes` is supply chain risk | Pending |

---

## Wave 7: High Priority Improvements (NEW)

*Can execute in parallel with Wave 6*

### HIGH Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| TL-1 🆕 | Global Cache Resource Governor | `src/proxy/mod.rs` | Prevent OOM from unbounded `TeeBody` buffering - introduce `MAX_INFLIGHT_CACHE_BYTES` and fail-fast on exceed | Pending |
| TL-3 🆕 | Unified Host Routing Index | `src/router.rs` | Replace O(Sites × Domains) routing bottleneck with O(1) global index using `AHashMap<Arc<str>, Arc<SiteConfig>>` | Pending |
| TL-4 🆕 | Secure-by-Default Cache Whitelisting | `src/proxy/cache.rs` | Convert `SENSITIVE_HEADERS` blacklist to `SAFE_HEADERS` whitelist; add `allowed_cache_headers` config | Pending |
| TL-5 🆕 | Worker Liveness in Shared State | `src/upstream/shared_state.rs` | Add `last_heartbeat` (AtomicU64) to `SharedConnectionTable`; check stale >5s to ignore dead worker connections | Pending |
| TL-9 🆕 | Architectural Pressure Valve | Multiple | Implement `SystemHealthMonitor` with AtomicU8 state (0=Normal, 1=Warning, 2=Critical); Warning bypasses TeeBody, Critical bypasses behavioral WAF | Pending |
| MESH-14 🆕 | No Source Node ID Binding Validation in All Ingress Paths | `src/mesh/dht/signed.rs:42-48` | Implement missing `verify_for_ingress()` for: DhtSyncRequest, DhtAntiEntropyRequest, DhtRecordPush, DhtRecordCommit, QuorumStoreRequest | Pending |

---

## Wave 8: Medium Priority Fixes (NEW)

*Can execute in parallel with Wave 6/7*

### MEDIUM Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| TL-2 🆕 | Fast-Path WAF Pre-Screening | `src/waf/attack_detection/detector_common.rs` | Add `pre_scan` method using `regex::RegexSet` to skip 20+ heavy detectors for clean traffic | Pending |
| TL-6 🆕 | Deduplicated Background Revalidation | `src/proxy/cache.rs` | Add `inflight_revalidations: Arc<DashMap<CacheKey, ()>>` to prevent thundering herd on stale-while-revalidate | Pending |
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
| DOC-MESH-1 🆕 | DHT Ingress Verification Not Documented | `src/mesh/dht/signed.rs:50-82` | Document `DhtRecord::verify_for_ingress()` and `IngressPath`/`SourceClassification` types | Pending |
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
| 7 | 6 | High Priority Improvements | None |
| 8 | 10 | Medium/Low Priority Fixes | None |
| 9 | 4 | Documentation Fixes | None |
| **Total New** | **25** | | |

---

## Wave Execution Guidance (New Items)

### Wave 6 Items (Can execute in parallel, ~3 agents)
1. MESH-11, MESH-15 (Critical Mesh issues)
2. SUP-1 (gRPC TLS - can do independently)
3. APP-14, APP-17 (App handler security)

### Wave 7 Items (Can execute in parallel, ~3 agents)
1. TL-1, TL-3 (Cache/Routing improvements)
2. TL-4, TL-5 (Cache/Worker state)
3. TL-9, MESH-14 (Pressure valve + DHT validation)

### Wave 8 Items (Can execute in parallel, ~3 agents)
1. TL-2, TL-6, TL-7, TL-8 (Traffic layer improvements)
2. APP-15, MESH-12, MESH-13, MESH-16, MESH-17 (App/Mesh fixes)
3. APP-16 (Low priority)

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

## Reference Files

**Verified accurate paths:**

| File | Purpose |
|------|---------|
| `src/waf/attack_detection/streaming.rs` | Core streaming WAF logic, BufferPool usage |
| `src/waf/attack_detection/normalizer.rs` | NORMALIZE_BUFFER thread-local, hex_chars_to_u32 |
| `src/http/server.rs:4530-4537` | `collect_body_with_chunk_waf` function (NOT in shared_handler.rs) |
| `src/http/server.rs` | Main HTTP/1/2 request handler, SECTION 10 around line 4525+ |
| `src/http3/server.rs` | Main HTTP/3 request handler, line 518 for cookies, 978 for zero-copy threshold |
| `src/proxy/mod.rs` | Proxy forwarding logic, line 956 for retry, 1131 for response buffering |
| `crates/synvoid-utils/src/buffer/pool.rs:203` | Jumbo tier hardcoded 256KB |
| `src/process/ipc_signed.rs` | IPC signing and key management, lines 113-120 for nonce cache, 206/645 for key file deletion |
| `src/mesh/dht/signed.rs:860-934` | Quorum verification (NOT in state_machine.rs:166-172) |
| `src/mesh/security_challenge.rs:196` | Simple `!=` comparison (DO NOT change to constant-time) |
| `src/mesh/dht/quorum.rs:337-381` | Quorum manager race condition - new items MESH-11 |
| `src/supervisor/api.rs:114-129` | gRPC server without TLS - new item SUP-1 |
| `src/fastcgi/mod.rs:132-164` | FastCGI buffered response - new item APP-15 |
| `src/mesh/transport.rs:797-875` | Pending membership memory leak - new item MESH-12 |
| `src/mesh/hybrid_signature.rs:39-46` | HybridSignature validation gap - new item MESH-13 |
| `src/mesh/peer_auth.rs:275-347` | Duplicate role validation code - new item MESH-16 |
| `src/mesh/ml_kem_key_exchange.rs:143-148` | Session establishment ignored - new item MESH-17 |

**Key corrections from original plans:**
- `src/http/shared_handler.rs` does NOT contain `collect_body_with_chunk_waf` — it's in `src/http/server.rs:4530-4537`
- `src/mesh/raft/state_machine.rs:166-172` does NOT contain quorum verification — it's in `src/mesh/dht/signed.rs:860-934`

---

**Last Updated**: 2026-05-22
**Verification Status**: 🆕 NEW ITEMS PENDING VERIFICATION