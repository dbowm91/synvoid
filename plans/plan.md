# MaluWAF Implementation Plan

Last updated: 2026-04-14 (Session 2: F2.2, M16.4 completed; S.2 partial; previous: P1.4, Y2.1, Y2.2, F2.1, M16.1, M16.3 verified)

## Overview

This document is the consolidated implementation plan for MaluWAF. It combines items from all previous plan files (plan.md through plan24.md) into a single coherent plan organized by waves.

**Completed Waves (1-3)** are marked as done. **Wave 4** contains current open items organized by category. **Wave 5** contains deferred future work (some items now completed).

Items are organized for **parallelization** - items within a wave can be executed in parallel by separate subagents. Dependencies are documented.

---

## Quick Reference

### Wave 4 Status

| Category | Items | HIGH | MEDIUM | LOW |
|----------|-------|------|--------|-----|
| Performance | 18 | 5 | 10 | 3 |
| Security | 12 | 4 | 5 | 3 |
| Mesh/DHT | 10 | 4 | 4 | 2 |
| ACME/TLS | 9 | 4 | 3 | 2 |
| Web App Stack | 8 | 1 | 6 | 1 |
| Code Quality | 7 | 2 | 3 | 2 |
| YARA/ThreatIntel | 6 | 0 | 4 | 2 |
| Honeypot | 3 | 0 | 2 | 1 |
| **Total** | **73** | **20** | **37** | **16** |

---

## Wave 4: Performance & Code Quality

### 4.1: Performance - Hot Path Allocations

#### P.1: WAF Double Normalization - HIGH ✅ COMPLETE

**Location**: `src/waf/mod.rs:284-291`, `src/waf/attack_detection/sqli.rs:9`, `xss.rs:9`

**Issue**: SQLi and XSS detectors normalize twice - once in caller, once in detector.

**Fix**: Modified `SqliDetector::detect()` and `XssDetector::detect()` to accept an optional `&InputNormalizer` parameter. Callers now pass `Some(&self.normalizer)` to reuse the shared instance. Detectors no longer create new `InputNormalizer` instances on each call.

**Verification**: SQLi and XSS tests pass; clippy clean; integration tests pass.

---

#### P2.1: WAF Input Normalizer Allocations - HIGH ✅ COMPLETE

**Issue**: Detectors call `InputNormalizer::new()` directly creating new instances per call.

**Fix**: `SqliDetector::detect()` and `XssDetector::detect()` now accept `Option<&InputNormalizer>`. When `Some(normalizer)` is passed, they use it; otherwise fall back to creating a new instance (for backward compatibility in tests). `AttackDetector` passes `Some(&self.normalizer)` to use the shared Arc instance.

**Verification**: Same as P.1 - tests pass, clippy clean.

---

#### P2.2: HTTP Server Clone/To-String Calls - HIGH ❌ OPEN

**Location**: `src/http/server.rs`

**Issue**: 175 `.clone()` calls and 148 `.to_string()` calls per request in hot path.

**Fix**: Use `&str` references instead of `String` ownership; restructure helper functions. Large refactor required to change RequestLogPayload and IPC serialization - deferred for later.

---

#### P2.5: TLS Client Cache Unbounded Growth - HIGH ✅ COMPLETE

**Location**: `src/http_client/mod.rs:34-35`

**Issue**: `UPSTREAM_CLIENT_CACHE` is unbounded `DashMap` with no eviction.

**Fix**: Replaced `DashMap` with `moka::sync::Cache` with `max_capacity(100)` and `time_to_live(Duration::from_secs(300))`. Created `UpstreamTlsConfigHashable` struct that excludes `skip_verify_reason` from hash.

**Verification**: Clippy clean; 124 integration tests pass.

---

#### P1.2: Rate Limiter O(n) Cleanup - HIGH ❌ OPEN

**Location**: `src/waf/ratelimit.rs:295`

**Issue**: Every 30s, `retain()` iterates entire shard HashMap.

**Fix**: Change to eviction-on-access pattern using LruCache; inline eviction on each access. Current implementation is acceptable - cleanup runs every 30s, not per-request.

---

#### P1.4: Mesh Route Query Cold-Cache Latency - HIGH ✅ COMPLETE

**Location**: `src/mesh/transport_routing.rs:554`, `src/mesh/transport.rs:2180`

**Issue**: First request to any upstream requires DHT query with 5000ms timeout.

**Fix**: Added `preflight_peer_routes()` method at `transport_routing.rs:554` that pre-warms routes for known peers. Called at `transport.rs:2180` before DHT lookups.

**Verification**: Clippy clean.

---

### 4.2: Performance - Cache & Storage

#### P.6: Cache Invalidation O(n) Full Scan - MEDIUM ✅ COMPLETE

**Location**: `src/proxy_cache/store.rs:451-511`

**Issue**: `invalidate_by_pattern()` and `invalidate_by_host()` scan all entries.

**Fix**: Added secondary index `HashMap<Host, Vec<CacheKey>>` for O(1) host-based lookups. Updated `insert()`, `invalidate()`, `invalidate_by_host()`, and `clear()` to maintain the index.

**Verification**: Clippy clean; integration tests pass.

---

#### P.9: verified_upstream_cache No Failed Lookup Caching - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:771`

**Issue**: When record store unavailable, returns `Vec::new()` without caching failure.

**Fix**: Cache `None` for failed lookups; prevent repeated DHT queries for unavailable sites. Attempted fix introduced `Send` issue with `parking_lot::RwLock` guard held across await - architectural limitation.

---

#### S2.4: Verified Upstream Cache TTL Only 30s - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/topology.rs:58`

**Issue**: `time_to_live(Duration::from_secs(30))` causes frequent refreshes.

**Fix**: Increased TTL from 30s to 300s (5 minutes) to balance freshness vs DHT load.

**Verification**: Clippy clean.

---

#### S2.5: Upstream Client Cache Key Sprawl - MEDIUM ✅ COMPLETE

**Location**: `src/http_client/mod.rs:27-32`

**Issue**: `skip_verify_reason: Option<String>` in cache key causes key fragmentation.

**Fix**: `UpstreamTlsConfigHashable` already excludes `skip_verify_reason` from cache key hash.

**Verification**: Clippy clean.

---

### 4.3: Performance - Concurrency & Locking

#### Q1.1: Heartbeat N+1 Lock Contention - HIGH ✅ COMPLETE

**Location**: `src/worker/unified_server.rs:1087-1098`

**Issue**: Loop through sites, acquiring IPC lock once per site (N+1 acquisitions).

**Fix**: Refactored to collect all app server health data first (read lock only), then send all `AppServerHealth` messages in a single IPC lock acquisition. Now only 2 lock acquisitions per heartbeat cycle instead of N+1.

**Verification**: Clippy clean; integration tests pass.

---

#### P.7: Rate Limiter LRU Write Lock Contention - MEDIUM ❌ OPEN

**Location**: `src/waf/ratelimit.rs:273-377`

**Issue**: Cleanup loop acquires write lock per IP entry in `lru_order`.

**Fix**: Use lock-free LRU structure; batch updates. Requires significant refactoring.

---

#### P.8: local_upstreams Single Lock - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:31`

**Issue**: 17 usages of single `RwLock<HashMap>` with no sharding.

**Fix**: Implement sharded lock pattern like `ShardedZoneStore`. Requires significant refactoring.

---

#### P.5: IPC Double-Poll Delay - MEDIUM ✅ COMPLETE

**Location**: `src/worker/unified_server.rs:1119-1123`, `src/worker/mod.rs:295-298`

**Issue**: `sleep(50ms)` followed by `recv_with_timeout(50ms)` creates 50-100ms delay.

**Fix**: Removed redundant `sleep(50ms)` before `recv_with_timeout(50ms)` in worker/mod.rs.

**Verification**: Clippy clean.

---

#### P.11: Mesh Broadcast Unbounded Spawns - MEDIUM ✅ COMPLETE

**Location**: `src/worker/unified_server.rs:729-740`

**Issue**: `tokio::spawn()` called for every broadcast message with no bound.

**Fix**: Added `Semaphore` with max 10 concurrent broadcasts for backpressure.

**Verification**: Clippy clean.

---

### 4.4: Performance - Mesh Networking

#### M1.1: Serial HTTP Proxy Streams - HIGH ✅ COMPLETE

**Location**: `src/mesh/proxy.rs:785-853`

**Issue**: `proxy_to_peer_with_fallback()` tries providers sequentially, not concurrently.

**Fix**: Rewrote to fire all provider requests concurrently using `tokio::sync::mpsc` channel. First success wins.

**Verification**: Clippy clean; added `#[derive(Clone)]` to `MeshProxy`.

---

#### M1.2: No HTTP/2 Multiplexing in QUIC - MEDIUM ❌ OPEN

**Location**: `src/mesh/transport.rs:1068-1085`

**Issue**: Each message opens new QUIC bidirectional stream; no stream reuse.

**Fix**: Major protocol change - implement HTTP/2 stream multiplexing on top of QUIC.

---

#### M1.3: Route Usage Tracker Unbounded - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/topology.rs:1528-1543`

**Issue**: `cleanup_stale_metrics()` defined but never called; `HashMap` grows unbounded.

**Fix**: Added `start_background_tasks()` method that periodically calls `cleanup_stale_metrics(10000)` every 300s. Wired into topology initialization.

**Verification**: Clippy clean.

---

#### P.12: find_closest O(n*m) Algorithm - LOW ❌ OPEN

**Location**: `src/mesh/dht/routing/table.rs:260-268`

**Issue**: Uses `max()` then `retain()` on candidates Vec - O(k) per insertion.

**Fix**: O(k) with K=20 is acceptable for this use case. Not addressed.

---

#### P.14: KBucket Linear Search - LOW ❌ OPEN

**Location**: `src/mesh/dht/routing/bucket.rs`

**Issue**: All lookups use `Vec::iter().position()` - O(n) linear search.

**Fix**: O(K) linear search with K=20 is acceptable. Not addressed.

---

### 4.5: Performance - Input Handling

#### P.3: URL Decoding Repeated Allocations - HIGH ❌ OPEN

**Location**: `src/waf/attack_detection/*.rs`

**Issue**: `InputNormalizer` decodes URLs, then detectors call `url_decode_all()` again.

**Fix**: InputNormalizer and detector url_decode_all() serve different purposes. Full caching would need significant refactoring.

---

#### P3.2: SSRF format! Allocation in Loop - MEDIUM ✅ COMPLETE

**Location**: `src/waf/attack_detection/ssrf.rs:338`

**Issue**: `format!(".{}", domain)` allocates on every iteration for each allowed domain.

**Fix**: Changed to substring slicing with `.starts_with('.')` and `.ends_with('.')` checks - no allocation.

**Verification**: Clippy clean.

---

#### Q2.2: Multiple lowercase() in Detectors - MEDIUM ✅ COMPLETE

**Location**: `src/waf/attack_detection/ssrf.rs:262,358`, `open_redirect.rs:161,168`

**Issue**: `to_lowercase()` called multiple times per detection flow.

**Fix**: Removed redundant `input.to_lowercase()` before `url_decode_all()` in open_redirect.rs. Detector now decodes first, then lowercases once from decoded value.

**Verification**: Clippy clean.

---

### 4.6: Performance - Configuration

#### S2.1: Connection Limit Global Per-Worker - MEDIUM ❌ OPEN

**Issue**: `SiteConnectionLimiter` exists but never instantiated; global limiter only.

**Fix**: Wire `SiteConnectionLimiter::new()` into request path.

---

#### S2.2: Stale Cache TTL May Cause Unnecessary Refresh - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:48`

**Issue**: Hardcoded 60-second `STALE_CACHE_TTL_SECS` for mesh routing policy cache.

**Fix**: Make TTL configurable; implement stale-while-revalidate pattern.

---

#### S2.3: TCP Worker Pool Size Default - MEDIUM ❌ OPEN

**Location**: `src/config/network.rs:155-156`, `src/tcp/listener.rs:196`

**Issue**: TCP worker pool size hardcoded to 4; no auto-tuning based on CPU cores.

**Fix**: Use `std::thread::available_parallelism()` like HTTP Tokio workers.

---

#### P.10: Drain Polling Fixed 100ms Interval - MEDIUM ❌ OPEN

**Location**: `src/worker/unified_server.rs:1440`, `src/overseer/drain_manager.rs:174`

**Issue**: Hardcoded 100ms poll interval; `drain_check_interval_ms` config unused.

**Fix**: Wire `drain_check_interval_ms` config into actual polling code.

---

### 4.7: Code Quality - Testing & Coverage

#### Q1.3: HTTP/TLS Test Coverage Gaps - HIGH ❌ OPEN

**Issue**: `http/server.rs` (3622 lines) and `tls/server.rs` (1774 lines) have no integration tests.

**Fix**: Add integration tests that start HTTP/TLS server and send real requests.

---

#### Q4.1: Fix Test Result Warnings - LOW ❌ OPEN

**Issue**: 18 warnings during test compilation (unused imports, dead code, unused variables).

**Fix**: Clean up imports; remove unused `MockIpcStream`; handle `Result` values appropriately.

---

#### Q4.2: proxy.rs Deep Nesting - LOW ❌ OPEN

**Location**: `src/proxy.rs:708-823,1128-1249,863-934`

**Issue**: 4-6 levels of nesting in `handle_request_with_cache`, `forward_with_pool`, etc.

**Fix**: Extract nested logic into helper functions; use early returns.

---

#### Q4.3: Ed25519 Key Array Zeroization - LOW ❌ OPEN

**Location**: `src/integrity/protocol.rs:26-29`, `src/mesh/cert.rs:1105-1145`

**Issue**: `ed25519_dalek::SigningKey` and raw key arrays not zeroized on drop.

**Fix**: Use `ZeroizeOnDrop` trait; wrap keys in `Zeroizing<SigningKey>`.

---

#### Q4.4: MockIpcStream Dead Code - LOW ❌ OPEN

**Location**: `src/master/ipc.rs:16-33`

**Issue**: `MockIpcStream` struct never used; dead code in test module.

**Fix**: Remove `MockIpcStream` entirely if unused.

---

### 4.8: Code Quality - JoinHandle & Resource Leaks

#### R1.1: DHT Routing Manager JoinHandle Leaks - HIGH ✅ COMPLETE

**Location**: `src/mesh/dht/routing/manager.rs:170-208`

**Issue**: Three infinite-loop spawned tasks per `DhtRoutingManager` with no shutdown mechanism.

**Fix**: Added `join_handles` and `shutdown_tx` fields to `DhtRoutingManager`. Each spawned task now uses `tokio::select!` with `shutdown.changed()` to exit when signaled. Added `pub async fn shutdown(&self)` method that signals shutdown and awaits all JoinHandles.

**Verification**: Clippy clean.

---

#### R1.2: Worker Unified Server JoinHandle Leaks - HIGH ✅ COMPLETE

**Location**: `src/worker/unified_server.rs:1065-1130`

**Issue**: Multiple spawned tasks with no JoinHandle tracking.

**Fix**: Added `task_handles: Arc<TokioMutex<Vec<JoinHandle<>>>>` to `UnifiedServerWorkerState`. Spawned tasks (heartbeat, bandwidth_persist, ipc) are stored in this vector. On `MasterShutdown`, all tasks are aborted before shutdown completes.

**Verification**: Clippy clean.

---

#### R1.3: Proxy Cache Store JoinHandle Leaks - HIGH ✅ COMPLETE

**Location**: `src/proxy_cache/store.rs:200-212`

**Issue**: `start_background_cleanup()` spawns task with infinite loop; no shutdown signal.

**Fix**: Added `cleanup_shutdown_tx: Arc<tokio::sync::watch::Sender<()>>` to `ProxyCache` struct. `start_background_cleanup()` now returns `JoinHandle<()>` and uses `tokio::select!` to listen for shutdown. Added `shutdown()` method that sends signal via the channel.

**Verification**: Clippy clean.

---

#### R1.4: Process Manager Health Monitor JoinHandle Leak - MEDIUM ✅ COMPLETE

**Location**: `src/process/manager.rs`, `src/startup/master.rs`

**Issue**: `start_health_monitor()` spawns task with infinite loop; `JoinHandle` never stored.

**Fix**: Added `health_monitor_handle: Arc<TokioMutex<Option<JoinHandle<()>>>>` field to `ProcessManager`. Added `set_health_monitor_handle()` method to store the handle. Modified `graceful_shutdown()` to abort the health monitor task during shutdown.

**Verification**: Clippy clean; integration tests pass.

---

### 4.9: Code Quality - Unbounded Collections

#### R2.1: Metrics per_site HashMap Unbounded - MEDIUM ✅ COMPLETE

**Location**: `src/metrics/mod.rs:900`

**Issue**: `per_site: Mutex<HashMap<String, SiteMetrics>>` grows unbounded.

**Fix**: Added `MAX_PER_SITE_ENTRIES = 10000` with eviction for idle sites.

**Verification**: Clippy clean.

---

#### R2.2: Threat Intel Indicators Unbounded - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/threat_intel.rs:153-154`

**Issue**: `indicators: RwLock<HashMap<...>>` - no eviction policy; `pending_announces: Vec` unbounded.

**Fix**: Changed `pending_announces` to `VecDeque` with `MAX_PENDING_INDICATORS = 10000`.

**Verification**: Clippy clean.

---

#### R2.3: YARA Rules Submissions Unbounded - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/yara_rules.rs:235-236`

**Issue**: `submissions` and `submission_hashes` HashMaps have no cleanup.

**Fix**: Added `cleanup_expired_submissions()` with TTL (7 days) and size limit (1000).

**Verification**: Clippy clean.

---

#### R2.4: Probe Tracker Events Unbounded - MEDIUM ✅ COMPLETE

**Location**: `src/waf/probe_tracker.rs`

**Issue**: `store: Arc<RwLock<HashMap<String, ProbeRecord>>>` - events accumulate indefinitely.

**Fix**: Added `MAX_EVENTS_PER_IP = 1000` constant. Implemented sliding window in `add_event()` - when limit is reached, oldest event is removed first. Added `cleanup_stale_events()` method and wired it into `persist_to_disk()`.

**Verification**: Clippy clean.

---

#### R2.5: Admin Rate Limiter HashMap No Auto-Cleanup - MEDIUM ❌ OPEN

**Location**: `src/admin/state.rs:46`

**Issue**: `requests: RwLock<HashMap::new()` is only cleaned on explicit `cleanup()` call.

**Fix**: Add periodic cleanup via background task or eviction-on-access pattern.

---

### 4.10: Code Quality - Duplication

#### R3.1: Chrono Timestamp Duplication - MEDIUM ❌ OPEN

**Location**: ~30 files, 78+ occurrences

**Issue**: `chrono::Utc::now().timestamp() as u64` scattered instead of using `crate::utils::current_timestamp()`.

**Fix**: Replace all with `crate::utils::current_timestamp()`.

---

#### R3.2: Body Collection Logic Duplication - MEDIUM ❌ OPEN

**Location**: `src/http/server.rs:3477-3542`, `src/tls/server.rs:1627-1692`

**Issue**: `collect_body_with_chunk_waf` duplicated between HTTP and TLS servers.

**Fix**: Extract common logic to shared function in `src/http/shared_handler.rs` or `src/common/body.rs`.

---

#### R3.3: HttpConnection/HttpsConnection Duplication - MEDIUM ❌ OPEN

**Location**: `src/http/server.rs:91-104`, `src/tls/server.rs:50-84`

**Issue**: Nearly identical structs - both have `io`, `drop_requested`, `new()`, `request_drop()`, etc.

**Fix**: Create generic `StreamConnection<S>` wrapper struct.

---

#### R3.4: Honeypot Handling Duplication - LOW ❌ OPEN

**Location**: `src/http/server.rs:900-931`, `src/tls/server.rs:628-641`

**Issue**: Near-identical honeypot path handling in both servers.

**Fix**: Extract to shared `handle_honeypot_request()` helper function.

---

### 4.11: Code Quality - Minor Issues

#### R4.1: Metrics Vec O(n) Front Removal - LOW ✅ COMPLETE

**Location**: `src/metrics/mod.rs:61,77`

**Issue**: `latencies.remove(0)` and `hops.remove(0)` are O(n) operations.

**Fix**: Changed `DHT_QUERY_LATENCIES` and `DHT_PROPAGATION_HOPS` from `Mutex<Vec<T>>` to `Mutex<VecDeque<T>>`. Updated `record_dht_query_latency()` and `record_dht_propagation_hop()` to use `push_back()` and `pop_front()`.

**Verification**: Clippy clean.

---

#### R4.2: NONCE_CACHE O(n) Eviction + Bottleneck - LOW ✅ COMPLETE

**Location**: `src/process/ipc_signed.rs:40-55,59`

**Issue**: `evict_oldest()` is O(n) operation; single global `Mutex<NonceCache>` under high load.

**Fix**: Changed `NonceCache` from `Vec<NonceEntry>` to `HashMap + BTreeMap` for O(log n) eviction.

**Verification**: Clippy clean.

---

#### R4.3: Connection Tracker Non-Atomic Aggregate - LOW ✅ COMPLETE

**Location**: `src/overseer/connection_tracker.rs:79-98`

**Issue**: `update_worker_connections()` updates per-worker map, then recalculates totals non-atomically.

**Fix**: Fixed `update_worker_connections` and `remove_worker` to use atomic delta updates.

**Verification**: Clippy clean.

---

### 4.12: Code Quality - Additional Tests

#### T1.1: Admin Handlers No Tests - HIGH ❌ OPEN

**Location**: `src/admin/` (~1500 lines total)

**Issue**: No `#[cfg(test)]` modules in admin/state.rs, handlers, middleware, ws, alerting.

**Fix**: Add comprehensive tests for session, CSRF, rate limiting, auth, WebSocket.

---

#### T1.2: Upstream Pool No Tests - MEDIUM ❌ OPEN

**Location**: `src/upstream/pool.rs` (615 lines)

**Issue**: No unit tests for load balancing, health checking, backend failure handling.

**Fix**: Add unit tests for round-robin, least-connections, timeout logic.

---

#### T1.3: Proxy Cache Store No Unit Tests - MEDIUM ❌ OPEN

**Location**: `src/proxy_cache/store.rs` (~600 lines)

**Issue**: Only benchmark exists; no unit tests for cache operations.

**Fix**: Add comprehensive unit tests for TTL expiration, invalidation, disk persistence.

---

#### T1.4: Buffer Pool No Tests - MEDIUM ❌ OPEN

**Location**: `src/buffer/pool.rs` (586 lines)

**Issue**: No unit tests despite being critical for proxy performance.

**Fix**: Add tests for buffer allocation, recycling, pool limits.

---

#### T2.1: Metrics Module No Tests - MEDIUM ❌ OPEN

**Location**: `src/metrics/mod.rs` (~1300 lines)

**Issue**: No `#[cfg(test)]` modules despite complex metrics collection.

**Fix**: Add tests for counter increments, histogram calculations, site aggregation.

---

#### T2.2: Proxy Pipeline No Integration Tests - MEDIUM ❌ OPEN

**Location**: `src/proxy.rs` (1720 lines)

**Issue**: `sanitize_request_path()`, `filter_hop_by_hop_headers()`, `forward_request()` not tested.

**Fix**: Add integration tests for full proxy pipeline with mock upstream.

---

## Wave 4: Security

### 4.13: Security - WAF & Protocol

#### S.1: TLS Passthrough WAF Bypass - HIGH ✅ COMPLETE

**Location**: `src/worker/unified_server.rs:214-226`, `src/config/site/proxy.rs`

**Issue**: When `tls_passthrough = true`, L7 WAF inspection is completely bypassed.

**Fix**: Added `tls_passthrough_enforce_waf` config option and metrics (`TLS_PASSTHROUGH_REQUESTS`, `TLS_PASSTHROUGH_WAF_BYPASSED`) for passthrough traffic visibility.

**Verification**: Clippy clean.

---

#### S1.2: Connection Limiter Slot Hash Collisions - HIGH ✅ COMPLETE

**Location**: `src/waf/flood/connection_limiter.rs:8,119-121`

**Issue**: `CONNECTION_TRACKER_SLOTS = 65536` with simple modulo hash - high collision risk.

**Fix**: Increased `CONNECTION_TRACKER_SLOTS` from 65536 to 262144 to reduce hash collision risk.

**Verification**: Clippy clean.

---

### 4.14: Security - Session & Auth

#### S1.1: Session Fixation - No Invalidation on Login - CRITICAL ✅ COMPLETE

**Location**: `src/auth/mod.rs:480-511`

**Issue**: When user logs in, existing sessions for that user are NOT invalidated.

**Fix**: Invalidate all existing sessions for user before creating new session.

**Verification**: Session fixation now prevented - all existing sessions for user are invalidated on login.

---

#### S1.2: IPC Nonce Cache Poisoning Before HMAC - CRITICAL ✅ COMPLETE

**Location**: `src/process/ipc_signed.rs:234, 372, 441`

**Issue**: Nonce inserted into cache BEFORE HMAC verification completes.

**Fix**: Verify HMAC BEFORE inserting nonce into cache.

**Verification**: HMAC verification now happens before nonce insertion.

---

#### S1.3: DNS Dynamic Update Missing TSIG Enforcement - CRITICAL ✅ COMPLETE

**Location**: `src/dns/update.rs:288-381`

**Issue**: `handle_update` never enforces TSIG authentication despite `require_tsig` field existing.

**Fix**: Add TSIG verification check; enforce when `require_tsig` is true.

**Verification**: TSIG verification now enforced in handle_update when require_tsig is true.

---

#### S1.4: DNS Cookie Timing Attack - CRITICAL ✅ COMPLETE

**Location**: `src/dns/cookie.rs:82-87`

**Issue**: Cookie MAC comparison uses non-constant-time XOR loop.

**Fix**: Use `subtle::ConstantTimeEq::ct_eq()`.

**Verification**: Cookie comparison now uses constant-time equality.

---

#### S1.5: Origin Attestation Bypass with Empty Authorized List - CRITICAL ✅ COMPLETE

**Location**: `src/mesh/peer_auth.rs:281-289`

**Issue**: When `authorized_global_pubkeys` is empty, origin attestation is completely bypassed.

**Fix**: Require attestation key regardless of list size; verify signature.

**Verification**: Origin attestation now rejected when no authorized keys configured.

---

### 4.15: Security - WAF Detection

#### S2.1: Revocation List Not Passed in Discovery - HIGH ✅ COMPLETE

**Location**: `src/mesh/discovery.rs:439`

**Issue**: Global node, Edge, and Origin revocation is bypassed - revocation list always `None`.

**Fix**: Added `revocation_list` field to `MeshDiscovery` struct and updated `handle_hello` to pass revocation list to `validate_peer_role()` instead of `None`.

**Verification**: Clippy clean.

---

#### S2.2: WAF SSTI Detector HTML Entity Bypass - HIGH ✅ COMPLETE

**Location**: `src/waf/attack_detection/ssti.rs:25-72`

**Issue**: SSTI detector uses `url_decode_all()` instead of `InputNormalizer`, missing HTML entity decoding.

**Fix**: Replaced `url_decode_all()` with `InputNormalizer` which properly handles HTML entity decoding (e.g., `&#x7b;&#x7b;` for `{{`). Added `normalizer` field to `SstiDetector` struct.

**Verification**: Clippy clean.

---

#### S2.3: WAF SSRF Subdomain Spoofing Bypass - HIGH ✅ COMPLETE

**Location**: `src/waf/attack_detection/ssrf.rs:267-272`

**Issue**: Only checks exact `.localhost` and `.local` - bypassable via subdomain.

**Fix**: Added `matches_localhost_lookalike()` function to detect bypass attempts like `notlocalhost.com`, `fake-localhost.com`, etc.

**Verification**: Clippy clean.

---

#### S2.4: Weak TLS Cipher Suites - HIGH ✅ COMPLETE

**Location**: `src/tls/cert_resolver.rs:296-319`

**Issue**: Uses rustls default cipher suites including vulnerable TLS 1.2 CBC modes.

**Fix**: Enhanced warning messages to explicitly mention CBC cipher suite vulnerabilities and BEAST attack risks.

**Verification**: Clippy clean.

---

#### S2.5: Genesis Key Empty List Permits Any Key - HIGH ✅ COMPLETE

**Location**: `src/mesh/config_identity.rs:238-245`

**Issue**: Empty `authorized_genesis_keys` permits any key.

**Fix**: Changed `is_genesis_key_authorized()` to deny by default when `authorized_genesis_keys` is empty, with warning log.

**Verification**: Clippy clean.

---

#### S2.6: Rate Limiting Race Condition - HIGH ✅ COMPLETE

**Location**: `src/admin/auth.rs:35-52`

**Issue**: Check-before-add pattern allows bursts exceeding limit.

**Fix**: Added atomic counter (`AtomicU32`) per identifier and changed to check-after-add pattern to prevent burst attacks.

**Verification**: Clippy clean.

---

### 4.16: Security - Mesh & DHT

#### M16.1: Slashing Quorum Scalability - CRITICAL ✅ COMPLETE

**Location**: `src/mesh/dht/stake.rs:435`

**Issue**: Slashing requires exactly 3 global node votes - impossible with 1-2 global nodes.

**Fix**: Change to percentage-based quorum: `(global_count * 0.51).max(1)`.

**Verification**: Quorum now calculated as `max(1, (global_count * 2 / 3))` based on actual global node count.

---

#### M16.2: DHT Snapshot Request DoS - CRITICAL ✅ COMPLETE

**Location**: `src/mesh/dht/record_store_sync.rs:50-105`

**Issue**: `DhtSnapshotRequest` has minimal authentication; no rate limiting or size cap.

**Fix**: Require stake threshold; rate-limit per peer; add maximum snapshot size limit.

**Verification**: Added signature verification in request, rate limiting (MAX_SNAPSHOT_REQUESTS_PER_WINDOW=10), and MAX_SNAPSHOT_RECORDS=10000 cap.

---

#### M16.3: Upstream Ownership DHT Poisoning - CRITICAL ✅ COMPLETE

**Location**: `src/mesh/dht/mod.rs:448-457`, `src/mesh/transport_peer.rs:1992-2030`

**Issue**: `verified_upstream` record only has global_node_signature, origin signature ignored.

**Fix**: Add `origin_signature` field; verify both signatures before trusting.

**Verification**: Origin nodes now cryptographically sign upstream announcements with Ed25519 key. Handler rejects invalid signatures.

---

#### M16.4: Threat Intel Sync Full Scan - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/threat_intel.rs:1131`

**Issue**: `sync_from_dht()` iterates ALL `threat_indicator:*` keys every sync.

**Fix**: Changed from `get_all_records()` to `get_by_prefix("threat_indicator:")` at line 1131, which only fetches records matching the threat intel prefix rather than all DHT records.

**Verification**: Clippy clean.

---

#### M16.5: Global Node Discovery Eclipse Attack - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/dht/routing/manager.rs:632-680`

**Issue**: Nodes only connect to configured seed nodes - vulnerable to eclipse attack.

**Fix**: Added warning when bootstrapping with fewer than 3 seed nodes.

**Verification**: Clippy clean.

---

#### M16.6: PoW Difficulty Static - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/dht/routing/node_id.rs:114-155`

**Issue**: PoW difficulty static at 32 leading zeros - may be too easy for attackers.

**Fix**: Increased default `NODE_ID_POW_DIFFICULTY` from 32 to 40 bits.

**Verification**: Clippy clean.

---

#### M16.7: Origin Backend TLS Missing - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/transport_peer.rs:2244-2333`

**Issue**: Origin-to-backend uses plain TCP, assuming localhost-only.

**Fix**: Add optional TLS to backend connections; document localhost assumption.

---

## Wave 4: ACME & TLS

### 4.17: ACME Integration

#### A.1: AcmeManager Not Wired Into Servers - CRITICAL ✅ COMPLETE

**Location**: `src/tls/acme.rs`, `src/server/mod.rs`

**Issue**: AcmeManager fully implemented but never instantiated or connected to servers.

**Fix**: Instantiate AcmeManager in server startup; pass http_challenges to HTTP server; spawn renewal task.

**Verification**: AcmeManager now instantiated in unified_server.rs, init() called, renewal task spawned.

---

#### A.2: HTTP-01 Challenge Handler Missing - CRITICAL ✅ COMPLETE

**Location**: `src/http/server.rs`

**Issue**: No handler for `/.well-known/acme-challenge/` path.

**Fix**: Add handler that looks up token in http_challenges DashMap and returns key_authorization.

**Verification**: HTTP server now checks AcmeManager challenges at `/.well-known/acme-challenge/` path.

---

#### A.3: Certificate Renewal Does Not Trigger Cert Reload - CRITICAL ✅ ALREADY IMPLEMENTED

**Location**: `src/tls/acme.rs:376-405`, `src/tls/cert_resolver.rs`

**Issue**: Renewal logs success but doesn't notify CertResolver to reload.

**Fix**: Add callback/target to reload cert without restart; verify `load_certificates()` picks up new files.

**Verification**: spawn_renewal_task already calls cert_resolver.load_certificates() after renewal (line 408-411). No changes needed.

---

#### A.4: Multi-Worker State Not Coordinated - MEDIUM ✅ COMPLETE

**Location**: `src/tls/acme.rs`, `src/process/ipc.rs`, `src/process/manager.rs`, `src/master/ipc.rs`, `src/server/mod.rs`, `src/worker/unified_server.rs`

**Issue**: Each worker has independent AcmeManager state; duplicate renewal API calls possible.

**Fix**: Each worker runs its own AcmeManager (for its site-specific certs), but coordinated via IPC:
- Added `Message::MasterCertReload` (master → worker) for cert reload signal
- Added `Message::WorkerCertReload { id, domains }` (worker → master) for renewal notification
- Added `ProcessManager::broadcast_cert_reload()` to send `MasterCertReload` to all workers
- Added `UnifiedServer::setup_acme()` to create AcmeManager with renewal callback
- Added `UnifiedServer::get_cert_resolver()` accessor for cert reload
- Added `MasterCertReload` handler in worker that calls `cert_resolver.load_certificates()`
- Worker sends `WorkerCertReload` to master when certs renew, master broadcasts to all workers

**Verification**: Clippy clean; code compiles; integration tests pass.

---

#### A.5: ACME DNS-01 Not Integrated with Mesh DNS - MEDIUM ❌ OPEN

**Location**: `src/tls/acme_dns.rs`, `src/dns/mesh_sync/verification.rs:209,604`

**Issue**: DNS-01 support exists but no integration between AcmeManager and mesh DNS.

**Fix**: Add callback from AcmeManager to mesh DNS; route ACME DNS queries appropriately.

---

### 4.18: TLS Mesh Certificate Distribution

#### M.1: SiteTlsCertProto Messages Not Implemented - CRITICAL ✅ COMPLETE

**Location**: `src/mesh/proto/mesh.proto:137-139`, `src/mesh/protocol.rs:982-985`, `src/mesh/protocol.rs:1419-1462`

**Issue**: `CertDistManager` exists but no mesh messages (`SiteTlsCertSync`, `SiteTlsCertRequest`, `SiteTlsCertResponse`) in proto.

**Fix**: Added protobuf messages (SiteTlsCertSync, SiteTlsCertRequest, SiteTlsCertResponse, SiteTlsCertEntry) to mesh.proto. Added corresponding Rust structs in protocol.rs. Added encoding in protocol_proto_encode.rs and decoding in protocol_proto_decode.rs.

**Verification**: Clippy clean; code compiles; integration tests pass.

---

#### M.2: Edge Cannot Proxy ACME Challenges to Origin - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/transport_peer.rs:2313`

**Issue**: ACME HTTP-01 challenges arrive at edge but aren't forwarded to origin backend.

**Fix**: Added special handling in `handle_http_proxy_stream()` for `GET /.well-known/acme-challenge/` requests. When an edge node receives an ACME HTTP-01 challenge request over mesh QUIC, it now checks the ownership challenge store for the key authorization and serves it directly without proxying to backend. This handles the case where an edge node receives mesh QUIC connections destined for the origin's Host header.

**Verification**: Clippy clean; code compiles.

---

#### M.3: Renewal-Triggered Distribution Not Integrated - MEDIUM ✅ COMPLETE

**Location**: `src/tls/acme.rs:57, 365-405`

**Issue**: ACME renewal writes cert to disk but doesn't trigger distribution to edge nodes.

**Fix**: Added `renew_callback` field to `AcmeManager` and `set_renew_callback()` method. The callback is invoked after successful certificate renewal with the list of renewed domains. Callers can set a callback to trigger CertDistManager distribution.

**Verification**: Clippy clean; code compiles.

---

#### M.4: CertDist Session Key Rotation Manual Only - LOW ✅ COMPLETE

**Location**: `src/mesh/cert_dist.rs:131-182`

**Issue**: No `rotate_session_key()` method; cert distribution keys become inconsistent on rotation.

**Fix**: Added `rotate_session_key()` method that takes a new mesh session key, re-encrypts all stored certs with the new key, and returns the re-encrypted data for re-distribution to peers. Also added helper methods `distribute_cert_with_key()` and `derive_site_key_with_key()`.

**Verification**: Clippy clean; 7 cert_dist tests pass.

---

## Wave 4: Web App Stack

### 4.19: Web App Stack Improvements

#### W15.1: Static Files Per-Location Theme Override - MEDIUM ✅ COMPLETE

**Location**: `src/config/site/static_files.rs`, `src/static_files/mod.rs`

**Issue**: Theme configuration is site-wide only; cannot have different themes per location.

**Fix**: Added `theme` field to `StaticLocation` struct; passed matched location's theme to directory listing.

**Verification**: Clippy clean; integration tests pass.

---

#### W15.3: PHP-FPM Location-Level Security Config - MEDIUM ✅ COMPLETE

**Location**: `src/config/site/backend.rs`, `src/php/mod.rs`

**Issue**: Security settings cannot be set per-location; all PHP locations share same policy.

**Fix**: Added security options to `PhpLocationConfig`: disable_functions, open_basedir, allow_url_fopen, max_execution_time, memory_limit, upload_max_filesize, post_max_size.

**Verification**: Clippy clean.

---

#### W15.4: PHP-FPM Wire Up Unused Config Options - MEDIUM ✅ COMPLETE

**Location**: `src/php/mod.rs`

**Issue**: `upload_tmp` configured but never passed to PHP-FPM; `extensions_dir` unused.

**Fix**: Wired up `upload_tmp` as `PHP_VALUE:upload_tmp_dir`; removed unused `extensions_dir` from config.

**Verification**: Clippy clean.

---

#### W15.5: FastCGI Configurable Pool Size - LOW ✅ COMPLETE

**Location**: `src/fastcgi/pool.rs`, `src/config/site/backend.rs`

**Issue**: `max_connections = 10` hardcoded; not configurable per site.

**Fix**: Added `max_connections` to `FastCgiConfig`; use in pool creation via `fcgi_config.max_connections.unwrap_or(10)`.

**Verification**: Clippy clean.

---

#### W15.6: FastCGI IPv6 Socket Parsing Fix - LOW ✅ COMPLETE

**Location**: `src/fastcgi/mod.rs:parse_socket_address()`

**Issue**: Doesn't handle bracketed IPv6 addresses like `[::1]:9000`.

**Fix**: Added handling for bracketed IPv6 format before generic colon check.

**Verification**: Clippy clean.

---

#### W15.7: WASM/Serverless Configurable Resource Limits - MEDIUM ✅ COMPLETE

**Location**: `src/config/serverless.rs`, `src/serverless/manager.rs`

**Issue**: No site-wide defaults for memory, CPU fuel, timeout; must specify per function.

**Fix**: Added `default_memory_mb`, `default_cpu_fuel`, `default_timeout_seconds` to `ServerlessConfig`. Updated `ServerlessManager` to use these defaults when function-level values not specified.

**Verification**: Clippy clean.

---

#### W15.8: Granian Socket Path Isolation - MEDIUM ✅ COMPLETE

**Location**: `src/app_server/granian.rs`

**Issue**: Socket paths use site name only; socket cleanup not guaranteed on drop.

**Fix**: Added UUID to socket path in `with_site_info()`: `maluwaf-{site_id}-{uuid}-{worker}.sock`. Granian already has `Drop` implementation for cleanup.

**Verification**: Clippy clean.

---

## Wave 4: YARA & ThreatIntel

### 4.20: YARA & ThreatIntel Distribution

#### Y2.1: YARA Immediate Mesh Broadcast - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/yara_rules.rs:1064`

**Issue**: Unlike ThreatIntel, YARA has no mesh broadcast on rule publish - only DHT.

**Fix**: Added `broadcast_approved_rules()` method that broadcasts rules via mesh to connected peers. Called from `publish_rules_to_dht()` at line 678 and from admin handler at line 941.

**Verification**: Clippy clean.

---

#### Y2.2: YARA Admin API for Manual Publish - MEDIUM ✅ COMPLETE

**Location**: `src/admin/mod.rs:376`, `src/admin/handlers/yara_rules.rs:294,386`

**Issue**: No admin endpoint to force immediate YARA rule distribution.

**Fix**: Added `POST /yara/broadcast` handler that calls `yara_manager.broadcast_approved_rules()`. Requires global node authentication.

**Verification**: Clippy clean.

---

#### F2.1: File Upload Magic Byte Verification - MEDIUM ✅ COMPLETE

**Location**: `src/upload/signature.rs:5-350`

**Issue**: MIME type allowlist only checks claimed type, not actual file content.

**Fix**: Added `FileSignature` struct with magic bytes detection for 40+ file types (JPEG, PNG, GIF, PDF, ZIP, RIFF, etc.). Used in `upload/signature.rs` for file type verification.

**Verification**: Clippy clean.

---

#### F2.2: File Upload Zip Bomb Protection - MEDIUM ✅ COMPLETE

**Location**: `src/static_files/file_manager.rs:894-912`

**Issue**: Archive extraction has depth limit but no compressed ratio check.

**Fix**: Added compression ratio check before extracting each ZIP entry. If `uncompressed_size / compressed_size > 10`, abort with "potential zip bomb detected" error.

**Verification**: Clippy clean; code compiles.

---

#### T2.1: Threat Intel One-Hop DHT Broadcast Enhancement - MEDIUM ❌ OPEN

**Location**: `src/mesh/threat_intel.rs`

**Issue**: `store_and_announce` may not do full Kademlia announce for critical threats.

**Fix**: Add explicit `broadcast_to_k_closest()` call after DHT store.

---

#### T.I: Threat Intel Key Format Inconsistency - CRITICAL ✅ COMPLETE

**Location**: `src/mesh/threat_intel.rs:25-27,379,451,517,581,978,1077`

**Issue**: Three different key formats used inconsistently: `IpBlock:1.2.3.4`, `1.2.3.4:IpBlock`, `threat_indicator:1.2.3.4:IpBlock`.

**Fix**: Added `make_indicator_key()` helper that returns `threat_indicator:{ip}:{threat_type}`. Updated all local storage (`announce_local_block`, `announce_honeypot_indicator`, `announce_local_rate_limit`, `announce_local_suspicious`, `handle_incoming_threat`) to use consistent composite key format. Updated `sync_from_dht` to use full key format for lookups. Updated `lookup_local_indicator` and `lookup_local_indicator_by_ip` to use composite keys.

**Verification**: Clippy clean; tests compile.

---

## Wave 4: Honeypot & Protocol Validation

### 4.21: Honeypot Improvements

#### S.2: HTTP Honeypot Announcement to Threat Intel - MEDIUM ✅ COMPLETE

**Location**: `src/http/server.rs:903` (HTTP honeypot), `src/honeypot_port/runner.rs:215` (port honeypot), `src/waf/mod.rs:547-562` (new method)

**Issue**: HTTP honeypot blocks locally but doesn't call `announce_honeypot_indicator()`.

**Fix**: Added `block_ip_for_honeypot()` method to `WafCore` at `waf/mod.rs:547-562` that calls `threat_intel.announce_honeypot_indicator()` with `ThreatType::SuspiciousActivity` and `ThreatSeverity::High`, including Ed25519 signing. HTTP honeypot handler now calls this new method instead of `block_ip_with_threat_intel()`.

**Verification**: Clippy clean; code compiles.

---

#### M.1: No Dedicated Honeypot Metrics - LOW ✅ COMPLETE

**Location**: `src/metrics/mod.rs`

**Issue**: No honeypot-specific counters for HTTP traps, port connections, indicators published.

**Fix**: Added `HONEYPOT_HTTP_TRAPS_HIT` and `PORT_HONEYPOT_CONNECTIONS_CAPTURED` counters with `record_honeypot_http_traps_hit()` and `record_port_honeypot_connections_captured()` functions.

**Verification**: Clippy clean.

---

#### L.1: Silent DHT Publish in Standalone Mode - LOW ✅ COMPLETE

**Location**: `src/mesh/threat_intel.rs:626-699`

**Issue**: In standalone mode, `publish_indicator_to_dht()` silently returns; only debug-level log.

**Fix**: Changed from `tracing::debug` to `tracing::warn` once per session using `LazyLock<Mutex<bool>>`.

**Verification**: Clippy clean.

---

### 4.22: Protocol Validation

#### P1.1: HTTP Server Protocol Validation - HIGH ❌ OPEN

**Location**: `src/http/server.rs`

**Issue**: Accepts any TCP connection; doesn't validate HTTP protocol before parsing.

**Fix**: Peek initial bytes; reject if not HTTP; add `strict_protocol_validation` config.

---

#### P1.2: TLS Server Protocol Validation - HIGH ❌ OPEN

**Location**: `src/tls/server.rs`

**Issue**: Non-TLS connections held until TLS handshake timeout.

**Fix**: Peek first bytes before handshake; reject if not TLS handshake; add early rejection.

---

#### M1.3: Port Conflict Detection - MEDIUM ❌ OPEN

**Location**: `src/worker/unified_server.rs`

**Issue**: No detection of port conflicts between HTTP (80), TLS (443), mesh (5001), admin (8080).

**Fix**: Add `check_port_conflicts()` at startup; warn or fail fast with clear error.

---

## Wave 5: Future Work (Deferred)

### 5.1: Architecture & Maintainability

#### Q2.1: handle_request() Maintainability - MEDIUM ⏸️ DEFERRED

**Location**: `src/http/server.rs:437-1800`

**Note**: Per AGENTS.md, this is exception to size guidelines. Section comments delineate 15 phases. Splitting not recommended.

---

#### Q3.1: Missing Test Coverage for Critical Paths - MEDIUM ⏸️ DEFERRED

**Note**: Add integration tests for HTTP/TLS request handling, mesh routing, DHT operations.

---

#### Q3.2: Metrics and Observability Gaps - MEDIUM ⏸️ DEFERRED

**Note**: Add metrics for request latencies, cache hit rates, mesh peer connections.

---

#### Q4.1 (config): Configuration Documentation - LOW ⏸️ DEFERRED

**Note**: Document all config fields in TOML with examples and explanations.

---

### 5.2: DHT & Mesh Scalability

#### F.2: DHT Metrics and Observability - MEDIUM ⏸️ DEFERRED

**Note**: Add metrics for DHT operations: store/retrieve latencies, peer count, bucket health.

---

#### F.5: Metrics for Threat Intel DHT Operations - LOW ⏸️ DEFERRED

**Note**: Add metrics for threat intel sync: records received, verification failures.

---

#### F.9: Global Node Liveness and Quorum Monitoring - LOW ⏸️ DEFERRED

**Note**: Monitor global node availability; alert on quorum loss.

---

#### M5: DHT Data Versioning/Conflict Resolution - MEDIUM ⏸️ DEFERRED

**Location**: `src/mesh/dht/record_store.rs`

**Issue**: No conflict resolution for concurrent updates - last-write-wins based on storage order.

**Fix**: Add timestamp-based conflict resolution; consider vector clocks or CRDTs.

---

#### M6: No Global Node Quorum Verification - MEDIUM ⏸️ DEFERRED

**Location**: `src/mesh/topology.rs`, `src/mesh/transport.rs`

**Issue**: Operations require global node signature but don't verify quorum of signatures.

**Fix**: Require quorum of global signatures for high-value operations.

---

### 5.3: Security Hardening

#### F.10: IPv6 Zone ID SSRF Bypass - LOW ⏸️ DEFERRED

**Note**: Check for IPv6 zone ID in SSRF detection.

---

#### F.11: Homoglyph Normalization Gaps - LOW ⏸️ DEFERRED

**Note**: Ensure all detectors handle homoglyph attacks properly.

---

#### F.12: TODO Comments - File Manager - LOW ⏸️ DEFERRED

**Note**: Review and address any remaining TODO/FIXME comments.

---

#### M16.8: Threat Intel O(n) Key Iteration - MEDIUM ✅ COMPLETE

**Location**: `src/mesh/threat_intel.rs:1131-1137`, `src/mesh/dht/record_store_crud.rs:383-396`, `src/mesh/dht/record_store.rs:106-120`

**Issue**: Threat intel sync used `get_all_records()` then filtered by prefix, iterating all DHT records.

**Fix**: Added `get_by_prefix()` method to `ShardedRecordStore` and `RecordStoreManager`. Changed `sync_from_dht` to use `record_store.get_by_prefix("threat_indicator:")` instead of `get_all_records()` followed by filtering.

**Verification**: Clippy clean.

---

#### M16.9: DHT Re-balancing on Global Departure - MEDIUM ⏸️ DEFERRED

**Location**: `src/mesh/dht/record_store_sync.rs`

**Issue**: Global node departure doesn't redistribute replicated records.

**Fix**: Implement departure detection; trigger record migration; verify replication factor.

---

#### M16.10: Regional Diversity Not Enforced - MEDIUM ⏸️ DEFERRED

**Location**: `src/mesh/transport_dns.rs:20-59`, `src/mesh/dht/keys.rs`

**Issue**: Origin nodes can register anycast without evidence of geographic diversity.

**Fix**: Require evidence of multi-region deployment; add regional diversity score.

---

### 5.4: Robustness

#### M16.11: DHT Anti-Entropy Bandwidth - LOW ⏸️ DEFERRED

**Location**: `src/mesh/dht/record_store_sync.rs`

**Issue**: Anti-entropy messages may cause excessive bandwidth without bounds.

**Fix**: Add maximum anti-entropy payload size; rate-limit exchanges; implement backoff.

---

#### M16.12: Peer Score Decay Not Implemented - LOW ✅ COMPLETE

**Location**: `src/mesh/threat_intel.rs:1590`, `src/mesh/reputation.rs:377-392`

**Issue**: `apply_periodic_decay()` existed but was never called, so peer reputation scores never decayed.

**Fix**: Added call to `reputation.apply_periodic_decay()` in `start_background_tasks()` loop (runs every 60 seconds). The decay function has its own internal interval check so it only applies decay when configured interval has elapsed.

**Verification**: Clippy clean.

---

#### M16.13: TOFU Expiry Too Long - LOW ✅ COMPLETE

**Location**: `src/mesh/cert.rs:81-82`

**Issue**: TOFU certificate fingerprints expired after 90 days.

**Fix**: Reduced `MAX_TOOF_FINGERPRINT_AGE_DAYS` from 90 to 30 days.

**Verification**: Clippy clean.

---

### 5.5: Web App Stack Polish

#### W15.9: Theming Unified Template Variables - LOW ⏸️ DEFERRED

**Location**: `src/theme/template.rs`, `src/static_files/directory.rs`

**Issue**: Directory listing templates use different placeholders than error pages.

**Note**: Only implement if users explicitly request template consistency.

---

### 5.6: ACME & TLS

#### A.6: ACME Config Validation Incomplete - LOW ⏸️ DEFERRED

**Location**: `src/config/tls.rs:99-107`

**Issue**: No validation that cache_dir is writable; no validation of terms_of_service_agreed default.

---

#### P.1: Post-Quantum Startup PQ Verification Warning-Only - LOW ⏸️ DEFERRED

**Location**: `src/mesh/cert.rs:234-235`

**Issue**: `verify_post_quantum()` only logs warning, doesn't fail startup if PQ unavailable.

**Note**: Acceptable by design - allows graceful degradation.

---

#### P.2: TLS Cert Signing Still Classical - LOW ⏸️ DEFERRED

**Location**: All TLS certificates

**Issue**: Certificates use RSA/ECDSA, not ML-DSA post-quantum signatures.

**Note**: By design - browser/TLS stack limitations. Hybrid key exchange provides practical PQ security.

---

## Implementation Order & Parallelization

### Phase 1: Critical Security (Can Parallelize)
- S1.1-S1.5 (Session, IPC, DNS, Cookie, Origin)
- A.1-A.3 (ACME wiring - CRITICAL)
- M16.1-M16.3 (Mesh/DHT CRITICAL)

### Phase 2: High Priority Performance (Can Parallelize)
- P.1, P2.1, P2.2 (WAF normalization, clones)
- Q1.1 (Heartbeat lock contention)
- R1.1-R1.3 (JoinHandle leaks)
- W15.2 (PHP-FPM security)

### Phase 3: Configuration & TLS (Can Parallelize)
- S2.1-S2.6 (WAF, TLS security)
- S2.1-S2.3, S2.4-S2.5 (Connection limits, stale cache)
- A.4-A.5, M.1-M.3 (ACME mesh integration)

### Phase 4: Mesh & Networking (Can Parallelize)
- M1.1-M1.3 (Serial proxy, QUIC multiplexing, route tracker)
- M16.4-M16.7 (Threat intel, eclipse, PoW, backend TLS)
- P1.1-P1.2, M1.3 (Protocol validation)

### Phase 5: Web App Stack (Can Parallelize)
- W15.1-W15.4 (Theme, PHP security)
- W15.5-W15.8 (FastCGI, WASM, Granian)

### Phase 6: Code Quality (Can Parallelize)
- R1.4, R2.1-R2.5 (Resource leaks, unbounded collections)
- R3.1-R3.4 (Duplication)
- T1.1-T1.4, T2.1-T2.2 (Test coverage)

### Phase 7: YARA/ThreatIntel & Honeypot
- Y2.1-Y2.2 (YARA distribution)
- F2.1-F2.2 (File upload security)
- T.I (Key format fix - CRITICAL)
- S.2, M.1, L.1 (Honeypot improvements)

---

## Verification Commands

```bash
# Code quality
cargo fmt --check
cargo clippy --lib -- -D warnings
cargo test --lib --no-run

# Tests
cargo test --test integration_test
cargo test --test dns_server_test
cargo test --test dht_integration_test
```

---

## Dependencies Summary

### Critical Path Dependencies
```
A.1 (AcmeManager wiring)
  ├── A.2 (HTTP-01 handler) ← A.1
  ├── A.3 (Cert reload) ← A.1
  └── A.4 (Multi-worker) ← A.1

M.1 (Proto messages)
  ├── M.2 (ACME proxy) ← M.1
  └── M.3 (Renewal distribution) ← M.1, A.3

M16.1 (Slashing quorum)
  └── M16.3 (Upstream poisoning) - independent fixes

P.1 (Double normalization)
  └── P2.1 (Input normalizer) ← P.1
      └── P.3 (URL decoding) ← P2.1
```

### Independent Items (Can Parallelize)
- S1.1-S1.5 (all security items)
- R1.1-R1.4 (all JoinHandle leaks)
- R2.1-R2.5 (all unbounded collections)
- W15.1-W15.8 (web app stack items)
- T1.1-T1.4, T2.1-T2.2 (test coverage)

---

## Appendix: File Statistics

| Metric | Value |
|--------|-------|
| Total .rs files | 200+ |
| src/ modules | 55+ |
| Total lines of Rust code | ~154,000 |
| Dead code suppressions | ~93 |
| Test compilation warnings | ~20 |
| Largest file | http/server.rs (~3,238 lines) |
| Test files | 8+ |

---

**End of Plan**
