# MaluWAF Implementation Plan

Last updated: 2026-04-14

## Overview

This document is the consolidated implementation plan for MaluWAF. It combines items from all previous plan files (plan.md through plan24.md) into a single coherent plan organized by waves.

**Completed Waves (1-3)** are marked as done. **Wave 4** contains current open items organized by category. **Wave 5** contains deferred future work.

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

#### P.1: WAF Double Normalization - HIGH ❌ OPEN

**Location**: `src/waf/mod.rs:284-291`, `src/waf/attack_detection/sqli.rs:9`, `xss.rs:9`

**Issue**: SQLi and XSS detectors normalize twice - once in caller, once in detector.

**Fix**: Remove redundant `InputNormalizer::new().normalize()` inside detectors.

---

#### P2.1: WAF Input Normalizer Allocations - HIGH ❌ OPEN

**Issue**: Detectors call `InputNormalizer::new()` directly creating new instances per call.

**Fix**: Share single `InputNormalizer` instance; use `Cow<str>` to avoid heap allocations.

---

#### P2.2: HTTP Server Clone/To-String Calls - HIGH ❌ OPEN

**Location**: `src/http/server.rs`

**Issue**: 175 `.clone()` calls and 148 `.to_string()` calls per request in hot path.

**Fix**: Use `&str` references instead of `String` ownership; restructure helper functions.

---

#### P2.5: TLS Client Cache Unbounded Growth - HIGH ❌ OPEN

**Location**: `src/http_client/mod.rs:34-35`

**Issue**: `UPSTREAM_CLIENT_CACHE` is unbounded `DashMap` with no eviction.

**Fix**: Add `max_capacity()` and TTL to cache; implement LRU eviction.

---

#### P1.2: Rate Limiter O(n) Cleanup - HIGH ❌ OPEN

**Location**: `src/waf/ratelimit.rs:295`

**Issue**: Every 30s, `retain()` iterates entire shard HashMap.

**Fix**: Change to eviction-on-access pattern using LruCache; inline eviction on each access.

---

#### P1.4: Mesh Route Query Cold-Cache Latency - HIGH ❌ OPEN

**Location**: `src/mesh/transport.rs:2154`, `src/mesh/proxy.rs:307-428`

**Issue**: First request to any upstream requires DHT query with 5000ms timeout.

**Fix**: Pre-warm route cache during mesh handshake; optimistic routing; background refresh; longer TTL.

---

### 4.2: Performance - Cache & Storage

#### P.6: Cache Invalidation O(n) Full Scan - MEDIUM ❌ OPEN

**Location**: `src/proxy_cache/store.rs:451-511`

**Issue**: `invalidate_by_pattern()` and `invalidate_by_host()` scan all entries.

**Fix**: Add secondary index `HashMap<Host, Vec<CacheKey>>` for O(1) host-based lookups.

---

#### P.9: verified_upstream_cache No Failed Lookup Caching - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:771`

**Issue**: When record store unavailable, returns `Vec::new()` without caching failure.

**Fix**: Cache `None` for failed lookups; prevent repeated DHT queries for unavailable sites.

---

#### S2.4: Verified Upstream Cache TTL Only 30s - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:58`

**Issue**: `time_to_live(Duration::from_secs(30))` causes frequent refreshes.

**Fix**: Increase TTL to 5-10 minutes; balance freshness vs DHT load.

---

#### S2.5: Upstream Client Cache Key Sprawl - MEDIUM ❌ OPEN

**Location**: `src/http_client/mod.rs:27-32`

**Issue**: `skip_verify_reason: Option<String>` in cache key causes key fragmentation.

**Fix**: Exclude `skip_verify_reason` from cache key hash; only use behavioral parameters.

---

### 4.3: Performance - Concurrency & Locking

#### Q1.1: Heartbeat N+1 Lock Contention - HIGH ❌ OPEN

**Location**: `src/worker/unified_server.rs:1087-1098`

**Issue**: Loop through sites, acquiring IPC lock once per site (N+1 acquisitions).

**Fix**: Batch `AppServerHealth` messages; single lock acquisition with aggregated state.

---

#### P.7: Rate Limiter LRU Write Lock Contention - MEDIUM ❌ OPEN

**Location**: `src/waf/ratelimit.rs:273-377`

**Issue**: Cleanup loop acquires write lock per IP entry in `lru_order`.

**Fix**: Use lock-free LRU structure; batch updates.

---

#### P.8: local_upstreams Single Lock - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:31`

**Issue**: 17 usages of single `RwLock<HashMap>` with no sharding.

**Fix**: Implement sharded lock pattern like `ShardedZoneStore`.

---

#### P.5: IPC Double-Poll Delay - MEDIUM ❌ OPEN

**Location**: `src/worker/unified_server.rs:1119-1123`, `src/worker/mod.rs:295-298`

**Issue**: `sleep(50ms)` followed by `recv_with_timeout(50ms)` creates 50-100ms delay.

**Fix**: Remove redundant explicit sleep; rely only on `recv_with_timeout`.

---

#### P.11: Mesh Broadcast Unbounded Spawns - MEDIUM ❌ OPEN

**Location**: `src/worker/unified_server.rs:729-740`

**Issue**: `tokio::spawn()` called for every broadcast message with no bound.

**Fix**: Add semaphore/bounded channel for backpressure; limit concurrent broadcasts.

---

### 4.4: Performance - Mesh Networking

#### M1.1: Serial HTTP Proxy Streams - HIGH ❌ OPEN

**Location**: `src/mesh/proxy.rs:785-853`

**Issue**: `proxy_to_peer_with_fallback()` tries providers sequentially, not concurrently.

**Fix**: Fire all provider requests concurrently; race to first success.

---

#### M1.2: No HTTP/2 Multiplexing in QUIC - MEDIUM ❌ OPEN

**Location**: `src/mesh/transport.rs:1068-1085`

**Issue**: Each message opens new QUIC bidirectional stream; no stream reuse.

**Fix**: Implement HTTP/2 stream multiplexing on top of QUIC; reuse connections.

---

#### M1.3: Route Usage Tracker Unbounded - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:1528-1543`

**Issue**: `cleanup_stale_metrics()` defined but never called; `HashMap` grows unbounded.

**Fix**: Call `cleanup_stale_metrics()` periodically; implement TTL-based eviction.

---

#### P.12: find_closest O(n*m) Algorithm - LOW ❌ OPEN

**Location**: `src/mesh/dht/routing/table.rs:260-268`

**Issue**: Uses `max()` then `retain()` on candidates Vec - O(k) per insertion.

**Fix**: Use `BinaryHeap` or sorted Vec for O(log k) insertion.

---

#### P.14: KBucket Linear Search - LOW ❌ OPEN

**Location**: `src/mesh/dht/routing/bucket.rs`

**Issue**: All lookups use `Vec::iter().position()` - O(n) linear search.

**Fix**: Use `HashMap<NodeId, PeerContact>` for O(1) lookups (K=20 limit makes this practical).

---

### 4.5: Performance - Input Handling

#### P.3: URL Decoding Repeated Allocations - HIGH ❌ OPEN

**Location**: `src/waf/attack_detection/*.rs`

**Issue**: `InputNormalizer` decodes URLs, then detectors call `url_decode_all()` again.

**Fix**: Cache decoded values; pass through call chain without re-decoding.

---

#### P3.2: SSRF format! Allocation in Loop - MEDIUM ❌ OPEN

**Location**: `src/waf/attack_detection/ssrf.rs:338`

**Issue**: `format!(".{}", domain)` allocates on every iteration for each allowed domain.

**Fix**: Use `ends_with(domain)` with preceding `.` character check; avoid allocation.

---

#### Q2.2: Multiple lowercase() in Detectors - MEDIUM ❌ OPEN

**Location**: `src/waf/attack_detection/ssrf.rs:262,358`, `open_redirect.rs:161,168`

**Issue**: `to_lowercase()` called multiple times per detection flow.

**Fix**: Compute lowercase once; pass through call chain as `Cow<str>`.

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

#### R1.1: DHT Routing Manager JoinHandle Leaks - HIGH ❌ OPEN

**Location**: `src/mesh/dht/routing/manager.rs:170-208`

**Issue**: Three infinite-loop spawned tasks per `DhtRoutingManager` with no shutdown mechanism.

**Fix**: Add `shutdown_tx: tokio::sync::watch::Sender<()>`; store `JoinHandle`s; call `.abort()` on shutdown.

---

#### R1.2: Worker Unified Server JoinHandle Leaks - HIGH ❌ OPEN

**Location**: `src/worker/unified_server.rs:1065-1130`

**Issue**: Multiple spawned tasks with no JoinHandle tracking.

**Fix**: Add struct fields to store `JoinHandle`s; add `shutdown()` method.

---

#### R1.3: Proxy Cache Store JoinHandle Leaks - HIGH ❌ OPEN

**Location**: `src/proxy_cache/store.rs:200-212`

**Issue**: `start_background_cleanup()` spawns task with infinite loop; no shutdown signal.

**Fix**: Add `shutdown_tx` to `Store`; return and store `JoinHandle`; abort on `Store::shutdown()`.

---

#### R1.4: Process Manager Health Monitor JoinHandle Leak - MEDIUM ❌ OPEN

**Location**: `src/process/manager.rs:1940-1959`

**Issue**: `start_health_monitor()` spawns task with infinite loop; `JoinHandle` never stored.

**Fix**: Store and await `JoinHandle` during manager shutdown.

---

### 4.9: Code Quality - Unbounded Collections

#### R2.1: Metrics per_site HashMap Unbounded - MEDIUM ❌ OPEN

**Location**: `src/metrics/mod.rs:900`

**Issue**: `per_site: Mutex<HashMap<String, SiteMetrics>>` grows unbounded.

**Fix**: Add max capacity (e.g., 10000); implement LRU eviction or TTL-based expiration.

---

#### R2.2: Threat Intel Indicators Unbounded - MEDIUM ❌ OPEN

**Location**: `src/mesh/threat_intel.rs:153-154`

**Issue**: `indicators: RwLock<HashMap<...>>` - no eviction policy; `pending_announces: Vec` unbounded.

**Fix**: Add TTL-based expiration; bound `pending_announces` with `VecDeque` and max size.

---

#### R2.3: YARA Rules Submissions Unbounded - MEDIUM ❌ OPEN

**Location**: `src/mesh/yara_rules.rs:235-236`

**Issue**: `submissions` and `submission_hashes` HashMaps have no cleanup.

**Fix**: Add TTL or max size limit with eviction.

---

#### R2.4: Probe Tracker Events Unbounded - MEDIUM ❌ OPEN

**Location**: `src/waf/probe_tracker.rs:107`

**Issue**: `store: Arc<RwLock<HashMap<String, ProbeRecord>>>` - events accumulate indefinitely.

**Fix**: Add per-IP event count limit; implement sliding window; clean stale entries during persistence.

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

#### R4.1: Metrics Vec O(n) Front Removal - LOW ❌ OPEN

**Location**: `src/metrics/mod.rs:61,77`

**Issue**: `latencies.remove(0)` and `hops.remove(0)` are O(n) operations.

**Fix**: Change to `VecDeque` for O(1) front removal.

---

#### R4.2: NONCE_CACHE O(n) Eviction + Bottleneck - LOW ❌ OPEN

**Location**: `src/process/ipc_signed.rs:40-55,59`

**Issue**: `evict_oldest()` is O(n) operation; single global `Mutex<NonceCache>` under high load.

**Fix**: Implement O(1) eviction with ring buffer; consider sharding by node ID.

---

#### R4.3: Connection Tracker Non-Atomic Aggregate - LOW ❌ OPEN

**Location**: `src/overseer/connection_tracker.rs:79-98`

**Issue**: `update_worker_connections()` updates per-worker map, then recalculates totals non-atomically.

**Fix**: Use atomic operations or transaction to ensure consistency.

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

#### S.1: TLS Passthrough WAF Bypass - HIGH ❌ OPEN

**Location**: `src/worker/unified_server.rs:214-226`

**Issue**: When `tls_passthrough = true`, L7 WAF inspection is completely bypassed.

**Fix**: Add `tls_passthrough_enforce_waf` config; require explicit opt-in; add metrics for passthrough traffic.

---

#### S1.2: Connection Limiter Slot Hash Collisions - HIGH ❌ OPEN

**Location**: `src/waf/flood/connection_limiter.rs:8,119-121`

**Issue**: `CONNECTION_TRACKER_SLOTS = 65536` with simple modulo hash - high collision risk.

**Fix**: Verify hash distribution; consider increasing slots to 262144; add per-site limits.

---

### 4.14: Security - Session & Auth

#### S1.1: Session Fixation - No Invalidation on Login - CRITICAL ❌ OPEN

**Location**: `src/auth/mod.rs:480-511`

**Issue**: When user logs in, existing sessions for that user are NOT invalidated.

**Fix**: Invalidate all existing sessions for user before creating new session.

---

#### S1.2: IPC Nonce Cache Poisoning Before HMAC - CRITICAL ❌ OPEN

**Location**: `src/process/ipc_signed.rs:234, 372, 441`

**Issue**: Nonce inserted into cache BEFORE HMAC verification completes.

**Fix**: Verify HMAC BEFORE inserting nonce into cache.

---

#### S1.3: DNS Dynamic Update Missing TSIG Enforcement - CRITICAL ❌ OPEN

**Location**: `src/dns/update.rs:288-381`

**Issue**: `handle_update` never enforces TSIG authentication despite `require_tsig` field existing.

**Fix**: Add TSIG verification check; enforce when `require_tsig` is true.

---

#### S1.4: DNS Cookie Timing Attack - CRITICAL ❌ OPEN

**Location**: `src/dns/cookie.rs:82-87`

**Issue**: Cookie MAC comparison uses non-constant-time XOR loop.

**Fix**: Use `subtle::ConstantTimeEq::ct_eq()`.

---

#### S1.5: Origin Attestation Bypass with Empty Authorized List - CRITICAL ❌ OPEN

**Location**: `src/mesh/peer_auth.rs:281-289`

**Issue**: When `authorized_global_pubkeys` is empty, origin attestation is completely bypassed.

**Fix**: Require attestation key regardless of list size; verify signature.

---

### 4.15: Security - WAF Detection

#### S2.1: Revocation List Not Passed in Discovery - HIGH ❌ OPEN

**Location**: `src/mesh/discovery.rs:439`

**Issue**: Global node, Edge, and Origin revocation is bypassed - revocation list always `None`.

**Fix**: Pass revocation list to validation in `validate_peer_role()`.

---

#### S2.2: WAF SSTI Detector HTML Entity Bypass - HIGH ❌ OPEN

**Location**: `src/waf/attack_detection/ssti.rs:25-72`

**Issue**: SSTI detector uses `url_decode_all()` instead of `InputNormalizer`, missing HTML entity decoding.

**Fix**: Use InputNormalizer in SSTI detector.

---

#### S2.3: WAF SSRF Subdomain Spoofing Bypass - HIGH ❌ OPEN

**Location**: `src/waf/attack_detection/ssrf.rs:267-272`

**Issue**: Only checks exact `.localhost` and `.local` - bypassable via subdomain.

**Fix**: Add more comprehensive checks for lookalike domains.

---

#### S2.4: Weak TLS Cipher Suites - HIGH ❌ OPEN

**Location**: `src/tls/cert_resolver.rs:296-319`

**Issue**: Uses rustls default cipher suites including vulnerable TLS 1.2 CBC modes.

**Fix**: Explicitly configure secure cipher suites; disable CBC modes.

---

#### S2.5: Genesis Key Empty List Permits Any Key - HIGH ❌ OPEN

**Location**: `src/mesh/config_identity.rs:238-245`

**Issue**: Empty `authorized_genesis_keys` permits any key.

**Fix**: Deny by default when no keys configured.

---

#### S2.6: Rate Limiting Race Condition - HIGH ❌ OPEN

**Location**: `src/admin/auth.rs:35-52`

**Issue**: Check-before-add pattern allows bursts exceeding limit.

**Fix**: Use atomic check-after-add.

---

### 4.16: Security - Mesh & DHT

#### M16.1: Slashing Quorum Scalability - CRITICAL ❌ OPEN

**Location**: `src/mesh/dht/stake.rs:435`

**Issue**: Slashing requires exactly 3 global node votes - impossible with 1-2 global nodes.

**Fix**: Change to percentage-based quorum: `(global_count * 0.51).max(1)`.

---

#### M16.2: DHT Snapshot Request DoS - CRITICAL ❌ OPEN

**Location**: `src/mesh/dht/record_store_sync.rs:50-105`

**Issue**: `DhtSnapshotRequest` has minimal authentication; no rate limiting or size cap.

**Fix**: Require stake threshold; rate-limit per peer; add maximum snapshot size limit.

---

#### M16.3: Upstream Ownership DHT Poisoning - CRITICAL ❌ OPEN

**Location**: `src/mesh/dht/mod.rs:448-457`, `src/mesh/transport_peer.rs:1992-2030`

**Issue**: `verified_upstream` record only has global_node_signature, origin signature ignored.

**Fix**: Add `origin_signature` field; verify both signatures before trusting.

---

#### M16.4: Threat Intel Sync Full Scan - MEDIUM ❌ OPEN

**Location**: `src/mesh/threat_intel.rs:1090-1229`

**Issue**: `sync_from_dht()` iterates ALL `threat_indicator:*` keys every sync.

**Fix**: Implement key pagination or version vectors for incremental sync.

---

#### M16.5: Global Node Discovery Eclipse Attack - MEDIUM ❌ OPEN

**Location**: `src/mesh/discovery.rs`, `src/mesh/dht/routing/manager.rs:632-680`

**Issue**: Nodes only connect to configured seed nodes - vulnerable to eclipse attack.

**Fix**: Require multiple independent seed configurations; cross-validate peer lists.

---

#### M16.6: PoW Difficulty Static - MEDIUM ❌ OPEN

**Location**: `src/mesh/dht/routing/node_id.rs:114-155`

**Issue**: PoW difficulty static at 32 leading zeros - may be too easy for attackers.

**Fix**: Make difficulty configurable; consider adaptive difficulty based on network size.

---

#### M16.7: Origin Backend TLS Missing - MEDIUM ❌ OPEN

**Location**: `src/mesh/transport_peer.rs:2244-2333`

**Issue**: Origin-to-backend uses plain TCP, assuming localhost-only.

**Fix**: Add optional TLS to backend connections; document localhost assumption.

---

## Wave 4: ACME & TLS

### 4.17: ACME Integration

#### A.1: AcmeManager Not Wired Into Servers - CRITICAL ❌ OPEN

**Location**: `src/tls/acme.rs`, `src/server/mod.rs`

**Issue**: AcmeManager fully implemented but never instantiated or connected to servers.

**Fix**: Instantiate AcmeManager in server startup; pass http_challenges to HTTP server; spawn renewal task.

---

#### A.2: HTTP-01 Challenge Handler Missing - CRITICAL ❌ OPEN

**Location**: `src/http/server.rs`

**Issue**: No handler for `/.well-known/acme-challenge/` path.

**Fix**: Add handler that looks up token in http_challenges DashMap and returns key_authorization.

---

#### A.3: Certificate Renewal Does Not Trigger Cert Reload - CRITICAL ❌ OPEN

**Location**: `src/tls/acme.rs:376-405`, `src/tls/cert_resolver.rs`

**Issue**: Renewal logs success but doesn't notify CertResolver to reload.

**Fix**: Add callback/target to reload cert without restart; verify `load_certificates()` picks up new files.

---

#### A.4: Multi-Worker State Not Coordinated - MEDIUM ❌ OPEN

**Location**: `src/tls/acme.rs`

**Issue**: Each worker has independent AcmeManager state; duplicate renewal API calls possible.

**Fix**: Move AcmeManager to master process; broadcast renewed certs via IPC.

---

#### A.5: ACME DNS-01 Not Integrated with Mesh DNS - MEDIUM ❌ OPEN

**Location**: `src/tls/acme_dns.rs`, `src/dns/mesh_sync/verification.rs:209,604`

**Issue**: DNS-01 support exists but no integration between AcmeManager and mesh DNS.

**Fix**: Add callback from AcmeManager to mesh DNS; route ACME DNS queries appropriately.

---

### 4.18: TLS Mesh Certificate Distribution

#### M.1: SiteTlsCertProto Messages Not Implemented - CRITICAL ❌ OPEN

**Location**: `src/mesh/proto/mesh.proto`, `src/mesh/cert_dist.rs`

**Issue**: `CertDistManager` exists but no mesh messages (`SiteTlsCertSync`, `SiteTlsCertRequest`, `SiteTlsCertResponse`) in proto.

**Fix**: Add protobuf messages; implement origin and edge handlers; implement request/response flow.

---

#### M.2: Edge Cannot Proxy ACME Challenges to Origin - MEDIUM ❌ OPEN

**Location**: `src/proxy.rs`

**Issue**: ACME HTTP-01 challenges arrive at edge but aren't forwarded to origin backend.

**Fix**: Add special handling for `/.well-known/acme-challenge/` to proxy to origin backend.

---

#### M.3: Renewal-Triggered Distribution Not Integrated - MEDIUM ❌ OPEN

**Location**: No integration between `AcmeManager` and `CertDistManager`

**Issue**: ACME renewal writes cert to disk but doesn't trigger distribution to edge nodes.

**Fix**: Add callback from AcmeManager on renewal; trigger CertDistManager distribution.

---

#### M.4: CertDist Session Key Rotation Manual Only - LOW ❌ OPEN

**Location**: `src/mesh/cert_dist.rs`

**Issue**: No `rotate_session_key()` method; cert distribution keys become inconsistent on rotation.

**Fix**: Add rotation method; integrate with mesh session rotation.

---

## Wave 4: Web App Stack

### 4.19: Web App Stack Improvements

#### W15.1: Static Files Per-Location Theme Override - MEDIUM ❌ OPEN

**Location**: `src/config/site/static_files.rs`, `src/static_files/mod.rs`

**Issue**: Theme configuration is site-wide only; cannot have different themes per location.

**Fix**: Add `theme` field to `StaticLocation` struct; pass matched location's theme to directory listing.

---

#### W15.2: PHP-FPM Security Hardening - HIGH ❌ OPEN

**Location**: `src/php/mod.rs:build_fcgi_config()`

**Issue**: `open_basedir` passed via `PHP_VALUE` (overridable by ini_set) instead of `PHP_ADMIN_VALUE`.

**Fix**: Change `open_basedir` to use `PHP_ADMIN_VALUE` to prevent bypass.

---

#### W15.3: PHP-FPM Location-Level Security Config - MEDIUM ❌ OPEN

**Location**: `src/config/site/backend.rs`, `src/php/mod.rs`

**Issue**: Security settings cannot be set per-location; all PHP locations share same policy.

**Fix**: Add security options to `PhpLocationConfig`: disable_functions, open_basedir, allow_url_fopen, etc.

---

#### W15.4: PHP-FPM Wire Up Unused Config Options - MEDIUM ❌ OPEN

**Location**: `src/php/mod.rs`

**Issue**: `upload_tmp` configured but never passed to PHP-FPM; `extensions_dir` unused.

**Fix**: Wire up `upload_tmp` as `PHP_VALUE:upload_tmp_dir`; remove unused `extensions_dir`.

---

#### W15.5: FastCGI Configurable Pool Size - LOW ❌ OPEN

**Location**: `src/fastcgi/pool.rs`, `src/config/site/backend.rs`

**Issue**: `max_connections = 10` hardcoded; not configurable per site.

**Fix**: Add `max_connections` to `FastCgiConfig`; use in pool creation.

---

#### W15.6: FastCGI IPv6 Socket Parsing Fix - LOW ❌ OPEN

**Location**: `src/fastcgi/mod.rs:parse_socket_address()`

**Issue**: Doesn't handle bracketed IPv6 addresses like `[::1]:9000`.

**Fix**: Add handling for bracketed IPv6 format.

---

#### W15.7: WASM/Serverless Configurable Resource Limits - MEDIUM ❌ OPEN

**Location**: `src/config/serverless.rs`, `src/serverless/manager.rs`

**Issue**: No site-wide defaults for memory, CPU fuel, timeout; must specify per function.

**Fix**: Add `default_memory_mb`, `default_cpu_fuel`, `default_timeout_seconds` to `ServerlessConfig`.

---

#### W15.8: Granian Socket Path Isolation - MEDIUM ❌ OPEN

**Location**: `src/app_server/granian.rs`

**Issue**: Socket paths use site name only; socket cleanup not guaranteed on drop.

**Fix**: Add site_id or UUID to socket path; implement `Drop` for guaranteed cleanup.

---

## Wave 4: YARA & ThreatIntel

### 4.20: YARA & ThreatIntel Distribution

#### Y2.1: YARA Immediate Mesh Broadcast - MEDIUM ❌ OPEN

**Location**: `src/mesh/yara_rules.rs`

**Issue**: Unlike ThreatIntel, YARA has no mesh broadcast on rule publish - only DHT.

**Fix**: Add `broadcast_rules_to_mesh()` method; call after `publish_rules_to_dht()`.

---

#### Y2.2: YARA Admin API for Manual Publish - MEDIUM ❌ OPEN

**Location**: `src/admin/handlers/`

**Issue**: No admin endpoint to force immediate YARA rule distribution.

**Fix**: Add `POST /mesh/yara/publish` handler; requires global node auth.

---

#### F2.1: File Upload Magic Byte Verification - MEDIUM ❌ OPEN

**Location**: `src/static_files/file_manager.rs`

**Issue**: MIME type allowlist only checks claimed type, not actual file content.

**Fix**: Detect actual MIME via magic bytes (trivium crate); compare against claimed MIME.

---

#### F2.2: File Upload Zip Bomb Protection - MEDIUM ❌ OPEN

**Location**: `src/static_files/file_manager.rs`

**Issue**: Archive extraction has depth limit but no compressed ratio check.

**Fix**: Track compressed vs decompressed ratio during extraction; abort if ratio > 10:1.

---

#### T2.1: Threat Intel One-Hop DHT Broadcast Enhancement - MEDIUM ❌ OPEN

**Location**: `src/mesh/threat_intel.rs`

**Issue**: `store_and_announce` may not do full Kademlia announce for critical threats.

**Fix**: Add explicit `broadcast_to_k_closest()` call after DHT store.

---

#### T.I: Threat Intel Key Format Inconsistency - CRITICAL ❌ OPEN

**Location**: `src/mesh/threat_intel.rs:749,1128-1217`

**Issue**: Three different key formats used inconsistently: `IpBlock:1.2.3.4`, `1.2.3.4:IpBlock`, `threat_indicator:1.2.3.4:IpBlock`.

**Fix**: Standardize on `"{type}:{ip}"` format for local storage; convert DHT keys properly in sync.

---

## Wave 4: Honeypot & Protocol Validation

### 4.21: Honeypot Improvements

#### S.2: HTTP Honeypot Announcement to Threat Intel - MEDIUM ❌ OPEN

**Location**: `src/waf/mod.rs:601-607`, `src/challenge/honeypot.rs`

**Issue**: HTTP honeypot blocks locally but doesn't call `announce_honeypot_indicator()`.

**Fix**: Call `threat_intel.announce_honeypot_indicator()` when honeypot detected.

---

#### M.1: No Dedicated Honeypot Metrics - LOW ❌ OPEN

**Location**: `src/metrics/mod.rs`

**Issue**: No honeypot-specific counters for HTTP traps, port connections, indicators published.

**Fix**: Add metrics: `honeypot_http_traps_hit`, `port_honeypot_connections_captured`, etc.

---

#### L.1: Silent DHT Publish in Standalone Mode - LOW ❌ OPEN

**Location**: `src/mesh/threat_intel.rs:626-699`

**Issue**: In standalone mode, `publish_indicator_to_dht()` silently returns; only debug-level log.

**Fix**: Use `tracing::warn!` once per session when first failing.

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

#### M16.8: Threat Intel O(n) Key Iteration - MEDIUM ⏸️ DEFERRED

**Location**: `src/mesh/threat_intel.rs:1148-1149`

**Issue**: Threat intel sync uses prefix scan `threat_indicator:` - O(n) where n = total indicators.

**Fix**: See M16.4 (same root cause, similar fix).

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

#### M16.12: Peer Score Decay Not Implemented - LOW ⏸️ DEFERRED

**Location**: `src/mesh/topology/types.rs`, `src/mesh/reputation.rs`

**Issue**: Peer reputation scores don't decay over time; unbounded memory growth.

**Fix**: Implement time-based score decay; add decay rate config; remove inactive peers.

---

#### M16.13: TOFU Expiry Too Long - LOW ⏸️ DEFERRED

**Location**: `src/mesh/cert.rs`

**Issue**: TOFU certificate fingerprints expire after 90 days - longer than ideal.

**Fix**: Reduce TOFU expiry to 30 days; add certificate rotation notification.

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
