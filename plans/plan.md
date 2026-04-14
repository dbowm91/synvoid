# MaluWAF Implementation Plan

Last updated: 2026-04-14

## Overview

This document tracks remaining implementation work. Completed items have been pruned.
Reference material for completed items is in `plans/COMPLETED.md`.

Items are organized into **Waves** for parallelization. Items within a wave can be executed
in parallel by separate subagents. Dependencies between waves are documented.

**Note**: Items marked 🔴 CRITICAL or 🟡 MEDIUM with ❌ Open status are candidates for
implementation. Items marked ⏸️ Deferred are intentionally deferred to future milestones.

---

## Quick Reference

| ID | Focus | Severity | Status |
|----|-------|----------|--------|
| **Wave 4: Performance & Code Quality** | | | |
| P1.2 | Rate Limiter O(n) Cleanup | 🔴 HIGH | ❌ Open |
| P1.3 | Response Body WAF Scanning | 🔴 HIGH | ❌ Open |
| P1.4 | Mesh Route Query Cold-Cache Latency | 🔴 HIGH | ❌ Open |
| P2.1 | WAF Input Normalizer Allocations | 🔴 HIGH | ❌ Open |
| P2.2 | HTTP Server Clone/To-String Calls | 🔴 HIGH | ❌ Open |
| P2.5 | TLS Client Cache Unbounded Growth | 🔴 HIGH | ❌ Open |
| P.1 | WAF Double Normalization | 🔴 HIGH | ❌ Open |
| P.2 | WAF Input Normalization Allocations | 🔴 HIGH | ❌ Open |
| P.3 | URL Decoding Repeated Allocations | 🔴 HIGH | ❌ Open |
| P3.2 | SSRF format! Allocation in Loop | 🟡 MEDIUM | ❌ Open |
| P3.3 | Response Header Filtering Allocation | 🟡 MEDIUM | ❌ Open |
| P.5 | IPC Double-Poll Delay | 🟡 MEDIUM | ❌ Open |
| P.6 | Cache Invalidation O(n) Full Scan | 🟡 MEDIUM | ❌ Open |
| P.7 | Rate Limiter LRU Write Lock Contention | 🟡 MEDIUM | ❌ Open |
| P.8 | local_upstreams Single Lock | 🟡 MEDIUM | ❌ Open |
| P.9 | verified_upstream_cache No Failed Lookup Caching | 🟡 MEDIUM | ❌ Open |
| P.10 | Drain Polling Fixed 100ms Interval | 🟡 MEDIUM | ❌ Open |
| P.11 | Mesh Broadcast Unbounded Spawns | 🟡 MEDIUM | ❌ Open |
| P.12 | find_closest O(n*m) Algorithm | 🟢 LOW | ❌ Open |
| P.14 | KBucket Linear Search | 🟢 LOW | ❌ Open |
| S2.1 | Connection Limit Global Per-Worker | 🟡 MEDIUM | ❌ Open |
| S2.2 | Stale Cache TTL May Cause Unnecessary Refresh | 🟡 MEDIUM | ❌ Open |
| S2.3 | TCP Worker Pool Size Default | 🟡 MEDIUM | ❌ Open |
| S2.4 | Verified Upstream Cache TTL Only 30s | 🟡 MEDIUM | ❌ Open |
| S2.5 | Upstream Client Cache Key Sprawl | 🟡 MEDIUM | ❌ Open |
| M1.1 | Serial HTTP Proxy Streams | 🔴 HIGH | ❌ Open |
| M1.2 | No HTTP/2 Multiplexing in QUIC | 🟡 MEDIUM | ❌ Open |
| M1.3 | Route Usage Tracker Unbounded | 🟡 MEDIUM | ❌ Open |
| Q1.1 | Heartbeat N+1 Lock Contention | 🔴 HIGH | ❌ Open |
| Q1.3 | HTTP/TLS Test Coverage Gaps | 🔴 HIGH | ❌ Open |
| Q2.1 | Silent Send Failures in Mesh | 🟡 MEDIUM | ❌ Open |
| Q2.2 | Multiple lowercase() in Detectors | 🟡 MEDIUM | ❌ Open |
| Q2.4 | MeshMessage Enum Size | 🟡 MEDIUM | ❌ Open |
| Q4.1 | Fix Test Result Warnings | 🟢 LOW | ❌ Open |
| Q4.2 | proxy.rs Deep Nesting | 🟢 LOW | ❌ Open |
| Q4.3 | Ed25519 Key Array Zeroization | 🟢 LOW | ❌ Open |
| Q4.4 | MockIpcStream Dead Code | 🟢 LOW | ❌ Open |
| **Wave 5: Future Work** | | | |
| Q2.1 (handle_request) | handle_request() Maintainability | 🟡 MEDIUM | ⏸️ Deferred |
| Q3.1 | Missing Test Coverage for Critical Paths | 🟡 MEDIUM | ⏸️ Deferred |
| Q3.2 | Metrics and Observability Gaps | 🟡 MEDIUM | ⏸️ Deferred |
| Q4.1 (config) | Configuration Documentation | 🟢 LOW | ⏸️ Deferred |
| F.2 | DHT Metrics and Observability | 🟡 MEDIUM | ⏸️ Deferred |
| F.3 | Configuration Documentation for DhtConfig | 🟢 LOW | ⏸️ Deferred |
| F.4 | CSS Honeypot Enhancement - Path Tracking | 🟢 LOW | ⏸️ Deferred |
| F.5 | Metrics for Threat Intel DHT Operations | 🟢 LOW | ⏸️ Deferred |
| F.9 | Global Node Liveness and Quorum Monitoring | 🟢 LOW | ⏸️ Deferred |
| F.10 | IPv6 Zone ID SSRF Bypass | 🟢 LOW | ⏸️ Deferred |
| F.11 | Homoglyph Normalization Gaps | 🟢 LOW | ⏸️ Deferred |
| F.12 | TODO Comments - File Manager | 🟢 LOW | ⏸️ Deferred |

---

## Wave 4: Performance & Code Quality

### P1.2: Rate Limiter O(n) Cleanup - HIGH ❌ OPEN

**Location**: `src/waf/ratelimit.rs:295`

**Issue**: Every 30s, `retain()` iterates entire shard HashMap.

**Fix**: Change to eviction-on-access pattern using LruCache; inline eviction on each access.

---

### P1.3: Response Body WAF Scanning - HIGH ❌ OPEN

**Location**: `src/waf/mod.rs`

**Issue**: WAF only inspects requests; response bodies not scanned for DLP/PII.

**Fix**: Add `check_response()` method; implement response body scanning with DLP patterns.

---

### P1.4: Mesh Route Query Cold-Cache Latency - HIGH ❌ OPEN

**Location**: `src/mesh/transport.rs:2154`, `src/mesh/proxy.rs:307-428`

**Issue**: First request to any upstream requires DHT query with 5000ms timeout.

**Fix**: Pre-warm route cache during mesh handshake; optimistic routing; background refresh; longer TTL.

---

### P2.1: WAF Input Normalizer Allocations - HIGH ❌ OPEN

**Issue**: Detectors call `InputNormalizer::new()` directly creating new instances per call.

**Fix**: Share single `InputNormalizer` instance; use `Cow<str>` to avoid heap allocations.

---

### P2.2: HTTP Server Clone/To-String Calls - HIGH ❌ OPEN

**Location**: `src/http/server.rs`

**Issue**: 175 `.clone()` calls and 148 `.to_string()` calls per request in hot path.

**Fix**: Use `&str` references instead of `String` ownership; restructure helper functions.

---

### P2.5: TLS Client Cache Unbounded Growth - HIGH ❌ OPEN

**Location**: `src/http_client/mod.rs:34-35`

**Issue**: `UPSTREAM_CLIENT_CACHE` is unbounded `DashMap` with no eviction.

**Fix**: Add `max_capacity()` and TTL to cache; implement LRU eviction.

---

### P.1: WAF Double Normalization - HIGH ❌ OPEN

**Location**: `src/waf/mod.rs:284-291`, `src/waf/attack_detection/sqli.rs:9`, `xss.rs:9`

**Issue**: SQLi and XSS detectors normalize twice - once in caller, once in detector.

**Fix**: Remove redundant `InputNormalizer::new().normalize()` inside detectors.

---

### P.2: WAF Input Normalization Allocations - HIGH ❌ OPEN

**Issue**: Double normalization pattern causes two heap allocations per input.

**Fix**: Normalize once and reuse; pass normalized `Cow<str>` through call chain.

---

### P.3: URL Decoding Repeated Allocations - HIGH ❌ OPEN

**Location**: `src/waf/attack_detection/*.rs`

**Issue**: `InputNormalizer` decodes URLs, then detectors call `url_decode_all()` again.

**Fix**: Cache decoded values; pass through call chain without re-decoding.

---

### P3.2: SSRF format! Allocation in Loop - MEDIUM ❌ OPEN

**Location**: `src/waf/attack_detection/ssrf.rs:338`

**Issue**: `format!(".{}", domain)` allocates on every iteration for each allowed domain.

**Fix**: Use `ends_with(domain)` with preceding `.` character check; avoid allocation.

---

### P3.3: Response Header Filtering Allocation - MEDIUM ❌ OPEN

**Location**: `src/proxy.rs:244-256`

**Issue**: `filter_response_headers()` allocates `Vec<(String, String)>` on every response.

**Fix**: Wire `filter_response_headers_buf()` into actual proxy path; reuse buffer.

---

### P.5: IPC Double-Poll Delay - MEDIUM ❌ OPEN

**Location**: `src/worker/unified_server.rs:1119-1123`, `src/worker/mod.rs:295-298`

**Issue**: `sleep(50ms)` followed by `recv_with_timeout(50ms)` creates 50-100ms delay.

**Fix**: Remove redundant explicit sleep; rely only on `recv_with_timeout`.

---

### P.6: Cache Invalidation O(n) Full Scan - MEDIUM ❌ OPEN

**Location**: `src/proxy_cache/store.rs:451-511`

**Issue**: `invalidate_by_pattern()` and `invalidate_by_host()` scan all entries.

**Fix**: Add secondary index `HashMap<Host, Vec<CacheKey>>` for O(1) host-based lookups.

---

### P.7: Rate Limiter LRU Write Lock Contention - MEDIUM ❌ OPEN

**Location**: `src/waf/ratelimit.rs:273-377`

**Issue**: Cleanup loop acquires write lock per IP entry in `lru_order`.

**Fix**: Use lock-free LRU structure; batch updates.

---

### P.8: local_upstreams Single Lock - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:31`

**Issue**: 17 usages of single `RwLock<HashMap>` with no sharding.

**Fix**: Implement sharded lock pattern like `ShardedZoneStore`.

---

### P.9: verified_upstream_cache No Failed Lookup Caching - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:771`

**Issue**: When record store unavailable, returns `Vec::new()` without caching failure.

**Fix**: Cache `None` for failed lookups; prevent repeated DHT queries for unavailable sites.

---

### P.10: Drain Polling Fixed 100ms Interval - MEDIUM ❌ OPEN

**Location**: `src/worker/unified_server.rs:1440`, `src/overseer/drain_manager.rs:174`

**Issue**: Hardcoded 100ms poll interval; `drain_check_interval_ms` config unused.

**Fix**: Wire `drain_check_interval_ms` config into actual polling code.

---

### P.11: Mesh Broadcast Unbounded Spawns - MEDIUM ❌ OPEN

**Location**: `src/worker/unified_server.rs:729-740`

**Issue**: `tokio::spawn()` called for every broadcast message with no bound.

**Fix**: Add semaphore/bounded channel for backpressure; limit concurrent broadcasts.

---

### P.12: find_closest O(n*m) Algorithm - LOW ❌ OPEN

**Location**: `src/mesh/dht/routing/table.rs:260-268`

**Issue**: Uses `max()` then `retain()` on candidates Vec - O(k) per insertion.

**Fix**: Use `BinaryHeap` or sorted Vec for O(log k) insertion.

---

### P.14: KBucket Linear Search - LOW ❌ OPEN

**Location**: `src/mesh/dht/routing/bucket.rs`

**Issue**: All lookups use `Vec::iter().position()` - O(n) linear search.

**Fix**: Use `HashMap<NodeId, PeerContact>` for O(1) lookups (K=20 limit makes this practical).

---

### S2.1: Connection Limit Global Per-Worker - MEDIUM ❌ OPEN

**Issue**: `SiteConnectionLimiter` exists but never instantiated; global limiter only.

**Fix**: Wire `SiteConnectionLimiter::new()` into request path.

---

### S2.2: Stale Cache TTL May Cause Unnecessary Refresh - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:48`

**Issue**: Hardcoded 60-second `STALE_CACHE_TTL_SECS` for mesh routing policy cache.

**Fix**: Make TTL configurable; implement stale-while-revalidate pattern.

---

### S2.3: TCP Worker Pool Size Default - MEDIUM ❌ OPEN

**Location**: `src/config/network.rs:155-156`, `src/tcp/listener.rs:196`

**Issue**: TCP worker pool size hardcoded to 4; no auto-tuning based on CPU cores.

**Fix**: Use `std::thread::available_parallelism()` like HTTP Tokio workers.

---

### S2.4: Verified Upstream Cache TTL Only 30s - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:58`

**Issue**: `time_to_live(Duration::from_secs(30))` causes frequent refreshes.

**Fix**: Increase TTL to 5-10 minutes; balance freshness vs DHT load.

---

### S2.5: Upstream Client Cache Key Sprawl - MEDIUM ❌ OPEN

**Location**: `src/http_client/mod.rs:27-32`

**Issue**: `skip_verify_reason: Option<String>` in cache key causes key fragmentation.

**Fix**: Exclude `skip_verify_reason` from cache key hash; only use behavioral parameters.

---

### M1.1: Serial HTTP Proxy Streams - HIGH ❌ OPEN

**Location**: `src/mesh/proxy.rs:785-853`

**Issue**: `proxy_to_peer_with_fallback()` tries providers sequentially, not concurrently.

**Fix**: Fire all provider requests concurrently; race to first success.

---

### M1.2: No HTTP/2 Multiplexing in QUIC - MEDIUM ❌ OPEN

**Location**: `src/mesh/transport.rs:1068-1085`

**Issue**: Each message opens new QUIC bidirectional stream; no stream reuse.

**Fix**: Implement HTTP/2 stream multiplexing on top of QUIC; reuse connections.

---

### M1.3: Route Usage Tracker Unbounded - MEDIUM ❌ OPEN

**Location**: `src/mesh/topology.rs:1528-1543`

**Issue**: `cleanup_stale_metrics()` defined but never called; `HashMap` grows unbounded.

**Fix**: Call `cleanup_stale_metrics()` periodically; implement TTL-based eviction.

---

### Q1.1: Heartbeat N+1 Lock Contention - HIGH ❌ OPEN

**Location**: `src/worker/unified_server.rs:1087-1098`

**Issue**: Loop through sites, acquiring IPC lock once per site (N+1 acquisitions).

**Fix**: Batch `AppServerHealth` messages; single lock acquisition with aggregated state.

---

### Q1.3: HTTP/TLS Test Coverage Gaps - HIGH ❌ OPEN

**Issue**: `http/server.rs` (3622 lines) and `tls/server.rs` (1774 lines) have no integration tests.

**Fix**: Add integration tests that start HTTP/TLS server and send real requests.

---

### Q2.1: Silent Send Failures in Mesh - MEDIUM ❌ OPEN

**Locations**: `src/mesh/transport_routing.rs:358,365,383`, `src/mesh/passover_key_exchange.rs:254,433`

**Issue**: `let _ = sender.send(...)` silently drops failures; clients wait indefinitely.

**Fix**: Log warnings on send failures; use `try_send()` with error handling.

---

### Q2.2: Multiple lowercase() in Detectors - MEDIUM ❌ OPEN

**Location**: `src/waf/attack_detection/ssrf.rs:262,358`, `open_redirect.rs:161,168`

**Issue**: `to_lowercase()` called multiple times per detection flow.

**Fix**: Compute lowercase once; pass through call chain as `Cow<str>`.

---

### Q2.4: MeshMessage Enum Size - MEDIUM ❌ OPEN

**Location**: `src/mesh/protocol.rs:207-978`

**Issue**: ~109 variants causes large enum size (size = largest variant + discriminant).

**Fix**: Split into smaller enums by domain (Discovery, Routing, Cert, etc.).

---

### Q4.1: Fix Test Result Warnings - LOW ❌ OPEN

**Issue**: 18 warnings during test compilation (unused imports, dead code, unused variables).

**Fix**: Clean up imports; remove unused `MockIpcStream`; handle `Result` values appropriately.

---

### Q4.2: proxy.rs Deep Nesting - LOW ❌ OPEN

**Location**: `src/proxy.rs:708-823,1128-1249,863-934`

**Issue**: 4-6 levels of nesting in `handle_request_with_cache`, `forward_with_pool`, etc.

**Fix**: Extract nested logic into helper functions; use early returns.

---

### Q4.3: Ed25519 Key Array Zeroization - LOW ❌ OPEN

**Location**: `src/integrity/protocol.rs:26-29`, `src/mesh/config.rs:855`, `src/mesh/cert.rs:1105-1145`

**Issue**: `ed25519_dalek::SigningKey` and raw key arrays not zeroized on drop.

**Fix**: Use `ZeroizeOnDrop` trait; wrap keys in `Zeroizing<SigningKey>`.

---

### Q4.4: MockIpcStream Dead Code - LOW ❌ OPEN

**Location**: `src/master/ipc.rs:16-33`

**Issue**: `MockIpcStream` struct never used; dead code in test module.

**Fix**: Remove `MockIpcStream` entirely if unused.

---

## Wave 5: Future Work (Deferred)

### Q2.1: handle_request() Maintainability - MEDIUM ⏸️ DEFERRED

**Location**: `src/http/server.rs:437-1800`

**Note**: Per AGENTS.md, this is exception to size guidelines. Section comments delineate 15 phases.
Splitting not recommended. Consider refactoring only if other work requires changes.

---

### Q3.1: Missing Test Coverage for Critical Paths - MEDIUM ⏸️ DEFERRED

**Note**: Add integration tests for HTTP/TLS request handling, mesh routing, DHT operations.

---

### Q3.2: Metrics and Observability Gaps - MEDIUM ⏸️ DEFERRED

**Note**: Add metrics for request latencies, cache hit rates, mesh peer connections.

---

### Q4.1 (config): Configuration Documentation - LOW ⏸️ DEFERRED

**Note**: Document all config fields in TOML with examples and explanations.

---

### F.2: DHT Metrics and Observability - MEDIUM ⏸️ DEFERRED

**Note**: Add metrics for DHT operations: store/retrieve latencies, peer count, bucket health.

---

### F.3: Configuration Documentation for DhtConfig - LOW ⏸️ DEFERRED

**Note**: Document DhtConfig fields with examples.

---

### F.4: CSS Honeypot Enhancement - Path Tracking - LOW ⏸️ DEFERRED

**Note**: Track which paths honeypot sensors were triggered on.

---

### F.5: Metrics for Threat Intel DHT Operations - LOW ⏸️ DEFERRED

**Note**: Add metrics for threat intel sync: records received, verification failures.

---

### F.9: Global Node Liveness and Quorum Monitoring - LOW ⏸️ DEFERRED

**Note**: Monitor global node availability; alert on quorum loss.

---

### F.10: IPv6 Zone ID SSRF Bypass - LOW ⏸️ DEFERRED

**Note**: Check for IPv6 zone ID in SSRF detection.

---

### F.11: Homoglyph Normalization Gaps - LOW ⏸️ DEFERRED

**Note**: Ensure all detectors handle homoglyph attacks properly.

---

### F.12: TODO Comments - File Manager - LOW ⏸️ DEFERRED

**Note**: Review and address any remaining TODO/FIXME comments.

---

## Implementation Order & Parallelization

### Wave 4 (Performance) - Ongoing
Can parallelize: P1.2-P1.4, P2.1-P2.2, P2.5, P.1-P.3, P3.2-P3.3, S2.1-S2.5, M1.1-M1.3, Q1.1, Q1.3, Q2.1-Q2.2, Q2.4

### Wave 5 (Future) - Backlog
Can parallelize: Q2.1, Q3.1-Q3.2, Q4.1, F.2-F.5, F.9-F.12

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
