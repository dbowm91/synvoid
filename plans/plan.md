# MaluWAF Implementation Plan

Last updated: 2026-04-15 (Pruned: Removed 112 completed items, kept 11 deferred items)

## Overview

This document contains the remaining deferred and partially-complete items from the MaluWAF implementation plan.

**Wave 4** contains remaining deferred items. **Wave 5** contains future work items.

---

## Quick Reference

### Remaining Items

| Item | Priority | Status | Category |
|------|----------|--------|----------|
| M1.2 | MEDIUM | ⏸️ DEFERRED | Mesh |
| S2.1 | MEDIUM | 🔧 IN PROGRESS | Config |
| Q4.2 | LOW | ❌ DEFERRED | Code Quality |
| R3.3 | MEDIUM | ⏸️ DEFERRED | Code Quality |
| R3.4 | LOW | ❌ DEFERRED | Code Quality |
| Q2.1 | MEDIUM | ⏸️ DEFERRED | Architecture |
| Q3.1 | MEDIUM | 🔧 IN PROGRESS | Testing |
| M5 | MEDIUM | ⏸️ DEFERRED | Mesh/DHT |
| M6 | MEDIUM | 🔧 IN PROGRESS | Mesh/DHT |
| M16.9 | MEDIUM | ✅ COMPLETED | Mesh/DHT |
| M16.10 | MEDIUM | ⏸️ DEFERRED | Mesh/DHT |

**Total**: 11 items (1 COMPLETED, 5 DEFERRED, 3 IN PROGRESS, 1 ❌ DEFERRED, 1 PARTIAL)

---

## Wave 4: Remaining Deferred Items

### 4.4: Performance - Mesh Networking

#### M1.2: No HTTP/2 Multiplexing in QUIC - MEDIUM ⏸️ DEFERRED

**Location**: `src/mesh/transport.rs:1068-1085`

**Issue**: Each message opens new QUIC bidirectional stream; no stream reuse.

**Assessment**: This is a major architectural change that should remain deferred:

1. **QUIC already provides native stream multiplexing** - each `open_bi()` creates an independent bidirectional stream multiplexed over the existing connection
2. **Opening a stream is a local-only operation** - no round trip required, just allocates stream state
3. **The current design is architecturally sound** - independent streams provide isolation (one stream's errors don't affect others) and per-stream ordering
4. **Stream reuse would add significant complexity**:
   - Need a pool of idle `SendStream` instances per peer
   - Need mutex coordination to serialize message sends per stream
   - Need to handle stream errors and remove bad streams from pool
   - Need bounds on pool size to avoid unbounded resource growth

**Fix**: Would require implementing a bounded stream pool with proper lifecycle management. Not recommended given architectural complexity vs marginal benefit at realistic message rates.

---

### 4.6: Performance - Configuration

#### S2.1: Connection Limit Global Per-Worker - MEDIUM 🔧 IN PROGRESS

**Location**: `src/waf/traffic_shaper/limiter.rs`

**Issue**: `SiteConnectionLimiter` never instantiated; `site_id` parameter in `try_acquire` ignored.

**Progress Made**:

1. **Added per-site tracking to ConnectionLimiter**:
   - Added `site_connections: RwLock<HashMap<String, HashMap<IpAddr, AtomicU32>>>` for per-site per-IP tracking
   - Added `site_total_connections: RwLock<HashMap<String, AtomicU32>>` for per-site total tracking
   - Updated `try_acquire()` to check and increment per-site counts
   - Updated `release()` to decrement per-site counts
   - Added `SiteLimitExceeded` error variant

2. **SiteConnectionLimiter infrastructure now functional**:
   - Per-site connection counts are now tracked
   - Site-level limits enforced (default max 10000 per site)
   - IP-level limits still tracked globally AND per-site

**Remaining Work**:
- Wire per-site limits from `SiteTrafficConnectionConfig` into `try_acquire`
- Instantiate `SiteConnectionLimiter` per site in site configuration
- Update call sites to use actual per-site limiter instead of global

---

### 4.7: Code Quality - Testing & Coverage

#### Q4.2: proxy.rs Deep Nesting - LOW ❌ DEFERRED

**Location**: `src/proxy.rs:708-823,1128-1249`

**Issue**: 4-6 levels of nesting in `handle_request_with_cache` and `forward_with_pool`.

**Assessment**: Code is readable with proper section comments and early returns. The main success path is flat; deep nesting only in error/retry paths. Refactoring would require extracting retry logic into helpers that share complex state, increasing overall complexity.

**Fix**: Not recommended - refactoring risk outweighs benefits.

---

### 4.10: Code Quality - Duplication

#### R3.3: HttpConnection/HttpsConnection Duplication - MEDIUM ⏸️ DEFERRED

**Location**: `src/http/server.rs:150-174`, `src/tls/server.rs:51-85`

**Issue**: ~15 lines of duplication in `HttpConnection` and `HttpsConnection` structs.

**Assessment**: The structs are nearly identical but use different underlying stream types. Using generics would require:
- A generic `Connection<S>` wrapper
- Changes to all places that construct or use these connections
- Complexity overhead for what is essentially copy-paste boilerplate

**Fix**: Not recommended - generics complexity not worth ~15 lines of duplication.

---

#### R3.4: Honeypot Handling Duplication - LOW ❌ DEFERRED

**Location**: `src/http/server.rs:900-931`, `src/tls/server.rs:628-641`

**Issue**: Honeypot handling code is duplicated between HTTP and HTTPS servers.

**Assessment**: The duplication is intentional - HTTP uses `block_ip_for_honeypot` while HTTPS uses `block_ip_with_threat_intel`. These represent different security behaviors appropriate for each protocol.

**Fix**: Not a bug - intentional protocol distinctions.

---

## Wave 5: Future Work (Deferred)

### 5.1: Architecture & Maintainability

#### Q2.1: handle_request() Maintainability - MEDIUM ⏸️ DEFERRED

**Location**: `src/http/server.rs:437-1800`

**Note**: Per AGENTS.md, this is exception to size guidelines. Section comments delineate 15 phases. Splitting not recommended.

---

#### Q3.1: Missing Test Coverage for Critical Paths - MEDIUM 🔧 IN PROGRESS

**Progress Made**:

1. **Fixed DHT Integration Tests**: `tests/dht_integration_test.rs` had 5 calls to `register_node()` with outdated 3-argument signature (now requires 4 args including `caller_verified_id: Option<&str>`). Fixed all calls to pass `None` as the fourth argument.

2. **Fixed Proxy Pipeline Tests**: `tests/integration_test.rs` had 7 async forward_request tests that were hanging due to:
   - ALPN conflict with hyper-rustls 0.27
   - HTTPS-only connector for HTTP URLs
   - Mock servers not closing connections
   - Case-sensitive header assertions
   - Content-Length mismatches
   All 24 proxy_pipeline_tests now pass.

3. **HTTP Server Handler Tests**: Added `http_server_handler_tests` module with 8 tests covering:
   - SharedRequestHandler health/ready requests
   - JSON response building
   - Error response building
   - Cookie and Alt-Svc header injection

4. **Early HTTP Parser Tests**: Added `early_http_parser_tests` module with 13 tests covering:
   - GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS methods
   - Query parameter parsing
   - Cookie parsing
   - Content-Length parsing
   - Malformed and partial request handling

5. **Response Builder Tests**: Added `response_builder_tests` module with 6 tests covering:
   - Reason phrase coverage
   - Error response body content
   - JSON response content-type
   - Cookie header injection
   - Alt-Svc header injection

6. **HTTP Security Header Tests**: Added `http_security_header_tests` module with 5 tests covering:
   - Security headers injection (HSTS, CSP, X-Frame-Options, etc.)
   - WebSocket upgrade detection edge cases
   - WebSocket accept key RFC 6455 compliance
   - CORS wildcard and specific origin handling

7. **DHT Integration Tests**: Added 15 new tests covering:
   - Record store basic operations
   - Record store prefix search
   - Record store clear
   - Signed record TTL
   - TTL manager for different record types
   - Message timestamp validation edge cases
   - KBucket eviction when full
   - GeoInfo distance calculation
   - Persisted bucket roundtrip
   - Stake manager initial state
   - DHT rate limiter peer independence
   - DHT key privileged vs public classification

**Total new tests added**: 47 (8 + 13 + 6 + 5 + 15)

---

### 5.2: DHT & Mesh Scalability

#### M5: DHT Data Versioning/Conflict Resolution - MEDIUM ⏸️ DEFERRED

**Location**: `src/mesh/dht/record_store.rs`, `src/mesh/dht/record_store_crud.rs`

**Issue**: No conflict resolution for concurrent updates - last-write-wins based on storage order.

**Assessment**: `DhtRecordEntry` already has a `version: u64` field, but it's only used for local tracking (incremented on each `store_record_global` call), not conflict resolution. When two nodes store the same key concurrently, the last write simply overwrites.

**Fix**: Would require significant architectural changes:
- Implement vector clocks or similar causal ordering mechanism
- Define semantic merge strategies for different record types (threat_intel vs upstream vs organization)
- Protocol changes to propagate version metadata
- Handling race conditions during merge

**Risk**: High - could introduce data loss if merge logic is incorrect.

---

#### M6: No Global Node Quorum Verification - MEDIUM 🔧 IN PROGRESS

**Location**: `src/mesh/dht/quorum.rs` (new), `src/mesh/dht/record_store_crud.rs`, `src/mesh/protocol.rs`

**Issue**: High-value operations (e.g., `verified_upstream` records) accept a single global node signature without verifying quorum.

**Progress Made**:

1. **Quorum infrastructure** (`src/mesh/dht/quorum.rs`):
   - `QuorumRequest`: tracks ongoing requests with signatures/rejections
   - `QuorumManager`: manages pending requests, tracks veto history
   - `RejectionReason` enum: DomainTaken, InvalidFormat, Unauthorized, PolicyViolation
   - 2/3 threshold for storing records
   - Veto abuse detection: tracks suspicious rejections

2. **Protocol changes**:
   - Added `QuorumStoreRequest`, `QuorumSignatureResponse`, `QuorumRejectionResponse` messages
   - Protobuf definitions added
   - Encoding/decoding implemented

**Remaining Work** (Implementation Steps):

1. **Wire QuorumManager into RecordStoreManager**:
   - Add `quorum_manager: Option<Arc<QuorumManager>>` to `RecordStoreManager`
   - Add `set_quorum_manager()` method to initialize it
   - Pass quorum_manager reference when creating record store

2. **Modify `store_record_global` for quorum-tracked keys**:
   - Identify privileged keys (verified_upstream, etc.) that need quorum
   - For these keys, do NOT store immediately
   - Instead, call `start_quorum_request()` and broadcast to global nodes

3. **Implement quorum broadcast**:
   - When quorum request starts, broadcast `QuorumStoreRequest` to all global nodes
   - Use existing mesh message infrastructure
   - Track responses with deadline (10 seconds per `QuorumRequest`)

4. **Handle quorum responses**:
   - When `QuorumSignatureResponse` received: call `add_signature()`
   - When `QuorumRejectionResponse` received: call `add_rejection()`
   - Check `threshold_met()` after each response

5. **Implement veto verification**:
   - For `DomainTaken` rejections, check DHT for existing key
   - `verify_rejection()` in QuorumManager already exists, wire it up
   - Mark verified fruitless claims in veto_history

6. **Complete quorum and store**:
   - On `threshold_met()` AND no valid rejections:
     - Store the record locally with full quorum signatures
     - Call `complete_request()` to clean up
   - On valid rejection: abort, do not store
   - On timeout: use signatures_collected if >= threshold, else abort

7. **Log suspicious veto patterns**:
   - After each quorum, call `get_veto_abuse_score()` for rejecting nodes
   - Log warnings for scores exceeding threshold

**Design**:
- Threshold: 2/3 of active global nodes
- Veto is hard block: ANY valid rejection blocks
- Non-response is acceptable
- Rejection verification for verifiable claims (DomainTaken checked against DHT)

---

### 5.3: Security Hardening

#### M16.9: DHT Re-balancing on Global Departure - MEDIUM ✅ COMPLETED

**Location**: `src/mesh/dht/record_store_message.rs`, `src/mesh/transport_peer.rs`

**Fix Applied**:
- Added `rebalance_after_departure()` to `RecordStoreManager` that:
  - Collects all local_origin records
  - Re-announces each to k-closest peers via `send_datagram_to_peer`
  - Tracks success count and warns if write quorum not met
  - Records metrics for announce sent/failed
- Modified `handle_peer_gone()` to check if departing node was global before removal, then trigger rebalance if so

---

#### M16.10: Regional Diversity Not Enforced - MEDIUM ⏸️ DEFERRED

**Location**: `src/dns/mesh_sync/registration.rs`, `src/mesh/transport_dns.rs`

**Issue**: Origin nodes can register anycast without evidence of geographic diversity.

**Assessment**: Current implementation:
- `DnsRegistration` includes a `geo` field for geographic location
- `RegisteredOriginNode` stores geo information
- No verification that claimed geo matches actual IP location
- No minimum diversity requirement for anycast registration
- A single entity could register multiple origins all claiming the same region

**Fix**: Would require significant architectural changes:
- Add GeoIP verification (compare claimed geo against actual IP location)
- Define minimum regional diversity threshold for anycast
- Implement regional diversity scoring
- Protocol changes to propagate diversity metrics

**Risk**: Medium - could break legitimate single-region deployments.

---

## Implementation Notes

### Dependencies

All deferred items are independent and can be worked on in parallel:
- M1.2: Requires mesh transport understanding
- S2.1: Requires WAF config system understanding
- Q4.2: Requires proxy.rs understanding
- R3.3: Requires HTTP/TLS server understanding
- R3.4: Requires HTTP/TLS server understanding (but is intentional)
- Q2.1: Exception in AGENTS.md - do not touch
- Q3.1: Testing work, no dependencies
- M5: Requires DHT internals understanding
- M6: Requires DHT and mesh security understanding
- M16.9: Requires DHT replication understanding
- M16.10: Requires DNS registration understanding

### Verification Commands

```bash
# Run integration tests
cargo test --test integration_test

# Run DHT integration tests
cargo test --test dht_integration_test

# Run clippy
cargo clippy --lib -- -D warnings

# Run all tests
cargo test
```

---

## Appendix: File Statistics

- Total items in original plan: ~180
- Completed items: ~165
- Remaining deferred items: 10
- Remaining partial items: 1

Last cleanup: 2026-04-15
