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
| S2.1 | MEDIUM | ⏸️ DEFERRED | Config |
| Q4.2 | LOW | ❌ DEFERRED | Code Quality |
| R3.3 | MEDIUM | ⏸️ DEFERRED | Code Quality |
| R3.4 | LOW | ❌ DEFERRED | Code Quality |
| Q2.1 | MEDIUM | ⏸️ DEFERRED | Architecture |
| Q3.1 | MEDIUM | ⏸️ PARTIAL | Testing |
| M5 | MEDIUM | ⏸️ DEFERRED | Mesh/DHT |
| M6 | MEDIUM | ⏸️ DEFERRED | Mesh/DHT |
| M16.9 | MEDIUM | ⏸️ DEFERRED | Mesh/DHT |
| M16.10 | MEDIUM | ⏸️ DEFERRED | Mesh/DHT |

**Total**: 11 items (1 PARTIAL, 9 DEFERRED, 1 ❌ DEFERRED)

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

#### S2.1: Connection Limit Global Per-Worker - MEDIUM ⏸️ DEFERRED

**Location**: `src/waf/traffic_shaper/limiter.rs`

**Issue**: `SiteConnectionLimiter` never instantiated; `site_id` parameter in `try_acquire` ignored.

**Assessment**: Current implementation:
- `ConnectionLimiter::try_acquire(site_id, client_ip)` accepts but ignores `site_id`
- `SiteConnectionLimiter` struct exists but is never instantiated anywhere in the codebase
- Global connection limits apply to all sites combined, not per-site

**Fix**: Would require significant architectural changes:
- Instantiate `SiteConnectionLimiter` per site in site configuration
- Modify `ConnectionLimiter` to track connections per site (nested HashMap: site_id -> ip -> count)
- Update all call sites to use per-site limiter
- Consider memory overhead of per-site tracking at high connection counts

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

#### Q3.1: Missing Test Coverage for Critical Paths - MEDIUM ⏸️ PARTIAL

**Progress Made**:

1. **Fixed DHT Integration Tests**: `tests/dht_integration_test.rs` had 5 calls to `register_node()` with outdated 3-argument signature (now requires 4 args including `caller_verified_id: Option<&str>`). Fixed all calls to pass `None` as the fourth argument.

2. **Fixed Proxy Pipeline Tests**: `tests/integration_test.rs` had 7 async forward_request tests that were hanging due to:
   - ALPN conflict with hyper-rustls 0.27
   - HTTPS-only connector for HTTP URLs
   - Mock servers not closing connections
   - Case-sensitive header assertions
   - Content-Length mismatches
   All 24 proxy_pipeline_tests now pass.

**Remaining Work**:
- Full HTTP/TLS server request handling tests (not just proxy)
- Mesh routing integration tests
- DHT operations under various network conditions

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

#### M6: No Global Node Quorum Verification - MEDIUM ⏸️ DEFERRED

**Location**: `src/mesh/dht/record_store_crud.rs`, `src/mesh/dht/keys.rs`

**Issue**: High-value operations (e.g., `verified_upstream` records) accept a single global node signature without verifying quorum.

**Assessment**: Current implementation:
- Records are signed by source node with Ed25519
- `stake_manager.can_write_dht()` checks if node has sufficient stake
- `access_control.require_global_node()` enforces global node requirement for privileged records
- M16.1 (slashing quorum) uses percentage-based quorum for governance, but record storage doesn't verify multiple signatures

**Fix**: Would require significant architectural changes:
- Change record structures to hold multiple signatures (e.g., `Vec<(node_id, signature)>`)
- Modify store logic to collect signatures from multiple global nodes before storing
- Define minimum quorum threshold (e.g., >50% or >2/3 of active global nodes)
- Protocol changes for signature collection

**Risk**: High - could break existing protocols and increase storage overhead.

---

### 5.3: Security Hardening

#### M16.9: DHT Re-balancing on Global Departure - MEDIUM ⏸️ DEFERRED

**Location**: `src/mesh/dht/record_store_sync.rs`, `src/mesh/dht/record_store_crud.rs`

**Issue**: Global node departure doesn't redistribute replicated records.

**Assessment**: Current implementation:
- `replication_factor` (default 20) controls how many peers store each record
- `announce_record_to_closest()` stores records to k closest peers
- Anti-entropy process can repair divergence between replicas
- But no mechanism to detect global node departure and trigger re-replication

**Fix**: Would require significant architectural changes:
- Add departure detection via heartbeat monitoring
- Track which peers hold replicas of each record
- When a peer departs, trigger re-announce of its records to new peers
- Verify replication factor is maintained after departure

**Risk**: Medium - could cause increased network traffic during rebalancing.

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
