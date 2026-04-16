# MaluWAF Implementation Plan

Last updated: 2026-04-16 (Post Wave 4/5 cleanup)

## Overview

This document contains remaining items from the MaluWAF implementation plan after Wave 4 completion.

**Legend**:
- ✅ COMPLETED - Item fully implemented
- ⏸️ DEFERRED - Item requires further investigation or is blocked
- ❌ NOT RECOMMENDED - Investigation shows risk outweighs benefit
- ❌ NOT REAL ISSUE - Investigation shows no actual problem exists

---

## Quick Reference

### Remaining Items

| Item | Priority | Status | Category | Summary |
|------|----------|--------|----------|---------|
| Q2.1 | MEDIUM | ⏸️ DEFERRED | Architecture | handle_request() size exception |
| R3.3 | MEDIUM | ❌ NOT RECOMMENDED | Code Quality | ~12 lines duplication (generics too complex) |

**Total**: 2 items (0 actionable, 2 closed/not recommended)

### Completed Items (Summary)

| Item | Status | Key Changes |
|------|--------|-------------|
| S2.1 | ✅ COMPLETED | Two-phase per-site connection limiting |
| Q3.1 | ✅ COMPLETED | 47 new tests added |
| M5 | ✅ COMPLETED | Timestamp-based DHT conflict resolution |
| M6 | ✅ COMPLETED | Quorum verification wired |
| M16.9 | ✅ COMPLETED | DHT rebalancing on global departure |
| M16.10 | ✅ COMPLETED | Geo derived programmatically from IP |

### Closed Items (Not Recommended / Not Real Issues)

| Item | Status | Decision Rationale |
|------|--------|-------------------|
| M1.2 | ❌ NOT REAL ISSUE | QUIC already provides native multiplexing; comparison to HTTP/2 invalid |
| Q4.2 | ❌ NOT RECOMMENDED | Code readable, error paths inherently complex; refactor risk > benefit |
| R3.3 | ❌ NOT RECOMMENDED | Generics won't help (~12 lines); duplication is harmless |
| R3.4 | ❌ NOT REAL ISSUE | Intentional protocol distinctions, not a bug |

---

## Remaining Items

### Q2.1: handle_request() Maintainability - MEDIUM ⏸️ DEFERRED

**Location**: `src/http/server.rs:437-1800`

**Note**: Per AGENTS.md, this file is an exception to size guidelines. Section comments delineate 15 phases within `handle_request()`. Splitting is not recommended.

**Rationale**: The function is large but well-structured with clear section comments. Breaking it apart would introduce complexity without clear benefit.

---

## Closed Items

### M1.2: QUIC Multiplexing - ❌ NOT REAL ISSUE

**Location**: `src/mesh/transport.rs:1068-1085`

**Decision**: This was a misunderstanding of QUIC's stream model vs HTTP/2's multiplexing layer over TCP.

**Rationale**:
- QUIC provides native stream multiplexing at transport layer
- Opening a stream (`open_bi()`) is local-only, no RTT required
- Current design is architecturally sound with independent streams providing error isolation
- Stream reuse would add complexity without meaningful benefit

---

### Q4.2: proxy.rs Deep Nesting - ❌ NOT RECOMMENDED

**Location**: `src/proxy.rs:708-823,1128-1249`

**Decision**: Code is readable, main success path is flat, error/retry paths are inherently complex.

**Rationale**:
- Main success path has flat nesting with early returns
- 4-6 levels of nesting only in error/retry paths
- Refactoring would require extracting retry logic into helpers that share complex state
- Risk outweighs benefit

---

### R3.3: HttpConnection Duplication - ❌ NOT RECOMMENDED

**Location**: `src/http/server.rs:150-174`, `src/tls/server.rs:51-85`

**Decision**: Generics won't help - types are fundamentally different.

**Rationale**:
- Only ~12 lines of duplication (three simple methods)
- HTTP uses `ProtocolValidatingStream<TcpStream>`; HTTPS uses `TlsStream<TcpStream>`
- These types can't be unified with generics - different crate hierarchies
- Methods are dead simple and stable - bug risk from duplication is negligible
- `ConnectionMeta` trait already provides unified interface for handlers

---

### R3.4: Honeypot Duplication - ❌ NOT REAL ISSUE

**Location**: `src/http/server.rs:900-931`, `src/tls/server.rs:628-641`

**Decision**: Intentional protocol distinctions, not a bug.

**Rationale**:
- HTTP uses `block_ip_for_honeypot`
- HTTPS uses `block_ip_with_threat_intel`
- These represent different security behaviors appropriate for each protocol

---

## Completed Items

### S2.1: Per-Site Connection Limiting - ✅ COMPLETED

**Files**: `src/waf/traffic_shaper/limiter.rs`, `src/http/server.rs`, `src/http3/server.rs`

**Summary**: Two-phase limiting architecture - Phase 1 (SECTION 5) for DoS protection, Phase 2 (SECTION 12) for per-site limits.

---

### Q3.1: Test Coverage - ✅ COMPLETED

**Files**: `tests/integration_test.rs`, `tests/dht_integration_test.rs`

**Summary**: Added 47 tests across HTTP server, DHT operations, proxy pipeline, and security headers.

---

### M5: DHT Conflict Resolution - ✅ COMPLETED

**Files**: `src/mesh/dht/record_store_crud.rs`

**Summary**: Added timestamp-based conflict resolution to `store_record_global()` using `(timestamp, sequence_number, source_node_id)` ordering.

**Future Work (Deferred)**: Per-record-type semantic merge strategies (e.g., ThreatIndicator severity merging, VerifiedUpstream winner selection).

---

### M6: Quorum Verification - ✅ COMPLETED

**Files**: `src/mesh/backend.rs`, `src/mesh/transport_peer.rs`, `src/mesh/dht/quorum.rs`, `src/mesh/dht/record_store_message.rs`, `src/mesh/dht/record_store_crud.rs`

**Summary**: QuorumManager wired for global nodes, quorum broadcast implemented, response handlers added.

---

### M16.9: DHT Re-balancing - ✅ COMPLETED

**Files**: `src/mesh/dht/record_store_message.rs`, `src/mesh/transport_peer.rs`

**Summary**: Added `rebalance_after_departure()` triggered when global node departs.

---

### M16.10: Regional Diversity - ✅ COMPLETED

**Files**: `src/dns/mesh_sync/registration.rs`, `src/dns/mesh_sync/registry.rs`, `src/dns/mesh_sync/mod.rs`

**Summary**: Geo now derived programmatically from IP using existing GeoIP implementation instead of self-reported values.

---

## Implementation Notes

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

## Appendix: Historical Statistics

- Total items in original plan: ~180
- Completed items: ~170
- Remaining deferred items: 1 (Q2.1 - untouchable per AGENTS.md)
- Closed items: 4 (2 not real issues, 2 not recommended)

Last cleanup: 2026-04-16
