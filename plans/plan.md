# MaluWAF Implementation Plan

Last updated: 2026-04-13

## Overview

This document tracks remaining work. Completed items have been pruned.
Reference material for completed items is in `plans/COMPLETED.md`.

---

## Quick Reference

| ID | Focus | Status |
|----|-------|--------|
| W2.5 | Origin Upstream Ownership Verification | ⚠️ Partial (stubbed) |
| W2.7 | Tier Key Encryption Scope Extension | ⚠️ Partial (TierKey only) |
| W3.2 | Stream Large Request Bodies | ❌ Open |
| W3.3 | Response Streaming | ❌ Open (HTTPS streaming, HTTP buffered) |
| W3.4 | ConnectionMeta Trait Migration | ⏸️ Deferred |
| W3.6 | Edge Node HTTP Response Cache | ❌ Not Implemented |
| W3.7 | Image Poison Cache TTL/Invalidation | ⚠️ Partial (DHT key added) |
| W4.1 | handle_request() Refactor | ⏸️ Deferred (per AGENTS.md guidance) |

---

## Wave 2: High Security - TLS, DNS, Mesh

### ⚠️ W2.5: Origin Upstream Ownership Verification - PARTIAL

**Severity**: HIGH

**Location**: `src/mesh/transport_peer.rs:1706-1790`, `src/mesh/verification.rs`

**Issue**: `VerifiedUpstream` requires global node signature but no mechanism verifies origin actually serves claimed URL.

**Status**: HTTP-01 and DNS-01 challenge handlers are **stubbed/simulated**:
- HTTP-01 handler echoes back `key_authorization` without serving it at `/.well-known/malu-challenge/{token}`
- DNS-01 handler logs TXT values but doesn't provision them
- `VerificationTaskManager` (tracking/penalties) is fully implemented

**Remaining Work**:
1. Implement actual HTTP-01 challenge serving
2. Implement actual DNS-01 challenge provisioning
3. Wire verification loop to periodic re-verification
4. Revoke on failure

---

### ⚠️ W2.7: Tier Key Encryption Scope Extension - PARTIAL

**Severity**: MEDIUM

**Location**: `src/mesh/tier_key_encryption.rs`, `src/mesh/transport_org.rs`

**Issue**: `TierKeyEncryption` only encrypts `tier_key:` records, but other `requires_global_node()` records are stored plaintext.

**Status**: Only `TierKey` records are encrypted. Other `requires_global_node()` records are **stored plaintext**:
- Organization
- MemberCertificate
- GlobalNodeList
- OrgNameReservation
- DnsZone
- DnsDomainRegistration
- AnycastNode

**Remaining Work**:
1. Encrypt all `requires_global_node()` record types
2. Derive per-record-type encryption keys via HKDF
3. Store with `encrypted:` prefix, old records continue working

---

## Wave 3: Core Functionality

### ❌ W3.2: Stream Large Request Bodies - OPEN

**Severity**: HIGH

**Location**: `src/http/server.rs`, `src/tls/server.rs`

**Issue**: Full request body buffered in memory.

**Status**: Chunk-based WAF scanning exists (can block attacks mid-stream), but body is still **fully buffered** for handler consumption.

**Remaining Work**:
1. Implement true streaming in `handle_request()` pipeline
2. Process body in chunks rather than buffering full body
3. Add configurable body buffer limit with early rejection

---

### ❌ W3.3: Response Streaming - OPEN

**Severity**: HIGH

**Location**: `src/http/server.rs`, `src/tls/server.rs`

**Issue**: Responses fully buffered before sending.

**Status**: **Inconsistent** - HTTPS (`tls/server.rs`) truly streams responses, but HTTP (`http/server.rs`) fully buffers.

**Remaining Work**:
1. Enable HTTP response streaming via `hyper::body::Body`
2. Chunked transfer encoding for HTTP
3. WAF response filtering in streaming mode

---

### ⏸️ W3.4: ConnectionMeta Trait Migration - DEFERRED

**Severity**: MEDIUM

**Location**: `src/server/request_handler.rs`, `src/http/server.rs`, `src/tls/server.rs`

**Issue**: `ConnectionMeta` trait and `TlsContext` exist but not fully wired. TLS handler has duplicate code.

**Status**: Infrastructure exists. Full migration requires significant refactoring.

**Note**: Per AGENTS.md guidance, `http/server.rs` and `tls/server.rs` are exceptions to size guidelines as cohesive request pipelines. Splitting is not recommended.

**Remaining Work** (if pursued):
1. Complete migration of request processing to use unified handler
2. Remove duplicate code in `tls/server.rs`

---

### ❌ W3.6: Edge Node HTTP Response Cache - NOT IMPLEMENTED

**Severity**: HIGH

**Location**: `src/mesh/proxy.rs`

**Issue**: `MeshProxy::new()` has `_cache_config: Option<ProxyCacheSettings>` (underscore prefix - unused).

**Status**: **Not implemented**:
- `proxy_cache` field missing from `MeshProxy` struct
- `SiteCachePreferencesStore` not found in codebase
- `proxy_cache_preferences` passed in mesh messages but ignored

**Remaining Work**:
1. Add `proxy_cache: Option<Arc<ProxyCache>>` to `MeshProxy`
2. Implement `SiteCachePreferencesStore`
3. Integrate with MeshProxy for cache lookup before proxying
4. Store responses in cache if cacheable

---

### ⚠️ W3.7: Image Poison Cache TTL and Invalidation - PARTIAL

**Severity**: MEDIUM

**Location**: `src/mesh/dht/keys.rs`

**Issue**: Poisoned images cached with fixed 1-hour TTL, no invalidation when origin content changes.

**Status**: `SiteContentVersion` DHT key type added.

**Remaining Work** (deferred):
1. Modify poison cache key format to include version
2. Implement version storage/increment logic
3. Add manual invalidation endpoint

---

## Wave 4: Code Quality

### ⏸️ W4.1: handle_request() Refactor - DEFERRED

**Severity**: HIGH

**Location**: `src/http/server.rs:437-1800`

**Issue**: `handle_request()` spans ~1,363 lines handling 15 phases.

**Status**: Per AGENTS.md guidance, `http/server.rs` is an exception to size guidelines. Section comments delineate the 15 phases. Splitting not recommended.

**Remaining Work** (if pursued):
1. Extract each phase into a private async helper function
2. Add `RequestContext` struct to carry state between phases

---

## Future Work (Lower Priority)

These items can be addressed after the items above.

| ID | Item | Location | Issue |
|----|------|----------|-------|
| F.1 | ShardedZoneStore is_empty() Optimization | `src/dns/server/sharded_store.rs` | `is_empty()` iterates all 64 shards O(n) |
| F.2 | DHT Metrics and Observability | `src/mesh/dht/`, `src/metrics/mod.rs` | Limited observability into DHT operations |
| F.3 | Configuration Documentation for DhtConfig | `src/mesh/dht/mod.rs` | DhtConfig fields lack documentation |
| F.4 | CSS Honeypot Enhancement - Path Tracking | `src/challenge/honeypot.rs` | Honeypot doesn't track which app_path served trap |
| F.5 | Metrics for Threat Intel DHT Operations | `src/metrics/mod.rs`, `src/mesh/threat_intel.rs` | No observability into Threat Intel DHT ops |
| F.8 | Reputation System Bug - Hardcoded 50 | `src/mesh/transport_dht.rs` | Hardcoded 50 reputation threshold |
| F.9 | Global Node Liveness and Quorum Monitoring | `src/mesh/dht/`, `src/mesh/transport_global.rs` | No heartbeat mechanism |
| F.10 | IPv6 Zone ID SSRF Bypass | `src/waf/attack_detection/ssrf.rs` | `looks_like_ip()` doesn't strip zone IDs |
| F.11 | Homoglyph Normalization Gaps | `src/waf/attack_detection/normalizer.rs` | Missing Cyrillic/Greek normalizations |
| F.12 | TODO Comments - File Manager | `src/http/file_manager.rs` | TODO comments still present |
| F.13 | ConnectionMeta Trait - Remaining Migration | `src/server/request_handler.rs` | (See W3.4 - partial) |

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
```
