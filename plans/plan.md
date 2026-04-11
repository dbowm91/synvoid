# MaluWAF Implementation Plan

This document tracks remaining improvement work. All completed items have been removed.

## Quick Reference

| Wave | Focus | Items | Priority | Status |
|------|-------|-------|----------|--------|
| 3 | Critical Correctness | 2 | CRITICAL | 🔶 1 item future work |
| 4 | Mesh & DHT Infrastructure | 10 | HIGH | 🔶 All future work |
| 5 | Code Quality (Large Files) | 6 | HIGH | 🔶 All future work |
| 7 | Medium Priority | 21 | MEDIUM | 🔶 All future work |
| 8 | Low Priority | 10 | LOW | 🔶 All future work |

**Legend**: 🔶 = Future Work | ✅ = Completed (see git history)

---

## Wave 3: Critical Correctness

### 3.2 DHT Query Response Collection Missing

**Status**: 🔶 Future Work

**Severity**: CRITICAL

**Location**: `src/mesh/dht/record_store_sync.rs:657-718`

`query_record_iterative()` has response collection code using oneshot channels, but the function itself is never called anywhere in the codebase (dead code). The response collection mechanism appears correct when examined in isolation.

**Fix**: Either wire up `query_record_iterative` to actual DHT lookup paths, or remove as dead code.

---

## Wave 4: Mesh & DHT Infrastructure

### 4.1 Upstream Ownership Validation

**Status**: 🔶 Future Work

**Severity**: CRITICAL

**Location**: `src/mesh/transport_org.rs`, `src/mesh/dht/keys.rs`, `src/mesh/topology.rs`

Origin nodes can claim ownership of any upstream domain without verification.

**Fix**: Implement DNS-01 or HTTP-01 ownership challenge before approving `VerifiedUpstream`.

---

### 4.2 Genesis Key Rotation and Revocation

**Status**: 🔶 Future Work

**Severity**: CRITICAL

**Location**: `src/mesh/config_identity.rs`, `src/mesh/config.rs`, `src/mesh/dht/keys.rs`

If the genesis key is compromised, all derived signing keys are compromised. No rotation or revocation mechanism.

**Fix**:
1. Add `previous_genesis_key_base64` and `rotation_sequence` to `GenesisKeyConfig`
2. Add `GenesisKeyTransition` DHT key type
3. Add `RevokedGlobalNode` DHT key type
4. Modify `validate_peer_role()` to check revocation list

---

### 4.5 VerifiedUpstream Cache Staleness

**Status**: 🔶 Future Work

**Severity**: HIGH

**Location**: `src/mesh/topology.rs:57-60, 736-738`

Cache returns stale data without checking staleness on read. Edge nodes may route to removed origins for up to 30 seconds.

**Fix**: Implement stale-while-revalidate pattern - return stale data immediately but refresh in background.

---

### 4.6 Edge Node DHT Propagation Blocked

**Status**: 🔶 Future Work

**Severity**: HIGH

**Location**: `src/mesh/dht/record_store_crud.rs:520`

Edge nodes can store but cannot propagate threat indicators via DHT. `create_record_announce()` returns `None` for non-global nodes.

**Fix**: Modify `create_record_announce()` to allow edge nodes for public record types (`ThreatIndicator`).

---

### 4.7 Local Key Format Inconsistency

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/mesh/threat_intel.rs`

Local indicators use different key formats depending on source, causing deduplication issues.

| Source | Key Format |
|--------|------------|
| Honeypot | `"honeypot:global:I:192.168.1.1"` |
| Rate Limit | `"global:192.168.1.1:ratelimit"` |
| DHT Sync | `"192.168.1.1"` |

**Fix**: Normalize all local keys to use IP as canonical key.

---

### 4.8 DHT Sync Interval Too Long

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/threat_intel.rs:1424`

`sync_from_dht()` runs every 300 seconds (5 minutes). For threat intelligence, faster propagation may be desirable.

**Fix**: Add separate `threat_sync_interval_secs` config field (default: 60 seconds).

---

### 4.9 Honeypot Standalone Mode - Local Blocking Gap

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/mesh/threat_intel.rs:385-456`

When mesh is disabled, standalone `ThreatIntelligenceManager` does NOT apply blocks when honeypot indicators are announced.

**Fix**: In `announce_honeypot_indicator()`, also call `block_store.block_ip()` for local honeypot indicators.

---

### 4.10 Add Version Tracking to Threat Intel Sync

**Status**: 🔶 Future Work

**Severity**: HIGH

**Location**: `src/mesh/threat_intel.rs:1057-1081`

YARA rules use manifest-based version tracking. Threat intel's `sync_from_dht()` lacks version tracking - adds all records without comparing versions.

**Fix**:
1. Introduce `ThreatIntelManifest` type (mirrors `YaraRulesManifest`)
2. Store manifest in DHT when publishing indicators
3. Use manifest for sync instead of processing all records blindly

---

### 4.11 Add Sync Startup Logging to Threat Intel

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/mesh/threat_intel.rs:1420-1456`

YARA rules logs startup but threat intel has no equivalent logging.

**Fix**: Add logging in `start_background_tasks()` similar to YARA.

---

## Wave 5: Code Quality (Large File Splitting)

**Note**: Files marked as deferred due to existing fragmentation or architectural rationale.

### 5.3 Split HttpsServer::handle_request_with_cache()

**Status**: 🔶 Future Work

**Location**: `src/tls/server.rs`

Mirrors `http/server.rs` reasoning - cohesive request pipeline. Section comments approach recommended.

---

### 5.4 Split mesh/transport.rs

**Status**: 🔶 Future Work

**Location**: `src/mesh/transport.rs` (~2,570 lines)

Already split into 11 submodules, but main file still oversized.

**Proposed Split**:
1. `mesh/transport_accept.rs` - Connection acceptance loop
2. `mesh/transport_dispatch.rs` - Message routing logic

---

### 5.5 Split mesh/config.rs

**Status**: 🔶 Future Work

**Location**: `src/mesh/config.rs` (~1,539 lines)

**Proposed Split**:
1. `mesh/config/identity.rs` - Node identity and key derivation
2. `mesh/config/node.rs` - Node configuration structs
3. `mesh/config/cert.rs` - Certificate management

---

### 5.6 Split mesh/topology.rs

**Status**: 🔶 Future Work

**Location**: `src/mesh/topology.rs` (~1,516 lines)

Types already extracted to `topology/types.rs`. Remaining issues:
- Local upstream management
- Topology state and updates

**Proposed Split**:
1. `mesh/topology/store.rs` - Local upstream storage
2. `mesh/topology/state.rs` - Topology state management

---

## Wave 7: Medium Priority

### 7.3 Add #[track_caller] to Error Types

**Status**: 🔶 Future Work

**Severity**: P1

54 error types use `thiserror::Error` but none use `#[track_caller]`. Adding it would improve error chain debugging.

**Fix**: Add `#[track_caller]` to custom error types derived with `thiserror::Error`.

---

### 7.6 Replace Deep Imports with crate:: Paths

**Status**: 🔶 Future Work

**Severity**: P2

18 files use `use super::super::` pattern which works correctly. Changing to absolute paths is a style preference, not a bug.

**Note**: Won't fix unless explicitly requested.

---

### 7.7 Group Import Statements

**Status**: 🔶 Future Work

**Severity**: P2

Files follow reasonable import grouping. Minor inconsistencies possible but nothing requiring action.

---

### 7.8 Standardize Builder Pattern Naming

**Status**: 🔶 Future Work

**Severity**: P2

`SupervisorConfigBuilder` uses `min_workers()` which is idiomatic Rust builder pattern. `with_` prefix is also valid but not required.

**Note**: Won't fix unless explicitly requested.

---

### 7.9 Document Public APIs

**Status**: 🔶 Future Work

**Severity**: P2

Two of four core modules lack doc comments:
- `src/http/server.rs` - Missing module docs
- `src/process/manager.rs` - Missing module docs

`src/proxy.rs` and `src/mesh/transport.rs` have proper docs.

---

### 7.10 Connection Rate Limiter O(n) Iteration

**Status**: 🔶 Future Work

**Severity**: MEDIUM

Uses `retain()` O(n) but vector is bounded. Acceptable for current use case.

**Fix**: Use ring buffer or sorted timestamp structure for O(1) rate limiting.

---

### 7.11 Serial Health Checks

**Status**: 🔶 Future Work

**Severity**: MEDIUM

Health checks are serial by design (avoids thundering herd). Not a bug.

---

### 7.12 Serial Upstream Announce Loop

**Status**: 🔶 Future Work

**Severity**: MEDIUM

Upstream announcement iterates through global peers serially. Could use `FuturesUnordered` for parallel sends.

---

### 7.13 Rate Limiter Cleanup Lock Contention

**Status**: 🔶 Future Work

**Severity**: MEDIUM

Cleanup holds write lock during `retain()` O(n). Early-continue optimization already helps.

---

### 7.14 Nested Spawns in Mesh Broadcast

**Status**: 🔶 Future Work

**Severity**: MEDIUM

Potential exponential task growth at low message rates. Not a practical issue.

---

### 7.15 HTTP Path Sanitization Allocations

**Status**: 🔶 Future Work

**Severity**: MEDIUM

Fast path avoids allocation but multiple `Vec`s allocated on some paths.

---

### 7.16 Response Header Filtering Allocations

**Status**: 🔶 Future Work

**Severity**: MEDIUM

Creates new `Vec` on every proxied response. Acceptable for correctness.

---

### 7.17 Static File Zero-Copy Broken

**Status**: 🔶 Future Work

**Severity**: MEDIUM

Manual buffering defeats streaming. Would need architectural change.

---

### 7.18 Unified Announcement Mechanism

**Status**: 🔶 Future Work

**Severity**: MEDIUM

Two mechanisms exist (`UpstreamAnnounce` vs `UpstreamRegistrationRequest`). Deprecation decision needed.

---

### 7.19 DHT Key Type Consistency

**Status**: 🔶 Future Work

**Severity**: MEDIUM

`is_privileged()` and `is_global_signature_required()` check different key sets.

---

### 7.20 Reputation System Clarification

**Status**: 🔶 Future Work

**Severity**: MEDIUM

`min_reputation_for_dht_write` defaults to 30 but no assignment mechanism exists.

---

### 7.21 Global Node Liveness and Quorum Monitoring

**Status**: 🔶 Future Work

**Severity**: MEDIUM

Would add `GlobalNodeHeartbeat` DHT record with short TTL. Feature implementation.

---

## Wave 8: Low Priority

### 8.1 Update dead_code Count in AGENTS.md

**Status**: 🔶 Future Work

**Severity**: P3

AGENTS.md states "~72" `#[allow(dead_code)]` annotations, actual count is ~116.

**Fix**: Update line 266 in `AGENTS.md`.

---

### 8.2 Audit Module-Level allow Attributes

**Status**: 🔶 Future Work

**Severity**: P3

Multiple modules suppress `unused_variables` and `dead_code`. Audit to determine which are genuinely incomplete vs unused.

---

### 8.3 Complete Admin UI Orphaned Files

**Status**: 🔶 Future Work

**Severity**: P3

`admin-ui/src/config_docs.rs` (538 lines) not declared as module. Decide to declare, move to docs/, or delete.

---

### 8.4 Add Architecture Decision Records

**Status**: 🔶 Future Work

**Severity**: P3

No ADR documents for major decisions. Create `docs/adr/` with records for key architectural choices.

---

### 8.5 Dead Code Annotations Audit

**Status**: 🔶 Future Work

**Severity**: LOW

116 `#[allow(dead_code)]` annotations. Audit for truly dead code vs reserved/future functionality.

---

### 8.6 Unsafe Code Audit

**Status**: 🔶 Future Work

**Severity**: LOW

~94 `unsafe` blocks. Add `// SAFETY:` annotations where missing.

---

### 8.7 Documentation Gaps

**Status**: 🔶 Future Work

**Severity**: LOW

`src/block_store.rs` (813 lines) and `src/utils.rs` (998 lines) lack module documentation.

---

### 8.8 ShardedZoneStore Full-Shard Iteration

**Status**: 🔶 Future Work

**Severity**: LOW

`keys()`, `len()`, `for_each()` lock ALL 64 shards sequentially. Consider async iteration.

---

### 8.9 DHT Metrics and Observability

**Status**: 🔶 Future Work

**Severity**: LOW

No metrics for DHT operations beyond basic counters. Add tracing spans and admin API for DHT stats.

---

### 8.10 Configuration Documentation

**Status**: 🔶 Future Work

**Severity**: LOW

Many config fields lack documentation. Add doc comments to `MeshDhtConfig` fields.

---

## Testing Requirements (General Guidance)

### Unit Tests
- All new helper functions
- Error handling paths
- Cache TTL expiration
- Lock-free data structures

### Integration Tests
- Full ownership challenge flow with mock servers (Wave 4.1)
- Genesis key rotation between two nodes (Wave 4.2)
- DHT record expiration and cleanup
- Cache staleness detection and refresh (Wave 4.5)

### Security Tests
- Replay attack with 0-RTT disabled
- IP spoofing blocked by trusted proxy check
- WAF bypass attempts with encoded payloads
