# MaluWAF Implementation Plan

This document consolidates all improvement plans into a single roadmap, organized by wave for parallelization.

## Quick Reference

| Wave | Focus | Items | Priority |
|------|-------|-------|----------|
| 1 | Critical Security | 7 | CRITICAL |
| 2 | High Security | 11 | HIGH |
| 3 | Critical Correctness | 2 | CRITICAL |
| 4 | Mesh & DHT Infrastructure | 10 | HIGH |
| 5 | Code Quality (Large Files) | 6 | HIGH |
| 6 | WAF Improvements | 2 | HIGH |
| 7 | Medium Priority | 21 | MEDIUM |
| 8 | Low Priority | 10 | LOW |

**Legend**: 🔶 = Future Work | ✅ = Completed (see git history)

---

## Wave 1: Critical Security Fixes

### 1.1 DNS Dynamic Updates - Client IP Not Validated

**Status**: ✅ Completed (2026-04-10)

**Severity**: CRITICAL

**Location**: `src/dns/update.rs:262-269`

The `_client_ip` parameter in `handle_update()` is unused. Dynamic updates (RFC 2136) have no source IP validation when `enabled=true` and `require_tsig=false`.

**Fix**:
1. Validate client IP against configured ACLs before processing updates
2. Require `require_tsig = true` by default
3. Log all dynamic updates with client IP for audit trail

**Files**: `src/dns/update.rs`, `src/dns/config.rs`

---

### 1.2 TSIG Verification Uses Wrong Message Data

**Status**: ✅ Completed (2026-04-10)

**Severity**: CRITICAL

**Location**: `src/dns/transfer.rs:262-281`

TSIG MAC is computed over just the query name, but RFC 2845 Section 2.4 requires computation over the **entire DNS message**.

**Fix**: Pass the full DNS message bytes to TSIG verification instead of just the qname.

---

### 1.3 NSEC3 Owner Name Hash Length Bug

**Status**: ✅ Completed (2026-04-10)

**Severity**: CRITICAL

**Location**: `src/dns/dnssec_signing.rs:259-262`

`hash.len()` returns raw byte length (20 for SHA-1), but RFC 5155 Section 5 requires the number of base32 characters in the encoded hash (32 for SHA-1).

```rust
// BUG: Uses hash byte length
format!("{}.{}.{}", hash.len(), hash_b32, base_name)

// FIX: Use base32 encoded length
format!("{}.{}.{}", hash_b32.len(), hash_b32, base_name)
```

---

### 1.4 WebSocket Authentication Not Enforced

**Status**: ✅ Completed (2026-04-10)

**Severity**: CRITICAL

**Location**: `src/admin/ws/mod.rs:14-28`

WebSocket handlers accept connections without authentication. The `OptionalAuth` middleware means auth is not enforced.

**Fix**:
1. Replace `OptionalAuth` with explicit token validation
2. Require valid bearer token in WebSocket upgrade request
3. Return 401 Unauthorized for invalid/missing tokens

---

### 1.5 Upstream Verification System Broken

**Status**: ✅ Completed (2026-04-10)

**Severity**: CRITICAL

**Location**: `src/mesh/transport_peer.rs:1639-1643`

`get_verification_manager()` always returns `None`, making the entire upstream reachability verification system non-functional.

```rust
// CURRENT: Always returns None
pub(crate) fn get_verification_manager(&self) -> Option<Arc<...>> {
    None
}

// FIX: Return actual manager
pub(crate) fn get_verification_manager(&self) -> Option<Arc<...>> {
    Some(self.verification_manager.clone())
}
```

---

### 1.6 Verification Response Has No Signature

**Status**: ✅ Completed (2026-04-10)

**Severity**: CRITICAL

**Location**: `src/mesh/transport_peer.rs:1575-1585`

`UpstreamVerificationResponse` has `global_node_signature: None`. Any node can forge verification results.

**Fix**:
1. Sign verification responses using the global node's signing key
2. Verify signature before accepting verification result
3. Add `global_node_signature` field with Ed25519 signature

---

### 1.7 SSRF Domain Substring Bypass

**Status**: ✅ Completed (2026-04-10)

**Severity**: CRITICAL

**Location**: `src/waf/attack_detection/ssrf.rs:243`

SSRF check uses `.contains("localhost")` without word boundaries. Domain `notlocalhost.com` incorrectly blocked (false positive).

**Fix**: Add `.` boundary check:
```rust
// Before
if input_lower.contains("localhost") || input_lower.contains(".local") {

// After  
if input_lower.contains(".localhost") || input_lower.contains("localhost.") 
    || input_lower.contains(".local") || input_lower.ends_with(".local") {
```

---

## Wave 2: High Security Fixes

### 2.1 TLS Passthrough Bypasses WAF

**Status**: ✅ Completed (2026-04-10)

**Severity**: HIGH

**Location**: `src/config/site/proxy.rs:44`, `src/tls/server.rs`

When `tls_passthrough = true`, raw TLS bytes forward directly to upstream. All L7 WAF inspection is bypassed.

**Fix**:
1. Document security implications prominently
2. Add startup warning when passthrough sites are configured
3. Consider adding `tls_passthrough_warn_only` option

---

### 2.2 0-RTT Enabled By Default (Replay Risk)

**Status**: ✅ Completed (2026-04-10)

**Severity**: HIGH

**Location**: `src/mesh/cert.rs:373-374`

QUIC 0-RTT connections are susceptible to replay attacks. No configuration option exists to disable 0-RTT.

**Fix**:
1. Add `quic_enable_0rtt` config option (default: false)
2. Disable 0-RTT by default
3. Document replay attack implications

---

### 2.3 RFC 5011 State Machine Bypasses

**Status**: ✅ Completed (2026-04-10)

**Severity**: HIGH

**Location**: `src/dns/trust_anchor.rs:450-455, 545-565`

Two RFC 5011 bypasses:
1. Keys promoted from Pending to Valid without re-checking DNSKEY RRset
2. Keys can go from Missing to Valid without observation period

**Fix**:
1. Before promoting Pending→Valid, verify key is still in DNSKEY RRset
2. Require Missing→Pending→Valid transition (not direct)

---

### 2.4 Mesh Node Identity Not Verified

**Status**: ✅ Completed (2026-04-10)

**Severity**: HIGH

**Location**: `src/mesh/dht/stake.rs:226-239`

`register_node()` accepts any reputation and role without cryptographic proof. Unknown nodes get `unwrap_or(false)` on stake checks.

**Fix**:
1. Require cryptographic proof during node registration
2. Verify node_id matches the calling peer's verified identity
3. Reject unknown nodes in `can_write_dht()` by default

---

### 2.5 IP Extraction Spoofing via X-Forwarded-For

**Status**: ✅ Completed (2026-04-10)

**Severity**: HIGH

**Location**: `src/admin/middleware.rs:34-61`

`extract_client_ip_from_request()` uses `X-Forwarded-For` header without validating the client is behind a trusted proxy.

**Fix**:
1. Call `configure_trusted_proxies()` during admin server initialization
2. Only use X-Forwarded-For when connection is from trusted proxy
3. Validate IP format before accepting

---

### 2.6 Rate Limiter Race Condition

**Status**: ✅ Completed (2026-04-10)

**Severity**: HIGH

**Location**: `src/admin/auth.rs:35-63`

`record_failure()` adds timestamp before checking limit. With concurrent requests, attacker can exceed limit before lockout triggers.

**Fix**: Use atomic check-and-add pattern:
```rust
pub fn record_failure(&self, identifier: &str) {
    let mut attempts = self.attempts.write();
    // Check first
    if attempts.get(identifier)
        .map(|e| e.0.iter().filter(|t| t.elapsed() < AUTH_WINDOW_DURATION).count())
        .unwrap_or(0) >= MAX_AUTH_ATTEMPTS {
        return;  // Already locked out
    }
    // Then add
    let entry = attempts.entry(identifier.to_string()).or_insert((Vec::new(), false));
    entry.0.push(Instant::now());
}
```

---

### 2.7 AuthStore Merge Loses Data

**Status**: ✅ Completed (2026-04-10)

**Severity**: HIGH

**Location**: `src/auth/mod.rs:162-180`

`merge_stores()` only merges `login_logs`, discarding `users` and `sessions` from all stores except the last.

**Fix**: Merge all collections:
```rust
fn merge_stores(stores: &[AuthStore]) -> AuthStore {
    let mut merged = stores.last().unwrap().clone();
    for store in stores.iter().take(stores.len() - 1) {
        merged.login_logs.extend(store.login_logs.iter().cloned());
        merged.users.extend(store.users.iter().cloned());      // ADD
        merged.sessions.extend(store.sessions.iter().cloned()); // ADD
    }
    merged
}
```

---

### 2.8 CSRF Tokens Not Bound to Session

**Status**: ✅ Completed (2026-04-10)

**Severity**: HIGH

**Location**: `src/admin/state.rs:591-604`

`validate_csrf()` only checks token existence and expiry, not session binding.

**Fix**:
1. Store session ID with CSRF token
2. Validate session ID matches current session
3. Invalidate token on logout

---

### 2.9 WAF Detection Bypasses (URL Decoding)

**Status**: ✅ Completed (2026-04-10)

**Severity**: HIGH

**Location**: Multiple detector files

Several detectors don't URL-decode input before pattern matching:

| Detector | URL Decoding | File |
|----------|-------------|------|
| SSTI | ❌ | `ssti.rs` |
| LDAP Injection | ❌ | `ldap_injection.rs` |
| XPath Injection | ❌ | `xpath_injection.rs` |
| Open Redirect | ❌ | `open_redirect.rs` |
| JWT | ❌ | `jwt.rs` |

**Fix**: Add URL decoding pre-processing to all affected detectors.

---

### 2.10 Private Keys Not Zeroized

**Status**: ✅ Completed (2026-04-10)

**Severity**: MEDIUM

**Location**: `src/mesh/cert.rs:146, 205`

Mesh node private keys stored in memory without `zeroize` for secure clearing.

**Fix**: Use `zeroize::ZeroizeOnDrop` for private key storage.

---

### 2.11 ACME ToS Auto-Accepted

**Status**: ✅ Completed (2026-04-10)

**Severity**: MEDIUM

**Location**: `src/tls/acme.rs:134-138`

ACME client automatically agrees to Let's Encrypt ToS without explicit user opt-in.

**Fix**: Make `terms_of_service_agreed` configurable with explicit user consent.

---

## Wave 3: Critical Correctness Fixes

### 3.1 Proxy Cache LRU Bug - Access Time Never Updated

**Status**: 🔶 Future Work

**Severity**: CRITICAL

**Location**: `src/proxy_cache/store.rs:238,255`

`ProxyCacheEntry` is cloned on every cache hit, but `update_access()` only modifies the clone. LRU eviction never tracks access patterns.

**Fix**: Modify `get()` to update the cached entry directly, or use moka's built-in notification mechanism.

---

### 3.2 DHT Query Response Collection Missing

**Status**: 🔶 Future Work

**Severity**: CRITICAL

**Location**: `src/mesh/dht/record_store_sync.rs:657-718`

`query_record_iterative()` sends DHT record queries but always returns `None`. No mechanism to receive responses.

**Fix**: Implement response tracking using oneshot channels (similar to `pending_queries` pattern in `transport.rs`).

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

### 4.3 DHT Record Expiration Cleanup

**Status**: 🔶 Future Work

**Severity**: HIGH

**Location**: `src/mesh/dht/record_store.rs`, `src/mesh/dht/record_store_crud.rs`

Records stored with TTL but no background task purges expired records. Storage grows indefinitely.

**Fix**:
1. Add `prune_expired()` method to `ShardedRecordStore`
2. Add expiration sweep background task
3. Enforce TTL on read

---

### 4.4 Illegal Upstream Terms Enforcement

**Status**: 🔶 Future Work

**Severity**: HIGH

**Location**: `src/mesh/transport_org.rs`

`illegal_upstream_terms` config exists but is never enforced when storing `verified_upstream` records.

**Fix**: Validate `upstream_url` against `illegal_upstream_terms` before creating `VerifiedUpstream`.

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

### 5.1 Tonic/Axum Version Conflict

**Status**: 🔶 Future Work

**Severity**: P0 (Critical)

**Location**: `Cargo.toml:222-226`

`tonic 0.12.3` pulls `axum 0.7.9`, but main project uses `axum 0.8.8`. 4 file manager routes disabled.

**Fix**: Upgrade tonic to 0.14+:
```toml
tonic = { version = "0.14", features = ["gzip", "prost"] }
tonic-reflection = "0.14"
tonic-build = "0.14"
```

---

### 5.2 Split HttpServer::handle_request()

**Status**: 🔶 Future Work

**Severity**: HIGH

**Location**: `src/http/server.rs` (3,238 lines)

`handle_request()` function is ~2,200 lines, handling too many concerns.

**Proposed Split**:
| New File | Contents |
|----------|----------|
| `http/internal_handlers.rs` | Drain, health, ready endpoint handlers |
| `http/websocket_handler.rs` | WebSocket tunnel handling |
| `http/waf_decision.rs` | WAF check integration and decision handling |
| `http/routing.rs` | Routing logic extraction |

---

### 5.3 Split HttpsServer::handle_request_with_cache()

**Status**: 🔶 Future Work

**Severity**: HIGH

**Location**: `src/tls/server.rs` (1,747 lines)

Mirrors `http/server.rs` with massive `handle_request_with_cache()` ~1,200 lines.

**Proposed Split**:
| New File | Contents |
|----------|----------|
| `tls/internal_handlers.rs` | Drain, health, ready handlers |
| `tls/tls_handshake.rs` | TLS handshake handling |
| `tls/https_routing.rs` | Routing logic extraction |

---

### 5.4 Split mesh/transport.rs

**Status**: 🔶 Future Work

**Severity**: HIGH

**Location**: `src/mesh/transport.rs` (~2,570 lines)

Already split into 11 submodules, but main file still oversized.

**Proposed Split**:
1. `mesh/transport_accept.rs` - Connection acceptance loop
2. `mesh/transport_dispatch.rs` - Message routing logic

---

### 5.5 Split mesh/config.rs

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/config.rs` (~1,539 lines)

**Proposed Split**:
1. `mesh/config/identity.rs` - Node identity and key derivation
2. `mesh/config/node.rs` - Node configuration structs
3. `mesh/config/cert.rs` - Certificate management

---

### 5.6 Split mesh/topology.rs

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/topology.rs` (~1,516 lines)

Types already extracted to `topology/types.rs`. Remaining issues:
- Local upstream management
- Topology state and updates

**Proposed Split**:
1. `mesh/topology/store.rs` - Local upstream storage
2. `mesh/topology/state.rs` - Topology state management

---

## Wave 6: WAF Improvements

### 6.1 Fix SSRF Domain Substring Bypass

**Status**: 🔶 Future Work (Also in Wave 1)

See Wave 1.7.

---

### 6.2 Add URL Decoding to WAF Detectors

**Status**: 🔶 Future Work (Also in Wave 2)

See Wave 2.9.

---

## Wave 7: Medium Priority

### 7.1 Audit unwrap()/expect() in Critical Paths

**Status**: 🔶 Future Work

**Severity**: P1

558 `.unwrap()` and 99 `.expect()` calls represent potential panic points.

**Scope**: Critical paths in:
- `src/proxy.rs`
- `src/mesh/proxy.rs`, `src/mesh/transport.rs`
- `src/dns/server/query.rs`
- `src/http/server.rs`

**Target**: Reduce unwraps in critical paths by 50%.

---

### 7.2 Standardize Result Type Usage

**Status**: 🔶 Future Work

**Severity**: P1

Only 5 files use `anyhow::Result` while most use explicit `Result<T, ErrorType>`.

**Decision Needed**: Choose approach:
1. **Option A**: Standardize on `anyhow::Result<T>`
2. **Option B**: Use explicit Result types everywhere

**Recommendation**: Option B is more appropriate for a security product.

---

### 7.3 Add #[track_caller] to Error Types

**Status**: 🔶 Future Work

**Severity**: P1

54 error types lack `#[track_caller]`, making error propagation hard to debug.

**Fix**: Add `#[track_caller]` to custom error types derived with `thiserror::Error`.

---

### 7.4 Fix Lock-Held-Across-Await Pattern

**Status**: 🔶 Future Work

**Severity**: P2

**Location**: `src/process/manager.rs:982-996`

`parking_lot::RwLock` held across await-able operations in heartbeat handler.

**Fix**: Restructure to not hold lock while potentially awaiting.

---

### 7.5 Address pending_queries Lock Pattern

**Status**: 🔶 Future Work

**Severity**: P2

**Location**: `src/mesh/transport.rs:1876-1923`

`pending_queries` lock acquired, released, awaits, then acquired again **twice**.

**Fix**: Combine into single lock acquisition or use transaction-style approach.

---

### 7.6 Replace Deep Imports with crate:: Paths

**Status**: 🔶 Future Work

**Severity**: P2

18 files use `use super::super::` pattern in `admin/handlers/`.

**Fix**: Replace with `use crate::admin::state::AdminState;`

---

### 7.7 Group Import Statements

**Status**: 🔶 Future Work

**Severity**: P2

Imports not grouped with blank lines between std/external/crate.

**Fix**: Organize per Rust style guide.

---

### 7.8 Standardize Builder Pattern Naming

**Status**: 🔶 Future Work

**Severity**: P2

**Location**: `src/config/process.rs:232-273`

`SupervisorConfigBuilder` uses `min_workers()` instead of `with_min_workers()`.

**Fix**: Rename to `with_min_workers()`, `with_max_workers()`, etc.

---

### 7.9 Document Public APIs

**Status**: 🔶 Future Work

**Severity**: P2

Only 431 doc comments (`///`) found; many public `fn` items lack documentation.

**Scope**: Focus on core modules:
- `src/http/server.rs`
- `src/proxy.rs`
- `src/process/manager.rs`
- `src/mesh/transport.rs`

---

### 7.10 Connection Rate Limiter O(n) Iteration

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/transport.rs:2524-2542`

Connection rate limit check iterates entire `Vec<Instant>` using `retain`.

**Fix**: Use ring buffer or sorted timestamp structure for O(1) rate limiting.

---

### 7.11 Serial Health Checks

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/transport.rs:1003-1018`

Health checks performed sequentially for each peer.

**Fix**: Use `futures::future::join_all()` or `FuturesUnordered`.

---

### 7.12 Serial Upstream Announce Loop

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/transport.rs:2066-2111`

Upstream announcement iterates through all global peers serially.

**Fix**: Use `FuturesUnordered` for parallel sends.

---

### 7.13 Rate Limiter Cleanup Lock Contention

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/waf/ratelimit.rs:282-299`

Cleanup holds write lock during `retain()` O(n) operation across 16 shards.

**Fix**: Consider `RwLock` with read-heavy workload optimization, or batch cleanup.

---

### 7.14 Nested Spawns in Mesh Broadcast

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/worker/unified_server.rs:709-720`

Each mesh message spawns a task that calls `broadcast_to_all_peers`, which spawns N tasks internally. Creates exponential task growth.

**Fix**: Remove nested spawn, call `broadcast_to_all_peers` directly in loop.

---

### 7.15 HTTP Path Sanitization Allocations

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/proxy.rs:138-233`

Every proxied request allocates multiple `Vec`s and intermediate buffers.

**Fix**: Use thread-local buffer reuse and avoid allocation for common "fast path".

---

### 7.16 Response Header Filtering Allocations

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/proxy.rs:236-248, 1345`

Creates new `Vec<(String, String)>` on every proxied response.

**Fix**: Use thread-local buffer or stack-allocated array for small header counts.

---

### 7.17 Static File Zero-Copy Broken

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/http/server.rs:1413-1461`

Manual buffering defeats streaming body. Entire file held in memory.

**Fix**: Use `StreamBody` directly without buffering.

---

### 7.18 Unified Announcement Mechanism

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/transport.rs`, `src/mesh/transport_org.rs`

Two mechanisms exist: `UpstreamAnnounce` (fire-and-forget) and `UpstreamRegistrationRequest` (reliable).

**Fix**: Deprecate `UpstreamAnnounce` for route announcements, use `UpstreamRegistrationRequest` exclusively.

---

### 7.19 DHT Key Type Consistency

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/dht/keys.rs`, `src/mesh/dht/routing/manager.rs`

`is_privileged()` and `is_global_signature_required()` check different sets of keys.

**Fix**: Unify key classification.

---

### 7.20 Reputation System Clarification

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/dht/mod.rs`, `src/mesh/config.rs`

`min_reputation_for_dht_write` defaults to 30, but no assignment mechanism exists.

**Fix**: Either implement proper reputation system or remove threshold.

---

### 7.21 Global Node Liveness and Quorum Monitoring

**Status**: 🔶 Future Work

**Severity**: MEDIUM

**Location**: `src/mesh/dht/record_store.rs`, `src/mesh/dht/routing/manager.rs`

No explicit liveness tracking for global nodes.

**Fix**:
1. Add `GlobalNodeHeartbeat` DHT record with short TTL (60s)
2. Global nodes publish heartbeat periodically
3. Modify quorum calculation to use live node count

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

Multiple entire modules suppress `unused_variables` and `dead_code`.

**Approach**:
1. Determine which modules are genuinely incomplete vs just have unused items
2. For genuinely incomplete: add TODO markers
3. For unused items: remove dead code or mark as intentionally reserved

---

### 8.3 Complete Admin UI Orphaned Files

**Status**: 🔶 Future Work

**Severity**: P3

`admin-ui/src/config_docs.rs` (538 lines) is not declared as a module.

**Fix**: Either declare as module, move to `docs/`, or delete.

---

### 8.4 Add Architecture Decision Records

**Status**: 🔶 Future Work

**Severity**: P3

No ADR document exists for major decisions.

**Scope**: Create `docs/adr/` with records for:
- ADR-001: Multi-process architecture choice
- ADR-002: DNSSEC validation limited to Recursive provider
- ADR-003: DHT as primary YARA/ThreatIntel propagation
- ADR-004: Global nodes as trust anchors (not elected)
- ADR-005: Single async worker process (not multi-process scaling)

---

### 8.5 Dead Code Annotations Audit

**Status**: 🔶 Future Work

**Severity**: LOW

116 `#[allow(dead_code)]` annotations across codebase. Most intentional (reserved/future functionality), but some may indicate truly dead code.

**Approach**:
1. Audit each file category for truly dead code
2. Remove `#[allow(dead_code)]` where code is actually dead
3. Keep annotations where reserved/future functionality exists

---

### 8.6 Unsafe Code Audit

**Status**: 🔶 Future Work

**Severity**: LOW

~94 `unsafe` blocks across codebase. Need to ensure safety requirements are documented.

**Approach**:
1. Audit all `unsafe` blocks for safety comments
2. Add `// SAFETY:` annotations where missing
3. Verify unsafe code is minimal and necessary

---

### 8.7 Documentation Gaps

**Status**: 🔶 Future Work

**Severity**: LOW

Several large modules lack module-level documentation:
- `src/block_store.rs` (813 lines) - Missing
- `src/utils.rs` (998 lines) - Minimal

**Fix**:
1. Add module documentation to `block_store.rs`
2. Consider splitting `utils.rs` into `utils/` submodule

---

### 8.8 ShardedZoneStore Full-Shard Iteration

**Status**: 🔶 Future Work

**Severity**: LOW

**Location**: `src/dns/server/sharded_store.rs:66-102`

`keys()`, `len()`, `for_each()` lock ALL 64 shards sequentially.

**Fix**: Make iteration lazy or add async iteration support.

---

### 8.9 DHT Metrics and Observability

**Status**: 🔶 Future Work

**Severity**: LOW

No metrics for DHT operations beyond basic counters.

**Fix**:
1. Add metrics for cache hit/miss, latency percentiles, quorum success/failure
2. Add tracing spans for DHT operations
3. Add admin API to dump DHT statistics

---

### 8.10 Configuration Documentation

**Status**: 🔶 Future Work

**Severity**: LOW

Many config fields lack documentation.

**Fix**:
1. Add doc comments to all `MeshDhtConfig` fields
2. Add example config snippets
3. Update skill file with all config options

---

## Parallelization Strategy

### Phase 1 (Can run in parallel - Security Critical)
- **Agent 1**: Wave 1 items 1.1-1.3 (DNS Security)
- **Agent 2**: Wave 1 items 1.4-1.7 (Auth/Verification/SSRF)
- **Agent 3**: Wave 2 items 2.1-2.5 (TLS, RFC5011, Mesh Identity)
- **Agent 4**: Wave 2 items 2.6-2.9 (Auth, Rate limiting, WAF)

### Phase 2 (Depends on Phase 1 completion for some)
- **Agent 5**: Wave 3 items 3.1-3.2 (Critical Correctness)
- **Agent 6**: Wave 4 items 4.1-4.5 (Mesh Critical/High)
- **Agent 7**: Wave 4 items 4.6-4.11 (Threat Intel)

### Phase 3 (Code Quality - Can run parallel)
- **Agent 8**: Wave 5 items 5.1-5.3 (HTTP/TLS Server Split)
- **Agent 9**: Wave 5 items 5.4-5.6 (Mesh Module Split)
- **Agent 10**: Wave 7 items 7.1-7.9 (Code Style)

### Phase 4 (Cleanup - Lower priority)
- **Agent 11**: Wave 7 items 7.10-7.21 (Medium Priority)
- **Agent 12**: Wave 8 items 8.1-8.10 (Low Priority)

---

## Dependencies

### Critical Dependencies
- **P0.1** (Tonic upgrade) must be completed before **5.2** and **5.3** (file manager routes depend on tonic)
- **Wave 3** (Critical Correctness) should be prioritized before Wave 7 medium items

### Recommended Order
1. Wave 1 (Critical Security) - 7 items
2. Wave 2 (High Security) - 11 items
3. Wave 3 (Critical Correctness) - 2 items
4. Wave 4 (Mesh & DHT) - 11 items
5. Wave 5 (Code Quality) - 6 items
6. Wave 6 (WAF) - 2 items (overlaps with Wave 1/2)
7. Wave 7 (Medium) - 21 items
8. Wave 8 (Low) - 10 items

---

## Testing Requirements

### Unit Tests
- All new helper functions
- Error handling paths
- Cache TTL expiration
- Lock-free data structures

### Integration Tests
- Full ownership challenge flow with mock servers
- Genesis key rotation between two nodes
- DHT record expiration and cleanup
- Cache staleness detection and refresh

### Security Tests
- Replay attack with 0-RTT disabled
- IP spoofing blocked by trusted proxy check
- WAF bypass attempts with encoded payloads

---

## Rollback Plan

Each phase includes rollback considerations:

**Wave 1-2 (Security)**:
- Config flags for new behavior (disabled by default during rollout)
- Incremental enablement per-site/region

**Wave 3 (Correctness)**:
- Cache LRU fix is safe - existing entries remain valid
- DHT fix can be reverted to return None behavior if needed

**Wave 5 (Module Split)**:
- Revert module declarations - keep extracted files, revert main file
- Run integration tests after each split

---

## Success Metrics

1. **Zero CRITICAL security issues remaining**
2. **Zero disabled routes due to dependency conflicts**
3. **unwrap() count reduced** in critical paths by 50%
4. **All public APIs documented** in core modules
5. **Import groups consistent** across codebase (verified by rustfmt)
6. **No lock-held-across-await** anti-patterns remaining
7. **Module sizes**:
   - `http/server.rs`: <1,000 lines (currently 3,238)
   - `mesh/transport.rs`: <1,000 lines (currently ~2,570)
   - `mesh/config.rs`: <1,000 lines (currently ~1,539)
   - `mesh/topology.rs`: <1,000 lines (currently ~1,516)
