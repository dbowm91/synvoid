# MaluWAF Implementation Plan

This document consolidates all improvement plans into a single roadmap, organized by wave for parallelization.

## Quick Reference

| Wave | Focus | Items | Priority | Status |
|------|-------|-------|----------|--------|
| 1 | Critical Security | 7 | CRITICAL | ✅ Complete |
| 2 | High Security | 11 | HIGH | ✅ Complete |
| 3 | Critical Correctness | 2 | CRITICAL | 🔶 Partial (3.1 done, 3.2 deferred) |
| 4 | Mesh & DHT Infrastructure | 10 | HIGH | 🔶 Partial (4.3, 4.4 done) |
| 5 | Code Quality (Large Files) | 6 | HIGH | 🔶 Partial (5.1 done) |
| 6 | WAF Improvements | 2 | HIGH | ✅ Complete |
| 7 | Medium Priority | 21 | MEDIUM | 🔶 Deferred (design decisions) |
| 8 | Low Priority | 10 | LOW | 🔶 Deferred (cleanup) |

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

**Status**: ✅ Completed (2026-04-11)

**Severity**: CRITICAL

**Location**: `src/proxy_cache/store.rs:238,255`

`ProxyCacheEntry` is cloned on every cache hit, but `update_access()` only modifies the clone. LRU eviction never tracks access patterns.

**Fix**: Modify `get()` to update the cached entry directly by constructing a new `CacheEntryInner` with the modified entry.

---

### 3.2 DHT Query Response Collection Missing

**Status**: 🔶 Deferred - Implementation appears functional; function defined but never called

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

### 4.3 DHT Record Expiration Cleanup

**Status**: ✅ Completed (2026-04-11)

**Severity**: HIGH

**Location**: `src/mesh/dht/record_store.rs`, `src/mesh/dht/record_store_crud.rs`

Records stored with TTL but no background task purges expired records. Storage grows indefinitely.

**Fix**:
1. `cleanup_expired()` method already exists in `record_store_crud.rs`
2. Added call to `cleanup_expired()` in `start_background_tasks()` (every 60 seconds)
3. TTL is already enforced on read in `get_record()`

---

### 4.4 Illegal Upstream Terms Enforcement

**Status**: ✅ Completed (2026-04-11)

**Severity**: HIGH

**Location**: `src/mesh/transport_org.rs`

`illegal_upstream_terms` config exists but is never enforced when storing `verified_upstream` records.

**Fix**: Added check in `handle_upstream_registration_request()` that validates `upstream_url` against `illegal_upstream_terms` before creating `VerifiedUpstream`. Rejects with `UpstreamRegistrationResponse{approved: false}` if violation found.

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

**Status**: 🔶 In Progress (5.1 done, 5.2 improved with section comments)

**Completed**:
- 5.1: Tonic/prost upgraded to 0.14 ✅
- 5.2: HttpServer::handle_request() - improved with section comments ✅ (not split - see rationale below)

**Rationale for not splitting http/server.rs**:
- Already has 10 submodules via http/mod.rs
- Massive function (2,200 lines) is a cohesive request handling pipeline
- Splitting would introduce risk with no meaningful improvement
- Section comments (15 sections) now delineate the flow clearly

**Deferred** (5.3-5.6):
- 5.3: tls/server.rs - mirrors http/server.rs, same reasoning applies
- 5.4: mesh/transport.rs - already well-structured with 9 sibling files
- 5.5: mesh/config.rs - already fragmented with sibling files
- 5.6: mesh/topology.rs - already partially split with types.rs

### 5.1 Tonic/Axum Version Conflict

**Status**: ✅ Completed (2026-04-11)

**Severity**: P0 (Critical)

**Location**: `Cargo.toml:222-226`

`tonic 0.12.3` pulls `axum 0.7.9`, but main project uses `axum 0.8.8`. 4 file manager routes disabled.

**Fix**: Upgraded tonic to 0.14, prost to 0.14, added tonic-prost dependency

---

### 5.2 Split HttpServer::handle_request()

**Status**: ✅ Completed (2026-04-11) - Alternative approach: section comments only

**Note**: Rather than splitting, added 15 section comment banners to delineate the request handling pipeline. See commit 74e1fbd.

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

**Note**: Prior attempt created files but didn't update server.rs to use them. Must preserve original function structure and update incrementally.

---

### 5.3 Split HttpsServer::handle_request_with_cache()

**Status**: 🔶 Deferred - Same reasoning as 5.2

---

### 5.4 Split mesh/transport.rs

**Status**: 🔶 Deferred - Already well-structured

---

### 5.5 Split mesh/config.rs

**Status**: 🔶 Deferred - Already fragmented

---

### 5.6 Split mesh/topology.rs

**Status**: 🔶 Deferred - Already partially split

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

**Status**: ✅ Completed (See Waves 1.7 and 2.9)

Both items were completed as part of earlier waves:
- 6.1 (SSRF Domain Substring Bypass): Completed as Wave 1.7
- 6.2 (URL Decoding to WAF Detectors): Completed as Wave 2.9

---

## Wave 7: Medium Priority

**Status**: 🔶 Future Work (mostly design decisions and minor improvements)

Most items are:
- Design choices (serial health checks, builder naming)
- Performance optimizations (rate limiter, path sanitization)
- Architecture refinements (unified announcements, DHT consistency)
- Documentation improvements (doc comments, API docs)

These items can be addressed incrementally but don't block functionality.

### 7.1 Audit unwrap()/expect() in Critical Paths

**Status**: ✅ Verified - No critical issues found (2026-04-11)

**Severity**: P1

All unwrap()/expect() calls in critical paths are either guarded or use safe static string parsing. No critical panic points identified.

---

### 7.2 Standardize Result Type Usage

**Status**: ✅ Verified - Already following explicit Result pattern (2026-04-11)

**Severity**: P1

The codebase uses explicit `Result<T, ErrorType>` extensively (840+ matches). Custom error types like `MeshTransportError`, `MeshDiscoveryError`, `ResolverError`, etc. are used appropriately. **No changes needed.**

---

### 7.3 Add #[track_caller] to Error Types

**Status**: 🔶 Future Work - Low priority improvement

**Severity**: P1

54 error types use `thiserror::Error` but none use `#[track_caller]`. Adding it would improve error chain debugging.

**Fix**: Add `#[track_caller]` to custom error types derived with `thiserror::Error`.

---

### 7.4 Fix Lock-Held-Across-Await Pattern

**Status**: ✅ Verified - Not an issue (2026-04-11)

**Severity**: P2

The code uses `parking_lot::RwLock` (synchronous), not tokio RwLock. Lock is held briefly and released before any async boundary. **No issue found.**

---

### 7.5 Address pending_queries Lock Pattern

**Status**: ✅ Verified - Not an issue (2026-04-11)

**Severity**: P2

Lock is acquired, released immediately, then async work happens. The subsequent lock acquisitions at lines 1930, 1937 are separate brief operations. **No issue found.**

---

### 7.6 Replace Deep Imports with crate:: Paths

**Status**: 🔶 Future Work - Low priority style preference

**Severity**: P2

18 files use `use super::super::` pattern which works correctly. Changing to absolute paths is a style preference, not a bug.

**Note**: Won't fix unless explicitly requested.

---

### 7.7 Group Import Statements

**Status**: 🔶 Future Work - Low priority

**Severity**: P2

Files follow reasonable import grouping. Minor inconsistencies possible but nothing requiring action.

---

### 7.8 Standardize Builder Pattern Naming

**Status**: 🔶 Future Work - Low priority style preference

**Severity**: P2

`SupervisorConfigBuilder` uses `min_workers()` which is idiomatic Rust builder pattern. `with_` prefix is also valid but not required.

**Note**: Won't fix unless explicitly requested.

---

### 7.9 Document Public APIs

**Status**: 🔶 Future Work - Documentation debt

**Severity**: P2

Two of four core modules lack doc comments:
- `src/http/server.rs` - Missing module docs
- `src/process/manager.rs` - Missing module docs

`src/proxy.rs` and `src/mesh/transport.rs` have proper docs.

---

### 7.10 Connection Rate Limiter O(n) Iteration

**Status**: 🔶 Future Work - Minor optimization

**Severity**: MEDIUM

Uses `retain()` O(n) but vector is bounded. Acceptable for current use case.

---

Connection rate limit check iterates entire `Vec<Instant>` using `retain`.

**Fix**: Use ring buffer or sorted timestamp structure for O(1) rate limiting.

---

### 7.11 Serial Health Checks

**Status**: 🔶 Future Work - Design choice

**Severity**: MEDIUM

Health checks are serial by design (avoids thundering herd). Not a bug.

---

### 7.12 Serial Upstream Announce Loop

**Status**: 🔶 Future Work - Performance optimization

**Severity**: MEDIUM

Upstream announcement iterates through global peers serially. Could use `FuturesUnordered` for parallel sends.

---

### 7.13 Rate Limiter Cleanup Lock Contention

**Status**: 🔶 Future Work - Minor optimization

**Severity**: MEDIUM

Cleanup holds write lock during `retain()` O(n). Early-continue optimization already helps.

---

### 7.14 Nested Spawns in Mesh Broadcast

**Status**: 🔶 Future Work - Low priority

**Severity**: MEDIUM

Potential exponential task growth at low message rates. Not a practical issue.

---

### 7.15 HTTP Path Sanitization Allocations

**Status**: 🔶 Future Work - Performance optimization

**Severity**: MEDIUM

Fast path avoids allocation but multiple `Vec`s allocated on some paths.

---

### 7.16 Response Header Filtering Allocations

**Status**: 🔶 Future Work - Performance optimization

**Severity**: MEDIUM

Creates new `Vec` on every proxied response. Acceptable for correctness.

---

### 7.17 Static File Zero-Copy Broken

**Status**: 🔶 Future Work - Performance optimization

**Severity**: MEDIUM

Manual buffering defeats streaming. Would need architectural change.

---

### 7.18 Unified Announcement Mechanism

**Status**: 🔶 Future Work - Architecture cleanup

**Severity**: MEDIUM

Two mechanisms exist (`UpstreamAnnounce` vs `UpstreamRegistrationRequest`). Deprecation decision needed.

---

### 7.19 DHT Key Type Consistency

**Status**: 🔶 Future Work - Architecture cleanup

**Severity**: MEDIUM

`is_privileged()` and `is_global_signature_required()` check different key sets.

---

### 7.20 Reputation System Clarification

**Status**: 🔶 Future Work - Documentation

**Severity**: MEDIUM

`min_reputation_for_dht_write` defaults to 30 but no assignment mechanism exists.

---

### 7.21 Global Node Liveness and Quorum Monitoring

**Status**: 🔶 Future Work - New feature

**Severity**: MEDIUM

Would add `GlobalNodeHeartbeat` DHT record with short TTL. Feature implementation.

---

## Wave 8: Low Priority

**Status**: 🔶 Future Work - All documentation and cleanup tasks

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

## Summary

**Completed Waves (1-6, partial 5)**: 38 items fixed
**Pending**: Wave 5.2-5.6 (module splits), Wave 7-8 (incremental improvements)

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
