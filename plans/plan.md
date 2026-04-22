# MaluWAF Implementation Consolidated Plan

**Last updated**: 2026-04-22
**Status**: 📋 PLANNING (consolidated from 17 individual plans)

## Overview

This document consolidates all implementation items from individual plan files into a single wave-based plan. Each wave represents a set of items that can be implemented in parallel using sub-agents.

**Total implementable items**: ~60+
**Completion target**: 95%+

---

## Wave A: Critical Bug Fixes (Compile Blocker)

Items that must be fixed first before any other work can proceed.

### A.1: Fix FastCGI Syntax Error
**Status**: ✅ COMPLETE

**Problem**: `src/fastcgi/mod.rs:333` has mismatched closing brace causing compile failure.

**Fix**: Removed duplicate/orphaned code in `impl FastCgiResponse` block (lines 319-333). The first `into_http_response` implementation (lines 299-316) was correct; the duplicate code was removed. Also fixed `self.body` move issue by cloning in the unwrap_else fallback.

**Additional fixes made during compilation**:
- `src/mesh/transport_types.rs:65` - Added missing `Arc` import
- `src/proxy_cache/store.rs:420` - Fixed typo `inflflight_requests` → `inflight_requests`
- `src/mesh/threat_intel.rs:1314-1317` - Fixed type mismatch (get_topology returns Arc, not Option)
- `src/http/server.rs:2758,2831` - Fixed clippy `manual_ignore_case_cmp` warning
- `src/proxy_cache/store.rs:152` - Added type alias for complex type

**Verification**:
```bash
cargo check  # Passes
cargo clippy --lib -- -D warnings  # Passes
cargo test --test integration_test  # 242 passed
```

---

## Wave B: Security Critical

High-priority security fixes from plan16 (Security Audit Remediation).

### B.1: DHT Record Signature Requirement
**Status**: ✅ COMPLETE

**Problem**: Global nodes can store records with empty signatures, enabling malicious data injection.

**Locations fixed**:
- `src/mesh/dht/mod.rs` - Added `SignatureRequired` error variant
- `src/mesh/dht/record_store_crud.rs:165` - Now rejects non-local records with empty signatures
- `src/mesh/dht/record_store_sync.rs:313` - Added early rejection in `handle_record_announce()`

**Verification**: `cargo clippy --lib -- -D warnings` passes

### B.2: Health Check Timestamp Validation
**Status**: ✅ COMPLETE

**Problem**: Health check responses echo timestamp back without validation, enabling replay attacks.

**Location**: `src/worker/common.rs:185-206`

**Fix**: Added timestamp validation (MAX_AGE_SECS=30, MAX_FUTURE_SECS=5). Invalid timestamps are rejected.

**Verification**: `cargo clippy --lib -- -D warnings` passes

### B.3: ACME Challenge HMAC Verification
**Status**: ✅ COMPLETE

**Problem**: `UpstreamOwnershipChallenge` messages have no HMAC/signature verification.

**Location**: `src/mesh/transport_peer.rs:1908-2055`

**Fix**: Added `verify_challenge_signature()` function and call it at start of `handle_upstream_ownership_challenge()`. Verifies Ed25519 signature over `request_id:global_node_id:timestamp`.

**Verification**: `cargo check` passes

### B.4: Edge Node PoW Bypass Fix
**Status**: ✅ COMPLETE

**Problem**: Edge nodes can bypass signature using trivial PoW (40 bits).

**Locations fixed**:
- `src/mesh/dht/routing/node_id.rs:10` - Increased PoW difficulty from 40 to 64 bits
- `src/mesh/peer_auth.rs:129-131` - Now requires BOTH PoW AND signature

**Verification**: `cargo clippy --lib -- -D warnings` passes

### B.5: PID Mismatch Rejection
**Status**: ✅ COMPLETE

**Problem**: False PID claims generate only warning, not rejection.

**Location**: `src/master/ipc.rs:357-376`

**Fix**: Changed warn to error, added WorkerError send with Critical severity, returns on mismatch.

**Verification**: `cargo clippy --lib -- -D warnings` passes

### B.6: DHT Announce Record Limit
**Status**: ✅ COMPLETE

**Problem**: No limit on records per `DhtRecordAnnounce` message enables DoS.

**Location**: `src/mesh/dht/record_store_message.rs:77-94`

**Fix**: Added `MAX_RECORDS_PER_ANNOUNCE = 100` constant and enforces limit.

**Verification**: `cargo clippy --lib -- -D warnings` passes

### B.7: DHT get_by_prefix Pagination
**Status**: ✅ COMPLETE

**Problem**: `get_by_prefix()` has no result limits.

**Locations fixed**:
- `src/mesh/dht/record_store.rs` - Added `DEFAULT_GET_BY_PREFIX_LIMIT = 100`
- `src/mesh/dht/record_store_crud.rs` - Updated to pass limit parameter
- `src/mesh/threat_intel.rs`, `src/mesh/transport.rs`, `src/mesh/yara_rules.rs`, `src/mesh/topology.rs` - Updated callers

**Verification**: `cargo check` passes

---

## Wave C: Performance Hot Paths

High-impact performance fixes for 500K rps target from plan14 and plan19.

### C.1: WAF Detection — Excessive String Allocations
**Status**: 📋 Planned

**Problem**: 11 attack detectors × 10 headers × 2 clones = 220 allocations/request.

**Locations**:
- `src/waf/attack_detection/mod.rs:285-900`
- `src/waf/attack_detection/normalizer.rs:433-460` — Double lowercasing in SSRF

**Proposed fix**:
1. Change `InputLocation::Header` to hold `&str` reference instead of `Cow`
2. Pre-lowercase header names once in `NormalizedInputs`
3. Remove redundant lowercasing in SSRF detector

### C.2: Response Header Filtering — Vec Allocation
**Status**: 📋 Planned

**Problem**: `filter_response_headers()` allocates Vec on every proxied response.

**Locations**: `src/proxy/mod.rs:1001-1005`, `src/http/server.rs:2541-2542`

**Note**: A `filter_response_headers_buf` variant already exists at `src/proxy/headers.rs:268-283` but is NOT being used.

**Proposed fix**: Use `filter_response_headers_buf` in request path instead.

### C.3: Rate Limiter — Mutex Contention
**Status**: 📋 Planned

**Problem**: `SlottedIpRateLimiter::check_and_increment()` acquires mutex on every request.

**Location**: `src/waf/ratelimit/core.rs:434`

**Proposed fix**: Replace `Mutex<HashSet<usize>>` with atomic bitset (`Vec<AtomicU32>`).

### C.4: DNS Zone Store — O(n) Suffix Query
**Status**: 📋 Planned

**Problem**: `ctx.zones.find()` iterates all 64 shards doing suffix matching with per-zone allocations.

**Location**: `src/dns/server/query.rs:897-900`

**Proposed fix**: Add domain suffix index for O(1) lookups.

### C.5: Mesh DHT — JSON Serialization
**Status**: 📋 Planned

**Problem**: DHT uses `serde_json` for storage, causing CPU bottleneck.

**Locations**: Multiple files in `src/mesh/`

**Proposed fix**: Replace with postcard (binary format) or rkyv for zero-copy.

### C.6: Fix Compile Error Typo (plan19)
**Status**: 📋 Planned

**Problem**: Typo in proxy_cache store.

**Location**: `src/proxy_cache/store.rs:420`
```
inflflight_requests  // Should be: inflight_requests
```

### C.7: Connection Token Leak (plan19)
**Status**: 📋 Planned

**Problem**: Connection token can leak if request errors before completion.

**Location**: `src/http/server.rs:1290-1317`

**Proposed fix**: Use RAII pattern with `Drop` implementation.

### C.8: Async Disk Write Race (plan19)
**Status**: 📋 Planned

**Problem**: Disk write spawned but never awaited, can leave orphaned files.

**Location**: `src/proxy_cache/store.rs:473-480`

---

## Wave D: Mesh & DHT Improvements

From plan2 (Mesh & DHT Security) and plan7 (YARA & ThreatIntel).

### D.1: DHT Capability-Based Write Authorization
**Status**: 📋 Planned

**Problem**: DHT allows nodes to store records for capabilities they don't possess.

**Proposed changes**:
1. Add `capability_attestation` verification to `DhtAccessControl`
2. Create `src/mesh/dht/capability_access.rs` module

### D.2: Edge Node Approval Workflow
**Status**: 📋 Planned

**Problem**: Edge nodes self-authenticate without authorization from global node.

**Proposed changes**:
1. Add `EdgeAttestation` structure
2. Modify `validate_edge_node()` in `peer_auth.rs`
3. Add DHT key `edge_attestation:{node_id}`

### D.3: VerifiedUpstream Signature Verification
**Status**: 📋 Planned

**Problem**: Origin signature not verified during storage.

**Proposed change**: Verify `origin_signature` in `handle_upstream_announce()`.

### D.4: ThreatIntel Re-Announce Global Restriction
**Status**: 📋 Planned

**Problem**: ThreatIntel re-announce NOT restricted to global nodes (unlike YARA).

**Location**: `src/mesh/threat_intel.rs:1764-1787`

**Current behavior**: Only checks `hub_only_mode`, not `is_global()`. ALL nodes re-announce.

**Proposed fix**:
```rust
if !self.node_role.is_global() {
    return;  // Only global nodes re-announce
}
```

### D.5: ThreatIntel hub_only_mode Sync Check
**Status**: 📋 Planned

**Problem**: Non-hub nodes sync from DHT when `hub_only_mode = true`.

**Location**: `src/mesh/threat_intel.rs:1725-1736`

**Proposed fix**: Add `hub_only_mode` check in sync block.

### D.6: YARA Chunk Keys Type Safety
**Status**: 📋 Planned

**Problem**: YARA chunk keys constructed manually, bypass DhtKey type safety.

**Location**: `src/mesh/yara_rules.rs:533`

**Proposed fix**: Add `YaraChunk { content_hash, index }` variant to `DhtKey` enum.

### D.7: Request Coalescing for Upstream Lookups
**Status**: 📋 Planned

**Problem**: Concurrent requests independently fan out to DHT.

**Proposed change**: Add request coalescing in `MeshTopology`.

### D.8: DHT Write Rate Limiting
**Status**: 📋 Planned

**Problem**: `DhtRateLimiter` only limits reads.

**Proposed change**: Extend to include writes.

### D.9: True Circuit Breaker
**Status**: 📋 Planned

**Problem**: `FAILED_PROVIDER_COOLDOWN_SECS` is not a true circuit breaker.

**Proposed change**: Add circuit state to `ProviderStats` with open/half-open.

### D.10: Reduce VerifiedUpstream Cache TTL
**Status**: 📋 Planned

**Problem**: 5 minute TTL on verified upstream cache causes stale data.

**Proposed change**: Change from 300s to 60s in `topology.rs`.

---

## Wave E: Stub & Incomplete Items

From plan9 (Stub & Incomplete Code).

### E.1: Rule Feed Placeholder Validation
**Status**: 📋 Planned

**Problem**: `EMBEDDED_PUBLIC_KEY = PLACEHOLDER` with no startup validation.

**Location**: `src/waf/rule_feed.rs:27,29`

**Proposed fix**: Add startup warning if placeholder is detected.

### E.2: CLI Auth Token Placeholder Validation
**Status**: 📋 Planned

**Problem**: Default config has `TOKEN_PLACEHOLDER` with no warning.

**Location**: `src/master/commands.rs:254`

**Proposed fix**: Add startup warning.

### E.3: Implement `resolve_txt_record()`
**Status**: 📋 Planned

**Problem**: Stub always returns empty Vec.

**Location**: `src/mesh/transport_dns.rs:1183-1185`

**Proposed fix**: Implement using `dns_resolver`.

### E.4: Implement `is_global_node_id()` (ThreatIntel)
**Status**: 📋 Planned

**Problem**: `is_global_node_ip_string()` stub always returns false.

**Location**: `src/mesh/threat_intel.rs:358-360`

**Proposed fix**: Replace with source verification.

---

## Wave F: OpenAPI & Admin Panel

From plan10 (OpenAPI) and plan11 (Admin Panel Usability).

### F.1: Add Swagger UI
**Status**: 📋 Planned

**Problem**: No interactive API documentation.

**Proposed fix**: Add `utoipa-swaggerui` endpoint at `/api/docs`.

### F.2: Add `--export-api-spec` CLI Flag
**Status**: 📋 Planned

**Problem**: `--export-openapi` exports config JSON, not API spec.

**Proposed fix**: Add `--export-api-spec` flag.

### F.3: Document Security Scheme in OpenAPI
**Status**: 📋 Planned

**Problem**: Bearer auth not documented in spec.

### F.4: Bulk Configuration Endpoint
**Status**: 📋 Planned

**Problem**: 30+ separate config endpoints.

**Proposed fix**: Add `GET/PUT /api/config/bundle`.

### F.5: Per-Site Bot Detection Config
**Status**: 📋 Planned

**Problem**: Bot detection only at global defaults level.

**Proposed fix**: Include in site configuration.

### F.6: DNS Configuration UI
**Status**: 📋 Planned

**Problem**: No dedicated DNS management section.

**Proposed fix**: Add DNS management endpoints (feature-gated).

---

## Wave G: Documentation & Configuration

From plan17 (Documentation) and plan4/plan5/plan6.

### G.1: Fix dns-dnssec-architecture.md
**Status**: 📋 Planned

**Problem**: States "inline validation planned" but IS implemented.

**Proposed fix**: Update with accurate recursive resolver DNSSEC support.

### G.2: Fix README.md Worker Architecture
**Status**: 📋 Planned

**Problem**: Mentions "minifier worker" but minifier is a module.

**Proposed fix**: Update to describe unified worker with Tokio.

### G.3: Directory Listing SVG Icons
**Status**: 📋 Planned

**Problem**: Uses hardcoded emoji that don't adapt to theme.

**Proposed fix**: Add SVG icon methods to `ThemeRenderer`.

### G.4: Serverless-as-Origin Architecture
**Status**: 📋 Planned

**Problem**: Serverless functions not wired for mesh origin mode.

**Proposed fix**: Implement serverless proxy stream handler.

### G.5: Edge Caching Image Poison
**Status**: 📋 Planned

**Issues**:
1. ProxyCache not created when DHT preferences arrive
2. Transform cache key missing poison parameters
3. Double poisoning (origin + edge)

---

## Wave H: Dependency & Code Quality

From plan12 (Dependency Security) and plan13/plan15.

### H.1: Update rustls-webpki
**Status**: 📋 Planned

**Problem**: RUSTSEC-2026-0104 vulnerability (panic in CRL parsing).

**Proposed fix**: Update from 0.103.12 to 0.103.13.

### H.2: Dead Code Suppression Audit
**Status**: 📋 Planned

**Problem**: ~100 `#[allow(dead_code)]` annotations need documentation.

**Proposed fix**: Add `SAFETY_REASON` comments to all kept suppressions.

### H.3: Admin UI Formatting
**Status**: 📋 Planned

**Problem**: 3 Admin UI files have formatting issues.

**Proposed fix**: Run `cargo fmt` on admin-ui.

### H.4: Typed Errors in YARA Rules
**Status**: 📋 Planned

**Problem**: Uses `Result<T, String>` instead of typed errors.

**Proposed fix**: Create `YaraRulesError` enum with thiserror.

---

## Wave I: WAF & Detection Improvements

### I.1: ConnectionLimiter Sharding
**Status**: 📋 Planned

**Problem**: Single lock for all IP counters at 500K rps.

**Proposed fix**: Use 64-sharded locks per `src/dns/server/sharded_store.rs` pattern.

### I.2: Body Vec Reallocation Fix
**Status**: 📋 Planned

**Problem**: For large uploads, Vec reallocates multiple times.

**Location**: `src/http/shared_handler.rs:339-386`

**Proposed fix**: Use `BytesMut` with extend() or pre-allocate.

### I.3: Streaming Body Size Limits
**Status**: 📋 Planned

**Problem**: No max body size for chunked encoding (slowloris risk).

**Location**: `src/http/server.rs:925-963`

**Proposed fix**: Add configurable max body size with streaming enforcement.

### I.4: WebSocket Upstream WAF Inspection
**Status**: 📋 Planned

**Problem**: Upstream WebSocket responses not WAF-checked.

**Location**: `src/http/server.rs:3226-3280`

### I.5: Retry Off-By-One Fix
**Status**: 📋 Planned

**Problem**: Retry boundary uses `<=` but attempt incremented before check.

**Location**: `src/proxy/mod.rs:855-872`

---

## Wave J: Remaining Issues

### J.1: Trust Anchor Non-Atomic Save
**Status**: 📋 Planned

**Problem**: Full DELETE before INSERT - crash would lose anchors.

**Location**: `src/dns/trust_anchor.rs:296-338`

### J.2: Missing->Pending State Guard
**Status**: 📋 Planned

**Problem**: Key can transition Missing->Pending without verifying was Valid.

### J.3: TOFU Fingerprint MITM
**Status**: ⚠️ PARTIALLY COMPLETE

**Current**: `require_explicit_fingerprint` config exists.

**Needed**: Enable by default (requires config change).

### J.4: Admin Token Redaction
**Status**: 📋 Planned

**Problem**: `get_main_config` returns full config including token.

**Location**: `src/admin/handlers/config.rs:33-35`

### J.5: YARA Rule Count Warning vs Rejection
**Status**: 📋 Planned

**Problem**: >100 rules only logs warning, not rejected.

**Location**: `src/mesh/yara_rules.rs:1149`

### J.6: Static Worker IPC Signing
**Status**: 📋 Planned

**Problem**: Static workers use unsigned IPC.

### J.7: IPC Temp File TOCTOU
**Status**: 📋 Planned

**Problem**: Race between IPC key read and file deletion.

---

## Deferred Items (Require Architectural Work)

These items require significant architectural changes and are deferred:

### D.3: Wire FileManager HTTP Router
(From original plan.md)

**Reason**: `create_file_manager_router()` exists in `src/http/file_manager.rs` but requires:
- Adding FileManager to AdminState
- Wiring through admin server initialization
- Integrating with auth and middleware

### F.3: Modify handle_http_proxy_stream for Serverless
(From original plan.md)

**Reason**: Serverless route info exists in topology but requires:
- Integrating serverless route lookup into mesh proxy path
- Adding serverless invocation before TCP proxy fallback
- Coordinating with serverless manager

### I.2: Implement Threat Intel Local Application
(From original plan.md)

**Completed**: `IpThrottle` fully integrated with block store

**Deferred**:
- `DomainBlock` — Requires DNS server integration
- `UrlBlock` — Requires HTTP proxy integration
- `CertBlock` — Requires certificate validation integration

---

## Implementation Notes

### Verified Completed Items (from original plan.md)

All other items from the original consolidated plan (64 total) have been successfully implemented:

- **Wave A**: Critical Security Fixes ✅ (6/6)
- **Wave B**: Performance Hot Paths ✅ (6/6)
- **Wave C**: Web App Stack Improvements ✅ (5/5)
- **Wave D**: YARA & ThreatIntel Distribution ✅ (4/6, 2 deferred)
- **Wave E**: Mesh & DHT Architecture ✅ (5/5)
- **Wave F**: Serverless Architecture ✅ (5/6, 1 deferred)
- **Wave G**: Edge Caching & Image Poison ✅ (6/6)
- **Wave H**: Admin Panel Improvements ✅ (6/6)
- **Wave I**: Stub/Incomplete Items ✅ (1/3, 2 deferred)
- **Wave J**: Dependency & Security Updates ✅ (3/3)
- **Wave K**: Documentation ✅ (4/4)
- **Wave L**: Testing Improvements ✅ (4/4)

---

## Wave Parallelization Guidelines

Each wave can be approached with parallel sub-agents:

| Wave | Items | Can Parallelize |
|------|-------|-----------------|
| A | 1 | No (compile blocker) |
| B | 7 | Yes (independent security fixes) |
| C | 8 | Yes (performance independent) |
| D | 10 | Yes (mesh/DHT independent) |
| E | 4 | Yes (stub fixes independent) |
| F | 6 | Yes (admin/API independent) |
| G | 5 | Yes (docs/config independent) |
| H | 4 | Yes (deps/quality independent) |
| I | 5 | Yes (WAF independent) |
| J | 7 | Some dependencies |

---

## Reference Commands

```bash
# Verify compilation
cargo check  # Must pass before any other work

# Run integration tests
cargo test --test integration_test

# Run clippy
cargo clippy --lib -- -D warnings

# Format check
cargo fmt --check

# Run DHT integration tests
cargo test --test dht_integration_test
```

---

## Accuracy Notes

This consolidated plan was created by:
1. Reading all 17 individual plan files
2. Verifying issues against current codebase with `cargo check`, `grep` searches
3. Confirming which items are still outstanding vs already implemented

**Verified blocker**: `src/fastcgi/mod.rs:333` syntax error prevents compilation — MUST be fixed first.