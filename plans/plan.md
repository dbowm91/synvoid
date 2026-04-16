# MaluWAF Implementation Plan

**Last updated**: 2026-04-16
**Consolidated from**: plan.md, plan2-plan16.md

---

## Overview

This document contains all remaining implementation items across the MaluWAF project. Items are organized by category and priority, with parallelization waves defined to speed up implementation.

**Status Legend**:
- ✅ COMPLETED - Item fully implemented
- ⏸️ DEFERRED - Item requires further investigation or is blocked
- ❌ NOT RECOMMENDED - Investigation shows risk outweighs benefit
- 📋 TODO - Ready for implementation
- 🔍 INVESTIGATING - Work in progress

---

## Quick Reference Summary

### Remaining Actionable Items (by Category)

| Category | Items | Highest Priority |
|----------|-------|------------------|
| Dependency | D1 | D1 (wasmtime 42.0.2) |
| Mesh/DHT | M-D5 | M-D5 (quorum tasks) |
| Code Quality | O1, O2, O3 | O2 (proxy.rs size) |
| Testing | G1-G8, T1, T4, T5 | G1 (process tree) |
| OpenAPI | Phase 2-5 (in progress) | Handler annotations |
| Admin Panel | Items 1-15 | Admin 2 (Mesh Config) |
| Web App Stack | Phase 3-5 (deferred) | Phase 3 |

### All Completed Categories
- Security: S-1 through S-10 all fixed
- Performance: P1.1, P1.2, P1.3, P2.1, P2.2, P2.3, P2.4, P3 all fixed
- WASM: W1-W10 all fixed
- Honeypot/Threat: H1-H4 all fixed
- Edge Transform: E1-E6 all verified/completed
- Reverse Proxy/WAF: All items fixed

### Already Fixed (from plan files)

| Item | Status | Evidence |
|------|--------|----------|
| S-1 (ML-KEM key mismatch) | ✅ FIXED | pqc/src/keys.rs: Added public_key() method; config_identity.rs derives from loaded key |
| S-2 (ACME key permissions) | ✅ FIXED | AGENTS.md: "Private key permissions too open" |
| S-3 (Threat intel unsigned records) | ✅ FIXED | threat_intel.rs: sync_from_dht() skips unsigned records |
| S-4 (Threat intel no signature) | ✅ FIXED | threat_intel.rs: publish_indicator_to_dht() refuses if no signer |
| S-11 (PID claiming) | ✅ FIXED | AGENTS.md: "Connection tracker non-atomic" |
| S-13 (PoW difficulty) | ✅ FIXED | AGENTS.md: "PoW difficulty increased" |
| S-18 (Nonce cache) | ✅ FIXED | AGENTS.md: "NONCE_CACHE O(n) eviction" |
| P3 (IPC nonce cache) | ✅ FIXED | AGENTS.md: "Nonce cache unbounded" |
| H1 (TLS honeypot) | ✅ FIXED | AGENTS.md: "HTTP honeypot bypass" |
| H2 (Port honeypot re-announce) | ✅ FIXED | AGENTS.md: "Port honeypot patterns not published" |
| H3 (Standalone mesh publishing) | ✅ FIXED | AGENTS.md: "Standalone threat sync missing" |
| H4 (Signature format) | ✅ FIXED | AGENTS.md: "Threat intel signature bypass" |
| M-D1 (Edge PoW unbinding) | ✅ FIXED | AGENTS.md: "Edge PoW key unbinding" |
| M-D1 (Edge PoW revokal bypass) | ✅ FIXED | peer_auth.rs: Revocation check moved before PoW handling |
| M-D2 (DnsRecord not privileged) | ✅ FIXED | keys.rs: DnsRecord added to is_privileged() |
| M-D8 (PoW difficulty) | ✅ FIXED | AGENTS.md: "PoW difficulty increased" |
| T1 (Stack overflow test) | ✅ FIXED | connection_limiter.rs: Uses heap allocation instead of stack |
| T2 (Off-by-one backoff test) | ✅ FIXED | overseer/process.rs: count < 6 instead of <= 6 |
| D1 (wasmtime update) | ✅ FIXED | Cargo.toml: wasmtime = "42.0.2" |
| E2 (Mesh QUIC no transforms) | ✅ FIXED | transport_peer.rs: Added apply_response_transforms() |
| C3 (IPC panic!) | ❌ NOT REAL | plan11: "All 9 panic! calls are in #[cfg(test)] modules" |
| S-21 (TLS warning) | ❌ NOT REAL | Already exists in cert_resolver.rs |
| S-22 (SSRF bypass) | ❌ NOT REAL | Logic is correct |
| S-23 (Rate limiter race) | ❌ NOT REAL | Write lock held during check+insert |
| S-24 (Socket /tmp) | ❌ NOT REAL | create_secure_dir_atomic fixes permissions |
| S-25 (SmallRng session) | ❌ NOT REAL | Ephemeral session keys, not master |

---

## Implementation Waves

### Wave 1: Critical Security & Test Fixes
*Can be implemented in parallel by multiple agents*

| Item | Priority | Category | Description | Files | Status |
|------|----------|----------|-------------|-------|--------|
| **S-1** | CRITICAL | Security | ML-KEM key pair mismatch (configured private key discarded) | `src/mesh/config_identity.rs` | ✅ COMPLETED |
| **S-3** | CRITICAL | Security | Threat intel DHT sync accepts unsigned records | `src/mesh/threat_intel.rs` | ✅ COMPLETED |
| **S-4** | CRITICAL | Security | Threat intel publishes without signature when no signer | `src/mesh/threat_intel.rs` | ✅ COMPLETED |
| **D1** | CRITICAL | Dependency | Update wasmtime to 42.0.2+ (RUSTSEC-2026-0095) | `Cargo.toml` | ✅ COMPLETED |
| **E2** | CRITICAL | Edge Transform | Mesh QUIC proxy applies NO transforms (raw TCP relay) | `src/mesh/transport_peer.rs` | ✅ COMPLETED |
| **T1** | CRITICAL | Testing | Stack overflow in `test_connection_rate_limiting` | `src/waf/flood/connection_limiter.rs` | ✅ COMPLETED |
| **T2** | CRITICAL | Testing | Off-by-one in `test_restart_delay_exponential_backoff` | `src/overseer/process.rs` | ✅ COMPLETED |
| **M-D1** | P1 | Mesh/DHT | Edge node PoW authentication bypasses revocation check | `src/mesh/peer_auth.rs` | ✅ COMPLETED |
| **M-D2** | P1 | Mesh/DHT | DnsRecord not privileged while DnsZone is | `src/mesh/dht/keys.rs` | ✅ COMPLETED |

### Wave 2: High Priority Security & Performance
*Can be implemented in parallel by multiple agents*

| Item | Priority | Category | Description | Files | Status |
|------|----------|----------|-------------|-------|--------|
| **S-5** | HIGH | Security | VerifiedUpstream records not signature-verified on lookup | `src/mesh/topology.rs` | ✅ COMPLETED |
| **S-6** | HIGH | Security | RFC 5011 state machine Missing->Valid bypass | `src/dns/trust_anchor.rs` | ✅ COMPLETED |
| **S-7** | HIGH | Security | Non-CSPRNG RNG for signing key generation | `src/mesh/config_identity.rs` | ✅ COMPLETED |
| **S-8** | HIGH | Security | Dynamic update prerequisite only checks existence | `src/dns/update.rs` | ✅ COMPLETED |
| **S-9** | HIGH | Security | RouteResponse signature never verified | `src/mesh/discovery.rs` | ✅ COMPLETED |
| **S-10** | HIGH | Security | DHT record store lacks cryptographic chain | `src/mesh/dht/record_store_crud.rs` | ✅ COMPLETED |
| **P1.1** | HIGH | Performance | Replace HashMap with AHashMap in hot paths | Multiple files | ✅ COMPLETED |
| **P1.2** | HIGH | Performance | Reduce to_string() allocations in HTTP handler | `src/http/server.rs` | ✅ COMPLETED |
| **P1.3** | HIGH | Performance | Fix ip_to_slot power-of-2 modulo | `src/utils.rs` | ✅ COMPLETED |
| **WAF P1.2** | HIGH | WAF | WAF detector header iteration redundancy | `src/waf/attack_detection/mod.rs` | ✅ COMPLETED |
| **W1** | HIGH | WASM | InstancePool uses wrong path (routing prefix as file path) | `src/serverless/instance_pool.rs` | ✅ COMPLETED |
| **W2** | HIGH | WASM | InstancePool spawns new WasmPluginManager per instance | `src/serverless/instance_pool.rs` | ✅ COMPLETED |
| **T1 (ACME)** | HIGH | Testing | ACME workflow tests missing | `tests/integration_test.rs` | ✅ COMPLETED |
| **T1 (ThreatIntel)** | HIGH | Testing | ThreatIntel publication/sync tests missing | `tests/dht_integration_test.rs` | 🔍 REVERTED - API mismatch |
| **T3** | HIGH | Testing | PeerAuth validation tests missing | `src/mesh/peer_auth.rs` | ✅ COMPLETED |

### Wave 3: Medium Priority Improvements
*Can be implemented in parallel by multiple agents*

| Item | Priority | Category | Description | Files | Status |
|------|----------|----------|-------------|-------|--------|
| **P2.1** | MEDIUM | Performance | Shard BlockStore (lock contention) | `src/block_store.rs` | ✅ COMPLETED |
| **P2.2** | MEDIUM | Performance | Reduce to_lowercase() allocations | Multiple files | ✅ COMPLETED |
| **P2.3** | MEDIUM | Performance | Provider stats cache mutation pattern | `src/mesh/proxy.rs` | ✅ COMPLETED |
| **P2.4** | MEDIUM | Performance | Global connection limiter contention | `src/waf/traffic_shaper/limiter.rs` | ✅ COMPLETED |
| **P3** | MEDIUM | Performance | filter_response_headers() allocation overhead | `src/proxy.rs` | ✅ COMPLETED |
| **M-D3** | P2 | Mesh/DHT | CapabilityAttestation write not restricted | `src/mesh/dht/mod.rs` | ✅ COMPLETED |
| **M-D4** | P2 | Mesh/DHT | DHT announce wrapper signature missing | `src/mesh/dht/record_store_sync.rs` | ✅ COMPLETED |
| **M-D5** | P2 | Mesh/DHT | Quorum async tasks accumulate on timeout | `src/mesh/dht/record_store_crud.rs` | ⏸️ DEFERRED |
| **M-D6** | P2 | Mesh/DHT | edge_can_respond_privileged config erosion risk | `src/mesh/dht/routing/manager.rs` | ✅ COMPLETED |
| **W3** | MEDIUM | WASM | Instance pool doesn't reuse WasmRuntime | `src/serverless/instance_pool.rs` | ✅ COMPLETED |
| **W4** | MEDIUM | WASM | No admin API for serverless | `src/admin/handlers/` | ✅ COMPLETED |
| **W5** | MEDIUM | WASM | No health checks for serverless instances | `src/serverless/instance_pool.rs` | ✅ COMPLETED |
| **W6** | MEDIUM | WASM | Instance pool limits not enforced | `src/serverless/instance_pool.rs` | ✅ COMPLETED |
| **H1** | MEDIUM | Honeypot | TLS honeypot uses wrong blocking function | `src/tls/server.rs` | ✅ COMPLETED |
| **H4** | MEDIUM | Honeypot | Signature format mismatch in Threat Intel | `src/mesh/threat_intel.rs` | ✅ COMPLETED |
| **T1** | MEDIUM | Testing | WAF detection integration tests missing | `tests/integration_test.rs` | 📋 TODO |
| **T5** | MEDIUM | Testing | Benchmarks missing | `benches/` | ⏸️ DEFERRED |
| **T2** | MEDIUM | Testing | Restart delay exponential backoff test | `src/overseer/process.rs` | ✅ COMPLETED |
| **E1** | MEDIUM | Edge Transform | DHT key mismatch in MeshProxy (dormant) | `src/mesh/proxy.rs` | ✅ COMPLETED |
| **E3** | MEDIUM | Edge Transform | All transforms silently skipped in MeshProxy | `src/mesh/proxy.rs` | ✅ COMPLETED |
| **E4** | MEDIUM | Edge Transform | Poisoned image cache key mismatch | `src/mesh/proxy.rs` | ✅ COMPLETED |
| **E5** | MEDIUM | Edge Transform | Duplicate transform config publishing code | `src/mesh/transports/manager.rs` | ✅ COMPLETED |
| **E6** | MEDIUM | Edge Transform | Dead code - MeshBackend/MeshProxy subsystem | `src/mesh/backend.rs` | ✅ COMPLETED |
| **C1** | CRITICAL | Code Quality | Blocking std::thread::sleep in async contexts | `src/worker/mod.rs` | ✅ COMPLETED |
| **C2** | CRITICAL | Code Quality | Circular dependency: proxy.rs ↔ waf/mod.rs | `src/proxy.rs`, `src/waf/mod.rs` | ✅ COMPLETED |
| **O1** | HIGH | Code Quality | lib.rs exposes 55+ modules publicly | `src/lib.rs` | ⏸️ DEFERRED |

### Wave 4: Lower Priority & Feature Work
*Can be implemented in parallel by multiple agents*

| Item | Priority | Category | Description | Files | Status |
|------|----------|----------|-------------|-------|--------|
| **M-D7** | P3 | Mesh/DHT | No DHT announce rate limiting | `src/mesh/dht/record_store_message.rs` | ✅ COMPLETED |
| **M-D9** | P2 | Mesh/DHT | Bootstrap only fails-fast on seed connection | `src/mesh/discovery.rs` | ✅ COMPLETED |
| **M-D10** | P3 | Mesh/DHT | Routing table sparse bucket refresh may miss peers | `src/mesh/dht/routing/manager.rs` | ✅ COMPLETED |
| **W7** | LOW | WASM | No serverless instance pool metrics | `src/serverless/instance_pool.rs` | ✅ COMPLETED |
| **W8** | LOW | WASM | Missing serverless invocation metrics | `src/serverless/manager.rs` | ✅ COMPLETED |
| **W9** | LOW | WASM | No graceful shutdown for serverless pools | `src/serverless/instance_pool.rs` | ✅ COMPLETED |
| **W10** | MEDIUM | WASM | PluginManager and ServerlessManager use separate WASM runtimes | `src/plugin/mod.rs` | ✅ COMPLETED |
| **H2** | MEDIUM | Honeypot | Port honeypot re-announce only runs for global nodes | `src/mesh/threat_intel.rs` | ✅ COMPLETED |
| **H3** | LOW | Honeypot | Standalone mode calls unnecessary mesh publishing | `src/worker/unified_server.rs` | ✅ COMPLETED |
| **T2** | HIGH | Testing | ThreatIntel publication/sync tests | `tests/dht_integration_test.rs` | ⏸️ DEFERRED |
| **T4** | MEDIUM | Testing | WAF detection integration tests | `tests/integration_test.rs` | ⏸️ DEFERRED |
| **P3.1** | MEDIUM | Testing | ProxyCache clone rebuilds host index | `src/proxy_cache/store.rs` | ✅ COMPLETED |
| **G1** | HIGH | Testing | Full process tree not tested | `tests/process_spawn_test.rs` | ⏸️ DEFERRED |
| **G2** | HIGH | Testing | Socket handoff not tested | `tests/e2e_process_test.rs` | ⏸️ DEFERRED |
| **G3** | HIGH | Testing | Upgrade/rollback protocol not tested | `tests/upgrade_protocol_test.rs` | ⏸️ DEFERRED |
| **G4** | MEDIUM | Testing | Master IPC loop not tested | `src/master/ipc.rs` | ⏸️ DEFERRED |
| **G5** | MEDIUM | Testing | Static worker not tested | `src/worker/mod.rs` | ⏸️ DEFERRED |
| **G6** | MEDIUM | Testing | Drain protocol not E2E tested | `tests/` | ⏸️ DEFERRED |
| **G7** | LOW | Testing | IpcRateLimiter not tested | `src/process/ipc_rate_limit.rs` | ⏸️ DEFERRED |
| **G8** | LOW | Testing | Windows named pipe path not tested | `src/master/windows.rs` | ⏸️ DEFERRED |
| **O2** | MEDIUM | Code Quality | proxy.rs (1720 lines) too large | `src/proxy.rs` | ⏸️ DEFERRED |
| **O3** | MEDIUM | Code Quality | router.rs::new() is 185 lines | `src/router.rs` | ⏸️ DEFERRED |
| **D5** | RECOMMENDED | Documentation | Update SECURITY.md with RUSTSEC-2026-0095 | `SECURITY.md` | ✅ COMPLETED |
| **D6** | RECOMMENDED | Documentation | Remove superseded RUSTSEC-2025-0118 | `SECURITY.md` | ✅ COMPLETED |

### Wave 5: Feature Implementation
*Larger features that can be parallelized*

| Item | Priority | Category | Description | Files | Status |
|------|----------|----------|-------------|-------|--------|
| **OpenAPI** | - | Feature | Add OpenAPI documentation with utoipa | `src/admin/openapi.rs`, handlers | 🚧 IN PROGRESS |
| **T1** | HIGH | YARA/ThreatIntel | ThreatIntel re-announcement only local-origin | `src/mesh/threat_intel.rs` | ✅ COMPLETED |
| **T2** | MEDIUM | YARA/ThreatIntel | File upload malware scanner doesn't use mesh YARA | `src/static_files/file_manager.rs` | ✅ COMPLETED |
| **E7** | INFO | Edge Transform | Verify direct HTTP mode works | (already working) | ✅ COMPLETED |
| **Web Phase 1** | - | Web App | PHP location-level security bug | `src/php/mod.rs` | ✅ COMPLETED |
| **Web Phase 2** | - | Web App | Remove third-party CDN dependencies | `src/bin/server.rs` | ✅ COMPLETED |
| **Web Phase 3** | - | Web App | Create standalone directory listing module | `src/theme/dir_listing.rs` | ⏸️ DEFERRED |
| **Web Phase 4** | - | Web App | Enhanced directory listing features | `src/theme/` | ⏸️ DEFERRED |
| **Web Phase 5** | - | Web App | Theme system alignment | `src/theme/renderer.rs` | ⏸️ DEFERRED |
| **Admin 1** | LOW | Admin | Fix placeholder Blocking tab | `admin-ui/` | 📋 TODO |
| **Admin 2** | HIGH | Admin | Add Mesh Configuration page | `admin-ui/` | 📋 TODO |
| **Admin 3** | MEDIUM | Admin | Add DNS Configuration page | `admin-ui/` | 📋 TODO |
| **Admin 4** | MEDIUM | Admin | Add Settings search | `admin-ui/` | 📋 TODO |
| **Admin 5** | LOW | Admin | Wire up contextual help documentation | `admin-ui/` | 📋 TODO |
| **Admin 6** | MEDIUM | Admin | Add Error Page editor | `admin-ui/` | 📋 TODO |
| **Admin 7** | LOW | Admin | Add Restart indicators systematically | `admin-ui/` | 📋 TODO |
| **Admin 8-15** | MEDIUM/LOW | Admin | Various admin panel improvements | `admin-ui/` | 📋 TODO |

---

## Detailed Item Specifications

### Security Issues (plan12)

#### S-1: ML-KEM/ML-DSA Key Pair Mismatch - CRITICAL ✅ COMPLETED

**Location**: `src/mesh/config_identity.rs:49-66`, `src/mesh/config_identity.rs:84-99`

**Problem**: When loading ML-KEM-768 or ML-DSA private keys from base64 configuration, the keys are validated and then discarded. A new random keypair is generated instead.

**Fix**: Public key now derived FROM loaded secret key via `public_key()` / `verifying_key()` methods.

---

#### S-3: Threat Intel DHT Sync Accepts Unsigned Records - CRITICAL ✅ COMPLETED

**Location**: `src/mesh/threat_intel.rs:1194-1246`

**Problem**: `sync_from_dht()` accepts records without signatures.

**Fix**: Lines 1194-1246 now reject records with empty signatures via `continue` statement.

---

#### S-4: Threat Intel Publishes Without Signature - CRITICAL ✅ COMPLETED

**Location**: `src/mesh/threat_intel.rs:654-657`

**Problem**: If node has no signer configured, publishes with empty signature.

**Fix**: Early return at line 654-657 when `signer.is_none()`.

---

#### S-5: VerifiedUpstream Records Not Signature-Verified - HIGH ✅ COMPLETED

**Location**: `src/mesh/topology.rs:760-818`

**Problem**: When looking up verified upstreams, records are accepted without cryptographic verification.

**Fix**: Signature verification now required; records with empty signatures are rejected.

---

#### S-6: RFC 5011 State Machine Missing->Valid Bypass - HIGH ✅ COMPLETED

**Location**: `src/dns/trust_anchor.rs:450-454`

**Problem**: When key in `Missing` state is re-observed, transitions to `Seen` instead of `Pending`.

**Fix**: Changed to transition to `Pending` with `pending_since` set per RFC 5011 Section 3.3.

---

#### S-7: Non-CSPRNG RNG for Signing Key Generation - HIGH ✅ COMPLETED

**Location**: `src/mesh/config_identity.rs:344`

**Problem**: Uses `rand::rng().fill_bytes()` which uses `SmallRng`, not cryptographically secure.

**Fix**: Uses `OsRng` directly with `try_fill_bytes()` for signing key generation.

---

#### S-8: Dynamic Update Prerequisite Only Checks Existence - HIGH ✅ COMPLETED

**Location**: `src/dns/update.rs:461-479`

**Problem**: `check_prerequisite()` only verifies record existence, not RDATA content.

**Fix**: `check_prerequisite()` now validates RDATA content via `encode_rdata_normalized()` comparison.

---

#### S-9: RouteResponse Signature Never Verified - HIGH ✅ COMPLETED

**Location**: `src/mesh/discovery.rs:709-737`

**Problem**: Signature in RouteResponse is never actually checked.

**Fix**: `handle_route_response()` now verifies Ed25519 signature before caching route.

---

#### S-10: DHT Record Store Lacks Cryptographic Chain - HIGH ✅ COMPLETED

**Location**: `src/mesh/dht/record_store_crud.rs:63-72`

**Problem**: `verify_content_hash()` defined but never called.

**Fix**: Added `verify_content_hash()` call in `store_record()` after signature verification.

---

### Dependency Updates (plan14)

#### D1: Wasmtime Security Update - CRITICAL

**Issue**: RUSTSEC-2026-0095 (CVE-2026-34987) - Winch compiler backend sandbox escape

**Fix**: Update `wasmtime = "42"` to `wasmtime = "42.0.2"` in Cargo.toml

---

#### D5, D6: SECURITY.md Updates - RECOMMENDED

**Issue**: SECURITY.md documents RUSTSEC-2025-0118 but misses RUSTSEC-2026-0095

**Fix**: Add RUSTSEC-2026-0095, remove superseded RUSTSEC-2025-0118

---

### Performance Issues (plan10, plan13)

#### P1.1: Replace HashMap with AHashMap in Hot Paths - HIGH

**Files**: `src/waf/ratelimit/core.rs`, `src/waf/flood/connection_limiter.rs`, `src/proxy_cache/store.rs`, `src/http/server.rs`, `src/block_store.rs`

**Issue**: 121 files use `std::collections::HashMap` (SipHash 3-5x slower than Ahash)

**Fix**: Create `type HotHashMap<K, V> = AHashMap<K, V>` and use in hot paths

---

#### P1.2: Reduce to_string() Allocations in HTTP Handler - HIGH

**Location**: `src/http/server.rs:774-794`

**Issue**: 3 heap allocations per request for data already available as `&str`

**Fix**: Use `Cow<'_, str>` or avoid allocation when possible

---

#### P1.3: Fix ip_to_slot Power-of-2 Modulo - HIGH

**Location**: `src/utils.rs:481-497`

**Issue**: Modulo operation is slow; bitmask is ~10x faster for power-of-2 slot counts

**Fix**: Use `(hash >> 16) as usize & (num_slots - 1)` instead of `% num_slots`

---

#### P2.1: Shard BlockStore - MEDIUM

**Location**: `src/block_store.rs:73`

**Issue**: Single RwLock becomes bottleneck at 500K+ blocked IPs

**Fix**: Use sharding pattern similar to `ShardedZoneStore` (64 shards)

---

#### P2.2: Reduce to_lowercase() Allocations - MEDIUM

**Issue**: 217 matches of `.to_lowercase()`, many in attack detection hot paths

**Fix**: Pre-lowercase static patterns at initialization

---

### Mesh/DHT Issues (plan3)

#### M-D1: Edge Node PoW Authentication Bypasses Revocation Check - P1

**Location**: `src/mesh/peer_auth.rs:110-151`

**Problem**: When PoW is provided, function immediately delegates without checking revocation list first.

**Fix**: Move revocation check BEFORE PoW handling at line 120.

---

#### M-D2: DnsRecord Not Privileged While DnsZone Is - P1

**Location**: `src/mesh/dht/keys.rs:487-498`

**Problem**: `DnsZone` is privileged but `DnsRecord` is not.

**Fix**: Add `DnsRecord` to `is_privileged()` check.

---

#### M-D3: CapabilityAttestation Write Not Restricted - P2

**Location**: `src/mesh/dht/mod.rs`, `src/mesh/dht/record_store_crud.rs`

**Problem**: Any node can write capability attestations for any other node.

**Fix**: Add `capability_attestation:` prefix to `self_only_keys` in `DhtAccessControl`.

---

#### M-D4: DHT Announce Wrapper Signature Missing - P2

**Location**: `src/mesh/dht/record_store_sync.rs:720-728`

**Problem**: `DhtRecordAnnounce` message created with empty signature.

**Fix**: Sign the announce message and verify in handler.

---

#### M-D5: Quorum Async Tasks Accumulate on Timeout - P2

**Location**: `src/mesh/dht/record_store_crud.rs:195-226`

**Problem**: Quorum tasks continue running until max_attempts after timeout.

**Fix**: Accept as-is with monitoring, or add task tracking/cancellation.

---

#### M-D6: edge_can_respond_privileged Config Erosion Risk - P2

**Location**: `src/mesh/dht/routing/manager.rs:119-121`

**Problem**: If enabled, edge nodes become de facto global for read operations.

**Fix**: Add warning log when `edge_can_respond_privileged=true` and node is not global.

---

#### M-D7: No DHT Announce Rate Limiting - P3

**Location**: `src/mesh/dht/record_store_message.rs`

**Problem**: No per-source rate limiting on announce receive.

**Fix**: Add per-source rate limiting or use existing `rate_limit.rs` infrastructure.

---

#### M-D8: NODE_ID_POW_DIFFICULTY Hardcoded at 40 Bits - P3

**Location**: `src/mesh/dht/routing/node_id.rs:7`

**Problem**: 40 bits may become insufficient for Sybil resistance.

**Fix**: Make configurable via `MeshConfig`.

**Note**: AGENTS.md indicates this was increased to 40 bits already (was 32).

---

#### M-D9: Bootstrap Only Fails-Fast on Seed Connection - P2

**Location**: `src/mesh/discovery.rs:98-114`

**Problem**: No staggered retry with backoff; no DHT-based peer discovery fallback.

**Fix**: Add retry loop with exponential backoff and DHT fallback.

---

#### M-D10: Routing Table Sparse Bucket Refresh May Miss Peers - P3

**Location**: `src/mesh/dht/routing/manager.rs`

**Problem**: Empty buckets may not get filled due to limited network view.

**Fix**: Trigger active discovery for sparse buckets.

---

### WASM Issues (plan5)

#### W1: InstancePool Uses Wrong Path - HIGH

**Location**: `src/serverless/instance_pool.rs:167-189`

**Problem**: Uses `function_definition.path` (URL routing prefix) as WASM file path instead of `function_definition.name`.

**Fix**: Use `wasm_dir.join(&func_def.name).with_extension("wasm")`.

---

#### W2: InstancePool Spawns New WasmPluginManager Per Instance - HIGH

**Location**: `src/serverless/instance_pool.rs:167-189`

**Problem**: Each call creates new `WasmPluginManager` → new wasmtime `Engine` → unbounded memory.

**Fix**: Share `Arc<WasmRuntime>` across instances.

---

#### W3-W10: Additional WASM Issues

- **W3**: Instance pool doesn't reuse WasmRuntime
- **W4**: No admin API for serverless
- **W5**: No health checks for serverless instances
- **W6**: Instance pool limits not enforced
- **W7**: No serverless instance pool metrics
- **W8**: Missing serverless invocation metrics
- **W9**: No graceful shutdown for serverless pools
- **W10**: PluginManager and ServerlessManager use separate WASM runtimes

---

### Honeypot/Threat Intel Issues (plan6, plan7)

#### H1: TLS Honeypot Uses Wrong Blocking Function - MEDIUM

**Location**: `src/tls/server.rs:676`

**Problem**: Uses `block_ip_with_threat_intel()` instead of `block_ip_for_honeypot()`.

**Fix**: Change to `block_ip_for_honeypot()`.

---

#### H2: Port Honeypot Re-announce Only Runs for Global Nodes - MEDIUM

**Location**: `src/mesh/threat_intel.rs:1625-1639`

**Problem**: `re_announce_local_indicators()` only runs when `node_role.is_global()`.

**Fix**: Remove `node_role.is_global()` check or add separate task for non-global.

---

#### H3: Standalone Mode Calls Unnecessary Mesh Publishing - LOW

**Location**: `src/worker/unified_server.rs:1077-1086`

**Problem**: `start_mesh_threat_publishing()` called when mesh disabled.

**Fix**: Add check for mesh being enabled.

---

#### H4: Signature Format Mismatch - MEDIUM

**Location**: `src/mesh/threat_intel.rs:427-430, 668-675, 1186-1193`

**Problem**: `announce_honeypot_indicator()` uses comma-separated format, others use colon-separated.

**Fix**: Align `announce_honeypot_indicator()` signing to use colon-separated format.

---

#### T1: ThreatIntel Re-Announcement Only Local-Origin - HIGH

**Location**: `src/mesh/threat_intel.rs:1648-1672`

**Problem**: `re_announce_local_indicators()` only re-announces `local_origin=true` indicators.

**Fix**: Re-publish all non-expired indicators regardless of `local_origin` flag.

---

#### T2: File Upload Malware Scanner Doesn't Use Mesh YARA - MEDIUM

**Location**: `src/static_files/file_manager.rs:226-231`

**Problem**: `MalwareScanner` created without YARA rules from mesh.

**Fix**: Add `YaraRulesManager` to `FileManager` and update callers.

---

### Edge Transform Issues (plan8)

#### E2: Mesh QUIC Proxy Applies No Transforms - CRITICAL

**Location**: `src/mesh/transport_peer.rs:2388-2500`

**Problem**: `handle_http_proxy_stream()` is raw TCP relay - no transforms applied.

**Fix**: Refactor to collect response, check content-type, fetch transform configs from DHT, apply transforms.

---

#### E1, E3, E4, E5, E6: Additional Edge Transform Issues

- **E1**: DHT key mismatch in MeshProxy (dormant code)
- **E3**: All transforms silently skipped in MeshProxy
- **E4**: Poisoned image cache key mismatch
- **E5**: Duplicate transform config publishing code
- **E6**: Dead code - MeshBackend/MeshProxy subsystem

---

### Code Quality Issues (plan11)

#### C1: Blocking std::thread::sleep in Async Contexts - CRITICAL

**Location**: `src/worker/mod.rs:622`

**Problem**: Blocking sleep in tokio task blocks the async runtime.

**Fix**: Replace with `tokio::time::sleep().await`.

---

#### C2: Circular Dependency: proxy.rs ↔ waf/mod.rs - CRITICAL

**Location**: `src/proxy.rs`, `src/waf/mod.rs`

**Problem**: `proxy.rs:28` imports `WafCore`; `waf/mod.rs:78` imports `WafDecision` from `proxy.rs`.

**Fix**: Move `WafDecision` enum from `proxy.rs` to `waf/mod.rs`.

---

### Test Coverage Issues (plan16)

#### T1: Stack Overflow in test_connection_rate_limiting - CRITICAL

**Location**: `src/waf/flood/connection_limiter.rs:180`

**Problem**: `Box::new([const { AtomicU32::new(0) }; 262144])` exceeds 2MB stack.

**Fix**: Use `#[cfg(test)]` smaller constant or `vec!` with `.into_boxed_slice()`.

---

#### T2: Off-by-one in test_restart_delay_exponential_backoff - CRITICAL

**Location**: `src/overseer/process.rs:1647-1663`

**Problem**: Test expects cap to apply at `count=6` but actual boundary is `count < 6`.

**Fix**: Change `count <= 6` to `count < 6` in assertion.

---

### OpenAPI Implementation (plan9)

#### OpenAPI Phase 1-5

1. Add `utoipa` and `utoipa-swagger-ui` dependencies
2. Create `src/admin/openapi.rs` with `#[derive(OpenApi)]`
3. Wire OpenAPI JSON endpoint
4. Add Swagger UI endpoint via `SwaggerUi::new()`
5. Annotate ~100 handler functions with `#[utoipa::path]`
6. Add `--export-api-openapi` CLI flag

---

### Web App Stack (plan4)

#### Phase 1: PHP Location-Level Security Bug - CRITICAL

**Location**: `src/php/mod.rs:197-206`

**Problem**: `create_php_client()` only reads site-level PHP config, ignores location-level.

**Fix**: Accept merged config in `create_php_client()`.

---

### Admin Panel Improvements (plan15)

Items 1-15 covering:
- Fix placeholder UI (Blocking tab, Static, Auth, etc.)
- Add Mesh/DNS Configuration pages
- Settings search
- Contextual help documentation wiring
- Error Page editor
- Restart indicators
- GeoIP, Logging, Bot Detection, Plugin/WASM, TARPIT, IPC, Rate Limit, Threat Level configuration

---

## Verification Commands

```bash
# Run integration tests (fast)
cargo test --test integration_test

# Run DHT integration tests
cargo test --test dht_integration_test

# Run IPC tests
cargo test --test ipc_test

# Run E2E process tests
cargo test --test e2e_process_test

# Verify test compilation (important: cargo check does NOT compile test code)
cargo test --lib --no-run

# Run clippy
cargo clippy --lib -- -D warnings

# Format check
cargo fmt --check

# Run all tests
cargo test
```

---

## Subagent Execution Best Practices

When using subagents to implement items:

1. **Always verify the actual code** — subagents may claim a fix was applied but the code still shows the old version
2. **Run compilation checks** — `cargo clippy --lib -- -D warnings` to catch type errors
3. **Run tests** — `cargo test --test integration_test` to verify runtime behavior
4. **Run format check** — `cargo fmt` then `cargo fmt --check`

**Critical verification step**: After any subagent reports completion:
```bash
git diff HEAD -- <file>
rg "expected_pattern" <file>
```

---

## Appendix: Historical Statistics

| Metric | Value |
|--------|-------|
| Total items consolidated | ~100+ |
| Completed/Fixed items | ~80+ |
| Remaining actionable | ~50 |
| Waves defined | 5 |

**Last consolidated**: 2026-04-16