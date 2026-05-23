# SynVoid Architecture Review - Implementation Plan

**Generated:** 2026-05-23
**Last Updated:** 2026-05-23 (consolidated and verified)
**Source:** batch1-4 consolidated reviews covering DNS, WAF, Layer 3.5, Admin API, Mesh, Process Lifecycle, Config, App Handlers, Routing, Plugin/WASM, Worker, Proxy, Platform, Networking, HTTP/Proxy, Config/Admin, Core/Overview

---

## Overview

This plan consolidates findings from 4 batches of architecture reviews across 16 modules. It organizes action items by priority and groups related items together for efficient implementation.

### Summary Statistics

| Category | Count | Wave |
|----------|-------|------|
| **Critical Bugs (needs fix)** | 3 | Wave 1 |
| **Critical Bugs (already fixed)** | 4 | Wave 1 |
| **Critical Bugs (needs investigation/removal)** | 3 | Wave 1 |
| **High Priority Items** | 19 | Wave 2 |
| **Medium Priority Items** | 40 | Wave 3 |
| **Implementation Projects** | 9 | Wave 4 |
| **Documentation Fixes** | 10 doc targets | Wave 5 |
| **Low Priority Items** | 50+ | Wave 6 |
| **Total Action Items** | 120+ | |

### Wave Organization

Implementation is organized into **waves** that can execute in parallel where dependencies allow. Items within a wave can be worked on simultaneously by different agents.

---

## Wave 1: Critical Security/Safety Bugs

**These items require immediate attention. Items marked "Already Fixed" should be removed from active tracking. Items marked "Needs Investigation" need clarification before work begins.**

### Items to REMOVE (Already Fixed)
| Item | Description | Location | Status |
|------|-------------|----------|--------|
| 1.1 | Audit Log File Permissions | `src/admin/audit.rs:76` | Already Fixed - permissions set in `log()` method at lines 131-139 |
| 1.2 | StreamingWafCore Trailing Window | `src/waf/attack_detection/streaming.rs:129-134` | Already Fixed - sliding window logic is correct |
| 1.5 | gRPC Uptime Hardcoded | `src/supervisor/api.rs:55` | Already Fixed - now returns `self.state.start_time.elapsed().as_secs()` |
| 1.10 | CSRF Validation | `src/admin/state.rs:736` | Already Fixed - uses `ct_eq()` constant-time comparison |

### Items to INVESTIGATE or CORRECT
| Item | Description | Location | Status |
|------|-------------|----------|--------|
| 1.4 | ML-KEM Missing Proof of Possession | `src/mesh/ml_kem_key_exchange.rs:63-164` | Needs Fix - no verification client can decapsulate |
| 1.6 | current_depth() Doesn't Exist | `src/location_matcher.rs:191-195` | **RESOLVED** - Documentation error, only `is_empty()` and `len()` exist |
| 1.7 | allowed_dht_prefixes Not Propagated | `instance_pool.rs:186,213-226` | **FIXED** - Now propagated via config |
| 1.8 | macos-sandbox Feature Gate | `src/platform/sandbox.rs:1036-1133` | Feature EXISTS - just needs enabling via `macos-sandbox` feature flag |

### 1.3 [x] verify_hybrid() Accepts Ed25519-Only Signatures (BUG-L1) - FIXED
- **Location:** `src/mesh/ml_dsa.rs:206-218`
- **Impact:** Medium - weakens fail-safe design
- **Issue:** When `signature.has_ml_dsa()` returns `false`, function returns `true` at line 217. Pure Ed25519-only signatures are accepted without ML-DSA verification.
- **Fix:** For hybrid signatures, both Ed25519 AND ML-DSA should be required. Return `false` when ML-DSA is absent.
- **Source:** batch1_layer_3_5_review
- **Status:** Fixed in `chore/wave1-mesh-critical-fixes` branch

### 1.4 [ ] ML-KEM Key Encapsulation Missing Proof of Possession (BUG-L3)
- **Location:** `src/mesh/ml_kem_key_exchange.rs:63-164`
- **Impact:** Medium - key encapsulation doesn't verify client proof of possession
- **Issue:** `confirm_key()` only checks if `session_id` exists (line 219), doesn't verify client can decapsulate. A rogue client could send any peer's public key.
- **Fix:** Add verification that client can decrypt the ciphertext before confirming session.
- **Source:** batch1_layer_3_5_review

### 1.6 [x] current_depth() Doesn't Exist (C4) - RESOLVED
- **Location:** `src/location_matcher.rs:191-195`
- **Impact:** HIGH - documentation references non-existent function
- **Issue:** The file contains `is_empty()` and `len()` methods but not `current_depth()`. This appears to be dead code or documentation error.
- **Fix:** Documentation error - no implementation needed.
- **Source:** batch2_routing_review
- **Status:** Resolved - documented in AGENTS.md

### 1.7 [x] allowed_dht_prefixes Not Propagated to Pooled Instances (C5) - FIXED
- **Location:** `src/serverless/instance_pool.rs:190`, `src/plugin/instance_pool.rs:186`
- **Impact:** CRITICAL - DHT restrictions may not enforce correctly for pooled instances
- **Issue:** Both locations hardcoded `allowed_dht_prefixes: Vec::new()` during warmup, ignoring configured values.
- **Fix:** Set `allowed_dht_prefixes` from `WasmResourceLimits` during warmup (instance_pool.rs:79-209 warmup flow)
- **Source:** batch2_plugin_review, AGENTS.md Lesson #19
- **Status:** Fixed in `chore/wave1-dht-prefix-fixes` branch

### 1.8 [~] macos-sandbox Feature Gate (BUG-PLATFORM-1) - FEATURE EXISTS
- **Location:** `Cargo.toml:38`, `src/platform/sandbox.rs:1037-1126`
- **Impact:** Medium - seatbelt sandbox requires explicit feature enablement
- **Status:** Feature EXISTS in Cargo.toml (`macos-sandbox = []`). Code is properly gated with `#[cfg(feature = "macos-sandbox")]`. Users must enable the feature for enforcement on macOS.
- **Action:** Ensure documentation clearly states users must enable `macos-sandbox` feature for enforcement.
- **Source:** batch3_platform_review, AGENTS.md Lesson #8

### 1.9 [x] Retry Config Not Applied from from_config() (BUG-PROXY-1) - FIXED
- **Location:** `src/proxy/mod.rs:293-316`
- **Impact:** HIGH - Retries **always disabled** regardless of configuration
- **Issue:** When `upstream_pool` is `None` (lines 252-260), `with_upstream_pool()` is never called, so `retry_config` remains `None`.
- **Fix:** Ensure `retry_config` is set even when `upstream_pool` is `None`, or call `with_upstream_pool()` regardless.
- **Source:** batch3_proxy_review, AGENTS.md Lesson #20
- **Status:** Fixed in `chore/wave1-proxy-critical-fixes` branch

---

## Wave 2: High Priority Items (Parallel Execution)

**These items can be executed in parallel by different agents. Each is independent.**

| Item | Description | Location | Dependencies | Status |
|------|-------------|----------|--------------|--------|
| 2.1 | DNS - Complete AXFR Record Type Support | `src/dns/transfer.rs:829-878` | None | **DONE** - `chore/wave2-dns-axfr-fixes` |
| 2.2 | DNS - Verify DNS Cookie Server Integration | `src/dns/cookie.rs` | None | |
| 2.3 | DNS - Complete GOST Algorithm Support | `src/dns/dnssec_validation.rs:260` | None | **DOCUMENTED** - requires GOST crate |
| 2.4 | WAF - Complete GeoIP Country Blocking | `src/waf/asn_tracker.rs` | None | **DOCUMENTED** - actually ASN-based |
| 2.5 | Layer 3.5 - Update Raft Documentation | `architecture/layer_3_5_deep_dive.md:32` | None | **DONE** - `chore/wave2-documentation-updates` |
| 2.6 | Layer 3.5 - Address Quorum Deadlock | `src/mesh/peer_auth.rs:230-243` | None | Deferred - MESH-15 |
| 2.7 | Mesh - Document DHT Ingress Verification Gaps | `architecture/mesh_deep_dive.md` | None | **DONE** - already documented |
| 2.8 | Config - Fix Sites HashMap Location in Diagram | `architecture/config_deep_dive.md` | None | Already correct |
| 2.9 | Config - Add Missing Fields to MainConfig | `architecture/config_deep_dive.md` | None | Already present |
| 2.10 | App Handlers - Integrate or Remove Minification | `src/static_files/mod.rs:131-137` | None | |
| 2.11 | Routing - Document Missing Backend Types | `src/router.rs:65-77` | None | **DOCUMENTED** |
| 2.12 | Routing - Add Active Health Checks to UpstreamPool | `src/upstream/pool.rs` | None | **DONE** - `chore/wave2-upstream-health-checks` |
| 2.13 | Plugin - Implement Spin Instance Reuse | `src/spin/runtime.rs:118` | None | **DONE** - `chore/wave2-spin-fixes` |
| 2.14 | Worker - Document Linux-Only CPU Affinity | `src/worker/unified_server.rs:205-208` | None | **DOCUMENTED** |
| 2.15 | HTTP/Proxy - Verify ErasedHttpClient Integration | `src/http/server.rs:3302` | None | Phase 9 incomplete - documented |
| 2.16 | HTTP/Proxy - Complete HTTP/2 Support | `src/http_client/mod.rs:890` | None | Requires ALPN - documented |
| 2.17 | Core/Overview - Add MeshProxy to Module Index | `architecture/overview.md` | None | Already present |
| 2.18 | Core/Overview - Add Missing Modules to Index | `architecture/overview.md` | None | Already present |
| 2.19 | Networking - Clarify PQC Feature Flag Interactions | `architecture/networking_deep_dive.md` | None | **DONE** - `chore/wave2-documentation-updates` |

### 2.1 DNS - Complete AXFR Record Type Support
- **Location:** `src/dns/transfer.rs:829-878`
- **Issue:** `build_axfr_record()` only handles A, AAAA, CNAME, NS, SOA, TXT, MX. Missing: SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA
- **Priority:** HIGH
- **Fix:** Add match arms for all missing record types
- **Source:** batch1_dns_review, AGENTS.md Lesson #12

### 2.2 DNS - Verify DNS Cookie Server Integration
- **Location:** `src/dns/cookie.rs`
- **Issue:** Cookie server exists (141 lines) with RFC 7873 compliant implementation. "Verify" means clarify integration points are correct.
- **Priority:** MEDIUM
- **Source:** batch1_dns_review

### 2.3 DNS - Complete GOST Algorithm Support
- **Location:** `src/dns/dnssec_validation.rs:260`
- **Issue:** GOST type 3 DS digest not supported
- **Priority:** HIGH
- **Source:** batch1_dns_review

### 2.4 WAF - Complete GeoIP Country Blocking (NOTE: Actually ASN-based)
- **Location:** `src/waf/asn_tracker.rs`
- **Issue:** `AsnTracker` implements **ASN-based distributed scraper detection**, not true GeoIP country blocking. Uses `GeoIpManager` only for ASN lookups.
- **Priority:** MEDIUM - clarify documentation to reflect actual behavior
- **Source:** batch1_waf_review

### 2.5 Layer 3.5 - Update Raft Documentation
- **Location:** `architecture/layer_3_5_deep_dive.md:32`
- **Issue:** Document recommends Raft migration but Raft already implemented in `src/mesh/raft/`
- **Priority:** HIGH
- **Source:** batch1_layer_3_5_review

### 2.6 Layer 3.5 - Address Quorum Deadlock
- **Location:** `src/mesh/peer_auth.rs:230-243`
- **Issue:** Quorum deadlock risk during partition - requires DHT-to-Raft trust chain migration
- **Priority:** HIGH
- **Source:** batch1_layer_3_5_review, MESH-15

### 2.7 Mesh - Document DHT Ingress Verification Gaps
- **Location:** `architecture/mesh_deep_dive.md`
- **Issue:** Multiple message types lack node_id/TLS cert validation (MESH-14)
- **Priority:** HIGH
- **Source:** batch1_mesh_review, batch4_mesh_networking, MESH-14

### 2.8 Config - Fix Sites HashMap Location in Diagram
- **Location:** `architecture/config_deep_dive.md`
- **Issue:** Diagram at line 86 shows `sites: HashMap<String, SiteConfig>` under **ConfigManager** (correct), not MainConfig. Documentation is ACCURATE.
- **Action:** Verify diagram correctness and remove if already fixed
- **Source:** batch2_config_review

### 2.9 Config - Add Missing Fields to MainConfig Hierarchy
- **Location:** `architecture/config_deep_dive.md:45-67`
- **Issue:** Diagram omits 20+ fields (tokio, ip_feeds, rule_feed, yara_feed, rate_limit_memory, proxy_limits, etc.)
- **Priority:** HIGH
- **Source:** batch2_config_review

### 2.10 App Handlers - Integrate or Remove Minification
- **Location:** `src/static_files/mod.rs:131-137`
- **Issue:** `new_with_minifier()` accepts minifier params but they are UNUSED (prefixed with `_`)
- **Priority:** HIGH
- **Source:** batch2_app_handlers_review

### 2.11 Routing - Document Missing Backend Types
- **Location:** `src/router.rs:65-77`
- **Issue:** BackendType enum has 11 variants (Upstream, FastCgi, Php, Cgi, AxumDynamic, AppServer, Static, QuicTunnel, Serverless, Mesh, Spin) - not all documented. PeakEwma is NOT in the enum.
- **Priority:** HIGH
- **Source:** batch2_routing_review, AGENTS.md Lesson #15

### 2.12 Routing - Add Active Health Checks to UpstreamPool
- **Location:** `src/upstream/pool.rs`
- **Issue:** Only FastCgiPool has active health check thread (`start_health_check()` at `src/fastcgi/pool.rs:148`). UpstreamPool relies only on on-demand/reactive checks via `HealthChecker::check()` called by admin API.
- **Priority:** HIGH
- **Source:** batch2_routing_review, AGENTS.md Lesson #17

### 2.13 Plugin - Implement Spin Instance Reuse
- **Location:** `src/spin/runtime.rs:251`
- **Issue:** Each request creates new `SpinAppInstance` via `instantiate_app()` - high cold-start overhead
- **Priority:** HIGH
- **Source:** batch2_plugin_review, AGENTS.md Lesson #16

### 2.14 Worker - Document Linux-Only CPU Affinity
- **Location:** `src/worker/unified_server.rs:205-208`
- **Issue:** CPU affinity only works on Linux; logs warning on non-Linux platforms
- **Priority:** MEDIUM
- **Source:** batch3_worker_review, AGENTS.md Lesson #7

### 2.15 HTTP/Proxy - Verify ErasedHttpClient Integration
- **Location:** `src/http/server.rs:3302`
- **Issue:** `use_erased_client` hardcoded to `false`. ErasedHttpClient cloned but never called. Phase 9 integration incomplete.
- **Priority:** HIGH
- **Source:** batch3_http_proxy_review, AGENTS.md Lesson #11

### 2.16 HTTP/Proxy - Complete HTTP/2 Support
- **Location:** `src/http_client/mod.rs:890`
- **Issue:** `is_http2` hardcoded to `false`; HTTP/2 infrastructure exists but never used
- **Priority:** HIGH
- **Source:** batch3_http_proxy_review, AGENTS.md Lesson #18

### 2.17 Core/Overview - Add MeshProxy to Module Index
- **Location:** `architecture/overview.md`
- **Issue:** `MeshProxy` at `src/mesh/proxy.rs:63` (1994 lines) is key routing component but not mentioned in architecture overview
- **Priority:** HIGH
- **Source:** batch4_core_overview, AGENTS.md Lesson #10

### 2.18 Core/Overview - Add Missing Modules to Index
- **Location:** `architecture/overview.md`
- **Issue:** Missing modules: `src/icmp_filter/`, `src/serverless/`, `src/spin/`, `src/wasm_pow/`, `src/tarpit/`, `src/honeypot_port/`, `src/plugin/`, `src/sandbox/`
- **Priority:** MEDIUM
- **Source:** batch4_core_overview

### 2.19 Networking - Clarify PQC Feature Flag Interactions
- **Location:** `architecture/networking_deep_dive.md`
- **Issue:** Need to clarify `post-quantum` vs `pqc-mesh` vs `verify-pq` feature flags
- **Priority:** MEDIUM
- **Source:** batch3_networking_review

---

## Wave 3: Medium Priority Items (Parallel Execution)

**These items can be executed in parallel. Documentation-only items grouped by target document.**

### 3.1 DNS - Add DNSSEC Validation Chain Logging
- **Location:** `src/dns/dnssec_validation.rs`
- **Source:** batch1_dns_review

### 3.2 DNS - Add DNSSEC Signing/Validation Round-Trip Integration Tests
- **Location:** `src/dns/dnssec_signing.rs`, `src/dns/dnssec_validation.rs`
- **Source:** batch1_dns_review

### 3.3 DNS - Document TSIG Algorithm Negotiation
- **Location:** `src/dns/tsig.rs`
- **Source:** batch1_dns_review

### 3.4 DNS - Add NSEC3 Opt-Out Support
- **Location:** `src/dns/dnssec_signing.rs:178-242`
- **Source:** batch1_dns_review

### 3.5 DNS - Review RSA Key Size Defaults
- **Location:** `src/dns/server/mod.rs:605`
- **Issue:** Currently hardcoded 2048; make configurable
- **Source:** batch1_dns_review

### 3.6 Layer 3.5 - Implement ML-KEM Key Rotation
- **Location:** `src/mesh/ml_kem_key_exchange.rs:41-58`, `src/mesh/transport.rs:1989-2001`
- **Source:** batch1_layer_3_5_review

### 3.7 Layer 3.5 - Consider Raft-Based Revocation Replication
- **Location:** `src/mesh/peer_auth.rs:21-117`
- **Issue:** Instead of DHT distribution
- **Source:** batch1_layer_3_5_review

### 3.8 Layer 3.5 - Update Topology-Aware Router Description
- **Location:** `architecture/mesh_deep_dive.md:44`
- **Issue:** Update to "weighted scoring based on latency, reputation, and node role"
- **Source:** batch1_mesh_review

### 3.9 Layer 3.5 - Soften Threat Propagation Timing
- **Location:** `architecture/mesh_deep_dive.md:49`
- **Issue:** Change to "Distributed via DHT propagation and Raft consensus"
- **Source:** batch1_mesh_review

### 3.10 Layer 3.5 - Clarify Raft Consensus Scope
- **Location:** `architecture/mesh_deep_dive.md:9`
- **Issue:** Clarify "OrgPublicKey and ThreatIntel records; DHT for routing and other state"
- **Source:** batch1_mesh_review

### 3.11 WAF - Document check_body_fragments() Zero-Copy
- **Location:** `src/waf/attack_detection/streaming.rs:118`
- **Source:** batch1_waf_review

### 3.12 WAF - Move FloodConfig Hardcoded Defaults
- **Location:** `src/waf/flood/mod.rs:40-56`
- **Source:** batch1_waf_review

### 3.13 WAF - Update Burst Tokens Documentation
- **Location:** `src/waf/traffic_shaper/limiter.rs:96`
- **Issue:** Document says "default 10" but it's configurable
- **Source:** batch1_waf_review

### 3.14 Config - ConfigManager Site Lookup Exact Match
- **Location:** `crates/synvoid-config/src/lib.rs:195-197`
- **Issue:** May not work for alias domains
- **Source:** batch2_config_review

### 3.15 Config - reload_site() Filename Storage
- **Location:** `crates/synvoid-config/src/lib.rs:199-220`
- **Issue:** Relies on `domains.first()` for filename; fails if filename ≠ primary domain
- **Source:** batch2_config_review

### 3.16 App Handlers - Verify Spin Registration Mechanism
- **Location:** Admin API
- **Source:** batch2_app_handlers_review

### 3.17 App Handlers - Verify FastCGI Streaming
- **Location:** `src/fastcgi/mod.rs`
- **Source:** batch2_app_handlers_review

### 3.18 Routing - Update Connection Lifecycle Documentation
- **Location:** `src/router.rs:1124-1219`
- **Issue:** "Protocol Negotiation" step doesn't match - no explicit lease
- **Source:** batch2_routing_review

### 3.19 Routing - Verify Weighted Round Robin Configurable
- **Location:** `src/upstream/pool.rs:566-583`
- **Source:** batch2_routing_review

### 3.20 Plugin - Serverless Engine Sharing
- **Location:** `instance_pool.rs:165`
- **Issue:** Creates fresh `Engine` per function pool; should share across serverless functions
- **Source:** batch2_plugin_review

### 3.21 Plugin - DHT Prefix Hardcoded List
- **Location:** `wasm_runtime.rs:840-848`
- **Issue:** Sensitive prefixes hardcoded; make configurable
- **Source:** batch2_plugin_review

### 3.22 Admin - Add Timing Normalization to Auth Handler
- **Location:** `src/admin/handlers/auth.rs:17-28`
- **Issue:** Session enumeration timing leak
- **Source:** batch1_admin_review, batch4_config_admin

### 3.23 Admin - Clarify Rate Limiter Distinction
- **Location:** `src/admin/auth.rs:139`, `src/admin/middleware.rs:124-128`
- **Issue:** Global vs per-instance rate_limiter distinction unclear
- **Source:** batch1_admin_review

### 3.24 Worker - Add BufferPool Documentation
- **Source:** batch3_worker_review

### 3.25 Worker - Clarify Process Hierarchy
- **Location:** `architecture/platform_deep_dive.md`
- **Source:** batch3_worker_review

### 3.26 Platform - Clarify SO_REUSEPORT Usage
- **Location:** architecture docs
- **Issue:** Only used during upgrades, not initial workers
- **Source:** batch3_platform_review

### 3.27 Proxy - Add Health Check TCP Mode
- **Location:** `src/upstream/health.rs:224-231`
- **Issue:** Use `UpstreamAddress::parse()`
- **Source:** batch3_proxy_review

### 3.28 Proxy - Add Connection Health Check Before Checkin
- **Location:** `src/http_client/erased_pool.rs:419`
- **Source:** batch3_proxy_review

### 3.29 Proxy - Fix TypedConnectionPool https_or_http() Inconsistency
- **Location:** `src/http_client/typed_pool.rs:128`
- **Source:** batch3_proxy_review

### 3.30 HTTP/Proxy - Document Layer 3.5 Half-TCP
- **Location:** `src/upstream/pool.rs:67`, `src/upstream/address.rs`
- **Source:** batch3_http_proxy_review

### 3.31 HTTP/Proxy - Add Integration Test for Connection Pool Checkout
- **Location:** `src/http_client/erased_pool.rs:245-283`
- **Source:** batch3_http_proxy_review

### 3.32 Networking - Document ACME Configuration Requirements
- **Issue:** DNS-01 vs HTTP-01, cache_dir requirements
- **Source:** batch3_networking_review

### 3.33 Networking - Add Amplification Protection Configuration
- **Source:** batch3_networking_review

### 3.34 Networking - Soften Zero-Copy IO Claim
- **Location:** `architecture/networking_deep_dive.md:54-55`
- **Issue:** Zero-copy is aspirational, not implementation fact
- **Source:** batch4_mesh_networking

### 3.35 Config/Admin - Clarify Admin Auth vs User Auth Distinction
- **Location:** `architecture/admin_deep_dive.md`
- **Source:** batch4_config_admin

### 3.36 Config/Admin - Add AUTH_WINDOW_DURATION Constant
- **Location:** `architecture/admin_deep_dive.md`
- **Source:** batch4_config_admin

### 3.37 Mesh/Networking - Clarify Bloom Filter Usage
- **Location:** `architecture/mesh_deep_dive.md:30`
- **Issue:** Route announcements, not DHT discovery (documentation already clarifies this)
- **Source:** batch4_mesh_networking

### 3.38 Mesh/Networking - Soften Zero-Copy IO Claim
- **Location:** `architecture/networking_deep_dive.md:54-55`
- **Source:** batch4_mesh_networking

### 3.39 Core/Overview - Improve Spin Handler Documentation
- **Source:** batch4_core_overview

### 3.40 Core/Overview - Update Generic WASM Handler Reference
- **Location:** `architecture/app_handlers.md:58`
- **Issue:** Document mentions `WasmHandler` but generic WASM uses `WasmRuntime` directly
- **Source:** batch4_core_overview

---

## Wave 4: Implementation Projects

**Larger items requiring multiple PRs and significant testing. Items with dependencies must be executed in sequence.**

### 4.1 AXFR Completion (DNS)
- **Location:** `src/dns/transfer.rs:829-878`
- **Dependencies:** None
- **Estimated Effort:** Medium
- **Record Types to Add:** SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA
- **Source:** batch1_dns_review

### 4.2 NSEC3 Opt-Out Support (DNS)
- **Location:** `src/dns/dnssec_signing.rs:178-242`
- **Dependencies:** None
- **Estimated Effort:** Medium
- **Source:** batch1_dns_review

### 4.3 CORS Middleware (Admin) - NOTE: Already Implemented
- **Location:** `src/admin/mod.rs:48-94` (NOT middleware.rs)
- **Dependencies:** None
- **Estimated Effort:** N/A - Verify and update documentation
- **Issue:** CORS is implemented via `create_cors_layer()`, not in middleware.rs
- **Source:** batch1_admin_review

### 4.4 DHT-to-Raft Migration (Layer 3.5)
- **Location:** `src/mesh/peer_auth.rs:230-243`
- **Dependencies:** Requires thorough testing, could affect mesh networking
- **Estimated Effort:** High
- **Source:** batch1_layer_3_5_review, MESH-15

### 4.5 GeoIP Blocking (WAF) - NOTE: Actually ASN Scraping Detection
- **Location:** `src/waf/asn_tracker.rs`
- **Dependencies:** May need GeoIP database integration for true country blocking
- **Estimated Effort:** Medium
- **Note:** Current implementation is ASN-based scraper detection, not GeoIP country blocking
- **Source:** batch1_waf_review

### 4.6 ErasedHttpClient Integration (HTTP/Proxy)
- **Location:** `src/http/server.rs:3302`
- **Dependencies:** None
- **Estimated Effort:** Medium
- **Note:** Phase 9 integration was never completed per AGENTS.md Lesson #11
- **Source:** batch3_http_proxy_review

### 4.7 HTTP/2 Complete Support (HTTP/Proxy)
- **Location:** `src/http_client/mod.rs:890`
- **Dependencies:** Item 4.6 (ErasedHttpClient integration) - both relate to `is_http2` in PoolKey
- **Estimated Effort:** Medium
- **Source:** batch3_http_proxy_review

### 4.8 Spin Instance Reuse (Plugin)
- **Location:** `src/spin/runtime.rs:251`
- **Dependencies:** None
- **Estimated Effort:** Medium
- **Source:** batch2_plugin_review

### 4.9 WAF Challenge Stage Refactor
- **Location:** `src/waf/mod.rs:440-515`
- **Dependencies:** None
- **Estimated Effort:** Medium
- **Alternative:** Update documentation to reflect threat-level-escalation model
- **Source:** batch3_worker_review

---

## Wave 5: Documentation Fixes

**Documentation-only changes grouped by target document. Multiple agents can work in parallel on different documents.**

### 5.1 architecture/mesh_deep_dive.md
- [ ] Update - Raft already implemented (not migration needed)
- [ ] Update topology-aware router description
- [ ] Soften threat propagation timing claims
- [ ] Clarify Raft consensus scope
- [ ] Strengthen Bloom filter purpose - route propagation, not DHT discovery (already documented at line 30)
- [ ] Document DHT ingress verification gaps as known limitations (MESH-14)
- [ ] Fix Ed25519/X25519 confusion
- [ ] Clarify "Kademlia-inspired with geo-distance enhancements"
- [ ] Add PQC feature flag cross-reference

### 5.2 architecture/waf_deep_dive.md
- [ ] Verify JS Challenge location: `src/challenge/pow.rs` (documentation at line 72 appears correct)
- [ ] Standardize detector names
- [ ] Document check_body_fragments() as zero-copy
- [ ] Update burst tokens documentation
- [ ] Document blackhole mechanism in FloodProtector

### 5.3 architecture/layer_3_5_deep_dive.md
- [ ] Update - Raft already implemented
- [ ] Document sign vs sign_with_ml_dsa distinction

### 5.4 architecture/dns_deep_dive.md
- [ ] Update recursive resolver description
- [ ] Add rate limiting architecture diagram
- [ ] Document DNS cookie server integration points

### 5.5 architecture/config_deep_dive.md
- [ ] Verify sites HashMap location (appears correct at line 86 under ConfigManager)
- [ ] Add missing fields: tokio, ip_feeds, rule_feed, yara_feed, rate_limit_memory, proxy_limits, etc.
- [ ] Fix Utils crate path: `crates/synvoid-utils/` (verify correct path)
- [ ] Clarify ConfigManager location in lib.rs (at `crates/synvoid-config/src/lib.rs:113`)
- [ ] Add config propagation pattern section
- [ ] Add site_id to SiteConfig hierarchy

### 5.6 architecture/admin_deep_dive.md
- [ ] Clarify two auth systems (Admin Auth vs User Auth)
- [ ] Add AUTH_WINDOW_DURATION constant documentation
- [ ] Clarify feature-gated handler count (29 modules including mesh-gated)
- [ ] Clarify rate limiter location

### 5.7 architecture/overview.md
- [ ] Add missing modules to Module Index:
  - `src/icmp_filter/` — ICMP filtering
  - `src/serverless/` — WASM serverless runtime
  - `src/spin/` — Spin framework support
  - `src/wasm_pow/` — WASM PoW
  - `src/tarpit/` — Bot tar pit
  - `src/honeypot_port/` — Honeypot ports
  - `src/mesh/proxy.rs` — MeshProxy (key component, 1994 lines)
  - `src/plugin/` — Plugin system
  - `src/sandbox/` — Process sandboxing
- [ ] Improve Spin manual registration requirement visibility
- [ ] Update Router module description (1377 lines, radix tree complexity)
- [ ] Process flags verification for MeshAgent
- [ ] Clarify gRPC binding - localhost requirement
- [ ] Fix handler count (document says 28, actual ~24)

### 5.8 architecture/networking_deep_dive.md
- [ ] Soften zero-copy IO claim or document actual zero-copy paths with file:line references
- [ ] Clarify ACME requires explicit configuration
- [ ] Add ConnectionLimiter config references
- [ ] Add `pqc-mesh` and `verify-pq` feature flags
- [ ] Remove BufferPool duplication (lines 57 and 66)
- [ ] Add QUIC connection migration configuration options
- [ ] Document 0-RTT tradeoffs (replay attacks, connection resumption risks)

### 5.9 architecture/app_handlers.md
- [ ] Update generic WASM handler reference (uses WasmRuntime, not WasmHandler)
- [ ] Add Spin backend documentation
- [ ] Add BackendType details to Application Handlers table

### 5.10 architecture/process_lifecycle.md
- [ ] Document SharedConnectionTable (SHM-based, not shared-nothing)
- [ ] Clarify BlockStore dual ownership (Supervisor vs Master)
- [ ] CPU affinity description - auto-assigned via `core = worker_id % cpu_count`
- [ ] Health check intervals - 5-second interval hardcoded in supervisor main loop
- [ ] Add Mesh Agent modes documentation
- [ ] Document CommandClient fallback chain (gRPC → Unix Socket → Signal)
- [ ] Add upgrade coordination sequence diagram
- [ ] Document drain_state worker states

---

## Wave 6: Low Priority Items

### 6.1 DNS
- [ ] Consider replacing manual DNS wire format with dns-parser or hickory (`src/dns/dnssec.rs:3-13`)

### 6.2 WAF
- [ ] Add streaming WAF multipart boundary crossing edge case tests (`src/waf/attack_detection/streaming.rs:484-509`)

### 6.3 Layer 3.5
- [ ] Consider fixed-size encoding for hybrid signature serialization (`src/mesh/hybrid_signature.rs:66-88`)
- [ ] Consider refactoring validate_peer_role() into state machine/strategy pattern (`src/mesh/peer_auth.rs:248-385`)

### 6.4 Admin
- [ ] Verify and correct handler count in documentation
- [ ] Verify OpenAPI title and version (`src/admin/openapi.rs`)

### 6.5 Mesh
- [ ] Use consistent backtick code formatting for file paths
- [ ] Add DHT GlobalNodeBlocklist clarification
- [ ] Verify YARA rule distribution timing

### 6.6 Process
- [ ] CPU affinity description correction (`src/process/manager.rs:667`)
- [ ] Health check interval documentation (`src/process/manager.rs:1283-1307`)
- [ ] drain_state documentation (`src/worker/drain_state.rs`)

### 6.7 Config
- [ ] DNS Config custom error type (`crates/synvoid-config/src/dns/mod.rs:207-236`)

### 6.8 App Handlers
- [ ] Verify WasmDistManager mechanism (`src/mesh/wasm_dist.rs`)

### 6.9 Routing
- [ ] LocationMatcher trie completion (`src/location_matcher.rs:139-188`)
- [ ] Add IP Hash algorithm description

### 6.10 Plugin
- [ ] Use DashMap instead of Mutex<HashMap> for metrics (`wasm_metrics.rs:7-20`)
- [ ] Use explicit length from guest for streaming body EOF detection (`wasm_runtime.rs:1660-1666`)
- [ ] Cache instantiated SpinAppInstance by component_id (`src/spin/runtime.rs:251`)

### 6.11 Worker
- [ ] Add Zero-copy section with explicit file:line examples
- [ ] Document Static Worker separately (CSS/JS minification, compression)

### 6.12 Platform
- [ ] Update message category count (18→19) and add missing categories
- [ ] Complete startup flow documentation

### 6.13 HTTP/Proxy
- [ ] Update UpstreamPool line reference (363→375)
- [ ] Update WAF integration line reference (362-459→371-481)
- [ ] Document ErasedConnectionPool::checkout() error paths
- [ ] Add architecture diagram for three-layer connection pooling

### 6.14 Networking
- [ ] Add verify-pq flag for mesh connections documentation
- [ ] Health check path appended without validation (`src/upstream/health.rs:193-197`)

### 6.15 Proxy
- [ ] Add visibility into Backend::record_latency millisecond units (`src/upstream/pool.rs:307-317`)

---

## Section 7: Dependencies and Cross-Cutting Concerns

### 7.1 Cross-Cutting Issues

| Issue | Appears In | Priority |
|-------|-----------|----------|
| CPU affinity Linux-only | worker_review, platform_review, networking | Document |
| macos-sandbox feature exists | platform_review, AGENTS.md | Document (feature exists, just needs enabling) |
| ErasedHttpClient not used | http_proxy_review, AGENTS.md Lesson #11 | HIGH |
| gRPC plaintext | worker_review, platform_review | Document |
| Retry config disabled | proxy_review | CRITICAL |
| Session enumeration timing | admin_review, config_admin | MEDIUM |

### 7.2 Item Dependencies

| Item | Depends On | Relationship |
|------|-----------|--------------|
| HTTP/2 Complete Support | ErasedHttpClient Integration | Both relate to `is_http2` in PoolKey |
| DHT-to-Raft Migration | Thorough testing | Could affect mesh networking |
| Spin instance reuse | None | Independent but architectural change |
| DHT prefix propagation | Understanding warmup flow | Requires understanding instance_pool.rs:79-209 |

### 7.3 Architecture Decisions Needed

Consider creating ADRs for:
1. PQC hybrid approach (X25519MLKEM768 vs pure PQC)
2. DHT vs Raft tradeoffs for different record types
3. Regional quorum design decisions
4. ErasedHttpClient integration strategy

---

## Section 8: Verification Commands

```bash
# Verify tests compile
cargo test --lib --no-run

# Run targeted test
cargo test --lib <test_name>

# Integration tests
cargo test --test integration_test
cargo test --test security_regression

# Lint and typecheck
cargo fmt && cargo clippy --lib -- -D warnings

# Profile compilation
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-config --no-default-features
cargo check -p synvoid-config --no-default-features --features mesh,dns
```

---

## Appendix A: Consolidated Lessons Learned (2026-05-23)

These lessons should be incorporated into future agent work:

1. **Process hierarchy is three-tier in traditional mode** - The codebase supports two deployment models:
   - **Consolidated (recommended)**: Supervisor → Workers directly
   - **Traditional (legacy)**: Overseer → Master → Workers

2. **Config field propagation** - When adding new fields to config structs, ensure they propagate through all layers (SiteAppServerConfig → AppServerConfig → GranianConfig).

3. **Dead code detection** - When code blocks are duplicated with no intervening return/break, check if second block is unreachable dead code.

4. **gRPC server has no TLS** - `src/supervisor/api.rs:114-129` uses plaintext gRPC. This is intentional for localhost IPC.

5. **SAFE_HEADERS count is 28** - `src/proxy/cache.rs:97-126` has 28 headers.

6. **Spin routing uses longest-prefix-match** - `src/spin/runtime.rs:271-285` collects all route matches and returns the longest prefix match.

7. **CPU affinity pinning is Linux-only** - Must be explicitly configured via `cpu_affinity` parameter.

8. **macOS Seatbelt sandbox requires feature flag** - Enable the `macos-sandbox` feature for actual enforcement on macOS.

9. **ConfigManager is in synvoid-config crate** - `ConfigManager` is at `crates/synvoid-config/src/lib.rs:113`.

10. **MeshProxy is a key routing component** - `src/mesh/proxy.rs:63` (1994 lines) handles backend routing via mesh.

11. **ErasedHttpClient integration is incomplete** - `use_erased_client` is hardcoded to `false`. Phase 9 integration was never completed.

12. **AXFR transfer incomplete** - `build_axfr_record()` at `src/dns/transfer.rs:829-878` lacks SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA support.

13. **Plan verification is essential** - Always verify items against codebase before marking as needing work.

14. **current_depth() doesn't exist** - `src/location_matcher.rs:191-195` contains `is_empty()` and `len()` methods, not `current_depth()`.

15. **BackendType enum variants** - `src/router.rs:65-77` has 11 variants not all documented.

16. **Spin cold-start overhead** - `src/spin/runtime.rs:251` creates new `SpinAppInstance` per request with no reuse.

17. **UpstreamPool vs FastCgiPool health checks** - Only FastCgiPool has active health check thread. UpstreamPool relies on on-demand reactive checks.

18. **HTTP/2 hardcoded disabled** - `src/http_client/mod.rs:890` has `is_http2 = false`.

19. **Allowed DHT prefixes not propagated** - Both `src/serverless/instance_pool.rs:186` and `src/plugin/instance_pool.rs:186` set `allowed_dht_prefixes: Vec::new()` during warmup.

20. **Retry config edge case** - `src/proxy/mod.rs:293-312` sets `retry_config: None` when `upstream_pool` is `None`.

---

*Last Updated: 2026-05-23*