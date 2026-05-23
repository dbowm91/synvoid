# SynVoid Architecture Review - Implementation Plan

**Generated:** 2026-05-23
**Source Files:** batch1-4 consolidated reviews covering DNS, WAF, Layer 3.5, Admin API, Mesh, Process Lifecycle, Config, App Handlers, Routing, Plugin/WASM, Worker, Proxy, Platform, Networking, HTTP/Proxy, Config/Admin, Core/Overview

---

## Overview

This plan consolidates findings from 4 batches of architecture reviews across 16 modules. It organizes action items by priority and groups related items together for efficient implementation.

### Summary Statistics

| Category | Count | Wave |
|----------|-------|------|
| **Critical Bugs (needs fix)** | 5 | Wave 1 |
| **Critical Bugs (already fixed)** | 2 | Wave 1 |
| **Critical Bugs (needs investigation)** | 1 | Wave 1 |
| **High Priority Items** | 21 | Wave 2 |
| **Medium Priority Items** | 43 | Wave 3 |
| **Implementation Projects** | 9 | Wave 4 |
| **Documentation Fixes** | 10 doc targets | Wave 5 |
| **Low Priority Items** | 50+ | Wave 6 |
| **Total Action Items** | 130+ | |

### Priority Order for Execution

Implementation is organized into **waves** that can execute in parallel where dependencies allow.

---

## Wave 1: Critical Security/Safety Bugs (Parallel Execution)

**These items require immediate attention and can be executed in parallel since they are independent.**

| Item | Description | Location | Status |
|------|-------------|----------|--------|
| 1.1 | Audit Log File Permissions Not Set | `src/admin/audit.rs:76` | Needs Fix |
| 1.2 | StreamingWafCore Trailing Window Logic | `src/waf/attack_detection/streaming.rs:129-134` | Needs Fix |
| 1.3 | verify_hybrid() Accepts Ed25519-Only | `src/mesh/ml_dsa.rs:206-218` | Needs Fix |
| 1.4 | ML-KEM Missing Proof of Possession | `src/mesh/ml_kem_key_exchange.rs:63-164` | Needs Fix |
| 1.5 | gRPC Uptime Hardcoded | `src/supervisor/api.rs:55` | ✅ Already Fixed |
| 1.6 | current_depth() Status Unclear | `src/location_matcher.rs:191-195` | Needs Investigation |
| 1.7 | allowed_dht_prefixes Not Propagated | `instance_pool.rs:186,213-226` | Needs Fix |
| 1.8 | macos-sandbox Feature Missing | `src/platform/sandbox.rs:1036-1133` | Needs Fix |
| 1.9 | Retry Config Not Applied | `src/proxy/mod.rs:293-312` | Needs Fix |
| 1.10 | CSRF Validation | `src/admin/state.rs:736` | ✅ Already Fixed |

### 1.1 [ ] Audit Log File Permissions Not Set (BUG-A1)
- **Location:** `src/admin/audit.rs:76`
- **Issue:** `with_audit_dir()` only sets permissions if file already exists. New files via `log()` don't get 0o600.
- **Fix:** Set permissions when creating file in `log()` method
- **Source:** batch1_admin_review

### 1.2 [ ] StreamingWafCore Trailing Window Logic Incorrect (BUG-W1)
- **Location:** `src/waf/attack_detection/streaming.rs:129-134`
- **Issue:** When updating trailing window for regular chunks, code copies only LAST 512 bytes of CURRENT chunk. For attack detection spanning chunk boundaries, trailing window should contain END of PREVIOUS + beginning of CURRENT.
- **Fix:** Trailing window should be a sliding window accumulating previous trailing window (up to 512 bytes) + as much of current chunk as fits in 512 bytes.
- **Source:** batch1_waf_review

### 1.3 [ ] verify_hybrid() Accepts Ed25519-Only Signatures (BUG-L1)
- **Location:** `src/mesh/ml_dsa.rs:206-218`
- **Impact:** Medium - weakens fail-safe design
- **Issue:** verify_hybrid() accepts Ed25519-only signatures by default
- **Source:** batch1_layer_3_5_review

### 1.4 [ ] ML-KEM Key Encapsulation Missing Proof of Possession (BUG-L3)
- **Location:** `src/mesh/ml_kem_key_exchange.rs:63-164`
- **Impact:** Medium - key encapsulation doesn't verify client proof of possession
- **Source:** batch1_layer_3_5_review

### 1.5 [~] gRPC Uptime_secs Hardcoded to 0 (C1) - ALREADY FIXED
- **Location:** `src/supervisor/api.rs:55`
- **Issue:** Previously hardcoded to 0, now returns `self.state.start_time.elapsed().as_secs()`
- **Status:** ✅ Already fixed in codebase
- **Source:** batch2_process_lifecycle

### 1.6 [~] current_depth() Always Returns 0 (C4) - LOCATION/STATUS UNCLEAR
- **Location:** `src/location_matcher.rs:191-195`
- **Impact:** HIGH - could cause incorrect route matching if trie path is used
- **Issue:** The function `current_depth()` does not appear to exist at this location. The file contains `is_empty()` and `len()` methods but not `current_depth()`.
- **Fix Needed:** Verify if this function exists elsewhere or if this is dead code that should be removed
- **Source:** batch2_routing_review

### 1.7 [ ] allowed_dht_prefixes Not Propagated to Pooled Instances (C5)
- **Location:** `instance_pool.rs:186,213-226` (serverless and plugin)
- **Impact:** CRITICAL - DHT restrictions may not enforce correctly for pooled instances
- **Issue:** `default_allowed_dht_prefixes` is always empty (`Vec::new()` from warmup)
- **Fix:** Set `default_allowed_dht_prefixes` from `WasmResourceLimits` during warmup
- **Implementation Context:** Understanding `instance_pool.rs:79-209` warmup flow is required
- **Source:** batch2_plugin_review

### 1.8 [ ] macos-sandbox Feature Gate Does Not Exist (BUG-PLATFORM-1)
- **Location:** `src/platform/sandbox.rs:1036-1133`, `Cargo.toml`
- **Impact:** CRITICAL - Seatbelt sandbox **cannot be enabled** on macOS
- **Fix:** Add `macos-sandbox = []` to Cargo.toml or remove dead code
- **Source:** batch3_platform_review
- **Also noted:** AGENTS.md Lesson #8

### 1.9 [ ] Retry Config Not Applied from from_config() (BUG-PROXY-1)
- **Location:** `src/proxy/mod.rs:293-312`
- **Impact:** HIGH - Retries **always disabled** regardless of configuration
- **Issue:** `from_config()` doesn't call `with_upstream_pool()` when `upstream_pool` is `None` (lines 252-260), so retry_config remains `None`
- **Fix:** Ensure `with_upstream_pool()` is called even when upstream_pool is None, or set retry_config directly
- **Source:** batch3_proxy_review

### 1.10 [~] CSRF Validation Missing ConstantTimeEq (BUG-1 + BUG-2) - ALREADY FIXED
- **Location:** `src/admin/state.rs:736` (BUG-1), `src/auth/mod.rs:772` (BUG-2)
- **Issue:** Previously used simple `==` comparison; now correctly uses `ct_eq()`
- **Status:** ✅ Already fixed in codebase
- **Source:** batch4_config_admin_review

---

## Wave 2: High Priority Items (Parallel Execution)

**These items can be executed in parallel by different agents.**

| Item | Description | Location | Dependencies |
|------|-------------|----------|--------------|
| 2.1 | DNS - Complete AXFR Record Type Support | `src/dns/transfer.rs:829-878` | None |
| 2.2 | DNS - Verify DNS Cookie Server Integration | `src/dns/cookie.rs` | None |
| 2.3 | WAF - Update JS Challenge Reference | `architecture/waf_deep_dive.md:72` | None |
| 2.4 | WAF - Complete GeoIP Country Blocking | `src/waf/asn_tracker.rs` | None |
| 2.5 | WAF - Add Feature-Gate Comments | `src/waf/attack_detection/mod.rs:77-79` | None |
| 2.6 | Layer 3.5 - Update Raft Documentation | `architecture/layer_3_5_deep_dive.md:32` | None |
| 2.7 | Layer 3.5 - Address Quorum Deadlock | `src/mesh/peer_auth.rs:230-243` | None |
| 2.8 | Mesh - Document 0-RTT Disabled by Default | `architecture/mesh_deep_dive.md:18` | None |
| 2.9 | Mesh - Strengthen Bloom Filter Purpose | `architecture/mesh_deep_dive.md:30` | None |
| 2.10 | Mesh - Document DHT Ingress Verification Gaps | `architecture/mesh_deep_dive.md` | None |
| 2.11 | Config - Fix Sites HashMap Location in Diagram | `architecture/config_deep_dive.md:64-67` | None |
| 2.12 | Config - Add Missing Fields to MainConfig | `architecture/config_deep_dive.md:45-67` | None |
| 2.13 | App Handlers - Integrate or Remove Minification | `src/static_files/mod.rs:131-137` | None |
| 2.14 | App Handlers - Update Generic WASM Handler Reference | `architecture/app_handlers.md:58` | None |
| 2.15 | Routing - Document Missing Backend Types | `src/router.rs:65-77` | None |
| 2.16 | Routing - Add Active Health Checks to UpstreamPool | `src/upstream/pool.rs` | None |
| 2.17 | Plugin - Implement Spin Instance Reuse | `src/spin/runtime.rs:251` | None |
| 2.18 | Worker - Document Linux-Only CPU Affinity | `src/worker/unified_server.rs:205-208` | None |
| 2.19 | Worker - Clarify WAF Challenge Stage | `src/waf/mod.rs:440-515` or docs | None |
| 2.20 | HTTP/Proxy - Verify ErasedHttpClient Integration | `src/http/server.rs:3302` | None |
| 2.21 | HTTP/Proxy - Complete HTTP/2 Support | `src/http_client/mod.rs:890` | None |

### 2.1 DNS - Complete AXFR Record Type Support
- **Location:** `src/dns/transfer.rs:829-878`
- **Issue:** Missing SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA record types
- **Priority:** HIGH
- **Source:** batch1_dns_review

### 2.2 DNS - Verify DNS Cookie Server Integration
- **Location:** `src/dns/cookie.rs`
- **Priority:** HIGH
- **Source:** batch1_dns_review

### 2.3 WAF - Update JS Challenge Reference
- **Location:** `architecture/waf_deep_dive.md:72`
- **Issue:** Document references `src/challenge/js.rs` but actual is `src/challenge/pow.rs`
- **Priority:** HIGH
- **Source:** batch1_waf_review

### 2.4 WAF - Complete GeoIP Country Blocking
- **Location:** `src/waf/asn_tracker.rs`
- **Priority:** HIGH
- **Source:** batch1_waf_review

### 2.5 WAF - Add Feature-Gate Comments for Mesh-Only Features
- **Location:** `src/waf/attack_detection/mod.rs:77-79`
- **Priority:** HIGH
- **Source:** batch1_waf_review

### 2.6 Layer 3.5 - Update Raft Documentation
- **Location:** `architecture/layer_3_5_deep_dive.md:32`
- **Issue:** Document recommends Raft migration but Raft already implemented
- **Priority:** HIGH
- **Source:** batch1_layer_3_5_review

### 2.7 Layer 3.5 - Address Quorum Deadlock
- **Location:** `src/mesh/peer_auth.rs:230-243`
- **Issue:** Requires completing DHT-to-Raft trust chain migration
- **Priority:** HIGH
- **Source:** batch1_layer_3_5_review

### 2.8 Mesh - Document 0-RTT Disabled by Default
- **Location:** `architecture/mesh_deep_dive.md:18`
- **Priority:** HIGH
- **Source:** batch1_mesh_review

### 2.9 Mesh - Strengthen Bloom Filter Purpose Documentation
- **Location:** `architecture/mesh_deep_dive.md:30`
- **Issue:** Clarify "reduces redundant route propagation, not DHT discovery latency"
- **Priority:** HIGH
- **Source:** batch1_mesh_review

### 2.10 Mesh - Document DHT Ingress Verification Gaps
- **Location:** `architecture/mesh_deep_dive.md`
- **Issue:** Multiple message types lack node_id/TLS cert validation
- **Priority:** HIGH
- **Source:** batch1_mesh_review, batch4_mesh_networking

### 2.11 Config - Fix Sites HashMap Location in Diagram
- **Location:** `architecture/config_deep_dive.md:64-67`
- **Issue:** Shows `sites: HashMap<String, SiteConfig>` under MainConfig, but it's in ConfigManager
- **Priority:** HIGH
- **Source:** batch2_config_review

### 2.12 Config - Add Missing Fields to MainConfig Hierarchy
- **Location:** `architecture/config_deep_dive.md:45-67`
- **Issue:** Diagram omits 20+ fields (tokio, ip_feeds, rule_feed, yara_feed, rate_limit_memory, proxy_limits, etc.)
- **Priority:** HIGH
- **Source:** batch2_config_review

### 2.13 App Handlers - Integrate or Remove Minification
- **Location:** `src/static_files/mod.rs:131-137`
- **Issue:** `new_with_minifier()` accepts minifier params but they are UNUSED (prefixed with `_`)
- **Priority:** HIGH
- **Source:** batch2_app_handlers_review

### 2.14 App Handlers - Update Generic WASM Handler Reference
- **Location:** `architecture/app_handlers.md:58`
- **Issue:** Document mentions `WasmHandler` but generic WASM uses `WasmRuntime` directly
- **Priority:** HIGH
- **Source:** batch2_app_handlers_review

### 2.15 Routing - Document Missing Backend Types
- **Location:** `src/router.rs:65-77`
- **Issue:** AxumDynamic, Spin, Cgi, PeakEwma exist but not documented
- **Priority:** HIGH
- **Source:** batch2_routing_review

### 2.16 Routing - Add Active Health Checks to UpstreamPool
- **Location:** `src/upstream/pool.rs`
- **Issue:** Only FastCgiPool has active health check thread (via `start_health_check()`); UpstreamPool relies only on on-demand/reactive health checks via `HealthChecker::check()` called manually by admin API
- **Priority:** HIGH
- **Source:** batch2_routing_review

### 2.17 Plugin - Implement Spin Instance Reuse
- **Location:** `src/spin/runtime.rs:251`
- **Issue:** Each request creates new `SpinAppInstance` - high cold-start overhead
- **Priority:** HIGH
- **Source:** batch2_plugin_review

### 2.18 Worker - Document Linux-Only CPU Affinity
- **Location:** `src/worker/unified_server.rs:205-208`
- **Issue:** CPU affinity only works on Linux; logs warning on non-Linux
- **Priority:** HIGH
- **Source:** batch3_worker_review

### 2.19 Worker - Clarify WAF Challenge Stage
- **Location:** `src/waf/mod.rs:440-515` or architecture docs
- **Issue:** Document lists 7 stages including "Challenge" but code integrates via threat level escalation
- **Priority:** HIGH
- **Source:** batch3_worker_review

### 2.20 HTTP/Proxy - Verify ErasedHttpClient Integration
- **Location:** `src/http/server.rs:3302`
- **Issue:** `use_erased_client` hardcoded to `false` - ErasedHttpClient never actually used
- **Priority:** HIGH
- **Source:** batch3_http_proxy_review, AGENTS.md Lesson #11

### 2.21 HTTP/Proxy - Complete HTTP/2 Support
- **Location:** `src/http_client/mod.rs:890`
- **Issue:** `is_http2` hardcoded to `false`; HTTP/2 never used despite infrastructure
- **Priority:** HIGH
- **Source:** batch3_http_proxy_review

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

### 3.6 DNS - Add GOST Algorithm Support
- **Location:** `src/dns/dnssec_validation.rs:260`
- **Issue:** GOST type 3 DS digest not supported
- **Source:** batch1_dns_review

### 3.7 Admin - Add Timing Normalization to Auth Handler
- **Location:** `src/admin/handlers/auth.rs:17-28`
- **Issue:** Session enumeration timing leak
- **Source:** batch1_admin_review, batch4_config_admin

### 3.8 Admin - Clarify Rate Limiter Distinction
- **Location:** `src/admin/auth.rs:139`, `src/admin/middleware.rs:124-128`
- **Issue:** Global vs per-instance rate_limiter distinction unclear
- **Source:** batch1_admin_review

### 3.9 Mesh - Update Topology-Aware Router Description
- **Location:** `architecture/mesh_deep_dive.md:44`
- **Issue:** Update to "weighted scoring based on latency, reputation, and node role"
- **Source:** batch1_mesh_review

### 3.10 Mesh - Soften Threat Propagation Timing
- **Location:** `architecture/mesh_deep_dive.md:49`
- **Issue:** Change to "Distributed via DHT propagation and Raft consensus"
- **Source:** batch1_mesh_review

### 3.11 Mesh - Clarify Raft Consensus Scope
- **Location:** `architecture/mesh_deep_dive.md:9`
- **Issue:** Clarify "OrgPublicKey and ThreatIntel records; DHT for routing and other state"
- **Source:** batch1_mesh_review

### 3.12 Layer 3.5 - Implement ML-KEM Key Rotation
- **Location:** `src/mesh/ml_kem_key_exchange.rs:41-58`, `src/mesh/transport.rs:1989-2001`
- **Source:** batch1_layer_3_5_review

### 3.13 Layer 3.5 - Consider Raft-Based Revocation Replication
- **Location:** `src/mesh/peer_auth.rs:21-117`
- **Issue:** Instead of DHT distribution
- **Source:** batch1_layer_3_5_review

### 3.14 Layer 3.5 - DhtAccessControl::require_global_node() Dead Code
- **Location:** `src/mesh/dht/mod.rs:755`
- **Issue:** Never called - add to verification path or remove
- **Source:** batch1_layer_3_5_review

### 3.15 WAF - Document check_body_fragments() Zero-Copy
- **Location:** `src/waf/attack_detection/streaming.rs:118`
- **Source:** batch1_waf_review

### 3.16 WAF - Move FloodConfig Hardcoded Defaults
- **Location:** `src/waf/flood/mod.rs:40-56`
- **Source:** batch1_waf_review

### 3.17 WAF - Update Burst Tokens Documentation
- **Location:** `src/waf/traffic_shaper/limiter.rs:96`
- **Issue:** Document says "default 10" but it's configurable
- **Source:** batch1_waf_review

### 3.18 Config - ConfigManager Site Lookup Exact Match
- **Location:** `crates/synvoid-config/src/lib.rs:195-197`
- **Issue:** May not work for alias domains
- **Source:** batch2_config_review

### 3.19 Config - reload_site() Filename Storage
- **Location:** `crates/synvoid-config/src/lib.rs:199-220`
- **Issue:** Relies on `domains.first()` for filename; fails if filename ≠ primary domain
- **Source:** batch2_config_review

### 3.20 App Handlers - Verify Spin Registration Mechanism
- **Location:** Admin API
- **Source:** batch2_app_handlers_review

### 3.21 App Handlers - Verify FastCGI Streaming
- **Location:** `src/fastcgi/mod.rs`
- **Source:** batch2_app_handlers_review

### 3.22 Routing - Update Connection Lifecycle Documentation
- **Location:** `src/router.rs:1124-1219`
- **Issue:** "Protocol Negotiation" step doesn't match - no explicit lease
- **Source:** batch2_routing_review

### 3.23 Routing - Verify Weighted Round Robin Configurable
- **Location:** `src/upstream/pool.rs:566-583`
- **Source:** batch2_routing_review

### 3.24 Plugin - Serverless Engine Sharing
- **Location:** `instance_pool.rs:165`
- **Issue:** Creates fresh `Engine` per function pool; should share across serverless functions
- **Source:** batch2_plugin_review

### 3.25 Plugin - DHT Prefix Hardcoded List
- **Location:** `wasm_runtime.rs:840-848`
- **Issue:** Sensitive prefixes hardcoded; make configurable
- **Source:** batch2_plugin_review

### 3.26 Worker - Add BufferPool Documentation
- **Source:** batch3_worker_review

### 3.27 Worker - Clarify Process Hierarchy
- **Location:** `architecture/platform_deep_dive.md`
- **Source:** batch3_worker_review

### 3.28 Platform - Clarify SO_REUSEPORT Usage
- **Location:** architecture docs
- **Issue:** Only used during upgrades, not initial workers
- **Source:** batch3_platform_review

### 3.29 Proxy - Add Health Check TCP Mode
- **Location:** `src/upstream/health.rs:224-231`
- **Issue:** Use `UpstreamAddress::parse()`
- **Source:** batch3_proxy_review

### 3.30 Proxy - Add Connection Health Check Before Checkin
- **Location:** `src/http_client/erased_pool.rs:419`
- **Source:** batch3_proxy_review

### 3.31 Proxy - Fix TypedConnectionPool https_or_http() Inconsistency
- **Location:** `src/http_client/typed_pool.rs:128`
- **Source:** batch3_proxy_review

### 3.32 HTTP/Proxy - Document Layer 3.5 Half-TCP
- **Location:** `src/upstream/pool.rs:67`, `src/upstream/address.rs`
- **Source:** batch3_http_proxy_review

### 3.33 HTTP/Proxy - Add Integration Test for Connection Pool Checkout
- **Location:** `src/http_client/erased_pool.rs:245-283`
- **Source:** batch3_http_proxy_review

### 3.34 Networking - Document ACME Configuration Requirements
- **Issue:** DNS-01 vs HTTP-01, cache_dir requirements
- **Source:** batch3_networking_review

### 3.35 Networking - Clarify PQC Feature Flag Interactions
- **Issue:** `post-quantum` vs `pqc-mesh` vs `verify-pq`
- **Source:** batch3_networking_review

### 3.36 Networking - Add Amplification Protection Configuration
- **Source:** batch3_networking_review

### 3.37 Core/Overview - Add MeshProxy to Module Index
- **Location:** `architecture/overview.md:219-233`
- **Issue:** Key component (1964 lines) not mentioned
- **Source:** batch4_core_overview

### 3.38 Core/Overview - Improve Spin Handler Documentation
- **Source:** batch4_core_overview

### 3.39 Config/Admin - Clarify Admin Auth vs User Auth Distinction
- **Location:** `architecture/admin_deep_dive.md`
- **Source:** batch4_config_admin

### 3.40 Config/Admin - Add AUTH_WINDOW_DURATION Constant
- **Location:** `architecture/admin_deep_dive.md`
- **Source:** batch4_config_admin

### 3.41 Mesh/Networking - Clarify Bloom Filter Usage
- **Location:** `architecture/mesh_deep_dive.md:30`
- **Issue:** Route announcements, not DHT discovery
- **Source:** batch4_mesh_networking

### 3.42 Mesh/Networking - Document DHT Ingress Verification Gaps
- **Location:** `architecture/mesh_deep_dive.md`
- **Issue:** node_id not validated against peer_id/TLS cert
- **Source:** batch4_mesh_networking

### 3.43 Mesh/Networking - Soften Zero-Copy IO Claim
- **Location:** `architecture/networking_deep_dive.md:54-55`
- **Issue:** Zero-copy is aspirational, not implementation fact
- **Source:** batch4_mesh_networking

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

### 4.3 CORS Middleware (Admin)
- **Location:** `src/admin/middleware.rs`
- **Dependencies:** None
- **Estimated Effort:** Low
- **Issue:** Claimed but not implemented
- **Source:** batch1_admin_review

### 4.4 DHT-to-Raft Migration (Layer 3.5)
- **Location:** `src/mesh/peer_auth.rs:230-243`
- **Dependencies:** Requires thorough testing, could affect mesh networking
- **Estimated Effort:** High
- **Source:** batch1_layer_3_5_review

### 4.5 GeoIP Blocking (WAF)
- **Location:** `src/waf/asn_tracker.rs`
- **Dependencies:** May need GeoIP database integration
- **Estimated Effort:** Medium
- **Source:** batch1_waf_review

### 4.6 ErasedHttpClient Integration (HTTP/Proxy)
- **Location:** `src/http/server.rs:3302`
- **Dependencies:** None
- **Estimated Effort:** Medium
- **Note:** Phase 9 integration was never completed per AGENTS.md Lesson #11
- **Source:** batch3_http_proxy_review

### 4.7 HTTP/2 Complete Support (HTTP/Proxy)
- **Location:** `src/http_client/mod.rs:890`
- **Dependencies:** Item 4.6 (ErasedHttpClient integration)
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
- [ ] Update 0-RTT disabled by default (was incorrectly implied as enabled)
- [ ] Update Raft already implemented (was marked as migration needed)
- [ ] Strengthen Bloom filter purpose - route propagation, not DHT discovery
- [ ] Document DHT ingress verification gaps as known limitations
- [ ] Update topology-aware router description
- [ ] Soften threat propagation timing claims
- [ ] Clarify Raft consensus scope
- [ ] Fix Ed25519/X25519 confusion
- [ ] Clarify "Kademlia-inspired with geo-distance enhancements"
- [ ] Add PQC feature flag cross-reference

### 5.2 architecture/waf_deep_dive.md
- [ ] Update JS Challenge location: `src/challenge/pow.rs` (not `js.rs`)
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
- [ ] Fix sites HashMap location (in ConfigManager, not MainConfig)
- [ ] Add missing fields: tokio, ip_feeds, rule_feed, yara_feed, rate_limit_memory, proxy_limits, etc.
- [ ] Fix Utils crate path: `crates/synvoid-utils/` → `crates/synvoid-utils/` (verify correct path)
- [ ] Clarify ConfigManager location in lib.rs
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
  - `src/mesh/proxy.rs` — MeshProxy (key component, 1964 lines)
  - `src/plugin/` — Plugin system
  - `src/sandbox/` — Process sandboxing
- [ ] Add MeshProxy to mesh networking table
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
| macos-sandbox feature missing | platform_review, AGENTS.md | CRITICAL |
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

## Appendix A: Source File Reference

| Batch | Source Files |
|-------|-------------|
| batch1 | dns_review_plan.md, waf_review_plan.md, layer_3_5_review_plan.md, admin_review_plan.md, mesh_review_plan.md |
| batch2 | process_lifecycle_review_plan.md, config_review_plan.md, app_handlers_review_plan.md, routing_review_plan.md, plugin_review_plan.md |
| batch3 | worker_review_plan.md, proxy_review_plan.md, platform_review_plan.md, networking_review_plan.md, http_proxy_review_plan.md |
| batch4 | config_admin_review_plan.md, core_overview_review_plan.md, mesh_networking_review_plan.md |

---

*Last Updated: 2026-05-23*
