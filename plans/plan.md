# SynVoid Consolidated Implementation Plan

**Generated:** 2026-05-23
**Status:** COMPLETED (2026-05-23)
**Sources:** All architecture review plans in `plans/` directory
**Consolidated by:** AI agents from batch review of 8 plan files

---

## Overview

This plan consolidates action items from architecture review plans across 8 modules:
- Config/Admin/Auth
- DNS
- WAF
- Plugin/WASM/Spin
- Platform
- Core/Overview
- HTTP/Proxy
- Mesh/Networking

**Items marked as ⚡ can execute in parallel within their wave.**

---

## Deferred Items (Architectural/Large Effort)

These items require significant architectural changes and are deferred until resources permit.

| ID | Issue | Reason | Status |
|----|-------|--------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | DHT ingress validation gaps require fundamental changes to bind node_id to TLS/cert identity | Deferred - Architectural |
| MESH-15 | Quorum Deadlock Risk During Partition | Raft implementation incomplete per TODO at `instance.rs:214`. Requires Raft migration. | Deferred - Requires Raft |
| MESH-17 | Session Establishment Failure Silently Ignored | Intentional - offer doesn't depend on session state for bidirectional communication | Working As Designed |
| APP-15 | FastCGI Response NOT Truly Streamed | Known limitation - buffers entire stdout. True streaming requires architectural refactor. | Deferred - Architectural |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC between Supervisor and Master processes | Working As Designed |
| DOC-MESH-1 | DHT Ingress Verification Gaps Not Documented | Requires documenting full identity/trust model - larger architectural task | Deferred |

---

## Wave 1: HIGH Priority ⚡

Items with no dependencies that can execute in parallel.

### NEW-1 | Config/Admin | Document Auth Manager vs Admin Auth distinction
- **Location:** `architecture/admin_deep_dive.md`
- **Description:** Admin auth (single token) vs User auth (multi-user with registration) are conflated
- **Priority:** HIGH
- **Dependencies:** None
- **Actionable Steps:**
  1. Add section clarifying Admin Auth vs User Auth distinction
  2. Explain single token vs multi-user registration flow
  3. Reference: `src/auth/mod.rs` and `src/admin/`

### NEW-2 | Platform | Fix Process Hierarchy Diagram Inconsistency
- **Location:** `architecture/platform_deep_dive.md:246-269`
- **Description:** Diagram shows `Supervisor → Master → Workers` but consolidated mode is `Supervisor → Workers` directly
- **Priority:** HIGH
- **Dependencies:** None
- **Actionable Steps:**
  1. Split diagram to show both Consolidated and Traditional modes
  2. Add legend explaining when each mode is used

### NEW-3 | Platform | Document Master "MUST NOT run UnifiedServer" Constraint
- **Location:** `architecture/platform_deep_dive.md:223`
- **Description:** Missing critical architectural requirement that Master MUST NOT handle requests
- **Priority:** HIGH
- **Dependencies:** None
- **Actionable Steps:**
  1. Add prominent note about Master only handling Admin API, threat intel, worker orchestration, IPC
  2. Reference: `src/startup/master.rs:279-302` (has full documentation block)

### NEW-4 | Platform | Document Critical Security Constraint
- **Location:** `architecture/platform_deep_dive.md` (new section)
- **Description:** No documentation of security separation between Master/Supervisor and Workers
- **Priority:** HIGH
- **Dependencies:** None
- **Actionable Steps:**
  1. Add section documenting that Master/Supervisor MUST NOT accept external traffic
  2. Explain security model: least privilege, crash isolation, process isolation

### NEW-5 | Core | Add Missing Modules to Index
- **Location:** `architecture/overview.md:332-383`
- **Description:** Missing modules: `src/icmp_filter/`, `src/serverless/`, `src/spin/`, `src/wasm_pow/`, `src/tarpit/`, `src/honeypot_port/`, `src/plugin/`, `src/sandbox/`
- **Priority:** HIGH
- **Dependencies:** None
- **Actionable Steps:**
  1. Add all missing modules to architecture index
  2. Include brief description and purpose for each

### NEW-6 | HTTP/Proxy | Verify ErasedHttpClient Integration with BodyBufferingPolicy::Streaming
- **Location:** `src/http/server.rs`
- **Description:** Phase 9 integration may be incomplete - verify streaming policy uses ErasedHttpClient
- **Priority:** HIGH
- **Dependencies:** None
- **Actionable Steps:**
  1. Verify `BodyBufferingPolicy::Streaming` wires to `ErasedHttpClient`
  2. Reference: `src/http_client/AGENTS.override.md:83-87`

### NEW-7 | Mesh/Network | Clarify Zero-Copy IO Claim
- **Location:** `architecture/networking_deep_dive.md:54-55`
- **Description:** Claims "zero-copy" but is aspirational - most handlers still copy data
- **Priority:** HIGH
- **Dependencies:** None
- **Actionable Steps:**
  1. Either (a) document actual zero-copy paths with examples, OR (b) soften to "ownership-based buffer reuse"
  2. Reference: `crates/synvoid-utils/src/buffer/pool.rs`

### NEW-8 | Mesh/Network | Clarify Bloom Filter Routing Description
- **Location:** `architecture/mesh_deep_dive.md:30`
- **Description:** Claims Bloom filters minimize "discovery latency" but they check route announcements, not DHT discovery
- **Priority:** HIGH
- **Dependencies:** None
- **Actionable Steps:**
  1. Clarify Bloom filters are for upstream route announcement checking, not regional discovery optimization
  2. Reference: `src/mesh/hierarchical_routing.rs:66` (MeshBloomFilter)

### NEW-9 | WAF | Add Streaming WAF documentation
- **Location:** `architecture/waf_deep_dive.md`
- **Description:** `streaming.rs` handles chunked processing, multipart, trailing window but not documented
- **Priority:** HIGH
- **Dependencies:** None
- **Actionable Steps:**
  1. Add Streaming WAF documentation section
  2. Document chunked processing, multipart handling, trailing window

### NEW-10 | Plugin | Update Spin routing status in documentation
- **Location:** `architecture/plugin_deep_dive.md:102`
- **Description:** Document says "NOT implemented" but longest-prefix-match IS implemented at `spin/runtime.rs:271-285`
- **Priority:** HIGH
- **Dependencies:** None
- **Actionable Steps:**
  1. Update line 102 to reflect Spin routing IS implemented with longest-prefix matching

---

## Wave 2: MEDIUM Priority ⚡

### NEW-11 | DNS | Add missing record types to AXFR transfer
- **Location:** `src/dns/transfer.rs:829-878`
- **Description:** `build_axfr_record()` lacks SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA support
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add support for common record types in `build_axfr_record()` (SRV, DNSKEY, RRSIG, NSEC, NSEC3, DS)
  2. Reference: RFC for each record type

### NEW-12 | DNS | Verify QueryCoalescer integration
- **Location:** `architecture/dns_deep_dive.md`
- **Description:** Document claims QueryCoalescer collapses identical queries but struct usage unconfirmed
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Verify and document QueryCoalescer integration status
  2. Find actual implementation or update documentation

### NEW-13 | WAF | Add rate limiting/flood protection description
- **Location:** `architecture/waf_deep_dive.md`
- **Description:** Document sparse on TokenBucket, ConnectionLimiter, SYN flood protection details
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Document rate limiting architecture (SYN flood, per-IP, TokenBucket)
  2. Reference: `src/waf/flood/mod.rs`, `src/waf/traffic_shaper/`

### NEW-14 | WAF | Clarify bot detection CSS honeypot
- **Location:** `architecture/waf_deep_dive.md`
- **Description:** Document mentions honeypots but not CSS challenge implementation
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Document bot detection including CSS honeypot and JS challenge
  2. Reference: `src/waf/detector/` modules

### NEW-15 | Plugin | Clarify warmup() stub vs real implementation
- **Location:** `architecture/plugin_deep_dive.md:70`
- **Description:** Warm instances use stub functions, real linking on first request. Documentation needs clarification.
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add clarification about stub implementations in warmup
  2. Update body_receiver in reset list

### NEW-16 | Platform | Fix CPU Affinity Documentation
- **Location:** `architecture/process_lifecycle.md:47`
- **Description:** Claims "automatic" CPU pinning on Linux, but requires explicit `cpu_affinity` parameter
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Update to clarify `cpu_affinity` must be explicitly configured
  2. Reference: `src/startup/worker.rs:32`

### NEW-17 | Platform | Fix gRPC Default Port Claim
- **Location:** `architecture/platform_deep_dive.md:167`
- **Description:** Claims default port 50051, but actually configurable via `control_api_addr`
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Document configurable port with default 127.0.0.1:50051
  2. Reference: `src/supervisor/process.rs:115-123`

### NEW-18 | Platform | Clarify SO_REUSEPORT Usage
- **Locations:** `architecture/process_lifecycle.md:68`, `architecture/platform_deep_dive.md:242`
- **Description:** Implies automatic for workers, but only used during upgrades
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Document that SO_REUSEPORT is for upgrade mode, not initial spawn
  2. Reference: `src/startup/worker.rs:42` (`reuse_port: false` for initial workers)

### NEW-19 | Platform | Document Two Deployment Modes
- **Location:** `architecture/platform_deep_dive.md` (new section)
- **Description:** No explicit documentation of Consolidated vs Traditional deployment models
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add Deployment Models section explaining both modes
  2. Define when to use each mode

### NEW-20 | Core | Document MeshProxy Role
- **Location:** `architecture/overview.md:219-233`
- **Description:** MeshProxy not mentioned as key component for backend routing via mesh
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add MeshProxy entry to mesh networking table
  2. Reference: `src/mesh/proxy.rs:63` (MeshProxy is 1996 lines)

### NEW-21 | Core | Make Spin Manual Registration More Prominent
- **Location:** `architecture/overview.md:205`
- **Description:** Spin requires manual app registration but not highlighted
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add prominent note about manual Spin app registration
  2. Reference: `src/http/server.rs:2417-2489`

### NEW-22 | HTTP/Proxy | Document Layer 3.5 Half-TCP Implementation
- **Location:** `architecture/layer_3_5_deep_dive.md`
- **Description:** Document focuses on PQC/mesh but doesn't document half-TCP proxy
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add documentation for half-TCP implementation if it exists
  2. Reference: `src/upstream/pool.rs:67` - `BackendProtocol::Tcp`

### NEW-23 | HTTP/Proxy | Add Integration Test for Connection Pool Checkout
- **Location:** `src/http_client/erased_pool.rs:245-283`
- **Description:** Complex error handling in `checkout()` needs explicit testing
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add integration test covering: connection timeout, pool extraction, connection reuse, new connection establishment

### NEW-24 | HTTP/Proxy | Clarify Spin vs WASM Backend Distinction
- **Location:** `architecture/app_handlers.md:40-45` vs `architecture/routing_deep_dive.md:24`
- **Description:** Documents mention both but don't clearly distinguish
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add section clarifying Spin uses WASM internally, has own routing/manifest system
  2. Distinguish from generic WASM edge functions

### NEW-25 | Mesh/Network | Add Security Implementation References
- **Location:** `architecture/mesh_deep_dive.md` and `architecture/networking_deep_dive.md`
- **Description:** Security properties described but no code references
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add inline code references for security-critical claims
  2. Link "Peer Authentication" → `src/mesh/peer_auth.rs`
  3. Link "Access Control" → `src/mesh/dht/capability_access.rs`

### NEW-26 | Mesh/Network | Complete PQC Feature Flag Documentation
- **Location:** `architecture/networking_deep_dive.md:38`
- **Description:** Only mentions `post-quantum`, missing `pqc-mesh` and `verify-pq` flags
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add all PQC-related feature flags: `pqc-mesh`, `verify-pq`, `post-quantum`

### NEW-27 | WAF | Document Zero-Copy Inspection details
- **Location:** `architecture/waf_deep_dive.md`
- **Description:** `BufferPool` and `PooledBuf` for zero-copy but no implementation details
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add implementation details for zero-copy inspection

### NEW-28 | WAF | Add Parallel Processing documentation
- **Location:** `architecture/waf_deep_dive.md`
- **Description:** Async WAF pipeline at `mod.rs:484-512` but no details
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Document parallel processing and async WAF pipeline

### NEW-29 | WAF | Add eBPF availability note
- **Location:** `architecture/waf_deep_dive.md`
- **Description:** Linux-only feature at `flood/mod.rs:5-6` but not documented
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add eBPF Linux-only note to documentation

### NEW-30 | Config/Admin | Fix SiteConfig hierarchy missing site_id field
- **Location:** `architecture/config_deep_dive.md:68-93`
- **Description:** SiteConfig has `site_id` used as key in ConfigManager but document omits it
- **Priority:** MEDIUM
- **Dependencies:** None
- **Actionable Steps:**
  1. Add `site_id` field to SiteConfig hierarchy documentation
  2. Reference: `crates/synvoid-config/src/lib.rs:113` (ConfigManager)

---

## Wave 3: LOW Priority ⚡

### NEW-31 | Config/Admin | Add config propagation validation check
- **Location:** `architecture/config_deep_dive.md`
- **Description:** Document missing pattern for verifying new SiteAppServerConfig fields propagate to AppServerConfig
- **Priority:** LOW
- **Dependencies:** None

### NEW-32 | Config/Admin | Fix ConfigManager file location
- **Location:** `architecture/config_deep_dive.md:31`
- **Description:** Document implies ConfigManager might be in main_config.rs but it's in `lib.rs:113-233`
- **Priority:** LOW
- **Dependencies:** None

### NEW-33 | Config/Admin | Document feature-gated handlers
- **Location:** `architecture/overview.md`
- **Description:** 4 handlers are mesh-gated but counted in total; add footnote explaining feature-gated modules
- **Priority:** LOW
- **Dependencies:** None

### NEW-34 | Config/Admin | Verify rate limiter location
- **Location:** `architecture/admin_deep_dive.md`
- **Description:** Claim `src/admin/rate_limit.rs` exists but needs confirmation
- **Priority:** LOW
- **Dependencies:** None

### NEW-35 | Config/Admin | Document ConfigManager discover_sites() return type
- **Location:** `architecture/config_deep_dive.md`
- **Description:** Signature returns `Vec<(String, Result<SiteConfig, String>)>` not void as documented
- **Priority:** LOW
- **Dependencies:** None

### NEW-36 | DNS | Fix TSIG Verification Rust version requirement
- **Location:** `src/dns/tsig.rs:162`
- **Description:** Uses `abs_diff` - requires Rust 1.78+ but mitigated by modern Rust edition
- **Priority:** LOW
- **Dependencies:** None

### NEW-37 | DNS | Add DS Digest Type 3 (GOST) support
- **Location:** `src/dns/dnssec_validation.rs:260`
- **Description:** RFC 4357 defined but not implemented
- **Priority:** LOW
- **Dependencies:** None

### NEW-38 | DNS | Document recursive resolver implementation
- **Location:** `architecture/dns_deep_dive.md`
- **Description:** Uses `hickory_resolver::TokioResolver` not "hickory-resolver"
- **Priority:** LOW
- **Dependencies:** None

### NEW-39 | DNS | List supported DNSSEC algorithms explicitly
- **Location:** `architecture/dns_deep_dive.md`
- **Description:** Only Ed25519 (15) and RSA/SHA-256 (8) currently
- **Priority:** LOW
- **Dependencies:** None

### NEW-40 | DNS | Clarify Cookie module purpose
- **Location:** `architecture/dns_deep_dive.md`
- **Description:** RFC 8905 implementation needs brief description
- **Priority:** LOW
- **Dependencies:** None

### NEW-41 | DNS | Add missing files to Key Files table
- **Location:** `architecture/dns_deep_dive.md`
- **Description:** Missing: qname.rs, zone_manager.rs, zone_file.rs, rpz.rs, edns.rs, limits.rs
- **Priority:** LOW
- **Dependencies:** None

### NEW-42 | DNS | Verify QUIC tunnel max datagram size
- **Location:** `architecture/networking_deep_dive.md`
- **Description:** Verify QUIC tunnel max datagram size (1200 bytes)
- **Priority:** LOW
- **Dependencies:** None

### NEW-43 | DNS | Document NSEC3 algorithm numbers
- **Location:** `architecture/dns_deep_dive.md`
- **Description:** Algorithm 1 (SHA-1) and 2 (SHA-256) implemented but missing from docs
- **Priority:** LOW
- **Dependencies:** None

### NEW-44 | WAF | Clarify ASN & GeoIP blocking
- **Location:** `architecture/waf_deep_dive.md`
- **Description:** `asn_tracker.rs` exists but no GeoIP blocking in WAF
- **Priority:** LOW
- **Dependencies:** None

### NEW-45 | WAF | Verify Distributed Intelligence in Mesh
- **Location:** `src/mesh/threat_intel.rs`, `src/waf/ip_feed.rs`
- **Description:** Claim needs verification
- **Priority:** LOW
- **Dependencies:** None

### NEW-46 | WAF | Verify Anomaly Scoring
- **Location:** `src/waf/threat_level/`
- **Description:** Claim needs verification
- **Priority:** LOW
- **Dependencies:** None

### NEW-47 | WAF | Clarify Aho-Corasick usage
- **Location:** `architecture/waf_deep_dive.md`
- **Description:** Trait exists at `detector_common.rs:264` but no detector uses it
- **Priority:** LOW
- **Dependencies:** None

### NEW-48 | Plugin | Add architecture diagram for plugin system
- **Location:** `architecture/plugin_deep_dive.md`
- **Description:** Missing diagram showing PluginManager → WasmPluginManager → WasmRuntime → WasmInstancePool
- **Priority:** LOW
- **Dependencies:** None

### NEW-49 | Plugin | Add security model section for DHT prefix restrictions
- **Location:** `architecture/plugin_deep_dive.md`
- **Description:** Missing security model section for DHT prefix restrictions
- **Priority:** LOW
- **Dependencies:** None

### NEW-50 | Plugin | Update feature comparison table for Spin mesh integration
- **Location:** `architecture/plugin_deep_dive.md`
- **Description:** Table shows "No" for Spin mesh integration - should be "Limited (via WASM host functions)"
- **Priority:** LOW
- **Dependencies:** None

### NEW-51 | Plugin | Update line references in documentation
- **Location:** `architecture/plugin_deep_dive.md`
- **Description:** WASM plugin execution line reference inaccurate - should be `server.rs:3043-3060` not `3043-3086`
- **Priority:** LOW
- **Dependencies:** None

### NEW-52 | Platform | Update Message Category Count
- **Location:** `architecture/platform_deep_dive.md:91`
- **Description:** Claims "15 categories" but actual is ~17 (App Server, Worker Restart, Mesh Control missing)
- **Priority:** LOW
- **Dependencies:** None

### NEW-53 | Platform | Document Missing Startup Flow Steps
- **Location:** `architecture/platform_deep_dive.md:203-220`
- **Description:** Missing Blocklist persistence loop, post-quantum TLS init, MIME type loading
- **Priority:** LOW
- **Dependencies:** None

### NEW-54 | Platform | Clarify IPC Rate Limiting Per-Connection
- **Location:** `architecture/platform_deep_dive.md:82-83`
- **Description:** Implies per-worker isolation but is actually per-connection
- **Priority:** LOW
- **Dependencies:** None

### NEW-55 | Platform | Fix macOS Seatbelt Sandbox Feature Gate
- **Location:** `architecture/platform_deep_dive.md:62`
- **Description:** `macos-sandbox` feature referenced but not implemented in codebase
- **Priority:** LOW
- **Dependencies:** None

### NEW-56 | Platform | Fix Admin Server Process Placement Diagram
- **Location:** `architecture/platform_deep_dive.md:249-251`
- **Description:** Diagram shows Admin Server in Master for consolidated mode (actually in Supervisor)
- **Priority:** LOW
- **Dependencies:** NEW-2 (depends on process hierarchy fix first)

### NEW-57 | Core | Clarify gRPC Binding Security Implication
- **Location:** `architecture/overview.md:393`
- **Description:** Claims localhost binding as security feature but no code enforcement
- **Priority:** LOW
- **Dependencies:** None

### NEW-58 | Core | Update Router Module Description
- **Location:** `architecture/overview.md:104`
- **Description:** `src/router.rs` (1377 lines) described as simple domain routing but contains MatchRouter, BackendType, Target
- **Priority:** LOW
- **Dependencies:** None

### NEW-59 | Core | Verify Process Table Flags
- **Location:** `architecture/overview.md:54-61`
- **Description:** Claims `--mesh-agent` flag but actual flags don't include it
- **Priority:** LOW
- **Dependencies:** None

### NEW-60 | Core | Add Cross-Reference to Routing Deep Dive
- **Location:** `architecture/overview.md:198-208`
- **Description:** BackendType integration details missing
- **Priority:** LOW
- **Dependencies:** None

### NEW-61 | HTTP/Proxy | Update UpstreamPool Line Reference
- **Location:** `architecture/proxy_deep_dive.md:115`
- **Description:** References pool.rs:363-368 but actual is at lines 375-380
- **Priority:** LOW
- **Dependencies:** None

### NEW-62 | HTTP/Proxy | Update WAF Integration Line Reference
- **Location:** `architecture/proxy_deep_dive.md:59`
- **Description:** Claims WAF integration at 362-459 but actual is 371-481
- **Priority:** LOW
- **Dependencies:** None

### NEW-63 | HTTP/Proxy | Document ErasedConnectionPool::checkout() Error Paths
- **Location:** `src/http_client/erased_pool.rs:245-282`
- **Description:** Missing code comments documenting error handling
- **Priority:** LOW
- **Dependencies:** None

### NEW-64 | HTTP/Proxy | Add Architecture Diagram for Three-Layer Connection Pooling
- **Location:** `architecture/proxy_deep_dive.md`
- **Description:** Layers: Global cache → Erased pool → Typed pool. No visual diagram.
- **Priority:** LOW
- **Dependencies:** None

### NEW-65 | Mesh/Network | Fix audit.rs Path Reference
- **Location:** `architecture/mesh_deep_dive.md:57`
- **Description:** Path shown without `src/` prefix
- **Priority:** LOW
- **Dependencies:** None

### NEW-66 | Mesh/Network | Clarify ACME Requires Explicit Configuration
- **Location:** `architecture/networking_deep_dive.md:31`
- **Description:** Implies automatic Let's Encrypt enrollment
- **Priority:** LOW
- **Dependencies:** None

### NEW-67 | Mesh/Network | Clarify PQC Key Exchange vs Signatures
- **Location:** `architecture/networking_deep_dive.md:37`, `architecture/mesh_deep_dive.md:25`
- **Description:** Ed25519 mentioned with X25519 for key exchange - Ed25519 is for signatures
- **Priority:** LOW
- **Dependencies:** None

### NEW-68 | Mesh/Network | Document Kademlia Customizations
- **Location:** `architecture/mesh_deep_dive.md:28`
- **Description:** DHT described as pure Kademlia but has geo-distance regional routing, KBucket routing
- **Priority:** LOW
- **Dependencies:** None

### NEW-69 | Mesh/Network | Document ConnectionLimiter Implementation
- **Location:** `architecture/networking_deep_dive.md:58-61`
- **Description:** Implies single limiter but per-site/IP via separate `SiteConnectionLimiter`
- **Priority:** LOW
- **Dependencies:** None

---

## Summary

| Wave | Count | Focus |
|------|-------|-------|
| Wave 1 (HIGH) | 10 | Security, critical documentation |
| Wave 2 (MEDIUM) | 20 | Implementation, documentation |
| Wave 3 (LOW) | 39 | Minor fixes, line references |
| Deferred | 6 | Architectural changes |
| **Total** | **75** | |

---

## Removed Items (Already Fixed or Verified)

The following items were removed because they are already FIXED or VERIFIED CORRECT:

| Source | Item | Status | Notes |
|--------|------|--------|-------|
| Config/Admin | CSRF validation uses ConstantTimeEq | ✅ FIXED | `src/admin/state.rs:737` uses `ct_eq()` |
| Plugin | BUG-2 (body_receiver not reset) | ✅ FIXED | `instance_pool.rs:221` |
| Plugin | BUG-3 (warmup missing functions) | ✅ FIXED | All 7 functions linked |
| Plugin | Spin find_route (LPM) | ✅ FIXED | `spin/runtime.rs:271-285` |
| WAF | Flood Protection Integration | ✅ VERIFIED | `check_request_full()` calls flood_protector |
| WAF | Request Smuggling Detection | ✅ VERIFIED | CL/TE conflict patterns exist |
| WAF | Fast-Path Bypass Fix | ✅ VERIFIED | 38 patterns in fast_path |
| WAF | Behavioral Analysis Mesh-Only | ✅ VERIFIED | `#[cfg(feature = "mesh")]` |
| Plan.md | REC-1, REC-3, REC-5 | ✅ FIXED | Fast-path patterns, streaming WAF |
| Plan.md | DOC-3, DOC-4, ISSUE-5 | ✅ FIXED | Documentation updates |
| Plan.md | PLUGIN-3 | ✅ FIXED | verify_caller_permission documented |
| Plan.md | MESH-11, MESH-16 | ✅ FIXED | Quorum race, dead code removed |
| Plan.md | APP-17 | ✅ FIXED | require_hashes field added |
| Plan.md | SAFE_HEADERS count | ✅ VERIFIED | 28 headers |
| Mesh | DHT Ingress Verification Gaps | ✅ VERIFIED | Documented at `signed.rs:42-48` |

---

## Verification Commands

```bash
# Core profile
cargo check --no-default-features

# Mesh profile
cargo check --no-default-features --features mesh

# DNS profile
cargo check --no-default-features --features dns

# Full profile
cargo check --no-default-features --features mesh,dns

# Format and lint
cargo fmt && cargo clippy --lib -- -D warnings

# Test compile check
cargo test --lib --no-run
```

---

**Last Updated:** 2026-05-23

## Execution Summary (2026-05-23)

All waves 1-3 from this plan have been executed and merged to main.

| Wave | Items | Status |
|------|-------|--------|
| Wave 1 (HIGH) | NEW-1 through NEW-10 | COMPLETED |
| Wave 2 (MEDIUM) | NEW-11 through NEW-30 | COMPLETED |
| Wave 3 (LOW) | NEW-31 through NEW-69 | COMPLETED |

Key findings:
1. ErasedHttpClient Phase 9 incomplete (server.rs:3302) - see skills/erased_http_client.md
2. Duplicate dead code fixed in erased_pool.rs
3. Spin routing IS implemented (spin/runtime.rs:271-285)

