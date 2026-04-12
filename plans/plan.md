# MaluWAF Implementation Plan

This document tracks deferred and remaining work. Waves 1-4 (Critical Security, High Security, Core Functionality, Code Quality) have been completed.

## Quick Reference

| Category | Items | Status |
|----------|-------|--------|
| Completed Wave 5 Items | 8 | ✅ Done |
| Deferred Work | 12 | 🔶 Future Work |

**Legend**: 🔶 = Future Work | ✅ = Completed

---

## Wave 5: Completed Items

### 5.1 Update dead_code Count in AGENTS.md

**Status**: ✅ Completed

**Location**: `AGENTS.md`

**Fix**: Updated count from ~116 to ~93 across ~50 files.

---

### 5.2 Audit Module-Level allow Attributes

**Status**: ✅ Completed (audit only, no changes)

**Location**: Multiple modules

**Audit Findings**:
- 20 files with module-level allow attributes reviewed
- Most suppressions are intentional (reserved future functionality, feature-gated stubs)
- WireGuard-related items are actively used despite apparent dead code
- Some vestigial code identified (MAX_NONCE_CACHE_SIZE, configure_trusted_proxies) - removed

---

### 5.3 Complete Admin UI Orphaned Files

**Status**: ✅ Completed

**Location**: `admin-ui/src/config_docs.rs`

**Fix**: Added `mod config_docs;` to `admin-ui/src/lib.rs`. Build succeeds. Functions `get_field_doc()` and `get_section_doc()` are available for future wiring to admin UI.

---

### 5.4 Add Architecture Decision Records

**Status**: ✅ Completed

**Location**: `docs/adr/`

**Fix**: Created `docs/adr/` with 4 ADRs:
- ADR-001: Global Nodes as Trust Anchors (Not Elected)
- ADR-002: DNSSEC Validation Limited to Recursive Resolver
- ADR-003: Unified Worker Process Architecture
- ADR-004: Module Split Pattern for Large Files

---

### 5.5 Dead Code Annotations Audit

**Status**: ✅ Completed

**Location**: Multiple files

**Fix**: Removed:
- `MAX_NONCE_CACHE_SIZE` constant in `src/process/ipc_signed.rs` (unused)
- `configure_trusted_proxies()` function in `src/admin/middleware.rs` (never called)
- `get_all_stats()` and `get_peer_stats()` functions in `src/tunnel/wireguard/stats.rs` (orphaned WireGuard stats)

Kept: Most other dead_code suppressions are for reserved/future functionality.

---

### 5.6 Unsafe Code Audit

**Status**: ✅ Completed

**Location**: Multiple files

**Fix**: Added SAFETY comments to 5 previously unannotated unsafe blocks:
- `src/dns/platform.rs:52` - CMSG pktinfo read
- `src/dns/platform.rs:70` - setsockopt IP_PKTINFO
- `src/process/ipc_transport.rs:447` - zeroed UCred
- `src/process/ipc_transport.rs:450` - getsockopt SO_PEERCRED
- `src/tls/server.rs:1702` - TcpStream from_raw_fd
- `src/tcp/listener.rs:63` - setsockopt TCP_QUICKACK

---

### 5.7 Documentation Gaps

**Status**: ✅ Completed

**Location**: `src/block_store.rs`, `src/utils.rs`

**Fix**: `src/block_store.rs` already had documentation. Added `//!` module documentation to `src/utils.rs` explaining submodules, types, extension traits, and functions.

---

### 5.11 Add Sync Startup Logging to Threat Intel

**Status**: ✅ Completed

**Location**: `src/mesh/threat_intel.rs:1447-1483`

**Fix**: Added `tracing::info!("Threat intel background tasks started (role: {:?}, sync_enabled: {})", node_role, sync_enabled);` after tokio::spawn in `start_background_tasks()`.

---

## Deferred Items

The following items require additional work and are not yet implemented:

---

### D.1 ShardedZoneStore Full-Shard Iteration

**Status**: 🔶 Deferred

**Severity**: LOW

**Location**: `src/dns/server/sharded_store.rs`

**Issue**: `is_empty()` calls `len()` which iterates all 64 shards sequentially. No short-circuit on first non-empty shard.

**Analysis**:
- `is_empty()` can short-circuit on first non-empty shard (O(1) vs O(n))
- `len()` and `for_each()` inherently need all shards but parallelization with rayon is possible
- Requires rayon dependency or explicit parallelization

---

### D.2 DHT Metrics and Observability

**Status**: 🔶 Deferred

**Severity**: LOW

**Location**: `src/mesh/dht/`

**Issue**: No metrics for DHT operations beyond basic counters.

**Analysis**:
- Existing metrics: DHT_QUERY_LATENCIES, DHT_THREAT_LOOKUP_HITS/MISSES, DHT_QUORUM counters
- Could add: per-bucket peer counts, record count by type, announce queue depth, query latency histograms
- Would require extending MeshAdminStatusResponse or creating new /mesh/dht/stats endpoint

---

### D.3 Configuration Documentation

**Status**: 🔶 Deferred

**Severity**: LOW

**Location**: `src/mesh/dht/config.rs`

**Issue**: Many config fields lack documentation.

**Analysis**: DhtConfig has 27 undocumented fields. All can be documented with straightforward research, but requires significant effort to write proper documentation for each field.

---

### D.4 CSS Honeypot Enhancement

**Status**: 🔶 Deferred

**Severity**: MEDIUM

**Location**: `src/challenge/honeypot.rs`, `src/admin/handlers/honeypot.rs`

**Issue**: CSS honeypot generates invisible trap URLs but has limited path-specific tracking.

**Analysis**:
- Current: Tracks IP → honeypot paths, detects hits, no path context
- Would add: Which application page served which trap URL, per-path hit statistics
- Feasibility: Medium - requires struct changes and new tracking logic
- Implementation would extend HoneypotEntry, modify generate_html(), add stats tracking

---

### D.5 Add Metrics for Threat Intel DHT Operations

**Status**: 🔶 Deferred

**Severity**: LOW

**Location**: `src/metrics/mod.rs`, `src/mesh/threat_intel.rs`

**Issue**: No metrics for DHT operations. Hard to diagnose sync issues.

**Analysis**: Recommended metrics include THREAT_INTEL_DHT_PUBLISH_TOTAL/FAILED, LOOKUP_HITS/MISSES, SYNC_TOTAL/SUCCESS/FAILED/ADDED/REMOVED. Pattern exists in metrics module, would require instrumentation at each DHT operation call site.

---

### D.6 Unified Announcement Mechanism

**Status**: 🔶 Deferred

**Severity**: MEDIUM

**Location**: `src/mesh/`

**Issue**: Two mechanisms exist (`UpstreamAnnounce` vs `UpstreamRegistrationRequest`). Deprecation decision needed.

**Analysis**:
- `UpstreamAnnounce`: Lightweight presence announcement, 5-min TTL, no verification - **ACTIVE**
- `UpstreamRegistrationRequest`: Heavyweight ownership verification via DNS-01/HTTP-01 challenge - **DEAD CODE** (never sent)
- Recommendation: Remove dead `UpstreamRegistrationRequest` code

---

### D.7 DHT Key Type Consistency

**Status**: 🔶 Deferred

**Severity**: MEDIUM

**Location**: `src/mesh/dht/keys.rs`

**Issue**: `is_global_signature_required()` is dead code (never called in codebase).

**Analysis**:
- `is_privileged()` is called in routing/manager.rs (active)
- `is_global_signature_required()` is defined but never called (orphaned)
- Bug: `VerifiedUpstream` appears in both is_public() and is_global_signature_required() - logical conflict
- Recommendation: Remove `is_global_signature_required()`

---

### D.8 Reputation System Bug

**Status**: 🔶 Deferred

**Severity**: MEDIUM

**Location**: `src/mesh/transport_dht.rs:99`

**Issue**: `min_reputation_for_dht_write` defaults to 30 but hardcoded `50` bypasses it.

**Analysis**:
- `transport_dht.rs:99` passes hardcoded `50` instead of actual peer reputation
- This bypasses min_reputation_for_dht_write since 50 >= 30 always
- Correct implementation exists in `record_store_message.rs:109-110` using `get_sender_reputation()`
- Fix needed: Replace hardcoded 50 with actual reputation value

---

### D.9 Global Node Liveness and Quorum Monitoring

**Status**: 🔶 Deferred

**Severity**: MEDIUM

**Location**: `src/mesh/dht/`

**Issue**: Would add `GlobalNodeHeartbeat` DHT record with short TTL.

**Analysis**:
- Infrastructure already exists: NodeHealth, NodeLoad patterns, SignedRecordType, TTL management
- Implementation would require: GlobalNodeHeartbeat DHT key, struct, publishing method, consuming logic
- Feasibility: HIGH - follow existing NodeHealth/NodeLoad patterns
- Publishing interval: 30s, TTL: 90s (3x interval)

---

### D.10 IPv6 Zone ID SSRF Bypass

**Status**: 🔶 Deferred

**Severity**: LOW

**Location**: `src/waf/attack_detection/ssrf.rs:213-239`

**Issue**: IPv6 detection misses zone IDs (e.g., `%eth0`) which could be used for SSRF bypass.

**Analysis**:
- `looks_like_ip()` allows `%` character - zone IDs slip through
- `normalize_ip_for_parse()` doesn't strip zone ID before parsing
- `is_private_ip()` only tries IPv4 parsing - IPv6 private check never reached
- Fix needed: Strip zone IDs in looks_like_ip() and normalize_ip_for_parse(), add IPv6 parsing path

---

### D.11 Homoglyph Normalization Gaps

**Status**: 🔶 Deferred

**Severity**: LOW

**Location**: `src/waf/attack_detection/normalizer.rs:283-311`

**Issue**: Not all Unicode letter homoglyphs are normalized.

**Analysis**:
- Cyrillic: Missing Т (U+0422); bugs in В→B (should be V) and Н→H (should be N)
- Greek: NOT normalized at all (alpha, tau, omicron, iota, etc. look identical to Latin)
- Fix needed: Fix 2 bugs, add missing Cyrillic T, add Greek letter normalization

---

### D.12 TODO Comments - File Manager

**Status**: 🔶 Deferred (partial completion)

**Severity**: LOW

**Location**: `src/http/file_manager.rs:362, 369`

**Issue**: Two `TODO: Re-enable once axum version conflict is resolved` comments.

**Analysis**:
- axum version conflict is RESOLVED (tonic 0.14.5 now depends on axum 0.8.8)
- Handler functions compile but don't satisfy axum Handler trait due to missing async trait impls
- Routes remain commented out with updated TODO noting trait resolution needed
- Handlers retain #[allow(dead_code)] for now

---

## Completed Waves Reference

Waves 1-4 (Critical Security, High Security, Core Functionality, Code Quality) have been fully implemented. The following items were completed:

### Wave 1: Critical Security (12 items)
1.1 WAF XSS Detection Bypass via URL Encoding - ✅
1.2 WAF libinjection Receives Pre-Normalized Input - ✅
1.3 TOFU First-Connection MITM Vulnerability - ✅
1.4 Empty CA Store = Permissive Trust - ✅
1.5 Honeypot Local Blocking Key Mismatch - ✅
1.6 Standalone Mode - Local Blocking Gap - ✅
1.7 No RBAC Enforcement - ✅
1.8 User Enumeration via Timing - ✅
1.9 No Audit Logging for Admin Actions - ✅
1.10 Non-Global Nodes Auto-Registered with Default Reputation - ✅
1.11 SSRF Allowlist Subdomain Bypass - ✅
1.12 Regex Not Complexity-Checked in RFI Detector - ✅

### Wave 2: High Security (14 items)
2.1 Upstream Ownership Validation - ✅
2.2 Genesis Key Rotation and Revocation - ✅
2.3 No Certificate Chain Validation - ✅
2.4 TOFU Without Out-of-Band Verification - ✅
2.5 Replay Window Too Large - ✅
2.6 Stake Grace Period Bypass - ✅
2.7 Forward Secrecy Missing - ✅ (already implemented)
2.8 Cache Poisoning Fingerprint Bypass - ✅
2.9 QUIC 0-RTT Replay Risk - ✅
2.10 Proof of Work Difficulty May Be Too Low - ✅
2.11 No Certificate Revocation List Enforcement - ✅ (already implemented)
2.12 SSRF Path Not Checked in Request Body - ✅ (already implemented)
2.13 File Upload Magic Byte Enforcement Missing - ✅ (already implemented)
2.14 Weak Random Number Generator for Admin Token - ✅ (already implemented)

### Wave 3: Core Functionality (18 items)
3.1 DHT Query Response Collection Missing - ✅
3.2 Granian Uses FastCGI Client Instead of HTTP - ✅
3.3 Edge Node DHT Propagation Blocked - ✅
3.4 VerifiedUpstream Cache Staleness - ✅
3.5 Image Poison Config Never Published to DHT - ✅
3.6 Proxy Cache Preferences Never Forwarded - ✅
3.7 Honeypot AdminState Disconnect - ✅
3.8 Threat Intel Version Tracking Missing - ✅
3.9 DHT Sync Interval Too Long - ✅
3.10 Port Honeypot Rate Limiting - ✅
3.11 Port Availability Race Condition - ✅
3.12 PHP-FPM Socket Auto-Detection Enhancement - ✅
3.13 FastCGI Response Handling Parity with Upstream - ✅
3.14 Granian WebSocket Support - ✅
3.15 Local Key Format Inconsistency - ✅
3.16 YARA Re-announce Disabled - ✅
3.17 Configurable Site Scope for Port Honeypot - ✅
3.18 DHT Quorum Insufficient Check - ✅ (already implemented)

### Wave 4: Code Quality (15 items)
4.1 Atomic Counter Underflow Risk - ✅
4.2 JA4 Fingerprint Computation Not Wired Up - ✅
4.3 WAF Detector String Allocation - ✅
4.4 Rate Limiter O(n) Cleanup - ✅
4.5 Per-IP Rate Limiter LRU Eviction Iterates All Entries - ✅
4.6 Input Normalizer NFKC Allocation - ✅
4.7 Static File Serving Without spawn_blocking - ✅
4.8 std::sync::Mutex in Async Context - ✅
4.9 Repeated IPC Lock in Heartbeat - ✅
4.10 DNS Zone Store Full-Shard Iteration - ✅
4.11 Proxy Cache Entry Clone on Every Hit - ✅
4.12 HTTP Path Sanitization Vector Allocation - ✅
4.13 Response Header Filtering Vector Allocation - ✅
4.14 Unsafe Code Missing Safety Comments - ✅
4.15 Missing Error Context in thiserror Types - ✅

(End of file)
