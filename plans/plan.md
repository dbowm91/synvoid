# MaluWAF Implementation Plan

Last updated: 2026-04-13

## Overview

This document tracks all remaining implementation work. Completed items have been pruned.
Reference material for completed items is in `plans/COMPLETED.md`.

Items are organized into **Waves** for parallelization. Items within a wave can be executed
in parallel by separate subagents. Dependencies between waves are documented.

---

## Quick Reference

| ID | Focus | Severity | Status |
|----|-------|----------|--------|
| **Wave 1: Critical Security (WAF, Auth, Mesh)** | | | |
| S1.1 | Threat Intel Signature Bypass | 🔴 CRITICAL | ✅ Completed |
| S1.2 | Tier Key Sent Unencrypted | 🔴 CRITICAL | ✅ Completed |
| M1.1 | Origin Node Self-Attestation Bypass | 🔴 CRITICAL | ✅ Completed |
| M1.2 | Edge Node PoW Key Unbinding | 🔴 HIGH | ✅ Completed |
| W1.5 | HTTP Honeypot Bypass (WAF not called) | 🔴 HIGH | ✅ Completed |
| W2.5 | Origin Upstream Ownership Verification | ⚠️ HIGH | ✅ Completed |
| W2.7 | Tier Key Encryption Scope Extension | ⚠️ MEDIUM | ✅ Completed |
| H1 | DHT Key Collision (W1.8 incomplete) | 🔴 HIGH | ✅ Completed |
| H2 | sync_from_dht Key Mismatch | 🔴 HIGH | ✅ Completed |
| **Wave 2: High Security (TLS, DNS, Mesh)** | | | |
| S2.6 | SSRF Allowlist Bypass via Substring | 🟡 MEDIUM | ❌ Open |
| S2.7 | Open Redirect Bypass via Encoding | 🟡 MEDIUM | ❌ Open |
| S2.8 | Transfer-Encoding Parsing Bypass | 🟡 MEDIUM | ❌ Open |
| S2.9 | JWT Algorithm Confusion | 🟡 MEDIUM | ❌ Open |
| S2.10 | Unicode Normalization Missing | 🟡 MEDIUM | ❌ Open |
| M1.3 | Revocation Bypass for Edge/Origin | 🟡 MEDIUM | ❌ Open |
| M2.1 | DHT Churn Handling Incomplete | 🔴 HIGH | ❌ Open |
| M2.2 | Bucket Refresh Never Triggered | 🟡 MEDIUM | ❌ Open |
| M2.3 | find_closest() Premature Return | 🟡 MEDIUM | ❌ Open |
| M2.4 | Edge Resync Single-Homed | 🟡 MEDIUM | ❌ Open |
| M3.1 | Unused Access Control Methods | 🟡 MEDIUM | ❌ Open |
| M3.2 | Incomplete Encryption for Privileged | 🟡 MEDIUM | ❌ Open |
| **Wave 3: Core Functionality (Web Stack, Caching, Honeypot)** | | | |
| W3.2 | Stream Large Request Bodies | 🔴 HIGH | ❌ Open |
| W3.3 | Response Streaming | 🔴 HIGH | ❌ Open |
| W3.6 | Edge Node HTTP Response Cache | 🔴 HIGH | ❌ Open |
| 1.1 | Wire FastCgiPool into Request Path | 🔴 HIGH | ❌ Open |
| 1.2 | Fix TLS Server Granian Forwarding | 🔴 HIGH | ❌ Open |
| 1.3 | PHP Security Settings Enforcement | 🔴 HIGH | ❌ Open |
| 2.1 | Add SiteStaticThemeConfig | 🟡 MEDIUM | ❌ Open |
| 2.2 | Template Loading for Directory Listing | 🟡 MEDIUM | ❌ Open |
| 2.3 | Wire Theme Config in StaticFileHandler | 🟡 MEDIUM | ❌ Open |
| T1 | Threat Intel Signature Verification Mismatch | 🔴 CRITICAL | ❌ Open |
| T2 | YARA Manifest Signature Never Verified | 🔴 HIGH | ❌ Open |
| **Wave 4: Performance & Code Quality** | | | |
| P1.1 | SSRF Detection Multiple to_lowercase() | 🔴 HIGH | ❌ Open |
| P1.2 | Rate Limiter O(n) Cleanup | 🔴 HIGH | ❌ Open |
| P1.3 | Response Body WAF Scanning | 🔴 HIGH | ❌ Open |
| P1.4 | Mesh Route Query Cold-Cache Latency | 🔴 HIGH | ❌ Open |
| P2.1 | WAF Input Normalizer Allocations | 🔴 HIGH | ❌ Open |
| P2.2 | HTTP Server Clone/To-String Calls | 🔴 HIGH | ❌ Open |
| P2.3 | SuspiciousWordTracker Unconditional Write Lock | 🔴 HIGH | ❌ Open |
| P2.4 | EndpointBlocker O(n) Pattern Matching | 🔴 HIGH | ❌ Open |
| P2.5 | TLS Client Cache Unbounded Growth | 🔴 HIGH | ❌ Open |
| P.1 | WAF Double Normalization | 🔴 HIGH | ❌ Open |
| P.2 | WAF Input Normalization Allocations | 🔴 HIGH | ❌ Open |
| P.3 | URL Decoding Repeated Allocations | 🔴 HIGH | ❌ Open |
| P.4 | SSRF Detection Repeated URL Parsing | 🔴 HIGH | ❌ Open |
| S2.1 | Connection Limit Global Per-Worker | 🟡 MEDIUM | ❌ Open |
| S2.2 | Stale Cache TTL May Cause Unnecessary Refresh | 🟡 MEDIUM | ❌ Open |
| S2.3 | TCP Worker Pool Size Default | 🟡 MEDIUM | ❌ Open |
| S2.4 | Verified Upstream Cache TTL Only 30s | 🟡 MEDIUM | ❌ Open |
| S2.5 | Upstream Client Cache Key Sprawl | 🟡 MEDIUM | ❌ Open |
| M1.1 | Serial HTTP Proxy Streams | 🔴 HIGH | ❌ Open |
| M1.2 | No HTTP/2 Multiplexing in QUIC | 🟡 MEDIUM | ❌ Open |
| M1.3 | Route Usage Tracker Unbounded | 🟡 MEDIUM | ❌ Open |
| Q1.1 | Heartbeat N+1 Lock Contention | 🔴 HIGH | ❌ Open |
| Q1.2 | IPC Error Information Loss | 🔴 HIGH | ❌ Open |
| Q1.3 | HTTP/TLS Test Coverage Gaps | 🔴 HIGH | ❌ Open |
| Q2.1 | Silent Send Failures in Mesh | 🟡 MEDIUM | ❌ Open |
| Q2.2 | Multiple lowercase() in Detectors | 🟡 MEDIUM | ❌ Open |
| Q2.3 | Unbounded CSRF Token Storage | 🟡 MEDIUM | ❌ Open |
| Q2.4 | MeshMessage Enum Size | 🟡 MEDIUM | ❌ Open |
| P3.1 | DHT pending_announces O(n) Remove | 🟡 MEDIUM | ❌ Open |
| P3.2 | SSRF format! Allocation in Loop | 🟡 MEDIUM | ❌ Open |
| P3.3 | Response Header Filtering Allocation | 🟡 MEDIUM | ❌ Open |
| P3.4 | Proxy Cache Redundant Lock in SWR | 🟡 MEDIUM | ❌ Open |
| P3.5 | RingBuffer is_empty() Not Short-Circuiting | 🟡 MEDIUM | ❌ Open |
| P.5 | IPC Double-Poll Delay | 🟡 MEDIUM | ❌ Open |
| P.6 | Cache Invalidation O(n) Full Scan | 🟡 MEDIUM | ❌ Open |
| P.7 | Rate Limiter LRU Write Lock Contention | 🟡 MEDIUM | ❌ Open |
| P.8 | local_upstreams Single Lock | 🟡 MEDIUM | ❌ Open |
| P.9 | verified_upstream_cache No Failed Lookup Caching | 🟡 MEDIUM | ❌ Open |
| P.10 | Drain Polling Fixed 100ms Interval | 🟡 MEDIUM | ❌ Open |
| P.11 | Mesh Broadcast Unbounded Spawns | 🟡 MEDIUM | ❌ Open |
| P.12 | find_closest O(n*m) Algorithm | 🟢 LOW | ❌ Open |
| P.13 | DNS Fingerprint Linear Scan | 🟢 LOW | ❌ Open |
| P.14 | KBucket Linear Search | 🟢 LOW | ❌ Open |
| P.15 | Path Sanitization Vec Allocations | 🟢 LOW | ❌ Open |
| P.16 | HTTP Header Cloning Per-Request | 🟢 LOW | ❌ Open |
| Q4.1 | Fix Test Result Warnings | 🟢 LOW | ❌ Open |
| Q4.2 | proxy.rs Deep Nesting | 🟢 LOW | ❌ Open |
| Q4.3 | Ed25519 Key Array Zeroization | 🟢 LOW | ❌ Open |
| Q4.4 | MockIpcStream Dead Code | 🟢 LOW | ❌ Open |
| **Wave 5: Polish & Optimization** | | | |
| Q1.1 | NSEC3 Hash Length Encoding Bug | 🔴 CRITICAL | ❌ Open |
| Q1.2 | Unsafe Blocks Missing SAFETY Comments | 🔴 HIGH | ❌ Open |
| Q2.1 | handle_request() Maintainability | 🟡 MEDIUM | ⏸️ Deferred |
| Q2.2 | Dead Code Audit and Cleanup | 🟡 MEDIUM | ❌ Open |
| Q3.1 | Missing Test Coverage for Critical Paths | 🟡 MEDIUM | ❌ Open |
| Q3.2 | Metrics and Observability Gaps | 🟡 MEDIUM | ❌ Open |
| Q4.1 | Configuration Documentation | 🟢 LOW | ❌ Open |
| Q4.2 | TODO Comments Cleanup | 🟢 LOW | ❌ Open |
| F.1 | ShardedZoneStore is_empty() Optimization | 🟡 MEDIUM | ❌ Open |
| F.2 | DHT Metrics and Observability | 🟡 MEDIUM | ❌ Open |
| F.3 | Configuration Documentation for DhtConfig | 🟢 LOW | ❌ Open |
| F.4 | CSS Honeypot Enhancement - Path Tracking | 🟢 LOW | ❌ Open |
| F.5 | Metrics for Threat Intel DHT Operations | 🟢 LOW | ❌ Open |
| F.8 | Reputation System Bug - Hardcoded 50 | 🟢 LOW | ❌ Open |
| F.9 | Global Node Liveness and Quorum Monitoring | 🟢 LOW | ❌ Open |
| F.10 | IPv6 Zone ID SSRF Bypass | 🟢 LOW | ❌ Open |
| F.11 | Homoglyph Normalization Gaps | 🟢 LOW | ❌ Open |
| F.12 | TODO Comments - File Manager | 🟢 LOW | ❌ Open |
| F.13 | ConnectionMeta Trait - Remaining Migration | 🟡 MEDIUM | ❌ Open |

---

## Wave 1: Critical Security (WAF, Auth, Mesh)

### 🔴 S1.1: Threat Intel Signature Bypass - CRITICAL ✅ COMPLETED

**Location**: `src/mesh/threat_intel.rs:709-716`

**Issue**: Content string format for signing differs from verification format:
- Signing: `"{}:{}:{}:{}:{}"` with `as u8` for threat_type/severity
- Verification: `"{},{},{:?},{},{}"` with `as u32` and `{:?}` Debug format

All threat intelligence signatures fail verification, allowing fake indicators.

**Fix**: Updated verification format at lines 709-716 to exactly match signing format:
- Changed from `"{},{},{:?},{},{}"` to `"{}:{}:{}:{}:{}"`
- Changed `indicator.threat_type as u32` to `indicator.threat_type as u8`
- Changed `{:?}` (Debug format for severity) to `indicator.severity as u8`
- Changed `from_node` to `indicator.source_node_id`

---

### 🔴 S1.2: Tier Key Sent Unencrypted - CRITICAL ✅ COMPLETED

**Location**: `src/mesh/transport_org.rs:249-261`

**Issue**: When no ML-KEM session exists, tier keys transmitted in plaintext.

**Fix**: Removed plaintext fallback. When no ML-KEM session exists, the tier key is not sent at all (`None`). Changed the fallback path from `Some(tk.clone())` to `None` with a debug log message "No ML-KEM session for peer {}, not sending tier key".

---

### 🔴 M1.1: Origin Node Self-Attestation Bypass - CRITICAL ✅ COMPLETED

**Location**: `src/mesh/discovery.rs:425-430`, `src/mesh/peer_auth.rs:238-269`

**Issue**: Origin nodes authenticate using their own credentials as "global node attestation".
Signature verified against origin's own public key = self-signing bypass.

**Fix**: In discovery.rs, changed origin node attestation to use `None` for both `global_node_att_key` and `global_node_att_sig`. This forces attestation to fail unless the origin has been properly attested by a real global node via a separate registration flow. Origin nodes can no longer self-attest.

---

### 🔴 M1.2: Edge Node PoW Key Unbinding - HIGH ✅ COMPLETED

**Location**: `src/mesh/peer_auth.rs:191-196`

**Issue**: `peer_public_key` and `pow_public_key` are separate and never bound together.
Attacker can compute PoW with key A, present key B as identity, bypass PoW requirement.

**Fix**: Added key comparison check at lines 191-196 that verifies `pk_bytes != pow_pk_bytes`. If the PoW public key does not match the identity public key, the validation fails with an error message. The PoW must now be computed using the same key used for Ed25519 identity.

---

### 🔴 W1.5: HTTP Honeypot Bypass - HIGH ✅ COMPLETED

**Location**: `src/http/server.rs:903-908`, `src/waf/mod.rs:527`, `src/tls/server.rs:631-636`

**Issue**: Direct `/_waf_hp_` requests return 408 but don't trigger WAF blocking.

**Fix**: Made `block_ip_with_threat_intel()` public in `src/waf/mod.rs`. Added call to `waf.block_ip_with_threat_intel(client_ip, "honeypot", waf.config.honeypot_ban_duration_secs, "global")` in the honeypot handler at lines 903-908 for HTTP and lines 631-636 for HTTPS. IPs accessing honeypot paths are now immediately blocked via threat intel.

---

### ✅ W2.5: Origin Upstream Ownership Verification - COMPLETED

**Location**: `src/mesh/transport.rs`, `src/mesh/transport_peer.rs:1730-1792`, `src/http/server.rs:555-580`

**Issue**: HTTP-01 and DNS-01 challenge handlers were stubbed/simulated.

**Fix**: Implemented actual challenge serving:
- Added `OwnershipChallengeStore` with LruCache-based storage for challenges
- HTTP-01: Stores `token -> key_authorization` and serves at `/.well-known/malu-challenge/{token}`
- DNS-01: Stores TXT record data for mesh DNS serving
- Added challenge serving in HTTP server SECTION 4.5

---

### ✅ W2.7: Tier Key Encryption Scope Extension - COMPLETED

**Location**: `src/mesh/tier_key_encryption.rs`, `src/mesh/mod.rs`

**Issue**: Only `TierKey` records encrypted; Organization, MemberCertificate, GlobalNodeList, etc. stored plaintext.

**Fix**: Extended `TierKeyEncryption` with `PrivilegedRecordType` enum and HKDF-derived keys per record type. Added specialized encrypt/decrypt methods for: Organization, MemberCertificate, GlobalNodeList, OrgNameReservation, DnsZone, DnsDomainRegistration, AnycastNode. All `requires_global_node()` record types are now encrypted.

---

### 🔴 H1: DHT Key Collision - HIGH ✅ COMPLETED

**Location**: `src/mesh/dht/keys.rs:36,159,287,415`, `src/mesh/threat_intel.rs:647-650`

**Issue**: W1.8 supposed to implement `threat_indicator:{ip}:{threat_type}` but uses flat `threat_indicator:{ip}`.
Same IP with different threat types overwrite each other.

**Fix**: Updated `DhtKey::ThreatIndicator` variant from `ThreatIndicator(String)` to `ThreatIndicator(String, String)`. Changed `threat_indicator()` constructor to take both `indicator_id` and `threat_type`. DHT keys are now `threat_indicator:{ip}:{threat_type}` (e.g., `threat_indicator:1.2.3.4:IpBlock`).

---

### 🔴 H2: sync_from_dht Key Mismatch - HIGH ✅ COMPLETED

**Location**: `src/mesh/threat_intel.rs:1148-1149,1162-1166`

**Issue**: `sync_from_dht()` stores with just IP, but retain logic compares composite keys → never matches, all entries incorrectly retained.

**Fix**: Changed to store with full composite key (`key.to_string()`) instead of stripped `indicator_value`. Updated retain logic to use `dht_keys.contains(key)` directly with full composite key format. Removed the now-unused `dht_indicator_values` variable that stripped prefixes.

---

## Wave 2: High Security (TLS, DNS, Mesh)

### S2.6: SSRF Allowlist Bypass via Substring - MEDIUM

**Location**: `src/waf/attack_detection/ssrf.rs:267-270, 322-336`

**Issue**: `evillocalhost.com` contains `.localhost`; `evil.comalloweddomain.com` bypasses allowlist.

**Fix**: Use word boundary checks; verify host is not IP when allowlist specifies domain-only.

---

### S2.7: Open Redirect Bypass via Encoding - MEDIUM

**Location**: `src/waf/attack_detection/open_redirect.rs:114-142`

**Issue**: Doesn't check for newline-encoded schemes (`java\nscript:`) or homograph attacks.

**Fix**: Normalize input before checking; add newline character checks; validate scheme is proper ASCII.

---

### S2.8: Transfer-Encoding Parsing Bypass - MEDIUM

**Location**: `src/waf/attack_detection/request_smuggling.rs:26-49`

**Issue**: `te_lower.contains("chunked")` doesn't validate chunked is complete.

**Fix**: Parse TE header properly as comma-separated list; match exact `chunked` value.

---

### S2.9: JWT Algorithm Confusion - MEDIUM

**Location**: `src/waf/attack_detection/jwt.rs:123-139`

**Issue**: Uses `contains()` not proper JSON parsing for `alg` field.

**Fix**: Parse JWT header as proper JSON; extract and validate `alg` against expected list.

---

### S2.10: Unicode Normalization Missing - MEDIUM

**Location**: `src/proxy.rs:138-232`

**Issue**: No Unicode normalization (NFKC/NFKD); homoglyph attacks possible (Cyrillic `а` vs ASCII `a`).

**Fix**: Add `unicode-normalization` crate; apply NFKC normalization to path.

---

### M1.3: Revocation Bypass for Edge/Origin - MEDIUM

**Location**: `src/mesh/peer_auth.rs:281-288`

**Issue**: Revocation check only in `validate_global_node()`, not in `validate_edge_node()` or `validate_origin_node()`.

**Fix**: Add revocation check to all validation functions.

---

### M2.1: DHT Churn Handling Incomplete - HIGH

**Location**: `src/mesh/dht/routing/table.rs:195-196, 417-431`

**Issue**: `pending_pings` used but no background task sends PINGs; `get_stale_peers()` never called.

**Fix**: Implement ping sender background task; wire into MeshTransport.

---

### M2.2: Bucket Refresh Never Triggered - MEDIUM

**Location**: `src/mesh/dht/routing/table.rs`, `src/mesh/dht/routing/manager.rs`

**Issue**: `BUCKET_REFRESH_INTERVAL = 60` defined but no code triggers FindNode to repopulate sparse buckets.

**Fix**: Implement `refresh_buckets_loop()` in DhtRoutingManager.

---

### M2.3: find_closest() Premature Return - MEDIUM

**Location**: `src/mesh/dht/routing/table.rs:233-282`

**Issue**: Breaks as soon as k candidates found without scanning all buckets.

**Fix**: Scan ALL buckets, not just until k found.

---

### M2.4: Edge Resync Single-Homed - MEDIUM

**Location**: `src/mesh/dht/routing/manager.rs`

**Issue**: `dht_cache_resync()` always contacts `global_nodes[0]` with no fallback.

**Fix**: Try all global nodes in sequence; return error only if all fail.

---

### M3.1: Unused Access Control Methods - MEDIUM

**Location**: `src/mesh/dht/mod.rs:569-695`

**Issue**: `DhtAccessControl::require_global_node()` never invoked; `is_privileged()` never enforced.

**Fix**: Wire `require_global_node()` into `store_record()` or remove dead code.

---

### M3.2: Incomplete Encryption for Privileged Records - MEDIUM

**Location**: `src/mesh/tier_key_encryption.rs`

**Issue**: Only `tier_key:` encrypted; Organization, MemberCertificate, etc. plaintext.

**Fix**: Extend TierKeyEncryption to handle all privileged record types via HKDF-derived keys.

---

## Wave 3: Core Functionality (Web Stack, Caching, Honeypot)

### 🔴 W3.2: Stream Large Request Bodies - OPEN

**Location**: `src/http/server.rs`, `src/tls/server.rs`

**Issue**: Full request body buffered in memory.

**Fix**: Implement true streaming in `handle_request()` pipeline; process body in chunks.

---

### 🔴 W3.3: Response Streaming - OPEN

**Location**: `src/http/server.rs`, `src/tls/server.rs`

**Issue**: HTTP fully buffered (HTTPS already streams).

**Fix**: Enable HTTP response streaming via `hyper::body::Body`; chunked transfer encoding.

---

### 🔴 W3.6: Edge Node HTTP Response Cache - NOT IMPLEMENTED

**Location**: `src/mesh/proxy.rs`

**Issue**: `MeshProxy::new()` ignores `_cache_config`; no `proxy_cache` field; `SiteCachePreferencesStore` missing.

**Fix**: Add `proxy_cache` to MeshProxy; implement SiteCachePreferencesStore; integrate cache lookup.

---

### 1.1: Wire FastCgiPool into Request Path - HIGH

**Location**: `src/fastcgi/pool.rs`, `src/fastcgi/mod.rs`

**Issue**: New connection created per request instead of reusing pooled connections.

**Fix**: Add `execute()` method to FastCgiPool; create module-level pool manager; replace `FastCgiClient::new()` calls.

---

### 1.2: Fix TLS Server Granian Forwarding - HIGH

**Location**: `src/tls/server.rs:1204-1215`

**Issue**: TLS server uses FastCgiClient for Granian (ASGI server), should use `GranianSupervisor::forward_request()`.

**Fix**: Change to use `supervisor.forward_request()` like HTTP server does.

---

### 1.3: PHP Security Settings Enforcement - HIGH

**Location**: `src/php/mod.rs`

**Issue**: `PhpConfig` defines security fields but never passes them to PHP-FPM.

**Fix**: Add security params as PHP_ADMIN_VALUE and PHP_VALUE in FastCGI request.

---

### 2.1: Add SiteStaticThemeConfig - MEDIUM

**Location**: `src/config/site/static_files.rs`

**Issue**: `SiteThemeConfig` lacks `directory_template_path` for static file directory listing.

**Fix**: Create `SiteStaticThemeConfig` struct wrapping `SiteThemeConfig` with `directory_template_path`.

---

### 2.2: Template Loading for Directory Listing - MEDIUM

**Location**: `src/static_files/mod.rs`, `src/static_files/directory.rs`

**Fix**: Add `load_directory_template()` and `render_custom_template()`; support Handlebars-like syntax.

---

### 2.3: Wire Theme Config in StaticFileHandler - MEDIUM

**Location**: `src/static_files/mod.rs`

**Fix**: Add `site_theme` field; check custom template path; load and render if set.

---

### T1: Threat Intel DHT Sync Missing Signature Verification - CRITICAL

**Location**: `src/mesh/threat_intel.rs:1083`

**Issue**: `sync_from_dht()` doesn't verify signatures before accepting indicators.

**Fix**: Add signature verification like YARA's pattern; skip records that fail verification.

---

### T2: YARA Manifest Signature Never Verified - HIGH

**Location**: `src/mesh/yara_rules.rs:430-528`

**Issue**: Manifest's signature never read/verified during `sync_from_dht()`.

**Fix**: Add manifest signature verification; verify rule content's content_hash matches manifest's peer_hash.

---

## Wave 4: Performance & Code Quality

### P1.1: SSRF Detection Multiple to_lowercase() - HIGH

**Location**: `src/waf/attack_detection/ssrf.rs:261-346`

**Issue**: `to_lowercase()` called 6+ times per input; `Cow` optimization not passed through helper chain.

**Fix**: Accept `Cow<str>` throughout helper functions; pass already-lowercased string through call chain.

---

### P1.2: Rate Limiter O(n) Cleanup - HIGH

**Location**: `src/waf/ratelimit.rs:295`

**Issue**: Every 30s, `retain()` iterates entire shard HashMap.

**Fix**: Change to eviction-on-access pattern using LruCache; inline eviction on each access.

---

### P1.3: Response Body WAF Scanning - HIGH

**Location**: `src/waf/mod.rs`

**Issue**: WAF only inspects requests; response bodies not scanned for DLP/PII.

**Fix**: Add `check_response()` method; implement response body scanning with DLP patterns.

---

### P1.4: Mesh Route Query Cold-Cache Latency - HIGH

**Location**: `src/mesh/transport.rs:2154`, `src/mesh/proxy.rs:307-428`

**Issue**: First request to any upstream requires DHT query with 5000ms timeout.

**Fix**: Pre-warm route cache during mesh handshake; optimistic routing; background refresh; longer TTL.

---

### P2.1-P2.5, P.1-P.4, P3.1-P3.5, P.5-P.16: Various Performance Issues

**See detailed descriptions in plan2.md, plan16.md, plan17.md for:**

- P2.1: WAF Input Normalizer Allocations
- P2.2: HTTP Server Clone/To-String Calls
- P2.3: SuspiciousWordTracker Unconditional Write Lock
- P2.4: EndpointBlocker O(n) Pattern Matching
- P2.5: TLS Client Cache Unbounded Growth
- P.1: WAF Double Normalization
- P.2: WAF Input Normalization Allocations
- P.3: URL Decoding Repeated Allocations
- P.4: SSRF Detection Repeated URL Parsing
- P3.1: DHT pending_announces O(n) Remove
- P3.2: SSRF format! Allocation in Loop
- P3.3: Response Header Filtering Allocation
- P3.4: Proxy Cache Redundant Lock in SWR
- P3.5: RingBuffer is_empty() Not Short-Circuiting
- P.5: IPC Double-Poll Delay
- P.6: Cache Invalidation O(n) Full Scan
- P.7: Rate Limiter LRU Write Lock Contention
- P.8: local_upstreams Single Lock
- P.9: verified_upstream_cache No Failed Lookup Caching
- P.10: Drain Polling Fixed 100ms Interval
- P.11: Mesh Broadcast Unbounded Spawns
- P.12: find_closest O(n*m) Algorithm
- P.13: DNS Fingerprint Linear Scan
- P.14: KBucket Linear Search
- P.15: Path Sanitization Vec Allocations
- P.16: HTTP Header Cloning Per-Request

---

### S2.1-S2.5, M1.1-M1.3: Scalability and Mesh Issues

**S2.1**: Per-site connection limits
**S2.2**: Stale Cache TTL adjustment
**S2.3**: TCP Worker Pool auto-tuning
**S2.4**: Verified Upstream Cache TTL increase
**S2.5**: Upstream Client Cache key consolidation
**M1.1**: Serial HTTP Proxy Streams fix
**M1.2**: HTTP/2 Multiplexing in QUIC
**M1.3**: Route Usage Tracker TTL eviction

---

### Q1.1-Q1.3, Q2.1-Q2.4, Q4.1-Q4.4: Code Quality Issues

**Q1.1**: Heartbeat N+1 Lock Contention
**Q1.2**: IPC Error Information Loss
**Q1.3**: HTTP/TLS Test Coverage Gaps
**Q2.1**: Silent Send Failures in Mesh
**Q2.2**: Multiple lowercase() in Detectors
**Q2.3**: Unbounded CSRF Token Storage
**Q2.4**: MeshMessage Enum Size refactor
**Q4.1**: Fix Test Result Warnings
**Q4.2**: proxy.rs Deep Nesting
**Q4.3**: Ed25519 Key Array Zeroization
**Q4.4**: MockIpcStream Dead Code

---

## Wave 5: Polish & Optimization

### 🔴 Q1.1: NSEC3 Hash Length Encoding Bug - CRITICAL

**Location**: `src/dns/dnssec_signing.rs:231-232`

**Issue**: `create_nsec3_record` missing Hash Length byte prefix (RFC 5155 Section 3.2).

**Fix**: Add `nsec3.push(next_hash.len() as u8)` before extending with next_hash.

---

### Q1.2: Unsafe Blocks Missing SAFETY Comments - HIGH

**Location**: Multiple files (ebpf, platform, process modules)

**Issue**: ~91 unsafe blocks lack SAFETY comments explaining invariants.

**Fix**: Add `// SAFETY: ...` to each unsafe block per AGENTS.md standard.

---

### Q2.1: handle_request() Maintainability - DEFERRED

**Location**: `src/http/server.rs:437-1800`

**Note**: Per AGENTS.md, this is exception to size guidelines. Section comments delineate 15 phases.
Splitting not recommended. Consider if deferred.

---

### Q2.2-Q3.2, Q4.1-Q4.2: Documentation, Testing, Cleanup

**Q2.2**: Dead Code Audit and Cleanup
**Q3.1**: Missing Test Coverage for Critical Paths
**Q3.2**: Metrics and Observability Gaps
**Q4.1**: Configuration Documentation
**Q4.2**: TODO Comments Cleanup

---

### F.1-F.13: Future/Lower Priority Work

**F.1**: ShardedZoneStore is_empty() Optimization
**F.2**: DHT Metrics and Observability
**F.3**: Configuration Documentation for DhtConfig
**F.4**: CSS Honeypot Enhancement - Path Tracking
**F.5**: Metrics for Threat Intel DHT Operations
**F.8**: Reputation System Bug - Hardcoded 50
**F.9**: Global Node Liveness and Quorum Monitoring
**F.10**: IPv6 Zone ID SSRF Bypass
**F.11**: Homoglyph Normalization Gaps
**F.12**: TODO Comments - File Manager
**F.13**: ConnectionMeta Trait - Remaining Migration

---

## Implementation Order & Parallelization

### Wave 1 (Critical Security) - Week 1-2
Can parallelize: S1.1, S1.2, M1.1, M1.2, W1.5, H1, H2

### Wave 2 (High Security) - Week 3-4
Can parallelize: M2.1, M2.2, M2.3, M2.4, M3.1, M3.2, S2.6-S2.10, M1.3

### Wave 3 (Core Functionality) - Week 5-6
Can parallelize: W3.2, W3.3, W3.6, 1.1-1.3, 2.1-2.3, T1, T2

### Wave 4 (Performance) - Week 7-10
Can parallelize: P1.1-P1.4, P2.1-P2.5, P.1-P.4, S2.1-S2.5, M1.1-M1.3, Q1.1-Q1.3, Q2.1-Q2.4

### Wave 5 (Polish) - Week 11+
Can parallelize: Q1.1, Q1.2, Q2.2, Q3.1, Q3.2, Q4.1-Q4.2, F.1-F.13

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
cargo test --test dht_integration_test
```

---

## Completed Items (Reference)

The following items have been completed (see `plans/COMPLETED.md` for details):

**Wave 1 Completed**: W1.1-W1.14, W3.1
**Wave 2 Completed**: W2.1-W2.4, W2.6, W2.8
**Wave 3 Completed (partial)**: W3.5, W3.7 (DHT key added), W3.8, W3.9, W3.10
**Wave 4 Completed**: W4.2 (dead code audit)