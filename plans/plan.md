# MaluWAF Implementation Consolidated Plan

**Last updated**: 2026-04-23
**Status**: ⚠️ IN PROGRESS - Many items remain

---

## Overview

This document consolidates all implementation items from 35 individual plan files into a single wave-based plan. **IMPORTANT**: The previous claim of "100% complete" was inaccurate. Individual plan files show many items still pending implementation.

**Total items identified**: ~150+
**Completed**: ~40 (based on individual plan verification)
**Pending**: ~110+

---

## Status Discrepancy Alert

The previous `plan.md` claimed 100% completion, but individual plans show:

| Plan | Status per File | Items Pending |
|------|----------------|--------------|
| plan3.md | PLANNED | 2 code changes |
| plan4.md | PENDING | ViolationTracker, allocations |
| plan6.md | PENDING | Template path traversal |
| plan7.md | PENDING | 9 WASM categories |
| plan18.md | Draft | 11 reverse proxy issues |
| plan19.md | Draft | 8 mesh/DHT issues |
| plan23.md | Draft | 18 performance issues |
| plan24.md | Draft | 8 security issues |
| plan25.md | Draft | 20 code quality issues |
| plan26.md | Draft | Serverless mesh gaps |
| plan27.md | Draft | YARA/ThreatIntel gaps |
| plan31.md | - | Dependency security |
| plan33.md | - | Edge caching issues |
| plan34.md | - | Test coverage |
| plan35.md | - | 3 failing DNS tests |

---

## CRITICAL Issues (Fix Immediately)

These security vulnerabilities and blocking bugs must be addressed before other work.

### CR-1: PoW Iteration Cap Blocks Edge Nodes

**Plan**: plan19.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `NODE_ID_POW_DIFFICULTY = 64` bits with `MAX_ITERATIONS = 10_000_000`. Probability of success is ~5.4×10^-13 - edge nodes literally cannot connect.

**Fix**: Change difficulty to 16 bits at `src/mesh/dht/routing/node_id.rs:10`

```rust
pub const NODE_ID_POW_DIFFICULTY: u32 = 16;  // Was: 64
```

**Verification**: `cargo test --lib mesh::peer_auth::tests::test_edge_node_with_valid_pow_passes`

---

### CR-2: Path Traversal in Template Loading

**Plan**: plan6.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `load_directory_template()` reads custom template paths without validating they're within allowed directories. An attacker can read arbitrary files.

**Location**: `src/static_files/directory.rs:30-37`

**Fix**: Add path validation using canonical path resolution and prefix check.

---

### CR-3: Stored XSS in Directory Listing

**Plan**: plan24.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: User-controlled filenames rendered in HTML without escaping. `entry.name` NOT escaped in `src/static_files/directory.rs:120-127` and `src/theme/dir_listing.rs:509-520`.

**Fix**: Apply `escape_html()` to `entry.name` before rendering.

---

### CR-4: Blocking Call Deadlock Risk

**Plan**: plan25.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `AiHoneypotResponder::respond()` calls `Handle::current().block_on()` which deadlocks if called from within async context.

**Location**: `src/honeypot_port/responders/mod.rs:159-160`

**Fix**: Override `respond_async()` to avoid calling sync `respond()`.

---

### CR-5: Admin Token Uses Weak RNG

**Plan**: plan25.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: Admin tokens generated with `ThreadRng` instead of `OsRng`.

**Location**: `src/config/admin.rs:86-101, 184-198`

**Fix**: Change to `rand::rngs::OsRng.fill_bytes()`.

---

### CR-6: TLS Passthrough WAF Bypass

**Plan**: plan18.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `tls_passthrough_enforce_waf` only logs warnings, doesn't enforce. `proxy_raw_tcp()` not wired into request handling.

**Fix**: Wire proxy_raw_tcp(), change WARN to ERROR, require rate limiting for passthrough.

---

### CR-7: Domain Ownership Verification Missing

**Plan**: plan19.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: Any node can announce `verified_upstream` for any domain without proving DNS ownership. `handle_upstream_ownership_challenge()` never actually serves HTTP-01 challenges.

**Fix**: Implement verification loop - origin stores challenge, global verifies via HTTP request, then origin responds with proof.

---

### CR-8: Zero-Key Fallback in YARA Signature

**Plan**: plan25.md
**Severity**: CRITICAL (Defensive)
**Status**: PENDING

**Problem**: When public key bytes can't convert to 32-byte array, silently falls back to zero key, masking bugs.

**Location**: `src/mesh/yara_rules.rs:771,934`

**Fix**: Return error explicitly instead of fallback to zero key.

---

## HIGH Priority Issues

### H-1: ViolationTracker Lock Contention

**Plan**: plan4.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: Global `RwLock<HashMap>` acquired on every violation. At 500K rps with 5% violation rate = 25K lock acquisitions/sec.

**Location**: `src/waf/violation_tracker.rs:152-180`

**Fix**: Implement 64-sharded ViolationTracker.

---

### H-2: JSON Serialization in DHT Hot Paths

**Plan**: plan23.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `serde_json` used for DHT record serialization where `postcard` should be used. ~1M allocations/sec at 500K req/s.

**Locations**: `src/mesh/dht/record_store_crud.rs:33-40`, `src/mesh/dht/record_store_message.rs:557-562,700-705`

**Fix**: Replace JSON with `crate::serialization::serialize()`.

---

### H-3: WAF Per-Header Arc Clone

**Plan**: plan23.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `InputLocation::Header(name.clone())` where name is already `Arc<str>`. ~110M Arc clones/sec at 500K req/s with 20 headers.

**Location**: `src/waf/attack_detection/mod.rs:302`

**Fix**: Change detector signatures to accept `&InputLocation` instead of `InputLocation`.

---

### H-4: Dead `lowercased` Field Allocation

**Plan**: plan23.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `Normalizer::normalize()` allocates `Cow::Owned(buffer.to_lowercase())` but field is never used.

**Location**: `src/waf/probe_tracker/normalizer.rs:66`

**Fix**: Delete `lowercased` field, `as_lowercased()` method, and `to_lowercase()` allocation.

---

### H-5: Proxy Cache O(n) Invalidation

**Plan**: plan23.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `invalidate_by_pattern()` iterates entire cache on every call.

**Location**: `src/proxy_cache/store.rs:557-562`

**Fix**: Add `uri_prefix_index: HashMap<String, Vec<CacheKey>>` for O(1) lookups.

---

### H-6: WASM verify_caller_permission() Unwired

**Plan**: plan7.md, plan26.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `verify_caller_permission()` at `manager.rs:190-282` is never called. All permission checks bypassed.

**Fix**: Add `CallerContext` struct, wire permission verification at entry points.

---

### H-7: WASM DHT Access Control Missing

**Plan**: plan7.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `mesh_query_dht()` reads ANY DHT key without capability verification.

**Location**: `src/plugin/wasm_runtime.rs:563-621`

**Fix**: Add per-plugin allowed DHT keys config, implement capability check.

---

### H-8: WASM Resource Limiter Not Implemented

**Plan**: plan7.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `ResourceLimiter` trait not implemented. WASM can bypass memory limits via `memory.grow`.

**Location**: `src/plugin/wasm_runtime.rs:820-838`

**Fix**: Implement wasmtime `ResourceLimiter` trait.

---

### H-9: HS256/RS256 Algorithm Confusion

**Plan**: plan18.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: JWT detector is pattern-based only. Cannot detect alg switch from RS256 to HS256.

**Location**: `src/waf/attack_detection/jwt.rs`

**Fix**: Add algorithm family tracking, detect symmetric/asymmetric switches.

---

### H-10: IPv4-Mapped IPv6 SSRF Bypass

**Plan**: plan18.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: `::ffff:192.168.1.1` NOT detected as private IP, but `192.168.1.1` IS.

**Location**: `src/waf/attack_detection/ssrf.rs:132-150`

**Fix**: Check for IPv4-mapped IPv6 format, extract and check IPv4.

---

### H-11: DNS Rebinding SSRF No Protection

**Plan**: plan18.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: SSRF detector does NOT perform DNS resolution. Attacker can bypass via DNS rebinding.

**Fix**: Add DNS resolver capability with mesh/third-party fallback and caching.

---

### H-12: Capability Verifier NOT Wired

**Plan**: plan27.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `CapabilityAccessVerifier` exists but `RecordStoreManager` created with `capability_verifier: None`.

**Location**: `src/mesh/dht/record_store.rs`

**Fix**: Wire verifier, add self-attestation for global nodes on startup.

---

### H-13: Serverless Proxy Stream Unreachable

**Plan**: plan26.md
**Severity**: CRITICAL
**Status**: PENDING

**Problem**: `handle_serverless_proxy_stream()` unreachable - `get_upstream_info()` returns None before serverless check.

**Location**: `src/mesh/transport_peer.rs:2539-2581`

**Fix**: Reorder checks - check `serverless:` prefix BEFORE `get_upstream_info()` lookup.

---

### H-14: RSA 1024 in DNSSEC Key Generation

**Plan**: plan24.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: RSA 1024 allowed, below NIST minimum (112 bits). RFC 8624 explicitly NOT RECOMMENDED.

**Location**: `src/dns/dnssec_key_mgmt.rs:240-247`

**Fix**: Auto-upgrade 1024→2048 with warning, update error message.

---

### H-15: DNS Cache Poisoning Confirmation Threshold

**Plan**: plan3.md
**Severity**: MEDIUM
**Status**: PENDING

**Problem**: Confirmation threshold of 2 may be too low.

**Location**: `src/dns/cache.rs:188-214`

**Fix**: Increase threshold from 2 to 3.

---

## MEDIUM Priority Issues

### M-1: Thread-Local Response Header Buffers

**Plan**: plan4.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: `Vec::new()` allocated for response headers on every proxied response.

**Locations**: `src/http/server.rs:2644,2741`, `src/tls/server.rs:1449,1599`

**Fix**: Use thread-local buffer reuse.

---

### M-2: String Allocations in Hot Paths

**Plan**: plan4.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: Multiple `.to_string()` calls per request - `method.to_string()`, duplicate `path_str` allocation.

**Fix**: Use `.as_str()`, reuse String variables.

---

### M-3: WebSocket HashMap Allocations

**Plan**: plan4.md
**Severity**: HIGH (for WebSocket)
**Status**: PENDING

**Problem**: Empty HashMaps created for every WebSocket frame.

**Location**: `src/http/server.rs:3337,3340,3412,3415,3547,3550,3618,3625`

**Fix**: Use static empty map constant.

---

### M-4: WASM Transform Empty HashMap

**Plan**: plan4.md
**Severity**: MEDIUM
**Status**: PENDING

**Problem**: Empty HashMap passed to WASM filters on every call.

**Location**: `src/http/server.rs:2033,2038,2336,2339,2772,2777`

**Fix**: Check if filters exist before calling.

---

### M-5: Connection Pool Limits Hardcoded

**Plan**: plan18.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: `max_connections=100`, `pool_max_idle_per_host=100`, `pool_idle_timeout=30s` hardcoded.

**Fix**: Expose via site proxy config.

---

### M-6: Global Rate Limiter Blackhole

**Plan**: plan18.md
**Severity**: MEDIUM
**Status**: PENDING

**Problem**: Blackhole is global (not per-IP). One loud neighbor blackholes everyone.

**Location**: `src/waf/ratelimit/core.rs`

**Fix**: Add per-IP blackhole tracking with admin API reset.

---

### M-7: GeoIP Cache Size

**Plan**: plan18.md
**Severity**: MEDIUM
**Status**: PENDING

**Problem**: Default 10,000 entry cache may thrash at 500K rps.

**Location**: `src/config/defaults.rs`

**Fix**: Increase default to 100,000.

---

### M-8: LRU Rate Limiter Eviction Dead Code

**Plan**: plan18.md
**Severity**: LOW
**Status**: PENDING

**Problem**: `lru_order` and `ip_requests` never populated - dead code.

**Location**: `src/waf/ratelimit.rs`

**Fix**: Remove dead code.

---

### M-9: Proxy Headers Excessive Allocations

**Plan**: plan23.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: `build_forward_headers()` allocates `Vec<(String, String)>` with `.to_string()` per header.

**Location**: `src/proxy/headers.rs:360-398`

**Fix**: Use `http::HeaderMap` instead.

---

### M-10: DNS Redundant to_lowercase() Calls

**Plan**: plan23.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: `qname.to_lowercase()` called multiple times per query.

**Location**: `src/dns/server/query.rs:670,716,719`

**Fix**: Pre-compute lowercase once before loops.

---

### M-11: DNS Zone Clone on Get

**Plan**: plan23.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: `get()` returns `Option<Zone>` - full Zone clone on every query.

**Location**: `src/dns/server/sharded_store.rs:67`

**Fix**: Return `Option<Arc<Zone>>`, store zones as `Arc<RwLock<Zone>>`.

---

### M-12: Rate Limiter O(bucket_count) Rotation

**Plan**: plan23.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: All 60 buckets summed sequentially on rotation.

**Location**: `src/waf/ratelimit/core.rs:176-180`

**Fix**: Maintain running_sum atomic counter.

---

### M-13: Cache Write Lock Contention

**Plan**: plan23.md
**Severity**: MEDIUM
**Status**: PENDING

**Problem**: `host_index.write()` on every cache insert.

**Location**: `src/proxy_cache/store.rs:524`

**Fix**: Replace `RwLock` with `DashMap`.

---

### M-14: Mesh Seen Messages Locking

**Plan**: plan23.md
**Severity**: MEDIUM
**Status**: PENDING

**Problem**: `RwLock` on `seen_messages` for every message check+mark.

**Location**: `src/mesh/transport.rs:961-968`

**Fix**: Replace with `DashMap`.

---

### M-15: ThreatIntel Re-Announce Missing

**Plan**: plan27.md
**Severity**: MEDIUM
**Status**: PENDING

**Problem**: ThreatIntel indicators not re-announced by global nodes.

**Fix**: Add `re_announce_interval_secs` and periodic re-announcement task.

---

### M-16: SHA-1 Deprecation for DNSSEC

**Plan**: plan24.md
**Severity**: HIGH
**Status**: PENDING

**Problem**: RFC 9905 (Nov 2025) deprecates SHA-1 for DNSSEC. TSIG HMAC-SHA1 still used.

**Fix**: Add HMAC-SHA-256 support, default to SHA-256 for DS records.

---

## Implementation Waves

### Wave 1: Compile Blocker + Critical Security (Sequential)

| # | Item | Plan | Risk |
|---|------|------|------|
| 1 | PoW difficulty fix (CR-1) | plan19 | LOW |
| 2 | Path traversal template (CR-2) | plan6 | LOW |
| 3 | Stored XSS fix (CR-3) | plan24 | LOW |
| 4 | Honeypot deadlock (CR-4) | plan25 | LOW |
| 5 | Admin token RNG (CR-5) | plan25 | LOW |
| 6 | TLS passthrough bypass (CR-6) | plan18 | MEDIUM |
| 7 | Domain verification (CR-7) | plan19 | HIGH |
| 8 | YARA zero-key fallback (CR-8) | plan25 | LOW |

### Wave 2: Critical WASM Security

| # | Item | Plan | Risk |
|---|------|------|------|
| 9 | Wire verify_caller_permission (H-6) | plan7,26 | MEDIUM |
| 10 | DHT access control (H-7) | plan7 | MEDIUM |
| 11 | ResourceLimiter impl (H-8) | plan7 | MEDIUM |
| 12 | Capability verifier wiring (H-12) | plan27 | MEDIUM |
| 13 | Serverless proxy unreachable (H-13) | plan26 | MEDIUM |

### Wave 3: High Priority Performance

| # | Item | Plan | Risk |
|---|------|------|------|
| 14 | ViolationTracker sharding (H-1) | plan4 | MEDIUM |
| 15 | DHT JSON→postcard (H-2) | plan23 | MEDIUM |
| 16 | WAF header clone (H-3) | plan23 | LOW |
| 17 | Dead lowercase (H-4) | plan23 | VERY LOW |
| 18 | Cache O(n) invalidation (H-5) | plan23 | LOW |
| 19 | Response header buffers (M-1) | plan4 | LOW |
| 20 | String allocations (M-2) | plan4 | LOW |
| 21 | Connection pool config (M-5) | plan18 | LOW |

### Wave 4: Reverse Proxy Security

| # | Item | Plan | Risk |
|---|------|------|------|
| 22 | JWT algorithm confusion (H-9) | plan18 | LOW |
| 23 | IPv4-mapped IPv6 SSRF (H-10) | plan18 | LOW |
| 24 | DNS rebinding SSRF (H-11) | plan18 | HIGH |
| 25 | Blackhole per-IP tracking (M-6) | plan18 | MEDIUM |

### Wave 5: DNS & DNSSEC

| # | Item | Plan | Risk |
|---|------|------|------|
| 26 | RSA 1024→2048 auto-upgrade (H-14) | plan24 | LOW |
| 27 | SHA-1 deprecation (M-16) | plan24 | MEDIUM |
| 28 | Cache poisoning threshold (H-15) | plan3 | LOW |
| 29 | DNS lowercase optimization (M-10) | plan23 | LOW |
| 30 | Zone Arc optimization (M-11) | plan23 | MEDIUM |
| 31 | Rate limiter rotation (M-12) | plan23 | LOW |

### Wave 6: Mesh & DHT Improvements

| # | Item | Plan | Risk |
|---|------|------|------|
| 32 | ThreatIntel re-announce (M-15) | plan27 | LOW |
| 33 | Mesh seen messages DashMap (M-14) | plan23 | LOW |
| 34 | Cache DashMap (M-13) | plan23 | LOW |

### Wave 7: Testing & Quality

| # | Item | Plan | Risk |
|---|------|------|------|
| 35 | DNS recursive test failures | plan35 | FIX |
| 36 | Worker drain test | plan34 | FIX |
| 37 | WASM regex pre-compilation | plan7 | LOW |
| 38 | Remote execution retries | plan7 | MEDIUM |
| 39 | Instance pool O(n) eviction | plan7 | MEDIUM |

---

## Test Failures

### DNS Recursive Test (plan35)

**Status**: 3 tests failing

**Problem**: `moka::sync::Cache::entry_count()` returns 0 while `get()` works.

**Location**: `src/dns/recursive_cache.rs:326-342`

**Fix**: Replace moka's `entry_count()` with manual atomic counters.

---

### Worker Drain Test (plan34)

**Status**: 1 test failing

**Problem**: `test_drain_completes_on_last_connection_decrement` expects drain_complete=true without calling `stop_accepting()`.

**Location**: `src/worker/drain_state.rs:293-307`

**Fix**: Update test to call `stop_accepting()` before checking drain_complete.

---

## Dependency Security

### hickory-recursor Migration (plan31)

**Status**: PENDING

**Problem**: RUSTSEC-2026-0106 - DNS cache poisoning. `hickory-recursor` deprecated.

**Fix**: Migrate to `hickory-resolver 0.26` with `recursor` feature.

---

### yara-x/wasmtime (plan31)

**Status**: MONITOR

**Problem**: yara-x 1.15.0 pulls wasmtime 40.0.4 (vulnerable). Direct dependency is 42.0.2 (patched).

**Fix**: Wait for yara-x 1.16.0 with wasmtime 43.0.1+.

---

## Files Summary by Wave

| Wave | Files | Est. Lines |
|------|-------|-----------|
| 1 | `node_id.rs`, `directory.rs`, `mod.rs`, `responders/mod.rs`, `admin.rs`, `tls/server.rs`, `verification.rs`, `yara_rules.rs` | ~200 |
| 2 | `manager.rs`, `wasm_runtime.rs`, `record_store.rs`, `transport_peer.rs` | ~500 |
| 3 | `violation_tracker.rs`, `record_store_crud.rs`, `mod.rs`, `normalizer.rs`, `store.rs`, `server.rs` | ~300 |
| 4 | `jwt.rs`, `ssrf.rs`, `ratelimit/core.rs` | ~200 |
| 5 | `dnssec_key_mgmt.rs`, `tsig.rs`, `cache.rs`, `query.rs`, `sharded_store.rs` | ~250 |
| 6 | `threat_intel.rs`, `transport.rs`, `store.rs` | ~150 |
| 7 | `recursive_cache.rs`, `drain_state.rs`, `routing.rs`, `manager.rs`, `instance_pool.rs` | ~300 |

---

## Verification Commands

```bash
# Verify compilation
cargo check

# Run integration tests
cargo test --test integration_test

# Run clippy
cargo clippy --lib -- -D warnings

# Format check
cargo fmt --check

# Run DHT tests
cargo test --test dht_integration_test

# Run DNS tests (expect failures until fixed)
cargo test --test dns_recursive_test
```

---

## Next Steps

1. Start with Wave 1 items - all are independent and can be parallelized
2. Fix test failures in Wave 7 concurrently
3. Address hickory-recursor migration (dependency security)
4. Progress through remaining waves

---

*This consolidated plan was created by analyzing all 35 individual plan files and reconciling against the previous plan.md which had inaccurate completion status.*
