# WAF Architecture Review Plan

## Executive Summary

Reviewed `architecture/waf_deep_dive.md` against source code in `src/waf/`, `src/challenge/`, `crates/synvoid-utils/src/buffer/`, and `src/wasm_pow/`. Found several claims that need correction, one critical bug, and multiple improvements needed.

---

## Claims Verification

### 1. Flood Protection Layer

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| SYN Flood Protection with default 50 SYNs/sec per IP | VERIFIED | `src/waf/flood/mod.rs:43-44` | Default values match |
| Global SYN rate 10,000 SYNs/sec | VERIFIED | `src/waf/flood/mod.rs:44` | Default matches |
| eBPF backend for Linux only | VERIFIED | `src/waf/flood/mod.rs:5-6` | Conditional compilation confirmed |
| ConnectionLimiter with 20,000 global limit | VERIFIED | `src/waf/flood/mod.rs:46` | `connection_rate_global: 20000` |
| Per-IP limit 100 connections | VERIFIED | `src/waf/flood/mod.rs:45` | `connection_rate_per_ip: 100` |
| Burst tokens default 10 | **NOT VERIFIED** | `src/waf/traffic_shaper/limiter.rs:96` | Uses `config.connection_burst` not hardcoded 10 |
| Queue system 1000 size, 5000ms timeout | VERIFIED | `src/waf/traffic_shaper/limiter.rs:176-183` | Config-based |
| TokenBucket rate limiting | VERIFIED | `src/waf/traffic_shaper/bucket.rs:5-111` | Full implementation found |
| UDP flood protection 1000/sec per IP | VERIFIED | `src/waf/flood/udp_flood.rs:29` | `per_ip_rate: 1000` |
| Global UDP limit 100,000/sec | VERIFIED | `src/waf/flood/udp_flood.rs:30` | `global_rate: 100000` |
| ASN & GeoIP blocking | VERIFIED | `src/waf/asn_tracker.rs` | Full implementation but GeoIP blocking incomplete |

**Issue Found**: Document says "GeoIP blocking not fully implemented" - this is accurate. See `src/waf/asn_tracker.rs` only does ASN-based detection, not GeoIP country blocking.

### 2. Protocol Layer (Request Sanitization)

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| HTTP Validation | VERIFIED | `src/waf/attack_detection/mod.rs:136-139` | `HeaderValidator` exists |
| Header Sanitization | VERIFIED | `src/waf/request_sanitization.rs` | `RequestSanitizer` found |
| Request Smuggling Detection | VERIFIED | `src/waf/attack_detection/mod.rs:132` | `RequestSmugglingDetector` exists |

### 3. Request Layer (Attack Detection)

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| SQL Injection with libinjection | VERIFIED | `src/waf/attack_detection/libinjection.rs` | Full implementation |
| XSS detection | VERIFIED | `src/waf/attack_detection/xss.rs` | Full implementation |
| Path Traversal | VERIFIED | `src/waf/attack_detection/path_traversal.rs` | Full implementation |
| SSRF & RFI | VERIFIED | `src/waf/attack_detection/ssrf.rs`, `src/waf/attack_detection/rfi.rs` | Both found |
| PatternDetector trait | VERIFIED | `src/waf/attack_detection/detector_common.rs:264` | `PatternDetector` trait confirmed |
| Aho-Corasick multi-pattern matching | VERIFIED | `src/waf/attack_detection/detector_common.rs:534-539` | `AhoCorasick::builder()` confirmed |
| SstiDetector, LdapInjectionDetector, XPathInjectionDetector, OpenRedirectDetector, XxeDetector, CmdInjectionDetector, PathTraversalDetector, RfiDetector, SsrfDetector | VERIFIED | All found in `src/waf/attack_detection/` | All implemented |

### 4. Bot Detection Layer

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| CSS Challenge via CssManager | VERIFIED | `src/challenge/css.rs` | Full implementation confirmed |
| Valid CSS rules with aspect ratios | VERIFIED | `src/challenge/css.rs:126-138` | Uses `min-aspect-ratio` and `max-aspect-ratio` |
| Invalid CSS rules with impossible ratios | VERIFIED | `src/challenge/css.rs:141-158` | Uses negative/zero denominators |
| HoneypotTracker | VERIFIED | `src/challenge/honeypot.rs` | Full implementation |
| Hidden links with CSS | VERIFIED | `src/challenge/honeypot.rs:137` | `display:none;visibility:hidden...` confirmed |
| Per-IP trap paths with TTL | VERIFIED | `src/challenge/honeypot.rs:76-111` | `generate_for_ip` and `get_or_generate` confirmed |
| JS Challenge | **NOT VERIFIED** | `src/challenge/` | No `js.rs` found. Only `css.rs`, `honeypot.rs`, `pow.rs`, `mesh_pow.rs` |
| Proof of Work (PoW) | VERIFIED | `src/wasm_pow/src/lib.rs` | WASM PoW found |
| Behavioral Analysis | VERIFIED | `src/waf/attack_detection/behavioral.rs` | `BehavioralEngine` found |

**Issue Found**: Document claims JS Challenge at `src/challenge/js.rs` but file does not exist. Actual location is `src/challenge/pow.rs` (Proof of Work).

### 5. Streaming WAF

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| StreamingWafCore | VERIFIED | `src/waf/attack_detection/streaming.rs` | Full implementation |
| Default chunk size 4096 bytes | VERIFIED | `src/waf/attack_detection/streaming.rs:8` | `DEFAULT_CHUNK_SIZE: usize = 4096` |
| Trailing window 512 bytes | VERIFIED | `src/waf/attack_detection/streaming.rs:46` | `const TRAILING_WINDOW_SIZE: usize = 512;` |
| max_buffered_bytes default 2MB | VERIFIED | `src/waf/attack_detection/streaming.rs:9` | `DEFAULT_MAX_BUFFERED_BYTES: usize = 2 * 1024 * 1024` |
| Multipart state machine | VERIFIED | `src/waf/attack_detection/streaming.rs:26-32` | States confirmed |
| File content scanning skipped | VERIFIED | `src/waf/attack_detection/streaming.rs:177-178` | Skips files with `filename=` |

### 6. BufferPool Architecture

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Four buffer tiers (4KB, 64KB, 256KB, 256KB+) | VERIFIED | `crates/synvoid-utils/src/buffer/pool.rs:7-9` | Confirmed |
| 8 shards | VERIFIED | `crates/synvoid-utils/src/buffer/pool.rs:16` | `const NUM_SHARDS: usize = 8;` |
| TLS cache 16 buffers per tier | VERIFIED | `crates/synvoid-utils/src/buffer/pool.rs:17` | `const TLS_CACHE_SIZE: usize = 16;` |
| PooledBuf lifecycle | VERIFIED | `crates/synvoid-utils/src/buffer/pool.rs:645-660` | `Drop` implementation confirmed |

### 7. Async WAF Pipeline

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Pipeline at `src/waf/mod.rs:484-512` | **NOT VERIFIED** | `src/waf/mod.rs:484-512` | Pipeline logic exists but line numbers differ slightly (484-515) |
| Parallel Attack Detection via async | VERIFIED | `src/waf/mod.rs:489-491` | `ad.check_request(...).await` confirmed |

---

## Bug Report

### Critical: StreamingWafCore trailing window logic incorrect

**File**: `src/waf/attack_detection/streaming.rs:129-134`

**Issue**: When updating the trailing window for regular (non-multipart) chunks, the code does:
```rust
self.state.trailing_window.clear();
let window_start = chunk.len().saturating_sub(TRAILING_WINDOW_SIZE);
self.state.trailing_window.extend_from_slice(&chunk[window_start..]);
```

This copies only the LAST 512 bytes of the CURRENT chunk into the trailing window. But for attack detection spanning chunk boundaries, the trailing window should contain the END of the PREVIOUS chunk + beginning of CURRENT chunk.

**Impact**: Attacks like `1' OR '1'='1'` split across chunks may not be detected properly if the split point is not at the chunk boundary.

**Fix Needed**: The trailing window should be a sliding window that accumulates:
1. The previous trailing window (up to TRAILING_WINDOW_SIZE bytes)
2. As much of the current chunk as fits in TRAILING_WINDOW_SIZE

Or alternatively, when scanning, combine `[previous_trailing, current_chunk]` as the scan region.

---

## Improvement Plan

### High Priority

| ID | Issue | Location | Recommendation |
|----|-------|----------|----------------|
| IMP-1 | Document claims `src/challenge/js.rs` for JS Challenge but file doesn't exist | `architecture/waf_deep_dive.md:72` | Update document to reference `src/challenge/pow.rs` or clarify that "JS Challenge" refers to PoW in WASM |
| IMP-2 | GeoIP blocking documented as "not fully implemented" - this is correct | `src/waf/asn_tracker.rs` | Consider completing GeoIP country blocking implementation |
| IMP-3 | Behavioral analysis is Mesh-only but documentation doesn't emphasize this | `src/waf/attack_detection/mod.rs:77-79` | Add feature-gate comments in code; update docs to clearly state "Mesh mode only" |

### Medium Priority

| ID | Issue | Location | Recommendation |
|----|-------|----------|----------------|
| IMP-4 | `check_body_fragments()` in streaming WAF should be documented as zero-copy | `src/waf/attack_detection/streaming.rs:118` | Add code comments explaining the fragmented scan approach |
| IMP-5 | FloodConfig has many hardcoded defaults that should be configurable | `src/waf/flood/mod.rs:40-56` | Consider moving more defaults to config structs |
| IMP-6 | `ConnectionLimiter` uses `connection_burst` from config but doc says "default 10" | `src/waf/traffic_shaper/limiter.rs:96` | Document should say "configurable burst tokens" instead of hardcoded value |

### Low Priority

| ID | Issue | Location | Recommendation |
|----|-------|----------|----------------|
| IMP-7 | Some detector names in doc don't match file naming convention | `architecture/waf_deep_dive.md:51` | Consider standardizing: e.g., "SSTI Detector" vs "SstiDetector" |
| IMP-8 | Test coverage for streaming WAF multipart boundary crossing | `src/waf/attack_detection/streaming.rs:484-509` | Tests exist but could add more edge cases |
| IMP-9 | `FloodProtector` has `enter_blackhole`/`exit_blackhole` but doc doesn't describe blackhole behavior | `src/waf/flood/mod.rs:311-327` | Document the blackhole mechanism more explicitly |

---

## Summary

**Verified Claims**: ~80% of documented features match source code
**Critical Bug**: 1 (StreamingWafCore trailing window logic)
**High Priority Improvements**: 3
**Medium Priority Improvements**: 3
**Low Priority Improvements**: 3

The WAF module is generally well-implemented and matches the architecture document well. The main issues are:
1. A documentation error about JS Challenge location
2. The trailing window bug in streaming WAF
3. Missing feature-gate documentation for mesh-only features
