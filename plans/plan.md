# SynVoid Implementation Plan

**Status**: 🏗️ PLANNING (2026-05-06)
**Target**: 1M RPS with streaming WAF, plus bug fixes and security hardening
**Consolidated from**: `plans/*.md` review

---

## Overview

This plan consolidates actionable items from architecture reviews into parallelizable waves. Each wave can be executed by independent agents.

---

## Wave 1: Critical Security & Compile Fixes

*Can execute in parallel — no interdependencies*

### HIGH Priority — Security Fixes

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| WAF-1 | Fix `sanitize()` race condition - unconditional `client_ip` overwrites trusted proxy extraction | `src/waf/request_sanitization.rs:119` | Remove unconditional assignment; only set `client_ip` in else branch |
| WAF-2 | Enable anomaly scoring by default | `src/waf/attack_detection/config.rs:46-53` | Set `enabled: true` or provide migration path |
| MESH-1 | Fix OrgKeyManager Raft fallback race condition | `src/mesh/org_key_manager.rs:264-294` | Require Raft success for Global node revocations; do not fall back to DHT-only |
| MESH-2 | Enforce Genesis Key Default Deny | `src/mesh/dht/mod.rs:702-706` | Add startup validation that `authorized_genesis_keys` is non-empty |
| MESH-3 | Require signing keys for ML-KEM exchange | `src/mesh/ml_kem_key_exchange.rs:131-141` | Reject key exchange if node lacks signing keys; `pow_nonce` AND `pow_public_key` must both be present |
| NET-6 | Cookie missing HttpOnly flag | `src/http/server.rs:934`, `src/http3/server.rs:518` | Add `; HttpOnly` to cookie format string |

### HIGH Priority — Compile Blocker

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| NET-1 | `erased_http_client` field missing from `HttpServer` | `src/http/server.rs:494,546` | Add field to `HttpServer` struct or remove references |

### HIGH Priority — Critical Bugs

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| APP-3 | InstancePool panics on missing WASM file | `src/serverless/instance_pool.rs:160-176` | Return `Result<InstancePool, InstancePoolError>` instead of `.expect()` |
| APP-4 | Serverless cpu_fuel defaults to 0 (unlimited) | `src/serverless/instance_pool.rs:168` | Default to reasonable limit like `1000000` |
| APP-2 | Granian socket URL malformed (trailing colon) | `src/app_server/granian.rs:967` | Change `http://unix:{}:` to `http://unix:{}` |
| ROUT-1 | Fix retry off-by-one error | `src/proxy/mod.rs:956` | Change `attempt <= max_retries` to `attempt < max_retries` |
| ROUT-2 | Remove dead code in retry loop | `src/proxy/mod.rs:1004-1006` | Remove unreachable code after backend exhaustion break |

### HIGH Priority — IPC Security

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| IPC-1 | IPC key file deleted before use complete | `src/process/ipc_signed.rs:206,645` | Delete key file only after successful `IpcSigner` construction |
| IPC-2 | Nonce cache O(n) eviction under attack | `src/process/ipc_signed.rs:113-120` | Use `DashMap::pinned_calibrate` or BTreeMap-based expiration queue |

---

## Wave 2: IPC & Process Lifecycle Hardening

*Depends on Wave 1 compile fixes*

### HIGH Priority — IPC

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| IPC-3 | PID validation only on WorkerStarted | `src/master/ipc.rs:355-379` | Bind worker identity to accepted socket connection at connection time |

### MEDIUM Priority — IPC

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| IPC-4 | TokenBucket refill precision loss | `src/process/ipc_rate_limit.rs:130` | Use saturating arithmetic or track fractional tokens |
| IPC-5 | Rate limiter stale cleanup logic gap | `src/process/ipc_rate_limit.rs:52-61` | Move `retain()` outside locked section or use background task |
| IPC-6 | Windows sandbox parity gap | `src/platform/sandbox.rs:9-10` | Implement using `SetFileSecurity` with restrictive DACL |

### MEDIUM Priority — Process Lifecycle

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| PL-1 | Empty workers in status file | `src/overseer/process.rs:403-412` | Query worker status via IPC from master before writing status file |
| PL-2 | Timeout ignored in apply_upgrade | `src/overseer/process.rs:630-695` | Use `timeout_secs` for pre-health-check sleep duration |
| PL-3 | Sequential port health checks | `src/overseer/health.rs:299-308` | Use `futures::future::join_all` for parallel checks |
| PL-4 | Drain metrics inaccurate | `src/worker/drain_state.rs:186-190` | Use `Swap` ordering or guard to ensure drain complete only recorded once |
| PL-5 | Cannot apply from RecoveryNeeded state | `src/overseer/state.rs:108-110` | Consider allowing `can_apply()` from `RecoveryNeeded` |

### LOW Priority — IPC/Process

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| IPC-7 | FD passing tests ignored | `src/process/socket_fd.rs:617` | Add mock-based test |
| IPC-8 | Unused NonceCache struct | `src/process/ipc_signed.rs:65-97` | Remove or document why it exists |
| PL-6 | Silent binary fallback | `src/overseer/spawn.rs:27-29` | Log warning and use `current_exe()` with error handling |
| PL-7 | Blocking I/O in async context | `src/overseer/process.rs:973-974` | Use `tokio::fs` for file operations |
| PL-8 | Non-const atomic initialization | `src/overseer/drain_manager.rs:14` | Use `AtomicU64::new_initialized(1)` |

---

## Wave 3: WAF Core Streaming Optimization

*Phase 1 of 4-phase streaming work — can run parallel to other waves*

### Phase 1: WAF Core Allocation Optimization

| ID | Item | File | Description |
|----|------|------|-------------|
| WSTREAM-1 | Integrate BufferPool | `src/waf/attack_detection/streaming.rs` | Modify `StreamingWafCore` to use `synvoid_utils::buffer::Pool` for `trailing_window` and internal buffers |
| WSTREAM-2 | Thread-local normalization buffer | `src/waf/attack_detection/normalizer.rs` | Use existing `NORMALIZE_BUFFER` instead of creating new `String` in `process_regular_chunk` |
| WSTREAM-3 | Zero-copy boundary checks | `src/waf/attack_detection/` | Update `AttackDetector` to support fragmented scan API (`&[&[u8]]`) to scan `trailing_window` + `current_chunk` without merging |
| WSTREAM-4 | Multipart buffer pooling | `src/waf/attack_detection/` | Replace `MultipartState` `String` buffers with pooled `BytesMut` |

### Phase 2: True Streaming HTTP Handlers

| ID | Item | File | Description |
|----|------|------|-------------|
| WSTREAM-5 | Refactor body collection | `src/http/server.rs:4532` | Rename `collect_body_with_chunk_waf` to `stream_body_with_waf`. Return `WafStreamedBody` implementing `http_body::Body` instead of `Result<Bytes, ()>` |
| WSTREAM-6 | Async WAF scanning in stream | `src/waf/attack_detection/streaming.rs` | Implement `poll_frame` for `WafStreamedBody`: scan chunk via `StreamingWafCore::scan_chunk`, return blocked/continue frames |
| WSTREAM-7 | Update HTTP/1/2 handler | `src/http/server.rs` | Replace `collect_body_with_chunk_waf` logic in SECTION 10 with streaming implementation. Pass stream directly to `ProxyServer` |
| WSTREAM-8 | Update HTTP/3 handler | `src/http3/server.rs` | Align HTTP/3 chunk scanning with new streaming pattern |

### Phase 3: Proxy Layer Stream Support

| ID | Item | File | Description |
|----|------|------|-------------|
| WSTREAM-9 | Modify ProxyServer::handle_request | `src/proxy/mod.rs` | Accept `BoxBody<Bytes, Infallible>` or streaming body type instead of `Option<Bytes>` |
| WSTREAM-10 | Update forwarding logic | `src/proxy/mod.rs` | Ensure `forward_request` and `send_single_request` pipe request body stream to upstream without buffering |
| WSTREAM-11 | Backpressure handling | `src/proxy/mod.rs` | Ensure WAF scanning and client reading throttle appropriately via standard async backpressure when upstream is slow |

---

## Wave 4: Remaining High/Medium Priority Fixes

*Can execute in parallel with Wave 3*

### HIGH Priority

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| WAF-3 | Add CAPTCHA implementation or remove from docs | `src/architecture/waf_deep_dive.md:34-35` | Implement CAPTCHA integration or update documentation |
| APP-1 | StaticFileHandler zero-copy is not zero-copy | `src/static_files/mod.rs:110,827` | Implement true zero-copy with `tokio::fs::File` + `AsyncReadExt` in chunks, or `sendfile()` syscall |
| NET-2 | HTTP/3 streaming path missing per-site connection limiting | `src/http3/server.rs:238-249,576-612` | Apply per-site connection limiting earlier in streaming path |
| NET-3 | HTTP/3 missing strict protocol validation | `src/http3/server.rs` vs `src/http/server.rs:548` | Add protocol validation check like HTTP/1.1 has |
| NET-4 | TLS 1.2 BEAST vulnerability not enforced | `src/tls/cert_resolver.rs:270-286` | Fail closed if `tls_1_3_only` not set in production mode |
| MESH-4 | Fix OrgPublicKey quorum verification | `src/mesh/dht/signed.rs` | Store signer's public key in `QuorumSignature`; explicitly verify signature-to-key mapping |
| MESH-5 | Use constant-time comparison for security challenge | `src/mesh/security_challenge.rs:196` | Replace `solution != expected_solution` with `subtle::ConstantTimeEq` |
| MESH-6 | Add quorum precondition check | `src/mesh/org_key_manager.rs:530` | Require `total_signers > 0` before accepting quorum-based operations |

### MEDIUM Priority

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| WAF-4 | Fix `StreamingWafCore::reset()` buffer handling | `src/waf/attack_detection/streaming.rs:258` | Use `clear()` instead of `BufferPool::acquire(0)` to avoid memory leak |
| WAF-5 | Add rate limiting to CSS asset requests | `src/challenge/css.rs:181-216` | Add per-IP/per-session rate limiting to prevent session exhaustion |
| WAF-6 | Optimize bot allow list lookup (O(n) linear scan) | `src/waf/bot.rs:248-252` | Use HashSet for faster lookups |
| MESH-7 | Use cryptographic hash for DHT sharding | `src/mesh/dht/record_store.rs:31-38` | Replace djb2 with SHA-256 or cityhash |
| MESH-8 | Fix HybridSignature `from_bytes` panic | `src/mesh/hybrid_signature.rs:97` | Return `HybridSignatureError::InvalidFormat` instead of panicking |
| MESH-9 | Change AuditEvent.timestamp to u64 | `src/mesh/audit.rs:16` | Use u64 to match project conventions |
| MESH-10 | Optimize RecordStoreManager Clone | `src/mesh/transport.rs:539-596` | Use `Arc<ShardedRecordStore>` or implement more efficient cloning |
| ROUT-3 | Align active health check recovery threshold with passive (3 vs 2) | `src/upstream/health.rs:145` vs `src/upstream/pool.rs:206` | Make thresholds consistent |
| ROUT-4 | Add configuration option for XFF trusted proxies | `src/proxy/headers.rs:378` | Allow trusted internal proxies in XFF chain |
| ROUT-5 | Consider trie-based suffix domain matching | `src/router.rs:1081-1085` | Replace O(n) linear scan with trie for performance |
| ROUT-6 | Buffer response body streaming | `src/proxy/mod.rs:1127` | Stream response bodies instead of buffering at 1M RPS |
| ROUT-7 | Cache cleaned domains instead of cleaning per request | `src/router.rs:1053` | Store cleaned domains in HashMaps at config load time |
| ROUT-8 | Extract hardcoded timeouts to config | Multiple | Extract magic numbers to configuration constants |
| NET-5 | ACME token format not validated | `src/tls/acme.rs:377-378` | Add regex validation for base64url characters |
| NET-7 | Zero-copy threshold not configurable | `src/http3/server.rs:968` | Add `zero_copy_threshold_bytes` to `Http3Config` |
| NET-8 | HTTP/3 small response buffering | `src/http3/server.rs:994-1054` | Stream responses under 1MB threshold |
| NET-9 | TLS peek buffer too small (16 bytes) | `src/http/server.rs:549` | Increase buffer size or read until non-matching byte |
| APP-5 | Hidden file check is case-sensitive | `src/static_files/mod.rs:387` | Use `eq_ignore_ascii_case(".htaccess")` |
| APP-6 | FastCGI allows response header leakage | `src/fastcgi/mod.rs:15` | Make header filtering case-insensitive and expand list |
| APP-7 | Range requests load entire file into memory | `src/static_files/mod.rs:461-518` | Use `tokio::fs::File` with `seek()` and `read()` to only read requested ranges |
| APP-8 | PHP socket auto-detection silently fails | `src/php/mod.rs:30-43` | Log warnings when directory read fails |
| APP-9 | Granian forward_request creates new HTTP client each call | `src/app_server/granian.rs:1004-1008` | Store HTTP client in `GranianSupervisor` and reuse |
| BUF-1 | BufferPool jumbo tier hardcoded 256KB | `crates/synvoid-utils/src/buffer/pool.rs:203` | Make jumbo tier configurable via `BufferPoolConfig` |

### LOW Priority

| ID | Issue | File:Line | Action |
|----|-------|-----------|--------|
| WAF-7 | Add HMAC cookie signing to PoW | `src/challenge/pow.rs:231` | Sign cookie with secret key to prevent replay |
| WAF-8 | Fix `hex_chars_to_u32` overflow | `src/waf/attack_detection/normalizer.rs:25-31` | Add bounds check on shift operations |
| WAF-9 | Prevent duplicate cleanup threads | `src/waf/mod.rs:614-625` | Use OnceLock or track spawned state |
| WAF-10 | Document mesh-only behavioral analysis | `src/waf/attack_detection/mod.rs:192` | Update architecture documentation |
| ROUT-9 | Extract RouteTarget construction to helper/builder | `src/router.rs:469-932` | Reduce code duplication |
| ROUT-10 | Clarify apply_least_connections algorithm documentation | `src/upstream/pool.rs:331` | Document composite_load (40% conn + 60% CPU) vs pure connection count |
| ROUT-11 | Standardize health check consecutive success pattern | `src/upstream/health.rs:137` | Use `fetch_add(...).saturating_add(1)` consistently |
| APP-10 | PHP FCGI_ENV prefix uses non-standard format | `src/fastcgi/mod.rs:280` | Use standard environment variable names or document as SynVoid-specific |
| APP-11 | MinifierCache LRU eviction is O(n) | `src/static_files/minifier.rs:260-273` | Use `BTreeMap` with `Instant` as key, or `linked_hash_map` crate |
| APP-12 | InstancePool autoscaler has no cleanup on drop | `src/serverless/instance_pool.rs:399-437` | Add `shutdown_tx` sender for graceful shutdown |
| APP-13 | Granian auto-install has no transaction safety | `src/app_server/granian.rs:464-508` | Add integrity verification after pip install |
| NET-10 | HTTP/3 missing header_read_timeout | `src/http3/server.rs` | Add `header_read_timeout` to `Http3Config` for consistency |
| NET-11 | Inconsistent Alt-Svc header format | Multiple | Standardize Alt-Svc format across all protocols |

---

## Wave 5: Validation & Benchmarking

*Execute after Wave 3 (WAF streaming) complete*

### Phase 4: Validation

| ID | Item | Description |
|----|------|-------------|
| VAL-1 | Memory profiling | Use `dtrace` or `heaptrack` to confirm per-request allocations minimized |
| VAL-2 | Throughput benchmarking | Use `wrk2` to simulate 1M RPS against streaming stack. Compare with buffered implementation |
| VAL-3 | Split-chunk attack verification | Add test cases where attack payloads split across chunk boundaries where `trailing_window` applies |

---

## Testing Gaps

| Area | Files | Missing Tests |
|------|-------|---------------|
| PID spoofing detection | `src/master/ipc.rs` | Integration tests for PID validation on all message types |
| Status file population | `src/overseer/process.rs` | Tests for worker status collection and file writing |
| Concurrent drain completion | `src/worker/drain_state.rs` | Tests for multiple `mark_drain_complete` calls |
| Recovery state machine | `src/overseer/state.rs` | Tests for RecoveryNeeded → apply transition |
| Split-chunk attacks | `src/waf/attack_detection/` | Verification tests for trailing_window boundary cases |

---

## Verification Commands

```bash
# Core profile check
cargo check --no-default-features

# Mesh profile check
cargo check --no-default-features --features mesh

# Full profile check
cargo check --no-default-features --features mesh,dns

# Overseer module tests
cargo test --lib -- overseer

# Worker drain state tests
cargo test --lib -- worker::drain_state

# Master IPC tests
cargo test --lib -- master::ipc

# Format and lint
cargo fmt && cargo clippy --lib -- -D warnings

# Run all lib tests (compile check)
cargo test --lib --no-run
```

---

## Summary

| Wave | Items | Focus |
|------|-------|-------|
| 1 | ~13 | Critical security, compile blocker, IPC |
| 2 | ~13 | IPC/Process lifecycle hardening |
| 3 | ~11 | WAF streaming (Phases 1-3) |
| 4 | ~30 | Remaining HIGH/MEDIUM/LOW fixes |
| 5 | ~3 | Validation & benchmarking |
| **Total** | **~70** | |

---

## Reference Files

- `src/waf/attack_detection/streaming.rs`: Core streaming WAF logic
- `src/http/shared_handler.rs`: Current body collection implementation
- `src/http/server.rs`: Main HTTP/1/2 request handler
- `src/http3/server.rs`: Main HTTP/3 request handler
- `src/proxy/mod.rs`: Proxy forwarding logic
- `crates/synvoid-utils/src/buffer/pool.rs`: The high-performance `BufferPool`
- `src/process/ipc_signed.rs`: IPC signing and key management
- `src/mesh/` for mesh security issues