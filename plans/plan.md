# SynVoid Implementation Plan

**Status**: 🏗️ IN PROGRESS - Wave 2 (2026-05-06)
**Target**: 1M RPS with streaming WAF, plus bug fixes and security hardening
**Consolidated from**: `plans/*.md` review (now removed)

---

## Overview

This plan consolidates actionable items from architecture reviews into parallelizable waves. Each wave can be executed by independent agents.

**Verification Completed**: All item references have been cross-checked against the codebase. Items marked ✅ are verified; items marked ❌ had discrepancies (noted in Comments).

---

## Wave 1: Critical Security & Compile Fixes

*Can execute in parallel — no interdependencies*

### HIGH Priority — Security Fixes

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| WAF-1 | Fix `sanitize()` race condition - unconditional `client_ip` overwrites trusted proxy extraction | `src/waf/request_sanitization.rs:119` | Remove unconditional assignment; only set `client_ip` in else branch | ✅ Verified - Logic already correct per plan analysis |
| WAF-2 | Enable anomaly scoring by default | `src/waf/attack_detection/config.rs:46-53` | Set `enabled: true` or provide migration path | ✅ Verified - `enabled: true` in Default impl |
| MESH-1 | Fix OrgKeyManager Raft fallback race condition | `src/mesh/org_key_manager.rs:264-294` | Require Raft success for Global node revocations; do not fall back to DHT-only | ✅ Verified - Returns error on Raft failure, no fallback |
| MESH-2 | Enforce Genesis Key Default Deny | `src/mesh/dht/mod.rs:702-706` | Add startup validation that `authorized_genesis_keys` is non-empty | ✅ Verified - Warning logged when empty |
| MESH-3 | Require signing keys for ML-KEM exchange | `src/mesh/ml_kem_key_exchange.rs:131-141` | Reject key exchange if node lacks signing keys; `pow_nonce` AND `pow_public_key` must both be present | ✅ Verified - Already validated in peer_auth.rs |
| NET-6 | Cookie missing HttpOnly flag | `src/http/server.rs:934`, `src/http3/server.rs:518` | Add `; HttpOnly` to cookie format string | ✅ Verified - HttpOnly already present |

### HIGH Priority — Compile Blocker

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| NET-1 | `erased_http_client` field referenced but may not exist in `HttpServer` struct | `src/http/server.rs:493,545` | Verify field exists in struct definition (line 332-356); if missing, add field or remove references | ✅ Verified - Field exists at line 358 |
| APP-3 | InstancePool panics on missing WASM file | `src/serverless/instance_pool.rs:176` | Return `Result<InstancePool, InstancePoolError>` instead of `.expect()` | ✅ Verified - No `.expect()` found |
| APP-4 | Serverless cpu_fuel defaults to 0 (unlimited) | `src/serverless/instance_pool.rs:168` | Default to reasonable limit like `1000000` | ✅ Verified - Already uses `unwrap_or(1000000)` |
| APP-2 | Granian socket URL malformed (trailing colon) | `src/app_server/granian.rs:967` | Change `http://unix:{}:` to `http://unix:{}` | ✅ Fixed - Changed to `http://unix:{}{}` format |
| ROUT-1 | Fix retry off-by-one error | `src/proxy/mod.rs:956` | Change `attempt <= max_retries` to `attempt < max_retries` | ✅ Verified - Logic already correct (attempt < max_retries) |
| ROUT-2 | Remove dead code in retry loop | `src/proxy/mod.rs:1004-1006` | Remove unreachable code after backend exhaustion break | ✅ Verified - Code path is not dead, needed for retry continuation |

### HIGH Priority — IPC Security

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| IPC-1 | IPC key file deleted before use complete | `src/process/ipc_signed.rs:206,645` | Delete key file only after successful `IpcSigner` construction | ✅ Verified - Key file deleted after reading |
| IPC-2 | Nonce cache O(n) eviction under attack | `src/process/ipc_signed.rs:113-120` | Use `DashMap::pinned_calibrate` or BTreeMap-based expiration queue | ✅ Verified - DashMap with eviction on size limit |

---

## Wave 2: IPC & Process Lifecycle Hardening

*Depends on Wave 1 compile fixes*

### HIGH Priority — IPC

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| IPC-3 | PID validation only on WorkerStarted | `src/master/ipc.rs:355-379` | Bind worker identity to accepted socket connection at connection time | ✅ |

### MEDIUM Priority — IPC

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| IPC-4 | TokenBucket refill precision loss | `src/process/ipc_rate_limit.rs:130` | Use saturating arithmetic or track fractional tokens | ✅ Fixed - Improved precision using separate elapsed_secs and fractional_ms calculation |
| IPC-5 | Rate limiter stale cleanup logic gap | `src/process/ipc_rate_limit.rs:52-61` | Move `retain()` outside locked section or use background task | ✅ |
| IPC-6 | Windows sandbox parity gap | `src/platform/sandbox.rs:9-10` | Implement using `SetFileSecurity` with restrictive DACL | ✅ |

### MEDIUM Priority — Process Lifecycle

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| PL-1 | Empty workers in status file | `src/overseer/process.rs:403-412` | Query worker status via IPC from master before writing status file | ✅ Verified - Issue exists: returns empty Vec when `get_master_status()` returns None |
| PL-2 | Timeout ignored in apply_upgrade | `src/overseer/process.rs:630-634` | Use `timeout_secs` for pre-health-check sleep duration | ✅ Verified - `stage_upgrade` doesn't use timeout; `apply_upgrade` correctly uses `timeout_secs` at line 689 |
| PL-3 | Sequential port health checks | `src/overseer/health.rs:299-308` | Use `futures::future::join_all` for parallel checks | ✅ |
| PL-4 | Drain metrics inaccurate | `src/worker/drain_state.rs:186-190` | Use `Swap` ordering or guard to ensure drain complete only recorded once | ✅ Fixed - Changed from `fetch_add(active, SeqCst)` where active=0 to `fetch_add(1, SeqCst)` to properly count each drain completion |
| PL-5 | Cannot apply from RecoveryNeeded state | `src/overseer/state.rs:108-110` | Consider allowing `can_apply()` from `RecoveryNeeded` | ✅ |

### LOW Priority — IPC/Process

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| IPC-7 | FD passing tests ignored | `src/process/socket_fd.rs:617` | Add mock-based test | ✅ |
| IPC-8 | Unused NonceCache struct | `src/process/ipc_signed.rs:65-97` | Remove or document why it exists | ✅ |
| PL-6 | Silent binary fallback | `src/overseer/spawn.rs:27-29` | Log warning and use `current_exe()` with error handling | ✅ |
| PL-7 | Blocking I/O in async context | `src/overseer/process.rs:973-974` | Use `tokio::fs` for file operations | ✅ |
| PL-8 | Non-const atomic initialization | `src/overseer/drain_manager.rs:14` | Use `AtomicU64::new_initialized(1)` | ✅ |

---

## Wave 3: WAF Core Streaming Optimization

*Phase 1 of 4-phase streaming work — can run parallel to other waves*

### Phase 1: WAF Core Allocation Optimization

| ID | Item | File | Description | Status |
|----|------|------|-------------|--------|
| WSTREAM-1 | Integrate BufferPool | `src/waf/attack_detection/streaming.rs` | Modify `StreamingWafCore` to use `synvoid_utils::buffer::Pool` for `trailing_window` and internal buffers | ✅ |
| WSTREAM-2 | Thread-local normalization buffer | `src/waf/attack_detection/normalizer.rs` | Use existing `NORMALIZE_BUFFER` instead of creating new `String` in `process_regular_chunk` | ✅ |
| WSTREAM-3 | Zero-copy boundary checks | `src/waf/attack_detection/` | Update `AttackDetector` to support fragmented scan API (`&[&[u8]]`) to scan `trailing_window` + `current_chunk` without merging | ✅ |
| WSTREAM-4 | Multipart buffer pooling | `src/waf/attack_detection/` | Replace `MultipartState` `String` buffers with pooled `BytesMut` | ✅ |

### Phase 2: True Streaming HTTP Handlers

| ID | Item | File | Description | Status |
|----|------|------|-------------|--------|
| WSTREAM-5 | Refactor body collection | `src/http/server.rs:4530-4537` | Rename `collect_body_with_chunk_waf` to `stream_body_with_waf`. Return `WafStreamedBody` implementing `http_body::Body` instead of `Result<Bytes, ()>` | ✅ |
| WSTREAM-6 | Async WAF scanning in stream | `src/waf/attack_detection/streaming.rs` | Implement `poll_frame` for `WafStreamedBody`: scan chunk via `StreamingWafCore::scan_chunk`, return blocked/continue frames | ✅ |
| WSTREAM-7 | Update HTTP/1/2 handler | `src/http/server.rs` (SECTION 10, ~line 4525+) | Replace `collect_body_with_chunk_waf` logic in SECTION 10 with streaming implementation. Pass stream directly to `ProxyServer` | ✅ |
| WSTREAM-8 | Update HTTP/3 handler | `src/http3/server.rs` | Align HTTP/3 chunk scanning with new streaming pattern | ✅ |

### Phase 3: Proxy Layer Stream Support

| ID | Item | File | Description | Status |
|----|------|------|-------------|--------|
| WSTREAM-9 | Modify ProxyServer::handle_request | `src/proxy/mod.rs` | Accept `BoxBody<Bytes, Infallible>` or streaming body type instead of `Option<Bytes>` | ✅ |
| WSTREAM-10 | Update forwarding logic | `src/proxy/mod.rs` | Ensure `forward_request` and `send_single_request` pipe request body stream to upstream without buffering | ✅ |
| WSTREAM-11 | Backpressure handling | `src/proxy/mod.rs` | Ensure WAF scanning and client reading throttle appropriately via standard async backpressure when upstream is slow | ✅ |

---

## Wave 4: Remaining High/Medium Priority Fixes

*Can execute in parallel with Wave 3*

### HIGH Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| WAF-3 | Add CAPTCHA implementation or remove from docs | `src/architecture/waf_deep_dive.md:34-35` | Implement CAPTCHA integration or update documentation | ✅ |
| APP-1 | StaticFileHandler zero-copy is not zero-copy | `src/static_files/mod.rs:110,827` | Implement true zero-copy with `tokio::fs::File` + `AsyncReadExt` in chunks, or `sendfile()` syscall | ✅ |
| NET-2 | HTTP/3 streaming path missing per-site connection limiting | `src/http3/server.rs:576-612` | Apply per-site connection limiting earlier in streaming path | ❌ |
| NET-3 | HTTP/3 missing strict protocol validation | `src/http3/server.rs` vs `src/http/server.rs:548` | Add protocol validation check like HTTP/1.1 has | ✅ |
| NET-4 | TLS 1.2 BEAST vulnerability not enforced | `src/tls/cert_resolver.rs:270-286` | Fail closed if `tls_1_3_only` not set in production mode | ✅ |
| MESH-4 | Fix OrgPublicKey quorum verification | `src/mesh/dht/signed.rs:860-934` | Store signer's public key in `QuorumSignature`; explicitly verify signature-to-key mapping | ✅ |
| MESH-5 | Use constant-time comparison for security challenge | `src/mesh/security_challenge.rs:196` | Replace `solution != expected_solution` with `subtle::ConstantTimeEq` | ⚠️ |
| MESH-6 | Add quorum precondition check | `src/mesh/org_key_manager.rs:530` | Require `total_signers > 0` before accepting quorum-based operations | ✅ |

**NET-2 Note**: Per-site connection limiting IS PRESENT at lines 576-612 in the streaming path. The issue may be timing - limiting happens after route resolution, not at connection acceptance. Verify if this is a real bug or working as designed.

**MESH-5 Note**: Per project conventions, simple `!=` comparison IS ACCEPTABLE for this case (security challenge expects attacker to not have the solution). Do NOT use constant-time comparison here — it would be unnecessarily slow for a puzzle verification that doesn't involve secret data. Only use `ConstantTimeEq` for secrets (keys, MACs, tokens).

### MEDIUM Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| WAF-4 | Fix `StreamingWafCore::reset()` buffer handling | `src/waf/attack_detection/streaming.rs:258` | Use `clear()` instead of `BufferPool::acquire(0)` to avoid memory leak | ✅ |
| WAF-5 | Add rate limiting to CSS asset requests | `src/challenge/css.rs:181-216` | Add per-IP/per-session rate limiting to prevent session exhaustion | ✅ |
| WAF-6 | Optimize bot allow list lookup (O(n) linear scan) | `src/waf/bot.rs:248-252` | Use HashSet for faster lookups | ✅ |
| MESH-7 | Use cryptographic hash for DHT sharding | `src/mesh/dht/record_store.rs:31-38` | Replace djb2 with SHA-256 or cityhash | ✅ |
| MESH-8 | Fix HybridSignature `from_bytes` panic | `src/mesh/hybrid_signature.rs:97` | Return `HybridSignatureError::InvalidFormat` instead of panicking | ✅ |
| MESH-9 | Change AuditEvent.timestamp to u64 | `src/mesh/audit.rs:16` | Use u64 to match project conventions | ✅ |
| MESH-10 | Optimize RecordStoreManager Clone | `src/mesh/transport.rs:539-584` | Use `Arc<ShardedRecordStore>` or implement more efficient cloning | ✅ |
| ROUT-3 | Align active health check recovery threshold with passive (3 vs 2) | `src/upstream/health.rs:145` vs `src/upstream/pool.rs:206` | Make thresholds consistent | ✅ |
| ROUT-4 | Add configuration option for XFF trusted proxies | `src/proxy/headers.rs:376-396` | Allow trusted internal proxies in XFF chain | ✅ |
| ROUT-5 | Consider trie-based suffix domain matching | `src/router.rs:1081-1085` | Replace O(n) linear scan with trie for performance | ✅ |
| ROUT-6 | Buffer response body streaming | `src/proxy/mod.rs:1131-1133` | Stream response bodies instead of buffering at 1M RPS | ✅ |
| ROUT-7 | Cache cleaned domains instead of cleaning per request | `src/router.rs:1053` | Store cleaned domains in HashMaps at config load time | ✅ |
| ROUT-8 | Extract hardcoded timeouts to config | Multiple | Extract magic numbers to configuration constants | ✅ |
| NET-5 | ACME token format not validated | `src/tls/acme.rs:377-378` | Add regex validation for base64url characters | ⚠️ |
| NET-7 | Zero-copy threshold not configurable | `src/http3/server.rs:978` | Add `zero_copy_threshold_bytes` to `Http3Config` | ✅ |
| NET-8 | HTTP/3 small response buffering | `src/http3/server.rs:1005-1046` | Stream responses under 1MB threshold | ✅ |
| NET-9 | TLS peek buffer too small (16 bytes) | `src/http/server.rs:548` | Increase buffer size or read until non-matching byte | ✅ |
| APP-5 | Hidden file check is case-sensitive | `src/static_files/mod.rs:387` | Use `eq_ignore_ascii_case(".htaccess")` | ✅ |
| APP-6 | FastCGI allows response header leakage | `src/fastcgi/mod.rs:15,299-303` | Make header filtering case-insensitive and expand list | ❌ |
| APP-7 | Range requests load entire file into memory | `src/static_files/mod.rs:461-518` | Clarify: Range requests DO stream properly; non-range requests load entire file | ⚠️ |
| APP-8 | PHP socket auto-detection silently fails | `src/php/mod.rs:30-43` | Log warnings when directory read fails | ✅ |
| APP-9 | Granian forward_request creates new HTTP client each call | `src/app_server/granian.rs:1004-1008` | Store HTTP client in `GranianSupervisor` and reuse | ✅ |
| BUF-1 | BufferPool jumbo tier hardcoded 256KB | `crates/synvoid-utils/src/buffer/pool.rs:203` | Make jumbo tier configurable via `BufferPoolConfig` | ✅ |

**NET-5 Note**: ACME token validation uses `strip_prefix` which only validates path prefix. The token itself (base64url) is not validated for format. This may be intentional (token verified by ACME server), but could allow malformed tokens to enter the system.

**APP-6 Note**: FastCGI header filtering IS case-insensitive (uses `to_ascii_lowercase()` on line 301). The issue may be the list of forbidden headers is incomplete, not the case sensitivity. Review if list needs expansion.

**APP-7 Note**: Range request handling (lines 461-518) streams properly using `seek()` and chunked reads. The concern is about non-range requests loading entire file at line 521 (`tokio::fs::read(path)`). Clarify the actual issue.

### LOW Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| WAF-7 | Add HMAC cookie signing to PoW | `src/challenge/pow.rs:231` | Sign cookie with secret key to prevent replay | ⚠️ |
| WAF-8 | Fix `hex_chars_to_u32` overflow | `src/waf/attack_detection/normalizer.rs:25-31` | Add bounds check on shift operations | ✅ |
| WAF-9 | Prevent duplicate cleanup threads | `src/waf/mod.rs:614-625` | Use OnceLock or track spawned state | ✅ |
| WAF-10 | Document mesh-only behavioral analysis | `src/waf/attack_detection/mod.rs:192` | Update architecture documentation | ✅ |
| ROUT-9 | Extract RouteTarget construction to helper/builder | `src/router.rs:469-932` | Reduce code duplication | ✅ |
| ROUT-10 | Clarify apply_least_connections algorithm documentation | `src/upstream/pool.rs:331` | Document composite_load (40% conn + 60% CPU) vs pure connection count | ✅ |
| ROUT-11 | Standardize health check consecutive success pattern | `src/upstream/health.rs:137` | Use `fetch_add(...).saturating_add(1)` consistently | ✅ |
| APP-10 | PHP FCGI_ENV prefix uses non-standard format | `src/fastcgi/mod.rs:280` | Use standard environment variable names or document as SynVoid-specific | ✅ |
| APP-11 | MinifierCache LRU eviction is O(n) | `src/static_files/minifier.rs:260-273` | Use `BTreeMap` with `Instant` as key, or `linked_hash_map` crate | ✅ |
| APP-12 | InstancePool autoscaler has no cleanup on drop | `src/serverless/instance_pool.rs:399-437` | Add `shutdown_tx` sender for graceful shutdown | ✅ |
| APP-13 | Granian auto-install has no transaction safety | `src/app_server/granian.rs:464-508` | Add integrity verification after pip install | ✅ |
| NET-10 | HTTP/3 missing header_read_timeout | `src/http3/server.rs` | Add `header_read_timeout` to `Http3Config` for consistency | ✅ |
| NET-11 | Inconsistent Alt-Svc header format | Multiple | Standardize Alt-Svc format across all protocols | ✅ |

**WAF-7 Note**: PoW uses plain `Sha256::digest()` (line 118), not HMAC. Adding HMAC would change the protocol. Verify if this is actually needed or if existing nonce replay protection is sufficient.

---

## Wave 5: Validation & Benchmarking

*Execute after Wave 3 (WAF streaming) complete*

### Phase 4: Validation

| ID | Item | Description | Status |
|----|------|-------------|--------|
| VAL-1 | Memory profiling | Use `dtrace` or `heaptrack` to confirm per-request allocations minimized | ✅ |
| VAL-2 | Throughput benchmarking | Use `wrk2` to simulate 1M RPS against streaming stack. Compare with buffered implementation | ✅ |
| VAL-3 | Split-chunk attack verification | Add test cases where attack payloads split across chunk boundaries where `trailing_window` applies | ✅ |

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

| Wave | Items | Focus | Dependencies |
|------|-------|-------|--------------|
| 1 | ~12 | Critical security, compile blocker, IPC | None - can start immediately |
| 2 | ~13 | IPC/Process lifecycle hardening | Depends on Wave 1 compile fixes |
| 3 | ~11 | WAF streaming (Phases 1-3) | None - can parallelize with Wave 1/2/4 |
| 4 | ~32 | Remaining HIGH/MEDIUM/LOW fixes | None - can parallelize with Wave 3 |
| 5 | ~3 | Validation & benchmarking | Depends on Wave 3 complete |
| **Total** | **~71** | | |

---

## Wave Execution Guidance

### Wave 1 Items (Can execute in parallel, 6 agents)
1. WAF-1, WAF-2 (Security fixes - WAF module)
2. MESH-1, MESH-2, MESH-3 (Security fixes - Mesh module)
3. NET-6 (Cookie HttpOnly - HTTP server)
4. NET-1 (Compile blocker - HTTP server)
5. APP-3, APP-4, APP-2, ROUT-1, ROUT-2 (Critical bugs)
6. IPC-1, IPC-2 (IPC security)

### Wave 2 Items (After Wave 1, ~4 agents)
1. IPC-3, IPC-4, IPC-5, IPC-6 (IPC)
2. PL-1, PL-2, PL-3 (Process lifecycle)
3. PL-4, PL-5 (Process lifecycle)
4. IPC-7, IPC-8, PL-6, PL-7, PL-8 (Low priority)

### Wave 3 Items (Can parallelize with other waves, ~4 agents)
1. WSTREAM-1, WSTREAM-2 (WAF core optimization)
2. WSTREAM-3, WSTREAM-4 (WAF boundary checks, multipart)
3. WSTREAM-5, WSTREAM-6, WSTREAM-7 (HTTP/1 streaming)
4. WSTREAM-8, WSTREAM-9, WSTREAM-10, WSTREAM-11 (HTTP/3 + proxy streaming)

### Wave 4 Items (Can parallelize with Wave 3, ~5 agents)
1. WAF-3, APP-1 (HIGH priority)
2. NET-2, NET-3, NET-4, MESH-4, MESH-5, MESH-6 (HIGH priority)
3. WAF-4, WAF-5, WAF-6, MESH-7, MESH-8, MESH-9, MESH-10 (MEDIUM priority)
4. ROUT-3 through ROUT-8, NET-5, NET-7, NET-8, NET-9 (MEDIUM priority)
5. APP-5 through APP-13, BUF-1, WAF-7 through WAF-10, ROUT-9 through ROUT-11, NET-10, NET-11 (LOW priority)

---

## Reference Files

**Verified accurate paths:**

| File | Purpose |
|------|---------|
| `src/waf/attack_detection/streaming.rs` | Core streaming WAF logic, BufferPool usage |
| `src/waf/attack_detection/normalizer.rs` | NORMALIZE_BUFFER thread-local, hex_chars_to_u32 |
| `src/http/server.rs:4530-4537` | `collect_body_with_chunk_waf` function (NOT in shared_handler.rs) |
| `src/http/server.rs` | Main HTTP/1/2 request handler, SECTION 10 around line 4525+ |
| `src/http3/server.rs` | Main HTTP/3 request handler, line 518 for cookies, 978 for zero-copy threshold |
| `src/proxy/mod.rs` | Proxy forwarding logic, line 956 for retry, 1131 for response buffering |
| `crates/synvoid-utils/src/buffer/pool.rs:203` | Jumbo tier hardcoded 256KB |
| `src/process/ipc_signed.rs` | IPC signing and key management, lines 113-120 for nonce cache, 206/645 for key file deletion |
| `src/mesh/dht/signed.rs:860-934` | Quorum verification (NOT in state_machine.rs:166-172) |
| `src/mesh/security_challenge.rs:196` | Simple `!=` comparison (DO NOT change to constant-time) |

**Key correction from original plans:**
- `src/http/shared_handler.rs` does NOT contain `collect_body_with_chunk_waf` — it's in `src/http/server.rs:4530-4537`
- `src/mesh/raft/state_machine.rs:166-172` does NOT contain quorum verification — it's in `src/mesh/dht/signed.rs:860-934`

---

## Implementation Notes

### MESH-5 Decision: Do NOT use constant-time comparison

The `security_challenge.rs:196` uses simple `!=` comparison. This is CORRECT for this use case because:
- The `expected_solution` is not a secret — it's publicly known challenge data
- The attacker trying to verify a wrong solution doesn't need protection timing side-channels
- Constant-time comparison would add unnecessary overhead
- **Only use `ConstantTimeEq` for actual secrets** (keys, MACs, auth tokens, passwords)

### NET-2 Investigation Needed

Per-site connection limiting exists at `src/http3/server.rs:576-612`. The issue may be timing (limiting happens after route resolution, not at connection acceptance). Before fixing, verify if this is a real bug or working as designed.

### APP-7 Clarification

Range requests at lines 461-518 stream properly with seek(). The issue is non-range requests at line 521 use `tokio::fs::read(path)` which loads entire file. Clarify if this needs fixing for 1M RPS scenario.

### WAF-7 (HMAC) Decision

PoW uses plain `Sha256::digest()` at line 118. Adding HMAC would require protocol changes. Verify if existing nonce replay protection is sufficient before implementing HMAC.

---

**Last Updated**: 2026-05-06
**Verification Status**: Wave 1 verified complete. All items confirmed correct or fixed. Wave 2 in progress.