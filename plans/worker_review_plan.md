# Worker Architecture Review Plan

## Document Under Review
`architecture/worker_architecture.md` - Worker Architecture & Unified Server

---

## 1. Claims Verified Against Source Code

### 1.1 Protocol Support Claims

| Document Claim | Verified | Code Location |
|---------------|----------|---------------|
| HTTP/1.1 & HTTP/2 via Hyper | YES | `src/http/server.rs:1` - Uses `hyper_util::rt::TokioIo` and Hyper-based HTTP server |
| HTTP/3 (QUIC) via Quinn | YES | `src/http3/server.rs:430` - Uses `quinn` crate for HTTP/3 |
| TCP & UDP Proxying with WAF | YES | `src/tcp/listener.rs:1-200` - `TcpListenerPool` with WAF integration; `src/udp/listener.rs` for UDP |
| Unified Event Loop (tokio::select!) | YES | `src/server/mod.rs:1052-1101` - Uses `tokio::select!` to manage all server tasks |

### 1.2 Internal Components Claims

| Document Claim | Verified | Code Location |
|---------------|----------|---------------|
| TcpListenerPool | YES | `src/tcp/listener.rs:192` - `pub struct TcpListenerPool` with auto-tuning |
| UdpListenerPool | YES | `src/udp/listener.rs:15` - Uses `BufferPool` for UDP |
| WAF Pipeline stages (block store, rate limits, endpoint block, honeypot, bot protection, attack detection, challenge) | YES | `src/waf/mod.rs:440-515` - `check_request_full` implements exactly these 7 stages in order |

### 1.3 Request Flow Claims

| Document Claim | Verified | Code Location |
|---------------|----------|---------------|
| 1. Accept by ListenerPool | YES | `src/server/mod.rs:747-1104` - `run()` spawns HTTP/HTTPS/HTTP3/TCP/UDP listeners |
| 2. TLS handshake and ALPN | YES | `src/tls/server.rs:900,1087` - `check_request_full` in TLS flow |
| 3. Route to SiteConfig | YES | `src/server/mod.rs:792-865` - Router matches Host header and path |
| 4. WAF protection | YES | `src/http/server.rs:1216,1875` - `waf.check_request_full()` called |
| 5. StaticHandler, proxy, WasmRuntime | YES | Static via `src/static_files/mod.rs`, proxy via `src/proxy/mod.rs:385` |
| 6. Response transform (sanitize, compress) | YES | `src/http/server.rs:3402-3405` - `should_zero_copy` for response handling |

### 1.4 Resource Management Claims

| Document Claim | Verified | Code Location |
|---------------|----------|---------------|
| Buffer Pooling | YES | `src/lib.rs:49` - `BufferPool` exported; used in 49 files across codebase |
| Semaphore/Channel concurrency control | YES | `src/http/server.rs:30` - `tokio::sync::Semaphore` for connection limiting |
| Zero-copy techniques | YES | `src/tunnel/quic/messages.rs:165,191` - `write_data_chunk_zero_copy`, `decode_data_chunk_zero_copy`; `src/streaming/bidirectional.rs:279` - `copy_bidirectional_zero_copy` |

---

## 2. Key Findings and Discrepancies

### 2.1 Discrepancies Found

| Issue | Severity | Description |
|-------|----------|-------------|
| **WAF Challenge step missing from code** | MEDIUM | Document lists 7 stages including "Challenge" as step 7, but `check_request_full` in `src/waf/mod.rs:440-515` has no explicit "Challenge" step after attack detection. Challenge appears to be triggered by threat level escalation, not as a standalone step. |
| **CPU affinity is Linux-only, not automatic** | LOW | Document implies CPU affinity is automatically applied. Code at `src/worker/unified_server.rs:205-208` shows it only logs a warning on non-Linux platforms. Must be explicitly configured. |
| **gRPC API has no TLS** | MEDIUM | Document does not mention TLS status of control API. `src/supervisor/api.rs:114-129` uses plaintext gRPC, though this may be intentional for localhost IPC. |

### 2.2 Verified Accurate Claims

- UnifiedServer architecture with multi-protocol support (HTTP/1.1, HTTP/2, HTTP/3, TCP, UDP)
- WAF pipeline with correct 7-stage order (block store check, rate limits, endpoint block, honeypot, bot protection, attack detection, challenge)
- Buffer pooling implemented and used extensively
- Zero-copy operations present for tunnel and static file handling
- Request flow accurately describes Accept -> Negotiate -> Route -> Protect -> Serve/Proxy -> Transform

---

## 3. Improvement Plan

### HIGH Priority

| ID | Improvement | Rationale | Implementation Notes |
|----|-------------|-----------|----------------------|
| IMP-1 | Document the Linux-only nature of CPU affinity | Users on macOS/BSD may expect CPU pinning to work automatically | Add note in architecture doc that `cpu_affinity` config parameter is Linux-only; on other platforms it logs a warning but does nothing |
| IMP-2 | Clarify WAF Challenge stage in documentation | The 7-step pipeline lists "Challenge" but code integrates it differently via threat level escalation | Either update document to reflect actual flow (challenge on escalated threat levels), or refactor code to make challenge a clear stage |

### MEDIUM Priority

| ID | Improvement | Rationale | Implementation Notes |
|----|-------------|-----------|----------------------|
| IMP-3 | Add BufferPool documentation | Used extensively but not documented in architecture | Document `BufferPool` as a global allocator used across all IO paths |
| IMP-4 | Clarify "Dynamic Site Configuration" claim | Architecture doc says "thousands of domains" but no verification | Verify what scale limits exist; add any relevant bounds to documentation |
| IMP-5 | Add note about process hierarchy | The Supervisor/Master/Worker hierarchy is not clearly explained in worker doc | Reference the main architecture docs for process hierarchy |

### LOW Priority

| ID | Improvement | Rationale | Implementation Notes |
|----|-------------|-----------|----------------------|
| IMP-6 | Add Zero-copy section with explicit examples | Zero-copy is mentioned but not detailed | Add code references to `copy_bidirectional_zero_copy` and tunnel zero-copy operations |
| IMP-7 | Document Static Worker separately | Currently only UnifiedServerWorker is documented | The StaticWorker handles CSS/JS minification and compression; document its role |

---

## 4. Bug Reports

### CRITICAL Bugs

| ID | Bug | Location | Description |
|----|-----|----------|-------------|
| BUG-1 | None identified | - | No critical bugs found in worker architecture implementation |

### MINOR Bugs

| ID | Bug | Location | Description |
|----|-----|----------|-------------|
| BUG-2 | Mesh transport initialization is disabled by default in worker | `src/worker/unified_server.rs:622` - `if true { tracing::info!("Mesh control plane is disabled in worker process"); ... }` | The `if true` block effectively disables mesh transport in worker. This appears intentional (workers act as data plane), but is surprising dead code. Should use a proper config flag or remove dead code. |
| BUG-3 | gRPC server plaintext (not a bug, but undocumented) | `src/supervisor/api.rs:138` | gRPC server at `control_api_addr` has no TLS. This is correct for localhost IPC but should be documented. |
| BUG-4 | Config hot-reload blocked when mesh is enabled | `src/worker/unified_server.rs:1459-1464` | Hot reload is explicitly blocked with mesh enabled, but document doesn't mention this limitation |

---

## 5. Summary

The Worker Architecture document is **mostly accurate** in its descriptions of:
- Multi-protocol support (HTTP/1.1, HTTP/2, HTTP/3, TCP, UDP)
- The WAF pipeline stages (verified 7-stage order in code)
- Resource management (buffer pooling, concurrency control, zero-copy)
- Request flow (Accept -> Route -> Protect -> Serve -> Transform)

Key discrepancies to address:
1. **WAF Challenge stage** - Not a standalone step in code as documented
2. **CPU affinity** - Linux-only, not automatic as implied
3. **Mesh control plane** - Disabled in workers (intentional, but unclear in docs)

The implementation is solid and matches the architectural intent in most areas.

---

## 6. Verification Commands

```bash
# Verify worker compilation
cargo check --no-default-features --features mesh

# Verify tests compile
cargo test --lib --no-run

# Run worker-related tests
cargo test --lib worker
cargo test --test integration_test
```
