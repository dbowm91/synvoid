# Streaming WAF and HTTP Stack Optimization Plan (1M RPS)

**Status**: 🏗️ PLANNING (2026-05-06)
**Target**: Support 1 million RPS with true streaming and optimized memory allocation.

## Goal
Transform the WAF and HTTP stack from "buffered scanning" to "true streaming". Eliminate body collection in memory, utilize the global `BufferPool` for all IO, and minimize per-chunk allocations in the WAF core to support high-throughput, low-latency traffic.

---

## Phase 1: WAF Core Allocation Optimization
**Goal**: Reduce the per-chunk allocation overhead in `StreamingWafCore` to zero (or near-zero).

- [ ] **Integrate BufferPool**: Modify `StreamingWafCore` to use `synvoid_utils::buffer::Pool` (BufferPool) for `trailing_window` and internal buffers.
- [ ] **Thread-Local Normalization Buffer**: Instead of creating a new `String` in `process_regular_chunk`, use the existing thread-local `NORMALIZE_BUFFER` from `src/waf/attack_detection/normalizer.rs`.
- [ ] **Zero-Copy Boundary Checks**:
    - Update `AttackDetector` to support a "fragmented scan" API that takes a slice of slices (e.g., `&[&[u8]]`).
    - Use this to scan the `trailing_window` + `current_chunk` without merging them into a new `Vec`.
- [ ] **Multipart Buffer Pooling**: Replace `MultipartState`'s `String` buffers with pooled `BytesMut`.

## Phase 2: True Streaming HTTP Handlers
**Goal**: Stop collecting request bodies in the HTTP/1/2/3 handlers and stream chunks to the proxy immediately after WAF scanning.

- [ ] **Refactor `collect_body_with_chunk_waf_impl`**:
    - Rename to `stream_body_with_waf`.
    - Change return type from `Result<Bytes, ()>` to a custom `WafStreamedBody` that implements `http_body::Body`.
    - This new body type should internally hold the `Incoming` body and the `StreamingWafCore` instance.
- [ ] **Async WAF Scanning in Stream**:
    - Implement the `poll_frame` method for `WafStreamedBody`.
    - For every frame received from the underlying body:
        1. Scan the chunk via `StreamingWafCore::scan_chunk`.
        2. If `Block`, return an error or a special "Blocked" frame.
        3. If `Continue`, yield the frame to the caller.
- [ ] **Update HTTP/1/2 Handler (`src/http/server.rs`)**:
    - Replace the `collect_body_with_chunk_waf` logic in SECTION 10 with the new streaming implementation.
    - Pass the resulting stream directly to the `ProxyServer`.
- [ ] **Update HTTP/3 Handler (`src/http3/server.rs`)**:
    - Align the HTTP/3 chunk scanning with the new streaming pattern.

## Phase 3: Proxy Layer Stream Support
**Goal**: Update the proxy server to handle streaming request bodies.

- [ ] **Modify `ProxyServer::handle_request`**:
    - Update signature to accept `BoxBody<Bytes, Infallible>` (or a similar streaming body type) instead of `Option<Bytes>`.
- [ ] **Update Forwarding Logic**:
    - Ensure `forward_request` and `send_single_request` can pipe the request body stream to the upstream client (`hyper` or `h3`) without buffering.
- [ ] **Backpressure Handling**:
    - Ensure that if the upstream is slow, the WAF scanning and client reading throttle appropriately via standard async backpressure.

## Phase 4: Validation and Benchmarking
**Goal**: Verify the 1M RPS target and memory efficiency.

- [ ] **Memory Profiling**: Use `dtrace` or `heaptrack` to confirm that per-request allocations are minimized.
- [ ] **Throughput Benchmarking**:
    - Use `wrk2` or a similar tool to simulate 1M RPS against the streaming stack.
    - Compare performance with the old buffered implementation.
- [ ] **Split-Chunk Attack Verification**:
    - Add test cases where an attack payload (e.g., `1' OR '1'='1`) is split across chunk boundaries precisely where `trailing_window` logic applies.

---

## Reference Files
- `src/waf/attack_detection/streaming.rs`: Core streaming WAF logic.
- `src/http/shared_handler.rs`: Current body collection implementation.
- `src/http/server.rs`: Main HTTP/1/2 request handler.
- `src/http3/server.rs`: Main HTTP/3 request handler.
- `src/proxy/mod.rs`: Proxy forwarding logic.
- `crates/synvoid-utils/src/buffer/pool.rs`: The high-performance `BufferPool`.
