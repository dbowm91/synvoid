---
name: streaming_waf
description: Streaming WAF engine for incremental body scanning and real-time attack detection.
---

# Skill: Streaming WAF Implementation

## Context
The codebase implements a streaming WAF engine for incremental body scanning. This skill guides future agents on implementing streaming features.

## When to Use
Use this skill when:
- Implementing incremental body scanning for HTTP requests
- Adding fail-closed buffer overflow protection
- Creating zero-copy buffer handling with `Bytes`
- Extending `AttackDetector` with streaming methods

## Key Files
- `crates/synvoid-waf/src/attack_detection/streaming.rs` - `StreamingWafCore` implementation
- `crates/synvoid-waf/src/attack_detection/mod.rs` - Added `check_body_only_via_normalized()` method
  (`src/waf/attack_detection/mod.rs` is only a compat re-export shim)
- `crates/synvoid-http/src/streaming_waf_body.rs` - `StreamingWafBody` request-body adapter
  (canonical home since Phase 34)
- `crates/synvoid-http3/src/http3_body.rs` - HTTP/3 body collection/limit handling

## Implementation Pattern

### 1. StreamingWafCore Structure
```rust
pub struct StreamingWafCore {
    inner: Arc<AttackDetector>,
    chunk_size: usize,
    max_buffered_bytes: usize,   // byte ceiling, not a chunk-count ceiling
    state: StreamingState,       // owned directly — NOT behind a lock
}

struct StreamingState {
    chunks_processed: usize,
    last_result: Option<AttackDetectionResult>,
    bytes_seen: usize,
    boundary: Option<String>,                  // set by set_multipart_boundary
    multipart_state: MultipartState,
    trailing_window: PooledBuf,               // Must accumulate previous chunk bytes!
    multipart_header_buffer: PooledBuf,
    multipart_field_buffer: PooledBuf,
    field_trailing_window: PooledBuf,
}
```
`StreamingWafCore` is a plain owned-state struct: every scanning method takes
`&mut self`. There is no `RwLock`, no `pending_chunks` queue, and no
`current_input`; `const TRAILING_WINDOW_SIZE: usize = 512` bounds the window.

### 2. Trailing Window Pattern (CRITICAL - Fixed 2026-05-23, Phase-54 rule)

The trailing window MUST properly accumulate context across chunks. Canonical
code is `process_regular_chunk` in
`crates/synvoid-waf/src/attack_detection/streaming.rs`:

```rust
// Scan previous window + current chunk together so patterns split across
// chunk boundaries are still detected.
if let Some(result) = self.inner.check_body_fragments(
    &[self.state.trailing_window.as_slice(), chunk],
) { /* ... Block ... */ }

// Slide the window: keep up to TRAILING_WINDOW_SIZE (512) bytes of
// previous + current. Snapshot BEFORE emptying (borrow discipline).
let max_old = TRAILING_WINDOW_SIZE.saturating_sub(chunk.len());
let take = self.state.trailing_window.len().min(max_old);
let old_start = self.state.trailing_window.len() - take;
let previous_content = self.state.trailing_window[old_start..].to_vec();

// Phase 54: `resize(0)` empties the window; `clear()` only zeroizes
// in place and would make the extends below accumulate unboundedly.
self.state.trailing_window.resize(0);
self.state.trailing_window.extend_from_slice(&previous_content);
self.state.trailing_window.extend_from_slice(
    &chunk[chunk.len().saturating_sub(
        TRAILING_WINDOW_SIZE.saturating_sub(previous_content.len()))..],
);
```

**Common Bug**: Simply `extend_from_slice(&chunk[window_start..])` loses previous context. Attack patterns split across chunk boundaries won't be detected.

### 3. Required Methods
All take `&mut self` (owned state, no interior locking):
- `scan_chunk(&mut self, chunk: &[u8]) -> StreamingWafDecision` - Main scanning entry; also
  dispatches to `process_multipart_chunk` once `set_multipart_boundary` has been called
- `finalize(&mut self) -> Option<AttackDetectionResult>` - Get final detection result
- `reset(&mut self)` - Reset state for reuse
- `set_multipart_boundary(&mut self, boundary: &str)` - Switch to multipart mode

There is **no `scan_chunk_utf8` method** — do not call it. The
`synvoid_core::streaming_waf::StreamingWafScanner` trait impl adapts
`scan_chunk` to the shared neutral decision type.

**Important**: Use `.resize(0)` on `PooledBuf`, never `.clear()`, when you
intend an empty buffer (Phase 54):
```rust
// CORRECT - empties the window for refill
state.trailing_window.resize(0);
state.trailing_window.extend_from_slice(&tail);

// WRONG - clear() only zeroizes in place and KEEPS the length, so the
// extends below append after stale content (unbounded window growth)
state.trailing_window.clear();
state.trailing_window.extend_from_slice(&tail);
```
Same rule for `BufferPool::acquire(N)` + fill: `acquire(N)` yields N logical
bytes, so empty with `resize(0)` before `extend_from_slice`/`copy_from_fragments`,
or copy directly into `as_mut_slice()`. Appending to a nonzero acquire leaves
a zero prefix in scanned content. Cross-chunk coverage is pinned by
`test_streaming_cross_chunk_split_patterns` (every split position) — do not
weaken it for performance.

### 4. StreamingWafDecision Enum
```rust
pub enum StreamingWafDecision {
    Continue,           // Normal operation, continue
    Block(u16, String), // Attack detected, block with status code and reason
}
```
(Canonical — there is no `NeedMore` variant. The crate-internal
`synvoid_waf` decision is adapted to the shared
`synvoid_core::streaming_waf::StreamingWafDecision` at the
`StreamingWafCore::scan_chunk` boundary so `synvoid-http` (body adapter)
can depend on it without a cycle. The generic transport
(`synvoid-http-client`) carries no WAF types since Phase 34.)

Enforcement mapping: chunk outcomes project onto the canonical contract via
`synvoid_waf::enforcement::streaming_candidate`
(`Continue`→no claim, `Block`→`Block/StreamingBodyScan/body_blocked`), and
buffered body-policy failures via `BodyPolicyError::candidate()` in
`crates/synvoid-http/src/body_policy.rs` (both variants terminal,
fail-closed). See `architecture/enforcement_decision_contract.md`.

### 5. AttackDetector Integration
Add `check_body_only_via_normalized()` to `AttackDetector`:
```rust
pub fn check_body_only_via_normalized(&self, body_str: &str) -> Option<AttackDetectionResult> {
    // Same logic as check_body_only but takes pre-normalized string
}
```

### 6. Fail-Closed Buffer Overflow
`scan_chunk` enforces the ceiling **before** scanning, on accumulated bytes
(`DEFAULT_MAX_BUFFERED_BYTES`, overridable via `with_config`):
```rust
if self.state.bytes_seen.saturating_add(chunk.len()) > self.max_buffered_bytes {
    return StreamingWafDecision::Block(
        413,
        "Request body too large: byte limit exceeded".to_string(),
    );
}
```
The limit is fail-closed: an oversized chunk blocks with 413 instead of being
truncated, dropped, or partially scanned.

### 7. Export Pattern
In `crates/synvoid-waf/src/attack_detection/mod.rs`:
```rust
pub use streaming::{StreamingWafCore, StreamingWafDecision};
```

## Verification
```bash
cargo nextest run -p synvoid-waf --cargo-profile ci --profile ci -E 'test(streaming)'
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
```

## Common Issues
1. **unwrap() on StreamingWafDecision** - The enum doesn't implement Option/Result traits, call directly
2. **Missing module export** - Add `pub use streaming::{...}` to parent module
3. **AttackType naming** - Use `AttackType::Sqli` not `AttackType::SqlInjection`
4. **Bytes vs Vec<u8>** - Use `Bytes::copy_from_slice()` for zero-copy chunk storage

## Memory Budget
Design target at 1000K RPS:
- Target: 256KB max buffer per request
- Total concurrent: 1000 requests = 256MB

The shipped default ceiling is `DEFAULT_MAX_BUFFERED_BYTES = 2MB`
(overridable per instance via `with_config`), so the target is not met by
default — treat the numbers above as the stated goal, not current behavior.

## StreamingWafBody for True Streaming (Wave P1)

**Location**: `crates/synvoid-http/src/streaming_waf_body.rs` (canonical since Phase 34; was `crates/synvoid-http-client/src/streaming_waf_body.rs`; re-exported via `src/http_client/streaming_waf_body.rs`)

For true streaming to upstream (without full body buffering), a `StreamingWafBody<B>` type was added that wraps `hyper::body::Body` and performs WAF scanning on chunks as they pass through. It is generic over the scanner **trait**, not the concrete type:

```rust
pub struct StreamingWafBody<B, S> {
    inner: B,
    streaming_waf: Option<S>,
    client_ip: IpAddr,
    blocked: bool,
    error_sent: bool,
}

impl<B, S> StreamingWafBody<B, S>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
    S: StreamingWafScanner,
{
    pub fn new(inner: B, streaming_waf: Option<S>, client_ip: IpAddr) -> Self {
        Self { inner, streaming_waf, client_ip, blocked: false, error_sent: false }
    }
}
```

**Key behavior**:
- Implements `hyper::body::Body` for compatibility with hyper client
- Polls inner body frames and scans each chunk with `streaming_waf.scan_chunk()`
- If attack detected, returns error frame causing upstream request to fail
- Metrics tracked via `synvoid.http.streaming_body_blocked`

**Usage pattern**:
```rust
let body_stream = StreamingWafBody::new(incoming_body, streaming_waf, client_ip);
send_request_streaming(&client, method, url, body_stream, headers, timeout).await
```

**Limitation**: Full true streaming requires more refactoring to avoid body collection at HTTP server level. The infrastructure exists but the path to use it needs completion.

## Type-Erased Body Infrastructure (2026-05-04)

**Location**: `crates/synvoid-http-client/src/erased_pool.rs`

For type-erased body handling in the connection pool, the following types were added:

```rust
pub trait ErasedBody: Send + Sync + 'static {
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>>;
    fn size_hint(&self) -> SizeHint;
}

pub struct ErasedBodyImpl<B> {
    inner: B,
}

impl<B> ErasedBodyImpl<B>
where
    B: HttpBody<Data = Bytes> + Send + Sync + Unpin + 'static,
    B::Error: fmt::Debug + Send,
{
    pub fn new(inner: B) -> Box<dyn ErasedBody> { ... }
}

pub type BoxErasedBody = Box<dyn ErasedBody>;
```

**Key insight**: `ErasedBodyImpl` can wrap any `HttpBody<Data = Bytes>` including `StreamingWafBody`, enabling type-erased body handling at the connection pool level.

**Current status**: The pool is built — `ErasedHttpClient::new(max_idle_per_host)`
constructs an `ErasedConnectionPool` and `send_request` checks out/returns
connections by `PoolKey { authority, is_http2 }`. However this whole surface is
**FROZEN legacy-only** (see the `http_client` skill, Phase 60/62): production
egress runs on the eggfetch lane. Keep it compiling and tested; do not build on it.

## Request Pipeline Normalization (Iteration 99)

Streaming WAF scanners are now passed as part of `Http3DispatchDeps` in the HTTP/3 pipeline.
Body/streaming semantics are intentionally NOT unified between HTTP/1 and HTTP/3 — different stream types,
flow-control, and backpressure semantics require protocol-specific implementations.
See `architecture/http_request_pipeline.md` for the body policy stage.
