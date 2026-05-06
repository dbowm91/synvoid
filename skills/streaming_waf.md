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
- `src/waf/attack_detection/streaming.rs` - `StreamingWafCore` implementation
- `src/waf/attack_detection/mod.rs` - Added `check_body_only_via_normalized()` method
- `src/http3/server.rs` - HTTP/3 body handling (lines 264-281)

## Implementation Pattern

### 1. StreamingWafCore Structure
```rust
pub struct StreamingWafCore {
    inner: Arc<AttackDetector>,
    chunk_size: usize,
    max_buffered_chunks: usize,
    state: RwLock<StreamingState>,
}

struct StreamingState {
    pending_chunks: VecDeque<Bytes>,
    current_input: Option<String>,
    chunks_processed: usize,
    last_result: Option<AttackDetectionResult>,
    bytes_seen: usize,
}
```

### 2. Required Methods
- `scan_chunk(&self, chunk: &[u8]) -> StreamingWafDecision` - Main scanning entry
- `scan_chunk_utf8(&self, chunk: &[u8]) -> StreamingWafDecision` - UTF-8 validated version
- `finalize(&self) -> Option<AttackDetectionResult>` - Get final detection result
- `reset(&self)` - Reset state for reuse

**Important**: Use `.clear()` on `PooledBuf` instead of `BufferPool::acquire(0)` in `reset()`:
```rust
// CORRECT - reuses buffer from pool
state.trailing_window.clear();

// WRONG - unnecessary allocation
state.trailing_window = BufferPool::acquire(0);
```

### 3. StreamingWafDecision Enum
```rust
pub enum StreamingWafDecision {
    Continue,           // Normal operation, continue
    Block(u16, String), // Attack detected, block with status code and reason
    NeedMore,           // Need more data (rarely used)
}
```

### 4. AttackDetector Integration
Add `check_body_only_via_normalized()` to `AttackDetector`:
```rust
pub fn check_body_only_via_normalized(&self, body_str: &str) -> Option<AttackDetectionResult> {
    // Same logic as check_body_only but takes pre-normalized string
}
```

### 5. Fail-Closed Buffer Overflow
Always check buffer limits:
```rust
if state.pending_chunks.len() >= self.max_buffered_chunks {
    return StreamingWafDecision::Block(
        413,
        "Request body too large: buffer overflow".to_string(),
    );
}
```

### 6. Export Pattern
In `src/waf/attack_detection/mod.rs`:
```rust
pub use streaming::{StreamingWafCore, StreamingWafDecision};
```

## Verification
```bash
cargo test --lib streaming
cargo fmt
cargo clippy --lib -- -D warnings
```

## Common Issues
1. **unwrap() on StreamingWafDecision** - The enum doesn't implement Option/Result traits, call directly
2. **Missing module export** - Add `pub use streaming::{...}` to parent module
3. **AttackType naming** - Use `AttackType::Sqli` not `AttackType::SqlInjection`
4. **Bytes vs Vec<u8>** - Use `Bytes::copy_from_slice()` for zero-copy chunk storage

## Memory Budget
At 1000K RPS:
- Target: 256KB max buffer per request
- Total concurrent: 1000 requests = 256MB

## StreamingWafBody for True Streaming (Wave P1)

**Location**: `src/http_client/mod.rs:92-203`

For true streaming to upstream (without full body buffering), a `StreamingWafBody<B>` type was added that wraps `hyper::body::Body` and performs WAF scanning on chunks as they pass through:

```rust
pub struct StreamingWafBody<B> {
    inner: B,
    streaming_waf: Option<Arc<StreamingWafCore>>,
    client_ip: IpAddr,
    blocked: bool,
    error_sent: bool,
}

impl<B> StreamingWafBody<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    pub fn new(inner: B, streaming_waf: Option<Arc<StreamingWafCore>>, client_ip: IpAddr) -> Self {
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

**Location**: `src/http_client/erased_pool.rs`

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

**Current status**: Core infrastructure complete. Full connection pooling (Phases 2-5 of Option D) deferred due to hyper type system complexity.
