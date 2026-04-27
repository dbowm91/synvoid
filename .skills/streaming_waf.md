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
At 500K RPS:
- Target: 256KB max buffer per request
- Total concurrent: 1000 requests = 256MB
