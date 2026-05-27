# FastCGI Streaming Implementation (APP-15)

## Overview

APP-15 implements true streaming for FastCGI responses, replacing the buffering approach that collected entire stdout into a Vec.

## Problem (Before)

The `fastcgi-client` crate (v0.10) returns complete `Output` with `stdout: Option<Vec<u8>>`. The original implementation at `src/fastcgi/mod.rs:132-164` collected all into Vec:

```rust
fn parse_response(
    stdout: Option<Vec<u8>>,  // <-- Entire stdout collected
    stderr: Option<Vec<u8>>,
) -> Result<FastCgiResponse, FastCgiError> {
    let stdout = stdout.unwrap_or_default();  // <-- Collects all into Vec
    let body = Bytes::from(body_bytes.to_vec());  // <-- Another copy
}
```

## Solution Implemented

### Key Files

| File | Purpose |
|------|---------|
| `src/fastcgi/streaming.rs` (new, 649 lines) | Streaming FCGI client implementation |
| `src/fastcgi/mod.rs` | Added `pub mod streaming` |
| `src/fastcgi/pool.rs` | Added `execute_stream()` method |
| `Cargo.toml` | Added `fastcgi_streaming` feature flag |

### Key Components

1. **`FastCgiResponseStream`** - Implements `futures::Stream<Item=Result<Bytes, FastCgiError>>`
2. **`StreamingFastCgiClient`** - Speaks FCGI protocol directly (no fastcgi-client buffering)
3. **`FastCgiRecordReader`** - Parses FCGI records incrementally

### FCGI Protocol

The FastCGI protocol uses 8-byte headers:
```
version: u8
type: u8
request_id: u16 (big-endian)
content_length: u16 (big-endian)
padding_length: u8
reserved: u8
```

Record types:
- `FCGI_BEGIN_REQUEST` = 1
- `FCGI_ABORT_REQUEST` = 2
- `FCGI_END_REQUEST` = 3
- `FCGI_STDOUT` = 6
- `FCGI_STDERR` = 7
- etc.

### API

```rust
// Pool interface for streaming
pub async fn execute_stream(
    &self,
    request: FastCgiRequest,
) -> Result<FastCgiResponseStream, FastCgiError> {
    // Returns streaming response
}

// Usage
let mut stream = pool.execute_stream(request).await?;
while let Some(chunk) = stream.next().await {
    // Process chunk incrementally
}
```

## Feature Flag

`fastcgi_streaming` feature flag controls the new implementation:
- Default: existing buffered behavior for stability
- Enabled: streaming mode for performance-critical deployments

```toml
[features]
fastcgi_streaming = ["dep:futures"]
```

## Verification

```bash
cargo test --lib fastcgi  # 7 tests pass
cargo check --no-default-features --features mesh,dns  # All profiles compile
```

## Limitations

1. The streaming implementation doesn't use the fastcgi-client crate
2. Falls back to buffered behavior if streaming fails
3. WAF transforms still need chunk-based processing (future work)

## Related Files

- `src/fastcgi/mod.rs` - Original buffering implementation
- `src/fastcgi/pool.rs` - Pool interface with both execute() and execute_stream()
- `src/http/server.rs` - HTTP handler integration point
- `src/tls/server.rs` - HTTPS handler integration point