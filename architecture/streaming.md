# Streaming Architecture

## 1. Purpose and Responsibility

The Streaming module (`src/streaming/`) provides **async bidirectional data copying** with optional WAF scanning, buffered writes, and BufferPool integration for high-performance proxying.

**Core Responsibilities:**
- Bidirectional async data copy between client and upstream
- Optional WAF scanning during streaming
- Buffered writes with configurable thresholds
- BufferPool integration for memory efficiency
- Native copy fallback for simple cases

---

## 2. Key Data Structures

```rust
pub struct ProxyConfig {
    pub buffer_size: usize,
    pub write_buffer_threshold: usize,
    pub flush_interval_bytes: usize,
    pub use_native_copy: bool,
    pub waf_scanner: Option<Arc<StreamingWafCore>>,
}

pub enum ProxyError {
    ReadError(io::Error),
    WriteError(io::Error),
    ConnectionClosed,
    Timeout,
    WafBlock(String),
    Other(String),
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `copy_bidirectional(client_r, client_w, upstream_r, upstream_w).await` | Basic bidirectional copy |
| `copy_bidirectional_with_config(..., config).await` | With WAF scanning and buffering |
| `copy_bidirectional_native(client, upstream).await` | Thin wrapper over tokio |
| `copy_bidirectional_auto(..., config).await` | Auto-select best method |

---

## 4. Integration Points

- **Proxy**: TCP/HTTP proxying between client and upstream
- **BufferPool**: Memory-efficient buffer allocation
- **StreamingWafCore**: Real-time attack detection during streaming
- **WAF**: Streaming body inspection

---

## 5. Key Implementation Details

- **Async Everything**: All operations are fully asynchronous
- **Buffer Pool**: Uses sharded buffer pool to reduce allocations
- **WAF Integration**: Optional inline scanning without buffering entire body
- **Auto Selection**: Chooses native or custom copy based on config
- **Flush Control**: Configurable flush thresholds for write buffering
