# FastCGI Architecture

## 1. Purpose and Responsibility

The FastCGI module (`src/fastcgi/`) provides a **FastCGI protocol client** supporting Unix sockets and TCP, with connection pooling, health checking, drain/reload, and streaming response support.

**Core Responsibilities:**
- FastCGI protocol implementation
- Connection pooling with health checks
- Streaming response support
- Drain and reload support
- Global pool registry

---

## 2. Key Data Structures

```rust
pub struct FastCgiClient {
    socket_path: String,
    is_tcp: bool,
}

pub struct FastCgiPool {
    config: FastCgiPoolConfig,
    connections: RwLock<VecDeque<PooledConnection>>,
    semaphore: tokio::sync::Semaphore,
    health_check_task: RwLock<Option<tokio::task::JoinHandle<()>>>,
    closed: RwLock<bool>,
    draining: RwLock<bool>,
}

pub struct FastCgiPoolConfig {
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub health_check_interval: Duration,
    pub health_check_timeout: Duration,
    pub max_idle_time: Duration,
    pub socket: String,
}

pub struct StreamingFastCgiClient { /* FCGI record-level streaming */ }
pub struct FastCgiResponseStream { /* futures::Stream impl */ }

pub struct FastCgiPoolStatus {
    pub total_connections: usize,
    pub active_connections: usize,
    pub idle_connections: usize,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `get_pool(socket, config)` | Get or create pool |
| `remove_pool(socket)` | Remove pool |
| `close_all_pools()` | Close all pools |
| `drain_and_reload_pool(socket, timeout).await` | Drain with timeout |
| `FastCgiPool::execute()` | Execute request |
| `execute_stream().await` | Streaming execution |
| `drain_with_timeout().await` | Drain pool |
| `parse_socket_address(socket)` | Unix/TCP detection |

---

## 4. Integration Points

- **HTTP Server**: PHP-FPM and FastCGI backend routing
- **Config**: `FastCgiConfig` per-site settings
- **Admin API**: Pool status monitoring
- **Drain**: Graceful pool shutdown

---

## 5. Key Implementation Details

- **Protocol**: Full FastCGI record framing
- **Connection Pool**: Semaphore-based concurrency control
- **Health Checks**: Periodic connection health validation (socket-format-only — checks TCP/Unix socket connectivity, not FastCGI protocol health; returns `false` on non-Unix platforms for Unix sockets)
- **Streaming**: Custom FCGI record-level streaming (not HTTP chunked)
- **Global Registry**: Singleton pool manager via `LazyLock`
