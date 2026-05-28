# Listener Architecture

## 1. Purpose and Responsibility

The Listener module (`src/listener/`) provides **shared base types for network listener configuration** including port binding, socket options, and connection context. Used as configuration primitives across HTTP/HTTPS/HTTP3 and ICMP listeners.

**Core Responsibilities:**
- Shared listener configuration types
- Socket option definitions (reuse_port, buffer sizes)
- Connection context for request tracking
- Protocol expectation per listener

---

## 2. Key Data Structures

```rust
pub struct SocketOptionsBase {
    pub reuse_port: bool,
    pub send_buffer_size: usize,    // Default: 262144
    pub recv_buffer_size: usize,    // Default: 262144
}

pub struct ListenerConfigBase {
    pub port: u16,
    pub bind_addresses: Vec<String>,
    pub expected_protocol: ProtocolType,
    pub upstream_address: Option<String>,
    pub filter_config: Option<FilterConfig>,
}

pub struct ListenerInstance<C> {
    pub config: C,
    pub listen_addr: SocketAddr,
}

pub struct ConnectionContext {
    pub client_ip: IpAddr,
    pub server_name: Option<String>,
    pub port: u16,
    pub expected_protocol: ProtocolType,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ListenerConfigBase::default()` | Port 0, 0.0.0.0, unknown protocol |
| `ListenerInstance::new(config, listen_addr)` | Create instance with resolved address |
| `ConnectionContext::new(client_ip, server_name, port, expected_protocol)` | Create context |

---

## 4. Integration Points

- **HTTP Server**: TLS and non-TLS listener configuration
- **HTTP/3**: QUIC listener setup
- **ICMP Filter**: ICMP listener configuration
- **Platform**: Socket option application per OS

---

## 5. Key Implementation Details

- **Generic Design**: `ListenerInstance<C>` is parameterized over config type
- **Default Buffer Sizes**: 262KB send/recv buffers for high throughput
- **Protocol Awareness**: Each listener declares expected protocol for validation
- **Filter Integration**: Optional filter configuration per listener
