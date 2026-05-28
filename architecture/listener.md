# Listener Architecture

## 1. Purpose and Responsibility

The Listener module (`src/listener/`) provides a minimal shared base type for network listener configuration: `ConnectionContext`. Concrete listener implementations (`TcpListenerConfig`, `UdpListenerConfig`, `TcpSocketOptions`, `UdpSocketOptions`) live in their respective protocol modules.

**Core Responsibilities:**
- Shared `ConnectionContext` for request tracking across protocols
- Protocol-specific listener configuration in `src/tcp/listener.rs` and `src/udp/listener.rs`

---

## 2. Key Data Structures

### Shared (`src/listener/common.rs`)

```rust
pub struct ConnectionContext {
    pub client_ip: IpAddr,
    pub server_name: String,
    pub port: u16,
    pub expected_protocol: String,
}
```

### TCP (`src/tcp/listener.rs`)

```rust
pub struct TcpSocketOptions {
    pub nodelay: bool,                     // Default: true
    pub send_buffer_size: usize,           // Default: 262144
    pub recv_buffer_size: usize,           // Default: 262144
    pub reuse_port: bool,                  // Default: true
    pub reuse_port_ebpf: bool,             // Default: false
    pub quickack: bool,                    // Default: true
    pub keepalive_secs: Option<u64>,       // Default: Some(60)
    pub keepalive_interval_secs: Option<u64>, // Default: Some(10)
    pub keepalive_retries: Option<u32>,    // Default: Some(3)
}

pub struct TcpListenerConfig {
    pub port: u16,                         // Default: 25
    pub bind_address: String,              // Default: "0.0.0.0"
    pub bind_address_v6: Option<String>,   // Default: None
    pub expected_protocol: String,         // Default: "smtp"
    pub upstream_address: String,          // Default: "127.0.0.1:25"
    pub upstream_address_v6: Option<String>, // Default: Some("[::1]:25")
    pub filter_enabled: bool,              // Default: true
    pub strict_mode: bool,                 // Default: true
    pub socket_options: TcpSocketOptions,
    pub tcp_backlog: Option<u32>,
}

struct TcpListenerInstance {
    config: TcpListenerConfig,
    listen_addr: SocketAddr,
}
```

### UDP (`src/udp/listener.rs`)

```rust
pub struct UdpListenerConfig {
    pub port: u16,                         // Default: 53
    pub bind_address: String,              // Default: "0.0.0.0"
    pub bind_address_v6: Option<String>,   // Default: None
    pub expected_protocol: String,         // Default: "dns"
    pub upstream_address: String,          // Default: "127.0.0.1:5353"
    pub upstream_address_v6: Option<String>, // Default: Some("[::1]:5353")
    pub filter_enabled: bool,              // Default: true
    pub strict_mode: bool,                 // Default: true
    pub max_packet_size: usize,            // Default: 4096
    pub rate_limit_per_ip: u32,            // Default: 100
    pub socket_options: UdpSocketOptions,
}

struct UdpListenerInstance {
    config: UdpListenerConfig,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ConnectionContext::new(client_ip, server_name, port, expected_protocol)` | Create connection context |
| `TcpListenerPool::new(pool_config, filter_config)` | Create TCP listener pool |
| `TcpListenerPool::add_listener(listener_config)` | Add TCP listener |
| `UdpListenerPool::new(pool_config, filter_config)` | Create UDP listener pool |
| `UdpListenerPool::add_listener(listener_config)` | Add UDP listener |

---

## 4. Integration Points

- **HTTP Server**: TLS and non-TLS listener configuration
- **HTTP/3**: QUIC listener setup
- **ICMP Filter**: ICMP listener configuration
- **Platform**: Socket option application per OS

---

## 5. Key Implementation Details

- **Shared Context**: `ConnectionContext` is the only type exported from `src/listener/`
- **Default Buffer Sizes**: 262KB send/recv TCP buffers for high throughput
- **Protocol Awareness**: Each listener declares expected protocol as a `String` (e.g., "smtp", "dns")
- **Filter Integration**: Filter enabled via `filter_enabled: bool` and `strict_mode: bool` fields directly on listener configs
- **Dual-Stack Support**: IPv6 bind/upstream addresses are optional (`Option<String>`) alongside IPv4 addresses
