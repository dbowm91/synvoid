# Listener Architecture

## 1. Purpose and Responsibility

The Listener module (`crates/synvoid-http/src/listener/`, re-exported by the `src/listener/` compatibility facade) provides a minimal shared base type for network listener configuration: `ConnectionContext`. Concrete listener implementations (`TcpListenerConfig`, `UdpListenerConfig`, `TcpSocketOptions`, `UdpSocketOptions`) live in their respective protocol modules.

**Core Responsibilities:**
- Shared `ConnectionContext` for request tracking across protocols
- Protocol-specific listener configuration in `src/tcp/listener.rs` and `src/udp/listener.rs`

---

## 2. Key Data Structures

### Shared (`crates/synvoid-http/src/listener/common.rs`)

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
- **Raw Listener Pools**: `TcpListenerPool` (`src/tcp/listener.rs`) and `UdpListenerPool`
  (`src/udp/listener.rs`) each hold many per-port `*ListenerInstance`s and spawn an accept loop per
  instance; `TcpListenerPool::new(pool_config, filter_config)` takes a `FilterConfig`.
- **`SO_REUSEPORT`**: `reuse_port` defaults to `true`; `set_reuse_port(true)` is applied at bind when the
  platform supports it (`src/tcp/listener.rs:115-124`, gated by `synvoid-platform`). Support is
  **not universal** — `Platform::supports_reuse_port()` (`crates/synvoid-platform/src/lib.rs:141-146`)
  returns `true` only for `Linux`, `LinuxMusl`, `Macos`, and `FreeBSD`. OpenBSD, NetBSD, and Windows
  return `false`, so `SO_REUSEPORT` is silently skipped there. `reuse_port_ebpf` (default `false`)
  additionally requests eBPF acceleration on Linux only.
- **Protocol Detection & Filtering**: each accepted connection is rate-limited, then protocol-detected
  (`ProtocolDetector::detect_peek`), then checked by `ProtocolFilter::check()` against the listener's
  `expected_protocol` **before** it is proxied upstream (`src/tcp/listener.rs:531-580`). The result is a
  `FilterAction` of `Allow`, `Drop`, or `Stall`; `Drop`/`Stall` return without proxying (and `Stall`
  deliberately stalls the socket rather than closing it, so the client times out). `block_unknown_ports`
  escalates `Protocol::Unknown` to `Stall`, and `check_upstream()` additionally enforces each upstream's
  `allowed_protocols` (`src/tcp/filter.rs:103-128`).
- **Default Buffer Sizes**: 262KB send/recv TCP buffers for high throughput
- **Protocol Awareness**: Each listener declares expected protocol as a `String` (e.g., "smtp", "dns")
- **Filter Integration**: Filter enabled via `filter_enabled: bool` and `strict_mode: bool` fields directly on listener configs
- **Dual-Stack Support**: IPv6 bind/upstream addresses are optional (`Option<String>`) alongside IPv4 addresses
