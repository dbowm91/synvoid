# Tunnel Module Architecture

## 1. Purpose and Responsibility

The Tunnel module (`src/tunnel/`) provides secure, encrypted tunnel communication for SynVoid's mesh networking infrastructure. It enables:

- **Site-to-site VPN connectivity** via QUIC-based tunnels
- **WireGuard VPN support** with both kernel and userspace implementations
- **UDP tunnel management** for DNS and other UDP-based protocols
- **Tunnel routing** that integrates with the proxy layer for upstream resolution
- **TUN device abstraction** for network packet handling

**Core Responsibilities:**
1. Establish and maintain encrypted tunnels between nodes
2. Route traffic through tunnels based on session/mapping lookup
3. Provide access control via `VpnAccessLevel` (Admin/General)
4. Health monitoring and connection quality tracking
5. Session management for tunnel clients and peers

---

## 2. Submodule Structure and Responsibilities

```
src/tunnel/
├── mod.rs              # Module exports, TunnelManager, TunnelTransport trait
├── router.rs           # TunnelRouter, TunnelBackend, route session management
├── tun.rs              # TUN device abstraction (platform-specific)
├── udp_manager.rs      # UDP tunnel lifecycle management
├── upstream.rs         # Tunnel-aware upstream resolution
├── quic/               # QUIC tunnel transport implementation
│   ├── mod.rs
│   ├── runtime.rs      # QuicRuntime, QuicConnection lifecycle
│   ├── server.rs       # QuicTunnelServer, session handling
│   ├── client.rs       # QuicTunnelClient, peer connection management
│   ├── registry.rs     # QuicTunnelRegistry, global session registry
│   ├── health.rs        # QuicHealthMonitor, connection quality tracking
│   ├── messages.rs     # TunnelMessage, DatagramMessage protocol
│   ├── framing.rs      # Message encoding/decoding
│   ├── tls.rs          # QUIC TLS configuration
│   ├── validation.rs   # Input validation for security
│   └── ipc.rs          # Inter-process communication
└── wireguard/          # WireGuard VPN implementation
    ├── mod.rs
    ├── runtime.rs      # WireGuardRuntime, backend selection
    ├── kernel.rs       # KernelWireGuard (Linux netlink)
    ├── userspace.rs    # UserspaceWireGuard (boringtun)
    ├── config.rs       # WireGuardConfig, peer configuration
    ├── session.rs      # WgSessionManager, WgPeerSession
    ├── stats.rs        # WgStatsCollector, interface stats
    └── tun.rs          # WireGuard-specific TUN interface
```

### Key Submodule Responsibilities

| Submodule | Responsibility |
|-----------|----------------|
| `mod.rs` | Core types (`TunnelType`, `TunnelStats`, `PeerInfo`, `TunnelTransport` trait) |
| `router.rs` | Central routing: resolves tunnel backends for proxy layer |
| `quic/runtime.rs` | QUIC endpoint management, connection lifecycle |
| `quic/server.rs` | Accepts incoming QUIC tunnel connections, authentication |
| `quic/client.rs` | Manages outbound peer connections with retry logic |
| `quic/registry.rs` | Global QUIC session registry (`QUIC_TUNNEL_REGISTRY`) |
| `quic/health.rs` | Connection quality monitoring, health events |
| `quic/messages.rs` | Protocol messages (`TunnelMessage`, `DatagramMessage`) |
| `wireguard/runtime.rs` | WireGuard backend selection (Kernel/Userspace/Auto) |
| `wireguard/kernel.rs` | Linux kernel WireGuard via netlink |
| `wireguard/session.rs` | WireGuard session state management (`WG_TUNNEL_REGISTRY`) |

---

## 3. Key Data Structures and Types

### Core Enums and Types (`mod.rs`)

```rust
// Tunnel transport type
pub enum TunnelType {
    Quic,
    WireGuard,
}

// Statistics for tunnel connections
pub struct TunnelStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub latency_ms: Option<u64>,
    pub connected_at: Option<std::time::Instant>,
}

// Peer information
pub struct PeerInfo {
    pub id: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub last_handshake: Option<std::time::Instant>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

// Core tunnel transport trait (implemented by QuicRuntime, WireGuardRuntime)
#[async_trait]
pub trait TunnelTransport: Send + Sync {
    fn tunnel_type(&self) -> TunnelType;
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn stop(&mut self);
    fn is_running(&self) -> bool;
    fn stats(&self) -> TunnelStats;
    fn local_address(&self) -> Option<std::net::SocketAddr>;
    fn peer_count(&self) -> usize;
    fn peers(&self) -> Vec<PeerInfo>;
    fn shutdown(&self);
}

// Session management
pub struct TunnelManager { ... }
pub struct TunnelSession { ... }
pub struct TunnelConnection { ... }
```

### QUIC Types

```rust
// From quic/runtime.rs
pub struct QuicRuntime {
    config: TunnelQuicConfig,
    tls_config: QuicTlsConfig,
    sessions: Arc<DashMap<String, QuicConnection>>,
    endpoint: Arc<Mutex<Option<Endpoint>>>,
    health_monitor: Option<Arc<QuicHealthMonitor>>,
    // timeouts, limits, datagram settings
}

pub struct QuicConnection {
    pub remote_addr: SocketAddr,
    pub peer_id: Option<String>,
    pub session_id: String,
    pub client_id: String,
    pub mappings: HashMap<String, u16>,
    pub connection: Option<Connection>,
    pub datagram_capabilities: DatagramCapabilities,
}

// From quic/server.rs
pub struct QuicTunnelServer { ... }
pub struct QuicTunnelSession {
    pub id: String,
    pub client_id: String,
    pub remote_addr: String,
    pub mappings: HashMap<String, PortMappingConfig>,
    pub connection: Connection,
    pub access_level: VpnAccessLevel,
    pub allowed_ports_tcp: Vec<u16>,
    pub allowed_ports_udp: Vec<u16>,
}

// From quic/client.rs
pub struct QuicTunnelClient { ... }
pub struct QuicClientSession { ... }

// From quic/messages.rs
pub enum TunnelMessage {
    Hello { client_id, auth_token, mappings, supports_datagrams },
    HelloAck { server_session_id, server_mappings, supports_datagrams, max_datagram_size, access_level },
    PeerHello { peer_id, auth_token, supports_datagrams },
    PeerHelloAck { session_id, supports_datagrams, max_datagram_size },
    StreamOpen { identifier, port, protocol, tls_passthrough },
    StreamOpenAck { identifier, success, message },
    UdpTunnelOpen { identifier, port },
    UdpTunnelOpenAck { identifier, success, message },
    // ... other variants
    KeepAlive, DataChunk, StreamClose, etc.
}

pub struct DatagramMessage {
    pub identifier: String,
    pub sequence: u64,
    pub data: Vec<u8>,
    pub port: u16,
    pub source_addr: String,
    pub return_addr: Option<String>,
    pub fragment_info: Option<FragmentInfo>,
    pub hop_count: u8,
}
```

### WireGuard Types

```rust
// From wireguard/config.rs
pub enum WgImplementation {
    Auto,
    Kernel,
    Userspace,
}

pub struct WireGuardConfig {
    pub enabled: bool,
    pub interface_name: String,
    pub private_key: String,
    pub listen_port: u16,
    pub peers: Vec<WireGuardPeerConfig>,
    pub dns: Vec<String>,
    pub mtu: u16,
    pub implementation: WgImplementation,
    pub fwmark: Option<u32>,
    // ... lifecycle scripts (pre_up, post_up, etc.)
}

pub struct WireGuardPeerConfig {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
}

// From wireguard/session.rs
pub enum WgSessionState {
    Initializing,
    Handshaking,
    Established,
    Rekeying,
    Disconnected,
    Error,
}

pub struct WgPeerSession {
    pub id: String,
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub created_at: Instant,
    pub last_handshake: Option<Instant>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub state: WgSessionState,
}

// From wireguard/runtime.rs
pub enum WireGuardBackend {
    Kernel(KernelWireGuard),
    Userspace(UserspaceWireGuard),
}

pub struct WireGuardRuntime {
    config: WireGuardConfig,
    backend: Option<WireGuardBackend>,
    sessions: Arc<WgSessionManager>,
    implementation: WgImplementation,
}
```

### Tunnel Routing Types

```rust
// From router.rs
pub struct TunnelRouter {
    config: TunnelConfig,
    sessions: Arc<DashMap<String, TunnelRouteSession>>,
    quic_runtime: Option<Arc<QuicRuntime>>,
    quic_server: Option<QuicTunnelServer>,
    quic_client: Option<QuicTunnelClient>,
}

pub struct TunnelRouteSession {
    pub id: String,
    pub peer_id: String,
    pub remote_addr: String,
    pub session_type: TunnelSessionType,
    pub connected_at: std::time::Instant,
    pub mappings: HashMap<String, TunnelMapping>,
}

pub enum TunnelSessionType {
    Server,
    Client,
    Peer,
}

pub struct TunnelMapping {
    pub identifier: String,
    pub port: u16,
    pub protocol: String,
    pub upstream_host: Option<String>,
    pub upstream_port: Option<u16>,
}

pub enum TunnelBackend {
    Direct { host: String, port: u16 },
    Tunnel { session_id: String, identifier: String },
}
```

---

## 4. Key APIs and Entry Points

### Module Exports (`mod.rs`)

```rust
pub use quic::{
    QuicConnection, QuicRuntime, QuicTunnelRegistry, TunnelSessionInfo, QUIC_TUNNEL_REGISTRY,
};
pub use router::{TunnelBackend, TunnelMapping, TunnelRouteSession, TunnelRouter};
pub use tun::{
    is_tun_available, AsyncTunDevice, TunConfig, TunInterface, TunPacket, TunProtocol, TunReader,
    TunWriter,
};
pub use udp_manager::{
    ActiveUdpTunnel, PendingRequest, UdpResponse, UdpTunnelConfig, UdpTunnelManager,
};
pub use upstream::TunnelUpstreamResolver;
pub use wireguard::{
    detect_available_implementation, generate_keypair, is_wireguard_available, WgImplementation,
    WgSessionInfo, WireGuardClient, WireGuardClientConfig, WireGuardConfig, WireGuardPeerConfig,
    WireGuardRuntime, WireGuardServer, WireGuardServerConfig, WireGuardServerWrapper,
    WG_TUNNEL_REGISTRY,
};
```

### TunnelRouter API (`router.rs`)

```rust
impl TunnelRouter {
    // Construction
    pub fn new(config: TunnelConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
    
    // Lifecycle
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    pub fn shutdown(&self)
    
    // Session management
    pub async fn resolve_tunnel_backend(&self, identifier: &str) -> Option<TunnelBackend>
    pub async fn list_sessions(&self) -> Vec<TunnelRouteSession>
    
    // QUIC accessors
    pub fn is_quic_enabled(&self) -> bool
    pub fn quic_runtime(&self) -> Option<&Arc<QuicRuntime>>
    pub fn quic_client(&self) -> Option<&QuicTunnelClient>
}
```

### QuicRuntime API (`quic/runtime.rs`)

```rust
impl QuicRuntime {
    // Construction with builder pattern
    pub fn new(config: TunnelQuicConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
    pub fn with_timeouts(mut self, max_idle_secs: u64, keepalive_secs: u64) -> Self
    pub fn with_stream_limits(mut self, max_streams: u64, buffer_size: usize) -> Self
    pub fn with_datagram_size(mut self, max_size: usize) -> Self
    pub fn with_health_monitor(mut self, config: HealthCheckConfig) -> Self
    
    // Server mode
    pub async fn start_server(&self) -> Result<mpsc::Receiver<IncomingConnection>, ...>
    
    // Client connections
    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<QuicConnection, ...>
    pub async fn connect_to_peer(&self, peer_addr: &str, server_name: &str) -> Result<QuicConnection, ...>
    
    // Stream operations
    pub async fn open_tunnel_stream(&self, session_id: &str, identifier: &str) -> Result<(SendStream, RecvStream), ...>
    pub async fn open_tunnel_stream_to_peer(&self, peer_id: &str, identifier: &str) -> Result<(SendStream, RecvStream), ...>
    
    // Datagram operations
    pub fn send_datagram(&self, session_id: &str, data: Vec<u8>) -> Result<(), ...>
    pub async fn recv_datagram(&self, session_id: &str, timeout: Duration) -> Result<Vec<u8>, ...>
    pub fn send_datagram_message(&self, session_id: &str, msg: DatagramMessage) -> Result<(), ...>
    
    // Session management
    pub async fn add_session(&self, connection: QuicConnection)
    pub async fn remove_session(&self, session_id: &str)
    pub async fn close_session(&self, session_id: &str)
    pub fn get_session(&self, session_id: &str) -> Option<QuicConnection>
    pub fn list_sessions(&self) -> Vec<QuicConnection>
    
    // Health and quality
    pub fn get_connection_quality(&self, session_id: &str) -> Option<ConnectionQuality>
    pub fn get_connection_health(&self, session_id: &str) -> Option<ConnectionHealth>
}
```

### WireGuardRuntime API (`wireguard/runtime.rs`)

```rust
impl WireGuardRuntime {
    pub fn new(config: WireGuardConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
    pub fn builder(config: WireGuardConfig) -> WireGuardRuntimeBuilder
    
    // Backend selection
    async fn select_backend(&self) -> Result<WireGuardBackend, ...>
    
    // Peer management
    pub fn add_peer(&self, peer_config: WireGuardPeerConfig) -> Result<(), ...>
    pub fn remove_peer(&self, public_key: &str) -> Result<(), ...>
    pub fn session_manager(&self) -> &WgSessionManager
    pub fn implementation(&self) -> WgImplementation
    
    // Datagram (userspace only)
    pub async fn send_datagram(&self, peer_public_key: &str, data: &[u8]) -> Result<(), ...>
}

// TunnelTransport implementation for WireGuardRuntime
impl TunnelTransport for WireGuardRuntime {
    async fn start(&mut self) -> Result<(), ...>
    async fn stop(&mut self)
    fn tunnel_type(&self) -> TunnelType { TunnelType::WireGuard }
    fn stats(&self) -> TunnelStats
    fn peers(&self) -> Vec<PeerInfo>
    // ...
}
```

### QuicTunnelServer API (`quic/server.rs`)

```rust
impl QuicTunnelServer {
    pub fn new(config: TunnelQuicConfig, runtime: Arc<QuicRuntime>, proxy_sender: mpsc::Sender<TunnelProxyRequest>) -> Self
    pub async fn start(&mut self) -> Result<(), ...>
    pub async fn run(&mut self)  // Main accept loop
    
    // Authentication
    async fn handle_connection(...) -> Result<(), ...>
    async fn session_loop(...) -> Result<(), ...>
    async fn handle_stream(...) -> Result<(), ...>
    async fn handle_udp_tunnel(...) -> Result<(), ...>
    async fn proxy_bidirectional(...) -> Result<(), ...>
    
    // Port access control
    fn can_access_port(&self, port: u16, protocol: &str) -> bool
}

pub struct TunnelProxyRequest {
    pub session_id: String,
    pub identifier: String,
    pub port: u16,
    pub data: Vec<u8>,
    pub response_tx: mpsc::Sender<Result<Vec<u8>, String>>,
}
```

### UDP Tunnel Manager API (`udp_manager.rs`)

```rust
impl UdpTunnelManager {
    pub fn new(config: UdpTunnelConfig) -> Self
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self
    
    pub async fn get_or_open_tunnel(&self, peer_id: &str, port: u16) -> Result<Arc<ActiveUdpTunnel>, ...>
    pub async fn send(&self, peer_id: &str, port: u16, data: &[u8], client_addr: SocketAddr) -> Result<(), ...>
    pub async fn send_with_dns_tracking(&self, peer_id: &str, port: u16, data: &[u8], client_addr: SocketAddr) -> Result<(), ...>
    
    pub fn cleanup_idle_tunnels(&self)
    pub fn shutdown(&self)
}

impl ActiveUdpTunnel {
    pub async fn send(&self, data: &[u8], client_addr: SocketAddr) -> Result<(), ...>
    pub async fn send_with_tracking(&self, data: &[u8], client_addr: SocketAddr, dns_transaction_id: Option<u16>) -> Result<(), ...>
    pub fn get_pending_request(&self, sequence: u64) -> Option<PendingRequest>
    pub fn find_pending_by_dns_id(&self, dns_id: u16) -> Option<(u64, PendingRequest)>
    pub fn age(&self) -> Duration
    pub fn is_expired(&self, timeout: Duration) -> bool
}
```

---

## 5. Tunnel Routing Flow

### Architecture Overview

The tunnel router serves as the bridge between the proxy layer and tunnel transports:

```
Proxy Layer                    Tunnel Router                    Tunnel Transports
    |                               |                                   |
    | resolve_tunnel_backend()      |                                   |
    |------------------------------>|                                   |
    |                               |                                   |
    |   Returns TunnelBackend::     |                                   |
    |   Direct { host, port }       |                                   |
    |                               |                                   |
    |<------------------------------|                                   |
    |                               |                                   |
    |   Routes to upstream          |                                   |
    |-------------------------------------------------------------->    |
```

### Routing Resolution Path

**File:** `src/tunnel/router.rs:150-169`

```rust
pub async fn resolve_tunnel_backend(&self, identifier: &str) -> Option<TunnelBackend> {
    // 1. First check QUIC client for configured mappings
    if let Some(ref client) = self.quic_client {
        if let Some((host, port)) = client.resolve_upstream(identifier).await {
            return Some(TunnelBackend::Direct { host, port });
        }
    }
    
    // 2. Then check active route sessions
    for session in self.sessions.iter() {
        if let Some(mapping) = session.mappings.get(identifier) {
            return Some(TunnelBackend::Direct {
                host: mapping.upstream_host.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
                port: mapping.upstream_port.unwrap_or(mapping.port),
            });
        }
    }
    
    None
}
```

### Tunnel Backend Types

```rust
pub enum TunnelBackend {
    // Direct connection to upstream host:port
    Direct { host: String, port: u16 },
    
    // Tunneled connection via session
    Tunnel { session_id: String, identifier: String },
}
```

### Session Mapping Flow

When a `TunnelProxyRequest` arrives at the server:

1. **Server receives proxy request** (`quic/server.rs:108`)
2. **Creates TunnelRouteSession** with mapping from request identifier
3. **Inserts into router sessions** DashMap
4. **Resolves upstream** via `TunnelRouter::resolve_tunnel_backend()`

```rust
// From router.rs:107-144
let session = TunnelRouteSession {
    id: req.session_id.clone(),
    peer_id: String::new(),
    remote_addr: String::new(),
    session_type: TunnelSessionType::Server,
    connected_at: std::time::Instant::now(),
    mappings: [(
        req.identifier.clone(),
        TunnelMapping {
            identifier: req.identifier.clone(),
            port: req.port,
            protocol: "tcp".to_string(),
            upstream_host: Some(upstream_host),
            upstream_port: Some(req.port),
        },
    )]
    .into_iter()
    .collect(),
};

sessions.insert(req.session_id, session);
```

---

## 6. QUIC Tunnel Transport

### Overview

The QUIC tunnel transport provides:
- **Connection-oriented tunnels** over QUIC (RFC 9000)
- **Bidirectional streams** for request/response
- **Datagram support** for UDP tunnel passthrough
- **TLS encryption** with self-signed certificates
- **Authentication** via client_id/peer_id and auth_token

### Connection Flow

**Server Side** (`quic/server.rs:278-553`):

1. Accept incoming QUIC connection
2. Wait for initial bidirectional stream
3. Read `TunnelMessage::Hello` or `TunnelMessage::PeerHello`
4. Validate client_id/peer_id format
5. Check auth_rate_limiter for DoS protection
6. Authenticate against configured credentials
7. Create `QuicTunnelSession` with access level
8. Register session in `QUIC_TUNNEL_REGISTRY` and `QuicRuntime`
9. Send `HelloAck` or `PeerHelloAck`
10. Enter session loop for stream handling

**Client Side** (`quic/client.rs:242-299`):

1. Connect to peer address via `QuicRuntime::connect_to_peer()`
2. Open bidirectional stream
3. Send `TunnelMessage::PeerHello` with auth_token
4. Wait for `PeerHelloAck`
5. Store session in `sessions` DashMap

### Stream Protocol

Streams use length-prefixed message framing (`framing.rs`):

```
┌─────────────┬─────────────────────────────┐
│ Len (4B)    │ Message (variable)          │
├─────────────┼─────────────────────────────┤
│ u32 BE     │ TunnelMessage encoded        │
└─────────────┴─────────────────────────────┘
```

Message types for streams:
- `StreamOpen` / `StreamOpenAck` - Open upstream connection
- `UdpTunnelOpen` / `UdpTunnelOpenAck` - Open UDP tunnel
- `DataChunk` / `DataAck` - Data transfer
- `KeepAlive` / `KeepAliveAck` - Liveness check
- `StreamClose` / `PortClose` - Clean shutdown

### Datagram Protocol

QUIC datagrams (`quic/messages.rs:214-300`) provide low-overhead UDP forwarding:

```rust
pub struct DatagramMessage {
    pub identifier: String,    // Tunnel identifier
    pub sequence: u64,         // Packet sequence number
    pub data: Vec<u8>,         // UDP payload
    pub port: u16,             // Target port
    pub source_addr: String,   // Original source
    pub return_addr: Option<String>,
    pub fragment_info: Option<FragmentInfo>,
    pub hop_count: u8,
}
```

### Authentication

Server authentication (`quic/server.rs:362-373`):
```rust
let auth_result = match Self::authenticate_client(&client_id, &auth_token, &config) {
    Some(result) => result,
    None => {
        // Send AuthFailure, increment counter
        return Ok(());
    }
};
```

Rate limiting via `AuthRateLimiter`:
- Configurable max attempts per window
- Per-client-ID rate tracking
- 60-second cleanup interval

### Port Access Control

Session-level port restrictions based on `VpnAccessLevel`:

```rust
impl QuicTunnelSession {
    pub fn can_access_port(&self, port: u16, protocol: &str) -> bool {
        match self.access_level {
            VpnAccessLevel::Admin => true,
            VpnAccessLevel::General => {
                let allowed = if protocol.eq_ignore_ascii_case("udp") {
                    &self.allowed_ports_udp
                } else {
                    &self.allowed_ports_tcp
                };
                allowed.contains(&port)
            }
        }
    }
}
```

---

## 7. WireGuard Transport

### Implementation Backends

WireGuard supports three implementation modes (`wireguard/config.rs:6-12`):

```rust
pub enum WgImplementation {
    Auto,       // Kernel preferred, fallback to userspace
    Kernel,     // Linux netlink only
    Userspace,  // boringtun only
}
```

Backend selection (`wireguard/runtime.rs:60-93`):
1. If `Kernel` requested, check `is_kernel_wireguard_available()`
2. If `Auto`, try kernel first, then userspace
3. If userspace, check `is_userspace_available()`

### Kernel WireGuard (`wireguard/kernel.rs`)

Linux-specific implementation using netlink:

**Interface Setup:**
- Creates WireGuard interface via `wireguard_control` crate
- Sets private key, listen port, fwmark
- Configures MTU via `ip link set ... mtu`
- Adds address via `ip addr add`
- Brings interface up

**Peer Management:**
- Uses `PeerConfigBuilder` for peer configuration
- Converts CIDR notation to `AllowedIp` entries
- Sets endpoint, persistent keepalive
- Calls `DeviceUpdate::apply(&Backend::Kernel)`

**Stats Collection:**
- Polls interface stats every 5 seconds
- Records handshake times, rx/tx bytes
- Reports via metrics gauges/counters

### Userspace WireGuard (`wireguard/userspace.rs`)

Cross-platform implementation using `boringtun`:
- Runs WireGuard protocol entirely in userspace
- No kernel support required
- Similar API to kernel implementation
- Can send datagrams directly (kernel cannot)

### Session Management

`WgSessionManager` (`wireguard/session.rs:100-256`):
```rust
pub struct WgSessionManager {
    sessions: Arc<DashMap<String, WgPeerSession>>,
}

impl WgSessionManager {
    pub fn add_session(&self, session: WgPeerSession)
    pub fn remove_session(&self, id: &str)
    pub fn get_session(&self, id: &str) -> Option<WgPeerSession>
    pub fn get_session_by_public_key(&self, public_key: &str) -> Option<WgPeerSession>
    pub fn list_sessions(&self) -> Vec<WgPeerSession>
    pub fn session_count(&self) -> usize
}
```

Session states:
- `Initializing` - Created, not yet connected
- `Handshaking` - Performing WireGuard handshake
- `Established` - Active, encrypted tunnel
- `Rekeying` - Initiating key renegotiation
- `Disconnected` - Gracefully closed
- `Error` - Connection failed

---

## 8. Feature Gates

### `wireguard` Feature

**Location:** `Cargo.toml` and conditional compilation throughout `wireguard/` module

```rust
// wireguard/kernel.rs - only compiled with feature
#[cfg(all(target_os = "linux", feature = "wireguard"))]
use wireguard_control::{Backend, DeviceUpdate, ...};

// wireguard/config.rs
#[cfg(feature = "wireguard")]
pub fn x25519_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let secret = defguard_boringtun::x25519::StaticSecret::from(*private_key);
    let public = defguard_boringtun::x25519::PublicKey::from(&secret);
    *public.as_bytes()
}

#[cfg(not(feature = "wireguard"))]
pub fn x25519_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    // Fallback: generate random (NOT secure for WireGuard)
}
```

### `tun-rs` Feature

**Location:** `src/tunnel/tun.rs:141-644`

Controls platform-specific TUN device implementation:
```rust
#[cfg(feature = "tun-rs")]
pub mod platform {
    use tun_rs::{Device, DeviceBuilder, TunReader, TunWriter};
    // Full AsyncTunDevice implementation
}

#[cfg(not(feature = "tun-rs"))]
pub mod platform {
    // Stub implementation returning errors
}
```

### QUIC Feature Gates

The QUIC implementation has no additional feature gates - it's compiled by default but controlled by configuration:
```rust
// router.rs:46-63
let quic_runtime = if config.quic.enabled {
    let runtime = QuicRuntime::new(config.quic.clone())?
        .with_timeouts(...)
        .with_stream_limits(...);
    Some(Arc::new(runtime))
} else {
    None
};
```

### Availability Checks

```rust
// wireguard/mod.rs:133-154
pub async fn is_wireguard_available() -> bool {
    #[cfg(feature = "wireguard")]
    { true }
    #[cfg(not(feature = "wireguard"))]
    { false }
}

pub async fn detect_available_implementation() -> Option<WgImplementation> {
    if kernel::is_kernel_wireguard_available().await {
        return Some(WgImplementation::Kernel);
    }
    if userspace::is_userspace_available().await {
        return Some(WgImplementation::Userspace);
    }
    None
}
```

---

## 9. Global Registries

### QUIC Tunnel Registry

**File:** `src/tunnel/quic/registry.rs:10-113`

```rust
pub static QUIC_TUNNEL_REGISTRY: LazyLock<QuicTunnelRegistry> = 
    LazyLock::new(QuicTunnelRegistry::new);

pub struct QuicTunnelRegistry {
    sessions: DashMap<String, TunnelSessionInfo>,
    sessions_by_client: DashMap<String, String>,
    sessions_by_peer: DashMap<String, String>,
    runtime: Arc<RwLock<Option<Arc<QuicRuntime>>>>,
}

impl QuicTunnelRegistry {
    pub async fn set_runtime(&self, runtime: Arc<QuicRuntime>)
    pub async fn get_runtime(&self) -> Option<Arc<QuicRuntime>>
    pub async fn register(&self, info: TunnelSessionInfo)
    pub async fn unregister(&self, session_id: &str)
    pub async fn get(&self, session_id: &str) -> Option<TunnelSessionInfo>
    pub async fn get_by_client_id(&self, client_id: &str) -> Option<TunnelSessionInfo>
    pub async fn get_by_peer_id(&self, peer_id: &str) -> Option<TunnelSessionInfo>
    pub async fn list(&self) -> Vec<TunnelSessionInfo>
    pub async fn find_by_port(&self, port: u16) -> Option<TunnelSessionInfo>
}
```

### WireGuard Tunnel Registry

**File:** `src/tunnel/wireguard/session.rs:9-98`

```rust
pub static WG_TUNNEL_REGISTRY: LazyLock<WgTunnelRegistry> = 
    LazyLock::new(WgTunnelRegistry::new);

pub struct WgTunnelRegistry {
    sessions: DashMap<String, WgSessionInfo>,
}

impl WgTunnelRegistry {
    pub fn register(&self, session: WgSessionInfo)
    pub fn unregister(&self, session_id: &str)
    pub fn get(&self, session_id: &str) -> Option<WgSessionInfo>
    pub fn get_by_public_key(&self, public_key: &str) -> Option<WgSessionInfo>
    pub fn list(&self) -> Vec<WgSessionInfo>
    pub fn count(&self) -> usize
    pub fn update_stats(&self, session_id: &str, tx_bytes: u64, rx_bytes: u64)
    pub fn update_handshake(&self, session_id: &str)
}
```

---

## 10. Health Monitoring

### QuicHealthMonitor (`quic/health.rs:179-454`)

Connection quality tracking with configurable thresholds:

```rust
pub struct HealthCheckConfig {
    pub interval_secs: u64,           // Check interval (default: 10s)
    pub timeout_secs: u64,            // Check timeout (default: 5s)
    pub failure_threshold: u32,       // Failures to mark failed (default: 3)
    pub recovery_threshold: u32,       // Successes to recover (default: 2)
    pub rtt_warning_threshold_ms: u64, // RTT warning (default: 100ms)
    pub rtt_critical_threshold_ms: u64,// RTT critical (default: 500ms)
    pub loss_rate_warning_threshold: f64,    // (default: 5%)
    pub loss_rate_critical_threshold: f64,   // (default: 15%)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionQuality {
    Excellent,
    Good,
    Degraded,
    Poor,
    Failed,
}

impl ConnectionQuality {
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Excellent | Self::Good | Self::Degraded)
    }
    pub fn should_reconnect(&self) -> bool {
        matches!(self, Self::Poor | Self::Failed)
    }
}
```

### Health Events

```rust
pub enum HealthEvent {
    QualityChanged { session_id, peer_id, old_quality, new_quality },
    ConnectionFailed { session_id, peer_id, reason },
    ConnectionRecovered { session_id, peer_id },
    RttWarning { session_id, rtt_ms },
    PacketLossWarning { session_id, loss_rate },
}
```

---

## 11. UDP Tunnel Manager

**File:** `src/tunnel/udp_manager.rs`

Manages UDP tunnel lifecycle for DNS and other UDP protocols:

### Architecture

```
Client                    UdpTunnelManager                 QUIC
   |                             |                           |
   |-- DNS Query --------------->|                           |
   |                             |-- get_or_open_tunnel() -->|
   |                             |<-- ActiveUdpTunnel -------|
   |                             |                           |
   |                             |-- tunnel.send() --------->|
   |                             |<-- DatagramMessage -------|
   |                             |                           |
   |<-- DNS Response ------------|                           |
```

### Key Features

- **Lazy tunnel creation** - Opens tunnel on first packet
- **Sequence tracking** - Maps responses to requests
- **DNS transaction ID tracking** - Correlates DNS queries/responses
- **Idle cleanup** - Removes tunnels after configurable timeout
- **Stream fallback** - Falls back to stream for oversized packets

### Tunnel Life Cycle

1. `get_or_open_tunnel()` creates if not exists
2. Opens `UdpTunnelOpen` stream to peer
3. Spawns response handler task
4. `send()` adds sequence and tracks pending request
5. Response handler routes back by sequence/DNS ID
6. `cleanup_idle_tunnels()` removes expired tunnels

---

## 12. Upstream Resolution

**File:** `src/tunnel/upstream.rs`

Tunnel-aware upstream resolver for the proxy layer:

```rust
pub struct TunnelUpstreamResolver {
    manager: Arc<TunnelManager>,
    static_mappings: HashMap<String, String>,
}

impl TunnelUpstreamResolver {
    pub async fn resolve(&self, upstream: &str) -> Option<TunnelUpstreamTarget> {
        // Handles "tunnel:" and "tunnel://" prefixes
        // Returns TunnelUpstreamTarget with tunnel_identifier, static_port, session_id
    }
}

pub struct TunnelUpstreamTarget {
    pub tunnel_identifier: String,
    pub static_port: Option<u16>,
    pub session_id: Option<String>,
}
```

---

## 13. Configuration

### TunnelConfig Structure

Configuration comes from `crates/synvoid-config/src/tunnel.rs` (referenced via `config::TunnelConfig`):

- `quic.enabled` - Enable QUIC tunnels
- `quic.server.enabled` - Run QUIC server
- `quic.client.enabled` - Connect to peers
- `quic.port` - Listen port (default: 51821)
- `quic.max_idle_timeout_secs` - Idle timeout (default: 300s)
- `quic.keepalive_interval_secs` - Keepalive (default: 25s)
- WireGuard VPN settings
- UDP tunnel settings

---

## 14. Metrics

### QUIC Tunnel Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `synvoid.tunnel.quic.enabled` | gauge | QUIC tunnel enabled |
| `synvoid.tunnel.quic.server.enabled` | gauge | Server enabled |
| `synvoid.tunnel.quic.server.connections` | counter | Total connections |
| `synvoid.tunnel.quic.server.sessions` | counter | Established sessions |
| `synvoid.tunnel.quic.server.active_sessions` | gauge | Current sessions |
| `synvoid.tunnel.quic.server.streams.opened` | counter | Stream opens |
| `synvoid.tunnel.quic.client.connections` | counter | Client connections |
| `synvoid.tunnel.quic.client.peers` | gauge | Connected peers |
| `synvoid.tunnel.quic.datagrams.sent` | counter | Datagrams sent |
| `synvoid.tunnel.quic.datagrams.received` | counter | Datagrams received |
| `synvoid.tunnel.quic.health.rtt` | histogram | RTT measurements |
| `synvoid.tunnel.quic.health.failures` | counter | Health check failures |

### WireGuard Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `synvoid.tunnel.wireguard.running` | gauge | Runtime running |
| `synvoid.tunnel.wireguard.started` | counter | Start events |
| `synvoid.tunnel.wireguard.peers.added` | counter | Peers added |
| `synvoid.tunnel.wireguard.sessions.active` | gauge | Active sessions |
| `synvoid.tunnel.wireguard.peer.rx` | counter | Peer bytes received |
| `synvoid.tunnel.wireguard.peer.tx` | counter | Peer bytes sent |

### UDP Tunnel Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `synvoid.tunnel.udp.tunnels.opened` | counter | Tunnels opened |
| `synvoid.tunnel.udp.tunnels.active` | gauge | Active tunnels |
| `synvoid.tunnel.udp.tunnels.cleaned` | counter | Tunnels cleaned |
| `synvoid.tunnel.udp.datagrams.sent` | counter | Datagrams sent |
| `synvoid.tunnel.udp.responses.routed` | counter | Responses routed |
| `synvoid.tunnel.udp.response_latency` | histogram | Response latency |
