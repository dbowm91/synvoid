---
name: tunnel
description: Tunnel transport layer supporting QUIC and WireGuard protocols for encrypted upstream connections.
---

# Skill: Tunnel (Transport Layer)

## Context
The tunnel crate provides encrypted transport abstractions for connecting to upstream backends via QUIC or WireGuard tunnels, with session management, routing, and TUN device support.

## When to Use
- Adding new tunnel transport types
- Modifying QUIC connection management or WireGuard configuration
- Working on TUN device integration
- Debugging tunnel session lifecycle or routing

## Key Files
- `crates/synvoid-tunnel/src/lib.rs` — re-exports
- `crates/synvoid-tunnel/src/quic/` — `QuicConnection`, `QuicRuntime`, `QuicTunnelRegistry`
- `crates/synvoid-tunnel/src/quic_adapter.rs` — QUIC adapter
- `crates/synvoid-tunnel/src/router.rs` — `TunnelRouter`, `TunnelRouteSession`, `TunnelMapping`
- `crates/synvoid-tunnel/src/serialization.rs` — tunnel wire format
- `crates/synvoid-tunnel/src/tun.rs` — `AsyncTunDevice`, `TunConfig`, `TunInterface`, `TunPacket`
- `crates/synvoid-tunnel/src/udp_manager.rs` — `UdpTunnelManager`, `ActiveUdpTunnel`
- `crates/synvoid-tunnel/src/upstream.rs` — `TunnelUpstreamResolver`
- `crates/synvoid-tunnel/src/wireguard/` — `WireGuardClient`, `WireGuardServer`, `generate_keypair()`

## Architecture

### Transport Abstraction
`crates/synvoid-tunnel/src/lib.rs`:
```rust
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
```
Note the signatures that differ from an intuitive reading: `start`/`stop`
take `&mut self`, `stop` returns `()` (not a `Result`), `shutdown` is
**synchronous** and returns `()`, and `local_address` yields a
`SocketAddr` (not a `String`).

### Session Management
```
TunnelManager
  ├── QUIC_TUNNEL_REGISTRY (global static)
  └── WG_TUNNEL_REGISTRY (global static)
       ├── add_session(TunnelSession)
       ├── remove_session(id)
       ├── list_sessions()
       └── resolve(addr) → Option<TunnelSession>
```

### Routing Flow
```
Outgoing connection → TunnelRouter
  → Check TunnelMapping for existing route
  → If found → route through existing tunnel
  → If not → establish new tunnel → add mapping
```

## Critical Invariants
- `TunnelTransport` is `#[async_trait]` — its `async fn`s are async, but
  `shutdown()` is a plain sync method
- Session state uses `Arc<RwLock<HashMap>>` for concurrent access
- `broadcast::channel` used for shutdown signaling
- QUIC and WireGuard are separate, independent transports
- `detect_available_implementation()` (in `crates/synvoid-tunnel/src/wireguard/mod.rs`)
  is **async** and checks WireGuard availability at runtime

## Configuration
Schema: `crates/synvoid-config/src/tunnel.rs`. There is **no `[tunnel.wireguard]`
section** — WireGuard config lives under `[tunnel.vpn]`, and `[tunnel.quic]` has
no `endpoint`/`max_connections` field.

```toml
[tunnel]
enabled = false

[tunnel.quic]
enabled = false
bind_address = "0.0.0.0"       # default_quic_bind()
port = 51821                  # default_quic_port()
max_idle_timeout_secs = 300   # default_quic_max_idle()
keepalive_interval_secs = 25  # default_quic_keepalive()
cert_path = "..."             # optional
# plus [tunnel.quic.server] / [tunnel.quic.client]

[tunnel.vpn]                  # WireGuard
enabled = false
bind_address = "0.0.0.0"      # default_wg_bind()
port = 51820                  # default_wg_port()
interface = "wg0"             # default_wg_interface()
private_key = "..."           # Option<String>
addresses = ["10.0.0.2/32"]
persistent_keepalive = 0      # #[serde(default)] — only per-peer default is 25
# plus [[tunnel.vpn.peers]] (each with endpoint, persistent_keepalive, enabled)
```
Under `--features mesh` there is additionally `[tunnel.mesh]`, which reduced-feature
binaries reject fail-closed (Phase 41).

## Testing
```bash
cargo nextest run -p synvoid-tunnel --cargo-profile ci --profile ci
```
