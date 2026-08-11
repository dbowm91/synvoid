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
```rust
#[async_trait]
pub trait TunnelTransport: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    fn is_running(&self) -> bool;
    fn stats(&self) -> TunnelStats;
    fn local_address(&self) -> Option<String>;
    fn peer_count(&self) -> usize;
    fn peers(&self) -> Vec<PeerInfo>;
    async fn shutdown(&self) -> Result<()>;
}
```

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
- `TunnelTransport` is `async_trait` — all operations are async
- Session state uses `Arc<RwLock<HashMap>>` for concurrent access
- `broadcast::channel` used for shutdown signaling
- QUIC and WireGuard are separate, independent transports
- `detect_available_implementation()` checks WireGuard availability at runtime

## Configuration
```toml
[tunnel]
enabled = false

[tunnel.quic]
endpoint = "0.0.0.0:51820"
max_connections = 256

[tunnel.wireguard]
interface = "wg0"
private_key = "..."
```

## Testing
```bash
cargo test -p synvoid-tunnel --all-targets
```
