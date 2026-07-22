# VPN Client Deep Dive

## Overview

The `synvoid-vpn-client` crate provides VPN client connectivity for SynVoid, supporting both QUIC and WireGuard transports. It manages local port mapping, reconnection logic, event handling, and connection statistics.

## Crate Location

`crates/synvoid-vpn-client/`

## Key Files

| File | Responsibility |
|------|----------------|
| `lib.rs` | Crate root, VPN client lifecycle, transport selection |
| `config.rs` | VPN client configuration |
| `local_listener.rs` | Local port mapping and forwarding |
| `events.rs` | VPN client event system (connect, disconnect, error) |
| `stats.rs` | Connection statistics and tracking |

## Architecture

```
┌───────────────────────────────────────┐
│         synvoid-vpn-client            │
├───────────────────────────────────────┤
│  Transport Selection                  │
│  ├── QUIC (via synvoid-tunnel)        │
│  └── WireGuard (via synvoid-tunnel)   │
├───────────────────────────────────────┤
│  Local Listener ──► Port Mapping      │
│  Events ──► Reconnection Logic        │
│  Stats ──► Connection Tracking         │
└───────────────────────────────────────┘
```

## Key Integration Points

- **Tunnel**: `synvoid-tunnel` provides the underlying QUIC and WireGuard transports
- **Config**: VPN configuration via `VpnConfig` in `synvoid-config`
- **Platform**: Platform detection for transport selection via `synvoid-platform`
- **Metrics**: Connection stats reported via `synvoid-metrics`

## Deep Dive Topics

> **TODO**: Expand with implementation details for:
> - Transport selection logic (QUIC vs WireGuard)
> - Local port mapping and forwarding rules
> - Reconnection and retry strategies
> - Event system and callback patterns
> - Statistics collection and reporting
> - Integration with mesh networking for VPN-over-mesh
