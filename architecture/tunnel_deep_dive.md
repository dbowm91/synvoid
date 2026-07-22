# Tunnel Deep Dive

## Overview

The `synvoid-tunnel` crate provides VPN tunnel infrastructure for SynVoid, supporting both QUIC-based tunnels and WireGuard. It handles tunnel establishment, routing, TUN interface management, and UDP tunnel multiplexing.

## Crate Location

`crates/synvoid-tunnel/`

## Key Files

| File | Responsibility |
|------|----------------|
| `lib.rs` | Crate root, re-exports |
| `quic/mod.rs` | QUIC tunnel module root |
| `quic/runtime.rs` | QUIC tunnel runtime lifecycle |
| `quic/client.rs` | QUIC tunnel client |
| `quic/server.rs` | QUIC tunnel server |
| `quic/tls.rs` | QUIC tunnel TLS configuration |
| `quic/framing.rs` | QUIC tunnel frame encoding |
| `quic/messages.rs` | QUIC tunnel message types |
| `quic/registry.rs` | QUIC tunnel connection registry |
| `quic/health.rs` | QUIC tunnel health checking |
| `quic/validation.rs` | QUIC tunnel input validation |
| `quic/ipc.rs` | QUIC tunnel IPC integration |
| `wireguard/mod.rs` | WireGuard module root |
| `wireguard/client.rs` | WireGuard client implementation |
| `wireguard/server.rs` | WireGuard server implementation |
| `wireguard/runtime.rs` | WireGuard runtime lifecycle |
| `wireguard/config.rs` | WireGuard configuration |
| `wireguard/session.rs` | WireGuard session management |
| `wireguard/tun.rs` | TUN interface management |
| `wireguard/kernel.rs` | Kernel WireGuard integration |
| `wireguard/userspace.rs` | Userspace WireGuard (boringtun) |
| `wireguard/stats.rs` | WireGuard statistics |
| `tun.rs` | TUN device abstraction |
| `router.rs` | Tunnel routing table |
| `udp_manager.rs` | UDP tunnel multiplexing |
| `upstream.rs` | Upstream tunnel connections |
| `quic_adapter.rs` | QUIC adapter for tunnel integration |
| `serialization.rs` | Tunnel message serialization |

## Architecture

```
┌─────────────────────────────────────────┐
│            synvoid-tunnel               │
├─────────────────────────────────────────┤
│  QUIC Tunnel          WireGuard Tunnel  │
│  ├── client           ├── client        │
│  ├── server           ├── server        │
│  ├── runtime          ├── runtime       │
│  ├── tls              ├── config        │
│  ├── framing          ├── session       │
│  ├── messages         ├── tun           │
│  ├── registry         ├── kernel        │
│  ├── health           ├── userspace     │
│  └── ipc              └── stats         │
├─────────────────────────────────────────┤
│  TUN Interface │ Router │ UDP Manager   │
└─────────────────────────────────────────┘
```

## Feature Gates

- `wireguard` — Enables WireGuard tunnel support (requires `defguard_boringtun`)
- Default: QUIC-only tunnel support

## Key Integration Points

- **Upstream**: `synvoid-upstream` provides `TunnelConnector` for QUIC tunnel connections
- **Config**: Tunnel configuration via `TunnelConfig` in `synvoid-config`
- **Mesh**: Mesh networking can use tunnels for inter-node transport
- **Platform**: TUN interface creation via `synvoid-platform`

## Deep Dive Topics

> **TODO**: Expand with implementation details for:
> - QUIC tunnel protocol and frame format
> - WireGuard session lifecycle and key rotation
> - TUN interface management across platforms
> - UDP multiplexing and connection tracking
> - Health checking and failover behavior
> - Integration with upstream connection pooling
