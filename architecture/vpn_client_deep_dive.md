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
- **Config**: VPN configuration via `VpnClientConfig` in `synvoid-vpn-client`
- **Platform**: Platform detection for transport selection via `synvoid-platform`

## Deep Dive Topics

### Transport Selection (`lib.rs:79-153`)

`VpnClientConfig.transport: TransportType` selects the backend (default `Quic`):

1. User sets the transport via `with_transport()` / `with_wireguard()` or the TOML `transport` key.
2. `VpnClient::new()` (`lib.rs:80`) runs platform checks first: WireGuard without
   userspace support is a hard error; missing TUN is a warning; admin-gated TUN logs an info.
3. Only the selected runtime is constructed — `QuicRuntime` (300s idle timeout, 25s keepalive,
   caller-supplied connect timeout) **or** `WireGuardRuntime` from the `wireguard` config block.
4. `connect()` (`lib.rs:148`) dispatches on the enum: `TransportType::Quic` → `connect_quic()`,
   `TransportType::WireGuard` → `connect_wireguard()`. Active state is `VpnConnection::Quic { session }` /
   `VpnConnection::WireGuard` (`lib.rs:38`).

QUIC handshake is `Hello` → `HelloAck`, after which a `VpnSession` (`lib.rs:55`: id, client_id,
remote_addr, connected_at, QUIC `Connection`, datagram capabilities, access level) is stored and
`VpnEvent::Connected` fires. WireGuard connect delegates to `WireGuardRuntime::start()`.

### Local Port Mapping and Forwarding (`local_listener.rs`)

After a QUIC connect, `setup_port_mappings()` (`lib.rs:316`) builds one `LocalListener` per
`ClientPortMapping` (`config.rs:232`: local/remote port, `Tcp`/`Udp` protocol, upstream host),
bound to `{local_bind_host}:{local_port}` and stored in a `DashMap` keyed by
`identifier = "local-{port}-{protocol}"`. Mappings can also be added/removed at runtime
(`add_port_mapping`, `remove_port_mapping`).

- **TCP** (`start_tcp`, `:165`): binds a `TcpListener`, accepts in a loop, and per connection opens
  a QUIC bi-directional stream: `StreamOpen` → wait `StreamOpenAck` → relay `DataChunk`s with
  length-prefixed framing and a 64KB buffer pool.
- **UDP** (`start_udp`, `:364`): requires negotiated datagram support; binds a `UdpSocket`,
  opens the tunnel (`UdpTunnelOpen` → `UdpTunnelOpenAck`), then pumps `DatagramMessage`s over QUIC
  datagrams (not streams) via recv/send tasks plus a periodic cleanup task. `UdpClientTracker`
  (`:53`) maps local client addresses with a 10K-client cap, 300s TTL, and batched 60s cleanup.
- **WireGuard mode** ignores port mappings — traffic routes at the IP layer through the TUN device.

### Reconnection Strategy (`lib.rs:481`, `quic/validation.rs:191-234`)

`run_with_auto_reconnect()` is the main loop: connect → serve → on loss stop listeners and retry.
Backoff is `JitteredBackoff`: `min(base * multiplier^(attempt-1), max_delay)` ± 30% jitter
(defaults from `config.rs:7-11` / `ReconnectConfig`: 1s base, 60s cap, 2.0x multiplier, 10 max attempts).
Success resets the backoff; exceeding `max_attempts` returns an error. Loss detection is
`connection.closed()` for QUIC vs 60s polling for WireGuard; sleeps are shutdown-cancellable.

### Event System and Statistics (`events.rs`, `stats.rs`)

Callbacks are `VpnEventCallback = Arc<dyn Fn(VpnEvent) + Send + Sync>` (`events.rs:3`), installed via
`with_event_callback()`. Variants: `Connected { session_id, access_level }`, `Disconnected { reason }`,
`Reconnecting { attempt }`, `PortMappingAdded/Removed { identifier }`, `Error { error }`.
`VpnStatsTracker` (`stats.rs:16`) holds atomic byte/packet counters plus `connected_at` /
`last_message_at` timestamps, snapshotted non-blockingly via `get_stats()`.

### Configuration (`config.rs`)

`VpnClientConfig::new(host, port, client_id, token)` (`:117`) plus builder methods; wire format is TOML
(`load_config_from_file` uses `toml::from_str`). Notable fields: `server_name` + `verify_server` /
`server_ca` (TLS verification), `local_bind_host`, `[[port_mappings]]`, `reconnect: ReconnectConfig`,
and `wireguard: Option<WireGuardClientTransportConfig>` (private key, peer public key/endpoint,
allowed IPs — convertible via `to_wireguard_config()`). `to_quic_config()` (`:191`) maps to the
tunnel QUIC config (BBR, 300s idle timeout, 16MB stream window).

### CLI and Dashboard (`src/bin/synvoid-vpn.rs`, `src/bin/server.rs`)

- `synvoid-vpn` subcommands: `connect` (server/port/client-id/token, `--tcp`/`--udp` `local:remote`
  mappings parsed by `parse_port_mapping`, `--reconnect`, `--max-retries`), `connect-config`,
  `generate-config` (writes a TOML template), `serve` (dashboard mode).
- `server` binary: axum dashboard with `GET /api/status` (connected, server, transport, mappings,
  byte/packet counters, duration), `POST /api/connect`, `POST /api/disconnect`,
  `POST /api/mapping/{add,remove}`. API-key auth uses constant-time comparison
  (`subtle::ConstantTimeEq` in `check_auth`).
