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
- `tun-rs` — Enables TUN interface backend via `tun-rs` crate
- Default: QUIC-only tunnel support

## Key Integration Points

- **Upstream**: `synvoid-upstream` provides `TunnelConnector` for QUIC tunnel connections
- **Config**: Tunnel configuration via `TunnelConfig` in `synvoid-config`
- **Mesh**: Mesh networking can use tunnels for inter-node transport
- **Platform**: TUN interface creation via `synvoid-platform`

## Deep Dive Topics

### QUIC Tunnel Protocol State Machine (`quic/server.rs`, `quic/client.rs`)

Establishment (client → server):

1. `QuicRuntime::connect_to_peer()` opens a Quinn endpoint connection with timeout (`quic/runtime.rs:311-382`;
   retried variant `connect_to_peer` with `MAX_RETRIES=3`).
2. `QuicTunnelClient::connect_to_peer()` opens a bi-stream, writes `TunnelMessage::PeerHello`, reads
   `PeerHelloAck` (`quic/client.rs:240-297`); the app-level variant `connect_as_client()` does
   `Hello`/`HelloAck` with port mappings (`:299-376`).
3. `QuicTunnelServer::handle_connection()` accepts the bi-stream, reads `Hello`/`PeerHello`, validates
   IDs, applies the per-client sliding-window `AuthRateLimiter` (`server.rs:31-64`), authenticates the
   token, creates a `QuicTunnelSession` (access level, allowed ports, active streams), answers
   `HelloAck`/`PeerHelloAck`, and enters `session_loop` (`server.rs:277-553`).
4. Both sides register in `QUIC_TUNNEL_REGISTRY` (triple-indexed by session/client/peer ID,
   `quic/registry.rs:11-112`) and `QuicRuntime::sessions` (`runtime.rs:525-537`).

Steady state is `session_loop` → `accept_bi` → per-stream `handle_stream` dispatch (`server.rs:555-883`):
`KeepAlive` (RTT-tracked), `StreamOpen` → TCP proxy, `UdpTunnelOpen`, `PortOpen`/`PortClose`/`Data`.

### QUIC Framing and Serialization (`quic/framing.rs`, `quic/messages.rs`, `quic/ipc.rs`, `serialization.rs`)

- **Streams:** `[4-byte BE length][postcard TunnelMessage]` via `TunnelMessageCodec` (pooled reads through
  `BufferPool::acquire`, `framing.rs:30-83`); the 18-variant `TunnelMessage` enum covers
  Hello/HelloAck/AuthFailure/KeepAlive/PortOpen/Close/Data/StreamOpen/Close/UdpTunnel*/UdpData/
  DataChunk/DataAck/Error (`messages.rs:7-106`), plus a zero-copy `DataChunk` write path (`:165-189`).
- **Datagrams:** bare postcard `DatagramMessage` (id, seq, data, port, src/return addrs, fragment info,
  hop — no length prefix; Quinn frames), with `DatagramCapabilities { supported, max_size }`
  (`messages.rs:214-315`).
- **Local IPC multiplexing** (unix): `[4-byte len][u64 stream_id][u8 type][u8 flags][u32 payload_len][payload]`
  with `StreamType { Tcp=1, Udp=2, Control=0 }` and SYN/FIN/RST/DATA flags (`ipc.rs:25-151`).
- All serialization is postcard (`serialization.rs`); the `*_bincode` helpers are postcard aliases kept
  for `TunnelMessage` compat.

### Session Lifecycle and Timeouts (`quic/runtime.rs`, `quic/registry.rs`, `udp_manager.rs`)

- **Registration:** dual-index (`QUIC_TUNNEL_REGISTRY` + runtime session map); `add_session` / `remove_session`
  keep both in sync (`runtime.rs:525-562`).
- **Idle timeout:** quinn `TransportConfig` `max_idle_timeout` (default 300s, `runtime.rs:169-172`);
  25s keepalive; high-throughput + stream-limit tuning in `build_transport_config()` (`:133-175`).
- **UDP tunnels:** `UdpTunnelManager` lazily opens (`get_or_open_tunnel`: `UdpTunnelOpen` → `Ack`,
  `udp_manager.rs:86-170`) and `cleanup_idle_tunnels()` sweeps `last_activity > timeout` (`:248-273`).
  Sends use datagrams when under `max_datagram_size`, else stream fallback (`:281-295`); responses are
  matched by sequence with latency recording (`spawn_response_handler`, `:172-211`).
- **Teardown:** `close_session(id)` → `conn.close(0, …)` → unregister everywhere (`runtime.rs:659-666`).
- **Server admission:** `Semaphore`-capped `max_connections` (`server.rs:134-135`).

### UDP Tunnel Multiplexing (`udp_manager.rs`, `quic/server.rs:885-1190`)

Server side binds a local UDP socket per tunnel and forwards both directions (local→QUIC datagrams,
QUIC→local) with client-address tracking, DNS transaction-ID correlation (`send_with_dns_tracking`),
and expired-client cleanup. Client side reuses tunnels per (peer, port) with pending-request maps
carrying client addr + timestamp + optional DNS tx ID.

### Health Checking and Failover (`quic/health.rs`, `quic/client.rs:143-238`)

`QuicHealthMonitor` tracks per-session RTT history (10 samples), loss rate, and consecutive
failures/successes, merging them into `ConnectionQuality { Excellent/Good/Degraded/Poor/Failed }` and
emitting `HealthEvent::{QualityChanged, ConnectionFailed, ConnectionRecovered, RttWarning,
PacketLossWarning}` (`health.rs:12-211`). Monitoring runs as a periodic loop (semaphore-capped at 50
concurrent checks). Client reconnect uses `JitteredBackoff` (exponential + 30% jitter, max 10 retries;
see `vpn_client_deep_dive.md` for the shared algorithm); keepalives (`KeepAlive` → `KeepAliveAck`)
double as RTT probes (`client.rs:490-522`).

### WireGuard Transport (`wireguard/`)

- **Backend selection:** `WireGuardRuntime::select_backend()` honors `WgImplementation { Auto, Kernel,
  Userspace }` by probing kernel support first (`runtime.rs:60-94`); the kernel backend is currently a
  tracking stub reporting "not yet available" (`kernel.rs:78-179`), so userspace (boringtun) does the work.
- **Userspace:** `start_boringtun()` decodes the x25519 private key, creates the TUN interface, registers
  peers (`userspace.rs:133-207`); outbound datagrams queue through mpsc with per-session stats (`:236-262`).
- **Sessions:** `WgPeerSession` state machine `Initializing → Handshaking → Established → Rekeying →
  Disconnected/Error` with interval-based `needs_rekey()` (`session.rs:106-174`); tracked both globally
  (`WG_TUNNEL_REGISTRY`) and per runtime (`WgSessionManager`). Stats parse `wg show` output on Linux
  (`stats.rs:93-228`).
- **Keys:** `generate_keypair()` / `x25519_public_from_private()` with base64 encoding (`config.rs:315-347`).
- **TUN per platform** (`wireguard/tun.rs:148-991`): Linux `/dev/net/tun` via `ioctl(TUNSETIFF)`, BSD
  `/dev/tun`, macOS utun (socket + ioctl, 4-byte AF header strip/prepend). The top-level `tun.rs`
  abstraction is dependency-free and reports unavailable — platform code lives under `wireguard/`.

### TLS Configuration (`quic/tls.rs`)

`QuicTlsConfig` (cert/key/CA paths, mTLS flags, cert auto-generation) builds Quinn server configs from
PEM files and client configs with either platform verification or explicit opt-out (`verify_server=false`).
Dev convenience `generate_self_signed_cert()` (rcgen) writes keys atomically with mode `0o600`
(`tls.rs:246-293`); all token comparisons on the path use constant-time `secure_token_compare`
(`validation.rs:12-17`), and identifiers/ports/sizes are validated and clamped (`:42-173`).

### Upstream and Router Integration (`upstream.rs`, `quic_adapter.rs`, `router.rs`)

- `TunnelUpstreamResolver` maps `tunnel:` URIs to sessions or static mappings (`upstream.rs:36-66`),
  wrapped for concurrent use by `TunnelUpstreamPool`.
- `QuicTunnelAdapter` implements `synvoid-upstream`'s `TunnelConnector` by delegating to
  `QUIC_TUNNEL_REGISTRY.get_runtime()` (`quic_adapter.rs:8-20`).
- `TunnelRouter` owns the QUIC runtime/server/client and resolves an identifier to
  `TunnelBackend::{Direct, Tunnel}` by scanning client sessions then active session mappings
  (`router.rs:149-208`).

### Access Control (`quic/server.rs:31-110,350-359`)

`can_access_port()`: `Admin` access always passes; `General` is checked against per-port TCP/UDP
allowlists stored on the session. Authentication binds tokens to ACLs at session creation, with the
sliding-window auth rate limiter bounding brute force.
