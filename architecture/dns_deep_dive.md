# DNS & Tunnel Deep Dive

## Overview

This document covers SynVoid's DNS server with DNSSEC support, tunnel protocols (QUIC tunnel, WireGuard), and VPN client functionality.

---

## 1. DNS Module (`src/dns/`)

### Overview

SynVoid's DNS module provides an **authoritative DNS server** with DNSSEC signing, recursive resolver capabilities, and support for encrypted DNS protocols (DoT, DoH, DoQ). It also supports dynamic updates (RFC 2136), zone transfers (AXFR/IXFR), and mesh-based anycast for distributed deployments.

### Feature-Gated

The DNS module is gated by the `dns` feature in `Cargo.toml`.

### Key Files

| File | Responsibility |
|------|----------------|
| `store.rs` | Zone storage interface and implementation |
| `server/mod.rs` | Core DNS server, query handling, zone management, protocol handlers |
| `server/startup.rs` | Server initialization, listener spawning, protocol server startup (DoT/DoH/DoQ) |
| `server/query.rs` | Query processing logic, response building |
| `server/zone.rs` | Zone data structures, serial management (RFC 1982) |
| `server/rate_limit.rs` | Rate limiting (RRL - Response Rate Limiting) |
| `server/sharded_store.rs` | Sharded zone storage for high concurrency |
| `dnssec.rs` | DNSSEC types, algorithms, key rotation config |
| `dnssec_signing.rs` | RRSIG creation, NSEC/NSEC3 record generation |
| `dnssec_validation.rs` | Signature verification, chain of trust, DS record handling |
| `dnssec_key_mgmt.rs` | DNSSEC key lifecycle management |
| `tsig.rs` | TSIG authentication for dynamic updates and zone transfers |
| `recursive.rs` | Recursive DNS resolver using `hickory_resolver::TokioResolver` |
| `recursive_cache.rs` | Cache for recursive resolver responses |
| `trust_anchor.rs` | RFC 5011 trust anchor management |
| `hsm.rs` | HSM-based key storage and signing |
| `cookie.rs` | RFC 7873 DNS cookies - client authentication via EDNS cookie exchange |
| `update.rs` | Dynamic DNS updates (RFC 2136) |
| `transfer.rs` | Zone transfers (AXFR/IXFR) |
| `doh.rs` | DNS-over-HTTPS server |
| `dot.rs` | DNS-over-TLS server |
| `doq.rs` | DNS-over-QUIC server |
| `cache.rs` | Authoritative server response cache |
| `firewall.rs` | DNS firewall for blocking queries/responses |
| `wire.rs` | DNS wire format parsing/building |
| `messages.rs` | Mesh sync messages for distributed DNS |
| `anycast.rs` | Anycast socket management |
| `anycast_sync.rs` | Mesh-based zone synchronization |
| `qname.rs` | DNS query name parsing and normalization |
| `zone_manager.rs` | Zone lifecycle management, loading, and persistence |
| `zone_file.rs` | Zone file parsing and serialization |
| `rpz.rs` | Response Policy Zones for DNS firewall rules |
| `edns.rs` | EDNS(0) extension handling (OPT records, buffer size) |
| `limits.rs` | Query and response size limits, rate limiting thresholds |

### Query Flow

1. **Query Reception**: UDP/TCP listeners on port 53 (or configured port)
2. **Rate Limiting**: IP-based rate limiting check via `DnsRateLimiter`
3. **Query Validation**: `DnsQueryValidator` checks malformed queries
4. **Firewall**: `DnsFirewall` evaluates against blocking rules (subnet, opcode)
5. **Cache Check**: If enabled, `DnsCache` checked first
6.  **Query Coalescing**: `QueryCoalescer` collapses identical in-flight queries
    - Implemented at `src/dns/query_coalesce.rs`
    - Configured via `config.settings.query_coalescing` (enabled, max_wait_ms, max_entries, entry_ttl_secs)
    - `QueryCoalescer::with_config()` created in `DnsServer::new()` at `src/dns/server/mod.rs:634-644`
    - Passed to query handler via `QueryContext` at `src/dns/server/mod.rs:419-445`
    - `max_wait_ms` controls the timeout for coalescing requests via `tokio::time::timeout`
7. **Zone Resolution**: `ShardedZoneStore` looks up zone, builds response
8. **DNSSEC Signing**: If zone signed, RRSIG records added
9. **Response**: Wire format response sent to client

### Zone Transfers (AXFR/IXFR) (`transfer.rs`)

**IXFR** (RFC 1995) - Incremental zone transfer
**TSIG** (RFC 2845) - Transaction signature authentication for zone transfers

**AXFR Record Type Coverage:** The AXFR implementation at `src/dns/transfer.rs:829-1029` handles the following record types: A, AAAA, CNAME, NS, SOA, TXT, MX, SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA. The following record types are **not handled** (fall through with `_ => continue` at line 1029):
- **NAPTR** (35) - Naming Authority Pointer
- **CERT** (37) - Certificate record
- **SMMEA** (48) - Simple Mail Messaging Exchange Authority
- **DNAME** (39) - Delegation Name
- **Note:** AXFR requests for unsupported record types will return no records of that type in the response. These record types are silently skipped. Adding support requires implementing the wire format encoding for each type (DNS-4).

### DNSSEC Signing/Validation

**Signing** (`dnssec_signing.rs`):
- Supported Algorithms: **Ed25519** (Algorithm 15), **RSA/SHA-256** (Algorithm 8)
- Note: ECDSAP256SHA256 (13) and ECDSAP384SHA384 (14) are **NOT implemented** - only Ed25519 and RSA are supported.
- `sign_data()` - Signs RDATA using Ed25519 or RSA private key
- `create_rrsig_record()` - Builds RRSIG with inception/expiration (7 days signed)
- `create_nsec_record()` / `create_nsec3_record()` - Proof of nonexistence
- **NSEC3 Algorithms**: Algorithm 1 (SHA-1) and Algorithm 2 (SHA-256) supported

**Validation** (`dnssec_validation.rs`):
- `calculate_key_tag()` - DNSKEY key tag per RFC 4034
- `compute_dnskey_canonical()` - Canonical DNSKEY wire format
- `compute_ds_digest()` - DS record digest (SHA-1 [type 1], SHA-256 [type 2], SHA-384 [type 4]). GOST R 34.11-94 (type 3) **not supported** - returns error at `src/dns/dnssec_validation.rs:260`.
- `verify_ds_digest()` - Validates DS against DNSKEY
- **Trust Chain (RFC 4035):** Validation follows these steps:
  1. Start with a trusted trust anchor (configured or RFC 5011 auto-updated)
  2. Verify DNSKEY chain: trust anchor → DS record → DNSKEY → RRSIG → zone data
  3. Check RRSIG inception/expiration windows
  4. Verify signature using the DNSKEY's algorithm
  5. For authenticated denial of existence, verify NSEC/NSEC3 proofs

**Key Management** (`dnssec_key_mgmt.rs`):
- KSK (Key Signing Key) / ZSK (Zone Signing Key) separation
- Automatic key rotation with configurable intervals (KSK: 30d, ZSK: 7d)
- HSM support via `HsmManager` (PKCS#11 backend optional)

**Trust Anchors** (`trust_anchor.rs`):
- RFC 5011 automated trust anchor updates
- States: `Seen → Pending → Valid → Revoked → Removed → Missing`

**DNSSEC Limitations** (`dnssec.rs:1-13`):
- Manual wire format construction - no built-in compression support
- All DNSSEC record building is done manually

### TSIG (Feature-Gated)

**Rust Version Requirement**: Uses `u64::abs_diff()` which requires Rust 1.78+ (mitigated by modern Rust edition 2021).

**Algorithms**: HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512

**Security Features**:
- Constant-time MAC comparison via `subtle::ConstantTimeEq`
- Replay attack prevention via `ReplayCache` (5-minute TTL, 10K entries)
- Time validity check with configurable fudge (default 300s)

**Verification Flow**:
1. Check `tsig_error` is 0
2. Validate time signed within fudge window
3. Check replay cache
4. Verify key exists and algorithm matches
5. Compute MAC over message + key name + algorithm + time + fudge + error + other
6. Constant-time compare with original MAC

---

## 2. Tunnel Module (`src/tunnel/`)

### Overview

Tunnel module provides **VPN tunnel protocols** for site-to-site and client connectivity. Supports **QUIC-based tunnels** and **WireGuard**.

### Key Files

| File | Responsibility |
|------|----------------|
| `mod.rs` | Core tunnel traits, `TunnelTransport`, `TunnelManager` |
| `quic/mod.rs` | QUIC tunnel sub-module exports |
| `quic/runtime.rs` | QUIC runtime initialization, connection management |
| `quic/client.rs` | QUIC tunnel client session |
| `quic/server.rs` | QUIC tunnel server, session management |
| `quic/messages.rs` | TunnelMessage protocol (Hello, DataChunk, PortMapping, etc.) |
| `quic/framing.rs` | Message encoding/decoding |
| `quic/validation.rs` | Input validation, jittered backoff |
| `quic/health.rs` | Connection quality monitoring |
| `quic/tls.rs` | TLS certificate generation |
| `quic/ipc.rs` | Inter-process communication |
| `wireguard/mod.rs` | WireGuard exports, server wrapper |
| `wireguard/runtime.rs` | WireGuard async runtime |
| `wireguard/server.rs` | WireGuard server implementation |
| `wireguard/client.rs` | WireGuard client |
| `wireguard/session.rs` | Peer session management |
| `wireguard/tun.rs` | TUN device for userspace WireGuard |
| `wireguard/kernel.rs` | Kernel WireGuard integration |
| `wireguard/userspace.rs` | Userspace WireGuard implementation |
| `wireguard/config.rs` | Key generation, key parsing |
| `router.rs` | Tunnel routing, `TunnelRouter` |
| `tun.rs` | TUN device abstraction |

### QUIC Tunnel Protocol

**Message Types**:
```rust
TunnelMessage::Hello { client_id, auth_token, mappings, supports_datagrams }
TunnelMessage::HelloAck { server_session_id, server_mappings, supports_datagrams, max_datagram_size, access_level }
TunnelMessage::AuthFailure { reason }
TunnelMessage::KeepAlive
TunnelMessage::KeepAliveAck
TunnelMessage::PortOpen { identifier, port, protocol }
TunnelMessage::PortClose { identifier }
TunnelMessage::PortData { identifier }
TunnelMessage::RequestProxy { identifier, target_host, target_port }
TunnelMessage::ProxyResponse { identifier, success, message }
TunnelMessage::PeerHello { peer_id, auth_token, supports_datagrams }
TunnelMessage::PeerHelloAck { session_id, supports_datagrams, max_datagram_size }
TunnelMessage::Error { code, message }
TunnelMessage::DataChunk { identifier, sequence, data, fin }
TunnelMessage::DataAck { identifier, sequence }
TunnelMessage::StreamOpen { identifier, port, protocol, tls_passthrough }
TunnelMessage::StreamOpenAck { identifier, success, message }
TunnelMessage::StreamClose { identifier }
TunnelMessage::UdpTunnelOpen { identifier, port }
TunnelMessage::UdpTunnelOpenAck { identifier, success, message }
TunnelMessage::UdpTunnelClose { identifier }
TunnelMessage::UdpData { identifier, data }
TunnelMessage::UdpClose { identifier }
```

**Features**:
- Stream-based tunnel protocol over QUIC
- Bidirectional streams for port mappings
- Datagram support for UDP emulation
- TLS-secured transport
- Automatic certificate generation
- Health monitoring with jittered backoff reconnection
- Fragmentation for large datagrams (max 1200 bytes per payload)

### WireGuard

- Userspace implementation via `boringtun` (defguard/boringtun)
- Peer session management with keepalive
- Key pair generation (Curve25519)
- Persistent keepalive configuration
- AllowedIPs routing

### Tunnel Transport Trait

```rust
#[async_trait]
pub trait TunnelTransport: Send + Sync {
    fn tunnel_type(&self) -> TunnelType;
    async fn start(&mut self) -> Result<(), ...>;
    async fn stop(&mut self);
    fn is_running(&self) -> bool;
    fn stats(&self) -> TunnelStats;
    fn local_address(&self) -> Option<SocketAddr>;
    fn peer_count(&self) -> usize;
    fn peers(&self) -> Vec<PeerInfo>;
    fn shutdown(&self);
}
```

---

## 3. VPN Client Module (`src/vpn_client/`)

### Overview

VPN client for connecting to SynVoid VPN servers. Supports **QUIC transport** (primary) and **WireGuard** as fallback.

### Key Files

| File | Responsibility |
|------|----------------|
| `mod.rs` | VpnClient, VpnSession, connection management |
| `config.rs` | VpnClientConfig, TransportType, PortMapping, ReconnectConfig |
| `local_listener.rs` | Local port forwarding listeners |
| `stats.rs` | VpnStats, VpnStatsTracker |
| `events.rs` | VpnEvent, VpnEventCallback |

### Key Structs

```
VpnClient                    - Main VPN client with transport abstraction
VpnSession                   - Active session (QUIC connection, datagram caps)
VpnClientConfig              - Client configuration (server, auth, port mappings)
VpnClientBuilder (struct)    - Builder pattern for VpnClient construction
VpnConnection (enum)         - Quic { session }, WireGuard
ClientPortMapping            - Local to remote port mapping
ReconnectConfig              - Auto-reconnect settings
LocalPortMapping             - Per-listener local binding
LocalListener                - Handles port forwarding over tunnel
TransportType (enum)        - Quic, WireGuard
VpnStats                     - Traffic stats snapshot
VpnStatsTracker              - Real-time stats collection
VpnEvent (enum)              - Connected, Disconnected, PortMapped, Error
PlatformInfo                 - Platform capabilities (TUN, WireGuard)
```

### VPN Connection Flow

**QUIC Transport**:
1. Create `QuicRuntime` with client config
2. Connect to server via `connect_to_peer()`
3. Open bidirectional stream
4. Send `TunnelMessage::Hello` with client_id, auth_token, mappings
5. Receive `HelloAck` with server_session_id, access_level
6. Create `VpnSession` with QUIC connection
7. Start `LocalListener` for each port mapping
8. Optional datagram support if server announces capability

**WireGuard Transport**:
1. Create `WireGuardRuntime` from config
2. Start WireGuard interface
3. Bring up TUN device
4. Routes traffic through WireGuard tunnel

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                         DNS Module                               │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ DnsServer   │───▶│ DoH Server   │    │ DoT/DoQ Servers  │  │
│  │ (Port 53)   │    │ (Port 443)   │    │ (Ports 853/8853) │  │
│  └──────┬───────┘    └──────────────┘    └──────────────────┘  │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Query Handler Chain                         │   │
│  │  RateLimit → Validate → Firewall → Cache → ZoneLookup   │   │
│  └─────────────────────────────────────────────────────────┘   │
│         │                                                       │
│         ▼                                                       │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐               │
│  │ DNSSEC     │  │   TSIG     │  │  Recursive │               │
│  │ Signing/  │  │  (Update/  │  │  Resolver   │               │
│  │ Validation │  │   XFR)     │  │             │               │
│  └────────────┘  └────────────┘  └────────────┘               │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        Tunnel Module                             │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  TunnelRouter                             │   │
│  │              (routes to backend tunnels)                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                    │                    │                      │
│                    ▼                    ▼                      │
│  ┌─────────────────────┐   ┌─────────────────────┐            │
│  │    QUIC Tunnel      │   │    WireGuard         │            │
│  │                     │   │                     │            │
│  │  - QUIC Runtime     │   │  - WireGuardServer   │            │
│  │  - Stream multiplex │   │  - Peer sessions     │            │
│  │  - Datagram support │   │  - Kernel/Userspace  │            │
│  │  - TLS encryption   │   │  - TUN device        │            │
│  └─────────────────────┘   └─────────────────────┘            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      VPN Client Module                           │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                      VpnClient                           │   │
│  │                                                           │   │
│  │  - Transport abstraction (QUIC/WireGuard)                │   │
│  │  - Session management                                    │   │
│  │  - Auto-reconnect with jittered backoff                  │   │
│  │  - Event callbacks                                       │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Related Documentation

- [Overview](overview.md) - Bird's eye view of SynVoid architecture
- [Mesh Deep Dive](mesh_deep_dive.md) - Mesh networking (anycast DNS)
- [Layer 3.5 Deep Dive](layer_3_5_deep_dive.md) - Post-quantum key exchange for tunnels