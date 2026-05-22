# DNS Architecture Review - Improvement Plan

**Review Date:** 2026-05-22
**Reviewer:** Architecture Agent
**Document Reviewed:** `architecture/dns_deep_dive.md`
**Modules Reviewed:** DNS (`src/dns/`), Tunnel (`src/tunnel/`), VPN Client (`src/vpn_client/`)

---

## Executive Summary

The DNS deep dive documentation is **largely accurate** but contains several discrepancies between documented architecture and actual implementation. Most significantly, there's a **security bug** in DS digest verification that violates the constant-time comparison requirement documented in `AGENTS.md`.

---

## 1. Summary: Documented vs Implemented

### 1.1 DNS Module - Key Files (Documented)

| Documented File | Status | Actual Location |
|----------------|--------|-----------------|
| `server/mod.rs` | EXISTS | `src/dns/server/mod.rs` |
| `server/startup.rs` | EXISTS | `src/dns/server/startup.rs` |
| `server/query.rs` | EXISTS | `src/dns/server/query.rs` |
| `server/zone.rs` | EXISTS | `src/dns/server/zone.rs` |
| `server/rate_limit.rs` | EXISTS | `src/dns/server/rate_limit.rs` |
| `server/sharded_store.rs` | EXISTS | `src/dns/server/sharded_store.rs` |
| `dnssec.rs` | EXISTS | `src/dns/dnssec.rs` |
| `dnssec_signing.rs` | EXISTS | `src/dns/dnssec_signing.rs` |
| `dnssec_validation.rs` | EXISTS | `src/dns/dnssec_validation.rs` |
| `dnssec_key_mgmt.rs` | EXISTS | `src/dns/dnssec_key_mgmt.rs` |
| `tsig.rs` | EXISTS | `src/dns/tsig.rs` |
| `recursive.rs` | EXISTS | `src/dns/recursive.rs` |
| `recursive_cache.rs` | EXISTS | `src/dns/recursive_cache.rs` |
| `trust_anchor.rs` | EXISTS | `src/dns/trust_anchor.rs` |
| `doh.rs` | EXISTS | `src/dns/doh.rs` |
| `dot.rs` | EXISTS | `src/dns/dot.rs` |
| `doq.rs` | EXISTS | `src/dns/doq.rs` |
| `cache.rs` | EXISTS | `src/dns/cache.rs` |
| `firewall.rs` | EXISTS | `src/dns/firewall.rs` |
| `wire.rs` | EXISTS | `src/dns/wire.rs` |
| `messages.rs` | EXISTS | `src/dns/messages.rs` |
| `anycast.rs` | EXISTS | `src/dns/anycast.rs` |
| `anycast_sync.rs` | EXISTS | `src/dns/anycast_sync.rs` |

**Additional files not documented but exist:**
- `hsm.rs` - HSM/PKCS#11 support (documented as optional feature)
- `cookie.rs` - DNS cookies (RFC 7873)
- `update.rs` - Dynamic updates
- `transfer.rs` - Zone transfers
- `query_validator.rs` - Query validation
- `query_coalesce.rs` - Query coalescing (confirmed implemented)
- `rpz.rs` - Response Policy Zones
- `edns.rs` - EDNS handling
- `dns64.rs` - DNS64 support
- `prefetch.rs` - Prefetch support
- `metrics.rs` - Metrics collection
- `limits.rs` - Rate limiting
- `zone_trie.rs` - Zone trie
- `store.rs` - Zone store
- `sharded_cache.rs` - Sharded cache
- `compression.rs` - Message compression
- `zone_manager.rs` - Zone management
- `zone_file.rs` - Zone file parsing
- `platform.rs` - Platform-specific DNS
- `resolver.rs` - Resolver implementation
- `resolver_global.rs` - Global resolver
- `notify.rs` - Notify protocol
- `crypto_rng.rs` - Crypto RNG
- `qname.rs` - QNAME handling
- `mesh_sync/` - Mesh-based DNS sync (directory, not in doc)
- `mesh_dnssec.rs` - Mesh DNSSEC

---

## 2. Discrepancies and Bugs

### 2.1 CRITICAL: Security Bug - DS Digest Comparison

**Location:** `src/dns/dnssec_validation.rs:272`

```rust
pub fn verify_ds_digest(
    digest_type: u8,
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &[u8],
    expected_digest: &[u8],
) -> Result<bool, String> {
    let computed = compute_ds_digest(digest_type, flags, protocol, algorithm, public_key)?;
    Ok(computed == expected_digest)  // <-- BUG: Uses == instead of ConstantTimeEq
}
```

**Issue:** The DS digest comparison uses simple `==` instead of `subtle::ConstantTimeEq`. This violates:
1. The AGENTS.md requirement for constant-time comparison for secrets
2. Security best practices for comparing MACs/digests

**Fix Required:**
```rust
use subtle::ConstantTimeEq;
// ...
Ok(bool::from(computed.ct_eq(expected_digest)))
```

**Note:** The `cookie.rs:86` correctly uses `ConstantTimeEq` for cookie comparison. This inconsistency suggests the DS digest verification was overlooked.

---

### 2.2 Documentation: TunnelMessage Types Mismatch

**Documented in `dns_deep_dive.md:137-147`:**
```rust
TunnelMessage::Hello { client_id, auth_token, mappings, supports_datagrams }
TunnelMessage::HelloAck { server_session_id, server_mappings, supports_datagrams, ... }
TunnelMessage::PortOpen { identifier, port, protocol }
TunnelMessage::PortClose { identifier }
TunnelMessage::DataChunk { identifier, sequence, data, fin }
TunnelMessage::UdpTunnelOpen { identifier, port }
TunnelMessage::UdpTunnelClose { identifier }
TunnelMessage::UdpData { identifier, data }
```

**Actual in `src/tunnel/quic/messages.rs:7-106`:**
```rust
enum TunnelMessage {
    Hello { ... },           // MATCH
    HelloAck { ... },        // MATCH
    AuthFailure { ... },     // NOT documented
    KeepAlive,               // NOT documented
    KeepAliveAck,            // NOT documented
    PortOpen { ... },        // MATCH
    PortClose { ... },       // MATCH
    PortData { ... },        // NOT documented
    RequestProxy { ... },    // NOT documented
    ProxyResponse { ... },   // NOT documented
    PeerHello { ... },      // NOT documented
    PeerHelloAck { ... },   // NOT documented
    Error { ... },           // NOT documented
    DataChunk { ... },      // MATCH
    DataAck { ... },        // NOT documented
    StreamOpen { ... },     // NOT documented
    StreamOpenAck { ... },  // NOT documented
    StreamClose { ... },    // NOT documented
    UdpTunnelOpen { ... },   // MATCH
    UdpTunnelOpenAck { ... },// NOT documented
    UdpTunnelClose { ... },  // MATCH
    UdpData { ... },         // MATCH
    UdpClose { ... },        // NOT documented
}
```

**Impact:** The documentation is incomplete. Many message types are not documented.

---

### 2.3 Documentation: Missing VPN Client Components

**Documented in `dns_deep_dive.md:202-219`:**
- `VpnClientBuilder` - Listed as separate struct
- `VpnConnection` enum - Listed
- `ClientPortMapping` - Listed as separate struct

**Actual in `src/vpn_client/mod.rs`:**
- `VpnClientBuilder` is not a separate struct - it is a builder pattern method on `VpnClient` (lines 65-76)
- `VpnConnection` enum exists (line 38-41) CORRECT
- `ClientPortMapping` exists in `config.rs` CORRECT
- `LocalPortMapping` exists in `local_listener.rs` but NOT documented

**Also documented but implementation differs:**
- `VpnStatsTracker` - Documented, exists in `stats.rs` CORRECT
- `VpnEvent` - Documented, exists in `events.rs` CORRECT
- `PlatformInfo` - Documented, exists in `mod.rs:32-36` CORRECT

---

### 2.4 Documentation: Query Flow Discrepancy

**Documented in `dns_deep_dive.md:47-57`:**
```
1. Query Reception
2. Rate Limiting
3. Query Validation
4. Firewall
5. Cache Check
6. Query Coalescing
7. Zone Resolution
8. DNSSEC Signing
9. Response
```

**Actual in `src/dns/server/mod.rs`:**
The actual flow is implemented in `server/query.rs` and `server/mod.rs`. Query coalescing is optional and enabled via config (`query_coalescer: Option<Arc<QueryCoalescer>>` at line 411).

---

### 2.5 Known Code Note: DNSSEC Manual Wire Format

**Location:** `src/dns/dnssec.rs:1-9`

```rust
// DNSSEC signing module
//
// NOTE: This module currently uses manual DNS wire format construction.
// For production use, consider switching to the `dns-parser` or `hickory` crate
// for proper DNS message parsing and construction.
```

**Issue:** The documentation does not mention this architectural limitation. The manual wire format construction is a known tradeoff.

---

### 2.6 Documentation: Tunnel Transport Trait Incomplete

**Documented in `dns_deep_dive.md:169-181`:**
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

**Actual in `src/tunnel/mod.rs:61-80`:**
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

**Match:** The trait signature matches (the `...` in doc was shorthand).

---

### 2.7 WireGuard Implementation Note

**Documented:** "Kernel WireGuard via `wireguard-kit`"
**Actual:** Uses `defguard_boringtun` crate for userspace WireGuard. See `src/tunnel/wireguard/userspace.rs:136`.

The documentation mention of `wireguard-kit` is incorrect - the actual implementation uses `boringtun` (via `defguard_boringtun` crate).

---

## 3. Recommended Improvements

### 3.1 Critical Security Fix

| Priority | Issue | File | Line | Recommendation |
|----------|-------|------|------|----------------|
| **CRITICAL** | DS digest comparison uses `==` instead of constant-time | `src/dns/dnssec_validation.rs` | 272 | Replace `==` with `ct_eq()` from `subtle::ConstantTimeEq` |

**Fix:**
```rust
// Line 272 in dnssec_validation.rs
// BEFORE:
Ok(computed == expected_digest)

// AFTER:
use subtle::ConstantTimeEq;
Ok(bool::from(computed.ct_eq(expected_digest)))
```

This matches the pattern used in `tsig.rs:238` and `cookie.rs:86`.

---

### 3.2 Documentation Updates

| Priority | Issue | Recommendation |
|----------|-------|----------------|
| High | TunnelMessage types incomplete | Update `dns_deep_dive.md:137-147` to include all message types: `AuthFailure`, `KeepAlive`, `KeepAliveAck`, `PortData`, `RequestProxy`, `ProxyResponse`, `PeerHello`, `PeerHelloAck`, `Error`, `DataAck`, `StreamOpen`, `StreamOpenAck`, `StreamClose`, `UdpTunnelOpenAck`, `UdpClose` |
| High | WireGuard implementation mismatch | Update `dns_deep_dive.md:160` from "via `wireguard-kit`" to "via `defguard-boringtun` userspace implementation" |
| Medium | Missing VPN client components | Document `LocalPortMapping` and clarify that `VpnClientBuilder` is a builder pattern on `VpnClient` |
| Medium | Missing DNS modules | Add undocumented files to the key files table: `hsm.rs`, `cookie.rs`, `update.rs`, `transfer.rs`, `query_validator.rs`, `rpz.rs`, `edns.rs`, `dns64.rs`, `mesh_sync/` |
| Low | Known DNSSEC limitation | Add note about manual wire format construction in DNSSEC section |

---

### 3.3 Code Quality Improvements

| Priority | Issue | File | Line | Recommendation |
|----------|-------|------|------|----------------|
| Low | Missing constant-time for digest comparison | `src/dns/dnssec_validation.rs` | 272 | See 3.1 |
| Low | Code comment notes manual implementation | `src/dns/dnssec.rs` | 1-9 | Consider migrating to hickory/dns-parser for RFC compliance |

---

## 4. Verification Checklist

- [ ] **SECURITY**: Fix `verify_ds_digest` to use constant-time comparison
- [ ] **DOCS**: Update TunnelMessage types in `dns_deep_dive.md`
- [ ] **DOCS**: Fix WireGuard implementation description
- [ ] **DOCS**: Add missing VPN client components
- [ ] **DOCS**: Add missing DNS module files to key files table
- [ ] **CODE**: Consider migrating DNSSEC wire format to use hickory/dns-parser

---

## 5. Files Referenced

### Modified Files
- `src/dns/dnssec_validation.rs:272` - Security bug location

### Documentation to Update
- `architecture/dns_deep_dive.md` - Multiple sections need updating

### No Change Required (Verified Correct)
- `src/dns/tsig.rs` - Correctly uses `ConstantTimeEq` at line 238
- `src/dns/cookie.rs` - Correctly uses `ConstantTimeEq` at line 86
- `src/dns/trust_anchor.rs` - RFC 5011 states implemented correctly
- `src/tunnel/mod.rs` - `TunnelTransport` trait matches documentation
- `src/vpn_client/mod.rs` - Core structures match documentation

---

**End of Review**
