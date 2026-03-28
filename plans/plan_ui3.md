# MaluWAF Admin Panel Configuration & Usability Improvement Plan

## Overview

This plan addresses exposing missing system configurations in the admin panel and improving usability. It focuses on adding DNS, Tunnel, and other infrastructure configuration management while maintaining the overseer/master/worker architecture.

### Related Plans

- `plan_ui.md` - Frontend security, architecture, and UX improvements for the Yew-based admin UI

### Assumptions

- Admin panel runs in the **master process**
- Configuration changes propagate to workers via existing IPC mechanisms
- Full stack implementation: backend handlers + frontend UI pages

---

## Executive Summary

| Category | Gap | Priority | Implementation Effort |
|-----------|-----|----------|----------------------|
| DNS Config | Completely missing | P0 (HIGH) | 2-3 weeks |
| Tunnel Config | Completely missing | P1 | 1-2 weeks |
| Stub Endpoints | 7 incomplete endpoints | P1 | 1 week |
| Usability | Logs, listeners, workers | P2 | 1-2 weeks |
| Security Config | Partially exposed | P3 | 1 week |

---

## Part 1: Current State Analysis

### 1.1 Admin Panel Handler Modules (16 total)

| Handler | Status | Endpoints |
|---------|--------|-----------|
| Config | Complete | GET/PUT main, overseer, supervisor, process-manager, schema |
| Stats | Complete | summary, sites, history, attacks, cache, bandwidth, requests |
| Sites | Complete | CRUD operations, theme management |
| Upstreams | Partial | List, health check stub (NOT IMPLEMENTED) |
| Logs | Stub | Returns empty (NOT IMPLEMENTED) |
| TCP/UDP | Partial | List only, CRUD stubs (NOT IMPLEMENTED) |
| Probes | Complete | Tracking, suspicious words, upstream errors |
| Threat Level | Complete | Auto/manual, backups, history |
| ICMP | Conditional | Only with `icmp-filter` feature |
| System | Partial | Master, workers, overseer status; restart stub |
| Alerting | Complete | Config, webhook test |
| Honeypot | Complete | Status, control |
| Mesh | Complete | Nodes, bans, audit |
| Rules Feed | Complete | Status, check, apply |
| Theme | Partial | GET/PUT stub |
| **DNS** | **MISSING** | No endpoints |
| **Tunnel** | **MISSING** | No endpoints |

### 1.2 Configuration Not Exposed

| Config Module | Fields | Admin Handler |
|--------------|--------|---------------|
| `dns` | 60+ (RRL, DNSSEC, DoT, DoH, RPZ, etc.) | **NONE** |
| `tunnel` | 30+ (WireGuard, QUIC peers) | **NONE** |
| `security` | IPC, static config | Partial |
| `plugins` | WASM plugins | **NONE** |
| `geoip` | GeoIP settings | **NONE** |
| `yara_feed` | YARA rules config | **NONE** |

### 1.3 Stub Endpoints (Not Yet Implemented)

| Endpoint | Handler File | Line |
|----------|-------------|------|
| `POST /upstreams/{site_id}/check` | upstreams.rs | - |
| `POST /tcp-udp/listeners` | tcp_udp.rs | - |
| `DELETE /tcp-udp/listeners/{id}` | tcp_udp.rs | - |
| `POST /system/workers/{id}/restart` | system.rs | - |
| `PUT /error-pages/{code}` | logs.rs | - |
| `POST /probes/block` | probes.rs | - |
| `GET /logs` | logs.rs | - |

---

## Part 2: DNS Configuration Panel (Priority - P0)

### 2.1 DNS Architecture Context

The DNS server runs as a separate process (within master) with these components:
- `src/dns/server/mod.rs` - Main DNS server
- `src/dns/cache.rs` - Cache management
- `src/dns/dnssec.rs` - DNSSEC signing/validation
- `src/dns/trust_anchor/` - RFC 5011 trust anchor management
- `src/config/dns.rs` - DNS configuration (1800+ lines)

### 2.2 Backend Handlers to Add

File: `src/admin/handlers/dns.rs` (new)

```rust
// Endpoints to implement:
GET  /dns/config          // Get DNS configuration (DnsConfig)
PUT  /dns/config          // Update DNS configuration
GET  /dns/status          // Server status, zones loaded, query stats
GET  /dns/zones           // List all zones
POST /dns/zones            // Create new zone
GET  /dns/zones/{name}    // Get zone details
PUT  /dns/zones/{name}    // Update zone
DELETE /dns/zones/{name} // Delete zone
GET  /dns/zones/{name}/records   // List zone records
POST /dns/zones/{name}/records   // Add record
DELETE /dns/zones/{name}/records // Remove record
GET  /dns/cache/stats     // Cache statistics
GET  /dns/dnssec/status   // DNSSEC status, trust anchors
GET  /dns/ratelimit/status // Rate limit stats
POST /dns/reload          // Reload zones
POST /dns/test            // Test DNS resolution
```

### 2.3 DNS Config Structure (for reference)

```rust
// src/config/dns.rs - DnsConfig fields
pub struct DnsConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub mode: DnsMode,          // Standalone/Mesh
    pub ratelimit: DnsRateLimitConfig,
    pub rrl: DnsRrlConfig,      // Response Rate Limiting
    pub firewall: DnsFirewallConfig,
    pub settings: DnsSettingsConfig,
    pub mesh: DnsMeshConfig,
    pub zones: DnsZonesConfig,
    pub limits: DnsLimitsConfig,
    pub dnssec: DnsSecConfig,
    pub dot: DnsDotConfig,      // DNS over TLS
    pub doh: DnsDohConfig,      // DNS over HTTPS
    pub doq: DnsDoqConfig,     // DNS over QUIC
    pub rpz: DnsRpzConfig,      // Response Policy Zone
    pub dns64: Dns64Config,
    pub prefetch: DnsPrefetchConfig,
    pub trust_anchors: TrustAnchorConfig,
    pub anycast: DnsAnycastConfig,
    pub recursive: RecursiveDnsConfig,
}
```

### 2.4 Admin State Extension (if needed)

The DNS server is managed by the master process. The `AdminState` may need a reference to the DNS server for status queries:

```rust
// src/admin/state.rs - potential extension
#[derive(Clone)]
pub struct DnsState {
    pub server: Option<Arc<dns::server::DnsServer>>,
    // Or read from MainConfig for configuration-only access
}
```

### 2.5 Frontend UI Pages

New pages in `admin-ui/src/pages/`:

| Page | Route | Description |
|------|-------|-------------|
| `dns.rs` | `/dns` | Dashboard with query stats, cache stats |
| `dns_zones.rs` | `/dns/zones` | Zone management |
| `dns_config.rs` | `/dns/config` | DNS server configuration |
| `dns_dnssec.rs` | `/dns/dnssec` | DNSSEC/trust anchor management |

#### DNS Dashboard Page Structure

```rust
// admin-ui/src/pages/dns.rs
#[function_component]
pub fn DnsDashboard() -> Html {
    // Components:
    // - DnsQueryStats: queries/sec, by type, by zone
    // - DnsCacheStats: hit rate, size, entries
    // - DnsServerStatus: uptime, zones loaded, memory
    // - DnsZoneList: quick view of all zones
}
```

#### Types to Add

```rust
// admin-ui/src/types/mod.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    // ... all DnsConfig fields
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStatus {
    pub running: bool,
    pub zones_loaded: usize,
    pub queries_total: u64,
    pub queries_per_second: f64,
    pub cache_hit_rate: f64,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZone {
    pub name: String,
    pub records: Vec<DnsRecord>,
    pub serial: u32,
    pub dnssec_enabled: bool,
}
```

---

## Part 3: Tunnel Configuration Panel (Priority - P1)

### 3.1 Tunnel Architecture Context

- WireGuard VPN: `src/config/tunnel.rs` - TunnelVpnConfig
- QUIC Tunnel: TunnelQuicConfig
- Both configured via `main.tunnel` in config

### 3.2 Backend Handlers to Add

File: `src/admin/handlers/tunnel.rs` (new)

```rust
GET  /tunnel/config          // Get tunnel configuration
PUT  /tunnel/config          // Update tunnel configuration
GET  /tunnel/vpn/status     // WireGuard status
GET  /tunnel/vpn/peers       // List WireGuard peers
POST /tunnel/vpn/peers       // Add WireGuard peer
PUT  /tunnel/vpn/peers/{id}  // Update peer
DELETE /tunnel/vpn/peers/{id} // Remove peer
GET  /tunnel/quic/status     // QUIC tunnel status
GET  /tunnel/quic/connections // Active connections
POST /tunnel/test            // Test tunnel connectivity
```

### 3.3 Frontend UI Pages

| Page | Route | Description |
|------|-------|-------------|
| `tunnel.rs` | `/tunnel` | Tunnel overview |
| `tunnel_vpn.rs` | `/tunnel/vpn` | WireGuard peer management |
| `tunnel_config.rs` | `/tunnel/config` | Tunnel configuration |

---

## Part 4: Stub Endpoint Implementation (Priority - P1)

### 4.1 Upstream Health Check

```rust
// src/admin/handlers/upstreams.rs
// POST /upstreams/{site_id}/check
// Implementation: Trigger health check for upstream
// Use existing health check mechanism in site management
```

### 4.2 TCP/UDP Listener Management

```rust
// src/admin/handlers/tcp_udp.rs
// POST /tcp-udp/listeners - Create listener
// DELETE /tcp-udp/listeners/{id} - Delete listener
// Requires: Implement actual listener creation/deletion logic
```

### 4.3 Worker Restart

```rust
// src/admin/handlers/system.rs
// POST /system/workers/{id}/restart
// Implementation: Send IPC message to supervisor to restart worker
```

### 4.4 Error Page Management

```rust
// src/admin/handlers/logs.rs
// PUT /error-pages/{code}
// Implementation: Save custom error page content
```

### 4.5 Probe Blocking

```rust
// src/admin/handlers/probes.rs
// POST /probes/block
// Implementation: Add IP to blocklist via threat level or IP feed
```

### 4.6 Logs Retrieval

```rust
// src/admin/handlers/logs.rs
// GET /logs
// Implementation: Actual log retrieval (currently returns empty)
// Requires: Integration with log_controller or file-based logging
```

---

## Part 5: Usability Improvements

### 5.1 Process Management UI

- **Current**: Can view workers, scale manually
- **Missing**: Individual worker restart, worker resource usage graphs
- **Add**: Worker detail view with memory/CPU per worker

### 5.2 Real-time Metrics

- WebSocket already exists for metrics
- **Enhance**: Add DNS-specific real-time metrics via same WebSocket

### 5.3 Configuration Consistency

- Schema endpoint already exposes 82+ fields
- **Enhance**: Group settings by category in UI
- **Add**: Configuration validation before applying

### 5.4 Navigation Improvements

- Add breadcrumb navigation for nested pages (e.g., DNS > Zones > {zone} > Records)
- Add quick actions in sidebar for common tasks

---

## Part 6: Architecture Considerations

### 6.1 Overseer/Master/Worker IPC

Configuration changes flow through existing IPC:

```
Admin Panel (Master Process)
    |
    v
POST /config/{section}
    |
    v
ConfigManager updates MainConfig
    |
    v
IPC Message: MasterConfigReload / MasterSupervisorConfigReload
    |
    v
Worker processes receive config via IPC
```

### 6.2 DNS Server Communication

DNS runs within master process. Access pattern:

```rust
// Option 1: Configuration-only (read from MainConfig)
let config = state.process.config.read().await;
let dns_config = config.main.dns.clone();

// Option 2: Runtime status (requires DNS server reference in AdminState)
// Would need to store Arc<dns::server::DnsServer> in AdminState
```

### 6.3 Admin State Extensions

```rust
// src/admin/state.rs - potential new state structs
#[derive(Clone)]
pub struct DnsState {
    // If needed for runtime status
}

#[derive(Clone)]
pub struct TunnelState {
    // If needed for runtime status
}
```

### 6.4 Handler Registration

Add to `src/admin/handlers/mod.rs`:

```rust
pub mod dns;      // New
pub mod tunnel;  // New
```

Add routes in `src/admin/mod.rs`:

```rust
// Router::new()
// .merge(handlers::dns::routes())
// .merge(handlers::tunnel::routes())
```

---

## Part 7: Implementation Phases

### Phase 1: DNS Configuration (Weeks 1-3)

| Task | Files | Effort |
|------|-------|--------|
| DNS handlers backend | `src/admin/handlers/dns.rs` | 2-3 days |
| DNS types frontend | `admin-ui/src/types/mod.rs` | 1 day |
| DNS dashboard UI | `admin-ui/src/pages/dns.rs` | 2-3 days |
| DNS zones UI | `admin-ui/src/pages/dns_zones.rs` | 2-3 days |
| DNS config UI | `admin-ui/src/pages/dns_config.rs` | 2-3 days |
| DNS DNSSEC UI | `admin-ui/src/pages/dns_dnssec.rs` | 1-2 days |
| **Total** | | **~2 weeks** |

### Phase 2: Tunnel Configuration (Weeks 3-4)

| Task | Files | Effort |
|------|-------|--------|
| Tunnel handlers backend | `src/admin/handlers/tunnel.rs` | 2 days |
| Tunnel types frontend | `admin-ui/src/types/mod.rs` | 0.5 day |
| Tunnel VPN UI | `admin-ui/src/pages/tunnel_vpn.rs` | 1-2 days |
| Tunnel config UI | `admin-ui/src/pages/tunnel_config.rs` | 1 day |
| **Total** | | **~1 week** |

### Phase 3: Stub Endpoints (Weeks 4-5)

| Task | Files | Effort |
|------|-------|--------|
| Upstream health check | `src/admin/handlers/upstreams.rs` | 1 day |
| TCP/UDP listener CRUD | `src/admin/handlers/tcp_udp.rs` | 2 days |
| Worker restart | `src/admin/handlers/system.rs` | 1 day |
| Error page management | `src/admin/handlers/logs.rs` | 1 day |
| Probe blocking | `src/admin/handlers/probes.rs` | 1 day |
| Logs retrieval | `src/admin/handlers/logs.rs` | 2 days |
| **Total** | | **~1 week** |

### Phase 4: Usability Improvements (Weeks 5-6)

| Task | Files | Effort |
|------|-------|--------|
| Worker detail view | `admin-ui/src/pages/workers.rs` | 2 days |
| DNS real-time metrics | WebSocket extension | 2 days |
| Configuration validation UI | `admin-ui/src/pages/settings.rs` | 2 days |
| Navigation improvements | Sidebar, breadcrumbs | 1 day |
| **Total** | | **~1 week** |

### Phase 5: Security & Remaining Configs (Weeks 6-7)

| Task | Files | Effort |
|------|-------|--------|
| Security config UI | `admin-ui/src/pages/security.rs` | 2 days |
| Plugin management UI | `admin-ui/src/pages/plugins.rs` | 2 days |
| GeoIP config UI | `admin-ui/src/pages/geoip.rs` | 1 day |
| YARA rules UI | `admin-ui/src/pages/yara.rs` | 1 day |
| **Total** | | **~1 week** |

---

## Part 8: API Design Details

### 8.1 DNS Endpoints

```rust
// GET /dns/config
#[derive(Serialize)]
pub struct DnsConfigResponse {
    pub config: DnsConfig,
}

// GET /dns/status
#[derive(Serialize)]
pub struct DnsStatusResponse {
    pub running: bool,
    pub zones_loaded: usize,
    pub queries_total: u64,
    pub queries_per_second: f64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub memory_bytes: u64,
    pub uptime_secs: u64,
}

// GET /dns/zones
#[derive(Serialize)]
pub struct DnsZonesResponse {
    pub zones: Vec<ZoneSummary>,
}

#[derive(Serialize)]
pub struct ZoneSummary {
    pub name: String,
    pub record_count: usize,
    pub serial: u32,
    pub dnssec_enabled: bool,
    pub last_updated: String,
}

// GET /dns/zones/{name}/records
#[derive(Serialize)]
pub struct DnsRecordsResponse {
    pub zone: String,
    pub records: Vec<DnsRecord>,
}

#[derive(Serialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: String,  // A, AAAA, CNAME, MX, TXT, etc.
    pub ttl: u32,
    pub data: String,
}
```

### 8.2 Tunnel Endpoints

```rust
// GET /tunnel/config
#[derive(Serialize)]
pub struct TunnelConfigResponse {
    pub config: TunnelConfig,
}

// GET /tunnel/vpn/peers
#[derive(Serialize)]
pub struct VpnPeersResponse {
    pub peers: Vec<WireGuardPeer>,
}

#[derive(Serialize)]
pub struct WireGuardPeer {
    pub id: String,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: u16,
    pub enabled: bool,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub last_handshake: Option<String>,
}
```

---

## Part 9: Testing Requirements

### 9.1 Backend Handler Tests

```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_dns_config_get() {
        // Test GET /dns/config returns correct DnsConfig
    }
    
    #[tokio::test]
    async fn test_dns_config_update() {
        // Test PUT /dns/config updates configuration
    }
    
    #[tokio::test]
    async fn test_dns_zone_crud() {
        // Test zone create/read/update/delete
    }
}
```

### 9.2 Integration Tests

- Admin panel endpoints work correctly with DNS/Tunnel configs
- Configuration changes propagate to workers via IPC

---

## Part 10: Rollback & Safety

### 10.1 Configuration Validation

Before applying any config change:
1. Validate syntax in handler
2. Return errors to UI if invalid
3. Log all config changes

### 10.2 Graceful Reload

- DNS zone reload should not interrupt active queries
- Tunnel changes should maintain existing connections where possible
- Worker restart should drain connections first

### 10.3 Feature Flags

Consider adding feature flags for:
- DNS panel (conditional on `dns` feature)
- Tunnel panel (conditional on `wireguard` feature)

---

## Appendix A: File Locations

### New Backend Files

```
src/admin/handlers/dns.rs      # DNS handlers
src/admin/handlers/tunnel.rs   # Tunnel handlers
```

### Modified Backend Files

```
src/admin/handlers/mod.rs      # Add dns, tunnel modules
src/admin/mod.rs               # Register routes
src/admin/state.rs             # Optional: add DnsState, TunnelState
```

### New Frontend Files

```
admin-ui/src/pages/dns.rs           # DNS dashboard
admin-ui/src/pages/dns_zones.rs     # Zone management
admin-ui/src/pages/dns_config.rs    # DNS config editor
admin-ui/src/pages/dns_dnssec.rs    # DNSSEC management
admin-ui/src/pages/tunnel.rs        # Tunnel overview
admin-ui/src/pages/tunnel_vpn.rs    # WireGuard peers
admin-ui/src/pages/tunnel_config.rs # Tunnel config
```

### Modified Frontend Files

```
admin-ui/src/types/mod.rs           # Add DnsConfig, TunnelConfig types
admin-ui/src/pages/mod.rs           # Add new pages
admin-ui/src/app.rs                 # Add routes
admin-ui/src/components/layout/sidebar.rs  # Add navigation items
```

---

## Appendix B: Configuration Schema (Partial)

### DNS Settings Exposed

| Path | Type | Description |
|------|------|-------------|
| `dns.enabled` | bool | Enable DNS server |
| `dns.bind_address` | string | Bind address |
| `dns.port` | u16 | DNS port (default 53) |
| `dns.mode` | enum | standalone/mesh |
| `dns.ratelimit.per_second` | u64 | Queries per second |
| `dns.rrl.enabled` | bool | Response rate limiting |
| `dns.dnssec.enabled` | bool | DNSSEC enabled |
| `dns.dot.enabled` | bool | DNS over TLS |
| `dns.doh.enabled` | bool | DNS over HTTPS |
| `dns.zones` | array | Zone configurations |
| `dns.cache.size` | usize | Cache size |
| `dns.trust_anchors` | config | RFC 5011 trust anchors |

### Tunnel Settings Exposed

| Path | Type | Description |
|------|------|-------------|
| `tunnel.enabled` | bool | Enable tunnel |
| `tunnel.vpn.enabled` | bool | WireGuard enabled |
| `tunnel.vpn.bind_address` | string | WG bind address |
| `tunnel.vpn.port` | u16 | WG port (default 51820) |
| `tunnel.vpn.interface` | string | Interface name |
| `tunnel.vpn.peers` | array | Peer configurations |
| `tunnel.quic.enabled` | bool | QUIC tunnel enabled |

---

**Document Version**: 1.0
**Created**: 2026-03-27
**Status**: Planning Complete
**Next Steps**: Begin Phase 1 implementation