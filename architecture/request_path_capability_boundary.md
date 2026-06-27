# Request-Path Capability Boundary

**Established**: Phase 4
**Guardrail**: `tests/request_path_capability_boundary_guard.rs`

## Invariant

> Request-path modules consume narrow capabilities; they must not own or import concrete control-plane, mesh, supervisor, or admin infrastructure.

## Overview

This document defines the capability boundary for HTTP/WAF/proxy request-path code. Request-path modules handle live HTTP requests and must consume narrow traits or config snapshots, not concrete infrastructure types.

## Request-Path Scan Roots

| Directory | Purpose |
|-----------|---------|
| `src/http/` | HTTP server request handling |
| `src/waf/` | WAF request evaluation |
| `src/proxy/` | Proxy re-export shim |
| `crates/synvoid-http/src/` | HTTP request dispatch |
| `crates/synvoid-waf/src/` | WAF engine traits and primitives |
| `crates/synvoid-proxy/src/` | Proxy engine |
| `crates/synvoid-http3/src/` | HTTP/3 QUIC protocol handling |

## Forbidden Request-Path Imports

Request-path code must not import:

| Category | Forbidden Tokens |
|----------|-----------------|
| Concrete control-plane types | `MeshTransportManager`, `MeshBackendPool`, `ThreatIntelligenceManager` (concrete), `BlockStore` (concrete) |
| Mesh/DHT/Raft | `crate::mesh::transport`, `crate::raft::`, `openraft::`, `crate::dht::` |
| Supervisor/admin | `crate::supervisor::`, `verify_admin_token`, `crate::admin::handlers` |
| Worker lifecycle | `UnifiedServerWorkerState`, `WorkerTaskRegistry`, `WorkerShutdownCause` |
| Control-plane operations | `lookup_threat_indicator_in_dht`, `BlocklistCatchupRequest`, `BlocklistSnapshotRequest`, `BlocklistEventGossip` |
| Raw threat-intel lookups | `lookup_local_indicator(`, `lookup_local_indicator_by_ip(` |

## Capability Traits

Request-path code consumes narrow traits instead of concrete types:

| Trait | Location | Purpose |
|-------|----------|---------|
| `BlockListStore` | `crates/synvoid-waf/src/traits.rs` | IP blocking/checking (decouples from `BlockStore`) |
| `WafProcessor` | `crates/synvoid-waf/src/traits.rs` | Core WAF evaluation |
| `GeoIpLookup` | `crates/synvoid-waf/src/traits.rs` | IP-to-country/ASN |
| `ThreatIntelLookup` | `src/worker/context.rs` | Request-time threat intel lookups — decouples from `ThreatIntelligenceManager` (adapter in `services.rs` and `init_mesh.rs`) |
| `BehavioralIntelLookup` | `src/worker/context.rs` | Request-time behavioral analysis — decouples from `BehavioralIntelligenceManager` (adapter in `services.rs`) |
| `WafAccess` | `crates/synvoid-waf/src/access.rs` | WAF service adapter for HTTP/3 |
| `Http3RequestWaf` | `crates/synvoid-http/src/http3_request_dispatch.rs` | HTTP/3 WAF evaluation |

## RequestServices

`RequestServices` (`src/worker/context.rs`) is the narrow request-path handle:

```rust
pub struct RequestServices {
    #[cfg(feature = "mesh")]
    pub threat_intel: Option<Arc<dyn ThreatIntelLookup>>,
    #[cfg(feature = "mesh")]
    pub behavioral_intel: Option<Arc<dyn BehavioralIntelLookup>>,
    pub upload_validator: Option<Arc<UploadValidator>>,
    #[cfg(feature = "mesh")]
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    pub plugin_manager: Option<Arc<GlobalPluginManager>>,
    pub serverless_registry: Option<Arc<ServerlessRegistry>>,
}
```

### Rules

- Must not import worker startup, supervision, or shutdown modules
- Must not carry mesh transport, IPC, or task registry handles
- Must contain only request-execution services
- Built by `DataPlaneServicesBuilder::build()` — never construct directly

## Concrete Pass-Through Types

Some concrete types are threaded through request-path dispatch as pass-through data from the composition root. These are documented exceptions:

| Type | Origin | Usage | Risk |
|------|--------|-------|------|
| `MeshTransportManager` | Mesh init | Serverless routing, response transforms | Low — received, not constructed |
| `MeshBackendPool` | Mesh init | Backend routing | Low — received, not constructed |
| `ServerlessManager` | App init | WASM dispatch | Low — received, not constructed |
| `GranianSupervisor` | App init | App-server dispatch | Low — received, not constructed |
| `AsyncIpcStream` | IPC init | Request logging pass-through | Low — received, not constructed |
| `WorkerId` | IPC init | Request logging pass-through | Low — received, not constructed |

## Composition Root Adapter Pattern

When a concrete type must be exposed to request path, wrap it with an adapter at the composition boundary:

```rust
// In composition root (services.rs)
struct ThreatIntelLookupAdapter {
    inner: Arc<ThreatIntelligenceManager>,
}

impl ThreatIntelLookup for ThreatIntelLookupAdapter {
    fn is_known_threat_ip(&self, ip: IpAddr) -> bool {
        self.inner.lookup_local_indicator_by_ip(&ip.to_string()).is_some()
    }
    fn threat_level_for_ip(&self, ip: IpAddr) -> Option<u8> {
        // delegate to inner
    }
}

struct BehavioralIntelLookupAdapter {
    inner: Arc<BehavioralIntelligenceManager>,
}

impl BehavioralIntelLookup for BehavioralIntelLookupAdapter {
    fn analyze_request(&self, features: &RequestFeatures) -> Option<BehavioralFingerprint> {
        self.inner.analyze_request(features)
    }
    fn adjust_paranoia_level(&self, features: &RequestFeatures, base_paranoia: u8) -> u8 {
        self.inner.adjust_paranoia_level(features, base_paranoia)
    }
}
```

## Adding New Request-Path Capabilities

1. Define a narrow trait in `crates/synvoid-waf/src/traits.rs` or `src/worker/context.rs`
2. Implement it on a concrete type in a composition root (`src/worker/unified_server/services.rs`)
3. Pass `Arc<dyn YourTrait>` to request-path modules
4. Never pass concrete types directly to request-path code

## Threat-Intel Diagnostic/Enforcement Separation

Raw lookups (`lookup_local_indicator`, `lookup_local_indicator_by_ip`, `lookup_threat_indicator_in_dht`) are diagnostic-only. Enforcement consumers must use `lookup_*_policy_strict` wrappers. This separation is enforced by `tests/threat_intel_boundary_guard.rs`.

## Guard Tests

| Test | What It Enforces |
|------|------------------|
| `tests/request_path_capability_boundary_guard.rs` | Request-path modules don't import forbidden concrete types |
| `tests/data_plane_composition_boundary_guard.rs` | Composition boundary role-based classification |
| `tests/http_request_pipeline_boundary_guard.rs` | HTTP dispatch doesn't import worker lifecycle |
| `tests/http3_waf_boundary_guard.rs` | HTTP/3 WAF doesn't leak concrete types |
| `tests/threat_intel_boundary_guard.rs` | Raw lookups separated from enforcement |
| `tests/mesh_id_boundary_guard.rs` | Mesh-ID blocks not in request path |

## Verification

```bash
cargo test --test request_path_capability_boundary_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test http_request_pipeline_boundary_guard
cargo test --test http3_waf_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test mesh_id_boundary_guard
```
