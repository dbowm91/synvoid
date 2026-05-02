# Worker Runtime Split: Core and Optional Extensions

**Status**: DOCUMENTATION ONLY
**Last Updated**: 2026-05-02
**Related ADR**: ADR-003 (Unified Worker Process Architecture)

## Problem Statement

The unified worker is a single operational container for too many responsibilities. ADR-003 argues that a single async worker is simpler and efficient, but the implementation now includes enough optional subsystems that the worker is no longer just an HTTP/WAF worker.

The architecture does not need to abandon unified serving immediately, but it should distinguish core serving from optional extensions and allow isolation where risk warrants it.

---

## 1. CoreWorkerRuntime (Conceptual)

This is **documentation only** - no new struct is created. The conceptual `CoreWorkerRuntime` owns:

| Component | Description |
|-----------|-------------|
| Config snapshot | `Arc<RwLock<ConfigManager>>` - loaded on startup, refreshed on reload |
| HTTP/HTTPS/HTTP3 listeners | Port binding, socket acceptance |
| Router | `Router` - precomputed host maps, location matchers |
| WAF | `WafCore` - attack detection, body inspection, request sanitization |
| Proxy/static handlers | Request forwarding, static file serving |
| Metrics | `WorkerMetrics`, bandwidth tracking |
| Drain/shutdown | `RunningFlag`, `DrainFlag`, graceful shutdown coordination |

**What is NOT core:**
- Mesh networking and DHT
- DNS serving and mesh DNS registry
- WASM/plugin runtime
- Serverless function execution
- Upload scanning with YARA
- Port honeypot

---

## 2. Extension Initialization Boundaries

Each extension is documented with its current initialization location and behavior.

### 2.1 MeshRuntime

| Property | Value |
|----------|-------|
| **Initialization location** | `src/worker/unified_server.rs:537-1037` |
| **Feature requirement** | `dns` feature (conditionally compiled, lines 699-829) |
| **Config requirement** | `main.tunnel.mesh.enabled = true` |
| **Startup failure policy** | **Fail-open with dummy state**: Creates `ThreatIntelligenceManager::new_for_standalone()` with dummy node_id if mesh fails to initialize (lines 543-579, 1040-1077) |
| **Shutdown behavior** | Stops transport manager tasks, topology background tasks |
| **Reload behavior** | Config hot-reload blocked when mesh is enabled (lines 1334-1341) |

**Current issues:**
- Creates dummy `ThreatIntelligenceManager` even when mesh is disabled in config
- Dummy threat intel is set globally via `crate::waf::set_threat_intel()` - no way to distinguish real vs dummy
- Mesh failure does not fail worker startup

### 2.2 DnsRuntime

| Property | Value |
|----------|-------|
| **Initialization location** | `src/worker/unified_server.rs:699-795` (inside `#[cfg(feature = "dns")]`) |
| **Feature requirement** | `dns` feature |
| **Config requirement** | `main.dns.enabled = true` AND `mesh.role.is_global()` for resolver |
| **Startup failure policy** | **Fail-open with warning**: Logs error/warning but continues with `None` registry |
| **Shutdown behavior** | Verification loop stops on shutdown |
| **Reload behavior** | N/A - no reload support |

**Current issues:**
- Global nodes require DNS but can be compiled without `dns` feature
- Edge nodes get a minimal registry without resolver - different behavior based on role
- DNS failure only logs a warning

### 2.3 PluginRuntime

| Property | Value |
|----------|-------|
| **Initialization location** | `src/worker/unified_server.rs:22` (import) + plugin manager setup |
| **Feature requirement** | `wasm` feature (via `get_global_plugin_manager().get_wasm_manager()`) |
| **Config requirement** | Serverless config or plugin config |
| **Startup failure policy** | **Fail-open**: Plugin manager created even if WASM runtime unavailable |
| **Shutdown behavior** | Managed by `ServerlessManager` |
| **Reload behavior** | Config reload updates serverless functions |

**Note:** This is currently coupled with `ServerlessRuntime`. The plugin manager is a dependency of `ServerlessManager`.

### 2.4 ServerlessRuntime

| Property | Value |
|----------|-------|
| **Initialization location** | `src/worker/unified_server.rs:333-364` |
| **Feature requirement** | WASM plugin support |
| **Config requirement** | `main.serverless.enabled = true` |
| **Startup failure policy** | **Fail-open**: Logs warning and sets `None` manager (lines 341-353) |
| **Shutdown behavior** | `ServerlessManager::shutdown()` |
| **Reload behavior** | Config reload updates serverless functions |

**Current issues:**
- Serverless failure does not fail worker startup
- If mesh is enabled, wires serverless manager to DHT record store and mesh transport (lines 1080-1096)

### 2.5 UploadScanningRuntime

| Property | Value |
|----------|-------|
| **Initialization location** | `src/worker/unified_server.rs:429-469` |
| **Feature requirement** | YARA support |
| **Config requirement** | `main.defaults.upload` config |
| **Startup failure policy** | **Fail-open**: Logs warning and proceeds without validator (lines 466-469) |
| **Shutdown behavior** | Via `UploadValidator::stop_drain()` |
| **Reload behavior** | N/A |

**Current issues:**
- Upload scanning failure does not fail worker startup
- Creates `UploadValidator` even if `scan_with_yara = false`
- No way to disable upload scanning at runtime without config change

### 2.6 HoneypotRuntime

| Property | Value |
|----------|-------|
| **Initialization location** | `src/worker/unified_server.rs:472-520` |
| **Feature requirement** | None (always compiled) |
| **Config requirement** | `main.honeypot_port.enabled = true` |
| **Startup failure policy** | **Fail-open**: Logs warning and sets `None` runner (lines 504-507) |
| **Shutdown behavior** | Runner shutdown via `PortHoneypotRunner::shutdown()` |
| **Reload behavior** | N/A |

**Current issues:**
- Honeypot failure does not fail worker startup
- Spawns background task via `tokio::spawn` - not tracked in `task_handles`

### 2.7 TunnelRuntime

| Property | Value |
|----------|-------|
| **Initialization location** | `src/worker/unified_server.rs:624-628` (MeshTransportManager QUIC transport) |
| **Feature requirement** | None (always compiled) |
| **Config requirement** | Part of mesh config |
| **Startup failure policy** | Integrated with mesh - fail-open with dummy |
| **Shutdown behavior** | Integrated with mesh transport |
| **Reload behavior** | Integrated with mesh |

**Note:** Tunnel is not a separate extension - it is a feature of `MeshRuntime`. QUIC tunnel endpoints are served by `MeshTransportManager::get_quic_transport()`.

---

## 3. Current State Summary

### Extensions and Their Initialization Locations

| Extension | File Location | Lines | Always Initialized |
|-----------|--------------|-------|-------------------|
| MeshRuntime | `unified_server.rs` | 537-1037 | No (config-gated) |
| DnsRuntime | `unified_server.rs` | 699-795 | No (feature-gated) |
| PluginRuntime | `unified_server.rs` | 22, 337-338 | No (feature-gated) |
| ServerlessRuntime | `unified_server.rs` | 333-364 | No (config-gated) |
| UploadScanningRuntime | `unified_server.rs` | 429-469 | Yes (always compiled) |
| HoneypotRuntime | `unified_server.rs` | 472-520 | Yes (always compiled) |
| TunnelRuntime | `unified_server.rs` | 624-628 | No (config-gated) |

### Feature-Gated vs Always-Initialized

**Feature-gated (compile-time):**
- `dns` - DNS serving, mesh DNS registry
- `wasm` - WASM plugin support (implied)

**Config-gated (runtime):**
- Mesh networking: `main.tunnel.mesh.enabled`
- Serverless: `main.serverless.enabled`
- Port honeypot: `main.honeypot_port.enabled`

**Always compiled:**
- Upload scanning (YARA may be runtime-disabled)
- Honeypot (config-gated but always compiled)

### Failure Policy Issues

| Extension | Current Policy | Issue |
|-----------|---------------|-------|
| Mesh | Fail-open (dummy threat intel) | Security issue - mesh is security-critical |
| DNS | Fail-open (warning) | Global nodes require DNS |
| Serverless | Fail-open (warning) | May be acceptable for optional feature |
| UploadScanning | Fail-open (warning) | May be acceptable for optional feature |
| Honeypot | Fail-open (warning) | Observability feature - fail-open acceptable |

---

## 4. Approach for Truly Optional Extensions at Runtime

This section documents what **would need to change** to make extensions truly optional at runtime. **This is NOT implemented.**

### 4.1 Replace Global Singletons with `Option<Arc<T>>` in Runtime Context

**Problem:** Global accessors like `crate::waf::get_threat_intel()` and `crate::waf::get_yara_rules()` return non-optional `Arc` even when the feature is disabled.

**Approach:**
1. Change global accessors to return `Option<Arc<T>>`
2. Store extensions as `Option<Arc<T>>` in `UnifiedServerWorkerState`
3. Request-handling code checks `Option::is_some()` before using extension
4. Eliminates need for dummy managers when feature is disabled

**Example change:**
```rust
// Current (conceptual)
pub fn get_threat_intel() -> Arc<ThreatIntelligenceManager> { ... }

// Desired
pub fn get_threat_intel() -> Option<Arc<ThreatIntelligenceManager>> { ... }
```

### 4.2 Explicit Extension Initialization Traits

**Problem:** Extensions are initialized inline in `run_unified_server_worker()`, making it unclear what depends on what.

**Approach:**
1. Define `ExtensionRuntime` trait:
```rust
trait ExtensionRuntime {
    fn initialize(worker_context: &WorkerContext, config: &Config) -> Result<Arc<Self>, ExtensionError>;
    fn shutdown(&self) -> impl Future<Output = ()>;
    fn reload(&self, config: &Config) -> Result<(), ExtensionError>;
}
```

2. Implement for each extension: `MeshRuntime`, `DnsRuntime`, `ServerlessRuntime`, etc.
3. Core worker only depends on extension trait objects, not concrete types
4. Extension list is configurable via profile/config

### 4.3 Clear Failure Policy per Extension

| Extension | Recommended Failure Policy |
|-----------|---------------------------|
| MeshRuntime | **Fail-closed** if enabled in config but cannot start |
| DnsRuntime | **Fail-closed** if global node and DNS required |
| ServerlessRuntime | **Fail-open** with warning (optional feature) |
| UploadScanningRuntime | **Fail-open** with warning (optional feature) |
| HoneypotRuntime | **Fail-open** with warning (observability) |

**Implementation:**
- Add `failure_policy: FailPolicy` to extension config
- `FailPolicy::FailClosed` - worker fails to start
- `FailPolicy::FailOpen` - worker continues with degraded capability
- Security-critical extensions default to `FailClosed`

### 4.4 Core Worker Without Extensions

**Problem:** Reading `unified_server.rs` to understand what the worker does requires understanding mesh, DNS, plugin, YARA, and honeypot code.

**Approach:**
1. Extract extension initialization into separate functions called from `run_unified_server_worker()`
2. Each extension has a clear `initialize_extension_name()` function
3. Core worker startup sequence is readable in one function
4. Extension functions document their dependencies

### 4.5 Process Isolation Consideration (Deferred)

**Problem:** WASM plugins/serverless and upload scanning have higher risk if compromised. Mesh control-plane should remain in worker for routing performance.

**Approach (deferred):**
- Move WASM plugin runtime to separate process
- Move upload scanning to separate sandboxed process
- Document tradeoffs before implementing
- Do not implement until lifecycle boundaries are explicit

---

## 5. Items Not Fully Implemented

1. **No structural changes made** - this is documentation only
2. **Dummy global state still exists** - when mesh is disabled, dummy `ThreatIntelligenceManager` is still created (lines 543-579, 1040-1077)
3. **Extension failure policy not enforced** - currently all extensions fail-open
4. **Reload blocked for mesh** - `cfg!(feature = "mesh")` blocks config reload (line 1334), but this is compile-time feature, not runtime config
5. **Global accessors still return non-optional** - `get_threat_intel()`, `get_yara_rules()` would need API changes

---

## 6. Related Documentation

- `plans/plan.md` - Priority 5: Split the Unified Worker Runtime (lines 2135-2213)
- `docs/adr/ADR-003-unified-worker-process.md` - Unified Worker Process Architecture ADR
- `src/worker/unified_server.rs` - Main worker implementation
- `src/mesh/` - Mesh runtime implementation
- `src/waf/mod.rs` - WAF core and global accessors
