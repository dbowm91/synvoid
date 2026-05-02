# Runtime Ownership Inventory

**Status**: COMPLETE (draft for Priority 2)
**Last Updated**: 2026-05-02
**Purpose**: Document runtime ownership boundaries for each subsystem initialized in the worker

---

## Overview

The worker process (`src/worker/unified_server.rs`) initializes a large set of subsystems during startup. This document catalogs each subsystem's ownership, scope, lifecycle behavior, and background task handling.

---

## Data-Plane Subsystems (Core)

### HTTP Server (HTTP/1, HTTP/2)
- **Owner**: Worker
- **Scope**: per-worker (listeners on configured ports)
- **Startup**: `UnifiedServer::new()` → `run_http_server_inner()` at line 1119
- **Shutdown**: `shutdown_tx.broadcast()` → servers stop accepting, drain connections
- **Reload**: Not hot-reloadable; changes require restart
- **Background Tasks**: Tracked in `task_handles` at line 1644
- **Notes**: Spawns HTTP and HTTPS listeners as `JoinHandle`s; these are awaited in `tokio::select!`

### TLS Server
- **Owner**: Worker
- **Scope**: per-worker (listener on configured TLS port)
- **Startup**: `UnifiedServer::new()` → `run_https_server_inner()` at line 1188
- **Shutdown**: Same broadcast channel as HTTP
- **Reload**: Certificate reload via `MasterCertReload` message (line 1372)
- **Background Tasks**: Same `task_handles` tracking
- **Notes**: Shares shutdown coordination with HTTP

### HTTP/3 Server (QUIC)
- **Owner**: Worker
- **Scope**: per-worker
- **Startup**: `UnifiedServer::new()` → `run_http3_server_inner()` at line 1238
- **Shutdown**: Same broadcast channel
- **Reload**: Certificate reload same as TLS
- **Background Tasks**: Same `task_handles` tracking
- **Notes**: Uses `quinn` QUIC stack

### TCP Pool (SYN proxy / flood protection)
- **Owner**: Worker
- **Scope**: per-worker
- **Startup**: `create_tcp_pool()` at line 687 in `UnifiedServer::new()`
- **Shutdown**: Part of unified server shutdown
- **Reload**: Static config
- **Background Tasks**: `tcp_jh` awaited in `select!`
- **Notes**: Flood protector uses internal rate limiting

### UDP Pool
- **Owner**: Worker
- **Scope**: per-worker
- **Startup**: `create_udp_pool()` at line 734 in `UnifiedServer::new()`
- **Shutdown**: Part of unified server shutdown
- **Reload**: Static config
- **Background Tasks**: `udp_jh` awaited in `select!`

### WAF Core (`WafCore`)
- **Owner**: Worker
- **Scope**: per-worker, shared across all request handling
- **Startup**: `Self::create_waf()` at line 590 in `UnifiedServer::new()`
- **Shutdown**: Implicit in process shutdown
- **Reload**: `reload_attack_detector()` at line 576 via `RulePatternsUpdate` message
- **Background Tasks**: `start_background_tasks()` called at line 427 in worker startup
  - ASN tracker cleanup task (internal)
  - See `src/waf/mod.rs:562` for spawned task
- **Notes**: Uses global singletons (`THREAT_INTEL`, `YARA_RULES`, `UPLOAD_VALIDATOR`) accessed via `get_threat_intel()` etc.

### Router
- **Owner**: Worker
- **Scope**: per-worker
- **Startup**: Built in `UnifiedServer::run()` at line 884 using config
- **Shutdown**: Implicit
- **Reload**: Router is rebuilt on worker restart only; hot reload of config does NOT rebuild router
- **Background Tasks**: None

### Metrics (WorkerMetrics, BandwidthTracker)
- **Owner**: Worker
- **Scope**: per-worker (process-wide persistence)
- **Startup**: Line 323-324 and 311-320 for bandwidth
- **Shutdown**: Bandwidth persistence on shutdown (line 1310)
- **Reload**: N/A (in-memory)
- **Background Tasks**:
  - `bandwidth_persist_handle` at line 1251 — tracked in `task_handles`
  - Periodically persists bandwidth data every 60 seconds

---

## Data-Plane Optional Subsystems

### Serverless Manager
- **Owner**: Worker
- **Scope**: per-worker
- **Startup**: Lines 333-354 in worker startup, wrapped in `UnifiedServer::with_serverless_manager()`
- **Shutdown**: Implicit in process shutdown
- **Reload**: Replaces serverless manager handle; plugins can be hot-reloaded
- **Background Tasks**: None direct; WASM runtime manages plugin lifecycle
- **Notes**: Uses `get_global_plugin_manager()` for WASM runtime

### Upload Validator (YARA scanning, sandbox)
- **Owner**: Worker
- **Scope**: per-worker
- **Startup**: Lines 429-470
- **Shutdown**: Implicit
- **Reload**: Upload config is static per worker
- **Background Tasks**: None direct; YARA scanning happens per-upload
- **Notes**: Set as global singleton via `set_upload_validator()`

### Port Honeypot
- **Owner**: Worker
- **Scope**: per-worker
- **Startup**: Lines 472-512
- **Shutdown**: Implicit in process shutdown
- **Reload**: Static config
- **Background Tasks**:
  - `runner_clone.run().await` spawned at line 517 — **NOT TRACKED**
  - This is a detached infinite loop task

### Plugin Manager (WASM)
- **Owner**: Worker
- **Scope**: per-worker
- **Startup**: Lines 819-851 in `UnifiedServer::run()`
- **Shutdown**: Implicit
- **Reload**: `PluginManagerLifecycle::enable_hot_reload()` at line 877 - **INTENTIONALLY LEAKED**
  - See comment at line 876: "intentionally leaked so the watcher thread stays alive"
- **Background Tasks**: Plugin file watcher is leaked intentionally
- **Notes**: This is a known leak for hot reload compatibility

---

## Control-Plane / Distributed Subsystems

### Mesh Transport Manager
- **Owner**: Worker
- **Scope**: per-node (mesh network participation)
- **Startup**: Lines 582-628 in worker startup (when mesh enabled)
- **Shutdown**: Implicit (transport handles graceful disconnect)
- **Reload**: Mesh identity/role requires worker restart; hot reload blocked (line 1335)
- **Background Tasks**:
  - QUIC connection maintenance (internal to transport)
  - DHT operations
  - Topology maintenance
  - See `MeshTransportManager` docs
- **Notes**: Key mesh components initialized even when mesh disabled (creates dummy threat intel)

### Threat Intelligence Manager
- **Owner**: Worker (shared across mesh peers)
- **Scope**: cluster-wide (via mesh DHT sync)
- **Startup**: Lines 686-692 when mesh enabled, or dummy at lines 547-572 when disabled
- **Shutdown**: Implicit
- **Reload**: Via `ThreatFeedUpdate` messages from Master
- **Background Tasks**:
  - `start_background_tasks()` at line 898 spawns periodic sync/cleanup tasks
  - These tasks are internal to the manager (not exposed to worker)
- **Notes**: Set as global singleton via `set_threat_intel()`

### DHT Routing Manager
- **Owner**: Worker
- **Scope**: per-node (participates in DHT routing)
- **Startup**: Lines 593-609 when DHT enabled
- **Shutdown**: Implicit
- **Reload**: Requires worker restart
- **Background Tasks**:
  - `manager.init().await` spawned at line 604 — **NOT TRACKED**
  - This is a long-running DHT initialization

### YARA Rules Manager
- **Owner**: Worker
- **Scope**: per-node (distributes rules via DHT when mesh enabled)
- **Startup**: Lines 903-1008
- **Shutdown**: Implicit
- **Reload**: Via feed polling or DHT sync
- **Background Tasks**:
  - Feed fetching (line 956) - internal to manager
  - DHT sync task spawned at line 973 — **NOT TRACKED**
  - DHT re-announce task spawned at line 995 — **NOT TRACKED**
- **Notes**: Set as global singleton via `set_yara_rules()`

### DNS Server (global nodes only)
- **Owner**: Worker
- **Scope**: per-node (when compiled with `dns` feature and role is global)
- **Startup**: Lines 290-376 in `UnifiedServer::new()`
- **Shutdown**: Part of unified server shutdown
- **Reload**: Static config
- **Background Tasks**: `dns_jh` awaited in `select!`
- **Notes**: Only runs on global mesh nodes; edge nodes get minimal registry

### ACME Manager (TLS certificates)
- **Owner**: Worker
- **Scope**: per-worker
- **Startup**: `setup_acme()` at line 476
- **Shutdown**: Implicit
- **Reload**: Automatic renewal; `MasterCertReload` message triggers reload
- **Background Tasks**:
  - Renewal task spawned at line 514 via `tokio::spawn` — **NOT TRACKED**
  - Runs for certificate lifetime

### Granian Supervisors (AppServer backends)
- **Owner**: Worker
- **Scope**: per-site (one supervisor per site with AppServer config)
- **Startup**: Lines 387-422 spawned as async task
- **Shutdown**: Graceful stop via `supervisor.stop()` in shutdown handler (lines 1301-1304)
- **Reload**: Supervisors are recreated on worker restart only
- **Background Tasks**:
  - Initial spawn at line 391 — **NOT TRACKED** (fire-and-forget per site)
  - Each supervisor manages a subprocess lifecycle

---

## Background Task Tracking Summary

### Tracked (stored in `task_handles` and aborted on shutdown)
| Task | Line | Purpose |
|------|------|---------|
| `heartbeat_handle` | 1204 | Worker heartbeat to Master |
| `bandwidth_persist_handle` | 1251 | Bandwidth persistence |
| `ipc_handle` | 1263 | IPC message loop |
| `server_handle` | 1644 | HTTP/HTTPS/HTTP3 server |

### Untracked but Cancellable (spawned, runs indefinitely)
| Task | Line | Purpose | Issue |
|------|------|---------|-------|
| `port_honeypot_runner.run()` | 517 | Honeypot port monitoring | Not tracked |
| `granian_supervisor.start()` | 391 | AppServer process management | Not tracked |
| `manager.init().await` (DHT) | 604 | DHT routing initialization | Not tracked |
| `registry.start_verification_loop()` | 782 | DNS verification (global nodes) | Not tracked |
| `mesh_broadcast_rx.forward` | 843 | Mesh broadcast forwarder | Not tracked |
| `yara_rules.sync_from_dht` | 973 | YARA DHT sync | Not tracked |
| `yara_rules.publish_rules` | 995 | YARA rule re-announce | Not tracked |

### Intentionally Leaked (process-lifetime tasks)
| Task | Line | Purpose | Note |
|------|------|---------|------|
| `PluginManagerLifecycle` file watcher | 877 | Plugin hot reload | Comment explicitly says "intentionally leaked" |
| ACME renewal task | 514 | Certificate renewal | Runs until certificate expires or is renewed |

### Internal (managed by subsystem, not worker-visible)
| Task | Line | Manager |
|------|------|---------|
| ThreatIntel background tasks | 898 | ThreatIntelligenceManager |
| WAF background tasks | 427 | WafCore |
| Topology background tasks | 590 | MeshTopology |
| RecordStore background tasks | 113 | RecordStore |
| YaraRulesManager internal sync | various | YaraRulesManager |

---

## Lifecycle Phases (Worker Startup)

The worker startup in `run_unified_server_worker()` can be partitioned into these phases:

### Phase 1: Load Config and Validate
- Lines 177-247
- Initialize IPC connection to Master
- Load and validate main config
- Check port availability
- Extract TLS passthrough sites

### Phase 2: Initialize Core Data Plane
- Lines 303-368
- Bandwidth tracker initialization
- WorkerMetrics initialization
- UnifiedServer creation
- Serverless manager initialization

### Phase 3: Initialize Data-Plane Extensions
- Lines 387-427
- Granian supervisors for AppServer backends
- WAF background tasks (`start_background_tasks()`)
- Upload validator
- Port honeypot

### Phase 4: Initialize Control-Plane / Distributed Extensions
- Lines 522-1077
- Mesh transport initialization (when enabled)
- Threat intelligence
- DHT routing
- YARA rules
- DNS server (global nodes)
- ACME manager

### Phase 5: Wire Inter-Subsystem References
- Lines 1079-1108
- Serverless manager → record store / transport wiring
- Port honeypot → threat intel wiring

### Phase 6: Request Blocklist from Master
- Lines 1114-1160
- Request initial blocklist via IPC

### Phase 7: Start Listeners
- Lines 1162-1650
- Finalize worker state
- Spawn heartbeat, bandwidth persistence, IPC, and server tasks
- `UnifiedServer::run()` starts HTTP/HTTPS/HTTP3/TCP/UDP/DNS listeners

---

## Subsystem Reload Behavior

| Subsystem | Hot Reload? | Restart Required? |
|-----------|------------|-------------------|
| WAF rules | Yes | No (`RulePatternsUpdate`) |
| WAF attack detector | Yes | No (`reload_attack_detector()`) |
| TLS certificates | Yes | No (`MasterCertReload`) |
| Site routing | No | Yes (router rebuilt) |
| Mesh config | No | Yes |
| Threat intel | Yes (feed update) | No |
| Port honeypot | No | Yes |
| Granian supervisors | No | Yes |
| Upload validator | No | Yes |
| Plugin manager | Partial (hot reload) | No for plugins |
| DNS config | No | Yes |

---

## Issues Identified

1. **Global Singletons**: `THREAT_INTEL`, `YARA_RULES`, `UPLOAD_VALIDATOR` in `src/waf/mod.rs` are process-wide singletons accessed via getter functions. This prevents per-context ownership.

2. **Untracked Tasks**: Several tasks are spawned without being stored in `task_handles`:
   - Port honeypot runner
   - Granian supervisor initialization
   - DHT routing manager init
   - DNS verification loop
   - Mesh broadcast forwarder
   - YARA DHT sync and re-announce

3. **Intentional Leaks**: Plugin lifecycle manager is explicitly leaked for hot reload. ACME renewal task is also not tracked.

4. **Mesh Blocks Hot Reload**: At line 1335-1340, hot reload is completely blocked when mesh feature is enabled.

5. **DHT Routing Init Not Awaited**: The DHT routing manager initialization at line 604 is spawned but never awaited, making startup success unclear.

6. **Bandwidth Persistence Interval**: Bandwidth persistence runs every 60 seconds indefinitely; if this task were cancelled during drain, data could be lost.
