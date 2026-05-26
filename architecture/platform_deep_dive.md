# Platform & Process Deep Dive

## Overview

This document covers the platform abstraction layer, IPC primitives, and process supervision architecture.

---

## 1. Platform Module (`src/platform/`)

### Purpose

Cross-platform abstractions providing OS-level functionality for Unix and Windows systems, including IPC transport, sandboxing, process control, and socket management.

### Key Files

| File | Responsibility |
|------|----------------|
| `mod.rs` | Platform enum detection, capability queries, exports |
| `ipc.rs` | Traits for IPC transport abstraction (`IpcTransport`, `IpcListener`, `IpcStream`) |
| `sandbox.rs` | Multi-backend sandboxing (Landlock, Capsicum, Pledge, Seatbelt, Job Objects) |
| `socket.rs` | Socket creation, FD passing, owned socket wrappers |
| `process.rs` | Process control traits, signal handling |
| `unix.rs` | Unix-specific implementations (UnixDomain sockets, signals, daemonization) |
| `windows_impl.rs` | Windows-specific IPC via named pipes |
| `fs.rs` | Filesystem operations with sandbox integration (path resolution, traversal prevention) |

### Platform Abstraction Pattern

```rust
// Capability detection via Platform enum
pub enum Platform {
    Linux, LinuxMusl, Macos, FreeBSD, OpenBSD, NetBSD, Windows, Unknown
}

// Feature gates via boolean queries
platform().supports_socket_fd_passing()  // Unix only
platform().supports_signals()            // Unix only
platform().supports_sandbox()            // Linux/FreeBSD/OpenBSD only
platform().supports_reuse_port()         // Linux/Macos/FreeBSD
```

### Key Traits

| Trait | Purpose |
|-------|---------|
| `IpcTransport` | Send/recv/close semantics for byte streams |
| `IpcListener` | Binding and accepting connections |
| `IpcStream` | Client-side connect with peer PID detection |
| `ProcessControl` | Signal sending, daemonization |
| `SignalHandler` | Async signal registration |
| `SocketHandle` | TCP listener/stream conversion |
| `SocketFDPassing` | SCM_Rights-based FD passing over Unix sockets |
| `SandboxBackend` | Filesystem restrictions, syscall filtering |

### Sandbox Backends

| Platform | Backend | Key Capabilities |
|---------|---------|------------------|
| Linux (5.13+) | **Landlock** | Read/write path allowlists, filesystem restrictions |
| FreeBSD | **Capsicum** | FD rights limiting, process limits |
| OpenBSD | **Pledge + Unveil** | Promise-based syscall filtering, path permissions |
| macOS | **Seatbelt** | Sandboxed profile compilation (planned feature, not yet implemented) |
| Windows | **Job Objects + DACL** | Process memory limits, file security descriptors |

---

## 2. Process Module (`src/process/`)

### Purpose

IPC primitives, process management, socket FD passing, message framing, worker lifecycle, and signed communication.

### Key Files

| File | Purpose |
|------|---------|
| `ipc.rs` | Message enum (60+ variants), `IpcStream` sync wrapper, validation |
| `ipc_framing.rs` | Length-prefixed message framing (4-byte BE length header) |
| `ipc_signed.rs` | HMAC-SHA3-256 signing, nonce replay protection, timestamp validation |
| `ipc_transport.rs` | Async IPC transport (`IpcStream`, `IpcListener`, `IpcEndpoint`) |
| `ipc_pool.rs` | Connection pooling per endpoint with statistics |
| `ipc_rate_limit.rs` | Token bucket rate limiting (global + per-worker) |
| `socket_fd.rs` | Unix FD passing via `SCM_Rights`, `SocketHolder` for batch handoff |
| `manager.rs` | `ProcessManager` - spawn/monitor/restart workers |
| `worker.rs` | Worker process structs (`BaseWorkerProcess`, `WorkerProcess`, `StaticWorkerProcess`, `UnifiedServerWorkerProcess`) |
| `pidfile.rs` | PID file management, overseer lock file |
| `command.rs` | Command client/response types |
| `ipc_windows.rs` | Windows IPC via named pipes (Server side, pipe server implementation) |
| `socket_path.rs` | Master socket path resolution and versioning for upgrades |

### Message Types (IPC)

The `Message` enum is organized into **17 categories**:

1. **WorkerLifecycle**: `WorkerStarted`, `WorkerReady`, `WorkerHeartbeat`, `WorkerError`
2. **MasterCommand**: `MasterShutdown`, `MasterConfigReload`, `MasterHealthCheck`
3. **StaticWorker**: `StaticWorkerStarted`, `StaticWorkerReady`, `StaticWorkerDrain`
4. **ThreatIntel**: `ThreatIndicatorAnnounce`, `ThreatSyncRequest/Response`
5. **BlocklistRules**: `BlocklistUpdate`, `RulePatternsUpdate`
6. **StaticContent**: `MinifyRequest/Response`, `PoisonImageRequest/Response`
7. **AppServer**: `AppServerRequest`, `AppServerResponse`, `AppServerChunk`, `AppServerUpgrade`
8. **UnifiedServer**: `UnifiedServerWorkerStarted/Ready/Drain`
9. **WorkerDrain**: `WorkerDrain`, `WorkerDrained`, `WorkerDrainComplete`
10. **Upgrade**: `UpgradeReady`, `OverseerUpgradePrepare/Commit/Rollback`
11. **Overseer**: `OverseerDrainWorkers`, `OverseerGetStatus`
12. **MasterDrain**: `MasterDrainMode`, `MasterConnectionsReport`
13. **DrainProtocol**: `DrainRequest`, `DrainStatusResponse`
14. **SocketHandoff**: `SocketHandoffRequest/Ready/Complete` (Windows)
15. **WorkerRestart**: `WorkerRestartRequest`, `WorkerRestartAck`
16. **Plugin**: `PluginExecuteRequest/Response`, `ServerlessHandleRequest/Response`
17. **MeshControl**: `MeshControlRequest/Response`, `MeshUpdateNotification`

### IPC Framing Protocol

```
4-byte length (BE) + serialized Message
MAX_MESSAGE_SIZE: 1 MiB
```

### Signed IPC

```
[4-byte length][8-byte timestamp][16-byte nonce][32-byte HMAC][payload]
```

**Security features**:
- HMAC-SHA3-256 authentication
- Timestamp validation (60-second replay window)
- Nonce deduplication via `DashMap` sharded cache
- Constant-time HMAC comparison via `subtle::ConstantTimeEq`

### Socket FD Passing (Unix)

- Uses `SCM_Rights` control messages over Unix domain sockets
- `SocketFDPassing::send_fds()` / `recv_fds()` 
- `MAX_FDS_PER_MESSAGE`: 254 (Linux kernel limit)
- `SocketHolder` batches multiple sockets for handoff

---

## 3. Supervisor Module (`src/supervisor/`)

### Purpose

Consolidated supervisor process handling zero-downtime upgrades, IPC communications, and worker orchestration via `ProcessManager`.

### Key Files

| File | Purpose |
|------|---------|
| `process.rs` | `SupervisorProcess` struct, `run_supervisor_mode()` entry point |
| `api.rs` | gRPC control plane server (tonic-based) |
| `state.rs` | `SupervisorState` with trackers |
| `commands.rs` | Command handling |
| `mesh.rs` | Mesh agent mode |

### Supervisor Process Architecture

```
SupervisorProcess
├── state: SupervisorState
├── process_manager: Arc<ProcessManager>
├── event_rx: mpsc::Receiver<ProcessEvent>
├── running: RunningFlag
└── ipc_listener: Option<IpcListener>
```

**Main responsibilities**:
1. Spawns unified server workers
2. Maintains IPC listener for worker/command connections
3. Runs gRPC control API on `localhost` (port 50051 default)
4. Periodic health checks and zombie reaping (every 5 seconds)
5. Shared state initialization (connection table, rate limit table)

### gRPC Control Plane API

| RPC | Purpose |
|-----|---------|
| `GetStatus` | Worker info, request statistics |
| `ReloadConfig` | Hot-reload configuration |
| `Stop` | Graceful shutdown |
| `BlockIp` | Manual IP block |
| `UnblockIp` | Manual IP unblock |

**Security note**: gRPC binds to `localhost` only - TLS not required for local IPC.

---

## 4. Startup Module (`src/startup/`)

### Purpose

Bootstrap, daemonization, master/worker startup entry points.

### Key Files

| File | Purpose |
|------|---------|
| `bootstrap.rs` | Logging initialization, test mode warning |
| `daemon.rs` | Signal handlers, PID file acquisition, daemonize |
| `master.rs` | `run_master_mode()`, `run_overseer_mode()`, master event loop |
| `worker.rs` | Worker argument builders (`build_static_worker_args`, `build_unified_server_worker_args`) |
| `mod.rs` | `MasterState`, `MasterStateTrackers` shared across processes |

### Startup Flow

```
run_master_mode()
├── setup_panic_handler()
├── ConfigManager::load_main()
├── Tokio multi-thread runtime
├── Post-quantum TLS initialization
├── Site discovery and loading
├── BlockStore initialization
├── RuleFeedManagerForWaf (if threat intel enabled)
├── ProcessManager::new()
├── IpcListener bind
├── Worker spawning (UnifiedServerWorker)
├── StaticWorker spawning
├── setup_signal_handlers()
├── start_health_monitor()
├── start_admin_server()
└── event_rx loop
```

**Note:** The Master MUST NOT run UnifiedServer inline for request handling, accept external network traffic, or handle HTTP/TCP/UDP/QUIC/WebSocket requests. Master ONLY runs admin panel API, orchestrates threat intelligence, manages worker processes, and handles IPC communications.

> **Source:** `src/startup/master.rs:278-302`

---

## Architecture Diagram

SynVoid supports two deployment modes:

### Consolidated Mode (Recommended)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Supervisor Process                           │
│  ┌──────────────┐  ┌─────────────────┐  ┌───────────────────────┐   │
│  │ SupervisorState │  │ ProcessManager │  │  gRPC Control API    │   │
│  │  - Config     │  │  - Workers[]   │  │  (127.0.0.1:50051)    │   │
│  │  - BlockStore│  │  - Unified[]   │  │                      │   │
│  │  - Trackers  │  │  - Static      │  │                      │   │
│  └──────────────┘  └─────────────────┘  └───────────────────────┘   │
│         │                    │                      │                │
│         │         ┌──────────┴──────────┐            │                │
│         │         │   IPC Listener      │            │                │
│         │         │ (Unix Domain Socket)│            │                │
│         └─────────┼─────────────────────┼────────────┘                │
│                   │                     │                             │
│                   └──────────┬──────────┘                             │
│                              │                                        │
│     ┌────────────────────────▼────────────────────────┐             │
│     │              Worker Processes                     │             │
│     │  ┌─────────────────────────────────────────────┐  │             │
│     │  │ UnifiedServerWorker                         │  │             │
│     │  │ (HTTP/HTTPS/HTTP3 + WAF + Proxy)           │  │             │
│     │  │ (tokio async loop, CPU-affinity pinned)     │  │             │
│     │  └─────────────────────────────────────────────┘  │             │
│     │  ┌─────────────────────────────────────────────┐  │             │
│     │  │ StaticWorker                                │  │             │
│     │  │ (CSS/JS minification, compression)          │  │             │
│     │  └─────────────────────────────────────────────┘  │             │
│     └─────────────────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────────────────┘
```

**Legend:** Supervisor spawns Workers directly. No Master process. Use this for single-host deployments.

### Traditional Mode (Legacy)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Supervisor Process                           │
│  ┌──────────────┐  ┌─────────────────┐  ┌───────────────────────┐   │
│  │ SupervisorState │  │ ProcessManager │  │  gRPC Control API    │   │
│  │  - Config     │  │  - Workers[]   │  │  (127.0.0.1:50051)    │   │
│  │  - BlockStore│  │  - Unified[]   │  │                      │   │
│  │  - Trackers  │  │  - Static      │  │                      │   │
│  └──────────────┘  └─────────────────┘  └───────────────────────┘   │
│         │                    │                      │                │
│         │         ┌──────────┴──────────┐            │                │
│         │         │   IPC Listener      │            │                │
│         │         │ (Unix Domain Socket)│            │                │
│         │         └─────────────────────┘            │                │
└─────────┼─────────────────────────────────────────────┼────────────────┘
          │                                             │
          │         ┌─────────────────────────────────┘
          │         │
     ┌────▼─────────▼──────────────────────────────────┐
     │               Master Process                       │
     │  ┌─────────────────┐  ┌──────────────────────┐   │
     │  │ ProcessManager  │  │ Admin Server         │   │
     │  │ (shared w/ sup) │  │ (port from config)   │   │
     │  │                 │  │                      │   │
     │  │ ⚠️ MUST NOT     │  │                      │   │
     │  │ handle requests │  │                      │   │
     │  └─────────────────┘  └──────────────────────┘   │
     │           │                                      │
     └───────────┼──────────────────────────────────────┘
                 │
     ┌───────────▼───────────────┐
     │   IPC Socket (signing)    │
     └───────────▲───────────────┘
                 │
     ┌───────────┴───────────────┐
     │   Worker Processes        │
     │  ┌─────────────────────┐  │
     │  │ UnifiedServerWorker │  │  (HTTP/HTTPS/HTTP3 + WAF)
     │  │ (tokio async loop)   │  │
     │  └─────────────────────┘  │
     │  ┌─────────────────────┐  │
     │  │ StaticWorker        │  │  (CSS/JS minification)
     │  └─────────────────────┘  │
     └───────────────────────────┘
```

**Legend:** Supervisor → Master → Workers. Master handles admin API only. Use this for multi-host orchestration.

---

## Key Security Patterns

| Pattern | Implementation |
|---------|----------------|
| **IPC Signing** | HMAC-SHA3-256 with nonce + timestamp |
| **Replay Protection** | Sharded nonce cache (DashMap), 60s window |
| **Constant-time Compare** | `subtle::ConstantTimeEq` for HMAC |
| **Key Injection** | Temp file with 0o600 perms, not env var |
| **Sandboxing** | Landlock/Capsicum/Pledge/Seatbelt per-platform |
| **Strict Sandbox** | Requires read-path allowlist support |
| **IPC Rate Limiting** | Token bucket + per-worker isolation |
| **FD Passing** | Unix-only SCM_Rights, max 254 FDs |
| **Message Validation** | String length limits, path traversal checks |

---

## Critical Security Constraint: Master/Supervisor Isolation

### Requirement

**Master and Supervisor processes MUST NOT accept external traffic or handle untrusted client requests.**

### Architecture

| Process | Role | External Traffic |
|---------|------|------------------|
| **Supervisor** | Lifecycle management, health monitoring, upgrade coordination | No - localhost IPC only |
| **Master** | Admin API, worker orchestration, threat intelligence | No - localhost admin API only |
| **UnifiedServerWorker** | HTTP/HTTPS/HTTP3 request handling, WAF, proxy | **Yes - all client traffic** |

### Security Model

1. **Least Privilege**: Master/Supervisor handle sensitive operations (config management, worker orchestration, threat intelligence aggregation). Workers handle untrusted client input (HTTP requests, uploads, etc.)

2. **Process Isolation**: If a CVE exists in request handling code (UnifiedServerWorker), the Master/Supervisor processes are protected because they run in separate processes. An attacker cannot escalate from a compromised Worker to Master.

3. **Crash Isolation**: When a Worker crashes (OOM, segfault, panic), the Master continues running and can restart the Worker. The admin panel remains accessible even during Worker failures.

4. **gRPC Binding**: The Supervisor's gRPC control API binds to `127.0.0.1:50051` only (configurable via `control_api_addr`). TLS is not required for localhost IPC.

### Enforcement

- `src/startup/master.rs:278-302`: Master MUST NOT run UnifiedServer inline for request handling
- Master MUST NOT accept HTTP/TCP/UDP/QUIC/WebSocket requests directly
- Master MUST NOT handle any external network traffic for proxying

### macOS Seatbelt Sandboxing

Seatbelt sandbox for macOS is **planned but not yet implemented** (`src/platform/sandbox.rs`). Other platforms use Landlock (Linux), Capsicum (FreeBSD), or Pledge+Unveil (OpenBSD).

---

## Related Documentation

- [Overview](overview.md) - Bird's eye view of SynVoid architecture
- [Process Lifecycle](process_lifecycle.md) - Detailed process lifecycle
- [Worker Architecture](worker_architecture.md) - Worker architecture details