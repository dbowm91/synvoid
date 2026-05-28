# Supervisor Module Architecture

## 1. Purpose and Responsibility

The **Supervisor** is the top-level management process in SynVoid's multi-process architecture, responsible for:

- **Zero-downtime upgrades**: Coordinates graceful worker replacement during upgrades via socket handoff
- **Worker orchestration**: Manages the lifecycle of `UnifiedServerWorker` processes that handle HTTP/HTTPS/HTTP3 traffic
- **IPC communications**: Receives commands from CLI tools and forwards them to workers
- **Drain-aware shutdown**: Coordinates graceful connection draining before shutdown
- **Health monitoring**: Monitors worker health and restarts failed workers
- **gRPC control API**: Provides a control plane for runtime management

The Supervisor **consolidates** the legacy Overseer and Master hierarchy into a single unified process, simplifying the architecture while maintaining the same functionality.

### Process Hierarchy

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Supervisor                                    │
│  - Parent process (pid 1 in containerized deployments)              │
│  - Manages worker lifecycle via ProcessManager                      │
│  - gRPC control API on configurable address                       │
│  - IPC command socket (Unix domain / Windows named pipe)           │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│              UnifiedServerWorker(s)                                 │
│  - Tokio async runtime (configurable worker threads)                │
│  - Handles HTTP/HTTPS/HTTP3 + WAF + proxy                          │
│  - IPC channel back to supervisor                                   │
│  - Shared memory for connection tables                              │
└─────────────────────────────────────────────────────────────────────┘
```

### Entry Points

| Entry Point | File | Purpose |
|-------------|------|---------|
| `run_supervisor_mode()` | `src/supervisor/process.rs:306` | Default entry point (no flags) |
| `run_mesh_agent_mode()` | `src/supervisor/mesh.rs:27` | Standalone mesh agent (`--mesh-agent`) |

## 2. Key Submodules and Their Responsibilities

### 2.1 `supervisor/mod.rs` - Module Root

Public API surface for the supervisor crate:

```rust
pub mod api;       // gRPC control plane service
pub mod commands;  // CLI command handlers
pub mod mesh;      // Mesh agent mode
pub mod process;   // SupervisorProcess and run_supervisor_mode
pub mod state;     // SupervisorState and SupervisorStateTrackers

pub use mesh::run_mesh_agent_mode;
pub use process::{run_supervisor_mode, SupervisorProcess};
pub use state::{SupervisorState, SupervisorStateTrackers};
```

### 2.2 `supervisor/process.rs` - Core Supervisor

Core supervisor implementation with the main event loop and orchestration logic.

**Key Types:**
- `SupervisorProcess`: Main supervisor struct managing worker lifecycle
- `run_supervisor_mode()`: Entry point function

**Responsibilities:**
- Initialize `ProcessManager` and `DrainManager`
- Spawn initial unified server workers
- Accept IPC connections and route messages
- Start gRPC control server
- Run main event loop (health checks, zombie reaping, event handling)
- Coordinate drain-aware shutdown

### 2.3 `supervisor/state.rs` - State Management

Holds all supervisor state including configuration, block store, and feature-gated managers.

**Key Types:**
- `SupervisorState`: Central state container
- `SupervisorStateTrackers`: Feature-gated tracker collection

```rust
pub struct SupervisorState {
    pub config: Arc<RwLock<ConfigManager>>,
    pub shutdown_tx: broadcast::Sender<()>,
    pub start_time: std::time::Instant,
    
    // Feature-gated trackers (only present with `mesh` feature)
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub threat_level_manager: Option<Arc<ThreatLevelManager>>,
    pub rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    pub threat_intel_manager: Option<Arc<ThreatIntelligenceManager>>,  // mesh only
    pub yara_rules: Option<Arc<YaraRulesManager>>,                    // mesh only
    pub mesh_transport_manager: Option<Arc<MeshTransportManager>>,    // mesh only
    pub org_key_manager: Option<Arc<OrgKeyManager>>,                  // mesh only
    
    pub block_store: Arc<BlockStore>,
}
```

### 2.4 `supervisor/api.rs` - gRPC Control Plane

Implements `ControlPlane` tonic service for runtime management.

**Service Definition** (`proto/control.proto`):
```protobuf
service ControlPlane {
  rpc GetStatus (StatusRequest) returns (StatusResponse);
  rpc ReloadConfig (ReloadRequest) returns (ReloadResponse);
  rpc Stop (StopRequest) returns (StopResponse);
  rpc BlockIp (BlockRequest) returns (BlockResponse);
  rpc UnblockIp (UnblockRequest) returns (UnblockResponse);
}
```

**RPC Methods:**
| Method | Purpose |
|--------|---------|
| `GetStatus` | Returns supervisor PID, uptime, version, worker info, and stats |
| `ReloadConfig` | Triggers hot reload of configuration |
| `Stop` | Initiates graceful shutdown (with optional grace period) |
| `BlockIp` | Manually block an IP address with reason and duration |
| `UnblockIp` | Remove a manual IP block |

### 2.5 `supervisor/commands.rs` - CLI Command Handlers

Handles CLI commands received via IPC socket.

**Supported Commands:**
- `MasterCommand::Status` - Returns comprehensive status
- `MasterCommand::Stop { graceful }` - Initiates shutdown
- `MasterCommand::ReloadConfig` - Hot reload configuration
- `MasterCommand::HealthCheck` - Liveness check

### 2.6 `supervisor/mesh.rs` - Mesh Agent Mode

Standalone mesh agent for distributed mesh operations (feature-gated).

**Responsibilities:**
- Initialize mesh control plane components (when `mesh` feature enabled)
- Start background mesh tasks (DHT, topology, threat intel)
- Provide mesh-specific gRPC endpoints

**Feature Gates:**
- `#[cfg(feature = "mesh")]`: Full mesh agent implementation
- `#[cfg(not(feature = "mesh"))]`: Stub that exits with error message

## (Table of Contents placeholder - content continues below)

### 2.7 `src/supervisor/drain_manager.rs` - Drain Management

Drain infrastructure for coordinated worker draining during upgrades.

**Key Types:**
- `DrainManager`: Manages drain state for all workers
- `DrainProtocol`: Protocol for coordinating drain with workers

**Key Methods:**
| Method | Purpose |
|--------|---------|
| `start_drain(timeout_secs)` | Initiates a new drain with unique ID |
| `register_worker(worker_id, active, idle)` | Registers a worker for drain tracking |
| `update_worker_connections(worker_id, active, idle)` | Updates connection counts |
| `mark_worker_stopped_accepting(worker_id)` | Marks worker as no longer accepting |
| `mark_worker_drain_complete(worker_id, drained)` | Marks worker drain as complete |
| `wait_for_drain(timeout_secs)` | Awaits all workers to drain |
| `drain_worker_with_confirmation(ipc, worker_id, ...)` | Full drain protocol with worker |

**Drain Protocol Flow:**
```
1. Supervisor sends DrainRequest { timeout_secs, drain_id }
2. Worker acknowledges and enters drain mode
3. Supervisor sends StopAccepting { drain_id }
4. Worker acknowledges and stops accepting new connections
5. Supervisor polls DrainStatusRequest until drain_complete
6. Worker responds with DrainStatusResponse showing remaining connections
7. When all complete, Supervisor proceeds with shutdown
```

## 3. Major Data Structures and Types

### 3.1 Supervisor Process Structures

```rust
// src/supervisor/process.rs:30-38
pub struct SupervisorProcess {
    state: SupervisorState,
    process_manager: Arc<ProcessManager>,
    drain_manager: Arc<DrainManager>,
    drain_protocol: Arc<DrainProtocol>,
    event_rx: mpsc::Receiver<ProcessEvent>,
    running: RunningFlag,
    ipc_listener: Option<IpcListener>,
}
```

### 3.2 Drain Structures

```rust
// src/drain/mod.rs:6-10
pub struct WorkerConnectionInfo {
    pub active: u64,
    pub idle: u64,
}

// src/drain/mod.rs:12-24
pub struct DrainStatus {
    pub drain_id: u64,
    pub is_draining: bool,
    pub active_connections: u64,
    pub idle_connections: u64,
    pub connections_drained: u64,
    pub drain_start: Option<Instant>,
    pub drain_elapsed_secs: Option<u64>,
    pub drain_remaining_secs: Option<u64>,
    pub drain_complete: bool,
    pub by_worker: HashMap<usize, WorkerConnectionInfo>,
}

// src/drain/mod.rs:67-78
pub struct WorkerDrainState {
    pub drain_id: u64,
    pub worker_id: WorkerId,
    pub active_connections: u64,
    pub idle_connections: u64,
    pub stopped_accepting: bool,
    pub drain_complete: bool,
    pub initial_connections: u64,
    pub connections_drained: u64,
    pub drain_start: Instant,
}
```

### 3.3 IPC Message Types (Worker ↔ Supervisor)

```rust
// src/process/ipc.rs:729-761 - Drain Protocol Messages
Message::DrainRequest {
    timeout_secs: u64,
    drain_id: u64,
}
Message::DrainStatusRequest { drain_id: u64 }
Message::DrainStatusResponse {
    drain_id: u64,
    is_draining: bool,
    active_connections: u64,
    idle_connections: u64,
    connections_drained: u64,
    drain_elapsed_secs: u64,
    drain_complete: bool,
}
Message::StopAccepting { drain_id: u64 }
Message::StopAcceptingAck {
    drain_id: u64,
    accepted: bool,
    active_connections: u64,
}
```

### 3.4 Process Manager Configuration

```rust
// src/process/manager.rs:37-59
pub struct ProcessManagerConfig {
    pub min_workers: usize,
    pub max_workers: usize,
    pub unified_server_workers: usize,
    pub max_restart_attempts: u32,
    pub restart_cooldown_secs: u64,
    pub restart_backoff_max_secs: u64,
    pub heartbeat_timeout_secs: u64,
    pub graceful_shutdown_timeout_secs: u64,
    pub worker_port_base: u16,
    pub config_path: PathBuf,
    pub supervisor_socket_path: PathBuf,
    pub log_level: Option<String>,
    pub pre_spawn_workers: usize,
    pub warm_workers_target: usize,
    pub health_check_interval_secs: u64,
    pub control_api_addr: String,
    pub control_api_tls: Option<InternalTlsConfig>,
    pub ipc_session_key: Option<[u8; 32]>,
    pub ipc_enforce_signing: bool,
    pub allow_insecure_ipc_key: bool,
    pub ipc_rate_limit: IpcRateLimitConfig,
}
```

### 3.5 gRPC Control Plane Types

```rust
// src/supervisor/api.rs (generated from proto/control.proto)
message StatusResponse {
    uint32 pid = 1;
    uint64 uptime_secs = 2;
    string version = 3;
    repeated WorkerInfo workers = 4;
    Stats stats = 5;
}

message WorkerInfo {
    uint32 id = 1;
    uint32 pid = 2;
    uint32 port = 3;
    string status = 4;
    uint64 requests = 5;
    uint64 blocked = 6;
}

message Stats {
    uint64 total_requests = 1;
    uint64 blocked_last_hour = 2;
    uint64 challenged_last_hour = 3;
    uint64 active_blocks = 4;
}
```

## 4. Key APIs and Entry Points

### 4.1 Supervisor Initialization

```rust
// src/supervisor/process.rs:40-64
pub async fn new(
    state: SupervisorState,
    pm_config: ProcessManagerConfig,
) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
```

Creates a new supervisor instance with:
1. `ProcessManager` from config
2. `DrainManager` with 100ms poll interval
3. `DrainProtocol` wrapper
4. IPC listener bound to master endpoint

### 4.2 Main Supervisor Run Loop

```rust
// src/supervisor/process.rs:66-184
pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
```

Main event loop that:
1. Initializes shared tables (connections, rate limits)
2. Spawns initial unified server workers
3. Starts IPC accept loop
4. Starts gRPC control server
5. Runs main event loop:
   - Periodic health checks every 5 seconds
   - Zombie reaping
   - Process event handling
   - Shutdown signal handling

### 4.3 Drain-Aware Shutdown

```rust
// src/supervisor/process.rs:186-260
async fn drain_aware_shutdown(&self)
```

Graceful shutdown sequence:
1. ```rust
   let drain_id = self.drain_manager.start_drain(timeout_secs);
   ```
2. Register all unified server workers with drain manager
3. For each worker:
   - Send drain request via IPC
   - Send stop accepting via IPC
   - Poll drain status until complete or timeout
4. Wait for all workers to drain (with timeout)
5. Log drain status (active/idle connections)
6. Call `process_manager.shutdown_workers()`
7. Clear drain manager state

### 4.4 IPC Connection Handling

```rust
// src/supervisor/process.rs:262-299
async fn handle_connection(
    mut ipc: IpcStream,
    pm: Arc<ProcessManager>,
    state: SupervisorState,
)
```

Distinguishes between worker messages and admin commands:
1. Try receiving as `Message` (worker protocol)
2. If timeout/failure, try as `MasterCommand` (admin protocol)
3. Routes to appropriate handler

### 4.5 gRPC Server Start

```rust
// src/supervisor/api.rs:129-144
pub async fn start_grpc_server(
    addr: std::net::SocketAddr,
    process_manager: Arc<ProcessManager>,
    state: SupervisorState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
```

Starts tonic gRPC server with `ControlPlaneServer` service.

## 5. Process Supervision and Worker Orchestration

### 5.1 Worker Types

| Worker Type | Description | Management |
|-------------|-------------|------------|
| `UnifiedServerWorker` | HTTP/HTTPS/HTTP3 + WAF + proxy | Created by Supervisor via ProcessManager |
| `StaticWorker` | CSS/JS minification, compression | Optional, managed separately |
| `BaseWorkerProcess` | Legacy raw TCP/UDP (deprecated) | Not used for HTTP traffic |

### 5.2 ProcessManager Responsibilities

The `ProcessManager` (in `src/process/manager.rs`) handles:

- **Worker spawning** via `spawn_unified_server_workers(count)`
- **Health monitoring** via periodic heartbeats
- **Zombie reaping** via `reap_zombies()`
- **Graceful shutdown** via `shutdown_workers()`
- **Worker lookup** via `get_unified_server_worker_ipc(worker_id)`
- **Dynamic configuration** via `update_config()`

### 5.3 Worker Lifecycle

```
                    ┌─────────────────────────┐
                    │   Supervisor starts     │
                    │   ProcessManager        │
                    └─────────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ spawn_unified_server_   │
                    │ workers(N)              │
                    └─────────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Worker IPC connects     │
                    │ to master socket        │
                    └─────────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Worker sends           │
                    │ WorkerReady message    │
                    └─────────────────────────┘
                                 │
                    ┌───────────┴───────────┐
                    │                      │
                    ▼                      ▼
         ┌─────────────────┐   ┌─────────────────┐
         │ Worker handles  │   │ Health monitor  │
         │ traffic         │   │ checks         │
         └─────────────────┘   └─────────────────┘
                    │                      │
                    ▼                      ▼
         ┌─────────────────┐   ┌─────────────────┐
         │ On shutdown:    │   │ If heartbeat    │
         │ DrainRequest    │   │ missing:       │
         │ sent via IPC    │   │ Restart worker  │
         └─────────────────┘   └─────────────────┘
```

### 5.4 IPC Protocol

The IPC system uses typed messages over Unix domain sockets (Unix) or named pipes (Windows):

**Worker → Supervisor Messages:**
- `WorkerStarted` / `WorkerReady` - Lifecycle events
- `WorkerHeartbeat` - Periodic health + metrics
- `WorkerRequestLog` - Per-request logging
- `WorkerShutdownComplete` - Drain complete notification

**Supervisor → Worker Messages:**
- `DrainRequest` - Initiate graceful drain
- `DrainStatusRequest` - Poll drain status
- `StopAccepting` - Stop accepting new connections
- `MasterShutdown` - Immediate shutdown signal

## 6. Drain-Aware Shutdown

### 6.1 DrainManager Architecture

```rust
// src/supervisor/drain_manager.rs:20-25
pub struct DrainManager {
    workers: Arc<RwLock<HashMap<WorkerId, WorkerDrainState>>>,
    current_drain_id: Arc<AtomicU64>,
    drain_start_time: Arc<Mutex<Option<Instant>>>,
    poll_interval_ms: u64,
}
```

Thread-safe drain state tracking using:
- `parking_lot::RwLock` for worker state map
- `tokio::sync::Mutex` for drain start time
- Atomic counter for drain IDs

### 6.2 Drain Protocol Sequence

```rust
// src/supervisor/drain_manager.rs:297-369
pub async fn drain_worker_with_confirmation(
    &self,
    ipc: &mut IpcStream,
    worker_id: &WorkerId,
    drain_timeout_secs: u64,
    poll_interval_ms: u64,
) -> std::io::Result<bool>
```

Full protocol:
1. Send `DrainRequest` with unique drain_id
2. Send `StopAccepting` to stop new connections
3. Poll `DrainStatusRequest` in a loop:
   - On success: update connection counts
   - If `drain_complete`, mark worker done and return
   - On error: exponential backoff retry (max 3 retries)
4. Return `true` if drained within timeout, `false` otherwise

### 6.3 Shutdown Timeout

```rust
// src/supervisor/process.rs:20-21
const DRAIN_POLL_INTERVAL_MS: u64 = 100;
const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;
```

From supervisor:
```rust
let timeout_secs = self
    .process_manager
    .get_config()
    .graceful_shutdown_timeout_secs;
```

Workers have the same timeout to complete their drain.

### 6.4 Shared Memory Tables (Initialized on Startup)

```rust
// src/supervisor/process.rs:72-95
// Shared Connection Table for distributed load balancing
SharedConnectionTable::init_global(shm_path, max_workers, max_backends)

// Shared Rate Limit Table
SharedRateLimitTable::init_global(ratelimit_shm_path, IP_RATE_LIMIT_SLOTS)
```

## 7. gRPC Control API

### 7.1 Service Definition

```protobuf
// proto/control.proto
service ControlPlane {
  rpc GetStatus (StatusRequest) returns (StatusResponse);
  rpc ReloadConfig (ReloadRequest) returns (ReloadResponse);
  rpc Stop (StopRequest) returns (StopResponse);
  rpc BlockIp (BlockRequest) returns (BlockResponse);
  rpc UnblockIp (UnblockRequest) returns (UnblockResponse);
}
```

### 7.2 Status Endpoint

Returns comprehensive system status:

```rust
// src/supervisor/api.rs:33-65
async fn get_status(&self, _request: Request<StatusRequest>) 
    -> Result<Response<StatusResponse>, Status>
```

Response includes:
- **Supervisor PID**: Current process ID
- **Uptime**: Seconds since supervisor started
- **Version**: Cargo package version
- **Workers**: Per-worker info (id, pid, port, status, requests, blocked)
- **Stats**: Aggregate statistics (total requests, blocked/hour, etc.)

### 7.3 ReloadConfig Endpoint

Hot-reloads all configuration:

```rust
// src/supervisor/api.rs:67-79
async fn reload_config(&self, _request: Request<ReloadRequest>) 
    -> Result<Response<ReloadResponse>, Status>
```

Implementation:
```rust
let mut config = self.state.config.write().await;
config.reload_all();
```

### 7.4 Stop Endpoint

Initiates graceful shutdown:

```rust
// src/supervisor/api.rs:81-92
async fn stop(&self, request: Request<StopRequest>) 
    -> Result<Response<StopResponse>, Status>
```

Note: 100ms delay before sending shutdown signal to allow response to be sent.

### 7.5 BlockIp / UnblockIp Endpoints

Runtime IP blocking (integrates with BlockStore):

```rust
// src/supervisor/api.rs:94-126
async fn block_ip(&self, request: Request<BlockRequest>) 
async fn unblock_ip(&self, request: Request<UnblockRequest>)
```

Supports:
- IP address parsing with validation
- Reason and duration for blocks
- Scope specification for tenant isolation

### 7.6 Configuration

```toml
# config/main.toml
[supervisor]
control_api_addr = "127.0.0.1:50051"  # Default gRPC address
```

## 8. Feature Gates

### 8.1 Mesh Feature

```toml
# Cargo.toml:33
mesh = ["synvoid-config/mesh", "dep:openraft"]
```

**Feature-gated components:**
- `SupervisorState::threat_intel_manager`
- `SupervisorState::yara_rules`
- `SupervisorState::mesh_transport_manager`
- `SupervisorState::org_key_manager`
- `MeshControlPlane` in `mesh.rs`
- `run_mesh_agent_mode()` actual implementation

### 8.2 DNS Feature

```toml
# Cargo.toml:23
dns = ["synvoid-config/dns", "dep:hickory-proto", ...]
```

**Effect on Supervisor:**
- Enables DNS resolver integration in mesh transport initialization
- `MeshTransportManager::initialize_mesh_transports()` takes DNS-specific parameters

### 8.3 How Feature Gates Affect Compilation

| Feature | SupervisorState Fields | Mesh Agent | DNS Transport |
|---------|----------------------|------------|---------------|
| `mesh=off` | No mesh fields | Stub exits | No DNS support |
| `mesh=on` | Full mesh state | Full implementation | (depends on dns) |
| `dns=off` | - | - | Basic transport only |
| `dns=on` | - | - | DNS resolver + mesh DNS registry |

## 9. Relationship to Legacy Components

### 9.1 Overseer & Master (Consolidated)

The Overseer and Master modules have been consolidated into the Supervisor as of 2026. The `src/overseer/` and `src/master/` directories no longer exist.

**What was preserved:**
- `DrainManager` and `DrainProtocol` were ported from Overseer to Supervisor (`src/supervisor/drain_manager.rs`)
- `MasterCommand` message types are shared via the IPC module
- CLI commands are re-exported via `supervisor::commands`

### 9.2 Architectural Evolution

```
LEGACY (pre-consolidation):
┌──────────────────────────────────┐
│           Overseer               │  ← Health monitoring, upgrades
│  (Port 9001 admin API)          │
└──────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐
│           Master                 │  ← Process management, IPC
│  (Port 9002 command socket)     │
└──────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐
│           Workers               │
└──────────────────────────────────┘

NEW (supervisor consolidation):
┌──────────────────────────────────┐
│         Supervisor               │
│  - Health monitoring (from Overseer)
│  - Process management (from Master)
│  - gRPC control API             │
│  - IPC command socket           │
└──────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐
│        UnifiedServerWorkers     │
└──────────────────────────────────┘
```

## 10. Constants and Configuration

### 10.1 Supervisor Constants

| Constant | Value | Location |
|----------|-------|----------|
| `DRAIN_POLL_INTERVAL_MS` | 100 | `process.rs:20` |
| `DEFAULT_DRAIN_TIMEOUT_SECS` | 30 | `process.rs:21` |
| Default gRPC port | 50051 | `ProcessManagerConfig::default()` |

### 10.2 Runtime Directory

```rust
// src/supervisor/process.rs:368-379
let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
    .unwrap_or_else(|| PathBuf::from("/var/run"))
    .join("synvoid");
```

### 10.3 Tokio Runtime Configuration

```rust
// src/supervisor/process.rs:354-358
let rt = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(4)
    .enable_all()
    .build()
    .expect("Failed to build Tokio runtime");
```

Supervisor uses multi-threaded Tokio runtime with 4 worker threads (independent of worker pool size).

## 11. Error Handling

### 11.1 Supervisor Process Errors

| Error | Behavior |
|-------|----------|
| Config load failure | Log warning, use defaults |
| Block store init failure | Log warning, continue |
| Worker spawn failure | Log error, continue with fewer workers |
| gRPC server failure | Log error (doesn't stop supervisor) |
| IPC accept error | Log debug, sleep and retry |
| Drain timeout | Log warning, proceed with forced shutdown |

### 11.2 Panic Handling

```rust
// src/supervisor/process.rs:312-316
let supervisor_panic_log = format!(
    "{}/synvoid-supervisor-panic.log",
    std::env::temp_dir().display()
);
crate::common::setup_panic_handler("SUPERVISOR", Some(&supervisor_panic_log));
```

### 11.3 Process Manager Health Checks

```rust
// src/process/manager.rs
// Periodic checks every health_check_interval_secs (default 5s)
process_manager.check_workers_health().await;

// Zombie reaping
process_manager.reap_zombies().await;
```

## 12. IPC Socket Path Resolution

| Platform | Socket Type | Path |
|----------|-------------|------|
| Unix | Unix domain | `/var/run/synvoid/master.sock` (or `XDG_RUNTIME_DIR/synvoid/master.sock`) |
| Windows | Named pipe | `\\.\pipe\synvoid-master` |

See `src/process/socket_path.rs` for full resolution logic including versioned paths for upgrades.

## 13. Summary

The Supervisor module is the central orchestration component that:

1. **Manages process lifecycle** via `ProcessManager` and `DrainManager`
2. **Provides control API** via gRPC for runtime management
3. **Handles CLI commands** via IPC socket
4. **Coordinates graceful shutdown** with drain-aware worker termination
5. **Initializes shared tables** for connection and rate limit tracking
6. **Consolidates legacy Overseer/Master** into single binary

The design prioritizes:
- **Zero-downtime upgrades** via socket handoff and drain coordination
- **Scalability** via shared-memory communication and O(1) domain-based routing
- **Observability** via gRPC status endpoints and comprehensive logging
- **Security** via IPC signing and constant-time comparisons where appropriate
