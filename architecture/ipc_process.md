# IPC & Process Module Architecture

**Module Path:** `src/process/`

**Purpose:** Provides inter-process communication (IPC) infrastructure and process lifecycle management for the SynVoid multi-process arc
able
hitecture. This module handles all aspects of worker process spawning, IPC message passing, signed authentication, rate limiting, and process supervision.

---

## 1. Purpose and Responsibility

The IPC & Process module is responsible for:

1. **Process Lifecycle Management**: Spawning, supervising, health monitoring, and graceful shutdown of worker processes (base workers, unified server workers, and static workers)
2. **IPC Transport**: Reliable message passing between supervisor, master, and worker processes via Unix domain sockets (Unix) or named pipes (Windows)
3. **Message Framing**: Length-prefixed framing for serialized IPC messages with configurable maximum message size (1MB)
4. **Signed IPC**: Cryptographic authentication of IPC messages using HMAC-SHA3-256 with replay protection via nonce caching
5. **Rate Limiting**: Token bucket-based rate limiting for IPC connections to prevent DoS attacks
6. **Connection Pooling**: Connection pooling for IPC endpoints to reduce connection overhead
7. **Socket FD Passing**: Unix-specific file descriptor passing for socket handoff during upgrades
8. **PID/Lock Management**: PID file management and overseer lock file handling for single-instance enforcement

---

## 2. Key Submodules and Their Responsibilities

| Submodule | File | Responsibility |
|-----------|------|----------------|
| **mod.rs** | `src/process/mod.rs` | Module root; re-exports all public types; defines `CURRENT_WORKER_ID` global |
| **manager.rs** | `src/process/manager.rs` | `ProcessManager` for worker lifecycle, health monitoring, restart policies |
| **ipc.rs** | `src/process/ipc.rs` | `Message` enum (all IPC message types), `IpcStream` (sync), `WorkerId` |
| **ipc_transport.rs** | `src/process/ipc_transport.rs` | Async IPC transport via `tokio::net::UnixStream` |
| **ipc_framing.rs** | `src/process/ipc_framing.rs` | Length-prefixed message framing for sync/async I/O |
| **ipc_signed.rs** | `src/process/ipc_signed.rs` | HMAC-SHA3-256 signed messages, nonce cache for replay protection |
| **ipc_rate_limit.rs** | `src/process/ipc_rate_limit.rs` | Token bucket rate limiter with per-worker tracking |
| **ipc_pool.rs** | `src/process/ipc_pool.rs` | Connection pooling for IPC endpoints |
| **ipc_windows.rs** | `src/process/ipc_windows.rs` | Windows named pipe utilities |
| **worker.rs** | `src/process/worker.rs` | `BaseWorkerProcess`, `WorkerProcess`, `StaticWorkerProcess`, `UnifiedServerWorkerProcess` |
| **command.rs** | `src/process/command.rs` | `CommandClient` for sending commands to master via socket/signal/grpc |
| **socket_path.rs** | `src/process/socket_path.rs` | Socket path resolution, generation tracking, permissions |
| **socket_fd.rs** | `src/process/socket_fd.rs` | Unix socket creation and file descriptor passing |
| **pidfile.rs** | `src/process/pidfile.rs` | `PidFileManager`, `SupervisorLockFile` for process single-instance |

---

## 3. Major Data Structures and Types

### 3.1 Process Manager Types

**ProcessManagerConfig** (`manager.rs:38-59`):
- `min_workers: usize` - Minimum worker count
- `max_workers: usize` - Maximum worker count
- `unified_server_workers: usize` - Unified server worker count
- `max_restart_attempts: u32` - Max restart attempts before giving up
- `restart_cooldown_secs: u64` - Base cooldown between restarts
- `restart_backoff_max_secs: u64` - Maximum restart backoff
- `heartbeat_timeout_secs: u64` - Worker heartbeat timeout
- `graceful_shutdown_timeout_secs: u64` - Graceful shutdown timeout
- `worker_port_base: u16` - Base port for worker assignment
- `config_path: PathBuf` - Config file path
- `master_socket_path: PathBuf` - Master IPC socket path
- `ipc_session_key: Option<[u8; 32]>` - HMAC session key
- `ipc_enforce_signing: bool` - Require signed IPC
- `ipc_rate_limit: IpcRateLimitConfig` - Rate limit config

**ProcessEvent** (`manager.rs:114-127`):
- WorkerStarted, WorkerReady, WorkerStopped, WorkerFailed, WorkerRestarted
- UnifiedServerWorkerStarted, UnifiedServerWorkerReady, UnifiedServerWorkerStopped, UnifiedServerWorkerFailed
- ShutdownInitiated, ShutdownComplete

### 3.2 IPC Message Types

**WorkerId** (`ipc.rs:150-157`): Unique worker identifier wrapping `usize`

The `Message` enum (`ipc.rs:299-802`) contains **60+ variants** organized into 17 categories:

| Category | Message Variants |
|----------|-----------------|
| **WorkerLifecycle** | WorkerStarted, WorkerReady, WorkerHeartbeat, WorkerRequestLog, WorkerShutdownComplete, WorkerError, WorkerCertReload |
| **MasterCommand** | MasterShutdown, MasterConfigReload, MasterProcessConfigReload, MasterSupervisorConfigReload, MasterHealthCheck, MasterResizeThreadpool, MasterCertReload, HealthCheckAck, WorkerResizeAck, CommandResponse |
| **StaticWorker** | StaticWorkerStarted, StaticWorkerReady, StaticWorkerHeartbeat, StaticWorkerRequestLog, StaticWorkerShutdownComplete, StaticWorkerBackgroundTasksDone, StaticWorkerResizeAck, StaticWorkerScan, StaticWorkerCacheUpdate, StaticWorkerDrain, StaticWorkerDrained, StaticWorkerDrainStatus |
| **AppServer** | AppServerStarted, AppServerReady, AppServerHealth, AppServerStopped, AppServerRestarted, AppServerError |
| **UnifiedServer** | UnifiedServerWorkerStarted, UnifiedServerWorkerReady, UnifiedServerWorkerHeartbeat, UnifiedServerWorkerShutdownComplete, UnifiedServerWorkerError, UnifiedServerWorkerDrain, UnifiedServerWorkerDrained, UnifiedServerWorkerResize, UnifiedServerWorkerResizeAck |
| **WorkerDrain** | WorkerDrain, WorkerDrained, WorkerConnectionCount, WorkerDrainComplete, WorkerReadyForTraffic |
| **Upgrade** | UpgradeReady, UpgradeFailed, SupervisorUpgradePrepare, SupervisorUpgradePrepareAck, SupervisorUpgradeCommit, SupervisorUpgradeCommitAck, SupervisorUpgradeRollback, SupervisorUpgradeRollbackAck, SupervisorCommitUpgrade, SupervisorCommitUpgradeAck |
| **Supervisor** | SupervisorDrainWorkers, SupervisorDrainWorkersAck, SupervisorGetStatus, SupervisorStatusResponse, SupervisorDualSupervisorPrepare, SupervisorDualSupervisorPrepareAck |
| **MasterDrain** | MasterDrainMode, MasterDrainModeAck, MasterReportConnections, MasterConnectionsReport, MasterStopAccepting, MasterStopAcceptingAck, MasterDrainStatus |
| **DrainProtocol** | DrainRequest, DrainStatusRequest, DrainStatusResponse, DrainComplete, StopAccepting, StopAcceptingAck, RestoreFromDrain, RestoreFromDrainAck |
| **SocketHandoff** | SocketHandoffRequest, SocketHandoffReady, SocketHandoffComplete, SocketHandoffFailed, SocketHandoffActiveConnection, WorkerConnectionHandoff, WorkerConnectionAdopted, WindowsSocketInfo |
| **ThreatIntel** | ThreatIndicatorAnnounce, ThreatIndicatorFromMesh, ThreatSyncRequest, ThreatSyncResponse, ThreatFeedUpdate, BlocklistRequest, BlocklistResponse |
| **BlocklistRules** | BlocklistUpdate, RulePatternsUpdate, BlocklistWriteComplete |
| **StaticContent** | MinifyRequest, MinifyResponse, MinifyError, PoisonImageRequest, PoisonImageResponse, PoisonImageError, GetCompressedRequest, GetCompressedResponse |
| **Plugin** | PluginStateSync, PluginExecuteRequest, PluginExecuteResponse, ServerlessHandleRequest, ServerlessHandleResponse |
| **MeshControl** | MeshControlRequest, MeshControlResponse, MeshUpdateNotification |
| **WorkerRestart** | RestartWorkerRequest, RestartWorkerResponse |
| **Upstream** | UpstreamGlobalStats, GlobalUpstreamStatsBroadcast |

### 3.3 Signed IPC Types

**Constant sizes** (`ipc_signed.rs:49-53`):
```
HMAC_SIZE: 32 bytes
TIMESTAMP_SIZE: 8 bytes
NONCE_SIZE: 16 bytes
SIGNED_MESSAGE_OVERHEAD: 60 bytes (4 + 8 + 16 + 32)
MAX_IPC_MESSAGE_SIZE: 1,048,576 bytes (1MB)
```

**IpcSigner** (`ipc_signed.rs:114-117`):
- `signer_id: u64` - Derived from first 8 bytes of key
- `key: [u8; 32]` - HMAC-SHA3-256 key

**IpcEnvelope** (`ipc_signed.rs:408-415`):
- `timestamp: u64` - Unix timestamp
- `nonce: [u8; 16]` - Random nonce
- `hmac: [u8; 32]` - HMAC-SHA3-256
- `data: Vec<u8>` - Serialized message

### 3.4 Rate Limiting Types

**IpcRateLimiter** (`ipc_rate_limit.rs:5-18`):
- Global token bucket for all IPC messages
- Per-worker HashMap with window tracking
- Automatic stale entry cleanup every 60 seconds

Default configuration:
- `max_messages_per_second`: 1000
- `max_burst`: 2000

### 3.5 Worker Process Types

**BaseWorkerProcess** (`worker.rs:47-54`):
- pid, status, child, started_at, last_heartbeat

**WorkerProcess** (`worker.rs:93-101`):
- id: WorkerId, base: BaseWorkerProcess, port, metrics, restart_count, last_restart_at

**StaticWorkerProcess** (`worker.rs:158-162`):
- worker_id, base: BaseWorkerProcess, ipc: Option<Arc<Mutex<IpcStream>>>

**UnifiedServerWorkerProcess** (`worker.rs:185-192`):
- id: WorkerId, base: BaseWorkerProcess, metrics, restart_count, last_restart_at, ipc

---

## 4. Key APIs and Entry Points

### 4.1 ProcessManager (`manager.rs:145-208`)

```rust
pub fn new(config: ProcessManagerConfig, block_store: Option<Arc<BlockStore>>) -> (Self, mpsc::Receiver<ProcessEvent>)
pub fn spawn_worker(&self) -> std::io::Result<WorkerId>
pub fn spawn_static_worker(&self) -> std::io::Result<usize>
pub fn spawn_unified_server_workers(&self, count: usize) -> std::io::Result<Vec<WorkerId>>
pub fn spawn_unified_server_worker(&self) -> std::io::Result<WorkerId>
pub fn spawn_upgrade_worker(&self, binary_path: Option<&PathBuf>, port: u16, upgrade_mode: bool, reuse_port: bool) -> std::io::Result<WorkerId>

pub async fn shutdown_workers(&self)
pub async fn graceful_shutdown(&self)
pub async fn drain_unified_server_worker_async(&self, worker_id: WorkerId, timeout_secs: u64) -> Result<u64, String>
pub async fn drain_static_worker_async(&self, timeout_secs: u64) -> Result<u64, String>

pub fn handle_heartbeat(&self, worker_id: WorkerId, metrics: WorkerMetricsPayload)
pub fn handle_worker_ready(&self, worker_id: WorkerId)
pub fn handle_worker_error(&self, worker_id: WorkerId, error: String, severity: ErrorSeverity, error_code: ErrorCode)

pub async fn broadcast_config_reload(&self, config_path: PathBuf)
pub async fn broadcast_threat_feed_update(&self, indicators: Vec<ThreatIndicatorData>, version: u64)
pub async fn broadcast_rule_patterns_update(&self, version: String, patterns: Vec<RulePatternData>)

pub async fn check_workers_health(&self)
pub async fn reap_zombies(&self)

pub fn get_status(&self) -> MasterStatus
pub fn get_config(&self) -> ProcessManagerConfig
pub fn update_config(&self, new_config: ProcessManagerConfig) -> Result<bool, String>

pub fn get_ipc_rate_limiter(&self) -> &IpcRateLimiter
pub fn get_ipc_session_key(&self) -> Option<[u8; 32]>
pub fn get_ipc_enforce_signing(&self) -> bool

pub fn resize_unified_server_worker_threadpool(&self, worker_threads: u32) -> Result<(), String>
pub fn resize_threadpool(&self, worker_threads: u32)
pub fn reload_config(&self)
```

### 4.2 IpcSigner (`ipc_signed.rs:119-246`)

```rust
pub fn new(key: &[u8; 32]) -> Self
pub fn signer_id(&self) -> u64
pub fn try_from_env() -> Option<Self>  // Reads SYNVOID_IPC_KEY_FILE or SYNVOID_IPC_KEY
pub fn sign(&self, data: &[u8]) -> [u8; 32]
pub fn verify(&self, data: &[u8], expected_hmac: &[u8; 32]) -> bool
pub fn sign_parts(&self, parts: &[&[u8]]) -> [u8; 32]
pub fn verify_parts(&self, parts: &[&[u8]], expected_hmac: &[u8; 32]) -> bool

pub fn generate_session_key() -> [u8; 32]  // Uses OsRng
pub fn read_ipc_key_file(key_file: &str) -> Option<Arc<IpcSigner>>
```

### 4.3 SignedIpcMessage (`ipc_signed.rs:424-534`)

```rust
pub fn serialize_signed<T: Serialize>(msg: &T, signer: &IpcSigner) -> io::Result<Vec<u8>>
pub fn deserialize_signed<T: DeserializeOwned>(data: &[u8], signer: &IpcSigner) -> io::Result<T>
pub fn deserialize_signed_from_stream<R: Read>(stream: &mut R, signer: &IpcSigner) -> io::Result<Option<Message>>
```

### 4.4 IpcRateLimiter (`ipc_rate_limit.rs:25-112`)

```rust
pub fn new(max_messages_per_second: u64, max_burst: u64) -> Self
pub fn check(&self) -> Result<(), RateLimitExceeded>           // Global check
pub fn check_worker(&self, worker_id: u64) -> Result<(), RateLimitExceeded>  // Per-worker check
pub fn reset_worker(&self, worker_id: u64)
```

### 4.5 IpcConnectionPool (`ipc_pool.rs:32-116`)

```rust
pub fn new(max_connections_per_endpoint: usize, connection_ttl_secs: u64) -> Self
pub async fn try_acquire(&self, endpoint_name: &str) -> Result<ConnectionPermit, PoolError>
pub async fn release(&self, endpoint_name: &str)
pub async fn record_failure(&self, endpoint_name: &str)
pub async fn get_stats(&self, endpoint_name: &str) -> Option<ConnectionPoolStats>
```

### 4.6 CommandClient (`command.rs:20-66`)

```rust
pub fn new(socket_path: Option<PathBuf>, grpc_addr: Option<String>) -> Self
pub fn send_command(&self, command: MasterCommand) -> Result<String, CommandError>
pub fn get_status(&self) -> Result<MasterStatus, CommandError>
pub fn method(&self) -> CommandMethod
```

### 4.7 IpcStream Sync (`ipc.rs:1847-1972`)

```rust
pub fn send(&mut self, msg: &Message) -> io::Result<()>
pub fn send_signed(&mut self, msg: &Message) -> io::Result<()>
pub fn try_recv(&mut self) -> io::Result<Option<Message>>
pub fn try_recv_signed(&mut self) -> io::Result<Option<Message>>
pub fn recv(&mut self, timeout_ms: u64) -> io::Result<Option<Message>>
```

### 4.8 IpcStream Async (`ipc_transport.rs:381-482`)

```rust
pub async fn send<T: Serialize>(&mut self, msg: &T) -> io::Result<()>
pub async fn recv<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>>
pub async fn recv_with_timeout<T: DeserializeOwned>(&mut self, timeout_ms: u64) -> io::Result<Option<T>>
pub fn is_signed(&self) -> bool
pub fn peer_pid(&self) -> Option<u32>
```

---

## 5. IPC Protocol and Message Types

### 5.1 Transport Layer

| Platform | Transport | Implementation |
|----------|-----------|----------------|
| Unix | Unix Domain Socket | `tokio::net::UnixStream` / `std::os::unix::net::UnixStream` |
| Windows | Named Pipe | `tokio::net::windows::named_pipe` / `windows_sys` |

### 5.2 Framing Protocol

**Format**: 4-byte big-endian length prefix + serialized message

```
+------------+--------------------------------+
|  Length    |  Serialized Message Data       |
|  (4 bytes) |  (variable, max 1MB)          |
+------------+--------------------------------+
```

- MAX_MESSAGE_SIZE: 1,048,576 bytes (1MB)
- DEFAULT_BUFFER_SIZE: 65,536 bytes (64KB)

### 5.3 Signed Message Format

When signing is enabled, messages are wrapped with:

```
+------------+----------+---------+------------+--------------------------------+
|  Total     | Timestamp| Nonce   | HMAC-SHA3  | Message Data                   |
|  Length    | (8 bytes)|(16 bytes)| (32 bytes) | (variable)                     |
+------------+----------+---------+------------+--------------------------------+
```

- TIMESTAMP_SIZE: 8 bytes (Unix timestamp)
- NONCE_SIZE: 16 bytes (random, OsRng)
- HMAC_SIZE: 32 bytes (HMAC-SHA3-256 of timestamp + nonce + data)
- Total overhead: 60 bytes per message

### 5.4 Message Validation

Message validation enforces:
- MAX_STRING_LENGTH: 64KB per string field
- MAX_PATH_LENGTH: 4KB per path field
- Path traversal detection (rejecting ".." in path fields)

---

## 6. Signed IPC for Authentication

### 6.1 Key Exchange Security

1. **Master generates session key** via `generate_session_key()` (OsRng)
2. **Key passed to workers via temp file** (avoids `/proc/<pid>/environ` exposure)
   - File path: `$TMPDIR/synvoid_ipc_key_<pid>`
   - Permissions: `0o600` (owner read/write only)
   - `O_NOFOLLOW` flag prevents symlink attacks
   - File deleted after worker reads key
3. **Fallback with warning**: If temp file creation fails and `allow_insecure_ipc_key=true`, key is passed via `SYNVOID_IPC_KEY` environment variable

### 6.2 Message Authentication

HMAC-SHA3-256 with constant-time comparison via `subtle::ConstantTimeEq`.

### 6.3 Replay Protection

The nonce cache (`DashMap<(u64, [u8; 16]), u64>`) prevents replay attacks:
- Key: `(signer_id, nonce)` tuple
- Value: Unix timestamp when nonce was first seen
- Cleanup: Entries older than 60 seconds are purged
- Max cache size: 10,000 entries (oldest evicted on overflow)

### 6.4 Timestamp Validation

Messages must be within 60 seconds of current time (`REPLAY_WINDOW_SECS`).

### 6.5 Signing Enforcement

`ProcessManagerConfig` contains:
- `ipc_session_key: Option<[u8; 32]>` - The shared HMAC key
- `ipc_enforce_signing: bool` - If true, unsigned messages are rejected

---

## 7. Rate Limiting

### 7.1 Global Rate Limiting

Token bucket algorithm with:
- `max_tokens`: initialized to `max_burst`
- `refill_rate`: `max_messages_per_second` tokens per second
- Fractional refill support (milliseconds precision)

### 7.2 Per-Worker Rate Limiting

Each worker has its own tracking window:
- Window duration: 1 second
- Max tracked workers: 10,000
- Entries older than 3 windows are cleaned up

### 7.3 Configuration

```rust
pub struct IpcRateLimitConfig {
    pub max_messages_per_second: u64,  // 1000 default
    pub max_burst: u64,                // 2000 default
}
```

---

## 8. Feature Gates

The process module has **no feature gates** - all functionality is always available. Platform-specific code is conditionally compiled via `#[cfg(unix)]` and `#[cfg(windows)]`.

---

## 9. Key Security Patterns

### 9.1 Constant-Time Comparison
HMAC verification uses `subtle::ConstantTimeEq` to prevent timing side-channel attacks.

### 9.2 Temp File Security
IPC keys written to temp files use:
- `create_new(true)` to prevent symlink attacks
- `O_NOFOLLOW` flag on Unix
- `0o600` permissions
- Immediate deletion after reading

### 9.3 Socket Permissions
Unix sockets use `0o700` permissions (owner-only).

### 9.4 Path Traversal Prevention
Message validation rejects `..` in all path fields.

### 9.5 Oversized Message Rejection
Framing layer checks against MAX_MESSAGE_SIZE (1MB) and increments `OVERSIZED_REJECTED` counter on violation.

---

## 10. Process Hierarchy

```
Supervisor (run_supervisor_mode)
  └── Master (run_master_mode)
        ├── BaseWorkerProcess (--worker) [legacy, unused for HTTP]
        ├── UnifiedServerWorkerProcess (--unified-server-worker) [primary HTTP worker]
        ├── StaticWorkerProcess (--static-worker) [CSS/JS minification, compression]
        └── AppServerProcess (Granian, per-site) [Spin WASM runtime]
```

The **UnifiedServerWorker** is the primary worker, handling HTTP/HTTPS/HTTP3 + WAF + proxy in a single Tokio event loop. The **StaticWorker** handles asset minification. Both communicate with Master via signed IPC.

---

## 11. Key Entry Points for IPC

| Function | File | Purpose |
|----------|------|---------|
| `start_health_monitor()` | `manager.rs:2067` | Background task for health checking |
| `connect_to_master_signed()` | `ipc_transport.rs:548` | Connect to master with signing |
| `connect_to_static_worker_signed()` | `ipc_transport.rs:555` | Connect to static worker |
| `connect_to_commands_signed()` | `ipc_transport.rs:566` | Connect to command endpoint |
| `read_ipc_key_file()` | `ipc_signed.rs:598` | Load signer from key file |
| `IpcSigner::try_from_env()` | `ipc_signed.rs:149` | Load signer from environment |

---

## 12. Important Constants

```rust
// ipc_signed.rs
HMAC_SIZE = 32
TIMESTAMP_SIZE = 8
NONCE_SIZE = 16
SIGNED_MESSAGE_OVERHEAD = 60
MAX_IPC_MESSAGE_SIZE = 1,048,576 (1MB)
MAX_STRING_LENGTH = 65,536 (64KB)
MAX_PATH_LENGTH = 4,096 (4KB)

// ipc_rate_limit.rs
MAX_NONCE_CACHE_SIZE = 10,000
REPLAY_WINDOW_SECS = 60
MAX_WORKERS_TRACKED = 10,000

// ipc_framing.rs
DEFAULT_BUFFER_SIZE = 65,536 (64KB)
```
