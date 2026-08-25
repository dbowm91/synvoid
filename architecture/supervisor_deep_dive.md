# Supervisor Deep Dive

The Supervisor is the single control-plane process that orchestrates all worker lifecycle, manages configuration, and exposes the gRPC management API.

## Architecture

### Core Struct

```rust
pub struct SupervisorProcess {
    state: SupervisorState,
    process_manager: Arc<ProcessManager>,
    drain_manager: Arc<DrainManager>,
    drain_protocol: Arc<DrainProtocol>,
    event_rx: mpsc::Receiver<ProcessEvent>,
    running: RunningFlag,
    ipc_listener: Option<IpcListener>,
    supervisor_tasks: SupervisorTaskRegistry,
}
```

### Main Event Loop

```rust
loop {
    tokio::select! {
        _ = heartbeat.tick() => {
            // Reap zombies, check worker health, poll tasks
        }
        event = process_manager.recv() => {
            // Handle worker lifecycle events
        }
        _ = shutdown_rx.recv() => {
            // Initiate coordinated shutdown
        }
    }
}
```

### Task Registry

| Task Class | Policy | Examples |
|------------|--------|----------|
| `CriticalControlPlane` | Fatal if exits | gRPC API, IPC accept loop |
| `RestartableControlPlane` | Logged, optionally restarted | Health monitor |
| `BestEffortMaintenance` | Drained during shutdown | Metrics flush |
| `ShutdownOnly` | Only joined during shutdown | Log rotation |

Critical task failures trigger `SupervisorShutdownCause::TaskFailed`.

## Worker Lifecycle

### Spawning

```
Supervisor
    │
    ├── spawn_unified_server_workers(count)
    │   ├── Fork + exec worker process
    │   ├── Pass: worker_id, config_path, supervisor_socket
    │   ├── Pass: IPC session key (env var)
    │   └── Optional: CPU affinity, reuse-port
    │
    └── spawn_cpu_worker()
        ├── Fork + exec CPU worker process
        └── Pass: worker_id, config_path, cpu_worker_socket
```

### State Tracking

```rust
pub struct ProcessManager {
    config: ProcessManagerConfig,
    workers: Arc<PLRwLock<HashMap<usize, WorkerProcess>>>,
    cpu_worker: Arc<PLRwLock<Option<CpuWorkerProcess>>>,
    unified_server_workers: Arc<PLRwLock<HashMap<usize, UnifiedServerWorkerProcess>>>,
    next_worker_id: Arc<PLRwLock<usize>>,
    running: Arc<AtomicBool>,
    shutdown_tx: broadcast::Sender<()>,
    event_tx: mpsc::Sender<ProcessEvent>,
    // ... metrics, rate limiter, signer, blocklist event log
}
```

## Drain Protocol (Zero-Downtime Upgrades)

### Supervisor Side

```rust
impl DrainProtocol {
    pub async fn drain_worker_with_confirmation(
        &self,
        worker_id: WorkerId,
        timeout_secs: u64,
    ) -> Result<DrainReport> {
        // 1. Send DrainRequest
        self.send_drain_request(worker_id, timeout_secs).await?;
        
        // 2. Send StopAccepting
        self.send_stop_accepting(worker_id).await?;
        
        // 3. Poll DrainStatus until complete or timeout
        loop {
            let status = self.poll_drain_status(worker_id).await?;
            if status.is_drained || elapsed > timeout {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        
        // 4. Return report
        Ok(DrainReport { remaining_connections, drain_time })
    }
}
```

### Worker Side

```rust
// On receiving DrainRequest
async fn handle_drain_request(&self, timeout_secs: u64, drain_id: Uuid) {
    // 1. Store drain ID (reject duplicates)
    self.drain_state.set_drain_id(drain_id);
    
    // 2. Stop accepting new connections
    self.drain_state.stop_accepting();
    
    // 3. Wait for active connections to drain
    let drained = self.drain_state.wait_for_drain(timeout_secs).await;
    
    // 4. Stop Granian supervisors
    self.stop_granian_supervisors().await;
    
    // 5. Send ack
    self.send_drained(drained).await;
}
```

### Drain State

```rust
pub struct WorkerDrainState {
    draining: DrainFlag,
    drain_id: Arc<AtomicU64>,
    active_connections: Arc<AtomicU64>,
    idle_connections: Arc<AtomicU64>,
    connections_drained: Arc<AtomicU64>,
    drain_start: Arc<Mutex<Option<Instant>>>,
    stopped_accepting: DrainFlag,
    short_requests: Arc<AtomicU64>,
    long_requests: Arc<AtomicU64>,
    streaming_requests: Arc<AtomicU64>,
    active_fds: Arc<DashMap<u64, (RawFd, RequestType, String)>>,
}
```

## gRPC Control Plane API

```protobuf
service ControlPlane {
    rpc GetStatus(StatusRequest) returns (StatusResponse);
    rpc ReloadConfig(ReloadRequest) returns (ReloadResponse);
    rpc Stop(StopRequest) returns (StopResponse);
    rpc BlockIp(BlockRequest) returns (BlockResponse);
    rpc UnblockIp(UnblockRequest) returns (UnblockResponse);
}
```

### Implementation

```rust
impl ControlPlane for ControlPlaneService {
    async fn get_status(&self) -> StatusResponse {
        StatusResponse {
            pid: std::process::id(),
            uptime: self.start_time.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION"),
            workers: self.process_manager.worker_status(),
            request_stats: self.state.request_stats(),
        }
    }
    
    async fn block_ip(&self, req: BlockRequest) -> BlockResponse {
        self.state.block_store.block_ip_with_provenance(
            req.ip,
            req.reason,
            BlockProvenanceKind::SupervisorManual,
        );
        
        // Propagate to workers via IPC
        self.process_manager.broadcast_blocklist_update();
        
        BlockResponse {
            result: AdminMutationResult::success("IP blocked"),
        }
    }
}
```

### mTLS Support

- Optional internal TLS for gRPC connections
- Self-signed certificates for intra-cluster communication
- Configured via `InternalTlsConfig`

## Shutdown Sequence

```
1. begin_coordinated_shutdown()
2. Stop accepting new connections
3. Graceful drain (if requested)
4. Stop Granian supervisors
5. Shutdown mesh transport
6. Stop mesh support bundle
7. Clear running flag
8. Broadcast registry cancellation
9. Persist bandwidth data
10. Await registry tasks (5s critical, 3s background)
11. Abort remaining handles
12. Send supervisor ack
13. Derive exit code
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `SupervisorProcess` | `src/supervisor/process.rs` | Main supervisor struct |
| `SupervisorState` | `src/supervisor/state.rs` | Shared state (config, block store, mesh) |
| `SupervisorStateTrackers` | `src/supervisor/state.rs` | Tracker bundles for state initialization |
| `ProcessManager` | `synvoid-ipc/src/manager.rs` | Worker process management |
| `DrainManager` | `src/supervisor/drain_manager.rs` | Per-worker drain state |
| `DrainProtocol` | `src/supervisor/drain_manager.rs` | IPC drain handshake |
| `SupervisorTaskRegistry` | `src/supervisor/task_registry.rs` | Long-lived task management |
| `ControlPlaneService` | `src/supervisor/api.rs` | gRPC API implementation |
| `SupervisorShutdownCause` | `src/supervisor/shutdown.rs` | Shutdown reason taxonomy |
