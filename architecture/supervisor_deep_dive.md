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
// src/supervisor/process.rs:276-330 (pseudocode)
let mut shutdown_cause = SupervisorShutdownCause::Requested;
loop {
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            // Periodic tick: reap zombies + check worker health.
            // A plain sleep, not an interval handle.
        }
        event = self.event_rx.recv() => {           // ProcessManager event channel
            // Worker lifecycle events; None => ProcessManagerFailed
        }
        res = self.supervisor_tasks.join_one_finished() => {
            // Registered task finished; a Failed outcome sets TaskFailed
        }
        _ = shutdown_rx.recv() => {
            shutdown_cause = SupervisorShutdownCause::Requested;
            break;
        }
    }
}
```

### Task Registry

| Task Class | Policy | Examples |
|------------|--------|----------|
| `CriticalControlPlane` | Fatal if exits | `supervisor_grpc_control_api`, `supervisor_ipc_accept` |
| `RestartableControlPlane` | Fatal if exits (**not** auto-restarted) | *none — declared but unused* |
| `BestEffortMaintenance` | Drained during shutdown | `supervisor_eggbench_telemetry_exporter`, `supervisor_eggbench_telemetry_bridge` |
| `ShutdownOnly` | Only joined during shutdown | *none — declared but unused* |

There is **no** health-monitor or log-rotation supervisor task, and no automatic
task restart: a `TaskOutcome::Failed` breaks the main loop and escalates to
`SupervisorShutdownCause::TaskFailed`.

Critical task failures trigger `SupervisorShutdownCause::TaskFailed`.

## Worker Lifecycle

### Spawning

```
Supervisor
    │
    ├── spawn_unified_server_workers(count)
    │   ├── Fork + exec worker process
    │   ├── Pass: worker_id, config_path, supervisor_socket
    │   ├── Pass: IPC session key via a 0600 temp file
    │   │   (SYNVOID_IPC_KEY_FILE points at it; SYNVOID_IPC_KEY env is
    │   │    only a warned fallback when allow_insecure_ipc_key is set)
    │   └── Pass: --worker-id, --worker-threads, --total-workers,
    │       optional --cpu-affinity, internal --reuse-port
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
    // Actual signature (drain_manager.rs)
    pub async fn drain_worker_with_confirmation(
        &self,
        ipc: &mut IpcStream,
        worker_id: WorkerId,
        drain_timeout_secs: u64,
        poll_interval_ms: u64,
    ) -> std::io::Result<bool> {   // Ok(true) = drained within budget
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
async fn handle_drain_request(&self, timeout_secs: u64, drain_id: u64) {
    // 1. Store drain ID (reject duplicates)
    self.drain_state.set_drain_id(drain_id);
    
    // 2. Stop accepting new connections
    self.drain_state.stop_accepting();
    
    // 3. Wait for active connections to drain
    let drained = self.drain_state.wait_for_drain(timeout_secs).await;
    
    // 4. Reply on the status poll
    //    (drain_id is a u64 counter, not a Uuid)
    
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
// src/supervisor/api.rs — every RPC takes a tonic Request wrapper and
// returns Result<Response<T>, Status>. Field-level values below are
// abbreviated; the signatures and the block_ip call are exact.
impl ControlPlane for ControlPlaneService {
    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Ok(Response::new(StatusResponse { /* pid, uptime, version,
            workers, stats, threat_summary from block_store + state */ }))
    }

    async fn block_ip(
        &self,
        request: Request<BlockRequest>,
    ) -> Result<Response<BlockResponse>, Status> {
        let req = request.into_inner();
        let ip = req.ip.parse::<std::net::IpAddr>()?;
        self.state.block_store.block_ip_with_provenance(
            &ip,
            &req.reason,
            req.duration_secs,
            &req.scope,
            BlockProvenance {
                kind: BlockProvenanceKind::SupervisorManual,
                source: Some("grpc_block_ip".to_string()),
            },
        );

        // No mesh broadcast is issued here; the handler logs
        // "Block list change queued for mesh propagation" and returns.
        Ok(Response::new(BlockResponse { success: true }))
    }
}
```

### mTLS Support

- Optional internal TLS for gRPC connections
- Self-signed certificates for intra-cluster communication
- Configured via `InternalTlsConfig`

## Shutdown Sequence

The supervisor's own shutdown has **four** phases (`src/supervisor/process.rs:275`,
`:363`). It does not perform the connection drain, mesh teardown, or app-server
shutdown itself — those are worker-side and driven over IPC.

```
1. Join registered supervisor tasks:  supervisor_tasks.shutdown_and_join(10s)
2. Per worker: send DrainRequest(timeout), then StopAccepting, then poll
   DrainStatusResponse until drained or the timeout (bounded exponential poll
   backoff, 3 retries max)
3. manager.wait_for_drain() -> drain_complete
4. graceful_shutdown() + reap_zombies(), then log the SupervisorDrainReport
```

> The 13-step list ("begin_coordinated_shutdown", "Stop Granian supervisors",
> "Persist bandwidth data", 5s/3s registry timeouts, …) is the **worker**
> shutdown procedure in `src/worker/unified_server/shutdown_executor.rs`, not
> the supervisor's. See `architecture/worker_task_lifecycle.md`.

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
