# Worker Deep Dive

Workers handle the data plane — HTTP request processing, WAF evaluation, proxy forwarding, and backend dispatch. The primary worker is `UnifiedServerWorker` running in a single Tokio event loop per process.

## UnifiedServerWorker Architecture

### Startup Plan (15 Phases)

| Phase | Description | Key Operations |
|-------|-------------|----------------|
| 0 | Worker identity | Set process-level worker ID |
| 1 | Runtime init | CPU affinity, logging, IPC connection, config load |
| 2 | Pre-bind port check | Validate port availability |
| 3 | TLS passthrough | Validate TLS configuration |
| 4 | Bandwidth config | Load bandwidth limits |
| 5 | Serverless + UnifiedServer | Construct server instances |
| 6 | ACME + Granian | Start TLS certificate management, app servers |
| 7 | WAF background | Initialize WAF tasks, upload validator, honeypot |
| 8 | Mesh + threat intel | Initialize mesh networking (feature-gated) |
| 8.5-8.7 | Mesh validation | Validate mesh configuration |
| 9 | Cross-wire services | Build DataPlaneServices |
| 10 | Initial blocklist | Request blocklist from supervisor |
| 11 | Build services + ready | Finalize DataPlaneServices |
| 11.5 | Mesh support tasks | Extract mesh support tasks, then send the ready message |
| 12 | Subscribe exit | Subscribe to exit notifications **before** any spawn |
| 13 | Spawn tasks | Heartbeat, bandwidth persist, IPC loop |
| 14 | Register server | Register HTTP server task |
| 14.5 | Mesh supervision | Mesh supervision pipeline |

### Core State

```rust
pub struct UnifiedServerWorkerState {
    pub worker_id: WorkerId,
    pub metrics: Arc<WorkerMetrics>,
    pub start_time: Instant,
    pub ipc: Arc<TokioMutex<AsyncIpcStream>>,
    pub running: RunningFlag,
    pub master_dead: RunningFlag,
    pub app_servers: Arc<RwLock<HashMap<String, Arc<GranianSupervisor>>>>,
    pub draining: DrainFlag,
    pub drain_id: Arc<AtomicU64>,
    pub stopped_accepting: DrainFlag,
    pub drain_state: Arc<WorkerDrainState>,
    pub stop_accepting_tx: Arc<TokioMutex<Option<broadcast::Sender<()>>>>,
    pub unified_server: Arc<UnifiedServer>,
    pub task_handles: Arc<TokioMutex<Vec<JoinHandle<()>>>>,
    pub request_services: Arc<RequestServices>,
    pub data_plane: Arc<DataPlaneServices>,
    // Mesh fields (feature-gated)
    pub canonical_snapshot: Arc<RwLock<Option<CanonicalTrustSnapshot>>>,
    pub mesh_status: Arc<RwLock<WorkerMeshStatus>>,
    pub mesh_policy: Option<MeshSupervisionPolicy>,
    pub task_registry: Arc<tokio::sync::Mutex<WorkerTaskRegistry>>,
}
```

### DataPlaneServices

```rust
pub struct DataPlaneServices {
    pub request_services: Arc<RequestServices>,
    pub serverless_manager: Arc<ServerlessManager>,
    pub port_honeypot_runner: Option<Arc<PortHoneypotRunner>>,
    // Mesh fields (feature-gated)
    pub mesh_transport_manager: Option<Arc<MeshTransportManager>>,
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    pub threat_intel_policy: Option<ThreatIntelPolicyContext>,
    pub record_store: Option<Arc<RecordStoreManager>>,
}

pub struct RequestServices {
    pub threat_intel: Option<Arc<dyn ThreatIntelLookup>>,
    pub behavioral_intel: Option<Arc<dyn BehavioralIntelLookup>>,
    pub upload_validator: Option<Arc<UploadValidator>>,
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    pub plugin_manager: Option<Arc<GlobalPluginManager>>,
    pub serverless_registry: Option<Arc<ServerlessRegistry>>,
}
```

## CPU Offload Worker

### Architecture

Separate process for CPU-intensive tasks, communicating via Unix domain socket.

```rust
pub struct CpuWorkerState {
    pub worker_id: usize,
    pub running: RunningFlag,
    pub stop_background_tasks: DrainFlag,
    pub ipc: Arc<TokioMutex<AsyncIpcStream>>,
    pub config_manager: Arc<RwLock<ConfigManager>>,
    pub minifier_caches: Arc<RwLock<HashMap<String, Arc<MinifierCache>>>>,
    pub compression_queue: Arc<RwLock<Vec<CompressionTask>>>,
    pub cpu_task_limiter: Arc<CpuTaskLimiter>,
    pub yara_scanner: Option<Arc<YaraScanner>>,
}
```

### Task Types

| Task | Description | Backpressure |
|------|-------------|--------------|
| `Minify` | HTML/CSS/JS minification | Per-site cache, global limit |
| `GetCompressed` | gzip/brotli compression | Queue limit |
| `PoisonImage` | Image rights marking | Queue limit |
| `YaraScan` | YARA rule evaluation | Concurrent scan limit |
| `WasmExecute` | WASM plugin execution | Concurrency semaphore |
| `ServerlessInvoke` | Serverless function invocation | Per-function pool |

### Backpressure System

```rust
pub struct CpuTaskLimiter {
    pub limits: CpuTaskLimits,
    pub state: Mutex<CpuTaskBackpressureState>,
}

pub struct CpuTaskLimits {
    pub max_active_global: usize,      // 128
    pub max_queue_global: usize,       // 1024
    pub max_active_per_site: usize,    // 32
    pub max_queue_per_site: usize,     // 256
    pub max_payload_bytes: usize,      // 64 MiB
    pub max_output_bytes: usize,       // 64 MiB
    // Values are set at the construction site in cpu_task/mod.rs:99-104;
    // there is no `impl Default for CpuTaskLimits`.
}
```

### Connection Model

- Listens on the Unix domain socket at `args.cpu_worker_socket` (`cpu_task/mod.rs:121`);
  the path is unlinked if it already exists (`:123`) before `UnixListener::bind` (`:131`)
- Up to `MAX_STATIC_CONNECTIONS = 100` concurrent connections (`cpu_task/mod.rs:149` and `:196`)
- `std::thread::spawn` accept loop (not Tokio — blocking I/O OK for accept)
- Each connection handled in a Tokio task

## Supervision Loop

```rust
// src/worker/unified_server/supervision_loop.rs:48 — pseudocode
pub async fn run_worker_supervision(
    state: &UnifiedServerWorkerState,           // by reference, not by value
    lifecycle_rx: mpsc::Receiver<LifecycleRequest>,
    exit_rx: broadcast::Receiver<NamedTaskExit>,
    mesh_decision_rx_opt: Option<MeshDecisionReceiver>,
    required_mesh_startup_failure: Option<WorkerShutdownCause>,
    active_mesh_support: OptionalMeshSupport,   // `Option<()>` without mesh
) -> WorkerSupervisionResult {                  // note: Result, not SupervisionResult
    loop {
        tokio::select! {
            request = lifecycle_rx.recv() => { /* LifecycleRequest + ack sender */ }
            exit = exit_rx.recv() => {
                // RecvError::Lagged / Closed are mapped by
                // map_exit_recv_error_to_shutdown_cause()
            }
            decision = mesh_decision_rx_opt... => { /* mesh supervision */ }
        }
    }
}
```

The receivers are passed **in** from the startup plan; there are no
`state.recv_lifecycle_event()` / `state.task_registry.next_exit()` accessors.
The function is side-effect free: it selects a cause and returns, leaving all
teardown to `shutdown_executor::execute_worker_shutdown()`.

## Shutdown Executor

Ordered teardown sequence — authoritative list is the doc comment at
`src/worker/unified_server/shutdown_executor.rs:140-155`, implemented in
`execute_worker_shutdown()`:

```
 1. Record coordinated shutdown intent + lifecycle ack  (begin_coordinated_shutdown)
 1.5. Establish the real shutdown deadline
 2. Stop accepting new connections
 3. Graceful drain (if requested and timeout nonzero) — wait for
    active_connections == 0, or drain-timeout expiry
 4. Stop app servers (Granian supervisors)
 4.5. Shutdown mesh transport (if running)
 4.6. Stop the active mesh support bundle explicitly
 5. Clear running flag
 6. Broadcast registry cancellation
 7. Bandwidth persist — handled by the background task's own final flush,
    NOT by the composition root
 8. Await registry tasks: shutdown_and_join(critical=5s, background=3s)
 9. Abort and await remaining non-migrated task handles
10. Send supervisor acknowledgement (routed by WorkerShutdownCause)
11. Derive exit code from shutdown_cause.exit_code()
```

(The list is 11 steps + two mesh sub-steps, not 13; the original count double-counted
the mesh support bundle and the bandwidth flush as separate top-level steps.)

## Task Registry (Worker-Level)

```rust
pub enum TaskClass {
    CriticalService,      // Fatal if exits unexpectedly
    RestartableBackground, // Logged, optionally restarted
    BoundedChild,         // Bounded lifetime
    CpuOffload,           // CPU worker task
    Detached,             // Fire-and-forget
    OneShot,              // Runs once then completes
}

pub enum TaskExitReason {
    Cancelled,
    CleanCompletion,
    UnexpectedCompletion,
    Panic(String),
    Error(String),
    Aborted,
}
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `UnifiedServerWorkerState` | `src/worker/unified_server/state.rs` | Core worker state |
| `DataPlaneServices` | `src/worker/unified_server/services.rs` | Bundled request-path services |
| `WorkerStartupArtifacts` | `src/worker/unified_server/startup_plan.rs` | Startup outputs (phases 0–14.5) |
| `WorkerSupervisionResult` | `src/worker/unified_server/supervision_loop.rs` | Supervision output |
| `WorkerShutdownPlan` | `src/worker/unified_server/shutdown_executor.rs` | Shutdown parameters |
| `CpuWorkerState` | `src/worker/cpu_task/state.rs` | CPU offload state |
| `CpuTaskLimiter` | `src/worker/cpu_task/state.rs` | Backpressure system |
| `WorkerTaskRegistry` | `src/worker/task_registry.rs` | Task lifecycle management |
| `WorkerDrainState` | `src/worker/drain_state.rs` | Per-worker drain tracking |
| `RequestServices` | `src/worker/context.rs` | Request-path service handles |
