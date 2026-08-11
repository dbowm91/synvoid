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
| 11 | Build services + ready | Finalize DataPlaneServices, send ready signal |
| 12 | Subscribe exit | Subscribe to exit notifications |
| 13 | Spawn tasks | Heartbeat, bandwidth persist, IPC loop |
| 14 | Register server | Register HTTP server task |
| 14.5 | Mesh supervision | Mesh supervision pipeline |

### Core State

```rust
pub struct UnifiedServerWorkerState {
    pub worker_id: u32,
    pub start_time: Instant,
    pub ipc: Arc<IpcStream>,
    pub running: Arc<RunningFlag>,
    pub master_dead: Arc<AtomicBool>,
    pub draining: Arc<AtomicBool>,
    pub stopped_accepting: Arc<AtomicBool>,
    pub drain_state: Arc<WorkerDrainState>,
    pub app_servers: Arc<RwLock<HashMap<String, Arc<GranianSupervisor>>>>,
    pub unified_server: Arc<UnifiedServer>,
    pub task_registry: Arc<Mutex<WorkerTaskRegistry>>,
    pub data_plane: Arc<DataPlaneServices>,
    // Mesh fields (feature-gated)
    pub canonical_snapshot: Arc<RwLock<Option<CanonicalTrustSnapshot>>>,
    pub mesh_status: Arc<RwLock<WorkerMeshStatus>>,
    pub mesh_policy: Arc<MeshSupervisionPolicy>,
}
```

### DataPlaneServices

```rust
pub struct DataPlaneServices {
    pub request_services: Arc<RequestServices>,
    pub serverless_manager: Option<Arc<ServerlessManager>>,
    pub port_honeypot_runner: Option<Arc<PortHoneypotRunner>>,
}

pub struct RequestServices {
    pub waf_core: Arc<WafCore>,
    pub router: Arc<Router>,
    pub block_store: Arc<BlockStore>,
    pub metrics: Arc<SiteMetrics>,
    pub drain_state: Arc<WorkerDrainState>,
    pub challenge_manager: Arc<PowManager>,
    pub tarpit_service: Arc<TarpitService>,
    pub upload_validator: Arc<UploadValidator>,
    pub config: Arc<MainConfig>,
}
```

## CPU Offload Worker

### Architecture

Separate process for CPU-intensive tasks, communicating via Unix domain socket.

```rust
pub struct CpuWorkerState {
    pub minifier_caches: HashMap<String, MinifierCache>,
    pub compression_queue: Vec<CompressionTask>,
    pub cpu_task_limiter: CpuTaskLimiter,
    pub yara_scanner: Option<YaraScanner>,
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
    max_active_global: usize,      // 128
    max_queue_global: usize,       // 1024
    max_active_per_site: usize,    // 32
    max_queue_per_site: usize,     // 256
    max_payload_bytes: usize,      // 64MB
    max_output_bytes: usize,       // 64MB
}
```

### Connection Model

- Listens on Unix domain socket (`cpu_worker_socket`)
- Up to `MAX_STATIC_CONNECTIONS = 100` concurrent connections
- `std::thread::spawn` accept loop (not Tokio — blocking I/O OK for accept)
- Each connection handled in a Tokio task

## Supervision Loop

```rust
async fn supervision_loop(state: UnifiedServerWorkerState) -> SupervisionResult {
    loop {
        tokio::select! {
            event = state.recv_lifecycle_event() => {
                match event {
                    LifecycleEvent::Drain { timeout } => {
                        state.start_drain(timeout).await;
                    }
                    LifecycleEvent::Shutdown { graceful } => {
                        return shutdown(state, graceful).await;
                    }
                    LifecycleEvent::ConfigReload => {
                        state.reload_config().await;
                    }
                }
            }
            exit = state.task_registry.next_exit() => {
                handle_task_exit(exit, &state).await;
            }
            decision = state.mesh_supervision_decision() => {
                apply_mesh_decision(decision, &state).await;
            }
        }
    }
}
```

## Shutdown Executor

Ordered teardown sequence:

```
1. begin_coordinated_shutdown() + lifecycle ack
2. Stop accepting new connections
3. Graceful drain (if requested)
   - Wait for active_connections == 0
   - Or timeout expiry
4. Stop Granian supervisors
5. Shutdown mesh transport
6. Stop mesh support bundle
7. Clear running flag
8. Broadcast registry cancellation
9. Persist bandwidth data
10. Await registry tasks
    - Critical: 5s timeout
    - Background: 3s timeout
11. Abort remaining handles
12. Send supervisor ack
13. Derive exit code
```

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
| `WorkerStartupArtifacts` | `src/worker/unified_server/startup_plan.rs` | Startup outputs |
| `WorkerSupervisionResult` | `src/worker/unified_server/supervision_loop.rs` | Supervision output |
| `WorkerShutdownPlan` | `src/worker/unified_server/shutdown_executor.rs` | Shutdown parameters |
| `CpuWorkerState` | `src/worker/cpu_task/state.rs` | CPU offload state |
| `CpuTaskLimiter` | `src/worker/cpu_task/state.rs` | Backpressure system |
| `WorkerTaskRegistry` | `src/worker/task_registry.rs` | Task lifecycle management |
| `WorkerDrainState` | `src/worker/drain_state.rs` | Per-worker drain tracking |
