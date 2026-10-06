# Process Lifecycle & Execution Model

SynVoid uses a two-tier architecture with a latency-sensitive unified worker data plane and supervisor-led control plane. The default model is one `UnifiedServerWorker` plus bounded CPU offload workers.

> **Historical Note:** Earlier versions used a three-tier Overseer → Master → Worker hierarchy. The Overseer and Master have been consolidated into the Supervisor as of 2026.

## The Hierarchy

### 1. Supervisor (Control Plane)

The Supervisor is the top-level process that manages worker lifecycle, upgrades, health monitoring, and control-plane APIs.

- **Responsibilities:**
  - **Process Management:** Spawns and monitors Worker processes via ProcessManager.
  - **Health Monitoring:** Monitors child process heartbeats and restarts failed processes.
  - **Zero-Downtime Upgrades:** Coordinating worker rotations and hot-reloads.
  - **Drain Coordination:** Provides staged worker draining via `DrainManager` (`src/supervisor/drain_manager.rs`) during upgrades. The `drain_aware_shutdown()` method at `src/supervisor/process.rs:363-460` coordinates the full drain protocol.
  - **Control Plane Coordination:** Handles Raft consensus, DHT routing, and Mesh transport.
  - **Configuration:** Loads and validates configuration using the `synvoid-config` crate.
  - **gRPC API:** Hosts the formal Control Plane API (`proto/control.proto`) for remote management. (Mesh-gated: `src/supervisor/api.rs` is `#[cfg(feature = "mesh")]`; without `mesh` there is no control-plane listener.)
- **Key Logic:** `src/supervisor/`.
- **Entry Point:** `run_supervisor_mode()` (`src/supervisor/process.rs:588`), called from `src/commands/runtime_launch.rs:194`.
- **IPC Role:** Acts as the central hub for worker coordination.

### 2. Jail Processes (Sandboxed Execution Plane, Phase 22 Operational, Phase 29 Packaged)

WASM plugin execution and YARA rule evaluation run in dedicated jail binaries
(`synvoid-wasm-jail`, `synvoid-yara-jail` from `synvoid-jail-runtime`, Phase 29;
legacy `synvoid --wasm-jail` / `--yara-jail` flags remain only as internal
forwarding shims with no unisolated path), supervised by the parent via
`JailHandle` (`crates/synvoid-ipc/src/jail_process.rs`, resolved via
`crates/synvoid-ipc/src/jail_binary.rs` exe-dir lookup — never CWD/PATH/plugin
dirs — with `JailClient::spawn_resolved` in `src/sandbox/policy.rs`):

- **Transport:** parent-created anonymous stdio pipes inherited by the child.
  No socket bind/connect happens after sandboxing; peer identity rests on
  descriptor inheritance. Jail logs go to stderr — stdout carries only
  length-delimited frames.
- **Protocol:** versioned (`SVJL`/v1), length-bounded (8 MiB frames, 1 MiB
  invoke I/O, 4 MiB scan input), typed narrow operations only (module/rule
  load, invoke/scan, unload, ping, shutdown). Spec:
  [`sandbox_jail_protocol.md`](./sandbox_jail_protocol.md).
- **Supervision:** bounded restarts (default budget 5, exponential backoff
  100 ms–5 s), quarantine-and-restart on any timeout/protocol violation/desync
  instead of continuing on a desynchronized stream, deterministic shutdown
  (stop → drain → `Shutdown` → grace → `kill` → reap). One in-flight request
  per jail; no pipelining.
- **Policy:** `InProcess` (default) / `Preferred` (documented fallback only
  where safe) / `Required` (fail closed, never silently falls back).
  Production routing defaults to in-process; jail adoption is per-call-site
  explicit.
- **Trust:** the parent validates signatures/manifests/capabilities before any
  load; the jail re-verifies content digests (constant-time) and enforces
  fuel/memory/timeout limits with hook-only capabilities (ambient filesystem,
  network, mesh, admin authority is unexpressible inside the jail).

### 3. Worker (The Data Plane)
Workers are request-handling engines managed by the Supervisor. SynVoid uses a unified worker, CPU offload workers, one legacy raw TCP/UDP worker type, plus the jail execution plane above:

- **UnifiedServerWorker:** Primary worker handling HTTP/HTTPS/HTTP3 + WAF + proxy via a single Tokio async event loop. Handles all site routing and security enforcement.
- **CPU Offload Worker (historically `StaticWorker`):** Dedicated worker for bounded heavy tasks like CSS/JS minification, compression, image transforms, YARA scans, and other expensive transforms. The legacy `StaticWorker` IPC names are retained for compatibility.
- **Legacy Worker (BaseWorkerProcess):** Deprecated raw TCP/UDP proxy worker struct (`crates/synvoid-ipc/src/worker.rs`). Unused for HTTP traffic; the legacy `--worker` flag has no dispatch branch and falls through to Supervisor.

- **Isolation:** Worker process boundaries isolate failure domains and lifecycle operations.
- **Kernel Load Balancing:** `SO_REUSEPORT` can be used in advanced multi-unified-worker mode and upgrade overlap flows.
- **CPU Pinning:** Workers accept an optional `--cpu-affinity <CORE>` flag, which the supervisor passes through to each spawned worker (`manager.rs`, worker arg list). The macOS/BSD "logs a warning" behavior was **not confirmed** — the affinity handling under `src/startup/worker.rs` was not traced to a platform-conditional warning.
- **Minimal Intelligence:** Workers focus strictly on request handling (WAF pipeline, proxying). They receive threat intelligence and configuration updates from the Supervisor.
- **Key Logic:** `src/worker/`.

---

## Communication Flow (gRPC & IPC)

SynVoid utilizes a tiered communication strategy:

1.  **External Management (gRPC, mesh-gated):** The tonic `ControlPlane` gRPC service binds localhost by default (`127.0.0.1:50051`) and only exists with the `mesh` feature. The operator CLI does **not** use it: `CommandClient` selects a Unix socket / named pipe by default and its gRPC transport is a stub that returns `CommandError::ConnectionFailed("gRPC support requires root crate")` (`crates/synvoid-ipc/src/command.rs`). See `architecture/supervisor.md` §4.6.
2.  **Internal Coordination (IPC):** The Supervisor communicates with Workers using a high-speed, binary IPC protocol over Unix domain sockets or Windows named pipes.
3.  **Mesh Network:** Supervisors communicate with other Supervisors via the Mesh transport (QUIC) to maintain global state (Raft/DHT).

---

## Unified Data Plane Contract

The default scaling contract is:

- **Unified worker:** Handles listener accept, TLS/HTTP parsing, routing, cheap WAF decisions, and streaming proxy.
- **CPU offload workers:** Handle bounded heavy work (minification/compression/image transforms/deep scans/plugin execution).
- **Advanced multi-unified-worker mode:** Available but not the primary throughput knob.

Inline work stays on the unified worker when it is small, bounded, and predictable. Once work depends on body size, deep regex behavior, or transform cost, it belongs in the CPU offload plane.

---

## Zero-Downtime Upgrades

Worker rotation is coordinated by the Supervisor's staged drain protocol, and
versioned socket paths exist to support an overlap window:

1.  The Supervisor signals existing workers to drain and waits for
    `DrainComplete` (bounded by the drain timeout, `drain_manager.rs`).
2.  New workers are spawned by `spawn_unified_server_workers`; `SO_REUSEPORT` can
    be requested for the overlap window (`--reuse-port`, an internal hidden flag).
3.  Versioned supervisor sockets are available via
    `get_versioned_supervisor_socket_path(gen)` (`socket_path.rs`) so a replacement
    Supervisor can bind beside a running one.
4.  The `--restart` CLI flag is **stop-then-start**, not a handover: `plan.rs:263-270`
    emits `CommandPreAction::RestartSupervisor`, which issues `SupervisorCommand::Stop`
    and only then launches the new runtime.

> **Not verified in code:** no supervisor-to-supervisor gRPC management handover or
> automatic worker-rotation orchestration was found. Steps 1–2 describe mechanisms
> that exist (`DrainProtocol`, `spawn_unified_server_workers`, `SO_REUSEPORT`); the
> "new supervisor takes over the management interface" step has no implementation
> to point at and is retained here as a design intent, not a shipped behavior.

---

## Process State & Health Monitoring

The Supervisor provides a unified view of the system health:

- **Worker Monitoring:** The Supervisor monitors worker process exits and heartbeats.
- **Self-Healing:** If a worker fails, the Supervisor immediately spawns a replacement and pins it to the correct core.
- **Status Retrieval:** The `CommandClient` queries the Supervisor over the **IPC command socket** (named pipe on Windows), sending `SupervisorCommand::Status` and reading `SupervisorStatus`; the mesh-gated gRPC `ControlPlane.GetStatus` serves a different, proto-shaped caller.
