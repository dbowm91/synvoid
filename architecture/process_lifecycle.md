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
  - **Drain Coordination:** Provides staged worker draining via `DrainManager` (`src/supervisor/drain_manager.rs`) during upgrades. The `drain_aware_shutdown()` method at `src/supervisor/process.rs:198-272` coordinates the full drain protocol.
  - **Control Plane Coordination:** Handles Raft consensus, DHT routing, and Mesh transport.
  - **Configuration:** Loads and validates configuration using the `synvoid-config` crate.
  - **gRPC API:** Hosts the formal Control Plane API (`proto/control.proto`) for remote management.
- **Key Logic:** `src/supervisor/`.
- **Entry Point:** `run_supervisor_mode()` (`src/main.rs:531-537`).
- **IPC Role:** Acts as the central hub for worker coordination.

### 2. Worker (The Data Plane)
Workers are request-handling engines managed by the Supervisor. SynVoid uses a unified worker, CPU offload workers, and one legacy raw TCP/UDP worker type:

- **UnifiedServerWorker:** Primary worker handling HTTP/HTTPS/HTTP3 + WAF + proxy via a single Tokio async event loop. Handles all site routing and security enforcement.
- **CPU Offload Worker (historically `StaticWorker`):** Dedicated worker for bounded heavy tasks like CSS/JS minification, compression, image transforms, YARA scans, and other expensive transforms. The legacy `StaticWorker` IPC names are retained for compatibility.
- **Legacy Worker (BaseWorkerProcess):** Deprecated raw TCP/UDP proxy worker. Unused for HTTP traffic; requires further investigation to determine if it should be removed.

- **Isolation:** Worker process boundaries isolate failure domains and lifecycle operations.
- **Kernel Load Balancing:** `SO_REUSEPORT` can be used in advanced multi-unified-worker mode and upgrade overlap flows.
- **CPU Pinning:** On Linux, workers can be assigned CPU affinity based on worker ID via the `--cpu-affinity` flag. Not supported on macOS/BSD (logs warning).
- **Minimal Intelligence:** Workers focus strictly on request handling (WAF pipeline, proxying). They receive threat intelligence and configuration updates from the Supervisor.
- **Key Logic:** `src/worker/`.

---

## Communication Flow (gRPC & IPC)

SynVoid utilizes a tiered communication strategy:

1.  **External Management (gRPC):** The CLI (`CommandClient`) and remote managers communicate with the Supervisor via gRPC (localhost only for local IPC).
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

Upgrades are coordinated by the Supervisor:

1.  A new Supervisor process can be started to replace the old one.
2.  The new Supervisor takes over the gRPC management interface.
3.  Workers are rotated: new workers are spawned by the new Supervisor, and old workers are signaled to drain.
4.  When enabled for advanced overlap mode, `SO_REUSEPORT` allows old and new workers to coexist during transition.

---

## Process State & Health Monitoring

The Supervisor provides a unified view of the system health:

- **Worker Monitoring:** The Supervisor monitors worker process exits and heartbeats.
- **Self-Healing:** If a worker fails, the Supervisor immediately spawns a replacement and pins it to the correct core.
- **gRPC Status:** The `CommandClient` queries the Supervisor via gRPC to retrieve detailed health and performance metrics.
