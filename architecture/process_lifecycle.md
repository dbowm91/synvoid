# Process Lifecycle & Execution Model

SynVoid uses a "Shared-Nothing Architecture" to achieve maximum performance, linear scalability, and robust security isolation. The model follows a two-tier hierarchy with Supervisor as the control plane and Workers as the data plane.

> **Historical Note:** Earlier versions used a three-tier Overseer → Master → Worker hierarchy. The Overseer and Master have been consolidated into the Supervisor as of 2026. The `src/overseer/` and `src/master/` directories no longer exist.

## The Hierarchy

### 1. Supervisor (Control Plane)
The Supervisor is the top-level process that manages worker lifecycle, upgrades, health monitoring, and control-plane APIs.

- **Responsibilities:**
  - **Process Management:** Spawns and monitors Worker processes via ProcessManager.
  - **Health Monitoring:** Monitors child process heartbeats and restarts failed processes.
  - **Zero-Downtime Upgrades:** Coordinating worker rotations and hot-reloads.
  - **Drain Coordination:** Provides staged worker draining via `DrainManager` (`src/supervisor/drain_manager.rs`) during upgrades.
  - **Control Plane Coordination:** Handles Raft consensus, DHT routing, and Mesh transport.
  - **Configuration:** Loads and validates configuration using the `synvoid-config` crate.
  - **gRPC API:** Hosts the formal Control Plane API (`proto/control.proto`) for remote management.
- **Key Logic:** `src/supervisor/`.
- **Entry Point:** `run_supervisor_mode()` (`src/main.rs:531-537`).
- **IPC Role:** Acts as the central hub for worker coordination.

### 2. Worker (The Data Plane)
Workers are lightweight, "dumb" request-handling engines that operate in a shared-nothing environment. SynVoid uses three worker types:

- **UnifiedServerWorker:** Primary worker handling HTTP/HTTPS/HTTP3 + WAF + proxy via a single Tokio async event loop. Handles all site routing and security enforcement.
- **StaticWorker:** Dedicated worker for background tasks like CSS/JS minification and image compression. Communicates with the unified server via IPC.
- **Legacy Worker (BaseWorkerProcess):** Deprecated raw TCP/UDP proxy worker. Unused for HTTP traffic; requires further investigation to determine if it should be removed.

- **Isolation:** Each worker process is completely independent.
- **Kernel Load Balancing:** Uses `SO_REUSEPORT` during worker upgrades to allow kernel distribution across old and new workers. Initial workers use `reuse_port: false` (default). See `src/startup/worker.rs:42` and `src/process/manager.rs:558-612`.
- **CPU Pinning:** On Linux, workers are automatically assigned CPU affinity based on worker ID via `sched_setaffinity`. Not supported on macOS/BSD (logs warning).
- **Minimal Intelligence:** Workers focus strictly on request handling (WAF pipeline, proxying). They receive threat intelligence and configuration updates from the Supervisor.
- **Key Logic:** `src/worker/`.

---

## Communication Flow (gRPC & IPC)

SynVoid utilizes a tiered communication strategy:

1.  **External Management (gRPC):** The CLI (`CommandClient`) and remote managers communicate with the Supervisor via gRPC (localhost only for local IPC).
2.  **Internal Coordination (IPC):** The Supervisor communicates with Workers using a high-speed, binary IPC protocol over Unix domain sockets or Windows named pipes.
3.  **Mesh Network:** Supervisors communicate with other Supervisors via the Mesh transport (QUIC) to maintain global state (Raft/DHT).

---

## Shared-Nothing Data Plane

The transition to a shared-nothing model ensures that the data plane can scale linearly with the number of CPU cores:

- **No Shared State:** Workers do not share memory or mutexes for request handling.
- **Independent Listeners:** Each worker opens its own set of listeners using `SO_REUSEPORT`.
- **Async Efficiency:** Each worker runs a dedicated Tokio runtime optimized for its assigned core.

---

## Zero-Downtime Upgrades

Upgrades are coordinated by the Supervisor:

1.  A new Supervisor process can be started to replace the old one.
2.  The new Supervisor takes over the gRPC management interface.
3.  Workers are rotated: new workers are spawned by the new Supervisor, and old workers are signaled to drain.
4.  `SO_REUSEPORT` allows both old and new workers to coexist during the transition without dropping connections.

---

## Process State & Health Monitoring

The Supervisor provides a unified view of the system health:

- **Worker Monitoring:** The Supervisor monitors worker process exits and heartbeats.
- **Self-Healing:** If a worker fails, the Supervisor immediately spawns a replacement and pins it to the correct core.
- **gRPC Status:** The `CommandClient` queries the Supervisor via gRPC to retrieve detailed health and performance metrics.
