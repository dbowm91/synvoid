# Process Lifecycle & Execution Model

SynVoid uses a "Shared-Nothing Architecture" to achieve maximum performance, linear scalability, and robust security isolation. The model follows a three-tier hierarchy for maximum flexibility, with Supervisor consolidating legacy Overseer + Master responsibilities.

## The Hierarchy

### 1. Overseer (Legacy - Parent Process)
The Overseer is the top-level orchestrator that spawns and monitors the Master process and Mesh Agent. It handles system-wide health monitoring, recovery orchestration, and upgrade coordination.

- **Responsibilities:**
  - **Process Spawning:** Spawns the Master process and Mesh Agent at startup.
  - **Health Monitoring:** Monitors child process heartbeats and restarts failed processes.
  - **Recovery Orchestration:** Handles system recovery when faults occur.
  - **Upgrade Coordination:** Coordinates zero-downtime upgrades across the system.
  - **Drain Coordination:** Provides staged worker draining via `DrainManager` (`src/overseer/drain_manager.rs`) during upgrades.
  - **SO_REUSEPORT Fallback:** Supports both `SO_REUSEPORT` and `PortSwap` upgrade modes via `UpgradeMode` enum (`src/overseer/mode.rs`).
- **Note:** The `run_overseer_mode()` function exists in `src/startup/master.rs:89` but is not exposed via the default CLI entry point. It is retained for advanced deployment scenarios but is not actively maintained. The Supervisor mode is recommended for new deployments.
- **Key Logic:** `src/overseer/`.

### 2. Master (Legacy - Mid-tier Process)
The Master runs as a child of Overseer and provides process management, admin API, block store, and IPC coordination for workers.

- **Responsibilities:**
  - **Process Management:** Spawns and monitors Worker processes via ProcessManager.
  - **Admin API:** Hosts the management interface.
  - **Block Store:** Manages persistent IP blocklists.
  - **IPC Coordination:** Broadcasts configuration and threat intelligence to workers.
- **Key Logic:** `src/startup/master.rs`, `src/master/`.

### 3. Supervisor (Consolidated Control Plane)
The Supervisor is a newer consolidated mode (2026) that merges Overseer + Master responsibilities into a single process for simpler deployments.

- **Modes:**
  - **Consolidated Mode (default):** Supervisor replaces Overseer + Master, spawning workers directly via `run_supervisor_mode()` (`src/main.rs:541-546`).
  - **Legacy Mode:** Invoked via `--master` flag which calls `run_master_mode()` (`src/main.rs:531`). The Master process handles process management, admin API, and IPC coordination for workers.
- **Drain Coordination Limitation:** Unlike the Overseer (which has `DrainManager` at `src/overseer/drain_manager.rs` for coordinated worker draining during upgrades), the Supervisor does not currently implement drain coordination. Workers are restarted directly without the staged draining that Overseer provides. See PL-5 in `plans/plan.md` for planned improvements.
- **Responsibilities:**
  - **Process Management:** Spawning and monitoring Worker processes.
  - **Zero-Downtime Upgrades:** Coordinating worker rotations and hot-reloads.
  - **Control Plane Coordination:** Handles Raft consensus, DHT routing, and Mesh transport.
  - **Configuration:** Loads and validates configuration using the `synvoid-config` crate.
  - **gRPC API:** Hosts the formal Control Plane API (`proto/control.proto`) for remote management.
- **Key Logic:** `src/supervisor/`.
- **IPC Role:** Acts as the central hub for worker coordination.

### 4. Worker (The Data Plane)
Workers are lightweight, "dumb" request-handling engines that operate in a shared-nothing environment. SynVoid uses three worker types:

- **UnifiedServerWorker:** Primary worker handling HTTP/HTTPS/HTTP3 + WAF + proxy via a single Tokio async event loop. Handles all site routing and security enforcement.
- **StaticWorker:** Dedicated worker for background tasks like CSS/JS minification and image compression. Communicates with the unified server via IPC.
- **Legacy Worker (BaseWorkerProcess):** Deprecated raw TCP/UDP proxy worker. Unused for HTTP traffic; requires further investigation to determine if it should be removed.

- **Isolation:** Each worker process is completely independent.
- **Kernel Load Balancing:** Uses `SO_REUSEPORT` during worker upgrades (via upgrade mode) to allow kernel distribution across old and new workers. Initial workers use `reuse_port: false` (default). See `src/startup/worker.rs:42` and `src/process/manager.rs:558-612`.
- **SO_REUSEPORT Upgrade Path:** In Supervisor mode, the upgrade path uses `SO_REUSEPORT` directly for worker replacement. However, the `UpgradeMode` enum and `detect_upgrade_mode()` function are implemented only in the Overseer module (`src/overseer/mode.rs`). The Supervisor does not currently support the `PortSwap` upgrade mode that Overseer provides as a fallback when `SO_REUSEPORT` is unavailable. See PL-4 in `plans/plan.md`.
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
