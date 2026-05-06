# Process Lifecycle & Execution Model

SynVoid uses a hierarchical multi-process architecture to achieve high availability, zero-downtime updates, and security isolation. The model follows an **Overseer → Master → Worker** pattern.

## The Hierarchy

### 1. Overseer (The Supervisor)
The Overseer is the long-lived entry point process. Its primary responsibility is to ensure the Master process is running and healthy.

- **Responsibilities:**
  - Spawning and monitoring the Master process.
  - Handling zero-downtime upgrades via a "Dual Master" handoff mechanism.
  - Managing drain cycles for old processes during upgrades.
  - Performing health checks on the Master (both process-level and IPC-level).
  - Executing rollbacks if an upgrade fails.
- **Key Logic:** `src/overseer/process.rs`, `src/overseer/upgrade.rs`.
- **IPC Role:** Communicates with the Master to monitor its health and coordination.

### 2. Master (The Coordinator)
The Master process acts as the control plane for a single instance. It orchestrates all the heavy lifting that doesn't involve direct request handling.

- **Responsibilities:**
  - **Process Management:** Spawns and monitors Worker processes (Unified Server, Static Workers) using the `ProcessManager`.
  - **Configuration:** Loads, validates, and reloads configuration files (`main.toml`, `sites/*.toml`).
  - **Orchestration:** Aggregates threat intelligence, manages global blocklists (`BlockStore`), and coordinates rule feed updates.
  - **Admin Interface:** Runs the Admin API server and handles management commands (rehash, status, stop).
  - **IPC Hub:** Listens on a Unix domain socket (or Windows named pipe) to communicate with its Workers.
- **Security Isolation:** The Master NEVER handles external client traffic directly. This protects the control plane from vulnerabilities in the request-handling stack.
- **Key Logic:** `src/master/mod.rs`, `src/startup/master.rs`, `src/process/mod.rs`.

### 3. Worker (The Data Plane)
Workers are the actual request-handling engines.

- **Unified Server Worker:** Runs a single, highly-optimized Tokio event loop that handles HTTP/1, HTTP/2, HTTP/3 (QUIC), TCP, and UDP traffic for all configured sites.
- **Static Worker:** Specialized worker for high-performance static file serving.
- **Key Logic:** `src/worker/`, `src/server/`.

---

## Communication Flow (IPC)

SynVoid uses a custom binary IPC protocol over Unix domain sockets (standard) or Windows named pipes.

1.  **Overseer ↔ Master:** Health checks, upgrade coordination, and handoff signals.
2.  **Master ↔ Worker:** Configuration distribution, threat feed updates, rule updates, and heartbeat/status reporting.
3.  **Worker ↔ Worker:** In the Mesh network, workers communicate directly via QUIC streams for threat intelligence sharing and P2P proxying.

---

## Zero-Downtime Upgrades

Upgrades are coordinated by the Overseer using a "Dual Master" approach:

1.  Overseer spawns a **New Master** (Generation N+1) while the **Old Master** (Generation N) is still running.
2.  The New Master spawns its own set of workers.
3.  Overseer performs a **Preflight** check on the New Master.
4.  If healthy, the Overseer signals the Old Master to enter **Drain Mode**.
5.  The Old Master signals its workers to finish existing connections and then exit.
6.  The Overseer monitors the drain progress and eventually shuts down the Old Master.
7.  If the New Master fails health checks, the Overseer performs an **Auto-Rollback**, keeping the Old Master alive.

---

## Process State & Health Monitoring

The Overseer maintains a status file (`overseer_status.json`) in the runtime directory, providing a real-time view of the entire process tree.

- **Process Health:** Monitored via `try_wait()` and SIGCHLD.
- **IPC Health:** Monitored via periodic `MasterHealthCheck` messages. If the Master is unresponsive, the Overseer may attempt a restart.
- **Worker Health:** The Master monitors its workers via heartbeats. If a worker fails, the Master attempts to restart it with backoff logic.
