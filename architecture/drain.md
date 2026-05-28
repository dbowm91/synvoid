# Drain Architecture

## 1. Purpose and Responsibility

The Drain module (`src/drain/`) provides **state tracking for graceful connection draining** during worker upgrades and shutdowns. Tracks per-worker drain progress and connection counts.

**Core Responsibilities:**
- Aggregate drain state tracking
- Per-worker drain progress monitoring
- Active/idle connection counting
- Time-based drain deadlines

---

## 2. Key Data Structures

```rust
pub struct DrainStatus {
    pub drain_id: u64,
    pub active_connections: u64,
    pub idle_connections: u64,
    pub elapsed: Duration,
    pub remaining: Option<Duration>,
    pub workers: Vec<WorkerDrainState>,
}

pub struct WorkerDrainState {
    pub worker_id: WorkerId,
    pub drain_id: u64,
    pub initial_connections: u64,
    pub stopped_accepting: bool,
    pub drain_complete: bool,
}

pub struct WorkerConnectionInfo {
    pub active: u64,
    pub idle: u64,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `DrainStatus::new()` | Constructor |
| `.with_drain_id(id)` | Set drain ID |
| `.with_draining(active, idle)` | Set connection counts |
| `.with_drain_start(start)` | Set drain start time |
| `.with_complete(duration)` | Mark drain complete |
| `.with_worker_breakdown(workers)` | Add per-worker details |
| `WorkerDrainState::new(worker_id, drain_id, active, idle)` | Per-worker state |

---

## 4. Integration Points

- **Supervisor**: Orchestrates drain protocol
- **DrainManager**: Uses drain state for shutdown decisions
- **Worker**: Reports connection counts during drain
- **gRPC API**: Exposes drain status to operators

---

## 5. Key Implementation Details

- **Immutable State**: Builder pattern for constructing drain snapshots
- **Time Tracking**: Elapsed/remaining time for drain deadlines
- **Per-Worker Breakdown**: Individual worker drain progress
- **Connection Classification**: Active vs idle connection tracking
