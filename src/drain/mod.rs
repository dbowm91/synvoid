use std::collections::HashMap;
use std::time::Instant;

use crate::process::WorkerId;

#[derive(Debug, Clone)]
pub struct WorkerConnectionInfo {
    pub active: u64,
    pub idle: u64,
}

#[derive(Debug, Clone)]
#[derive(Default)]
pub struct DrainStatus {
    pub drain_id: u64,
    pub is_draining: bool,
    pub active_connections: u64,
    pub idle_connections: u64,
    pub connections_drained: u64,
    pub drain_start: Option<Instant>,
    pub drain_elapsed_secs: Option<u64>,
    pub drain_remaining_secs: Option<u64>,
    pub drain_complete: bool,
    pub by_worker: HashMap<usize, WorkerConnectionInfo>,
}


impl DrainStatus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_drain_id(mut self, drain_id: u64) -> Self {
        self.drain_id = drain_id;
        self
    }

    pub fn with_draining(mut self, is_draining: bool) -> Self {
        self.is_draining = is_draining;
        self
    }

    pub fn with_connections(mut self, active: u64, idle: u64) -> Self {
        self.active_connections = active;
        self.idle_connections = idle;
        self
    }

    pub fn with_drain_start(mut self, start: Option<Instant>, timeout_secs: u64) -> Self {
        self.drain_start = start;
        self.drain_elapsed_secs = start.map(|s| s.elapsed().as_secs());
        self.drain_remaining_secs = self
            .drain_elapsed_secs
            .map(|e| timeout_secs.saturating_sub(e));
        self
    }

    pub fn with_complete(mut self, complete: bool) -> Self {
        self.drain_complete = complete;
        self
    }

    pub fn with_worker_breakdown(mut self, workers: HashMap<usize, WorkerConnectionInfo>) -> Self {
        self.by_worker = workers;
        self
    }
}

#[derive(Debug, Clone)]
pub struct WorkerDrainState {
    pub drain_id: u64,
    pub worker_id: WorkerId,
    pub active_connections: u64,
    pub idle_connections: u64,
    pub stopped_accepting: bool,
    pub drain_complete: bool,
    pub initial_connections: u64,
    pub connections_drained: u64,
    pub drain_start: Instant,
}

impl WorkerDrainState {
    pub fn new(worker_id: WorkerId, drain_id: u64, active: u64, idle: u64) -> Self {
        Self {
            drain_id,
            worker_id,
            active_connections: active,
            idle_connections: idle,
            stopped_accepting: false,
            drain_complete: false,
            initial_connections: active,
            connections_drained: 0,
            drain_start: Instant::now(),
        }
    }
}
