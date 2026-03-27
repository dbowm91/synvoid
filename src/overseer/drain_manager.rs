#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::Mutex;

use crate::drain::{DrainStatus, WorkerDrainState};
use crate::process::{IpcStream, Message, WorkerId};

static DRAIN_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_drain_id() -> u64 {
    DRAIN_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub struct DrainManager {
    workers: Arc<RwLock<HashMap<WorkerId, WorkerDrainState>>>,
    current_drain_id: Arc<AtomicU64>,
    drain_start_time: Arc<Mutex<Option<Instant>>>,
}

impl Default for DrainManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DrainManager {
    pub fn new() -> Self {
        Self {
            workers: Arc::new(RwLock::new(HashMap::new())),
            current_drain_id: Arc::new(AtomicU64::new(0)),
            drain_start_time: Arc::new(Mutex::new(None)),
        }
    }

    pub fn start_drain(&self, timeout_secs: u64) -> u64 {
        let drain_id = next_drain_id();
        self.current_drain_id.store(drain_id, Ordering::SeqCst);

        let mut start_time = self.drain_start_time.blocking_lock();
        *start_time = Some(Instant::now());

        tracing::info!("Starting drain {} with timeout {}s", drain_id, timeout_secs);

        drain_id
    }

    pub fn register_worker(
        &self,
        worker_id: WorkerId,
        active_connections: u64,
        idle_connections: u64,
    ) {
        let drain_id = self.current_drain_id.load(Ordering::SeqCst);

        let state =
            WorkerDrainState::new(worker_id, drain_id, active_connections, idle_connections);

        self.workers.write().insert(worker_id, state);

        tracing::debug!(
            "Registered worker {} for drain {} with {} active connections",
            worker_id,
            drain_id,
            active_connections
        );
    }

    pub fn update_worker_connections(&self, worker_id: &WorkerId, active: u64, idle: u64) {
        let mut workers = self.workers.write();
        if let Some(state) = workers.get_mut(worker_id) {
            state.active_connections = active;
            state.idle_connections = idle;

            if active == 0 && state.stopped_accepting {
                state.drain_complete = true;
            }
        }
    }

    pub fn mark_worker_stopped_accepting(&self, worker_id: &WorkerId) {
        let mut workers = self.workers.write();
        if let Some(state) = workers.get_mut(worker_id) {
            state.stopped_accepting = true;

            if state.active_connections == 0 {
                state.drain_complete = true;
            }

            tracing::info!(
                "Worker {} stopped accepting, {} active connections remaining",
                worker_id,
                state.active_connections
            );
        }
    }

    pub fn mark_worker_drain_complete(&self, worker_id: &WorkerId, connections_drained: u64) {
        let mut workers = self.workers.write();
        if let Some(state) = workers.get_mut(worker_id) {
            state.drain_complete = true;
            state.connections_drained = connections_drained;

            tracing::info!(
                "Worker {} drain complete, {} connections handled",
                worker_id,
                connections_drained
            );
        }
    }

    pub fn get_drain_status(&self) -> DrainStatus {
        let workers = self.workers.read();
        let drain_id = self.current_drain_id.load(Ordering::SeqCst);

        let total_active: u64 = workers.values().map(|w| w.active_connections).sum();
        let total_idle: u64 = workers.values().map(|w| w.idle_connections).sum();
        let _total_drained: u64 = workers.values().map(|w| w.connections_drained).sum();
        let all_complete = !workers.is_empty() && workers.values().all(|w| w.drain_complete);

        let start_time = self.drain_start_time.blocking_lock();
        let drain_start = *start_time;

        DrainStatus::default()
            .with_drain_id(drain_id)
            .with_draining(drain_id > 0)
            .with_connections(total_active, total_idle)
            .with_drain_start(drain_start, 0)
            .with_complete(all_complete)
    }

    pub fn get_worker_status(&self, worker_id: &WorkerId) -> Option<WorkerDrainState> {
        self.workers.read().get(worker_id).cloned()
    }

    pub fn all_workers_drained(&self) -> bool {
        let workers = self.workers.read();
        !workers.is_empty()
            && workers
                .values()
                .all(|w| w.drain_complete || w.active_connections == 0)
    }

    pub fn total_active_connections(&self) -> u64 {
        self.workers
            .read()
            .values()
            .map(|w| w.active_connections)
            .sum()
    }

    pub fn clear(&self) {
        self.workers.write().clear();
        self.current_drain_id.store(0, Ordering::SeqCst);
        let mut start_time = self.drain_start_time.blocking_lock();
        *start_time = None;
    }

    pub async fn wait_for_drain(&self, timeout_secs: u64) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if self.all_workers_drained() {
                tracing::info!("All workers drained successfully");
                return true;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let active = self.total_active_connections();
        tracing::warn!(
            "Drain timeout reached, {} active connections remaining",
            active
        );

        false
    }
}

pub struct DrainProtocol {
    manager: Arc<DrainManager>,
}

impl DrainProtocol {
    pub fn new(manager: Arc<DrainManager>) -> Self {
        Self { manager }
    }

    pub async fn send_drain_request(
        &self,
        ipc: &mut IpcStream,
        worker_id: &WorkerId,
        timeout_secs: u64,
    ) -> std::io::Result<u64> {
        let drain_id = self.manager.start_drain(timeout_secs);

        ipc.send(&Message::DrainRequest {
            timeout_secs,
            drain_id,
        })?;

        tracing::info!(
            "Sent drain request {} to worker {} with timeout {}s",
            drain_id,
            worker_id,
            timeout_secs
        );

        Ok(drain_id)
    }

    pub async fn poll_drain_status(
        &self,
        ipc: &mut IpcStream,
        drain_id: u64,
    ) -> std::io::Result<DrainStatus> {
        ipc.send(&Message::DrainStatusRequest { drain_id })?;

        let start = Instant::now();
        let timeout = Duration::from_secs(5);

        while start.elapsed() < timeout {
            if let Some(Message::DrainStatusResponse {
                drain_id: resp_drain_id,
                is_draining,
                active_connections,
                idle_connections,
                connections_drained: _,
                drain_elapsed_secs,
                drain_complete,
            }) = ipc.recv(100)?
            {
                if resp_drain_id == drain_id {
                    let status = DrainStatus::default()
                        .with_drain_id(drain_id)
                        .with_draining(is_draining)
                        .with_connections(active_connections, idle_connections)
                        .with_drain_start(
                            Some(Instant::now() - Duration::from_secs(drain_elapsed_secs)),
                            0,
                        )
                        .with_complete(drain_complete);
                    return Ok(status);
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Timeout waiting for drain status response",
        ))
    }

    pub async fn send_stop_accepting(
        &self,
        ipc: &mut IpcStream,
        drain_id: u64,
    ) -> std::io::Result<bool> {
        ipc.send(&Message::StopAccepting { drain_id })?;

        let start = Instant::now();
        let timeout = Duration::from_secs(5);

        while start.elapsed() < timeout {
            if let Some(Message::StopAcceptingAck {
                drain_id: resp_drain_id,
                accepted,
                active_connections,
            }) = ipc.recv(100)?
            {
                if resp_drain_id == drain_id {
                    tracing::info!(
                        "Worker stopped accepting: accepted={}, active={}",
                        accepted,
                        active_connections
                    );
                    return Ok(accepted);
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Timeout waiting for stop accepting ack",
        ))
    }

    pub async fn drain_worker_with_confirmation(
        &self,
        ipc: &mut IpcStream,
        worker_id: &WorkerId,
        drain_timeout_secs: u64,
        poll_interval_ms: u64,
    ) -> std::io::Result<bool> {
        let drain_id = self
            .send_drain_request(ipc, worker_id, drain_timeout_secs)
            .await?;

        let stop_accepted = self.send_stop_accepting(ipc, drain_id).await?;
        if !stop_accepted {
            tracing::warn!("Worker {} did not accept stop accepting request", worker_id);
        }

        self.manager.register_worker(*worker_id, 0, 0);

        let start = Instant::now();
        let timeout = Duration::from_secs(drain_timeout_secs);
        let poll_interval = Duration::from_millis(poll_interval_ms);
        let max_retries: u32 = 3;

        while start.elapsed() < timeout {
            let mut last_error = None;

            for attempt in 0..max_retries {
                match self.poll_drain_status(ipc, drain_id).await {
                    Ok(status) => {
                        self.manager.update_worker_connections(
                            worker_id,
                            status.active_connections,
                            status.idle_connections,
                        );

                        if status.drain_complete {
                            self.manager
                                .mark_worker_drain_complete(worker_id, status.connections_drained);
                            return Ok(true);
                        }

                        break;
                    }
                    Err(e) => {
                        last_error = Some(e);
                        if attempt < max_retries - 1 {
                            let backoff = Duration::from_millis(100 * (1 << attempt));
                            tracing::warn!(
                                "Drain status poll failed for worker {} (attempt {}/{}), retrying in {:?}",
                                worker_id, attempt + 1, max_retries, backoff
                            );
                            tokio::time::sleep(backoff).await;
                        }
                    }
                }
            }

            if let Some(e) = last_error {
                return Err(e);
            }

            tokio::time::sleep(poll_interval).await;
        }

        tracing::warn!(
            "Drain timeout for worker {}, {} connections remaining",
            worker_id,
            self.manager.total_active_connections()
        );

        Ok(false)
    }
}

pub fn handle_drain_request(
    draining: &Arc<std::sync::atomic::AtomicBool>,
    drain_id: &mut u64,
    active_connections: u64,
    request_drain_id: u64,
    timeout_secs: u64,
) -> bool {
    if draining.load(Ordering::SeqCst) && *drain_id > 0 && *drain_id != request_drain_id {
        tracing::warn!(
            "Already draining with id {}, ignoring request for id {}",
            drain_id,
            request_drain_id
        );
        return false;
    }

    *drain_id = request_drain_id;
    draining.store(true, Ordering::SeqCst);

    tracing::info!(
        "Worker entering drain mode (id={}, timeout={}s, active={})",
        request_drain_id,
        timeout_secs,
        active_connections
    );

    true
}

pub fn create_drain_status_response(
    drain_id: u64,
    is_draining: bool,
    active_connections: u64,
    idle_connections: u64,
    connections_drained: u64,
    drain_start: Option<Instant>,
) -> Message {
    let elapsed_secs = drain_start.map(|s| s.elapsed().as_secs()).unwrap_or(0);

    Message::DrainStatusResponse {
        drain_id,
        is_draining,
        active_connections,
        idle_connections,
        connections_drained,
        drain_elapsed_secs: elapsed_secs,
        drain_complete: is_draining && active_connections == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drain_manager() {
        let manager = DrainManager::new();

        let drain_id = manager.start_drain(30);
        assert!(drain_id > 0);

        manager.register_worker(WorkerId(1), 10, 2);
        manager.register_worker(WorkerId(2), 5, 1);

        assert_eq!(manager.total_active_connections(), 15);
        assert!(!manager.all_workers_drained());

        manager.update_worker_connections(&WorkerId(1), 0, 0);
        manager.mark_worker_stopped_accepting(&WorkerId(1));
        manager.update_worker_connections(&WorkerId(2), 0, 0);
        manager.mark_worker_stopped_accepting(&WorkerId(2));

        assert!(manager.all_workers_drained());
    }

    #[test]
    fn test_drain_status() {
        let status = DrainStatus::default()
            .with_drain_id(1)
            .with_draining(true)
            .with_connections(5, 2)
            .with_drain_start(Some(Instant::now()), 0)
            .with_complete(false);

        assert!(!status.drain_complete);
    }
}
