use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(windows)]
use std::os::windows::io::RawSocket as RawFd;

use tokio::sync::Mutex;

use synvoid_http::{DrainStatusSnapshot, HttpDrainControl};
use synvoid_utils::DrainFlag;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RequestType {
    Short,
    Long,
    Streaming,
}

pub struct WorkerDrainState {
    draining: DrainFlag,
    drain_id: Arc<AtomicU64>,
    active_connections: Arc<AtomicU64>,
    idle_connections: Arc<AtomicU64>,
    connections_drained: Arc<AtomicU64>,
    drain_start: Arc<Mutex<Option<Instant>>>,
    stopped_accepting: DrainFlag,
    short_requests: Arc<AtomicU64>,
    long_requests: Arc<AtomicU64>,
    streaming_requests: Arc<AtomicU64>,
    active_fds: Arc<DashMap<u64, (RawFd, RequestType, String)>>,
}

impl Default for WorkerDrainState {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerDrainState {
    pub fn new() -> Self {
        Self {
            draining: DrainFlag::new(),
            drain_id: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicU64::new(0)),
            idle_connections: Arc::new(AtomicU64::new(0)),
            connections_drained: Arc::new(AtomicU64::new(0)),
            drain_start: Arc::new(Mutex::new(None)),
            stopped_accepting: DrainFlag::new(),
            short_requests: Arc::new(AtomicU64::new(0)),
            long_requests: Arc::new(AtomicU64::new(0)),
            streaming_requests: Arc::new(AtomicU64::new(0)),
            active_fds: Arc::new(DashMap::new()),
        }
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    pub async fn start_drain(&self, drain_id: u64) -> bool {
        if self.draining.is_draining() {
            let current_id = self.drain_id.load(Ordering::SeqCst);
            if current_id > 0 && current_id != drain_id {
                tracing::warn!(
                    "Already draining with id {}, ignoring request for id {}",
                    current_id,
                    drain_id
                );
                return false;
            }
        }

        self.drain_id.store(drain_id, Ordering::SeqCst);
        self.draining.start_drain();
        self.stopped_accepting.end_drain();

        let mut start = self.drain_start.lock().await;
        *start = Some(Instant::now());

        tracing::info!(
            "Worker entering drain mode (id={}, active={})",
            drain_id,
            self.active_connections.load(Ordering::SeqCst)
        );

        true
    }

    pub fn is_draining(&self) -> bool {
        self.draining.is_draining()
    }

    pub fn get_drain_id(&self) -> u64 {
        self.drain_id.load(Ordering::SeqCst)
    }

    pub fn register_connection(&self, id: u64, fd: RawFd, request_type: RequestType, addr: String) {
        self.active_fds.insert(id, (fd, request_type, addr));
        self.increment_active_typed(request_type);
    }

    pub fn unregister_connection(&self, id: u64) {
        if let Some((_, (_, request_type, _))) = self.active_fds.remove(&id) {
            self.decrement_active_typed(request_type);
        }
    }

    pub fn get_active_fds(&self) -> Vec<(u64, RawFd, RequestType, String)> {
        self.active_fds
            .iter()
            .map(|entry| {
                let (id, (fd, req_type, addr)) = entry.pair();
                (*id, *fd, *req_type, addr.clone())
            })
            .collect()
    }

    pub fn increment_active(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increment_active_typed(&self, request_type: RequestType) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
        match request_type {
            RequestType::Short => self.short_requests.fetch_add(1, Ordering::SeqCst),
            RequestType::Long => self.long_requests.fetch_add(1, Ordering::SeqCst),
            RequestType::Streaming => self.streaming_requests.fetch_add(1, Ordering::SeqCst),
        };
    }

    pub fn decrement_active(&self) {
        let prev = self
            .active_connections
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
            .unwrap_or(0);
        if prev == 1 && self.is_draining() {
            self.stopped_accepting.start_drain();
            self.mark_drain_complete();
        }
    }

    pub fn decrement_active_typed(&self, request_type: RequestType) {
        let prev = self
            .active_connections
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
            .unwrap_or(0);
        match request_type {
            RequestType::Short => {
                let _ = self
                    .short_requests
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1));
            }
            RequestType::Long => {
                let _ = self
                    .long_requests
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1));
            }
            RequestType::Streaming => {
                let _ =
                    self.streaming_requests
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1));
            }
        };
        if prev == 1 && self.is_draining() {
            self.mark_drain_complete();
        }
    }

    pub fn increment_idle(&self) {
        self.idle_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrement_idle(&self) {
        let _ = self
            .idle_connections
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1));
    }

    pub fn get_active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::SeqCst)
    }

    pub fn get_idle_connections(&self) -> u64 {
        self.idle_connections.load(Ordering::SeqCst)
    }

    pub fn get_request_type_counts(&self) -> (u64, u64, u64) {
        (
            self.short_requests.load(Ordering::SeqCst),
            self.long_requests.load(Ordering::SeqCst),
            self.streaming_requests.load(Ordering::SeqCst),
        )
    }

    pub fn stop_accepting(&self) {
        self.stopped_accepting.start_drain();
        tracing::info!(
            "Worker stopped accepting new connections, {} active remaining",
            self.active_connections.load(Ordering::SeqCst)
        );

        if self.active_connections.load(Ordering::SeqCst) == 0 {
            self.mark_drain_complete();
        }
    }

    pub fn is_stopped_accepting(&self) -> bool {
        self.stopped_accepting.is_draining()
    }

    fn mark_drain_complete(&self) {
        let active = self.active_connections.load(Ordering::SeqCst);
        if self.draining.is_draining() && active == 0 {
            self.connections_drained.fetch_add(1, Ordering::SeqCst);
            tracing::info!("Drain complete for worker");
        }
    }

    pub async fn get_status(&self) -> DrainStatusResponse {
        let drain_start = self.drain_start.lock().await;
        let elapsed_secs = drain_start.map(|s| s.elapsed().as_secs()).unwrap_or(0);

        let active = self.active_connections.load(Ordering::SeqCst);
        let is_draining = self.draining.is_draining();
        let drain_complete = is_draining && self.stopped_accepting.is_draining() && active == 0;

        let (short, long, streaming) = self.get_request_type_counts();

        DrainStatusResponse {
            drain_id: self.drain_id.load(Ordering::SeqCst),
            is_draining,
            active_connections: active,
            idle_connections: self.idle_connections.load(Ordering::SeqCst),
            connections_drained: self.connections_drained.load(Ordering::SeqCst),
            drain_elapsed_secs: elapsed_secs,
            drain_complete,
            stopped_accepting: self.stopped_accepting.is_draining(),
            short_requests: short,
            long_requests: long,
            streaming_requests: streaming,
        }
    }

    pub async fn reset(&self) {
        self.draining.end_drain();
        self.drain_id.store(0, Ordering::SeqCst);
        self.stopped_accepting.end_drain();
        self.connections_drained.store(0, Ordering::SeqCst);

        let mut start = self.drain_start.lock().await;
        *start = None;
    }
}

#[async_trait::async_trait]
impl HttpDrainControl for WorkerDrainState {
    async fn start_drain(&self, drain_id: u64) -> bool {
        WorkerDrainState::start_drain(self, drain_id).await
    }

    fn stop_accepting(&self) {
        WorkerDrainState::stop_accepting(self);
    }

    async fn get_status(&self) -> DrainStatusSnapshot {
        let status = WorkerDrainState::get_status(self).await;
        DrainStatusSnapshot {
            drain_id: status.drain_id,
            is_draining: status.is_draining,
            active_connections: status.active_connections,
            idle_connections: status.idle_connections,
            connections_drained: status.connections_drained,
            drain_elapsed_secs: status.drain_elapsed_secs,
            drain_complete: status.drain_complete,
            stopped_accepting: status.stopped_accepting,
            short_requests: status.short_requests,
            long_requests: status.long_requests,
            streaming_requests: status.streaming_requests,
        }
    }

    fn is_draining(&self) -> bool {
        WorkerDrainState::is_draining(self)
    }

    fn is_stopped_accepting(&self) -> bool {
        WorkerDrainState::is_stopped_accepting(self)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DrainStatusResponse {
    pub drain_id: u64,
    pub is_draining: bool,
    pub active_connections: u64,
    pub idle_connections: u64,
    pub connections_drained: u64,
    pub drain_elapsed_secs: u64,
    pub drain_complete: bool,
    pub stopped_accepting: bool,
    pub short_requests: u64,
    pub long_requests: u64,
    pub streaming_requests: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DrainRequest {
    pub timeout_secs: u64,
    pub drain_id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_drain_state() {
        let state = WorkerDrainState::new();

        assert!(!state.is_draining());

        state.start_drain(1).await;
        assert!(state.is_draining());
        assert_eq!(state.get_drain_id(), 1);

        state.increment_active();
        assert_eq!(state.get_active_connections(), 1);

        state.decrement_active();
        assert_eq!(state.get_active_connections(), 0);

        let status = state.get_status().await;
        assert!(status.is_draining);
    }

    #[test]
    fn test_request_type_tracking() {
        let state = WorkerDrainState::new();

        state.increment_active_typed(RequestType::Short);
        state.increment_active_typed(RequestType::Long);
        state.increment_active_typed(RequestType::Streaming);

        assert_eq!(state.get_active_connections(), 3);

        let (short, long, streaming) = state.get_request_type_counts();
        assert_eq!(short, 1);
        assert_eq!(long, 1);
        assert_eq!(streaming, 1);

        state.decrement_active_typed(RequestType::Streaming);
        let (_, _, streaming) = state.get_request_type_counts();
        assert_eq!(streaming, 0);
    }

    #[tokio::test]
    async fn test_drain_completes_on_last_connection_decrement() {
        let state = WorkerDrainState::new();
        state.start_drain(1).await;
        state.increment_active();
        assert_eq!(state.get_active_connections(), 1);

        // Decrement to 0 triggers drain complete
        state.decrement_active();
        assert_eq!(state.get_active_connections(), 0);

        let status = state.get_status().await;
        assert!(status.drain_complete);
        assert!(status.stopped_accepting || status.active_connections == 0);
    }

    #[tokio::test]
    async fn test_stop_accepting_completes_drain_when_no_connections() {
        let state = WorkerDrainState::new();
        state.start_drain(42).await;
        // No active connections
        assert_eq!(state.get_active_connections(), 0);

        state.stop_accepting();
        assert!(state.is_stopped_accepting());

        let status = state.get_status().await;
        assert!(status.drain_complete);
    }

    #[tokio::test]
    async fn test_stop_accepting_does_not_complete_with_active_connections() {
        let state = WorkerDrainState::new();
        state.start_drain(1).await;
        state.increment_active();
        state.increment_active();
        assert_eq!(state.get_active_connections(), 2);

        state.stop_accepting();
        assert!(state.is_stopped_accepting());

        let status = state.get_status().await;
        assert!(!status.drain_complete);
    }

    #[tokio::test]
    async fn test_duplicate_drain_id_rejected() {
        let state = WorkerDrainState::new();
        assert!(state.start_drain(1).await);

        // Different drain ID should be rejected
        assert!(!state.start_drain(2).await);
        assert_eq!(state.get_drain_id(), 1);
    }

    #[tokio::test]
    async fn test_same_drain_id_reentry_allowed() {
        let state = WorkerDrainState::new();
        assert!(state.start_drain(1).await);

        // Same drain ID should be allowed
        assert!(state.start_drain(1).await);
        assert_eq!(state.get_drain_id(), 1);
    }

    #[tokio::test]
    async fn test_reset_clears_all_state() {
        let state = WorkerDrainState::new();
        state.start_drain(99).await;
        state.increment_active();
        state.increment_active();
        state.stop_accepting();

        state.reset().await;

        assert!(!state.is_draining());
        assert_eq!(state.get_drain_id(), 0);
        assert!(!state.is_stopped_accepting());
        // active_connections is NOT reset (only drain metadata is reset)
        assert_eq!(state.get_active_connections(), 2);
    }
}
