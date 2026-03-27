use parking_lot::RwLock as PLRwLock;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::task::JoinHandle;

use crate::config::SupervisorConfig;
pub use crate::metrics::WorkerMetrics;
pub use crate::process::WorkerId;
pub use crate::process::WorkerStatus;

pub struct Worker {
    pub id: WorkerId,
    pub status: Arc<PLRwLock<WorkerStatus>>,
    pub metrics: WorkerMetrics,
    task: Arc<PLRwLock<Option<JoinHandle<()>>>>,
    config: SupervisorConfig,
    ready_tx: Arc<PLRwLock<Option<tokio::sync::oneshot::Sender<()>>>>,
    started_at: Arc<PLRwLock<Option<std::time::Instant>>>,
}

impl Worker {
    pub fn new(id: WorkerId, config: SupervisorConfig) -> Self {
        Self {
            id,
            status: Arc::new(PLRwLock::new(WorkerStatus::Starting)),
            metrics: WorkerMetrics::default(),
            task: Arc::new(PLRwLock::new(None)),
            config,
            ready_tx: Arc::new(PLRwLock::new(None)),
            started_at: Arc::new(PLRwLock::new(None)),
        }
    }

    pub fn status(&self) -> WorkerStatus {
        *self.status.read()
    }

    pub fn metrics(&self) -> &WorkerMetrics {
        &self.metrics
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.started_at
            .read()
            .map(|t| t.elapsed())
            .unwrap_or_default()
    }

    pub async fn start(&self) {
        *self.status.write() = WorkerStatus::Starting;
        *self.started_at.write() = Some(std::time::Instant::now());

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        *self.ready_tx.write() = Some(ready_tx);

        let id = self.id;
        let status = self.status.clone();

        let handle = tokio::spawn(async move {
            *status.write() = WorkerStatus::Running;
            tracing::info!("Worker {} started", id.0);

            let _ = ready_rx.await;

            tracing::info!("Worker {} ready", id.0);
        });

        *self.task.write() = Some(handle);
    }

    pub async fn set_ready(&self) {
        *self.status.write() = WorkerStatus::Ready;
        if let Some(tx) = self.ready_tx.write().take() {
            let _ = tx.send(());
        }
    }

    pub async fn shutdown(&self) {
        let current_status = *self.status.read();
        if current_status == WorkerStatus::Stopped || current_status == WorkerStatus::Stopping {
            return;
        }

        *self.status.write() = WorkerStatus::Stopping;

        if let Some(handle) = self.task.write().take() {
            handle.abort();
        }

        *self.status.write() = WorkerStatus::Stopped;
        tracing::info!("Worker {} stopped", self.id.0);
    }

    pub fn record_request_start(&self) {
        self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
        let current = self
            .metrics
            .current_concurrent
            .fetch_add(1, Ordering::Relaxed)
            + 1;

        let peak = self.metrics.peak_concurrent.load(Ordering::Relaxed);
        if current > peak {
            self.metrics
                .peak_concurrent
                .store(current, Ordering::Relaxed);
        }
    }

    pub fn record_request_end(
        &self,
        latency_ms: u64,
        blocked: bool,
        challenged: bool,
        proxied: bool,
        error: bool,
    ) {
        self.metrics
            .current_concurrent
            .fetch_sub(1, Ordering::Relaxed);

        [
            (blocked, &self.metrics.blocked),
            (challenged, &self.metrics.challenged),
            (proxied, &self.metrics.proxied),
            (error, &self.metrics.errors),
        ]
        .iter()
        .filter(|(flag, _)| *flag)
        .for_each(|(_, counter)| {
            counter.fetch_add(1, Ordering::Relaxed);
        });

        self.metrics
            .total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.metrics.request_count.fetch_add(1, Ordering::Relaxed);
    }
}

impl Clone for Worker {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            status: self.status.clone(),
            metrics: WorkerMetrics::default(),
            task: self.task.clone(),
            config: self.config.clone(),
            ready_tx: self.ready_tx.clone(),
            started_at: self.started_at.clone(),
        }
    }
}
