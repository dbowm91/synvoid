use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;
use parking_lot::RwLock as PLRwLock;

use crate::supervisor::SupervisorConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStatus {
    Starting,
    Running,
    Ready,
    Stopping,
    Stopped,
    Failed,
}

pub struct WorkerMetrics {
    pub total_requests: AtomicU64,
    pub blocked: AtomicU64,
    pub challenged: AtomicU64,
    pub proxied: AtomicU64,
    pub errors: AtomicU64,
    pub current_concurrent: AtomicUsize,
    pub peak_concurrent: AtomicUsize,
    pub total_latency_ms: AtomicU64,
    pub request_count_for_latency: AtomicU64,
}

impl Default for WorkerMetrics {
    fn default() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            challenged: AtomicU64::new(0),
            proxied: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            current_concurrent: AtomicUsize::new(0),
            peak_concurrent: AtomicUsize::new(0),
            total_latency_ms: AtomicU64::new(0),
            request_count_for_latency: AtomicU64::new(0),
        }
    }
}

impl WorkerMetrics {
    pub fn current_load(&self) -> f64 {
        self.current_concurrent.load(Ordering::Relaxed) as f64
    }

    pub fn avg_latency_ms(&self) -> f64 {
        let total = self.total_latency_ms.load(Ordering::Relaxed);
        let count = self.request_count_for_latency.load(Ordering::Relaxed);
        if count > 0 {
            total as f64 / count as f64
        } else {
            0.0
        }
    }

    pub fn requests_per_second(&self, uptime_secs: u64) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if uptime_secs > 0 {
            total as f64 / uptime_secs as f64
        } else {
            0.0
        }
    }
}

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
        self.started_at.read()
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
        let current = self.metrics.current_concurrent.fetch_add(1, Ordering::Relaxed) + 1;
        
        let peak = self.metrics.peak_concurrent.load(Ordering::Relaxed);
        if current > peak {
            self.metrics.peak_concurrent.store(current, Ordering::Relaxed);
        }
    }

    pub fn record_request_end(&self, latency_ms: u64, blocked: bool, challenged: bool, proxied: bool, error: bool) {
        self.metrics.current_concurrent.fetch_sub(1, Ordering::Relaxed);
        
        if blocked {
            self.metrics.blocked.fetch_add(1, Ordering::Relaxed);
        }
        if challenged {
            self.metrics.challenged.fetch_add(1, Ordering::Relaxed);
        }
        if proxied {
            self.metrics.proxied.fetch_add(1, Ordering::Relaxed);
        }
        if error {
            self.metrics.errors.fetch_add(1, Ordering::Relaxed);
        }
        
        self.metrics.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
        self.metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
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
