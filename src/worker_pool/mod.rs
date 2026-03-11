pub mod worker;
pub mod shared_state;

pub use worker::{Worker, WorkerId, WorkerStatus};
pub use shared_state::SharedWafState;

use crate::config::main::WorkerPoolDefaults;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::interval;
use parking_lot::RwLock as PLRwLock;
use metrics::{gauge, histogram};

#[derive(Debug, Clone)]
pub struct WorkerPool {
    config: WorkerPoolDefaults,
    workers: Arc<PLRwLock<Vec<Worker>>>,
    shared_state: Arc<SharedWafState>,
    shutdown_tx: broadcast::Sender<()>,
    scale_event_tx: mpsc::Sender<ScaleEvent>,
    current_worker_count: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
pub enum ScaleEvent {
    ScaleUp,
    ScaleDown,
    EmergencyMode { enabled: bool },
}

impl WorkerPool {
    pub fn new(config: WorkerPoolDefaults, shared_state: Arc<SharedWafState>) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (scale_event_tx, _) = mpsc::channel(100);

        let workers = Arc::new(PLRwLock::new(Vec::new()));

        WorkerPool {
            config,
            workers,
            shared_state,
            shutdown_tx,
            scale_event_tx,
            current_worker_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub async fn start(&self) {
        let initial_workers = self.config.workers;
        
        tracing::info!("Starting worker pool with {} initial workers", initial_workers);

        for i in 0..initial_workers {
            self.spawn_worker(i).await;
        }
        
        self.current_worker_count.store(initial_workers, Ordering::SeqCst);
    }

    pub async fn spawn_worker(&self, worker_id: usize) -> Worker {
        let port = self.config.worker_port_base + worker_id as u16;
        
        let worker = Worker::new(
            WorkerId(worker_id),
            port,
            "http://localhost:8000".to_string(),
            self.shared_state.clone(),
        );

        let worker_ref = worker.clone();
        Arc::new(worker).start().await;
        
        self.current_worker_count.fetch_add(1, Ordering::SeqCst);
        
        tracing::info!("Spawned worker {} on port {}", worker_id, port);

        {
            let mut workers = self.workers.write();
            workers.push(worker_ref.clone());
        }

        worker_ref
    }

    pub async fn get_worker_for_request(&self) -> Option<Worker> {
        let workers = self.workers.read();
        
        if workers.is_empty() {
            return None;
        }

        let mut best_worker = None;
        let mut lowest_load = u64::MAX;

        for worker in workers.iter() {
            if let WorkerStatus::Running = worker.status() {
                let load = worker.current_load();
                if load < lowest_load {
                    lowest_load = load;
                    best_worker = Some(worker.clone());
                }
            }
        }

        best_worker
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
        
        let workers = self.workers.read().clone();
        for worker in workers {
            worker.shutdown().await;
        }
        
        tracing::info!("Worker pool shut down");
    }
}

#[derive(Debug, Clone, Default)]
pub struct AggregatedMetrics {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub requests_per_second: f64,
    pub avg_latency_ms: f64,
    pub total_requests: u64,
    pub blocked_requests: u64,
}
