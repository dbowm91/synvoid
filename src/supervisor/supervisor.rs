use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};
use tokio::time::interval;
use metrics::{gauge, histogram};
use parking_lot::RwLock as PLRwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::SupervisorConfig;
use crate::supervisor::worker::{Worker, WorkerId, WorkerStatus};
use crate::supervisor::autoscaler::AutoScaler;
use crate::RunningFlag;

pub struct Supervisor {
    config: SupervisorConfig,
    workers: Arc<PLRwLock<Vec<Arc<Worker>>>>,
    #[allow(dead_code)] // Reserved for future auto-scaling functionality
    auto_scaler: AutoScaler,
    event_tx: broadcast::Sender<SupervisorEvent>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    metrics: Arc<SupervisorMetrics>,
    restart_state: Arc<RwLock<RestartState>>,
    running: RunningFlag,
    next_worker_id: Arc<PLRwLock<usize>>,
}

#[derive(Clone, Debug)]
pub enum SupervisorEvent {
    WorkerStarted(WorkerId),
    WorkerStopped(WorkerId),
    WorkerFailed(WorkerId, String),
    WorkerRestarted(WorkerId, u32),
    ConfigReloaded,
    ShutdownInitiated,
    ShutdownComplete,
    ScaleUp(usize),
    ScaleDown(usize),
}

struct RestartState {
    attempts: std::collections::HashMap<WorkerId, u32>,
    last_restart: std::collections::HashMap<WorkerId, Instant>,
}

struct SupervisorMetrics {
    total_restarts: AtomicU64,
    total_scale_ups: AtomicU64,
    total_scale_downs: AtomicU64,
    total_failures: AtomicU64,
}

impl Supervisor {
    pub fn new(config: SupervisorConfig) -> Self {
        let (event_tx, _) = broadcast::channel(100);
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config: config.clone(),
            workers: Arc::new(PLRwLock::new(Vec::new())),
            auto_scaler: AutoScaler::new(config.clone()),
            event_tx,
            shutdown_tx: Some(shutdown_tx),
            metrics: Arc::new(SupervisorMetrics {
                total_restarts: AtomicU64::new(0),
                total_scale_ups: AtomicU64::new(0),
                total_scale_downs: AtomicU64::new(0),
                total_failures: AtomicU64::new(0),
            }),
            restart_state: Arc::new(RwLock::new(RestartState {
                attempts: std::collections::HashMap::new(),
                last_restart: std::collections::HashMap::new(),
            })),
            running: RunningFlag::new(),
            next_worker_id: Arc::new(PLRwLock::new(0)),
        }
    }

    pub async fn start(&self) {
        tracing::info!(
            "Starting supervisor with {} initial workers (min: {}, max: {})",
            self.config.min_workers,
            self.config.min_workers,
            self.config.max_workers
        );

        for _i in 0..self.config.min_workers {
            self.spawn_worker().await;
        }

        self.start_health_monitor().await;
        self.start_auto_scaler().await;
        
        tracing::info!("Supervisor started successfully");
    }

    fn allocate_worker_id(&self) -> WorkerId {
        let mut id = self.next_worker_id.write();
        let worker_id = WorkerId(*id);
        *id += 1;
        worker_id
    }

    async fn spawn_worker(&self) -> Arc<Worker> {
        let id = self.allocate_worker_id();
        
        let worker = Worker::new(id, self.config.clone());
        let worker_arc = Arc::new(worker);
        
        {
            let mut workers = self.workers.write();
            workers.push(worker_arc.clone());
        }

        let event_tx = self.event_tx.clone();
        let _metrics = self.metrics.clone();
        let running = self.running.clone();
        
        let worker_clone = worker_arc.clone();
        tokio::spawn(async move {
            tracing::info!("Worker {} starting", id.0);
            
            *worker_clone.status.write() = WorkerStatus::Running;
            
            while running.is_running() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            
            *worker_clone.status.write() = WorkerStatus::Stopped;
            
            let _ = event_tx.send(SupervisorEvent::WorkerFailed(id, "worker exited".to_string()));
        });

        let _ = self.event_tx.send(SupervisorEvent::WorkerStarted(id));
        
        tracing::info!("Worker {} spawned", id.0);
        
        worker_arc
    }

    pub async fn handle_worker_failure(&self, worker_id: WorkerId, error: String) {
        if !self.running.is_running() {
            return;
        }

        let _ = self.event_tx.send(SupervisorEvent::WorkerFailed(worker_id, error.clone()));
        self.metrics.total_failures.fetch_add(1, Ordering::Relaxed);

        let (should_restart, can_restart) = {
            let mut state = self.restart_state.write().await;
            
            let attempts = state.attempts.entry(worker_id).or_insert(0);
            *attempts += 1;
            
            let current_attempts = *attempts;
            let cooldown_secs = self.config.restart_cooldown_secs;
            let max_attempts = self.config.max_restart_attempts;
            
            let last_restart_time = state.last_restart.get(&worker_id).copied();
            
            drop(state);
            
            if current_attempts > max_attempts {
                let cooldown_elapsed = last_restart_time
                    .map(|last| last.elapsed() > Duration::from_secs(cooldown_secs))
                    .unwrap_or(true);
                    
                if cooldown_elapsed {
                    tracing::warn!(
                        "Worker {} restart cooldown elapsed, resetting restart counter",
                        worker_id.0
                    );
                    let mut state = self.restart_state.write().await;
                    state.attempts.insert(worker_id, 1);
                    state.last_restart.insert(worker_id, Instant::now());
                    (1, true)
                } else {
                    tracing::error!(
                        "Worker {} exceeded max restart attempts ({}) and still in cooldown",
                        worker_id.0,
                        max_attempts
                    );
                    (current_attempts, false)
                }
            } else {
                let mut state = self.restart_state.write().await;
                state.last_restart.insert(worker_id, Instant::now());
                (current_attempts, true)
            }
        };

        if !can_restart {
            return;
        }

        let backoff_ms = 1000 * 2u64.saturating_pow((should_restart - 1).min(5));
        
        tracing::warn!(
            "Worker {} failed, restarting in {}ms (attempt {}/{})",
            worker_id.0,
            backoff_ms,
            should_restart,
            self.config.max_restart_attempts
        );

        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

        if !self.running.is_running() {
            return;
        }

        {
            let mut workers = self.workers.write();
            workers.retain(|w| w.id != worker_id);
        }

        self.spawn_worker().await;

        self.metrics.total_restarts.fetch_add(1, Ordering::Relaxed);
        
        let _ = self.event_tx.send(SupervisorEvent::WorkerRestarted(worker_id, should_restart));
    }

    async fn start_health_monitor(&self) {
        let workers = self.workers.clone();
        let event_tx = self.event_tx.clone();
        let metrics = self.metrics.clone();
        let config = self.config.clone();
        let running = self.running.clone();
        
        tokio::spawn(async move {
            let mut timer = interval(Duration::from_secs(config.health_check_interval_secs));
            
            loop {
                timer.tick().await;
                
                if !running.is_running() {
                    break;
                }
                
                let workers_guard = workers.read();
                let total = workers_guard.len();
                let running_count = workers_guard.iter()
                    .filter(|w| w.status() == WorkerStatus::Running)
                    .count();
                let stopped: Vec<_> = workers_guard.iter()
                    .filter(|w| w.status() == WorkerStatus::Stopped)
                    .map(|w| w.id)
                    .collect();
                
                drop(workers_guard);

                for worker_id in stopped {
                    let event_tx = event_tx.clone();
                    tokio::spawn(async move {
                        event_tx.send(SupervisorEvent::WorkerFailed(worker_id, "detected stopped".to_string())).ok();
                    });
                }
                
                gauge!("maluwaf.supervisor.workers_total").set(total as f64);
                gauge!("maluwaf.supervisor.workers_running").set(running_count as f64);
                gauge!("maluwaf.supervisor.workers_failed").set((total - running_count) as f64);
                histogram!("maluwaf.supervisor.restarts_total")
                    .record(metrics.total_restarts.load(Ordering::Relaxed) as f64);
            }
        });
    }

    async fn start_auto_scaler(&self) {
        let workers = self.workers.clone();
        let event_tx = self.event_tx.clone();
        let config = self.config.clone();
        let running = self.running.clone();
        let metrics = self.metrics.clone();
        
        tokio::spawn(async move {
            let mut timer = interval(Duration::from_secs(5));
            let mut last_scale = Instant::now();
            
            loop {
                timer.tick().await;
                
                if !running.is_running() {
                    break;
                }
                
                if last_scale.elapsed() < Duration::from_secs(config.scale_up_cooldown_secs) {
                    continue;
                }

                let workers_guard = workers.read();
                let current_count = workers_guard.len();
                
                let avg_load = if current_count > 0 {
                    workers_guard.iter()
                        .map(|w| w.metrics().current_load())
                        .sum::<f64>() / current_count as f64
                } else {
                    0.0
                };
                
                drop(workers_guard);

                if avg_load > config.scale_up_threshold && current_count < config.max_workers {
                    let new_count = (current_count + 1).min(config.max_workers);
                    let scale_up_by = new_count - current_count;
                    
                    tracing::info!(
                        "Scaling up: load {:.2}% > threshold {:.0}%, adding {} worker(s)",
                        avg_load * 100.0,
                        config.scale_up_threshold * 100.0,
                        scale_up_by
                    );

                    last_scale = Instant::now();
                    metrics.total_scale_ups.fetch_add(1, Ordering::Relaxed);
                    let _ = event_tx.send(SupervisorEvent::ScaleUp(scale_up_by));
                } 
                else if avg_load < config.scale_down_threshold && current_count > config.min_workers {
                    let new_count = (current_count - 1).max(config.min_workers);
                    let scale_down_by = current_count - new_count;
                    
                    tracing::info!(
                        "Scaling down: load {:.2}% < threshold {:.0}%, removing {} worker(s)",
                        avg_load * 100.0,
                        config.scale_down_threshold * 100.0,
                        scale_down_by
                    );

                    last_scale = Instant::now();
                    metrics.total_scale_downs.fetch_add(1, Ordering::Relaxed);
                    let _ = event_tx.send(SupervisorEvent::ScaleDown(scale_down_by));
                }
            }
        });
    }

    pub async fn graceful_shutdown(&self) {
        tracing::info!("Initiating graceful shutdown");
        let _ = self.event_tx.send(SupervisorEvent::ShutdownInitiated);
        
        self.running.stop();

        let timeout = Duration::from_secs(self.config.graceful_shutdown_timeout_secs);
        let start = Instant::now();
        
        loop {
            let workers = self.workers.read();
            let all_stopped = workers.iter().all(|w| w.status() == WorkerStatus::Stopped);
            drop(workers);
            
            if all_stopped || start.elapsed() > timeout {
                break;
            }
            
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
        }
        
        tracing::info!("Supervisor shutdown complete");
        let _ = self.event_tx.send(SupervisorEvent::ShutdownComplete);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SupervisorEvent> {
        self.event_tx.subscribe()
    }

    pub fn worker_count(&self) -> usize {
        self.workers.read().len()
    }

    pub fn is_running(&self) -> bool {
        self.running.is_running()
    }
}
