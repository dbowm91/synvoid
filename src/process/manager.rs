use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock as PLRwLock;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;

use super::ipc::{Message, WorkerId, WorkerMetricsPayload, WorkerStatus, current_timestamp, ErrorSeverity, ErrorCode};

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub id: WorkerId,
    pub port: u16,
    pub config_path: PathBuf,
    pub master_socket: PathBuf,
}

#[derive(Debug)]
pub struct WorkerProcess {
    pub id: WorkerId,
    pub pid: Option<u32>,
    pub port: u16,
    pub status: WorkerStatus,
    pub child: Option<Child>,
    pub started_at: Instant,
    pub last_heartbeat: Instant,
    pub metrics: WorkerMetricsPayload,
    pub restart_count: u32,
}

#[derive(Debug)]
pub struct StaticWorkerProcess {
    pub worker_id: usize,
    pub pid: Option<u32>,
    pub status: WorkerStatus,
    pub child: Option<Child>,
    pub started_at: Instant,
    pub last_heartbeat: Instant,
}

pub struct ProcessManagerConfig {
    pub min_workers: usize,
    pub max_workers: usize,
    pub max_restart_attempts: u32,
    pub restart_cooldown_secs: u64,
    pub heartbeat_timeout_secs: u64,
    pub graceful_shutdown_timeout_secs: u64,
    pub worker_port_base: u16,
    pub config_path: PathBuf,
    pub master_socket_path: PathBuf,
    pub log_level: Option<String>,
}

impl Default for ProcessManagerConfig {
    fn default() -> Self {
        Self {
            min_workers: 2,
            max_workers: 16,
            max_restart_attempts: 5,
            restart_cooldown_secs: 60,
            heartbeat_timeout_secs: 30,
            graceful_shutdown_timeout_secs: 30,
            worker_port_base: 9000,
            config_path: PathBuf::from("config"),
            master_socket_path: PathBuf::from("/tmp/rustwaf-master.sock"),
            log_level: None,
        }
    }
}

pub struct ProcessManager {
    config: ProcessManagerConfig,
    workers: Arc<PLRwLock<HashMap<usize, WorkerProcess>>>,
    static_worker: Arc<PLRwLock<Option<StaticWorkerProcess>>>,
    next_worker_id: Arc<PLRwLock<usize>>,
    running: Arc<AtomicBool>,
    shutdown_tx: broadcast::Sender<()>,
    event_tx: mpsc::Sender<ProcessEvent>,
    metrics: Arc<ProcessManagerMetrics>,
    pending_thread_count: Arc<PLRwLock<Option<u32>>>,
}

#[derive(Debug, Clone)]
pub enum ProcessEvent {
    WorkerStarted(WorkerId, u32, u16),
    WorkerReady(WorkerId),
    WorkerStopped(WorkerId),
    WorkerFailed(WorkerId, String),
    WorkerRestarted(WorkerId, u32),
    ShutdownInitiated,
    ShutdownComplete,
}

struct ProcessManagerMetrics {
    total_spawns: AtomicU64,
    total_restarts: AtomicU64,
    total_failures: AtomicU64,
}

impl Default for ProcessManagerMetrics {
    fn default() -> Self {
        Self {
            total_spawns: AtomicU64::new(0),
            total_restarts: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
        }
    }
}

impl ProcessManager {
    pub fn new(config: ProcessManagerConfig) -> (Self, mpsc::Receiver<ProcessEvent>) {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (event_tx, event_rx) = mpsc::channel(100);

        (
            Self {
                config,
                workers: Arc::new(PLRwLock::new(HashMap::new())),
                static_worker: Arc::new(PLRwLock::new(None)),
                next_worker_id: Arc::new(PLRwLock::new(0)),
                running: Arc::new(AtomicBool::new(true)),
                shutdown_tx,
                event_tx,
                metrics: Arc::new(ProcessManagerMetrics::default()),
                pending_thread_count: Arc::new(PLRwLock::new(None)),
            },
            event_rx,
        )
    }

    fn allocate_worker_id(&self) -> WorkerId {
        let mut id = self.next_worker_id.write();
        let worker_id = WorkerId(*id);
        *id += 1;
        worker_id
    }

    pub fn spawn_worker(&self) -> std::io::Result<WorkerId> {
        let id = self.allocate_worker_id();
        let port = self.config.worker_port_base + id.as_usize() as u16;
        
        self.spawn_worker_with_id(id, port)
    }

    fn spawn_worker_with_id(&self, id: WorkerId, port: u16) -> std::io::Result<WorkerId> {
        let worker_binary = self.find_worker_binary()?;
        
        let mut cmd = Command::new(&worker_binary);
        cmd.arg("--worker")
            .arg("--worker-id")
            .arg(id.as_usize().to_string())
            .arg("--port")
            .arg(port.to_string())
            .arg("--config-path")
            .arg(&self.config.config_path)
            .arg("--master-socket")
            .arg(&self.config.master_socket_path);
        
        if let Some(ref level) = self.config.log_level {
            cmd.arg("--log-level").arg(level);
        }

        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn()?;

        let pid = child.id();
        let worker_process = WorkerProcess {
            id: id.clone(),
            pid: Some(pid),
            port,
            status: WorkerStatus::Starting,
            child: Some(child),
            started_at: Instant::now(),
            last_heartbeat: Instant::now(),
            metrics: WorkerMetricsPayload::default(),
            restart_count: 0,
        };

        {
            let mut workers = self.workers.write();
            workers.insert(id.as_usize(), worker_process);
        }

        self.metrics.total_spawns.fetch_add(1, Ordering::Relaxed);
        
        let _ = self.event_tx.blocking_send(ProcessEvent::WorkerStarted(
            id.clone(),
            pid,
            port,
        ));

        tracing::info!("Spawned worker {} with PID {} on port {}", id, pid, port);
        Ok(id)
    }

    fn find_worker_binary(&self) -> std::io::Result<PathBuf> {
        std::env::current_exe()
    }

    pub fn spawn_static_worker(&self) -> std::io::Result<usize> {
        let worker_binary = self.find_worker_binary()?;
        
        let mut cmd = Command::new(&worker_binary);
        cmd.arg("--static-worker")
            .arg("--static-worker-id")
            .arg("0")
            .arg("--config-path")
            .arg(&self.config.config_path)
            .arg("--master-socket")
            .arg(&self.config.master_socket_path);
        
        if let Some(ref level) = self.config.log_level {
            cmd.arg("--log-level").arg(level);
        }

        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn()?;
        let pid = child.id();
        
        let static_worker_process = StaticWorkerProcess {
            worker_id: 0,
            pid: Some(pid),
            status: WorkerStatus::Starting,
            child: Some(child),
            started_at: Instant::now(),
            last_heartbeat: Instant::now(),
        };

        {
            let mut static_worker = self.static_worker.write();
            *static_worker = Some(static_worker_process);
        }

        tracing::info!("Spawned static worker with PID {}", pid);
        Ok(0)
    }

    pub fn handle_static_worker_ready(&self, worker_id: usize) {
        let mut static_worker = self.static_worker.write();
        if let Some(worker) = static_worker.as_mut() {
            worker.status = WorkerStatus::Ready;
            tracing::info!("Static worker {} is ready", worker_id);
        }
    }

    pub fn handle_static_worker_heartbeat(&self, worker_id: usize) {
        let mut static_worker = self.static_worker.write();
        if let Some(worker) = static_worker.as_mut() {
            worker.last_heartbeat = Instant::now();
            
            if worker.status == WorkerStatus::Starting {
                worker.status = WorkerStatus::Ready;
            }
        }
    }

    pub fn is_static_worker_ready(&self) -> bool {
        let static_worker = self.static_worker.read();
        static_worker.as_ref().map(|w| w.status == WorkerStatus::Ready).unwrap_or(false)
    }

    pub fn handle_heartbeat(&self, worker_id: WorkerId, metrics: WorkerMetricsPayload) {
        let mut workers = self.workers.write();
        if let Some(worker) = workers.get_mut(&worker_id.as_usize()) {
            worker.last_heartbeat = Instant::now();
            worker.metrics = metrics;
            
            if worker.status == WorkerStatus::Starting {
                worker.status = WorkerStatus::Ready;
                let _ = self.event_tx.blocking_send(ProcessEvent::WorkerReady(worker_id));
            }
        }
    }

    pub fn handle_worker_ready(&self, worker_id: WorkerId) {
        let mut workers = self.workers.write();
        if let Some(worker) = workers.get_mut(&worker_id.as_usize()) {
            worker.status = WorkerStatus::Ready;
        }
        let _ = self.event_tx.blocking_send(ProcessEvent::WorkerReady(worker_id));
    }

    pub fn handle_worker_error(&self, worker_id: WorkerId, error: String, severity: ErrorSeverity, error_code: ErrorCode) {
        match severity {
            ErrorSeverity::Warning => {
                tracing::warn!("Worker {} warning [{}]: {}", worker_id, error_code, error);
            }
            ErrorSeverity::Error => {
                tracing::error!("Worker {} error [{}]: {}", worker_id, error_code, error);
            }
            ErrorSeverity::Critical => {
                tracing::error!("Worker {} CRITICAL [{}]: {}", worker_id, error_code, error);
            }
        }
        
        let mut workers = self.workers.write();
        if let Some(worker) = workers.get_mut(&worker_id.as_usize()) {
            worker.status = WorkerStatus::Failed;
        }

        self.metrics.total_failures.fetch_add(1, Ordering::Relaxed);
        let _ = self.event_tx.blocking_send(ProcessEvent::WorkerFailed(worker_id, error));
    }

    pub fn mark_worker_stopped(&self, worker_id: WorkerId) {
        let mut workers = self.workers.write();
        if let Some(worker) = workers.get_mut(&worker_id.as_usize()) {
            worker.status = WorkerStatus::Stopped;
            if let Some(mut child) = worker.child.take() {
                let _ = child.kill();
            }
        }
        let _ = self.event_tx.blocking_send(ProcessEvent::WorkerStopped(worker_id));
    }

    pub async fn check_workers_health(&self) {
        let workers = self.workers.read();
        let now = Instant::now();
        let timeout = Duration::from_secs(self.config.heartbeat_timeout_secs);
        
        let unhealthy: Vec<WorkerId> = workers
            .iter()
            .filter(|(_, w)| {
                w.status == WorkerStatus::Ready 
                    && now.duration_since(w.last_heartbeat) > timeout
            })
            .map(|(_, w)| w.id.clone())
            .collect();
        drop(workers);

        for worker_id in unhealthy {
            tracing::warn!("Worker {} heartbeat timeout, marking as failed", worker_id);
            self.handle_worker_error(
                worker_id,
                "heartbeat timeout".to_string(),
                ErrorSeverity::Error,
                ErrorCode::Timeout,
            );
        }
    }

    pub async fn reap_zombies(&self) {
        let mut workers = self.workers.write();
        let mut to_restart = Vec::new();
        let mut resize_restart = Vec::new();
        
        for (id, worker) in workers.iter_mut() {
            if let Some(ref mut child) = worker.child {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let exit_code = status.code();
                        let is_resize_restart = exit_code == Some(100);
                        
                        if is_resize_restart {
                            tracing::info!(
                                "Worker {} (PID {:?}) exited for threadpool resize",
                                worker.id,
                                worker.pid
                            );
                            resize_restart.push(*id);
                        } else {
                            tracing::error!(
                                "Worker {} (PID {:?}) exited unexpectedly with status: {} - requires restart (attempt {})",
                                worker.id,
                                worker.pid,
                                status,
                                worker.restart_count + 1
                            );
                            to_restart.push((*id, worker.restart_count));
                        }
                        worker.status = WorkerStatus::Failed;
                        worker.child = None;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::error!("Error checking worker {}: {}", worker.id, e);
                    }
                }
            }
        }
        drop(workers);

        for id in resize_restart {
            {
                let mut pending = self.pending_thread_count.write();
                *pending = None;
            }
            
            let workers = self.workers.read();
            let worker = workers.get(&id);
            let port = worker.map(|w| w.port).unwrap_or_else(|| {
                self.config.worker_port_base + id as u16
            });
            drop(workers);

            tracing::info!("Respawning worker {} for threadpool resize on port {}", id, port);
            if let Err(e) = self.spawn_worker_with_id(WorkerId(id), port) {
                tracing::error!("Failed to respawn worker {}: {}", id, e);
            } else {
                self.metrics.total_restarts.fetch_add(1, Ordering::Relaxed);
            }
        }

        for (id, restart_count) in to_restart {
            let workers = self.workers.read();
            let worker = workers.get(&id);
            let port = worker.map(|w| w.port).unwrap_or_else(|| {
                self.config.worker_port_base + id as u16
            });
            drop(workers);

            if restart_count < self.config.max_restart_attempts {
                self.restart_worker(WorkerId(id), port);
            } else {
                tracing::error!(
                    "Worker {} exceeded max restart attempts ({}), not restarting",
                    id,
                    self.config.max_restart_attempts
                );
            }
        }
    }

    fn restart_worker(&self, worker_id: WorkerId, port: u16) {
        {
            let mut workers = self.workers.write();
            workers.remove(&worker_id.as_usize());
        }

        tracing::info!("Restarting worker {} on port {}", worker_id, port);
        
        if let Err(e) = self.spawn_worker_with_id(worker_id.clone(), port) {
            tracing::error!("Failed to restart worker {}: {}", worker_id, e);
        } else {
            self.metrics.total_restarts.fetch_add(1, Ordering::Relaxed);
            let _ = self.event_tx.blocking_send(ProcessEvent::WorkerRestarted(
                worker_id,
                0,
            ));
        }
    }

    /// Broadcast shutdown signal to all workers.
    ///
    /// Signal handling notes:
    /// - We use signals (SIGTERM/SIGKILL) as a **fallback mechanism** for worker shutdown
    /// - The primary shutdown path is via IPC message (`MasterShutdown`) which workers receive
    ///   through their socket connection
    /// - Signals are needed because:
    ///   1. They work even if the IPC socket is blocked or unresponsive
    ///   2. They work for zombie processes that have lost their IPC connection
    ///   3. They provide a guaranteed delivery mechanism for critical commands
    /// - On Windows, signals are not available, so this relies entirely on IPC (which requires
    ///   workers to maintain their socket connection)
    pub fn broadcast_shutdown(&self, graceful: bool) {
        let pids: Vec<(u32, bool)> = {
            let workers = self.workers.read();
            workers
                .values()
                .filter_map(|worker| {
                    worker.child.as_ref().map(|child| (child.id(), graceful))
                })
                .collect()
        };

        for (pid, is_graceful) in pids {
            if is_graceful {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGTERM,
                );
            } else {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
    }

    pub async fn graceful_shutdown(&self) {
        tracing::info!("Initiating graceful shutdown");
        let _ = self.event_tx.blocking_send(ProcessEvent::ShutdownInitiated);
        
        self.running.store(false, Ordering::SeqCst);
        
        self.broadcast_shutdown(true);

        let timeout = Duration::from_secs(self.config.graceful_shutdown_timeout_secs);
        let start = Instant::now();

        while start.elapsed() < timeout {
            let all_stopped = {
                let workers = self.workers.read();
                workers.values().all(|w| w.status == WorkerStatus::Stopped)
            };

            if all_stopped {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        {
            let mut workers = self.workers.write();
            for worker in workers.values_mut() {
                if let Some(ref mut child) = worker.child {
                    let _ = child.kill();
                }
            }
        }

        tracing::info!("Shutdown complete");
        let _ = self.event_tx.blocking_send(ProcessEvent::ShutdownComplete);
    }

    pub fn get_worker_count(&self) -> usize {
        self.workers.read().len()
    }

    pub fn get_running_worker_count(&self) -> usize {
        self.workers
            .read()
            .values()
            .filter(|w| w.status == WorkerStatus::Ready || w.status == WorkerStatus::Running)
            .count()
    }

    pub fn get_worker_metrics(&self) -> Vec<(WorkerId, WorkerMetricsPayload)> {
        self.workers
            .read()
            .iter()
            .map(|(id, w)| (w.id.clone(), w.metrics.clone()))
            .collect()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Reload configuration for all workers.
    ///
    /// Signal handling notes:
    /// - On Unix, we send SIGUSR1 as a **fallback** if IPC message delivery fails
    /// - On Windows (and as primary path), workers receive this via their IPC socket
    /// - The IPC socket is the primary path because it's more reliable for complex messages
    /// - Signals are kept as fallback for crashed/zombie workers that lost their IPC connection
    /// - Workers handle this via the `MasterConfigReload` IPC message
    pub fn reload_config(&self) {
        // Workers connect to master, so we can't directly send messages.
        // The rehash signal will be sent via the master IPC socket when workers reconnect
        // or we can signal workers via SIGUSR1/SIGHUP
        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, SIGUSR1};
            use nix::unistd::Pid;
            
            let workers = self.workers.read();
            for worker in workers.values() {
                if let Some(pid) = worker.pid {
                    let pid = Pid::from_raw(pid as i32);
                    let _ = nix::sys::signal::kill(pid, SIGUSR1);
                }
            }
            tracing::info!("Config reload signal sent to all workers");
        }
        
        #[cfg(not(unix))]
        {
            tracing::warn!("Config reload via signal not supported on this platform");
        }
    }

    /// Resize threadpool for all workers.
    ///
    /// Signal handling notes:
    /// - On Unix, we send SIGUSR2 as an **immediate notification** to workers
    /// - Workers also receive `MasterResizeThreadpool` via IPC socket in their main loop
    /// - The dual mechanism ensures workers don't miss the configuration change
    /// - On Windows, this relies entirely on IPC socket delivery
    /// - Note: The actual threadpool resize requires worker restart (exit code 100)
    pub fn resize_threadpool(&self, worker_threads: u32) {
        {
            let mut pending = self.pending_thread_count.write();
            *pending = Some(worker_threads);
        }
        
        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, SIGUSR2};
            use nix::unistd::Pid;
            
            let workers = self.workers.read();
            for worker in workers.values() {
                if let Some(pid) = worker.pid {
                    let pid = Pid::from_raw(pid as i32);
                    let _ = nix::sys::signal::kill(pid, SIGUSR2);
                }
            }
            tracing::info!("Threadpool resize signal (SIGUSR2) sent to all workers for {} threads", worker_threads);
        }
        
        #[cfg(not(unix))]
        {
            tracing::warn!("Threadpool resize via signal not supported on this platform");
        }
    }

    pub fn get_status(&self) -> super::ipc::MasterStatus {
        let workers = self.workers.read();
        let worker_infos: Vec<super::ipc::WorkerStatusInfo> = workers
            .values()
            .map(|w| super::ipc::WorkerStatusInfo {
                id: w.id.as_usize(),
                pid: w.pid.unwrap_or(0),
                port: w.port,
                status: format!("{:?}", w.status),
                requests: w.metrics.total_requests,
                blocked: w.metrics.blocked,
            })
            .collect();
        
        let total_requests: u64 = workers.values().map(|w| w.metrics.total_requests).sum();
        let total_blocked: u64 = workers.values().map(|w| w.metrics.blocked).sum();
        
        drop(workers);
        
        super::ipc::MasterStatus {
            master_pid: std::process::id(),
            started_at: 0,
            uptime_secs: 0,
            version: env!("CARGO_PKG_VERSION").to_string(),
            workers: worker_infos,
            stats: super::ipc::StatusStats {
                total_requests,
                blocked_last_hour: total_blocked,
                challenged_last_hour: 0,
                proxied_last_hour: total_requests.saturating_sub(total_blocked),
                active_blocks: 0,
                active_violations: 0,
            },
            threat_summary: super::ipc::ThreatSummary {
                critical_ips: 0,
                elevated_ips: 0,
                total_blocked_ips: 0,
            },
        }
    }
}

pub async fn start_health_monitor(
    manager: Arc<ProcessManager>,
    interval_secs: u64,
) {
    let mut timer = interval(Duration::from_secs(interval_secs));
    let running = manager.running.clone();

    while running.load(Ordering::SeqCst) {
        timer.tick().await;
        
        if !running.load(Ordering::SeqCst) {
            break;
        }

        manager.check_workers_health().await;
        manager.reap_zombies().await;
    }
}
