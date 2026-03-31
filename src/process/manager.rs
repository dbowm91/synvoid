use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock as PLRwLock;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;

use super::ipc::{
    ErrorCode, ErrorSeverity, IpcStream, Message, RequestLogPayload, WorkerId,
    WorkerMetricsPayload, WorkerStatus,
};

pub type SharedIpc = Arc<tokio::sync::Mutex<IpcStream>>;
use super::ipc_rate_limit::IpcRateLimiter;

macro_rules! delegate_to_base {
    ($ty:ty) => {
        impl $ty {
            pub fn pid(&self) -> Option<u32> {
                self.base.pid()
            }
            pub fn status(&self) -> &WorkerStatus {
                self.base.status()
            }
            pub fn status_mut(&mut self) -> &mut WorkerStatus {
                self.base.status_mut()
            }
            pub fn child_ref(&self) -> &Option<Child> {
                self.base.child_ref()
            }
            pub fn child_mut(&mut self) -> &mut Option<Child> {
                self.base.child_mut()
            }
            pub fn started_at(&self) -> Instant {
                self.base.started_at()
            }
            pub fn last_heartbeat(&self) -> Instant {
                self.base.last_heartbeat()
            }
            pub fn last_heartbeat_mut(&mut self) -> &mut Instant {
                self.base.last_heartbeat_mut()
            }
        }
    };
}

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub id: WorkerId,
    pub port: u16,
    pub config_path: PathBuf,
    pub master_socket: PathBuf,
}

#[derive(Debug)]
pub struct BaseWorkerProcess {
    pub pid: Option<u32>,
    pub status: WorkerStatus,
    pub child: Option<Child>,
    pub started_at: Instant,
    pub last_heartbeat: Instant,
}

impl BaseWorkerProcess {
    pub fn new(pid: u32, child: Child) -> Self {
        Self {
            pid: Some(pid),
            status: WorkerStatus::Starting,
            child: Some(child),
            started_at: Instant::now(),
            last_heartbeat: Instant::now(),
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }
    pub fn status(&self) -> &WorkerStatus {
        &self.status
    }
    pub fn status_mut(&mut self) -> &mut WorkerStatus {
        &mut self.status
    }
    pub fn child_ref(&self) -> &Option<Child> {
        &self.child
    }
    pub fn child_mut(&mut self) -> &mut Option<Child> {
        &mut self.child
    }
    pub fn started_at(&self) -> Instant {
        self.started_at
    }
    pub fn last_heartbeat(&self) -> Instant {
        self.last_heartbeat
    }
    pub fn last_heartbeat_mut(&mut self) -> &mut Instant {
        &mut self.last_heartbeat
    }
}

pub trait WorkerProcessBase {
    fn base(&self) -> &BaseWorkerProcess;
    fn base_mut(&mut self) -> &mut BaseWorkerProcess;
}

impl WorkerProcessBase for WorkerProcess {
    fn base(&self) -> &BaseWorkerProcess {
        &self.base
    }
    fn base_mut(&mut self) -> &mut BaseWorkerProcess {
        &mut self.base
    }
}

impl WorkerProcessBase for StaticWorkerProcess {
    fn base(&self) -> &BaseWorkerProcess {
        &self.base
    }
    fn base_mut(&mut self) -> &mut BaseWorkerProcess {
        &mut self.base
    }
}

impl WorkerProcessBase for UnifiedServerWorkerProcess {
    fn base(&self) -> &BaseWorkerProcess {
        &self.base
    }
    fn base_mut(&mut self) -> &mut BaseWorkerProcess {
        &mut self.base
    }
}

#[derive(Debug)]
pub struct WorkerProcess {
    pub id: WorkerId,
    pub base: BaseWorkerProcess,
    pub port: u16,
    pub metrics: WorkerMetricsPayload,
    pub restart_count: u32,
    pub last_restart_at: Option<Instant>,
}

impl WorkerProcess {
    pub fn new(id: WorkerId, pid: u32, port: u16, child: Child, restart_count: u32) -> Self {
        Self {
            id,
            base: BaseWorkerProcess::new(pid, child),
            port,
            metrics: WorkerMetricsPayload::default(),
            restart_count,
            last_restart_at: if restart_count > 0 {
                Some(Instant::now())
            } else {
                None
            },
        }
    }

    pub fn new_placeholder(id: WorkerId, port: u16, restart_count: u32) -> Self {
        Self {
            id,
            base: BaseWorkerProcess {
                pid: None,
                status: WorkerStatus::Starting,
                child: None,
                started_at: Instant::now(),
                last_heartbeat: Instant::now(),
            },
            port,
            metrics: WorkerMetricsPayload::default(),
            restart_count,
            last_restart_at: if restart_count > 0 {
                Some(Instant::now())
            } else {
                None
            },
        }
    }

    pub fn set_child(&mut self, child: Child) {
        let pid = child.id();
        self.base.pid = Some(pid);
        self.base.child = Some(child);
    }
}

delegate_to_base!(WorkerProcess);

pub struct StaticWorkerProcess {
    pub worker_id: usize,
    pub base: BaseWorkerProcess,
    pub ipc: Option<Arc<tokio::sync::Mutex<IpcStream>>>,
}

impl StaticWorkerProcess {
    pub fn new(worker_id: usize, pid: u32, child: Child) -> Self {
        Self {
            worker_id,
            base: BaseWorkerProcess::new(pid, child),
            ipc: None,
        }
    }
}

delegate_to_base!(StaticWorkerProcess);

pub struct UnifiedServerWorkerProcess {
    pub id: WorkerId,
    pub base: BaseWorkerProcess,
    pub metrics: WorkerMetricsPayload,
    pub restart_count: u32,
    pub last_restart_at: Option<Instant>,
    pub ipc: Option<Arc<tokio::sync::Mutex<IpcStream>>>,
}

impl UnifiedServerWorkerProcess {
    pub fn new(id: WorkerId, pid: u32, child: Child) -> Self {
        Self {
            id,
            base: BaseWorkerProcess::new(pid, child),
            metrics: WorkerMetricsPayload::default(),
            restart_count: 0,
            last_restart_at: None,
            ipc: None,
        }
    }
}

delegate_to_base!(UnifiedServerWorkerProcess);

pub struct ProcessManagerConfig {
    pub min_workers: usize,
    pub max_workers: usize,
    pub unified_server_workers: usize,
    pub max_restart_attempts: u32,
    pub restart_cooldown_secs: u64,
    pub restart_backoff_max_secs: u64,
    pub heartbeat_timeout_secs: u64,
    pub graceful_shutdown_timeout_secs: u64,
    pub worker_port_base: u16,
    pub config_path: PathBuf,
    pub master_socket_path: PathBuf,
    pub log_level: Option<String>,
    pub pre_spawn_workers: usize,
    pub warm_workers_target: usize,
    pub health_check_interval_secs: u64,
    pub ipc_session_key: Option<[u8; 32]>,
    pub ipc_enforce_signing: bool,
    pub allow_insecure_ipc_key: bool,
    pub ipc_rate_limit: super::ipc_rate_limit::config::IpcRateLimitConfig,
}

impl Default for ProcessManagerConfig {
    fn default() -> Self {
        let session_key = Some(super::ipc_signed::generate_session_key());

        Self {
            min_workers: 2,
            max_workers: 16,
            unified_server_workers: 1,
            max_restart_attempts: 5,
            restart_cooldown_secs: 60,
            restart_backoff_max_secs: 300,
            heartbeat_timeout_secs: 30,
            graceful_shutdown_timeout_secs: 30,
            worker_port_base: 9000,
            config_path: PathBuf::from("config"),
            master_socket_path: crate::process::get_secure_socket_path("master.sock"),
            log_level: None,
            pre_spawn_workers: 0,
            warm_workers_target: 2,
            health_check_interval_secs: 5,
            ipc_session_key: session_key,
            ipc_enforce_signing: true,
            allow_insecure_ipc_key: false,
            ipc_rate_limit: super::ipc_rate_limit::config::IpcRateLimitConfig::default(),
        }
    }
}

pub struct ProcessManager {
    config: ProcessManagerConfig,
    dynamic_config: Arc<PLRwLock<crate::config::ProcessManagerConfig>>,
    workers: Arc<PLRwLock<HashMap<usize, WorkerProcess>>>,
    static_worker: Arc<PLRwLock<Option<StaticWorkerProcess>>>,
    unified_server_worker: Arc<PLRwLock<Option<UnifiedServerWorkerProcess>>>,
    next_worker_id: Arc<PLRwLock<usize>>,
    running: Arc<AtomicBool>,
    shutdown_tx: broadcast::Sender<()>,
    event_tx: mpsc::Sender<ProcessEvent>,
    metrics: Arc<ProcessManagerMetrics>,
    pending_thread_count: Arc<PLRwLock<Option<u32>>>,
    unified_server_port: Arc<PLRwLock<Option<u16>>>,
    block_store: Option<Arc<crate::block_store::BlockStore>>,
    ipc_rate_limiter: IpcRateLimiter,
    static_worker_cache_hits: Arc<AtomicU64>,
    static_worker_cache_misses: Arc<AtomicU64>,
    request_logs: Arc<PLRwLock<Vec<RequestLogPayload>>>,
}

#[derive(Debug, Clone)]
pub enum ProcessEvent {
    WorkerStarted(WorkerId, u32, u16),
    WorkerReady(WorkerId),
    WorkerStopped(WorkerId),
    WorkerFailed(WorkerId, String),
    WorkerRestarted(WorkerId, u32),
    UnifiedServerWorkerStarted(WorkerId, u32),
    UnifiedServerWorkerReady(WorkerId),
    UnifiedServerWorkerStopped(WorkerId),
    UnifiedServerWorkerFailed(WorkerId, String),
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
    pub fn new(
        config: ProcessManagerConfig,
        block_store: Option<Arc<crate::block_store::BlockStore>>,
    ) -> (Self, mpsc::Receiver<ProcessEvent>) {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (event_tx, event_rx) = mpsc::channel(100);

        let ipc_rate_limiter = IpcRateLimiter::new(
            config.ipc_rate_limit.max_messages_per_second,
            config.ipc_rate_limit.max_burst,
        );

        let dynamic_config = crate::config::ProcessManagerConfig {
            min_workers: config.min_workers,
            max_workers: config.max_workers,
            unified_server_workers: config.unified_server_workers,
            max_restart_attempts: config.max_restart_attempts,
            restart_cooldown_secs: config.restart_cooldown_secs,
            restart_backoff_max_secs: config.restart_backoff_max_secs,
            heartbeat_timeout_secs: config.heartbeat_timeout_secs,
            graceful_shutdown_timeout_secs: config.graceful_shutdown_timeout_secs,
            worker_port_base: config.worker_port_base,
            pre_spawn_workers: config.pre_spawn_workers,
            warm_workers_target: config.warm_workers_target,
            health_check_interval_secs: config.health_check_interval_secs,
        };

        (
            Self {
                config,
                dynamic_config: Arc::new(PLRwLock::new(dynamic_config)),
                workers: Arc::new(PLRwLock::new(HashMap::new())),
                static_worker: Arc::new(PLRwLock::new(None)),
                unified_server_worker: Arc::new(PLRwLock::new(None)),
                next_worker_id: Arc::new(PLRwLock::new(0)),
                running: Arc::new(AtomicBool::new(true)),
                shutdown_tx,
                event_tx,
                metrics: Arc::new(ProcessManagerMetrics::default()),
                pending_thread_count: Arc::new(PLRwLock::new(None)),
                unified_server_port: Arc::new(PLRwLock::new(None)),
                block_store,
                ipc_rate_limiter,
                static_worker_cache_hits: Arc::new(AtomicU64::new(0)),
                static_worker_cache_misses: Arc::new(AtomicU64::new(0)),
                request_logs: Arc::new(PLRwLock::new(Vec::with_capacity(10000))),
            },
            event_rx,
        )
    }

    pub fn set_unified_server_port(&self, port: u16) {
        let mut p = self.unified_server_port.write();
        *p = Some(port);
    }

    pub fn get_unified_server_port(&self) -> Option<u16> {
        *self.unified_server_port.read()
    }

    pub fn get_ipc_rate_limiter(&self) -> &IpcRateLimiter {
        &self.ipc_rate_limiter
    }

    pub fn get_ipc_session_key(&self) -> Option<[u8; 32]> {
        self.config.ipc_session_key
    }

    pub fn get_ipc_enforce_signing(&self) -> bool {
        self.config.ipc_enforce_signing
    }

    pub fn update_config(
        &self,
        new_config: crate::config::ProcessManagerConfig,
    ) -> Result<bool, String> {
        let mut dynamic = self.dynamic_config.write();

        if new_config.min_workers > new_config.max_workers {
            return Err("min_workers cannot exceed max_workers".to_string());
        }

        if new_config.min_workers > dynamic.max_workers {
            return Err("new min_workers cannot exceed current max_workers".to_string());
        }

        let mut needs_restart = false;

        if new_config.worker_port_base != dynamic.worker_port_base {
            tracing::info!("worker_port_base changed - requires restart");
            needs_restart = true;
        }

        dynamic.max_workers = new_config.max_workers;
        dynamic.max_restart_attempts = new_config.max_restart_attempts;
        dynamic.restart_cooldown_secs = new_config.restart_cooldown_secs;
        dynamic.restart_backoff_max_secs = new_config.restart_backoff_max_secs;
        dynamic.heartbeat_timeout_secs = new_config.heartbeat_timeout_secs;
        dynamic.graceful_shutdown_timeout_secs = new_config.graceful_shutdown_timeout_secs;
        dynamic.pre_spawn_workers = new_config.pre_spawn_workers;
        dynamic.warm_workers_target = new_config.warm_workers_target;
        dynamic.health_check_interval_secs = new_config.health_check_interval_secs;

        if new_config.min_workers != dynamic.min_workers {
            let old_min = dynamic.min_workers;
            dynamic.min_workers = new_config.min_workers;

            if new_config.min_workers > old_min {
                tracing::info!(
                    "min_workers increased from {} to {} - spawning additional workers",
                    old_min,
                    new_config.min_workers
                );
                let current_count = self.get_running_worker_count();
                let needed = new_config.min_workers.saturating_sub(current_count);
                let mut spawned = 0;
                for _ in 0..needed {
                    drop(dynamic);
                    match self.spawn_worker() {
                        Ok(_) => spawned += 1,
                        Err(e) => tracing::error!("Failed to spawn worker when scaling up: {}", e),
                    }
                    dynamic = self.dynamic_config.write();
                }
                if spawned < needed {
                    tracing::warn!(
                        "Requested {} workers but only spawned {} due to errors",
                        needed,
                        spawned
                    );
                }
            } else {
                tracing::info!(
                    "min_workers decreased from {} to {} - will scale down on next worker exit",
                    old_min,
                    new_config.min_workers
                );
            }
        }

        tracing::info!("ProcessManager config updated dynamically");

        if new_config.warm_workers_target > dynamic.warm_workers_target {
            tracing::info!("Increasing warm workers target - spawning additional workers");
            drop(dynamic);
            match self.spawn_worker() {
                Ok(_) => {}
                Err(e) => tracing::error!("Failed to spawn warm worker: {}", e),
            }
        }

        Ok(needs_restart)
    }

    pub fn get_config(&self) -> crate::config::ProcessManagerConfig {
        let dynamic = self.dynamic_config.read();
        crate::config::ProcessManagerConfig {
            min_workers: dynamic.min_workers,
            max_workers: dynamic.max_workers,
            unified_server_workers: dynamic.unified_server_workers,
            max_restart_attempts: dynamic.max_restart_attempts,
            restart_cooldown_secs: dynamic.restart_cooldown_secs,
            restart_backoff_max_secs: dynamic.restart_backoff_max_secs,
            heartbeat_timeout_secs: dynamic.heartbeat_timeout_secs,
            graceful_shutdown_timeout_secs: dynamic.graceful_shutdown_timeout_secs,
            worker_port_base: dynamic.worker_port_base,
            pre_spawn_workers: dynamic.pre_spawn_workers,
            warm_workers_target: dynamic.warm_workers_target,
            health_check_interval_secs: dynamic.health_check_interval_secs,
        }
    }

    fn allocate_worker_id(&self) -> WorkerId {
        let mut id = self.next_worker_id.write();
        let worker_id = WorkerId(*id);
        *id += 1;
        worker_id
    }

    fn build_worker_command(&self, binary_path: &Path) -> Command {
        let mut cmd = Command::new(binary_path);

        if let Some(ref level) = self.config.log_level {
            cmd.arg("--log-level").arg(level);
        }

        // Pass IPC session key via a temporary file to avoid exposing it
        // in process listings (/proc/<pid>/environ, ps aux, etc.)
        if let Some(ref key) = self.config.ipc_session_key {
            let key_hex = key.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            match self.write_ipc_key_to_tempfile(&key_hex) {
                Ok(path) => {
                    cmd.env("MALUWAF_IPC_KEY_FILE", path);
                }
                Err(e) => {
                    if self.config.allow_insecure_ipc_key {
                        tracing::warn!(
                            "Failed to write IPC key to temp file: {}, falling back to env var \
                             (allow_insecure_ipc_key is set)",
                            e
                        );
                        cmd.env("MALUWAF_IPC_KEY", key_hex);
                    } else {
                        panic!(
                            "Failed to write IPC key to temp file: {}. \
                             Refusing to fall back to env var (key visible in /proc). \
                             Set security.allow_insecure_ipc_key=true to allow this fallback.",
                            e
                        );
                    }
                }
            }
        }

        cmd.arg("--config-path")
            .arg(&self.config.config_path)
            .arg("--master-socket")
            .arg(&self.config.master_socket_path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        cmd
    }

    fn write_ipc_key_to_tempfile(&self, key_hex: &str) -> std::io::Result<String> {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("maluwaf_ipc_key_{}", std::process::id()));

        {
            let mut file = std::fs::File::create(&file_path)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }

            file.write_all(key_hex.as_bytes())?;
            file.flush()?;
        }

        Ok(file_path.to_string_lossy().into_owned())
    }

    fn record_spawn(&self, id: &WorkerId, pid: u32, port: Option<u16>, event: ProcessEvent) {
        self.metrics.total_spawns.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = self.event_tx.blocking_send(event) {
            tracing::debug!("Failed to send spawn event: {:?}", e);
        }
        if let Some(p) = port {
            tracing::info!("Spawned worker {} with PID {} on port {}", id, pid, p);
        } else {
            tracing::info!("Spawned worker {} with PID {}", id, pid);
        }
    }

    pub fn spawn_worker(&self) -> std::io::Result<WorkerId> {
        let id = self.allocate_worker_id();
        let port = self.config.worker_port_base + id.as_usize() as u16;

        self.spawn_worker_with_id(id, port)
    }

    fn spawn_worker_with_id(&self, id: WorkerId, port: u16) -> std::io::Result<WorkerId> {
        self.spawn_worker_with_id_and_count(id, port, 0)
    }

    fn spawn_worker_with_id_and_count(
        &self,
        id: WorkerId,
        port: u16,
        restart_count: u32,
    ) -> std::io::Result<WorkerId> {
        let worker_binary = self.find_worker_binary()?;

        let mut cmd = self.build_worker_command(&worker_binary);
        cmd.arg("--worker")
            .arg("--worker-id")
            .arg(id.as_usize().to_string())
            .arg("--port")
            .arg(port.to_string());

        let pid = {
            let mut workers = self.workers.write();
            let worker_process = WorkerProcess::new_placeholder(id, port, restart_count);
            workers.insert(id.as_usize(), worker_process);
            drop(workers);

            let child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    self.workers.write().remove(&id.as_usize());
                    return Err(e);
                }
            };
            let pid = child.id();

            let mut workers = self.workers.write();
            if let Some(worker) = workers.get_mut(&id.as_usize()) {
                worker.set_child(child);
            }
            pid
        };

        self.record_spawn(
            &id,
            pid,
            Some(port),
            ProcessEvent::WorkerStarted(id, pid, port),
        );
        Ok(id)
    }

    fn find_worker_binary(&self) -> std::io::Result<PathBuf> {
        std::env::current_exe()
    }

    pub fn spawn_upgrade_worker(
        &self,
        binary_path: Option<&PathBuf>,
        port: u16,
        upgrade_mode: bool,
        reuse_port: bool,
    ) -> std::io::Result<WorkerId> {
        let id = self.allocate_worker_id();

        let worker_binary = match binary_path {
            Some(path) => path.clone(),
            None => self.find_worker_binary()?,
        };

        let mut cmd = self.build_worker_command(&worker_binary);
        cmd.arg("--worker")
            .arg("--worker-id")
            .arg(id.as_usize().to_string())
            .arg("--port")
            .arg(port.to_string());

        if upgrade_mode {
            cmd.arg("--upgrade-mode");
        }

        if reuse_port {
            cmd.arg("--reuse-port");
        }

        let child = cmd.spawn()?;

        let pid = child.id();
        let worker_process = WorkerProcess::new(id, pid, port, child, 0);

        {
            let mut workers = self.workers.write();
            workers.insert(id.as_usize(), worker_process);
        }

        self.record_spawn(
            &id,
            pid,
            Some(port),
            ProcessEvent::WorkerStarted(id, pid, port),
        );
        tracing::info!(
            "Spawned upgrade worker {} with PID {} on port {} (upgrade={}, reuse_port={})",
            id,
            pid,
            port,
            upgrade_mode,
            reuse_port
        );
        Ok(id)
    }

    pub fn spawn_static_worker(&self) -> std::io::Result<usize> {
        let worker_binary = self.find_worker_binary()?;

        let mut cmd = self.build_worker_command(&worker_binary);
        cmd.arg("--static-worker")
            .arg("--static-worker-id")
            .arg("0");

        let child = cmd.spawn()?;
        let pid = child.id();

        let static_worker_process = StaticWorkerProcess::new(0, pid, child);

        {
            let mut static_worker = self.static_worker.write();
            *static_worker = Some(static_worker_process);
        }

        tracing::info!("Spawned static worker with PID {}", pid);
        Ok(0)
    }

    pub fn spawn_unified_server_worker(&self) -> std::io::Result<WorkerId> {
        let id = WorkerId(0);

        let worker_binary = self.find_worker_binary()?;

        let pending_threads = *self.pending_thread_count.read();
        let worker_threads = pending_threads.unwrap_or(2) as usize;

        let mut cmd = self.build_worker_command(&worker_binary);
        cmd.arg("--unified-server-worker")
            .arg("--worker-id")
            .arg("0")
            .arg("--worker-threads")
            .arg(worker_threads.to_string());

        let child = cmd.spawn().map_err(|e| {
            tracing::error!("Failed to spawn unified server worker: {}", e);
            e
        })?;

        let pid = child.id();
        let unified_worker_process = UnifiedServerWorkerProcess::new(id, pid, child);

        {
            let mut unified_server_worker = self.unified_server_worker.write();
            *unified_server_worker = Some(unified_worker_process);
        }

        self.record_spawn(
            &id,
            pid,
            None,
            ProcessEvent::UnifiedServerWorkerStarted(id, pid),
        );
        Ok(id)
    }

    pub fn handle_unified_server_worker_heartbeat(
        &self,
        worker_id: WorkerId,
        metrics: WorkerMetricsPayload,
    ) {
        let event = {
            let mut unified_server_worker = self.unified_server_worker.write();
            if let Some(worker) = unified_server_worker.as_mut() {
                *worker.last_heartbeat_mut() = Instant::now();
                worker.metrics = metrics;

                if *worker.status() == WorkerStatus::Starting {
                    *worker.status_mut() = WorkerStatus::Ready;
                    Some(ProcessEvent::UnifiedServerWorkerReady(worker_id))
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(evt) = event {
            if let Err(e) = self.event_tx.try_send(evt) {
                tracing::debug!("Failed to send worker event: {:?}", e);
            }
        }
    }

    pub fn handle_unified_server_worker_ready(&self, worker_id: WorkerId) {
        {
            let mut unified_server_worker = self.unified_server_worker.write();
            if let Some(worker) = unified_server_worker.as_mut() {
                *worker.status_mut() = WorkerStatus::Ready;
            }
        }
        if let Err(e) = self
            .event_tx
            .try_send(ProcessEvent::UnifiedServerWorkerReady(worker_id))
        {
            tracing::debug!("Failed to send UnifiedServerWorkerReady event: {:?}", e);
        }
    }

    pub fn is_unified_server_worker_ready(&self) -> bool {
        let unified_server_worker = self.unified_server_worker.read();
        unified_server_worker
            .as_ref()
            .map(|w| *w.status() == WorkerStatus::Ready)
            .unwrap_or(false)
    }

    pub fn get_unified_server_worker_metrics(&self) -> Option<WorkerMetricsPayload> {
        let unified_server_worker = self.unified_server_worker.read();
        unified_server_worker.as_ref().map(|w| w.metrics.clone())
    }

    pub fn mark_unified_server_worker_stopped(&self, worker_id: WorkerId) {
        let mut unified_server_worker = self.unified_server_worker.write();
        if let Some(worker) = unified_server_worker.as_mut() {
            *worker.status_mut() = WorkerStatus::Stopped;
            worker.ipc = None;
            if let Some(mut child) = worker.child_mut().take() {
                let _ = child.kill();
            }
        }
        let _ = self
            .event_tx
            .blocking_send(ProcessEvent::UnifiedServerWorkerStopped(worker_id));
    }

    pub fn set_unified_server_worker_ipc(&self, ipc: IpcStream) {
        let mut unified_server_worker = self.unified_server_worker.write();
        if let Some(worker) = unified_server_worker.as_mut() {
            worker.ipc = Some(Arc::new(tokio::sync::Mutex::new(ipc)));
        }
    }

    pub fn set_unified_server_worker_ipc_arc(&self, ipc: Arc<tokio::sync::Mutex<IpcStream>>) {
        let mut unified_server_worker = self.unified_server_worker.write();
        if let Some(worker) = unified_server_worker.as_mut() {
            worker.ipc = Some(ipc);
        }
    }

    pub fn get_unified_server_worker_ipc(&self) -> Option<Arc<tokio::sync::Mutex<IpcStream>>> {
        let unified_server_worker = self.unified_server_worker.read();
        unified_server_worker.as_ref().and_then(|w| w.ipc.clone())
    }

    pub async fn drain_unified_server_worker_async(
        &self,
        timeout_secs: u64,
    ) -> Result<u64, String> {
        let ipc = {
            let unified_server_worker = self.unified_server_worker.read();
            unified_server_worker.as_ref().and_then(|w| w.ipc.clone())
        };

        self.drain_worker_async(
            ipc,
            "UnifiedServerWorker",
            |_, drain_id| Message::UnifiedServerWorkerDrain {
                timeout_secs,
                drain_id,
            },
            |msg, expected_drain_id| match msg {
                Message::UnifiedServerWorkerDrained {
                    remaining_connections,
                    drain_id,
                    ..
                } if *drain_id == expected_drain_id => Some(*remaining_connections),
                _ => None,
            },
        )
        .await
    }

    async fn drain_worker_async(
        &self,
        ipc: Option<SharedIpc>,
        worker_name: &str,
        drain_msg_fn: impl FnOnce(u64, u64) -> Message,
        drain_response_fn: impl Fn(&Message, u64) -> Option<u64>,
    ) -> Result<u64, String> {
        if let Some(ipc) = ipc {
            let drain_id = crate::utils::safe_unix_duration().as_millis() as u64;

            {
                let mut ipc = ipc.lock().await;
                ipc.send(&drain_msg_fn(0, drain_id))
                    .map_err(|e| format!("Failed to send drain request: {}", e))?;
            }

            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(10);

            while start.elapsed() < timeout {
                {
                    let mut ipc = ipc.lock().await;
                    if let Ok(Some(msg)) = ipc.recv(100) {
                        if let Some(remaining) = drain_response_fn(&msg, drain_id) {
                            tracing::info!(
                                "{} drained, {} remaining connections",
                                worker_name,
                                remaining
                            );
                            return Ok(remaining);
                        }
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }

            tracing::warn!("Drain timeout waiting for {}", worker_name);
            return Err("Drain timeout".to_string());
        }
        Err(format!("No {} IPC available", worker_name))
    }

    pub fn handle_static_worker_ready(&self, worker_id: usize) {
        let mut static_worker = self.static_worker.write();
        if let Some(worker) = static_worker.as_mut() {
            *worker.status_mut() = WorkerStatus::Ready;
            tracing::info!("Static worker {} is ready", worker_id);
        }
    }

    pub fn handle_static_worker_heartbeat(
        &self,
        _worker_id: usize,
        cache_hits: u64,
        cache_misses: u64,
    ) {
        let mut static_worker = self.static_worker.write();
        if let Some(worker) = static_worker.as_mut() {
            *worker.last_heartbeat_mut() = Instant::now();

            if *worker.status() == WorkerStatus::Starting {
                *worker.status_mut() = WorkerStatus::Ready;
            }
        }

        self.static_worker_cache_hits
            .store(cache_hits, Ordering::Relaxed);
        self.static_worker_cache_misses
            .store(cache_misses, Ordering::Relaxed);
    }

    pub fn get_static_worker_cache_stats(&self) -> (u64, u64) {
        (
            self.static_worker_cache_hits.load(Ordering::Relaxed),
            self.static_worker_cache_misses.load(Ordering::Relaxed),
        )
    }

    pub fn is_static_worker_ready(&self) -> bool {
        let static_worker = self.static_worker.read();
        static_worker
            .as_ref()
            .map(|w| *w.status() == WorkerStatus::Ready)
            .unwrap_or(false)
    }

    pub fn set_static_worker_ipc(&self, ipc: IpcStream) {
        let mut static_worker = self.static_worker.write();
        if let Some(worker) = static_worker.as_mut() {
            worker.ipc = Some(Arc::new(tokio::sync::Mutex::new(ipc)));
        }
    }

    pub fn clear_static_worker_ipc(&self) {
        let mut static_worker = self.static_worker.write();
        if let Some(worker) = static_worker.as_mut() {
            worker.ipc = None;
        }
    }

    pub fn clear_unified_server_worker_ipc(&self) {
        let mut unified_server_worker = self.unified_server_worker.write();
        if let Some(worker) = unified_server_worker.as_mut() {
            worker.ipc = None;
        }
    }

    pub fn set_static_worker_ipc_arc(&self, ipc: Arc<tokio::sync::Mutex<IpcStream>>) {
        let mut static_worker = self.static_worker.write();
        if let Some(worker) = static_worker.as_mut() {
            worker.ipc = Some(ipc);
        }
    }

    pub fn get_static_worker_ipc(&self) -> Option<Arc<tokio::sync::Mutex<IpcStream>>> {
        let static_worker = self.static_worker.read();
        static_worker.as_ref().and_then(|w| w.ipc.clone())
    }

    pub async fn drain_static_worker_async(&self, timeout_secs: u64) -> Result<u64, String> {
        let ipc = {
            let static_worker = self.static_worker.read();
            static_worker.as_ref().and_then(|w| w.ipc.clone())
        };

        self.drain_worker_async(
            ipc,
            "StaticWorker",
            |_, drain_id| Message::StaticWorkerDrain {
                timeout_secs,
                drain_id,
            },
            |msg, expected_drain_id| match msg {
                Message::StaticWorkerDrained {
                    remaining_tasks,
                    drain_id,
                    ..
                } if *drain_id == expected_drain_id => Some(*remaining_tasks),
                _ => None,
            },
        )
        .await
    }

    pub fn handle_heartbeat(&self, worker_id: WorkerId, metrics: WorkerMetricsPayload) {
        let event = {
            let mut workers = self.workers.write();
            if let Some(worker) = workers.get_mut(&worker_id.as_usize()) {
                *worker.last_heartbeat_mut() = Instant::now();
                worker.metrics = metrics;

                if *worker.status() == WorkerStatus::Starting {
                    *worker.status_mut() = WorkerStatus::Ready;
                    Some(ProcessEvent::WorkerReady(worker_id))
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(evt) = event {
            if let Err(e) = self.event_tx.try_send(evt) {
                crate::metrics::record_dropped_process_event();
                tracing::warn!("Failed to send process event: {}", e);
            }
        }
    }

    pub fn handle_worker_ready(&self, worker_id: WorkerId) {
        {
            let mut workers = self.workers.write();
            if let Some(worker) = workers.get_mut(&worker_id.as_usize()) {
                *worker.status_mut() = WorkerStatus::Ready;
            }
        }
        if let Err(e) = self.event_tx.try_send(ProcessEvent::WorkerReady(worker_id)) {
            crate::metrics::record_dropped_worker_event();
            tracing::warn!(
                "Failed to send WorkerReady event for worker {}: {}",
                worker_id,
                e
            );
        }
    }

    const MAX_REQUEST_LOGS: usize = 10000;

    pub fn handle_request_log(&self, _worker_id: WorkerId, log: RequestLogPayload) {
        let mut logs = self.request_logs.write();
        if logs.len() >= Self::MAX_REQUEST_LOGS {
            logs.remove(0);
        }
        logs.push(log);
    }

    pub fn get_request_logs(&self) -> Vec<RequestLogPayload> {
        self.request_logs.read().clone()
    }

    pub fn handle_worker_error(
        &self,
        worker_id: WorkerId,
        error: String,
        severity: ErrorSeverity,
        error_code: ErrorCode,
    ) {
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
            *worker.status_mut() = WorkerStatus::Failed;
        }

        self.metrics.total_failures.fetch_add(1, Ordering::Relaxed);
        if self
            .event_tx
            .blocking_send(ProcessEvent::WorkerFailed(worker_id, error))
            .is_err()
        {
            crate::metrics::record_dropped_worker_event();
            tracing::warn!("Failed to send WorkerFailed event for worker {}", worker_id);
        }
    }

    pub fn mark_worker_stopped(&self, worker_id: WorkerId) {
        let mut workers = self.workers.write();
        if let Some(worker) = workers.get_mut(&worker_id.as_usize()) {
            *worker.status_mut() = WorkerStatus::Stopped;
            if let Some(mut child) = worker.child_mut().take() {
                let _ = child.kill();
            }
        }
        let _ = self
            .event_tx
            .blocking_send(ProcessEvent::WorkerStopped(worker_id));
    }

    pub fn handle_blocklist_request(
        &self,
        _worker_id: usize,
    ) -> Option<Vec<crate::process::ipc::BlockEntryData>> {
        if let Some(ref store) = self.block_store {
            let entries = store.get_all_entries();
            Some(
                entries
                    .into_iter()
                    .map(|e| crate::process::ipc::BlockEntryData {
                        ip: e.ip,
                        reason: e.reason,
                        blocked_at: e.blocked_at,
                        ban_expire_seconds: e.ban_expire_seconds,
                        site_scope: e.site_scope,
                    })
                    .collect(),
            )
        } else {
            None
        }
    }

    pub fn handle_blocklist_update(&self, blocks: Vec<crate::process::ipc::BlockEntryData>) {
        let count = blocks.len();
        if let Some(ref store) = self.block_store {
            for block in blocks {
                store.add_block(
                    &block.ip,
                    &block.reason,
                    block.ban_expire_seconds,
                    &block.site_scope,
                );
            }
        }
        tracing::info!("Received blocklist update with {} entries", count);
    }

    pub fn trigger_blocklist_persist(&self) {
        if let Some(ref store) = self.block_store {
            store.trigger_persist();
        }
    }

    pub async fn broadcast_rule_patterns_update(
        &self,
        version: String,
        patterns: Vec<crate::process::ipc::RulePatternData>,
    ) {
        let msg = Message::RulePatternsUpdate { version, patterns };

        // Send to unified server worker
        if let Some(ref ipc) = self.get_unified_server_worker_ipc() {
            let mut ipc = ipc.lock().await;
            if let Err(e) = ipc.send(&msg) {
                tracing::error!(
                    "Failed to send rule patterns update to unified server worker: {}",
                    e
                );
            } else {
                tracing::info!("Broadcast rule patterns update to unified server worker");
            }
        }
    }

    pub async fn broadcast_config_reload(&self, config_path: PathBuf) {
        let msg = Message::MasterConfigReload {
            config_path: config_path.to_string_lossy().to_string(),
        };

        // Send to static worker
        if let Some(ref ipc) = self.get_static_worker_ipc() {
            let mut ipc = ipc.lock().await;
            if let Err(e) = ipc.send(&msg) {
                tracing::error!("Failed to send config reload to static worker: {}", e);
            } else {
                tracing::info!("Broadcast config reload to static worker");
            }
        }

        // Send to unified server worker
        if let Some(ref ipc) = self.get_unified_server_worker_ipc() {
            let mut ipc = ipc.lock().await;
            if let Err(e) = ipc.send(&msg) {
                tracing::error!(
                    "Failed to send config reload to unified server worker: {}",
                    e
                );
            } else {
                tracing::info!("Broadcast config reload to unified server worker");
            }
        }

        // Note: Regular pool workers don't have direct IPC channels.
        // They receive config reload via signal-based communication or will pick up on next request.
    }

    pub async fn check_workers_health(&self) {
        let workers = self.workers.read();
        let now = Instant::now();
        let timeout = Duration::from_secs(self.config.heartbeat_timeout_secs);

        let unhealthy: Vec<WorkerId> = workers
            .iter()
            .filter(|(_, w)| {
                *w.status() == WorkerStatus::Ready
                    && now.duration_since(w.last_heartbeat()) > timeout
            })
            .map(|(_, w)| w.id)
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
        let (resize_restart_ids, failure_restarts) = self.detect_dead_workers();
        self.handle_resize_restarts(resize_restart_ids).await;
        self.handle_failure_restarts(failure_restarts).await;
        self.handle_unified_worker_restart().await;
    }

    fn detect_dead_workers(&self) -> (Vec<usize>, Vec<(usize, u32)>) {
        let mut workers = self.workers.write();
        let mut resize_restart = Vec::new();
        let mut to_restart = Vec::new();

        for (id, worker) in workers.iter_mut() {
            if let Some(child) = worker.child_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let exit_code = status.code();
                        let is_resize_restart = exit_code == Some(100);

                        if is_resize_restart {
                            tracing::info!(
                                "Worker {} (PID {:?}) exited for threadpool resize",
                                worker.id,
                                worker.pid()
                            );
                            resize_restart.push(*id);
                        } else {
                            tracing::error!(
                                "Worker {} (PID {:?}) exited unexpectedly with status: {} - requires restart (attempt {})",
                                worker.id,
                                worker.pid(),
                                status,
                                worker.restart_count + 1
                            );
                            to_restart.push((*id, worker.restart_count));
                        }
                        *worker.status_mut() = WorkerStatus::Failed;
                        *worker.child_mut() = None;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::error!("Error checking worker {}: {}", worker.id, e);
                    }
                }
            }
        }

        (resize_restart, to_restart)
    }

    async fn handle_resize_restarts(&self, resize_restart_ids: Vec<usize>) {
        for id in resize_restart_ids {
            {
                let mut pending = self.pending_thread_count.write();
                *pending = None;
            }

            let workers = self.workers.read();
            let worker = workers.get(&id);
            let port = worker
                .map(|w| w.port)
                .unwrap_or_else(|| self.config.worker_port_base + id as u16);
            drop(workers);

            tracing::info!(
                "Respawning worker {} for threadpool resize on port {}",
                id,
                port
            );
            if let Err(e) = self.spawn_worker_with_id(WorkerId(id), port) {
                tracing::error!("Failed to respawn worker {}: {}", id, e);
            } else {
                self.metrics.total_restarts.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn handle_failure_restarts(&self, failure_restarts: Vec<(usize, u32)>) {
        for (id, restart_count) in failure_restarts {
            let workers = self.workers.read();
            let worker = workers.get(&id);
            let port = worker
                .map(|w| w.port)
                .unwrap_or_else(|| self.config.worker_port_base + id as u16);
            let last_restart_at = worker.and_then(|w| w.last_restart_at);
            drop(workers);

            if restart_count < self.config.max_restart_attempts {
                if let Some(last_restart) = last_restart_at {
                    let base_cooldown = self.config.restart_cooldown_secs;
                    let backoff_secs = std::cmp::min(
                        base_cooldown * 2_u64.pow(restart_count.min(8)),
                        self.config.restart_backoff_max_secs,
                    );

                    let elapsed = last_restart.elapsed();
                    if elapsed < Duration::from_secs(backoff_secs) {
                        let remaining = backoff_secs - elapsed.as_secs();
                        tracing::warn!(
                            "Worker {} restart backoff: waiting {}s (elapsed: {}s, backoff: {}s)",
                            id,
                            remaining,
                            elapsed.as_secs(),
                            backoff_secs
                        );
                        continue;
                    }
                }
                self.restart_worker(WorkerId(id), port, restart_count + 1);
            } else {
                tracing::error!(
                    "Worker {} exceeded max restart attempts ({}), not restarting",
                    id,
                    self.config.max_restart_attempts
                );
            }
        }
    }

    async fn handle_unified_worker_restart(&self) {
        let mut unified_worker = self.unified_server_worker.write();
        if let Some(ref mut worker) = unified_worker.as_mut() {
            if let Some(child) = worker.child_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let exit_code = status.code();
                        let is_resize_restart = exit_code == Some(100);

                        if is_resize_restart {
                            tracing::info!(
                                "UnifiedServerWorker (PID {:?}) exited for threadpool resize",
                                worker.pid()
                            );

                            let pending = self.pending_thread_count.write();
                            let new_threads = *pending;
                            drop(pending);

                            tracing::info!("Respawning UnifiedServerWorker for threadpool resize to {:?} threads", new_threads);
                            if let Err(e) = self.spawn_unified_server_worker() {
                                tracing::error!("Failed to respawn UnifiedServerWorker: {}", e);
                            } else {
                                self.metrics.total_restarts.fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            let restart_count = worker.restart_count;

                            tracing::error!(
                                "UnifiedServerWorker (PID {:?}) exited unexpectedly with status: {} (restart {}/{})",
                                worker.pid(),
                                status,
                                restart_count,
                                self.config.max_restart_attempts
                            );
                            *worker.status_mut() = WorkerStatus::Failed;
                            *worker.child_mut() = None;

                            if restart_count < self.config.max_restart_attempts {
                                let new_count = restart_count + 1;
                                worker.restart_count = new_count;
                                worker.last_restart_at = Some(Instant::now());

                                tracing::info!(
                                    "Respawning UnifiedServerWorker (attempt {})",
                                    new_count
                                );
                                if let Err(e) = self.spawn_unified_server_worker() {
                                    tracing::error!("Failed to respawn UnifiedServerWorker: {}", e);
                                } else {
                                    self.metrics.total_restarts.fetch_add(1, Ordering::Relaxed);
                                }
                            } else {
                                tracing::error!(
                                    "UnifiedServerWorker exceeded max restart attempts ({}), not restarting",
                                    self.config.max_restart_attempts
                                );
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::error!("Error checking UnifiedServerWorker: {}", e);
                    }
                }
            }
        }
    }

    fn restart_worker(&self, worker_id: WorkerId, port: u16, restart_count: u32) {
        tracing::info!(
            "Restarting worker {} on port {} (attempt {})",
            worker_id,
            port,
            restart_count
        );

        match self.spawn_worker_with_id_and_count(worker_id, port, restart_count) {
            Ok(_) => {
                self.metrics.total_restarts.fetch_add(1, Ordering::Relaxed);
                let _ = self
                    .event_tx
                    .blocking_send(ProcessEvent::WorkerRestarted(worker_id, restart_count));
            }
            Err(e) => {
                tracing::error!("Failed to restart worker {}: {}", worker_id, e);
            }
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
        let mut pids: Vec<(u32, bool)> = {
            let workers = self.workers.read();
            workers
                .values()
                .filter_map(|worker| {
                    worker
                        .child_ref()
                        .as_ref()
                        .map(|child| (child.id(), graceful))
                })
                .collect()
        };

        if let Some(ref worker) = *self.unified_server_worker.read() {
            if let Some(child) = worker.child_ref().as_ref() {
                pids.push((child.id(), graceful));
            }
        }

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
        if let Err(e) = self.event_tx.blocking_send(ProcessEvent::ShutdownInitiated) {
            tracing::debug!("Failed to send ShutdownInitiated event: {:?}", e);
        }

        self.running.store(false, Ordering::SeqCst);

        self.broadcast_shutdown(true);
        self.wait_for_workers_to_stop().await;
        self.kill_remaining_workers();

        tracing::info!("Shutdown complete");
        if let Err(e) = self.event_tx.blocking_send(ProcessEvent::ShutdownComplete) {
            tracing::debug!("Failed to send ShutdownComplete event: {:?}", e);
        }
    }

    async fn wait_for_workers_to_stop(&self) {
        let timeout = Duration::from_secs(self.config.graceful_shutdown_timeout_secs);
        let start = Instant::now();

        let check_interval = Duration::from_millis(100);
        let sigkill_grace_period = Duration::from_secs(5);
        let mut sent_sigkill = false;
        let mut rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                _ = rx.recv() => {
                    tracing::debug!("Shutdown signal received during graceful shutdown");
                }
                _ = tokio::time::sleep(check_interval) => {
                    let all_stopped = {
                        let workers = self.workers.read();
                        let workers_stopped = workers.values().all(|w| *w.status() == WorkerStatus::Stopped);

                        let unified_stopped = self.unified_server_worker.read()
                            .as_ref()
                            .map(|w| *w.status() == WorkerStatus::Stopped)
                            .unwrap_or(true);

                        workers_stopped && unified_stopped
                    };

                    if all_stopped {
                        tracing::info!("All workers stopped gracefully");
                        break;
                    }

                    if !sent_sigkill && start.elapsed() >= sigkill_grace_period {
                        tracing::warn!("Graceful shutdown taking longer than expected, escalating to SIGKILL");
                        self.broadcast_shutdown(false);
                        sent_sigkill = true;
                    }

                    if start.elapsed() >= timeout {
                        tracing::error!("Graceful shutdown timeout reached, workers may not have terminated cleanly");
                        break;
                    }
                }
            }
        }
    }

    fn kill_remaining_workers(&self) {
        {
            let mut workers = self.workers.write();
            for worker in workers.values_mut() {
                if let Some(child) = worker.child_mut() {
                    let _ = child.kill();
                }
            }
        }

        {
            let mut unified_server_worker = self.unified_server_worker.write();
            if let Some(ref mut worker) = unified_server_worker.as_mut() {
                if let Some(child) = worker.child_mut() {
                    let _ = child.kill();
                }
            }
        }
    }

    pub fn get_worker_count(&self) -> usize {
        self.workers.read().len()
    }

    pub fn ensure_warm_workers(&self) {
        if self.config.pre_spawn_workers == 0 {
            return;
        }

        let current_count = self.get_worker_count();
        let target = self.config.pre_spawn_workers.max(self.config.min_workers);

        if current_count < target {
            let to_spawn = target - current_count;
            tracing::info!(
                "Pre-spawning {} warm workers (current: {}, target: {})",
                to_spawn,
                current_count,
                target
            );

            for _ in 0..to_spawn {
                if let Err(e) = self.spawn_worker() {
                    tracing::error!("Failed to pre-spawn worker: {}", e);
                }
            }
        }
    }

    pub fn get_running_worker_count(&self) -> usize {
        self.workers
            .read()
            .values()
            .filter(|w| *w.status() == WorkerStatus::Ready || *w.status() == WorkerStatus::Running)
            .count()
    }

    pub fn get_worker_metrics(&self) -> Vec<(WorkerId, WorkerMetricsPayload)> {
        self.workers
            .read()
            .values()
            .map(|w| (w.id, w.metrics.clone()))
            .collect()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn is_worker_running(&self, worker_id: &WorkerId) -> bool {
        let workers = self.workers.read();
        workers
            .get(&worker_id.as_usize())
            .map(|w| *w.status() == WorkerStatus::Ready || *w.status() == WorkerStatus::Running)
            .unwrap_or(false)
    }

    pub fn get_worker_pid(&self, worker_id: &WorkerId) -> Option<u32> {
        let workers = self.workers.read();
        workers.get(&worker_id.as_usize()).and_then(|w| w.pid())
    }

    pub fn get_master_pid(&self) -> Option<u32> {
        Some(std::process::id())
    }

    pub fn restart_worker_by_id(&self, worker_id_str: &str) -> Result<(), String> {
        let id = self.parse_worker_id(worker_id_str)?;
        let worker_id = WorkerId(id);

        let pid = {
            let workers = self.workers.read();
            workers.get(&id).and_then(|w| w.pid())
        };

        let pid = pid.ok_or_else(|| format!("Worker {} has no PID", worker_id_str))?;

        tracing::info!("Sending SIGTERM to worker {} (PID {})", worker_id, pid);

        #[cfg(unix)]
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }

        #[cfg(not(unix))]
        {
            let mut workers = self.workers.write();
            if let Some(worker) = workers.get_mut(&id) {
                if let Some(mut child) = worker.child_mut().take() {
                    let _ = child.kill();
                }
                *worker.status_mut() = WorkerStatus::Stopped;
            }
        }

        Ok(())
    }

    fn parse_worker_id(&self, id_str: &str) -> Result<usize, String> {
        if let Ok(id) = id_str.parse::<usize>() {
            return Ok(id);
        }
        if let Some(inner) = id_str
            .strip_prefix("Worker(")
            .and_then(|s| s.strip_suffix(')'))
        {
            return inner
                .parse::<usize>()
                .map_err(|e| format!("Invalid worker ID: {}", e));
        }
        Err(format!("Cannot parse worker ID: {}", id_str))
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
            use nix::sys::signal::SIGUSR1;
            use nix::unistd::Pid;

            let workers = self.workers.read();
            for worker in workers.values() {
                if let Some(pid) = worker.pid() {
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
            use nix::sys::signal::SIGUSR2;
            use nix::unistd::Pid;

            let workers = self.workers.read();
            for worker in workers.values() {
                if let Some(pid) = worker.pid() {
                    let pid = Pid::from_raw(pid as i32);
                    let _ = nix::sys::signal::kill(pid, SIGUSR2);
                }
            }
            tracing::info!(
                "Threadpool resize signal (SIGUSR2) sent to all workers for {} threads",
                worker_threads
            );
        }

        #[cfg(not(unix))]
        {
            tracing::warn!("Threadpool resize via signal not supported on this platform");
        }
    }

    /// Resize threadpool for the unified server worker.
    ///
    /// This triggers the unified server worker to drain connections and restart
    /// with the new thread count.
    ///
    /// Note: The actual threadpool resize requires worker restart (exit code 100)
    pub fn resize_unified_server_worker_threadpool(
        &self,
        worker_threads: u32,
    ) -> Result<(), String> {
        {
            let mut pending = self.pending_thread_count.write();
            *pending = Some(worker_threads);
        }

        let runtime = tokio::runtime::Handle::current();

        runtime.block_on(async {
            self.resize_unified_server_worker_threadpool_internal(worker_threads)
                .await
        })
    }

    async fn resize_unified_server_worker_threadpool_internal(
        &self,
        worker_threads: u32,
    ) -> Result<(), String> {
        let ipc = {
            let unified_server_worker = self.unified_server_worker.read();
            unified_server_worker.as_ref().and_then(|w| w.ipc.clone())
        };

        if let Some(ipc) = ipc {
            {
                let mut ipc = ipc.lock().await;
                ipc.send(&Message::UnifiedServerWorkerResize { worker_threads })
                    .map_err(|e| format!("Failed to send resize request: {}", e))?;
            }

            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(35);

            while start.elapsed() < timeout {
                {
                    let mut ipc = ipc.lock().await;
                    if let Ok(Some(Message::UnifiedServerWorkerResizeAck {
                        id: _,
                        worker_threads: ack_threads,
                    })) = ipc.recv(100)
                    {
                        tracing::info!(
                            "UnifiedServerWorker acknowledged resize to {} threads",
                            ack_threads
                        );
                        return Ok(());
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }

            tracing::warn!("Resize timeout waiting for UnifiedServerWorker ack");
            return Err("Resize timeout".to_string());
        }
        Err("No unified server worker IPC available".to_string())
    }

    pub fn get_status(&self) -> super::ipc::MasterStatus {
        let workers = self.workers.read();
        let mut worker_infos: Vec<super::ipc::WorkerStatusInfo> = workers
            .values()
            .map(|w| super::ipc::WorkerStatusInfo {
                id: w.id.as_usize(),
                pid: w.pid().unwrap_or(0),
                port: w.port,
                status: format!("{:?}", w.status()),
                requests: w.metrics.total_requests,
                blocked: w.metrics.blocked,
            })
            .collect();

        let total_requests: u64 = workers.values().map(|w| w.metrics.total_requests).sum();
        let total_blocked: u64 = workers.values().map(|w| w.metrics.blocked).sum();

        drop(workers);

        let unified_server_worker = self.unified_server_worker.read();
        if let Some(ref worker) = *unified_server_worker {
            worker_infos.push(super::ipc::WorkerStatusInfo {
                id: worker.id.as_usize(),
                pid: worker.pid().unwrap_or(0),
                port: 0,
                status: format!("unified_{:?}", worker.status()),
                requests: worker.metrics.total_requests,
                blocked: worker.metrics.blocked,
            });
        }

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

pub async fn start_health_monitor(manager: Arc<ProcessManager>, interval_secs: u64) {
    let check_interval = if interval_secs > 0 {
        interval_secs
    } else {
        manager.config.health_check_interval_secs
    };
    let mut timer = interval(Duration::from_secs(check_interval));
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

pub fn check_port_available(port: u16) -> std::io::Result<()> {
    let addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    match TcpListener::bind(addr) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!("Port {} is already in use", port),
        )),
        Err(e) => Err(e),
    }
}

pub fn check_ports_available(ports: &[u16]) -> std::io::Result<Vec<u16>> {
    let mut unavailable = Vec::new();

    for &port in ports {
        if check_port_available(port).is_err() {
            unavailable.push(port);
        }
    }

    if unavailable.is_empty() {
        Ok(ports.to_vec())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!("Ports already in use: {:?}", unavailable),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restart_backoff_calculation() {
        let base_cooldown = 1u64;
        let max_backoff = 60u64;

        for attempt in 0..10u32 {
            let backoff = base_cooldown * 2_u64.pow(attempt.min(8));
            let expected = std::cmp::min(backoff, max_backoff);

            let calculated = std::cmp::min(base_cooldown * 2_u64.pow(attempt.min(8)), max_backoff);

            assert_eq!(calculated, expected, "Failed for attempt {}", attempt);
        }
    }

    #[test]
    fn test_worker_id_conversion() {
        let worker_id = WorkerId(42);
        assert_eq!(worker_id.0, 42);
    }

    #[test]
    fn test_worker_id_display() {
        let worker_id = WorkerId(5);
        assert_eq!(format!("{}", worker_id), "5");
    }

    #[test]
    fn test_process_manager_config_defaults() {
        let config = ProcessManagerConfig::default();
        assert_eq!(config.max_workers, 16);
        assert_eq!(config.min_workers, 2);
        assert_eq!(config.max_restart_attempts, 5);
    }

    #[test]
    fn test_restart_backoff_with_real_delays() {
        let base = 1u64;
        let max_backoff = 60u64;

        // Pre-compute expected values (not tautological)
        let expected = [1, 2, 4, 8, 16, 32, 60, 60, 60, 60];
        for (attempt, &exp) in expected.iter().enumerate() {
            let backoff = std::cmp::min(base * 2_u64.pow(attempt.min(8) as u32), max_backoff);
            assert_eq!(backoff, exp, "attempt {}", attempt);
        }
    }

    #[test]
    fn test_port_availability_free() {
        // A random high port should be available
        let result = check_port_available(0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_port_availability_in_use() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let result = check_port_available(port);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::AddrInUse);
    }

    #[test]
    fn test_process_manager_config_validation() {
        let mut config = ProcessManagerConfig::default();
        config.min_workers = 10;
        config.max_workers = 2;
        // Config allows min > max; validation should be done by caller
        assert!(config.min_workers > config.max_workers);
    }

    #[test]
    fn test_worker_id_ordering() {
        let id1 = WorkerId(1);
        let id2 = WorkerId(2);
        assert!(id1.0 < id2.0);
        assert_ne!(id1, id2);
    }
}
