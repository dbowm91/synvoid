//! Worker process implementation.
//!
//! Handles HTTP request processing, TLS termination, connection management,
//! and WAF enforcement. Workers are spawned by the supervisor process and
//! communicate via IPC.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use ::metrics::{counter, gauge, histogram};
use tokio::sync::Mutex as TokioMutex;

use crate::config::ConfigManager;
use crate::process::ipc_signed::IpcSigner;
use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
use crate::static_files::minifier;
use crate::upload::yara_scanner::{YaraRulesSource, YaraScanner};
use crate::{DrainFlag, RunningFlag};

use crate::common::setup_panic_handler;

pub mod common;
pub mod connect;
pub mod context;
pub mod drain_state;
pub mod extension;
pub mod metrics;
pub mod traits;
pub mod unified_server;

mod connection;
mod image_poisoning;
mod response_builder;

pub use traits::{BaseWorkerState, WorkerLifecycle};

pub use unified_server::{
    run_unified_server_worker, setup_unified_server_panic_handler, UnifiedServerWorkerArgs,
};

pub fn setup_worker_panic_handler() {
    let worker_panic_log = format!(
        "{}/synvoid-worker-panic.log",
        std::env::temp_dir().display()
    );
    setup_panic_handler("WORKER", Some(&worker_panic_log));
}

#[derive(Clone)]
pub struct StaticWorkerArgs {
    pub worker_id: usize,
    pub config_path: PathBuf,
    pub supervisor_socket: PathBuf,
    pub static_worker_socket: PathBuf,
    pub log_level: Option<String>,
    pub ipc_key: Option<String>,
}

pub type CpuWorkerArgs = StaticWorkerArgs;

#[derive(Clone)]
struct StaticWorkerState {
    worker_id: usize,
    running: RunningFlag,
    stop_background_tasks: DrainFlag,
    ipc: Arc<TokioMutex<AsyncIpcStream>>,
    config_manager: Arc<std::sync::RwLock<ConfigManager>>,
    minifier_caches: Arc<std::sync::RwLock<HashMap<String, Arc<minifier::MinifierCache>>>>,
    compression_queue: Arc<std::sync::RwLock<Vec<CompressionTask>>>,
    cpu_task_limiter: Arc<CpuTaskLimiter>,
    yara_scanner: Option<Arc<YaraScanner>>,
}

impl StaticWorkerState {
    fn get_cache_stats(&self) -> (u64, u64) {
        let mut total_hits = 0u64;
        let mut total_misses = 0u64;

        if let Ok(caches) = self.minifier_caches.read() {
            for cache in caches.values() {
                total_hits += cache.cache_hits();
                total_misses += cache.cache_misses();
            }
        }

        (total_hits, total_misses)
    }
}

#[derive(Clone)]
struct CompressionTask {
    site_id: String,
    path: String,
    encoding: String,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    queued_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct CpuTaskLimits {
    max_active_global: usize,
    max_queue_global: usize,
    max_active_per_site: usize,
    max_queue_per_site: usize,
    max_payload_bytes: usize,
    max_output_bytes: usize,
}

const INLINE_SMALL_TASK_MAX_BYTES: usize = 64 * 1024;
static CPU_TASK_ACTIVE_MINIFY: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_ACTIVE_GET_COMPRESSED: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_ACTIVE_POISON_IMAGE: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_ACTIVE_YARA_SCAN: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_QUEUED_MINIFY: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_QUEUED_GET_COMPRESSED: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_QUEUED_POISON_IMAGE: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_QUEUED_YARA_SCAN: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_COMPLETED_MINIFY: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_COMPLETED_GET_COMPRESSED: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_COMPLETED_POISON_IMAGE: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_COMPLETED_YARA_SCAN: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_PAYLOAD_BYTES_IN_TOTAL: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_PAYLOAD_BYTES_OUT_TOTAL: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_TIMEOUT_TOTAL: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_SUBMITTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_FALLBACK_INLINE_SMALL_TOTAL: AtomicU64 = AtomicU64::new(0);
static STATIC_CPU_OFFLOAD_EVENT_LOOP_LAG_MS: AtomicU64 = AtomicU64::new(0);
static CPU_TASK_DURATION_SAMPLES: LazyLock<Mutex<HashMap<&'static str, VecDeque<u64>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
const CPU_TASK_DURATION_SAMPLE_SIZE: usize = 1000;

#[derive(Default)]
struct CpuTaskBackpressureState {
    active_global: usize,
    queued_global: usize,
    active_by_site: HashMap<String, usize>,
    queued_by_site: HashMap<String, usize>,
}

struct CpuTaskLimiter {
    limits: CpuTaskLimits,
    state: Mutex<CpuTaskBackpressureState>,
}

struct CpuTaskPermit {
    limiter: Arc<CpuTaskLimiter>,
    site_id: Option<String>,
}

impl Drop for CpuTaskPermit {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.limiter.state.lock() {
            guard.active_global = guard.active_global.saturating_sub(1);
            if let Some(site_id) = self.site_id.as_ref() {
                if let Some(site_active) = guard.active_by_site.get_mut(site_id) {
                    *site_active = site_active.saturating_sub(1);
                    if *site_active == 0 {
                        guard.active_by_site.remove(site_id);
                    }
                }
            }
        }
    }
}

impl CpuTaskLimiter {
    fn new(limits: CpuTaskLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(CpuTaskBackpressureState::default()),
        }
    }

    fn try_acquire(&self, site_id: Option<&str>) -> Result<(), &'static str> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| "CPU task limiter lock poisoned")?;

        guard.queued_global = guard.queued_global.saturating_add(1);
        if guard.queued_global > self.limits.max_queue_global {
            guard.queued_global = guard.queued_global.saturating_sub(1);
            return Err("Global CPU task queue limit exceeded");
        }

        if let Some(site) = site_id {
            let site_queued = guard.queued_by_site.entry(site.to_string()).or_default();
            *site_queued = site_queued.saturating_add(1);
            if *site_queued > self.limits.max_queue_per_site {
                *site_queued = site_queued.saturating_sub(1);
                if *site_queued == 0 {
                    guard.queued_by_site.remove(site);
                }
                guard.queued_global = guard.queued_global.saturating_sub(1);
                return Err("Per-site CPU task queue limit exceeded");
            }
        }

        if guard.active_global >= self.limits.max_active_global {
            if let Some(site) = site_id {
                if let Some(site_queued) = guard.queued_by_site.get_mut(site) {
                    *site_queued = site_queued.saturating_sub(1);
                    if *site_queued == 0 {
                        guard.queued_by_site.remove(site);
                    }
                }
            }
            guard.queued_global = guard.queued_global.saturating_sub(1);
            return Err("Global CPU task active limit exceeded");
        }

        if let Some(site) = site_id {
            if guard.active_by_site.get(site).copied().unwrap_or(0)
                >= self.limits.max_active_per_site
            {
                if let Some(site_queued) = guard.queued_by_site.get_mut(site) {
                    *site_queued = site_queued.saturating_sub(1);
                    if *site_queued == 0 {
                        guard.queued_by_site.remove(site);
                    }
                }
                guard.queued_global = guard.queued_global.saturating_sub(1);
                return Err("Per-site CPU task active limit exceeded");
            }
        }

        guard.active_global = guard.active_global.saturating_add(1);
        if let Some(site) = site_id {
            let site_active = guard.active_by_site.entry(site.to_string()).or_default();
            *site_active = site_active.saturating_add(1);
            if let Some(site_queued) = guard.queued_by_site.get_mut(site) {
                *site_queued = site_queued.saturating_sub(1);
                if *site_queued == 0 {
                    guard.queued_by_site.remove(site);
                }
            }
        }
        guard.queued_global = guard.queued_global.saturating_sub(1);
        Ok(())
    }
}

pub async fn run_static_worker(
    args: StaticWorkerArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ref level) = args.log_level {
        crate::log_controller::init_logging_with_dynamic_level(level);
    }

    tracing::info!(
        "CPU worker {} starting, config: {:?}, supervisor socket: {:?}",
        args.worker_id,
        args.config_path,
        args.supervisor_socket
    );

    let signer = match IpcSigner::try_from_env() {
        Some(s) => s,
        None => {
            tracing::warn!("No IPC session key found - CPU worker will use unsigned IPC");
            return Err("No IPC session key for CPU worker".into());
        }
    };
    let ipc = Arc::new(TokioMutex::new(
        connect::connect_to_supervisor_async_signed(
            &args.supervisor_socket,
            5,
            std::time::Duration::from_secs(2),
            "CPU worker",
            Arc::new(signer),
        )
        .await?,
    ));

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard
            .send(&crate::process::Message::StaticWorkerStarted {
                worker_id: args.worker_id,
                pid: std::process::id(),
            })
            .await?;
    }

    let mut config_manager = ConfigManager::new(args.config_path.clone());
    let main_config_path = args.config_path.join("main.toml");

    if let Err(e) = config_manager.load_main(&main_config_path) {
        tracing::warn!("Failed to load main config: {}, using defaults", e);
    }

    let main_config = config_manager.main.clone();
    config_manager.discover_sites();

    let running = RunningFlag::new();
    let stop_background_tasks = DrainFlag::new();
    let config_manager = Arc::new(std::sync::RwLock::new(config_manager));

    let minifier_caches: Arc<std::sync::RwLock<HashMap<String, Arc<minifier::MinifierCache>>>> =
        Arc::new(std::sync::RwLock::new(HashMap::new()));

    let compression_queue: Arc<std::sync::RwLock<Vec<CompressionTask>>> =
        Arc::new(std::sync::RwLock::new(Vec::new()));
    let cpu_task_limiter = Arc::new(CpuTaskLimiter::new(CpuTaskLimits {
        max_active_global: 128,
        max_queue_global: 1024,
        max_active_per_site: 32,
        max_queue_per_site: 256,
        max_payload_bytes: 64 * 1024 * 1024,
        max_output_bytes: 64 * 1024 * 1024,
    }));

    let state = StaticWorkerState {
        worker_id: args.worker_id,
        running: running.clone(),
        stop_background_tasks: stop_background_tasks.clone(),
        ipc: ipc.clone(),
        config_manager: config_manager.clone(),
        minifier_caches,
        compression_queue,
        cpu_task_limiter: cpu_task_limiter.clone(),
        yara_scanner: build_yara_scanner_from_main_config(&main_config),
    };

    response_builder::init_minifier_caches(&state, &main_config);

    let socket_path = args.static_worker_socket.clone();
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixListener;

        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => {
                tracing::info!("CPU worker listening on {}", socket_path.display());
                l
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to bind CPU worker socket {}: {}",
                    socket_path.display(),
                    e
                );
                return Err(Box::new(e));
            }
        };

        let socket_state = state.clone();
        use std::sync::atomic::{AtomicU32, Ordering};
        let active_connections = Arc::new(AtomicU32::new(0));
        const MAX_STATIC_CONNECTIONS: u32 = 100;

        std::thread::spawn(move || loop {
            if !socket_state.running.is_running() {
                break;
            }

            match listener.accept() {
                Ok((stream, _)) => {
                    if active_connections.load(Ordering::Relaxed) >= MAX_STATIC_CONNECTIONS {
                        tracing::debug!(
                            "CPU worker at max connections ({}), dropping",
                            MAX_STATIC_CONNECTIONS
                        );
                        drop(stream);
                        continue;
                    }
                    active_connections.fetch_add(1, Ordering::Relaxed);
                    let ipc = crate::process::IpcStream::new(stream);
                    let state = socket_state.clone();
                    let counter = active_connections.clone();
                    tokio::spawn(async move {
                        tokio::task::spawn_blocking(move || {
                            handle_minify_client_connection(ipc, state);
                        })
                        .await
                        .ok();
                        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            v.checked_sub(1)
                        });
                    });
                }
                Err(e) => {
                    tracing::debug!("CPU worker socket accept error: {}", e);
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        });
    }

    #[cfg(windows)]
    {
        let listener = crate::process::ipc::WindowsIpcListener::new("synvoid-static-worker");
        let socket_state = state.clone();
        use std::sync::atomic::{AtomicU32, Ordering};
        let active_connections = Arc::new(AtomicU32::new(0));
        const MAX_STATIC_CONNECTIONS: u32 = 100;

        std::thread::spawn(move || loop {
            if !socket_state.running.is_running() {
                break;
            }

            match listener.accept() {
                Ok(stream) => {
                    if active_connections.load(Ordering::Relaxed) >= MAX_STATIC_CONNECTIONS {
                        tracing::debug!(
                            "CPU worker at max connections ({}), dropping",
                            MAX_STATIC_CONNECTIONS
                        );
                        drop(stream);
                        continue;
                    }
                    active_connections.fetch_add(1, Ordering::Relaxed);
                    let ipc = crate::process::IpcStream::new(stream);
                    let state = socket_state.clone();
                    let counter = active_connections.clone();
                    tokio::spawn(async move {
                        tokio::task::spawn_blocking(move || {
                            handle_minify_client_connection(ipc, state);
                        })
                        .await
                        .ok();
                        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            v.checked_sub(1)
                        });
                    });
                }
                Err(e) => {
                    tracing::warn!("CPU worker pipe accept error: {}", e);
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            }

            std::thread::sleep(Duration::from_millis(10));
        });
    }

    let socket_handle: Option<tokio::task::JoinHandle<()>> = None;

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard
            .send(&crate::process::Message::StaticWorkerReady {
                worker_id: args.worker_id,
            })
            .await?;
    }

    tracing::info!("CPU worker {} ready", args.worker_id);

    let ipc_state = state.clone();
    let ipc_handle = tokio::spawn(async move {
        let mut cancelled_requests = HashSet::new();
        loop {
            if !ipc_state.running.is_running() {
                break;
            }

            let mut ipc = ipc_state.ipc.lock().await;
            match ipc.recv_with_timeout::<crate::process::Message>(50).await {
                Ok(Some(crate::process::Message::MasterShutdown {
                    graceful,
                    timeout_secs,
                })) => {
                    tracing::info!(
                        "CPU worker {} received shutdown signal (graceful: {}, timeout: {}s), stopping background tasks",
                        ipc_state.worker_id,
                        graceful,
                        timeout_secs
                    );

                    ipc_state.stop_background_tasks.start_drain();

                    response_builder::process_compression_queue(&ipc_state);
                    tracing::info!(
                        "CPU worker {} completed final cache refresh",
                        ipc_state.worker_id
                    );

                    let _ = ipc
                        .send(&crate::process::Message::StaticWorkerBackgroundTasksDone {
                            worker_id: ipc_state.worker_id,
                        })
                        .await;
                }
                Ok(Some(message)) => {
                    if let crate::process::Message::CpuTaskCancel {
                        request_id,
                        task_kind,
                    } = message
                    {
                        cancelled_requests.insert((request_id, task_kind));
                        continue;
                    }
                    if let Some((
                        request_id,
                        task_kind,
                        _priority,
                        policy,
                        deadline_unix_ms,
                        payload_size_limit,
                        output_size_limit,
                        file_payload_path,
                        payload,
                        is_legacy_shape,
                    )) = message.into_cpu_task_request_compat()
                    {
                        if cancelled_requests.remove(&(request_id, task_kind)) {
                            let response = deadline_timeout_error(
                                request_id,
                                task_kind,
                                "CPU task cancelled by client".to_string(),
                            );
                            let response = crate::process::Message::adapt_cpu_task_response_compat(
                                response,
                                request_id,
                                task_kind,
                                is_legacy_shape,
                            );
                            if let Err(e) = ipc.send(&response).await {
                                tracing::warn!(
                                    "Failed to send CPU worker cancellation response for request {}: {}",
                                    request_id,
                                    e
                                );
                            }
                            continue;
                        }
                        if is_legacy_shape {
                            match payload {
                                crate::process::CpuTaskPayload::Minify {
                                    site_id,
                                    path,
                                    encoding,
                                } => {
                                    response_builder::handle_minify_request(
                                        &ipc_state, request_id, site_id, path, encoding,
                                    )
                                    .await;
                                    continue;
                                }
                                crate::process::CpuTaskPayload::GetCompressed {
                                    site_id,
                                    path,
                                    encoding,
                                } => {
                                    response_builder::handle_compressed_request(
                                        &ipc_state, request_id, site_id, path, encoding,
                                    )
                                    .await;
                                    continue;
                                }
                                crate::process::CpuTaskPayload::PoisonImage {
                                    site_id,
                                    body,
                                    last_modified,
                                    level,
                                    intensity,
                                    seed,
                                    max_dimension,
                                    jpeg_quality,
                                } => {
                                    let poisoned = image_poisoning::poison_image_sync(
                                        &ipc_state,
                                        &site_id,
                                        body,
                                        last_modified,
                                        level,
                                        intensity,
                                        seed,
                                        max_dimension,
                                        jpeg_quality,
                                    );
                                    if let Err(e) = ipc
                                        .send(&crate::process::Message::PoisonImageResponse {
                                            request_id,
                                            poisoned_body: poisoned,
                                        })
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to send poison image response for request {}: {}",
                                            request_id,
                                            e
                                        );
                                    }
                                    continue;
                                }
                                crate::process::CpuTaskPayload::YaraScan { .. } => {
                                    // No legacy YARA-specific IPC response shape exists.
                                    // Route through generic CpuTask* response handling below.
                                }
                            }
                        }

                        let response = process_cpu_task_request_sync(
                            &ipc_state,
                            request_id,
                            task_kind,
                            policy,
                            deadline_unix_ms,
                            payload_size_limit,
                            output_size_limit,
                            file_payload_path,
                            payload,
                        );
                        let response = crate::process::Message::adapt_cpu_task_response_compat(
                            response,
                            request_id,
                            task_kind,
                            is_legacy_shape,
                        );
                        if let Err(e) = ipc.send(&response).await {
                            tracing::warn!(
                                "Failed to send CPU worker response for request {}: {}",
                                request_id,
                                e
                            );
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }
    });

    let queue_state = state.clone();
    let queue_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            if !queue_state.running.is_running() {
                break;
            }

            if queue_state.stop_background_tasks.is_draining() {
                tracing::info!(
                    "CPU worker {} queue handler stopping (background tasks disabled)",
                    queue_state.worker_id
                );
                break;
            }

            response_builder::process_compression_queue(&queue_state);
        }
    });

    let watch_state = state.clone();
    let watch_interval = main_config
        .static_config
        .as_ref()
        .and_then(|c| c.watch_interval_ms)
        .unwrap_or(5000);

    let watch_handle = tokio::spawn(async move {
        let watch_interval = Duration::from_millis(watch_interval);
        let mut interval = tokio::time::interval(watch_interval);
        let mut next_heartbeat_at = Instant::now() + watch_interval;

        loop {
            interval.tick().await;

            if !watch_state.running.is_running() {
                break;
            }

            if watch_state.stop_background_tasks.is_draining() {
                tracing::info!(
                    "CPU worker {} watch handler stopping (background tasks disabled)",
                    watch_state.worker_id
                );
                break;
            }

            let lag_ms = Instant::now()
                .saturating_duration_since(next_heartbeat_at)
                .as_millis() as u64;
            STATIC_CPU_OFFLOAD_EVENT_LOOP_LAG_MS.store(lag_ms, Ordering::Relaxed);
            let (worker_rss_bytes, _cpu_percent) = common::collect_current_process_usage();
            next_heartbeat_at += watch_interval;

            if let Ok(config) = watch_state.config_manager.read() {
                for (site_id, site) in config.sites.iter() {
                    let static_config = &site.r#static;
                    if !static_config.enabled.unwrap_or(false) {
                        continue;
                    }

                    if static_config.enable_file_watching.unwrap_or(true) {
                        for location in &static_config.locations {
                            let root = PathBuf::from(location.root.as_str());
                            if root.exists() {
                                response_builder::check_and_invalidate_cache(
                                    &watch_state,
                                    site_id,
                                    &root,
                                );
                            }
                        }
                    }
                }
            }

            let (cache_hits, cache_misses) = watch_state.get_cache_stats();

            let mut ipc = watch_state.ipc.lock().await;
            let _ = ipc
                .send(&crate::process::Message::StaticWorkerHeartbeat {
                    worker_id: watch_state.worker_id,
                    timestamp: crate::process::current_timestamp(),
                    static_cache_hits: cache_hits,
                    static_cache_misses: cache_misses,
                    cpu_offload_stats: snapshot_static_cpu_offload_stats(worker_rss_bytes),
                })
                .await;
        }
    });

    let config_path = args.config_path.clone();
    let running_for_reload = running.clone();
    let stop_bg_for_reload = stop_background_tasks.clone();
    let caches_for_reload = state.minifier_caches.clone();
    let queue_for_reload = state.compression_queue.clone();
    let cpu_task_limiter_for_reload = state.cpu_task_limiter.clone();
    let reload_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            interval.tick().await;

            if !running_for_reload.is_running() {
                break;
            }

            if stop_bg_for_reload.is_draining() {
                tracing::info!("CPU worker reload handler stopping (background tasks disabled)");
                break;
            }

            let mut cm = ConfigManager::new(config_path.clone());
            if cm.load_main(config_path.join("main.toml")).is_ok() {
                cm.discover_sites();
                let main_config = cm.main.clone();

                let dummy_ipc = {
                    let socket_name = if cfg!(windows) { "nul" } else { "dummy_reload" };
                    match crate::process::ipc_transport::IpcEndpoint::new(socket_name)
                        .connect()
                        .await
                    {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!("Failed to create dummy IPC for reload handler: {}", e);
                            continue;
                        }
                    }
                };

                let temp_state = StaticWorkerState {
                    worker_id: 0,
                    running: running_for_reload.clone(),
                    stop_background_tasks: stop_bg_for_reload.clone(),
                    ipc: Arc::new(TokioMutex::new(dummy_ipc)),
                    config_manager: Arc::new(std::sync::RwLock::new(cm)),
                    minifier_caches: caches_for_reload.clone(),
                    compression_queue: queue_for_reload.clone(),
                    cpu_task_limiter: cpu_task_limiter_for_reload.clone(),
                    yara_scanner: build_yara_scanner_from_main_config(&main_config),
                };
                response_builder::init_minifier_caches(&temp_state, &main_config);
            }
        }
    });

    tokio::select! {
        _ = ipc_handle => {}
        _ = queue_handle => {}
        _ = watch_handle => {}
        _ = reload_handle => {}
        _ = async {
            if let Some(handle) = socket_handle {
                let _ = handle.await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
    }

    running.stop();

    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    tracing::info!("CPU worker {} shutting down", args.worker_id);
    Ok(())
}

pub async fn run_cpu_worker(
    args: CpuWorkerArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_static_worker(args).await
}

/// Handle a CPU worker IPC connection (cross-platform).
///
/// Uses the sync `IpcStream` abstraction for framed message I/O on both
/// Unix (UnixStream) and Windows (named pipe as File).
fn handle_minify_client_connection(mut ipc: crate::process::IpcStream, state: StaticWorkerState) {
    let mut cancelled_requests = HashSet::new();
    loop {
        match ipc.try_recv() {
            Ok(Some(message)) => {
                if let crate::process::Message::CpuTaskCancel {
                    request_id,
                    task_kind,
                } = message
                {
                    cancelled_requests.insert((request_id, task_kind));
                    continue;
                }
                if let Some((
                    request_id,
                    task_kind,
                    _priority,
                    policy,
                    deadline_unix_ms,
                    payload_size_limit,
                    output_size_limit,
                    file_payload_path,
                    payload,
                    is_legacy_shape,
                )) = message.into_cpu_task_request_compat()
                {
                    if cancelled_requests.remove(&(request_id, task_kind)) {
                        let response = deadline_timeout_error(
                            request_id,
                            task_kind,
                            "CPU task cancelled by client".to_string(),
                        );
                        let response = crate::process::Message::adapt_cpu_task_response_compat(
                            response,
                            request_id,
                            task_kind,
                            is_legacy_shape,
                        );
                        if let Err(e) = ipc.send(&response) {
                            tracing::warn!(
                                "Failed to send CPU worker cancellation response for request {}: {}",
                                request_id,
                                e
                            );
                        }
                        continue;
                    }
                    let response = process_cpu_task_request_sync(
                        &state,
                        request_id,
                        task_kind,
                        policy,
                        deadline_unix_ms,
                        payload_size_limit,
                        output_size_limit,
                        file_payload_path,
                        payload,
                    );
                    let response = crate::process::Message::adapt_cpu_task_response_compat(
                        response,
                        request_id,
                        task_kind,
                        is_legacy_shape,
                    );
                    if let Err(e) = ipc.send(&response) {
                        tracing::warn!(
                            "Failed to send CPU worker response for request {}: {}",
                            request_id,
                            e
                        );
                    }
                }
            }
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }

        if !state.running.is_running() {
            break;
        }
    }
}

fn process_cpu_task_request_sync(
    state: &StaticWorkerState,
    request_id: u64,
    task_kind: crate::process::CpuTaskKind,
    policy: crate::process::CpuTaskPolicy,
    deadline_unix_ms: u64,
    payload_size_limit: u64,
    output_size_limit: u64,
    file_payload_path: Option<String>,
    payload: crate::process::CpuTaskPayload,
) -> crate::process::Message {
    let task_kind_label = cpu_task_kind_label(task_kind);
    if is_deadline_exceeded(deadline_unix_ms) {
        CPU_TASK_TIMEOUT_TOTAL.fetch_add(1, Ordering::Relaxed);
        counter!(
            "synvoid.static.cpu_offload.task_timeouts",
            "task_kind" => task_kind_label
        )
        .increment(1);
        return deadline_timeout_error(
            request_id,
            task_kind,
            "CPU task deadline exceeded before execution".to_string(),
        );
    }
    let effective_payload_limit =
        payload_size_limit.min(state.cpu_task_limiter.limits.max_payload_bytes as u64) as usize;
    let payload = match apply_file_backed_payload(
        payload,
        file_payload_path.as_deref(),
        effective_payload_limit,
    ) {
        Ok(p) => p,
        Err(msg) => {
            return crate::process::Message::CpuTaskError {
                request_id,
                task_kind,
                code: crate::process::CpuTaskErrorCode::InvalidRequest,
                message: msg,
                retryable: false,
            };
        }
    };

    let payload_size = estimate_cpu_task_payload_size(&payload);
    if payload_size > effective_payload_limit {
        return crate::process::Message::CpuTaskError {
            request_id,
            task_kind,
            code: crate::process::CpuTaskErrorCode::PayloadTooLarge,
            message: format!(
                "CPU task payload too large: {} bytes > {} bytes",
                payload_size, effective_payload_limit
            ),
            retryable: false,
        };
    }

    let site_id = cpu_task_site_id(&payload);
    increment_task_kind_queued(task_kind);
    gauge!(
        "synvoid.static.cpu_offload.queue_depth",
        "task_kind" => task_kind_label
    )
    .increment(1.0);
    let _permit = match state.cpu_task_limiter.try_acquire(site_id.as_deref()) {
        Ok(()) => Some(CpuTaskPermit {
            limiter: state.cpu_task_limiter.clone(),
            site_id,
        }),
        Err(backpressure_err) => {
            if matches!(
                policy,
                crate::process::CpuTaskPolicy::DegradeToInlineSmallOnly
            ) && payload_size <= INLINE_SMALL_TASK_MAX_BYTES
            {
                tracing::warn!(
                    "CPU task request {} saturated offload queue; degrading to inline small-task execution ({} bytes)",
                    request_id,
                    payload_size
                );
                CPU_TASK_FALLBACK_INLINE_SMALL_TOTAL.fetch_add(1, Ordering::Relaxed);
                None
            } else {
                decrement_task_kind_queued(task_kind);
                gauge!(
                    "synvoid.static.cpu_offload.queue_depth",
                    "task_kind" => task_kind_label
                )
                .decrement(1.0);
                return cpu_task_backpressure_error(
                    request_id,
                    task_kind,
                    policy,
                    backpressure_err,
                );
            }
        }
    };
    decrement_task_kind_queued(task_kind);
    gauge!(
        "synvoid.static.cpu_offload.queue_depth",
        "task_kind" => task_kind_label
    )
    .decrement(1.0);

    CPU_TASK_SUBMITTED_TOTAL.fetch_add(1, Ordering::Relaxed);

    increment_task_kind_active(task_kind);
    gauge!(
        "synvoid.static.cpu_offload.active_tasks",
        "task_kind" => task_kind_label
    )
    .increment(1.0);
    let started = Instant::now();
    CPU_TASK_PAYLOAD_BYTES_IN_TOTAL.fetch_add(payload_size as u64, Ordering::Relaxed);
    counter!(
        "synvoid.static.cpu_offload.payload_bytes_in_total",
        "task_kind" => task_kind_label
    )
    .increment(payload_size as u64);

    let mut response = match payload {
        crate::process::CpuTaskPayload::Minify {
            site_id,
            path,
            encoding,
        } => match response_builder::process_minify_request(
            state, request_id, site_id, path, encoding,
        ) {
            Ok(crate::process::Message::MinifyResponse {
                site_id,
                path,
                content,
                content_type,
                encoding,
                queued_encodings,
                ..
            }) => {
                let response = crate::process::Message::CpuTaskResponse {
                    request_id,
                    task_kind,
                    result: crate::process::CpuTaskResult::Minify {
                        site_id,
                        path,
                        content,
                        content_type,
                        encoding,
                        queued_encodings,
                    },
                };
                if estimate_cpu_task_output_size(&response)
                    > output_size_limit.min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                        as usize
                {
                    crate::process::Message::CpuTaskError {
                        request_id,
                        task_kind,
                        code: crate::process::CpuTaskErrorCode::PayloadTooLarge,
                        message: "CPU task output exceeds configured cap".to_string(),
                        retryable: false,
                    }
                } else {
                    response
                }
            }
            Ok(_) => crate::process::Message::CpuTaskError {
                request_id,
                task_kind,
                code: crate::process::CpuTaskErrorCode::InternalError,
                message: "Unexpected minify response shape".to_string(),
                retryable: false,
            },
            Err(error) => crate::process::Message::CpuTaskError {
                request_id,
                task_kind,
                code: crate::process::CpuTaskErrorCode::InternalError,
                message: error,
                retryable: false,
            },
        },
        crate::process::CpuTaskPayload::GetCompressed {
            site_id,
            path,
            encoding,
        } => match response_builder::process_compressed_request(
            state, request_id, site_id, path, encoding,
        ) {
            Ok(crate::process::Message::GetCompressedResponse { content, .. }) => {
                let response = crate::process::Message::CpuTaskResponse {
                    request_id,
                    task_kind,
                    result: crate::process::CpuTaskResult::GetCompressed { content },
                };
                if estimate_cpu_task_output_size(&response)
                    > output_size_limit.min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                        as usize
                {
                    crate::process::Message::CpuTaskError {
                        request_id,
                        task_kind,
                        code: crate::process::CpuTaskErrorCode::PayloadTooLarge,
                        message: "CPU task output exceeds configured cap".to_string(),
                        retryable: false,
                    }
                } else {
                    response
                }
            }
            Ok(_) => crate::process::Message::CpuTaskError {
                request_id,
                task_kind,
                code: crate::process::CpuTaskErrorCode::InternalError,
                message: "Unexpected compressed response shape".to_string(),
                retryable: false,
            },
            Err(error) => crate::process::Message::CpuTaskError {
                request_id,
                task_kind,
                code: crate::process::CpuTaskErrorCode::InternalError,
                message: error,
                retryable: false,
            },
        },
        crate::process::CpuTaskPayload::PoisonImage {
            site_id,
            body,
            last_modified,
            level,
            intensity,
            seed,
            max_dimension,
            jpeg_quality,
        } => {
            let poisoned_body = image_poisoning::poison_image_sync(
                state,
                &site_id,
                body,
                last_modified,
                level,
                intensity,
                seed,
                max_dimension,
                jpeg_quality,
            );
            let response = crate::process::Message::CpuTaskResponse {
                request_id,
                task_kind,
                result: crate::process::CpuTaskResult::PoisonImage { poisoned_body },
            };
            if estimate_cpu_task_output_size(&response)
                > output_size_limit.min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                    as usize
            {
                crate::process::Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: crate::process::CpuTaskErrorCode::PayloadTooLarge,
                    message: "CPU task output exceeds configured cap".to_string(),
                    retryable: false,
                }
            } else {
                response
            }
        }
        crate::process::CpuTaskPayload::YaraScan {
            site_id: _site_id,
            body,
            excluded_categories,
        } => {
            let Some(scanner) = state.yara_scanner.as_ref() else {
                return crate::process::Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: crate::process::CpuTaskErrorCode::InvalidRequest,
                    message: "YARA scanner is not enabled for static CPU offload worker"
                        .to_string(),
                    retryable: false,
                };
            };

            let excluded_refs: Vec<&str> = excluded_categories.iter().map(|s| s.as_str()).collect();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match runtime {
                Ok(rt) => match rt.block_on(scanner.scan_bytes(&body, &excluded_refs)) {
                    Ok(matches) => {
                        let response = crate::process::Message::CpuTaskResponse {
                            request_id,
                            task_kind,
                            result: crate::process::CpuTaskResult::YaraScan {
                                matches: matches.into_iter().map(|m| m.rule_name).collect(),
                            },
                        };
                        if estimate_cpu_task_output_size(&response)
                            > output_size_limit
                                .min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                                as usize
                        {
                            crate::process::Message::CpuTaskError {
                                request_id,
                                task_kind,
                                code: crate::process::CpuTaskErrorCode::PayloadTooLarge,
                                message: "CPU task output exceeds configured cap".to_string(),
                                retryable: false,
                            }
                        } else {
                            response
                        }
                    }
                    Err(e) => crate::process::Message::CpuTaskError {
                        request_id,
                        task_kind,
                        code: crate::process::CpuTaskErrorCode::InternalError,
                        message: format!("YARA scan failed: {}", e),
                        retryable: false,
                    },
                },
                Err(e) => crate::process::Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: crate::process::CpuTaskErrorCode::InternalError,
                    message: format!("Failed to create YARA scan runtime: {}", e),
                    retryable: false,
                },
            }
        }
    };

    if is_deadline_exceeded(deadline_unix_ms) {
        response = match response {
            crate::process::Message::CpuTaskResponse { .. } => {
                CPU_TASK_TIMEOUT_TOTAL.fetch_add(1, Ordering::Relaxed);
                counter!(
                    "synvoid.static.cpu_offload.task_timeouts",
                    "task_kind" => task_kind_label
                )
                .increment(1);
                deadline_timeout_error(
                    request_id,
                    task_kind,
                    "CPU task deadline exceeded during execution".to_string(),
                )
            }
            other => other,
        };
    }

    let task_duration = started.elapsed();
    histogram!(
        "synvoid.static.cpu_offload.task_duration_seconds",
        "task_kind" => task_kind_label
    )
    .record(task_duration.as_secs_f64());
    record_cpu_task_duration(task_kind, task_duration.as_millis() as u64);
    decrement_task_kind_active(task_kind);
    gauge!(
        "synvoid.static.cpu_offload.active_tasks",
        "task_kind" => task_kind_label
    )
    .decrement(1.0);

    if let crate::process::Message::CpuTaskError { code, .. } = &response {
        match code {
            crate::process::CpuTaskErrorCode::QueueSaturated
            | crate::process::CpuTaskErrorCode::PayloadTooLarge
            | crate::process::CpuTaskErrorCode::InvalidRequest => {
                CPU_TASK_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                counter!(
                    "synvoid.static.cpu_offload.task_rejections",
                    "task_kind" => task_kind_label
                )
                .increment(1);
            }
            crate::process::CpuTaskErrorCode::Timeout => {
                CPU_TASK_TIMEOUT_TOTAL.fetch_add(1, Ordering::Relaxed);
                counter!(
                    "synvoid.static.cpu_offload.task_timeouts",
                    "task_kind" => task_kind_label
                )
                .increment(1);
            }
            crate::process::CpuTaskErrorCode::InternalError => {
                CPU_TASK_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
                counter!(
                    "synvoid.static.cpu_offload.task_failures",
                    "task_kind" => task_kind_label
                )
                .increment(1);
            }
        }
    } else {
        let output_size = estimate_cpu_task_output_size(&response) as u64;
        CPU_TASK_PAYLOAD_BYTES_OUT_TOTAL.fetch_add(output_size, Ordering::Relaxed);
        counter!(
            "synvoid.static.cpu_offload.payload_bytes_out_total",
            "task_kind" => task_kind_label
        )
        .increment(output_size);
        increment_task_kind_completed(task_kind);
    }

    response
}

fn is_deadline_exceeded(deadline_unix_ms: u64) -> bool {
    if deadline_unix_ms == 0 {
        return false;
    }
    let now_unix_ms = crate::utils::current_timestamp().saturating_mul(1000);
    now_unix_ms > deadline_unix_ms
}

fn deadline_timeout_error(
    request_id: u64,
    task_kind: crate::process::CpuTaskKind,
    message: String,
) -> crate::process::Message {
    crate::process::Message::CpuTaskError {
        request_id,
        task_kind,
        code: crate::process::CpuTaskErrorCode::Timeout,
        message,
        retryable: false,
    }
}

fn apply_file_backed_payload(
    payload: crate::process::CpuTaskPayload,
    file_payload_path: Option<&str>,
    effective_payload_limit: usize,
) -> Result<crate::process::CpuTaskPayload, String> {
    let Some(path_str) = file_payload_path else {
        return Ok(payload);
    };

    let raw_path = PathBuf::from(path_str);
    let canonical_path =
        fs::canonicalize(&raw_path).map_err(|e| format!("Invalid file_payload_path: {}", e))?;

    let temp_root = std::env::temp_dir();
    let canonical_temp_root = fs::canonicalize(&temp_root).unwrap_or(temp_root.clone());
    if !canonical_path.starts_with(&canonical_temp_root) && !canonical_path.starts_with(&temp_root)
    {
        return Err("file_payload_path must be under temp_dir".to_string());
    }
    let file_name = canonical_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "file_payload_path missing filename".to_string())?;
    if !file_name.starts_with("synvoid-cpu-task-") {
        return Err("file_payload_path missing trusted prefix".to_string());
    }

    let metadata = fs::metadata(&canonical_path)
        .map_err(|e| format!("Failed to read file_payload metadata: {}", e))?;
    let file_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if file_len > effective_payload_limit {
        return Err(format!(
            "file_payload exceeds limit: {} > {}",
            file_len, effective_payload_limit
        ));
    }
    let bytes = fs::read(&canonical_path)
        .map_err(|e| format!("Failed to read file_payload bytes: {}", e))?;
    let _ = fs::remove_file(&canonical_path);

    match payload {
        crate::process::CpuTaskPayload::PoisonImage {
            site_id,
            body,
            last_modified,
            level,
            intensity,
            seed,
            max_dimension,
            jpeg_quality,
        } => {
            if !body.is_empty() {
                return Err(
                    "PoisonImage payload must use either inline body or file payload, not both"
                        .to_string(),
                );
            }
            Ok(crate::process::CpuTaskPayload::PoisonImage {
                site_id,
                body: bytes,
                last_modified,
                level,
                intensity,
                seed,
                max_dimension,
                jpeg_quality,
            })
        }
        crate::process::CpuTaskPayload::YaraScan {
            site_id,
            body,
            excluded_categories,
        } => {
            if !body.is_empty() {
                return Err(
                    "YaraScan payload must use either inline body or file payload, not both"
                        .to_string(),
                );
            }
            Ok(crate::process::CpuTaskPayload::YaraScan {
                site_id,
                body: bytes,
                excluded_categories,
            })
        }
        _ => Err(
            "file_payload_path is currently supported only for PoisonImage and YaraScan"
                .to_string(),
        ),
    }
}

fn cpu_task_backpressure_error(
    request_id: u64,
    task_kind: crate::process::CpuTaskKind,
    policy: crate::process::CpuTaskPolicy,
    message: &str,
) -> crate::process::Message {
    CPU_TASK_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
    counter!(
        "synvoid.static.cpu_offload.task_rejections",
        "task_kind" => cpu_task_kind_label(task_kind)
    )
    .increment(1);
    if matches!(policy, crate::process::CpuTaskPolicy::FailOpenWithLog) {
        tracing::warn!(
            "CPU task backpressure fail-open path triggered for request {} kind {:?}: {}",
            request_id,
            task_kind,
            message
        );
    }
    let retryable = !matches!(policy, crate::process::CpuTaskPolicy::FailClosed);
    crate::process::Message::CpuTaskError {
        request_id,
        task_kind,
        code: crate::process::CpuTaskErrorCode::QueueSaturated,
        message: message.to_string(),
        retryable,
    }
}

fn snapshot_static_cpu_offload_stats(
    worker_rss_bytes: u64,
) -> crate::process::StaticCpuOffloadStats {
    crate::process::StaticCpuOffloadStats {
        queued_minify: CPU_TASK_QUEUED_MINIFY.load(Ordering::Relaxed),
        queued_get_compressed: CPU_TASK_QUEUED_GET_COMPRESSED.load(Ordering::Relaxed),
        queued_poison_image: CPU_TASK_QUEUED_POISON_IMAGE.load(Ordering::Relaxed),
        queued_yara_scan: CPU_TASK_QUEUED_YARA_SCAN.load(Ordering::Relaxed),
        active_minify: CPU_TASK_ACTIVE_MINIFY.load(Ordering::Relaxed),
        active_get_compressed: CPU_TASK_ACTIVE_GET_COMPRESSED.load(Ordering::Relaxed),
        active_poison_image: CPU_TASK_ACTIVE_POISON_IMAGE.load(Ordering::Relaxed),
        active_yara_scan: CPU_TASK_ACTIVE_YARA_SCAN.load(Ordering::Relaxed),
        completed_minify: CPU_TASK_COMPLETED_MINIFY.load(Ordering::Relaxed),
        completed_get_compressed: CPU_TASK_COMPLETED_GET_COMPRESSED.load(Ordering::Relaxed),
        completed_poison_image: CPU_TASK_COMPLETED_POISON_IMAGE.load(Ordering::Relaxed),
        completed_yara_scan: CPU_TASK_COMPLETED_YARA_SCAN.load(Ordering::Relaxed),
        payload_bytes_in_total: CPU_TASK_PAYLOAD_BYTES_IN_TOTAL.load(Ordering::Relaxed),
        payload_bytes_out_total: CPU_TASK_PAYLOAD_BYTES_OUT_TOTAL.load(Ordering::Relaxed),
        rejected_total: CPU_TASK_REJECTED_TOTAL.load(Ordering::Relaxed),
        timeout_total: CPU_TASK_TIMEOUT_TOTAL.load(Ordering::Relaxed),
        failed_total: CPU_TASK_FAILED_TOTAL.load(Ordering::Relaxed),
        submitted_total: CPU_TASK_SUBMITTED_TOTAL.load(Ordering::Relaxed),
        fallback_inline_small_total: CPU_TASK_FALLBACK_INLINE_SMALL_TOTAL.load(Ordering::Relaxed),
        task_duration_ms: summarize_cpu_task_durations(),
        event_loop_lag_ms: STATIC_CPU_OFFLOAD_EVENT_LOOP_LAG_MS.load(Ordering::Relaxed),
        worker_rss_bytes,
    }
}

fn increment_task_kind_queued(task_kind: crate::process::CpuTaskKind) {
    match task_kind {
        crate::process::CpuTaskKind::Minify => {
            CPU_TASK_QUEUED_MINIFY.fetch_add(1, Ordering::Relaxed);
        }
        crate::process::CpuTaskKind::GetCompressed => {
            CPU_TASK_QUEUED_GET_COMPRESSED.fetch_add(1, Ordering::Relaxed);
        }
        crate::process::CpuTaskKind::PoisonImage => {
            CPU_TASK_QUEUED_POISON_IMAGE.fetch_add(1, Ordering::Relaxed);
        }
        crate::process::CpuTaskKind::YaraScan => {
            CPU_TASK_QUEUED_YARA_SCAN.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

fn decrement_task_kind_queued(task_kind: crate::process::CpuTaskKind) {
    match task_kind {
        crate::process::CpuTaskKind::Minify => {
            let _ =
                CPU_TASK_QUEUED_MINIFY
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        crate::process::CpuTaskKind::GetCompressed => {
            let _ = CPU_TASK_QUEUED_GET_COMPRESSED.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
        crate::process::CpuTaskKind::PoisonImage => {
            let _ = CPU_TASK_QUEUED_POISON_IMAGE.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
        crate::process::CpuTaskKind::YaraScan => {
            let _ =
                CPU_TASK_QUEUED_YARA_SCAN
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        _ => {}
    }
}

fn increment_task_kind_active(task_kind: crate::process::CpuTaskKind) {
    match task_kind {
        crate::process::CpuTaskKind::Minify => {
            CPU_TASK_ACTIVE_MINIFY.fetch_add(1, Ordering::Relaxed);
        }
        crate::process::CpuTaskKind::GetCompressed => {
            CPU_TASK_ACTIVE_GET_COMPRESSED.fetch_add(1, Ordering::Relaxed);
        }
        crate::process::CpuTaskKind::PoisonImage => {
            CPU_TASK_ACTIVE_POISON_IMAGE.fetch_add(1, Ordering::Relaxed);
        }
        crate::process::CpuTaskKind::YaraScan => {
            CPU_TASK_ACTIVE_YARA_SCAN.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

fn decrement_task_kind_active(task_kind: crate::process::CpuTaskKind) {
    match task_kind {
        crate::process::CpuTaskKind::Minify => {
            let _ =
                CPU_TASK_ACTIVE_MINIFY
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        crate::process::CpuTaskKind::GetCompressed => {
            let _ = CPU_TASK_ACTIVE_GET_COMPRESSED.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
        crate::process::CpuTaskKind::PoisonImage => {
            let _ = CPU_TASK_ACTIVE_POISON_IMAGE.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
        crate::process::CpuTaskKind::YaraScan => {
            let _ =
                CPU_TASK_ACTIVE_YARA_SCAN
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        _ => {}
    }
}

fn increment_task_kind_completed(task_kind: crate::process::CpuTaskKind) {
    match task_kind {
        crate::process::CpuTaskKind::Minify => {
            CPU_TASK_COMPLETED_MINIFY.fetch_add(1, Ordering::Relaxed);
        }
        crate::process::CpuTaskKind::GetCompressed => {
            CPU_TASK_COMPLETED_GET_COMPRESSED.fetch_add(1, Ordering::Relaxed);
        }
        crate::process::CpuTaskKind::PoisonImage => {
            CPU_TASK_COMPLETED_POISON_IMAGE.fetch_add(1, Ordering::Relaxed);
        }
        crate::process::CpuTaskKind::YaraScan => {
            CPU_TASK_COMPLETED_YARA_SCAN.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

fn cpu_task_kind_label(task_kind: crate::process::CpuTaskKind) -> &'static str {
    match task_kind {
        crate::process::CpuTaskKind::Minify => "minify",
        crate::process::CpuTaskKind::GetCompressed => "get_compressed",
        crate::process::CpuTaskKind::PoisonImage => "poison_image",
        crate::process::CpuTaskKind::YaraScan => "yara_scan",
        crate::process::CpuTaskKind::WasmExecute => "wasm_execute",
        crate::process::CpuTaskKind::ServerlessInvoke => "serverless_invoke",
    }
}

fn record_cpu_task_duration(task_kind: crate::process::CpuTaskKind, duration_ms: u64) {
    let task_kind_label = cpu_task_kind_label(task_kind);
    let mut samples = CPU_TASK_DURATION_SAMPLES
        .lock()
        .expect("cpu task duration samples lock");
    let phase_samples = samples
        .entry(task_kind_label)
        .or_insert_with(|| VecDeque::with_capacity(CPU_TASK_DURATION_SAMPLE_SIZE));
    if phase_samples.len() >= CPU_TASK_DURATION_SAMPLE_SIZE {
        phase_samples.pop_front();
    }
    phase_samples.push_back(duration_ms);
}

fn summarize_timing_samples(samples: &[u64]) -> crate::metrics::TimingStatsPayload {
    if samples.is_empty() {
        return crate::metrics::TimingStatsPayload::default();
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let sum: u64 = sorted.iter().sum();
    let avg = sum as f64 / sorted.len() as f64;
    let p50 = sorted[sorted.len() / 2] as f64;
    let p95 = sorted[(sorted.len() as f64 * 0.95) as usize] as f64;
    let p99 = sorted[((sorted.len() as f64 * 0.99) as usize).min(sorted.len() - 1)] as f64;

    crate::metrics::TimingStatsPayload {
        avg_ms: avg,
        p50_ms: p50,
        p95_ms: p95,
        p99_ms: p99,
    }
}

fn summarize_cpu_task_durations() -> HashMap<String, crate::metrics::TimingStatsPayload> {
    let samples = CPU_TASK_DURATION_SAMPLES
        .lock()
        .expect("cpu task duration samples lock");
    let mut summary = HashMap::new();

    for (task_kind, durations) in samples.iter() {
        let durations: Vec<u64> = durations.iter().copied().collect();
        summary.insert(
            (*task_kind).to_string(),
            summarize_timing_samples(&durations),
        );
    }

    summary
}

fn cpu_task_site_id(payload: &crate::process::CpuTaskPayload) -> Option<String> {
    match payload {
        crate::process::CpuTaskPayload::Minify { site_id, .. }
        | crate::process::CpuTaskPayload::GetCompressed { site_id, .. }
        | crate::process::CpuTaskPayload::PoisonImage { site_id, .. }
        | crate::process::CpuTaskPayload::YaraScan { site_id, .. } => Some(site_id.clone()),
    }
}

fn estimate_cpu_task_payload_size(payload: &crate::process::CpuTaskPayload) -> usize {
    match payload {
        crate::process::CpuTaskPayload::Minify {
            site_id,
            path,
            encoding,
        } => site_id.len() + path.len() + encoding.as_ref().map_or(0, |v| v.len()),
        crate::process::CpuTaskPayload::GetCompressed {
            site_id,
            path,
            encoding,
        } => site_id.len() + path.len() + encoding.len(),
        crate::process::CpuTaskPayload::PoisonImage {
            site_id,
            body,
            last_modified,
            level,
            ..
        } => {
            site_id.len()
                + body.len()
                + last_modified.as_ref().map_or(0, |v| v.len())
                + level.as_ref().map_or(0, |v| v.len())
        }
        crate::process::CpuTaskPayload::YaraScan {
            site_id,
            body,
            excluded_categories,
        } => {
            site_id.len()
                + body.len()
                + excluded_categories
                    .iter()
                    .map(std::string::String::len)
                    .sum::<usize>()
        }
    }
}

fn estimate_cpu_task_output_size(message: &crate::process::Message) -> usize {
    match message {
        crate::process::Message::CpuTaskResponse { result, .. } => match result {
            crate::process::CpuTaskResult::Minify {
                content,
                content_type,
                encoding,
                queued_encodings,
                site_id,
                path,
            } => {
                site_id.len()
                    + path.len()
                    + content.len()
                    + content_type.len()
                    + encoding.as_ref().map_or(0, |v| v.len())
                    + queued_encodings.iter().map(|e| e.len()).sum::<usize>()
            }
            crate::process::CpuTaskResult::GetCompressed { content } => content.len(),
            crate::process::CpuTaskResult::PoisonImage { poisoned_body } => poisoned_body.len(),
            crate::process::CpuTaskResult::YaraScan { matches } => {
                matches.iter().map(std::string::String::len).sum::<usize>()
            }
        },
        crate::process::Message::CpuTaskError { message, .. } => message.len(),
        _ => 0,
    }
}

fn build_yara_scanner_from_main_config(
    main_config: &crate::config::MainConfig,
) -> Option<Arc<YaraScanner>> {
    let defaults = &main_config.defaults.upload;
    if !defaults.scan_with_yara {
        return None;
    }
    let source = YaraRulesSource::from_config(
        defaults
            .yara_rules_dir
            .clone()
            .map(std::path::PathBuf::from),
        true,
    )
    .unwrap_or(YaraRulesSource::Bundled);
    match YaraScanner::with_timeout(source, defaults.yara_timeout_ms, 3, 100 * 1024 * 1024) {
        Ok(scanner) => Some(Arc::new(scanner)),
        Err(e) => {
            tracing::warn!("Failed to initialize static-worker YARA scanner: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::site::SiteStaticConfig;
    use crate::static_files::minifier::{
        CacheEntry, CacheKey, ContentType, Encoding, MinifierCache, MinifierConfig,
    };
    use bytes::Bytes;
    use std::io::Write;
    use std::sync::Arc;
    use std::time::{Instant, SystemTime};
    use tempfile::{Builder, NamedTempFile};

    #[test]
    fn test_apply_file_backed_payload_poison_image_success_and_cleanup() {
        let mut temp_file = Builder::new()
            .prefix("synvoid-cpu-task-")
            .tempfile_in(std::env::temp_dir())
            .expect("create temp payload file");
        temp_file
            .write_all(b"payload-bytes")
            .expect("write payload bytes");
        let payload_path = temp_file.path().to_string_lossy().to_string();

        let payload = crate::process::CpuTaskPayload::PoisonImage {
            site_id: "site-a".to_string(),
            body: Vec::new(),
            last_modified: None,
            level: None,
            intensity: None,
            seed: None,
            max_dimension: None,
            jpeg_quality: None,
        };

        let updated =
            apply_file_backed_payload(payload, Some(&payload_path), 1024).expect("apply payload");
        drop(temp_file);

        match updated {
            crate::process::CpuTaskPayload::PoisonImage { body, .. } => {
                assert_eq!(body, b"payload-bytes");
            }
            _ => panic!("unexpected payload variant"),
        }

        assert!(!PathBuf::from(&payload_path).exists());
    }

    #[test]
    fn test_apply_file_backed_payload_rejects_untrusted_prefix() {
        let mut temp_file = NamedTempFile::new_in(std::env::temp_dir()).expect("create temp file");
        temp_file.write_all(b"data").expect("write data");
        let payload_path = temp_file.path().to_string_lossy().to_string();

        let payload = crate::process::CpuTaskPayload::PoisonImage {
            site_id: "site-a".to_string(),
            body: Vec::new(),
            last_modified: None,
            level: None,
            intensity: None,
            seed: None,
            max_dimension: None,
            jpeg_quality: None,
        };

        let result = apply_file_backed_payload(payload, Some(&payload_path), 1024);
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_file_backed_payload_rejects_oversized_file() {
        let mut temp_file = Builder::new()
            .prefix("synvoid-cpu-task-")
            .tempfile_in(std::env::temp_dir())
            .expect("create temp payload file");
        temp_file.write_all(b"1234567890").expect("write data");
        let payload_path = temp_file.path().to_string_lossy().to_string();

        let payload = crate::process::CpuTaskPayload::PoisonImage {
            site_id: "site-a".to_string(),
            body: Vec::new(),
            last_modified: None,
            level: None,
            intensity: None,
            seed: None,
            max_dimension: None,
            jpeg_quality: None,
        };

        let result = apply_file_backed_payload(payload, Some(&payload_path), 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_file_backed_payload_yara_scan_success_and_cleanup() {
        let mut temp_file = Builder::new()
            .prefix("synvoid-cpu-task-")
            .tempfile_in(std::env::temp_dir())
            .expect("create temp payload file");
        temp_file
            .write_all(b"yara-bytes")
            .expect("write payload bytes");
        let payload_path = temp_file.path().to_string_lossy().to_string();

        let payload = crate::process::CpuTaskPayload::YaraScan {
            site_id: "site-a".to_string(),
            body: Vec::new(),
            excluded_categories: vec!["archive".to_string()],
        };

        let updated =
            apply_file_backed_payload(payload, Some(&payload_path), 1024).expect("apply payload");
        drop(temp_file);

        match updated {
            crate::process::CpuTaskPayload::YaraScan {
                body,
                excluded_categories,
                ..
            } => {
                assert_eq!(body, b"yara-bytes");
                assert_eq!(excluded_categories, vec!["archive".to_string()]);
            }
            _ => panic!("unexpected payload variant"),
        }

        assert!(!PathBuf::from(&payload_path).exists());
    }

    #[test]
    fn test_cpu_task_backpressure_error_fail_closed_is_not_retryable() {
        let message = cpu_task_backpressure_error(
            7,
            crate::process::CpuTaskKind::YaraScan,
            crate::process::CpuTaskPolicy::FailClosed,
            "queue saturated",
        );

        match message {
            crate::process::Message::CpuTaskError {
                request_id,
                task_kind,
                code,
                retryable,
                ..
            } => {
                assert_eq!(request_id, 7);
                assert_eq!(task_kind, crate::process::CpuTaskKind::YaraScan);
                assert_eq!(code, crate::process::CpuTaskErrorCode::QueueSaturated);
                assert!(!retryable);
            }
            _ => panic!("expected CpuTaskError"),
        }
    }

    #[test]
    fn test_cpu_task_backpressure_error_fail_open_is_retryable() {
        let message = cpu_task_backpressure_error(
            8,
            crate::process::CpuTaskKind::WasmExecute,
            crate::process::CpuTaskPolicy::FailOpenWithLog,
            "global queue full",
        );

        match message {
            crate::process::Message::CpuTaskError {
                request_id,
                task_kind,
                code,
                retryable,
                ..
            } => {
                assert_eq!(request_id, 8);
                assert_eq!(task_kind, crate::process::CpuTaskKind::WasmExecute);
                assert_eq!(code, crate::process::CpuTaskErrorCode::QueueSaturated);
                assert!(retryable);
            }
            _ => panic!("expected CpuTaskError"),
        }
    }

    #[test]
    fn test_cpu_task_backpressure_error_skip_transform_is_retryable() {
        let message = cpu_task_backpressure_error(
            9,
            crate::process::CpuTaskKind::Minify,
            crate::process::CpuTaskPolicy::SkipTransform,
            "site queue full",
        );

        match message {
            crate::process::Message::CpuTaskError {
                request_id,
                task_kind,
                code,
                retryable,
                ..
            } => {
                assert_eq!(request_id, 9);
                assert_eq!(task_kind, crate::process::CpuTaskKind::Minify);
                assert_eq!(code, crate::process::CpuTaskErrorCode::QueueSaturated);
                assert!(retryable);
            }
            _ => panic!("expected CpuTaskError"),
        }
    }

    #[test]
    fn test_cpu_task_kind_label_mappings() {
        assert_eq!(
            cpu_task_kind_label(crate::process::CpuTaskKind::Minify),
            "minify"
        );
        assert_eq!(
            cpu_task_kind_label(crate::process::CpuTaskKind::GetCompressed),
            "get_compressed"
        );
        assert_eq!(
            cpu_task_kind_label(crate::process::CpuTaskKind::PoisonImage),
            "poison_image"
        );
        assert_eq!(
            cpu_task_kind_label(crate::process::CpuTaskKind::YaraScan),
            "yara_scan"
        );
    }

    #[test]
    fn test_static_cpu_offload_task_duration_summary() {
        record_cpu_task_duration(crate::process::CpuTaskKind::ServerlessInvoke, 10);
        record_cpu_task_duration(crate::process::CpuTaskKind::ServerlessInvoke, 20);
        record_cpu_task_duration(crate::process::CpuTaskKind::ServerlessInvoke, 30);

        let stats = snapshot_static_cpu_offload_stats(4096);
        let summary = stats
            .task_duration_ms
            .get("serverless_invoke")
            .expect("serverless_invoke summary should be present");

        assert_eq!(summary.avg_ms, 20.0);
        assert_eq!(summary.p50_ms, 20.0);
        assert_eq!(summary.p95_ms, 30.0);
        assert_eq!(summary.p99_ms, 30.0);
    }

    #[test]
    fn test_is_deadline_exceeded_zero_is_disabled() {
        assert!(!is_deadline_exceeded(0));
    }

    #[test]
    fn test_is_deadline_exceeded_past_timestamp() {
        assert!(is_deadline_exceeded(1));
    }

    #[test]
    fn test_deadline_timeout_error_shape() {
        let msg = deadline_timeout_error(
            42,
            crate::process::CpuTaskKind::YaraScan,
            "deadline".to_string(),
        );
        match msg {
            crate::process::Message::CpuTaskError {
                request_id,
                task_kind,
                code,
                message,
                retryable,
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(task_kind, crate::process::CpuTaskKind::YaraScan);
                assert_eq!(code, crate::process::CpuTaskErrorCode::Timeout);
                assert_eq!(message, "deadline");
                assert!(!retryable);
            }
            _ => panic!("expected CpuTaskError"),
        }
    }

    #[test]
    fn test_static_worker_args_creation() {
        let args = StaticWorkerArgs {
            worker_id: 1,
            config_path: PathBuf::from("/etc/synvoid"),
            supervisor_socket: PathBuf::from("/tmp/supervisor.sock"),
            static_worker_socket: PathBuf::from("/tmp/static.sock"),
            log_level: Some("debug".to_string()),
            ipc_key: Some("test-key".to_string()),
        };

        assert_eq!(args.worker_id, 1);
        assert_eq!(args.config_path, PathBuf::from("/etc/synvoid"));
        assert_eq!(
            args.supervisor_socket,
            PathBuf::from("/tmp/supervisor.sock")
        );
        assert_eq!(args.static_worker_socket, PathBuf::from("/tmp/static.sock"));
        assert_eq!(args.log_level, Some("debug".to_string()));
        assert_eq!(args.ipc_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_static_worker_args_default_log_level() {
        let args = StaticWorkerArgs {
            worker_id: 0,
            config_path: PathBuf::from("/etc/synvoid"),
            supervisor_socket: PathBuf::from("/tmp/supervisor.sock"),
            static_worker_socket: PathBuf::from("/tmp/static.sock"),
            log_level: None,
            ipc_key: None,
        };

        assert!(args.log_level.is_none());
        assert!(args.ipc_key.is_none());
    }

    #[test]
    fn test_compression_task_creation() {
        let task = CompressionTask {
            site_id: "test-site".to_string(),
            path: "/index.html".to_string(),
            encoding: "gzip".to_string(),
            queued_at: Instant::now(),
        };

        assert_eq!(task.site_id, "test-site");
        assert_eq!(task.path, "/index.html");
        assert_eq!(task.encoding, "gzip");
    }

    #[test]
    fn test_content_type_from_extension() {
        assert_eq!(ContentType::from_extension("html"), ContentType::Html);
        assert_eq!(ContentType::from_extension("htm"), ContentType::Html);
        assert_eq!(ContentType::from_extension("css"), ContentType::Css);
        assert_eq!(ContentType::from_extension("js"), ContentType::Js);
        assert_eq!(ContentType::from_extension("mjs"), ContentType::Js);
        assert_eq!(ContentType::from_extension("svg"), ContentType::Svg);
        assert_eq!(ContentType::from_extension("txt"), ContentType::Other);
        assert_eq!(ContentType::from_extension("bin"), ContentType::Other);
    }

    #[test]
    fn test_content_type_case_insensitive() {
        assert_eq!(ContentType::from_extension("HTML"), ContentType::Html);
        assert_eq!(ContentType::from_extension("CSS"), ContentType::Css);
        assert_eq!(ContentType::from_extension("SVG"), ContentType::Svg);
    }

    #[test]
    fn test_content_type_to_mime() {
        assert_eq!(ContentType::Html.to_mime(), "text/html");
        assert_eq!(ContentType::Css.to_mime(), "text/css");
        assert_eq!(ContentType::Js.to_mime(), "application/javascript");
        assert_eq!(ContentType::Svg.to_mime(), "image/svg+xml");
        assert_eq!(ContentType::Other.to_mime(), "application/octet-stream");
    }

    #[test]
    fn test_encoding_extension() {
        assert_eq!(Encoding::Gzip.extension(), "gz");
        assert_eq!(Encoding::Br.extension(), "br");
        assert_eq!(Encoding::None.extension(), "");
    }

    #[test]
    fn test_encoding_content_encoding() {
        assert_eq!(Encoding::Gzip.content_encoding(), "gzip");
        assert_eq!(Encoding::Br.content_encoding(), "br");
        assert_eq!(Encoding::None.content_encoding(), "");
    }

    #[test]
    fn test_cache_key_equality() {
        let key1 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };
        let key2 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };
        let key3 = CacheKey {
            site_id: Arc::from("site2"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_cache_key_with_different_encodings() {
        let key1 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };
        let key2 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::Gzip,
        };

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_hash() {
        use std::collections::HashMap;
        let mut map = HashMap::new();

        let key1 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };
        let key2 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::Gzip,
        };

        map.insert(key1.clone(), 1);
        map.insert(key2.clone(), 2);

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&key1), Some(&1));
        assert_eq!(map.get(&key2), Some(&2));
    }

    #[test]
    fn test_minifier_config_from_site_config_defaults() {
        let site_config = SiteStaticConfig {
            enabled: Some(true),
            enable_minification: Some(true),
            enable_html_minification: Some(true),
            enable_css_minification: Some(true),
            enable_js_minification: Some(true),
            enable_svg_compression: Some(true),
            enable_compression: Some(true),
            enable_brotli: Some(true),
            gzip_level: Some(6),
            brotli_level: Some(10),
            enable_file_cache: Some(true),
            cache_max_entries: Some(5000),
            cache_ttl_seconds: Some(1800),
            ..Default::default()
        };

        let config = MinifierConfig::from_site_config("test-site", &site_config);

        assert!(config.enabled);
        assert!(config.enable_html);
        assert!(config.enable_css);
        assert!(config.enable_js);
        assert!(config.enable_svg);
        assert!(config.enable_gzip);
        assert!(config.enable_brotli);
        assert_eq!(config.gzip_level, 6);
        assert_eq!(config.brotli_level, 10);
        assert!(config.enable_cache);
        assert_eq!(config.cache_max_entries, 5000);
        assert_eq!(config.cache_ttl_secs, 1800);
    }

    #[test]
    fn test_minifier_config_respects_disabled_flags() {
        let site_config = SiteStaticConfig {
            enable_minification: Some(false),
            enable_html_minification: Some(false),
            enable_css_minification: Some(false),
            enable_js_minification: Some(false),
            enable_svg_compression: Some(false),
            enable_compression: Some(false),
            enable_brotli: Some(false),
            enable_file_cache: Some(false),
            ..Default::default()
        };

        let config = MinifierConfig::from_site_config("test-site", &site_config);

        assert!(!config.enabled);
        assert!(!config.enable_html);
        assert!(!config.enable_css);
        assert!(!config.enable_js);
        assert!(!config.enable_svg);
        assert!(!config.enable_gzip);
        assert!(!config.enable_brotli);
        assert!(!config.enable_cache);
    }

    #[test]
    fn test_minifier_cache_insert_and_get() {
        let config = MinifierConfig {
            enabled: true,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        let key = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        let entry = CacheEntry {
            content: Bytes::from("<html>test</html>"),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Html,
        };

        cache.insert(key.clone(), entry);

        let retrieved = cache.get(&key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().content, Bytes::from("<html>test</html>"));
    }

    #[test]
    fn test_minifier_cache_get_missing_returns_none() {
        let config = MinifierConfig {
            enabled: true,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        let key = CacheKey {
            site_id: Arc::from("nonexistent"),
            path: Arc::from("/missing.html"),
            encoding: Encoding::None,
        };

        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_minifier_cache_disabled_returns_none() {
        let config = MinifierConfig {
            enabled: false,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        let key = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_minifier_cache_invalidate() {
        let config = MinifierConfig {
            enabled: true,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        let key = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        let entry = CacheEntry {
            content: Bytes::from("<html>test</html>"),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Html,
        };

        cache.insert(key.clone(), entry.clone());
        assert!(cache.get(&key).is_some());

        cache.invalidate("test-site", "/index.html");
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_minifier_cache_clear_site() {
        let config = MinifierConfig {
            enabled: true,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        let key1 = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };
        let key2 = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/style.css"),
            encoding: Encoding::None,
        };
        let key3 = CacheKey {
            site_id: Arc::from("other-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        let entry = CacheEntry {
            content: Bytes::from("content"),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Other,
        };

        cache.insert(key1.clone(), entry.clone());
        cache.insert(key2.clone(), entry.clone());
        cache.insert(key3.clone(), entry.clone());

        assert!(cache.get(&key1).is_some());
        assert!(cache.get(&key2).is_some());
        assert!(cache.get(&key3).is_some());

        cache.clear_site("test-site");

        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_none());
        assert!(cache.get(&key3).is_some());
    }

    #[test]
    fn test_minifier_cache_hit_rate_calculation() {
        let config = MinifierConfig {
            enabled: true,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        assert_eq!(cache.cache_hit_rate(), 0.0);

        let key = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        let entry = CacheEntry {
            content: Bytes::from("<html>test</html>"),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Html,
        };

        cache.insert(key.clone(), entry);

        cache.get(&key);
        let _misses = cache.cache_misses();

        let rate = cache.cache_hit_rate();
        assert!(rate >= 0.0 && rate <= 100.0);
    }

    #[test]
    fn test_cache_entry_clone() {
        let entry = CacheEntry {
            content: Bytes::from("test content"),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Html,
        };

        let cloned = entry.clone();
        assert_eq!(cloned.content, entry.content);
        assert_eq!(cloned.mtime, entry.mtime);
        assert_eq!(cloned.generated_at, entry.generated_at);
        assert_eq!(cloned.content_type, entry.content_type);
    }

    #[test]
    fn test_encoding_clone() {
        let enc1 = Encoding::Gzip;
        let enc2 = enc1.clone();
        assert_eq!(enc1, enc2);

        let enc3 = Encoding::Br;
        let enc4 = enc3.clone();
        assert_eq!(enc3, enc4);

        let enc5 = Encoding::None;
        let enc6 = enc5.clone();
        assert_eq!(enc5, enc6);
    }

    #[test]
    fn test_minifier_generator_gzip_compression() {
        use crate::static_files::minifier::MinifierGenerator;
        let generator = MinifierGenerator::new();

        let input = b"Hello, World! This is test content for gzip compression.";
        let compressed = generator.compress_gzip(input, 6).unwrap();

        assert!(compressed.len() < input.len() * 2);

        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed.as_slice(), input);
    }

    #[test]
    fn test_minifier_generator_brotli_compression() {
        use crate::static_files::minifier::MinifierGenerator;
        let generator = MinifierGenerator::new();

        let input = b"Hello, World! This is test content for brotli compression.";
        let compressed = generator.compress_brotli(input, 6).unwrap();

        assert!(compressed.len() < input.len() * 2);

        use std::io::Read;
        let mut decompressed = Vec::new();
        {
            let mut decoder = brotli::Decompressor::new(compressed.as_slice(), 4096);
            decoder.read_to_end(&mut decompressed).unwrap();
        }
        assert_eq!(decompressed.as_slice(), input);
    }

    #[test]
    fn test_minifier_generator_css_minification() {
        use crate::static_files::minifier::MinifierGenerator;
        let generator = MinifierGenerator::new();

        let css = r#"
            body {
                color: red;
                background-color: blue;
            }
            .container {
                margin: 10px;
                padding: 5px;
            }
        "#;

        let result = generator.minify_css(css);
        assert!(result.is_ok());

        let minified = result.unwrap();
        assert!(!minified.contains("\n"));
        assert!(!minified.contains("  "));
        assert!(minified.contains("color:red"));
    }

    #[test]
    fn test_minifier_generator_html_minification() {
        use crate::static_files::minifier::MinifierGenerator;
        let generator = MinifierGenerator::new();

        let html = r#"
            <!DOCTYPE html>
            <html>
                <head>
                    <title>Test</title>
                </head>
                <body>
                    <p>Hello World</p>
                </body>
            </html>
        "#;

        let result = generator.minify_html(html);
        assert!(result.is_ok());

        let minified = result.unwrap();
        assert!(!minified.contains("\n"));
        assert!(!minified.contains("  "));
    }

    #[test]
    fn test_minifier_generator_js_minification() {
        use crate::static_files::minifier::MinifierGenerator;
        let generator = MinifierGenerator::new();

        let js = r#"
            function hello(name) {
                console.log("Hello, " + name + "!");
                return true;
            }
            hello("World");
        "#;

        let result = generator.minify_js(js);
        assert!(result.is_ok());

        let minified = result.unwrap();
        assert!(minified.contains("hello"));
        assert!(!minified.contains("\n"));
    }

    #[test]
    fn test_content_type_from_path() {
        use crate::static_files::minifier::content_type_from_path;

        assert_eq!(content_type_from_path("/index.html"), "text/html");
        assert_eq!(content_type_from_path("/style.css"), "text/css");
        assert_eq!(
            content_type_from_path("/script.js"),
            "application/javascript"
        );
        assert_eq!(content_type_from_path("/image.svg"), "image/svg+xml");
        assert_eq!(
            content_type_from_path("/unknown.xyz"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_from_mime() {
        assert_eq!(
            ContentType::from_mime("text/html; charset=utf-8"),
            ContentType::Html
        );
        assert_eq!(ContentType::from_mime("text/css"), ContentType::Css);
        assert_eq!(
            ContentType::from_mime("application/javascript"),
            ContentType::Js
        );
        assert_eq!(ContentType::from_mime("image/svg+xml"), ContentType::Svg);
        assert_eq!(
            ContentType::from_mime("application/octet-stream"),
            ContentType::Other
        );
    }
}
