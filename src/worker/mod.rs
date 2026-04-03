//! Worker process implementation.
//!
//! Handles HTTP request processing, TLS termination, connection management,
//! and WAF enforcement. Workers are spawned by the master process and
//! communicate via IPC.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{watch, Mutex as TokioMutex};

use crate::config::ConfigManager;
use crate::metrics::WorkerMetrics;
use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
use crate::process::{current_timestamp, Message, WorkerId};
use crate::static_files::minifier;
use crate::{DrainFlag, RunningFlag};

use crate::common::setup_panic_handler;
use crate::worker::common::load_config;

pub mod common;
pub mod connect;
pub mod drain_state;
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

#[derive(Clone)]
pub struct WorkerArgs {
    pub worker_id: usize,
    pub port: u16,
    pub config_path: PathBuf,
    pub master_socket: PathBuf,
    pub test_mode: Option<Vec<String>>,
    pub log_level: Option<String>,
    pub upgrade_mode: bool,
    pub reuse_port: bool,
    pub ipc_key: Option<String>,
}

pub fn setup_worker_panic_handler() {
    let worker_panic_log = format!(
        "{}/maluwaf-worker-panic.log",
        std::env::temp_dir().display()
    );
    setup_panic_handler("WORKER", Some(&worker_panic_log));
}

pub async fn run_worker(args: WorkerArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let worker_id = WorkerId(args.worker_id);

    if let Some(ref level) = args.log_level {
        crate::log_controller::init_logging_with_dynamic_level(level);
    }

    tracing::info!(
        "Worker {} starting on port {}, config: {:?}, master socket: {:?}",
        worker_id,
        args.port,
        args.config_path,
        args.master_socket
    );

    let ipc = Arc::new(TokioMutex::new(
        connect::connect_to_master_async(
            &args.master_socket,
            5,
            std::time::Duration::from_secs(2),
            "Worker",
        )
        .await?,
    ));

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard
            .send(&Message::WorkerStarted {
                id: worker_id,
                pid: std::process::id(),
                port: args.port,
                timestamp: current_timestamp(),
            })
            .await?;
    }

    let config_manager = Arc::new(parking_lot::RwLock::new(load_config(&args.config_path)));
    let main_config = config_manager.read().main.clone();

    let _waf = connection::create_waf(&main_config);

    let metrics = Arc::new(WorkerMetrics::default());
    let running = RunningFlag::new();
    let draining = DrainFlag::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let state = connection::WorkerState {
        worker_id,
        metrics: metrics.clone(),
        start_time: Instant::now(),
        ipc: ipc.clone(),
        running,
        draining,
        config_manager: config_manager.clone(),
        config_path: args.config_path.clone(),
        shutdown_rx,
    };

    let shutdown_tx = Arc::new(shutdown_tx);

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard
            .send(&Message::WorkerReady { id: worker_id })
            .await?;
    }

    tracing::info!("Worker {} ready", worker_id);

    let heartbeat_state = state.clone();
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            if !heartbeat_state.running.is_running() {
                break;
            }

            let uptime = heartbeat_state.start_time.elapsed().as_secs();
            let payload = heartbeat_state.metrics.to_payload(uptime);

            let mut ipc = heartbeat_state.ipc.lock().await;
            let _ = ipc
                .send(&Message::WorkerHeartbeat {
                    id: heartbeat_state.worker_id,
                    timestamp: current_timestamp(),
                    metrics: payload,
                })
                .await;
        }
    });

    let ipc_state = state.clone();
    let shutdown_tx_for_ipc = shutdown_tx.clone();
    let ipc_handle = tokio::spawn(async move {
        loop {
            if !ipc_state.running.is_running() {
                break;
            }

            // Receive message with lock held, then drop lock before sending responses.
            // Holding the lock across both recv and send would deadlock if another
            // task (e.g. heartbeat) also needs the lock.
            let msg = {
                let mut ipc = ipc_state.ipc.lock().await;
                ipc.recv_with_timeout::<Message>(100).await
            };

            match msg {
                Ok(Some(Message::MasterShutdown {
                    graceful,
                    timeout_secs,
                })) => {
                    tracing::info!(
                        "Worker {} received shutdown signal (graceful: {}, timeout: {}s)",
                        ipc_state.worker_id,
                        graceful,
                        timeout_secs
                    );
                    ipc_state.running.stop();
                    let _ = shutdown_tx_for_ipc.send(true);

                    let mut ipc = ipc_state.ipc.lock().await;
                    let _ = ipc
                        .send(&Message::WorkerShutdownComplete {
                            id: ipc_state.worker_id,
                        })
                        .await;
                    break;
                }
                Ok(Some(Message::MasterConfigReload { config_path })) => {
                    tracing::info!(
                        "Worker {} received config reload: {}",
                        ipc_state.worker_id,
                        config_path
                    );
                    let config_dir = std::path::Path::new(&config_path);
                    let mut cm = ConfigManager::new(config_dir.to_path_buf());
                    let main_path = config_dir.join("main.toml");
                    if cm.load_main(&main_path).is_ok() {
                        cm.discover_sites();
                        *ipc_state.config_manager.write() = cm;
                        tracing::info!(
                            "Worker {} config reloaded successfully",
                            ipc_state.worker_id
                        );
                    } else {
                        tracing::warn!(
                            "Worker {} failed to reload config from {}",
                            ipc_state.worker_id,
                            config_path
                        );
                    }
                }
                Ok(Some(Message::MasterHealthCheck { timestamp })) => {
                    let mut ipc = ipc_state.ipc.lock().await;
                    if ipc
                        .send(&Message::HealthCheckAck { timestamp })
                        .await
                        .is_err()
                    {
                        tracing::warn!("Failed to send health check ack to master");
                    }
                }
                Ok(Some(Message::MasterResizeThreadpool { worker_threads })) => {
                    tracing::info!(
                        "Worker {} received threadpool resize request to {} threads",
                        ipc_state.worker_id,
                        worker_threads
                    );
                    ipc_state.draining.start_drain();

                    let mut ipc = ipc_state.ipc.lock().await;
                    let _ = ipc
                        .send(&Message::WorkerResizeAck {
                            id: ipc_state.worker_id,
                            worker_threads,
                        })
                        .await;
                }
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("IPC recv error: {}", e);
                }
            }
        }
    });

    let server_state = state.clone();
    let worker_id_for_log = worker_id;
    let port = args.port;
    let worker_exit_code: Arc<std::sync::atomic::AtomicI32> =
        Arc::new(std::sync::atomic::AtomicI32::new(0));
    let server_exit_code = worker_exit_code.clone();
    let mut server_shutdown_rx = state.shutdown_rx.clone();
    let server_handle = tokio::spawn(async move {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port)
            .parse()
            .expect("Invalid address");

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind to {}: {}", addr, e);
                return;
            }
        };

        tracing::info!(
            "Worker {} HTTP server listening on {}",
            worker_id_for_log,
            addr
        );

        loop {
            if server_state.draining.is_draining() {
                let concurrent = server_state
                    .metrics
                    .current_concurrent
                    .load(std::sync::atomic::Ordering::SeqCst);
                if concurrent == 0 {
                    tracing::info!(
                        "Worker {} finished draining, exiting for threadpool resize",
                        worker_id_for_log
                    );
                    server_exit_code.store(100, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                tracing::debug!(
                    "Worker {} draining, waiting for {} connections",
                    worker_id_for_log,
                    concurrent
                );
                tokio::select! {
                    _ = server_shutdown_rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
                continue;
            }

            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _client_addr)) => {
                            let metrics = server_state.metrics.clone();

                            metrics.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let current = metrics.current_concurrent.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

                            let peak = metrics.peak_concurrent.load(std::sync::atomic::Ordering::Relaxed);
                            if current > peak {
                                metrics.peak_concurrent.store(current, std::sync::atomic::Ordering::Relaxed);
                            }

                            tokio::spawn(async move {
                                let start = Instant::now();

                                let _ = stream;

                                tokio::time::sleep(Duration::from_millis(10)).await;

                                let elapsed = start.elapsed().as_millis() as u64;
                                metrics.record_request_end(elapsed);
                            });
                        }
                        Err(e) => {
                            tracing::debug!("Accept error: {}", e);
                        }
                    }
                }
                _ = server_shutdown_rx.changed() => {
                    break;
                }
            }
        }

        tracing::info!("Worker {} HTTP server stopped", worker_id_for_log);
    });

    tokio::select! {
        _ = heartbeat_handle => {}
        _ = ipc_handle => {}
        _ = server_handle => {}
    }

    state.running.stop();

    let exit_code = worker_exit_code.load(std::sync::atomic::Ordering::Relaxed);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    tracing::info!("Worker {} shutting down", worker_id);
    Ok(())
}

#[derive(Clone)]
pub struct StaticWorkerArgs {
    pub worker_id: usize,
    pub config_path: PathBuf,
    pub master_socket: PathBuf,
    pub static_worker_socket: PathBuf,
    pub log_level: Option<String>,
}

#[derive(Clone)]
struct StaticWorkerState {
    worker_id: usize,
    running: RunningFlag,
    stop_background_tasks: DrainFlag,
    ipc: Arc<TokioMutex<AsyncIpcStream>>,
    config_manager: Arc<std::sync::RwLock<ConfigManager>>,
    minifier_caches: Arc<std::sync::RwLock<HashMap<String, Arc<minifier::MinifierCache>>>>,
    compression_queue: Arc<std::sync::RwLock<Vec<CompressionTask>>>,
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
    #[allow(dead_code)]
    queued_at: Instant,
}

pub async fn run_static_worker(
    args: StaticWorkerArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ref level) = args.log_level {
        crate::log_controller::init_logging_with_dynamic_level(level);
    }

    tracing::info!(
        "Static worker {} starting, config: {:?}, master socket: {:?}",
        args.worker_id,
        args.config_path,
        args.master_socket
    );

    let ipc = Arc::new(TokioMutex::new(
        connect::connect_to_master_async(
            &args.master_socket,
            5,
            std::time::Duration::from_secs(2),
            "Static worker",
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

    let state = StaticWorkerState {
        worker_id: args.worker_id,
        running: running.clone(),
        stop_background_tasks: stop_background_tasks.clone(),
        ipc: ipc.clone(),
        config_manager: config_manager.clone(),
        minifier_caches,
        compression_queue,
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
                tracing::info!("Static worker listening on {}", socket_path.display());
                l
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to bind static worker socket {}: {}",
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
                            "Static worker at max connections ({}), dropping",
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
                    tracing::debug!("Static worker socket accept error: {}", e);
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        });
    }

    #[cfg(windows)]
    {
        let listener = crate::process::ipc::WindowsIpcListener::new("rustwaf-static-worker");
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
                            "Static worker at max connections ({}), dropping",
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
                    tracing::warn!("Static worker pipe accept error: {}", e);
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

    tracing::info!("Static worker {} ready", args.worker_id);

    let ipc_state = state.clone();
    let ipc_handle = tokio::spawn(async move {
        loop {
            if !ipc_state.running.is_running() {
                break;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut ipc = ipc_state.ipc.lock().await;
            match ipc.recv_with_timeout::<crate::process::Message>(50).await {
                Ok(Some(crate::process::Message::MasterShutdown {
                    graceful,
                    timeout_secs,
                })) => {
                    tracing::info!(
                        "Static worker {} received shutdown signal (graceful: {}, timeout: {}s), stopping background tasks",
                        ipc_state.worker_id,
                        graceful,
                        timeout_secs
                    );

                    ipc_state.stop_background_tasks.start_drain();

                    response_builder::process_compression_queue(&ipc_state);
                    tracing::info!(
                        "Static worker {} completed final cache refresh",
                        ipc_state.worker_id
                    );

                    let _ = ipc
                        .send(&crate::process::Message::StaticWorkerBackgroundTasksDone {
                            worker_id: ipc_state.worker_id,
                        })
                        .await;
                }
                Ok(Some(crate::process::Message::MinifyRequest {
                    request_id,
                    site_id,
                    path,
                    encoding,
                })) => {
                    response_builder::handle_minify_request(
                        &ipc_state, request_id, site_id, path, encoding,
                    )
                    .await;
                }
                Ok(Some(crate::process::Message::GetCompressedRequest {
                    request_id,
                    site_id,
                    path,
                    encoding,
                })) => {
                    response_builder::handle_compressed_request(
                        &ipc_state, request_id, site_id, path, encoding,
                    )
                    .await;
                }
                Ok(Some(_)) => {}
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
                    "Static worker {} queue handler stopping (background tasks disabled)",
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
        let mut interval = tokio::time::interval(Duration::from_millis(watch_interval));

        loop {
            interval.tick().await;

            if !watch_state.running.is_running() {
                break;
            }

            if watch_state.stop_background_tasks.is_draining() {
                tracing::info!(
                    "Static worker {} watch handler stopping (background tasks disabled)",
                    watch_state.worker_id
                );
                break;
            }

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
                })
                .await;
        }
    });

    let config_path = args.config_path.clone();
    let running_for_reload = running.clone();
    let stop_bg_for_reload = stop_background_tasks.clone();
    let caches_for_reload = state.minifier_caches.clone();
    let queue_for_reload = state.compression_queue.clone();
    let reload_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            interval.tick().await;

            if !running_for_reload.is_running() {
                break;
            }

            if stop_bg_for_reload.is_draining() {
                tracing::info!("Static worker reload handler stopping (background tasks disabled)");
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

    tracing::info!("Static worker {} shutting down", args.worker_id);
    Ok(())
}

/// Handle a static worker IPC connection (cross-platform).
///
/// Uses the sync `IpcStream` abstraction for framed message I/O on both
/// Unix (UnixStream) and Windows (named pipe as File).
fn handle_minify_client_connection(mut ipc: crate::process::IpcStream, state: StaticWorkerState) {
    loop {
        match ipc.try_recv() {
            Ok(Some(message)) => match message {
                crate::process::Message::MinifyRequest {
                    request_id,
                    site_id,
                    path,
                    encoding,
                } => {
                    let result = response_builder::process_minify_request(
                        &state, request_id, site_id, path, encoding,
                    );
                    match result {
                        Ok(response) => {
                            if let Err(e) = ipc.send(&response) {
                                tracing::warn!(
                                    "Failed to send minify response for request {}: {}",
                                    request_id,
                                    e
                                );
                            }
                        }
                        Err(error_msg) => {
                            if let Err(e) = ipc.send(&crate::process::Message::MinifyError {
                                request_id,
                                error: error_msg,
                            }) {
                                tracing::warn!(
                                    "Failed to send minify error for request {}: {}",
                                    request_id,
                                    e
                                );
                            }
                        }
                    }
                }
                crate::process::Message::GetCompressedRequest {
                    request_id,
                    site_id,
                    path,
                    encoding,
                } => {
                    let result = response_builder::process_compressed_request(
                        &state, request_id, site_id, path, encoding,
                    );
                    match result {
                        Ok(response) => {
                            if let Err(e) = ipc.send(&response) {
                                tracing::warn!(
                                    "Failed to send compressed response for request {}: {}",
                                    request_id,
                                    e
                                );
                            }
                        }
                        Err(error_msg) => {
                            if let Err(e) = ipc.send(&crate::process::Message::MinifyError {
                                request_id,
                                error: error_msg,
                            }) {
                                tracing::warn!(
                                    "Failed to send compressed error for request {}: {}",
                                    request_id,
                                    e
                                );
                            }
                        }
                    }
                }
                crate::process::Message::PoisonImageRequest {
                    request_id,
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
                        &state,
                        &site_id,
                        body,
                        last_modified,
                        level,
                        intensity,
                        seed,
                        max_dimension,
                        jpeg_quality,
                    );
                    if let Err(e) = ipc.send(&crate::process::Message::PoisonImageResponse {
                        request_id,
                        poisoned_body: poisoned,
                    }) {
                        tracing::warn!(
                            "Failed to send poison image response for request {}: {}",
                            request_id,
                            e
                        );
                    }
                }
                _ => {}
            },
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
