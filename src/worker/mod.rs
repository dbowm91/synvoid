//! Worker process implementation.
//!
//! Handles HTTP request processing, TLS termination, connection management,
//! and WAF enforcement. Workers are spawned by the master process and
//! communicate via IPC.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex as TokioMutex;

use crate::config::ConfigManager;
use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
use crate::static_files::minifier;
use crate::{DrainFlag, RunningFlag};

use crate::common::setup_panic_handler;

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

pub fn setup_worker_panic_handler() {
    let worker_panic_log = format!(
        "{}/maluwaf-worker-panic.log",
        std::env::temp_dir().display()
    );
    setup_panic_handler("WORKER", Some(&worker_panic_log));
}

#[derive(Clone)]
pub struct StaticWorkerArgs {
    pub worker_id: usize,
    pub config_path: PathBuf,
    pub master_socket: PathBuf,
    pub static_worker_socket: PathBuf,
    pub log_level: Option<String>,
    pub ipc_key: Option<String>,
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
