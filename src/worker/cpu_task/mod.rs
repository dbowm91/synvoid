// Submodule: CPU offload task subsystem (state, metrics, dispatch, yara,
// payload, connection handling, and the run_cpu_worker bootstrap).

pub mod connection;
pub mod dispatch;
pub mod metrics;
pub mod payload;
pub mod state;
pub mod yara;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex as TokioMutex;

use crate::worker::connect;
use crate::worker::image_rights;
use crate::worker::response_builder;
use crate::{DrainFlag, RunningFlag};
use synvoid_config::ConfigManager;
use synvoid_ipc::ipc_signed::IpcSigner;
use synvoid_ipc::{CpuTaskPayload, Message};
use synvoid_static_files::minifier;

use self::connection::handle_minify_client_connection;
use self::dispatch::process_cpu_task_request_sync;
use self::metrics::{snapshot_static_cpu_offload_stats, STATIC_CPU_OFFLOAD_EVENT_LOOP_LAG_MS};
use self::payload::deadline_timeout_error;
use self::state::{CompressionTask, CpuTaskLimiter, CpuTaskLimits, CpuWorkerState};
use self::yara::build_yara_scanner_from_main_config;

pub use self::state::CpuWorkerArgs;

pub async fn run_cpu_worker(
    args: CpuWorkerArgs,
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
            .send(&Message::CpuWorkerStarted {
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

    let state = CpuWorkerState {
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

    let socket_path = args.cpu_worker_socket.clone();
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
            .send(&Message::CpuWorkerReady {
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
            match ipc.recv_with_timeout::<Message>(50).await {
                Ok(Some(Message::MasterShutdown {
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
                        .send(&Message::CpuWorkerBackgroundTasksDone {
                            worker_id: ipc_state.worker_id,
                        })
                        .await;
                }
                Ok(Some(message)) => {
                    if let Message::CpuTaskCancel {
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
                            let response = Message::adapt_cpu_task_response_compat(
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
                                CpuTaskPayload::Minify {
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
                                CpuTaskPayload::GetCompressed {
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
                                CpuTaskPayload::PoisonImage {
                                    site_id,
                                    body,
                                    last_modified,
                                    level,
                                    intensity,
                                    seed,
                                    max_dimension,
                                    jpeg_quality,
                                } => {
                                    let poisoned = image_rights::mark_image_rights_sync(
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
                                        .send(&Message::PoisonImageResponse {
                                            request_id,
                                            poisoned_body: poisoned,
                                        })
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to send image rights response for request {}: {}",
                                            request_id,
                                            e
                                        );
                                    }
                                    continue;
                                }
                                CpuTaskPayload::YaraScan { .. } => {
                                    // No legacy YARA-specific IPC response shape exists.
                                    // Route through generic CpuTask* response handling below.
                                }
                                CpuTaskPayload::WasmExecute { .. }
                                | CpuTaskPayload::ServerlessInvoke { .. }
                                | CpuTaskPayload::WasmTransformResponse { .. } => {
                                    // No legacy WasmExecute/ServerlessInvoke response shape exists.
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
                        let response = Message::adapt_cpu_task_response_compat(
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
            let (worker_rss_bytes, _cpu_percent) =
                crate::worker::common::collect_current_process_usage();
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
                .send(&Message::CpuWorkerHeartbeat {
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

                let temp_state = CpuWorkerState {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::CpuTaskKind;

    #[test]
    fn test_cpu_task_payload_task_kind_for_new_variants() {
        let wasm_payload = CpuTaskPayload::WasmExecute {
            site_id: "site-a".to_string(),
            plugin_name: "plugin-1".to_string(),
            function_name: "handle".to_string(),
            input: vec![1, 2, 3],
            timeout_ms: 5_000,
        };
        assert_eq!(wasm_payload.task_kind(), CpuTaskKind::WasmExecute);

        let serverless_payload = CpuTaskPayload::ServerlessInvoke {
            site_id: "site-a".to_string(),
            function_name: "fn".to_string(),
            input: vec![4, 5, 6],
            timeout_ms: 2_000,
        };
        assert_eq!(
            serverless_payload.task_kind(),
            CpuTaskKind::ServerlessInvoke
        );
    }

    #[test]
    fn test_cpu_task_result_task_kind_for_new_variants() {
        let wasm_result = crate::process::CpuTaskResult::WasmExecute { output: vec![0xAA] };
        assert_eq!(wasm_result.task_kind(), CpuTaskKind::WasmExecute);

        let serverless_result =
            crate::process::CpuTaskResult::ServerlessInvoke { output: vec![0xBB] };
        assert_eq!(serverless_result.task_kind(), CpuTaskKind::ServerlessInvoke);
    }
}
