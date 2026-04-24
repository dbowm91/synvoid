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
use crate::process::ipc_signed::IpcSigner;
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
    // SAFETY_REASON: Debugging - stored for introspection
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

    let signer = match IpcSigner::try_from_env() {
        Some(s) => s,
        None => {
            tracing::warn!("No IPC session key found - static worker will use unsigned IPC");
            return Err("No IPC session key for static worker".into());
        }
    };
    let ipc = Arc::new(TokioMutex::new(
        connect::connect_to_master_async_signed(
            &args.master_socket,
            5,
            std::time::Duration::from_secs(2),
            "Static worker",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::site::SiteStaticConfig;
    use crate::static_files::minifier::{
        CacheEntry, CacheKey, ContentType, Encoding, MinifierCache, MinifierConfig,
    };
    use bytes::Bytes;
    use std::sync::Arc;
    use std::time::{Instant, SystemTime};

    #[test]
    fn test_static_worker_args_creation() {
        let args = StaticWorkerArgs {
            worker_id: 1,
            config_path: PathBuf::from("/etc/maluwaf"),
            master_socket: PathBuf::from("/tmp/master.sock"),
            static_worker_socket: PathBuf::from("/tmp/static.sock"),
            log_level: Some("debug".to_string()),
            ipc_key: Some("test-key".to_string()),
        };

        assert_eq!(args.worker_id, 1);
        assert_eq!(args.config_path, PathBuf::from("/etc/maluwaf"));
        assert_eq!(args.master_socket, PathBuf::from("/tmp/master.sock"));
        assert_eq!(args.static_worker_socket, PathBuf::from("/tmp/static.sock"));
        assert_eq!(args.log_level, Some("debug".to_string()));
        assert_eq!(args.ipc_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_static_worker_args_default_log_level() {
        let args = StaticWorkerArgs {
            worker_id: 0,
            config_path: PathBuf::from("/etc/maluwaf"),
            master_socket: PathBuf::from("/tmp/master.sock"),
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
            minified_dir: std::env::temp_dir().join("maluwaf-test-cache"),
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
            minified_dir: std::env::temp_dir().join("maluwaf-test-cache"),
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
            minified_dir: std::env::temp_dir().join("maluwaf-test-cache"),
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
            minified_dir: std::env::temp_dir().join("maluwaf-test-cache"),
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
            minified_dir: std::env::temp_dir().join("maluwaf-test-cache"),
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
            minified_dir: std::env::temp_dir().join("maluwaf-test-cache"),
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
