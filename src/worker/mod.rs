#![allow(dead_code)]

use bytes::Bytes;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

#[cfg(unix)]
use std::os::unix::net::UnixListener;

use tokio::task;
use tokio::sync::Mutex as TokioMutex;

use crate::config::ConfigManager;
use crate::metrics::WorkerMetrics;
use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
use crate::process::{Message, WorkerId, current_timestamp};
use crate::static_files::minifier;
use crate::waf::WafCore;
use crate::{RunningFlag, DrainFlag};

use crate::common::setup_panic_handler;
use crate::worker::common::load_config;

pub mod drain_state;
pub mod common;
pub mod connect;
pub mod metrics;
pub mod unified_server;
pub mod traits;

pub use traits::{BaseWorkerState, WorkerLifecycle};

pub use unified_server::{UnifiedServerWorkerArgs, run_unified_server_worker, setup_unified_server_panic_handler};

type MinifierCache = Arc<minifier::MinifierCache>;

fn get_content_type(path: &str) -> String {
    path.rsplit('.')
        .next()
        .and_then(|e| crate::mime::MIME_REGISTRY.read().get_mime_for_extension(e))
        .unwrap_or_else(|| "application/octet-stream".to_string())
}

fn get_compressed_content(
    cache: &MinifierCache,
    site_id: &str,
    path: &str,
    minified_content: &[u8],
    encoding: Option<&str>,
) -> Result<Vec<u8>, String> {
    let enc = match encoding {
        Some("gzip") => minifier::Encoding::Gzip,
        Some("br") => minifier::Encoding::Br,
        _ => return Ok(minified_content.to_vec()),
    };

    let enc_key = minifier::CacheKey {
        site_id: Arc::from(site_id),
        path: Arc::from(path),
        encoding: enc,
    };

    match cache.get(&enc_key) {
        Some(entry) => Ok(entry.content.to_vec()),
        None => {
            let enc_for_gen = match encoding {
                Some("gzip") => minifier::Encoding::Gzip,
                Some("br") => minifier::Encoding::Br,
                _ => return Ok(minified_content.to_vec()),
            };
            let content: Bytes = cache
                .generate_compressed(site_id, path, minified_content, &enc_for_gen)
                .map_err(|e| format!("{:?} compression failed: {}", enc_for_gen, e))?;
            let content_vec = content.to_vec();
            let _ = cache.write_compressed_to_disk(site_id, path, &content, &enc_for_gen);
            Ok(content_vec)
        }
    }
}

#[cfg(unix)]
enum ListenerType {
    Unix(UnixListener),
}

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
    let worker_panic_log = format!("{}/maluwaf-worker-panic.log", std::env::temp_dir().display());
    setup_panic_handler("WORKER", Some(&worker_panic_log));
}

#[derive(Clone)]
struct WorkerState {
    worker_id: WorkerId,
    metrics: Arc<WorkerMetrics>,
    start_time: Instant,
    ipc: Arc<TokioMutex<AsyncIpcStream>>,
    running: RunningFlag,
    draining: DrainFlag,
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
        connect::connect_to_master_async(&args.master_socket, 5, std::time::Duration::from_secs(2), "Worker").await?
    ));

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard.send(&Message::WorkerStarted {
            id: worker_id.clone(),
            pid: std::process::id(),
            port: args.port,
            timestamp: current_timestamp(),
        }).await?;
    }

    let config_manager = load_config(&args.config_path);
    let main_config = config_manager.main.clone();

    let _waf = create_waf(&main_config);

    let metrics = Arc::new(WorkerMetrics::default());
    let running = RunningFlag::new();
    let draining = DrainFlag::new();
    
    let state = WorkerState {
        worker_id: worker_id.clone(),
        metrics: metrics.clone(),
        start_time: Instant::now(),
        ipc: ipc.clone(),
        running,
        draining,
    };

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard.send(&Message::WorkerReady {
            id: worker_id.clone(),
        }).await?;
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
            let _ = ipc.send(&Message::WorkerHeartbeat {
                id: heartbeat_state.worker_id.clone(),
                timestamp: current_timestamp(),
                metrics: payload,
            }).await;
        }
    });

    let ipc_state = state.clone();
    let ipc_handle = tokio::spawn(async move {
        loop {
            if !ipc_state.running.is_running() {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;

            let mut ipc = ipc_state.ipc.lock().await;
            match ipc.recv_with_timeout::<Message>(100).await {
                Ok(Some(Message::MasterShutdown { graceful, timeout_secs })) => {
                    tracing::info!(
                        "Worker {} received shutdown signal (graceful: {}, timeout: {}s)",
                        ipc_state.worker_id,
                        graceful,
                        timeout_secs
                    );
                    ipc_state.running.stop();
                    
                    let mut ipc = ipc_state.ipc.lock().await;
                    let _ = ipc.send(&Message::WorkerShutdownComplete {
                        id: ipc_state.worker_id.clone(),
                    }).await;
                    break;
                }
                Ok(Some(Message::MasterConfigReload { config_path })) => {
                    tracing::info!("Worker {} received config reload: {}", ipc_state.worker_id, config_path);
                }
                Ok(Some(Message::MasterHealthCheck { timestamp })) => {
                    let mut ipc = ipc_state.ipc.lock().await;
                    let _ = ipc.send(&Message::HealthCheckAck { timestamp }).await;
                }
                Ok(Some(Message::MasterResizeThreadpool { worker_threads })) => {
                    tracing::info!(
                        "Worker {} received threadpool resize request to {} threads",
                        ipc_state.worker_id,
                        worker_threads
                    );
                    ipc_state.draining.start_drain();
                    
                    let mut ipc = ipc_state.ipc.lock().await;
                    let _ = ipc.send(&Message::WorkerResizeAck {
                        id: ipc_state.worker_id.clone(),
                        worker_threads,
                    }).await;
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
    let worker_id_for_log = worker_id.clone();
    let port = args.port;
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

        tracing::info!("Worker {} HTTP server listening on {}", worker_id_for_log, addr);

        loop {
            if server_state.draining.is_draining() {
                let concurrent = server_state.metrics.current_concurrent.load(std::sync::atomic::Ordering::SeqCst);
                if concurrent == 0 {
                    tracing::info!("Worker {} finished draining, exiting for threadpool resize", worker_id_for_log);
                    break;
                }
                tracing::debug!("Worker {} draining, waiting for {} connections", worker_id_for_log, concurrent);
                tokio::time::sleep(Duration::from_millis(100)).await;
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
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if !server_state.running.is_running() {
                        break;
                    }
                }
            }
        }

        tracing::info!("Worker {} HTTP server stopped", worker_id_for_log);
        
        if server_state.draining.is_draining() {
            tracing::info!("Worker {} exiting for threadpool resize", worker_id_for_log);
            std::process::exit(100);
        }
    });

    tokio::select! {
        _ = heartbeat_handle => {}
        _ = ipc_handle => {}
        _ = server_handle => {}
    }

    state.running.stop();

    tracing::info!("Worker {} shutting down", worker_id);
    Ok(())
}

fn create_waf(main_config: &crate::config::MainConfig) -> Arc<WafCore> {
    let data_dir = main_config.persistence.data_dir.as_ref()
        .map(std::path::PathBuf::from);

    let waf = WafCore::new(
        crate::waf::RateLimitConfigStore {
            ip: main_config.defaults.ratelimit.ip.clone(),
            global: main_config.defaults.ratelimit.global.clone(),
            cleanup_interval_secs: main_config.rate_limit_memory.cleanup_interval_secs,
        },
        main_config.rate_limit_memory.clone(),
        crate::waf::BotProtectionConfig {
            block_ai_crawlers: main_config.defaults.bot.block_ai_crawlers,
            enable_css_honeypot: main_config.defaults.bot.enable_css_honeypot,
            enable_pow_challenge: main_config.defaults.pow_challenge.enabled,
            known_bots_allow: main_config.defaults.bot.known_bots_allow.clone(),
            ai_crawlers_block: main_config.defaults.bot.ai_crawlers_block.clone(),
            scraper_patterns: Vec::new(),
            challenge_cookie_name: main_config.defaults.bot.challenge_cookie_name.clone(),
            challenge_window_secs: main_config.defaults.bot.challenge_window_secs,
            pow_difficulty: main_config.defaults.pow_challenge.difficulty,
            pow_timeout_secs: main_config.defaults.pow_challenge.timeout_secs,
            pow_window_secs: main_config.defaults.pow_challenge.window_secs,
            css_enabled: main_config.defaults.css_challenge.enabled,
            css_invalid_min: main_config.defaults.css_challenge.invalid_count_min,
            css_invalid_max: main_config.defaults.css_challenge.invalid_count_max,
            css_valid_count: main_config.defaults.css_challenge.valid_count,
            css_asset_path: main_config.defaults.css_challenge.asset_path.clone(),
            css_window_secs: main_config.defaults.css_challenge.challenge_window_secs,
            css_verification_window_secs: main_config.defaults.css_challenge.verification_window_secs,
            challenge_priority: crate::challenge::ChallengePriority::PowThenCss,
            challenge_max_attempts: 3,
            challenge_rate_limit_window_secs: 60,
            honeypot_endpoints_file: main_config.defaults.honeypot.endpoints_file.clone(),
            honeypot_enabled: true,
            honeypot_paths_per_ip: main_config.defaults.honeypot.paths_per_ip,
            honeypot_ttl_secs: main_config.defaults.honeypot.ttl_secs,
            honeypot_ban_duration: main_config.defaults.honeypot.block.ban_duration.clone(),
            error_pages_enabled: main_config.defaults.error_pages.enabled,
            error_pages_mode: "default".to_string(),
            error_pages_directory: main_config.defaults.error_pages.directory.clone(),
            error_pages_custom_directory: None,
            theme: crate::theme::ThemeConfig::from(main_config.defaults.theme.clone()),
            mesh_pow_enabled: false,
            mesh_pow_key_exchange_enabled: false,
            mesh_pow_auditing_enabled: false,
            mesh_id: None,
            mesh_global_node_url: None,
            mesh_audit_urls: Vec::new(),
        },
        crate::waf::EndpointBlockerConfig {
            paths: main_config.defaults.blocked.paths.clone(),
            use_regex: main_config.defaults.blocked.use_regex,
            block_methods: main_config.defaults.blocked.block_methods.clone(),
            block_response_code: main_config.defaults.blocked.block_response_code,
            block_page_html: None,
        },
        crate::waf::WafConfig {
            enable_css_honeypot: main_config.defaults.css_challenge.enabled,
            enable_pow_challenge: main_config.defaults.pow_challenge.enabled,
            enable_auth_challenge: main_config.defaults.auth.enabled,
            auth_login_path: main_config.defaults.auth.login_path.clone(),
            block_ai_crawlers: main_config.defaults.bot.block_ai_crawlers,
            drop_blocked_requests: false,
            test_mode: crate::waf::TestModeConfig::default(),
            honeypot_ban_duration_secs: 86400,
        },
        Vec::new(),
        None,
        None,
        Some(crate::waf::AttackDetectionConfig::default()),
        None,
        Some(main_config.threat_level.clone()),
        Some(main_config.ip_feeds.clone()),
        Some(main_config.defaults.honeypot_probe.clone()),
        Some(main_config.defaults.suspicious_words.clone()),
        Some(main_config.defaults.upstream_errors.clone()),
        Some(main_config.traffic_shaping.clone()),
        data_dir,
        crate::waf::TestModeConfig::default(),
    );

    Arc::new(waf)
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
    next_request_id: Arc<std::sync::atomic::AtomicU64>,
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
    queued_at: Instant,
}

pub async fn run_static_worker(args: StaticWorkerArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        connect::connect_to_master_async(&args.master_socket, 5, std::time::Duration::from_secs(2), "Static worker").await?
    ));

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard.send(&crate::process::Message::StaticWorkerStarted {
            worker_id: args.worker_id,
            pid: std::process::id(),
        }).await?;
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
        next_request_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
    };

    init_minifier_caches(&state, &main_config);

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
                tracing::warn!("Failed to bind static worker socket {}: {}", socket_path.display(), e);
                return Err(Box::new(e));
            }
        };

        let socket_state = state.clone();
        std::thread::spawn(move || {
            loop {
                if !socket_state.running.is_running() {
                    break;
                }

                match listener.accept() {
                    Ok((stream, _)) => {
                        let state = socket_state.clone();
                        std::thread::spawn(move || {
                            handle_minify_client_connection(stream, state);
                        });
                    }
                    Err(e) => {
                        tracing::debug!("Static worker socket accept error: {}", e);
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        
        let pipe_name = format!("\\\\.\\pipe\\rustwaf-static-worker");
        let pipe_name_wide: Vec<u16> = std::ffi::OsStr::new(&pipe_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        let socket_state = state.clone();
        
        std::thread::spawn(move || {
            loop {
                if !socket_state.running.is_running() {
                    break;
                }
                
                // Create a new pipe instance for each connection
                let pipe_handle = unsafe {
                    windows_sys::Win32::System::Pipes::CreateNamedPipeW(
                        pipe_name_wide.as_ptr(),
                        windows_sys::Win32::System::Pipes::PIPE_ACCESS_DUPLEX,
                        windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE 
                            | windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE 
                            | windows_sys::Win32::System::Pipes::PIPE_WAIT,
                        1,
                        65536,
                        65536,
                        0,
                        std::ptr::null_mut(),
                    )
                };

                if pipe_handle == 0 {
                    tracing::error!("Failed to create static worker named pipe: {:?}", std::io::Error::last_os_error());
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }

                // Wait for client connection
                let connected = unsafe {
                    windows_sys::Win32::System::Pipes::ConnectNamedPipe(
                        pipe_handle,
                        std::ptr::null_mut(),
                    )
                };

                if connected == 0 {
                    let error = unsafe { *windows_sys::Win32::Foundation::GetLastError() };
                    if error != windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED {
                        tracing::warn!("ConnectNamedPipe failed with error: {}", error);
                        unsafe { windows_sys::Win32::Foundation::CloseHandle(pipe_handle); }
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                }

                // Convert raw handle to File and handle connection
                let stream = unsafe { std::fs::File::from_raw_handle(pipe_handle as std::os::windows::io::RawHandle) };
                let state = socket_state.clone();
                std::thread::spawn(move || {
                    handle_minify_client_connection_windows(stream, state);
                });
                
                std::thread::sleep(Duration::from_millis(10));
            }
        });
    }

    let socket_handle: Option<tokio::task::JoinHandle<()>> = None;

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard.send(&crate::process::Message::StaticWorkerReady {
            worker_id: args.worker_id,
        }).await?;
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
                Ok(Some(crate::process::Message::MasterShutdown { graceful, timeout_secs })) => {
                    tracing::info!(
                        "Static worker {} received shutdown signal (graceful: {}, timeout: {}s), stopping background tasks",
                        ipc_state.worker_id,
                        graceful,
                        timeout_secs
                    );
                    
                    ipc_state.stop_background_tasks.start_drain();
                    
                    process_compression_queue(&ipc_state);
                    tracing::info!("Static worker {} completed final cache refresh", ipc_state.worker_id);
                    
                    let _ = ipc.send(&crate::process::Message::StaticWorkerBackgroundTasksDone {
                        worker_id: ipc_state.worker_id,
                    }).await;
                }
                Ok(Some(crate::process::Message::MinifyRequest { request_id, site_id, path, encoding })) => {
                    handle_minify_request_sync(&ipc_state, request_id, site_id, path, encoding);
                }
                Ok(Some(crate::process::Message::GetCompressedRequest { request_id, site_id, path, encoding })) => {
                    handle_compressed_request_sync(&ipc_state, request_id, site_id, path, encoding);
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
                tracing::info!("Static worker {} queue handler stopping (background tasks disabled)", queue_state.worker_id);
                break;
            }

            process_compression_queue(&queue_state);
        }
    });

    let watch_state = state.clone();
    let watch_interval = main_config.static_config.as_ref()
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
                tracing::info!("Static worker {} watch handler stopping (background tasks disabled)", watch_state.worker_id);
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
                                check_and_invalidate_cache(&watch_state, site_id, &root);
                            }
                        }
                    }
                }
            }

            let (cache_hits, cache_misses) = watch_state.get_cache_stats();
            
            let mut ipc = watch_state.ipc.lock().await;
            let _ = ipc.send(&crate::process::Message::StaticWorkerHeartbeat {
                worker_id: watch_state.worker_id,
                timestamp: crate::process::current_timestamp(),
                static_cache_hits: cache_hits,
                static_cache_misses: cache_misses,
            }).await;
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
            if cm.load_main(&config_path.join("main.toml")).is_ok() {
                cm.discover_sites();
                let main_config = cm.main.clone();
                
                let temp_state = StaticWorkerState {
                    worker_id: 0,
                    running: running_for_reload.clone(),
                    stop_background_tasks: stop_bg_for_reload.clone(),
                    ipc: Arc::new(TokioMutex::new(
                        futures::executor::block_on(async {
                            let path = std::path::PathBuf::from(if cfg!(windows) { "\\\\.\\pipe\\nul" } else { "/dev/null" });
                            let socket_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("dummy");
                            crate::process::ipc_transport::IpcEndpoint::new(socket_name)
                                .connect().await.unwrap_or_else(|_| {
                                    panic!("Failed to create dummy IPC for reload");
                                })
                        })
                    )),
                    config_manager: Arc::new(std::sync::RwLock::new(cm)),
                    minifier_caches: caches_for_reload.clone(),
                    compression_queue: queue_for_reload.clone(),
                    next_request_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
                };
                init_minifier_caches(&temp_state, &main_config);
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

#[cfg(unix)]
fn handle_minify_client_connection(
    stream: std::os::unix::net::UnixStream,
    state: StaticWorkerState,
) {
    let mut ipc = crate::process::IpcStream::new(stream);

    loop {
        match ipc.try_recv() {
            Ok(Some(message)) => {
                match message {
                    crate::process::Message::MinifyRequest { request_id, site_id, path, encoding } => {
                        let result = process_minify_request(&state, request_id, site_id, path, encoding);
                        match result {
                            Ok(response) => {
                                let _ = ipc.send(&response);
                            }
                            Err(error_msg) => {
                                let _ = ipc.send(&crate::process::Message::MinifyError {
                                    request_id,
                                    error: error_msg,
                                });
                            }
                        }
                    }
                    crate::process::Message::GetCompressedRequest { request_id, site_id, path, encoding } => {
                        let result = process_compressed_request(&state, request_id, site_id, path, encoding);
                        match result {
                            Ok(response) => {
                                let _ = ipc.send(&response);
                            }
                            Err(error_msg) => {
                                let _ = ipc.send(&crate::process::Message::MinifyError {
                                    request_id,
                                    error: error_msg,
                                });
                            }
                        }
                    }
                    crate::process::Message::PoisonImageRequest { request_id, site_id, body, last_modified } => {
                        let poisoned = poison_image_sync(&state, &site_id, body, last_modified);
                        let _ = ipc.send(&crate::process::Message::PoisonImageResponse {
                            request_id,
                            poisoned_body: poisoned,
                        });
                    }
                    _ => {}
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

#[cfg(windows)]
fn handle_minify_client_connection_windows(
    stream: std::fs::File,
    state: StaticWorkerState,
) {
    use std::io::{Read, Write};
    
    let mut ipc = crate::process::IpcStream::new(stream);
    let mut read_buffer = Vec::new();

    loop {
        // Read messages from the pipe
        let mut length_buf = [0u8; 4];
        match ipc.stream.read(&mut length_buf) {
            Ok(0) => break, // Client disconnected
            Ok(4) => {}
            Ok(n) => {
                tracing::debug!("Unexpected read size: {}", n);
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(_) => break,
        }

        let len = u32::from_be_bytes(length_buf) as usize;
        if len > 1024 * 1024 {
            break;
        }

        let mut json_buf = vec![0u8; len];
        let mut total_read = 0;
        while total_read < len {
            match ipc.stream.read(&mut json_buf[total_read..]) {
                Ok(0) => break,
                Ok(n) => total_read += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => break,
            }
        }

        let message: crate::process::Message = match serde_json::from_slice(&json_buf) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Failed to parse message: {}", e);
                break;
            }
        };

        match message {
            crate::process::Message::MinifyRequest { request_id, site_id, path, encoding } => {
                let result = process_minify_request(&state, request_id, site_id, path, encoding);
                match result {
                    Ok(response) => {
                        let _ = send_message_windows(&mut ipc, &response);
                    }
                    Err(error_msg) => {
                        let _ = send_message_windows(&mut ipc, &crate::process::Message::MinifyError {
                            request_id,
                            error: error_msg,
                        });
                    }
                }
            }
            crate::process::Message::GetCompressedRequest { request_id, site_id, path, encoding } => {
                let result = process_compressed_request(&state, request_id, site_id, path, encoding);
                match result {
                    Ok(response) => {
                        let _ = send_message_windows(&mut ipc, &response);
                    }
                    Err(error_msg) => {
                        let _ = send_message_windows(&mut ipc, &crate::process::Message::MinifyError {
                            request_id,
                            error: error_msg,
                        });
                    }
                }
            }
            _ => {}
        }

        if !state.running.load(std::io::Ordering::SeqCst) {
            break;
        }
    }
}

#[cfg(windows)]
fn send_message_windows(ipc: &mut crate::process::IpcStream, msg: &crate::process::Message) -> std::io::Result<()> {
    use std::io::Write;
    
    let json = serde_json::to_vec(msg).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let len = json.len() as u32;
    ipc.stream.write_all(&len.to_be_bytes())?;
    ipc.stream.write_all(&json)?;
    ipc.stream.flush()?;
    Ok(())
}

fn process_minify_request(
    state: &StaticWorkerState,
    request_id: u64,
    site_id: String,
    path: String,
    encoding: Option<String>,
) -> Result<crate::process::Message, String> {
    let cache = {
        let caches = state.minifier_caches.read()
            .map_err(|_| "Cache lock poisoned".to_string())?;
        caches.get(&site_id).cloned()
            .ok_or_else(|| format!("No cache for site: {}", site_id))?
    };
    
    let config = cache.config();
    let source_root = {
        let config_manager = state.config_manager.read()
            .map_err(|_| "Config lock poisoned".to_string())?;
        config_manager.sites.get(&site_id)
            .and_then(|s| s.r#static.locations.first())
            .map(|l| PathBuf::from(&l.root))
            .ok_or("No source root found".to_string())?
    };

    let source_path = source_root.join(path.trim_start_matches('/'));
    
    let original_content = std::fs::read(&source_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let mtime = std::fs::metadata(&source_path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let key = minifier::CacheKey {
        site_id: Arc::from(site_id.as_str()),
        path: Arc::from(path.as_str()),
        encoding: minifier::Encoding::None,
    };

    let minified_content = match cache.get(&key) {
        Some(entry) if entry.mtime >= mtime => entry.content.to_vec(),
        _ => {
            let entry = cache.minify_and_cache(&site_id, &path, &original_content, mtime)
                .map_err(|e| format!("Minification failed: {}", e))?;
            let _ = cache.write_to_disk(&site_id, &path, &entry.content, mtime);
            entry.content.to_vec()
        }
    };

    let content_type = path.rsplit('.')
        .next()
        .and_then(|e| crate::mime::MIME_REGISTRY.read().get_mime_for_extension(e))
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let mut queued_encodings = Vec::new();

    let response_content = if let Some(ref enc) = encoding {
        match enc.as_str() {
            "gzip" => {
                let enc_key = minifier::CacheKey {
                    site_id: Arc::from(site_id.as_str()),
                    path: Arc::from(path.as_str()),
                    encoding: minifier::Encoding::Gzip,
                };

                match cache.get(&enc_key) {
                    Some(entry) => entry.content.to_vec(),
                    _ => {
                        let content = cache.generate_compressed(&site_id, &path, &minified_content, &minifier::Encoding::Gzip)
                            .map_err(|e| format!("Gzip compression failed: {}", e))?;
                        let _ = cache.write_compressed_to_disk(&site_id, &path, &content, &minifier::Encoding::Gzip);
                        content.to_vec()
                    }
                }
            }
            "br" => {
                let enc_key = minifier::CacheKey {
                    site_id: Arc::from(site_id.as_str()),
                    path: Arc::from(path.as_str()),
                    encoding: minifier::Encoding::Br,
                };

                match cache.get(&enc_key) {
                    Some(entry) => entry.content.to_vec(),
                    _ => {
                        let content = cache.generate_compressed(&site_id, &path, &minified_content, &minifier::Encoding::Br)
                            .map_err(|e| format!("Brotli compression failed: {}", e))?;
                        let _ = cache.write_compressed_to_disk(&site_id, &path, &content, &minifier::Encoding::Br);
                        content.to_vec()
                    }
                }
            }
            _ => minified_content,
        }
    } else {
        minified_content
    };

    if config.enable_gzip && encoding.as_ref().map(|e| e != "gzip").unwrap_or(true) {
        queued_encodings.push("gzip".to_string());
    }
    if config.enable_brotli && encoding.as_ref().map(|e| e != "br").unwrap_or(true) {
        queued_encodings.push("br".to_string());
    }

    for enc in &queued_encodings {
        let compression_task = CompressionTask {
            site_id: site_id.clone(),
            path: path.clone(),
            encoding: enc.clone(),
            queued_at: Instant::now(),
        };
        if let Ok(mut queue) = state.compression_queue.write() {
            queue.push(compression_task);
        }
    }

    Ok(crate::process::Message::MinifyResponse {
        request_id,
        site_id,
        path,
        content: response_content,
        content_type,
        encoding,
        queued_encodings,
    })
}

fn process_compressed_request(
    state: &StaticWorkerState,
    request_id: u64,
    site_id: String,
    path: String,
    encoding: String,
) -> Result<crate::process::Message, String> {
    let cache = {
        let caches = state.minifier_caches.read()
            .map_err(|_| "Cache lock poisoned".to_string())?;
        caches.get(&site_id).cloned()
            .ok_or_else(|| format!("No cache for site: {}", site_id))?
    };

    let enc = match encoding.as_str() {
        "gzip" => minifier::Encoding::Gzip,
        "br" => minifier::Encoding::Br,
        _ => return Err(format!("Unknown encoding: {}", encoding)),
    };

    let enc_key = minifier::CacheKey {
        site_id: Arc::from(site_id.as_str()),
        path: Arc::from(path.as_str()),
        encoding: enc,
    };

    let content = cache.get(&enc_key)
        .ok_or("Compressed version not cached".to_string())?
        .content.to_vec();

    Ok(crate::process::Message::GetCompressedResponse {
        request_id,
        content,
    })
}

fn init_minifier_caches(state: &StaticWorkerState, _main_config: &crate::config::MainConfig) {
    let config = match state.config_manager.read() {
        Ok(c) => c,
        Err(_) => return,
    };
    
    let mut caches = match state.minifier_caches.write() {
        Ok(c) => c,
        Err(_) => return,
    };
    
    for (site_id, site) in config.sites.iter() {
        if !caches.contains_key(site_id) {
            if site.r#static.enable_minification.unwrap_or(true) {
                let min_config = minifier::MinifierConfig::from_site_config(site_id, &site.r#static);
                caches.insert(site_id.clone(), Arc::new(minifier::MinifierCache::new(min_config)));
                tracing::info!("Initialized minifier cache for site: {}", site_id);
            }
        }
    }
}

fn check_and_invalidate_cache(state: &StaticWorkerState, site_id: &str, root: &PathBuf) {
    if let Ok(caches) = state.minifier_caches.read() {
        if let Some(cache) = caches.get(site_id) {
            if let Ok(entries) = std::fs::read_dir(root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.is_file() {
                            let relative = path.strip_prefix(root)
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default();
                            let full_path = format!("/{}", relative);
                            
                            if cache.check_and_invalidate(site_id, &full_path) {
                                tracing::debug!("Invalidated cache for {}: {}", site_id, full_path);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn handle_minify_request_sync(
    state: &StaticWorkerState,
    request_id: u64,
    site_id: String,
    path: String,
    encoding: Option<String>,
) {
    let cache = {
        let caches = match state.minifier_caches.read() {
            Ok(c) => c,
            Err(_) => {
                send_error_sync(state, request_id, "Cache lock poisoned".to_string());
                return;
            }
        };
        match caches.get(&site_id).cloned() {
            Some(c) => c,
            None => {
                send_error_sync(state, request_id, format!("No cache for site: {}", site_id));
                return;
            }
        }
    };
    
    let config = cache.config();
    let source_root = {
        let config_manager = match state.config_manager.read() {
            Ok(c) => c,
            Err(_) => {
                send_error_sync(state, request_id, "Config lock poisoned".to_string());
                return;
            }
        };
        match config_manager.sites.get(&site_id) {
            Some(s) => s.r#static.locations.first().map(|l| PathBuf::from(&l.root)),
            None => None,
        }
    };

    let source_root = match source_root {
        Some(r) => r,
        None => {
            send_error_sync(state, request_id, "No source root found".to_string());
            return;
        }
    };

    let source_path = source_root.join(path.trim_start_matches('/'));
    
    // Use spawn_blocking to run blocking file I/O in the blocking thread pool
    // This prevents blocking the async runtime
    let file_result = task::block_in_place(|| {
        let read_result = std::fs::read(&source_path);
        let mtime = std::fs::metadata(&source_path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        (read_result, mtime)
    });

    let (original_content, mtime) = match file_result {
        (Ok(content), mtime) => (content, mtime),
        (Err(e), _) => {
            send_error_sync(state, request_id, format!("Failed to read file: {}", e));
            return;
        }
    };

    let key = minifier::CacheKey {
        site_id: Arc::from(site_id.as_str()),
        path: Arc::from(path.as_str()),
        encoding: minifier::Encoding::None,
    };

    let minified_content = match cache.get(&key) {
        Some(entry) if entry.mtime >= mtime => entry.content.to_vec(),
        _ => {
            match cache.minify_and_cache(&site_id, &path, &original_content, mtime) {
                Ok(entry) => {
                    let site_id_clone = site_id.clone();
                    let path_clone = path.clone();
                    let content = entry.content.clone();
                    let mtime_clone = mtime;
                    // Run disk write in blocking thread to avoid blocking async runtime
                    let write_result = task::block_in_place(|| {
                        cache.write_to_disk(&site_id_clone, &path_clone, &content, mtime_clone)
                    });
                    if let Err(e) = write_result {
                        tracing::warn!("Failed to write minified file: {}", e);
                    }
                    entry.content.to_vec()
                }
                Err(e) => {
                    send_error_sync(state, request_id, format!("Minification failed: {}", e));
                    return;
                }
            }
        }
    };

    let content_type = path.rsplit('.')
        .next()
        .and_then(|e| crate::mime::MIME_REGISTRY.read().get_mime_for_extension(e))
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let mut queued_encodings = Vec::new();

    let response_content = if let Some(ref enc) = encoding {
        match enc.as_str() {
            "gzip" => {
                let enc_key = minifier::CacheKey {
                    site_id: Arc::from(site_id.as_str()),
                    path: Arc::from(path.as_str()),
                    encoding: minifier::Encoding::Gzip,
                };

                match cache.get(&enc_key) {
                    Some(entry) => entry.content.to_vec(),
                    _ => {
                        match cache.generate_compressed(&site_id, &path, &minified_content, &minifier::Encoding::Gzip) {
                            Ok(content) => {
                                let site_id_clone = site_id.clone();
                                let path_clone = path.clone();
                                let content_clone = content.clone();
                                let write_result = task::block_in_place(|| {
                                    cache.write_compressed_to_disk(&site_id_clone, &path_clone, &content_clone, &minifier::Encoding::Gzip)
                                });
                                if let Err(e) = write_result {
                                    tracing::warn!("Failed to write gzip file: {}", e);
                                }
                                content.to_vec()
                            }
                            Err(e) => {
                                send_error_sync(state, request_id, format!("Gzip compression failed: {}", e));
                                return;
                            }
                        }
                    }
                }
            }
            "br" => {
                let enc_key = minifier::CacheKey {
                    site_id: Arc::from(site_id.as_str()),
                    path: Arc::from(path.as_str()),
                    encoding: minifier::Encoding::Br,
                };

                match cache.get(&enc_key) {
                    Some(entry) => entry.content.to_vec(),
                    _ => {
                        match cache.generate_compressed(&site_id, &path, &minified_content, &minifier::Encoding::Br) {
                            Ok(content) => {
                                let site_id_clone = site_id.clone();
                                let path_clone = path.clone();
                                let content_clone = content.clone();
                                let write_result = task::block_in_place(|| {
                                    cache.write_compressed_to_disk(&site_id_clone, &path_clone, &content_clone, &minifier::Encoding::Br)
                                });
                                if let Err(e) = write_result {
                                    tracing::warn!("Failed to write brotli file: {}", e);
                                }
                                content.to_vec()
                            }
                            Err(e) => {
                                send_error_sync(state, request_id, format!("Brotli compression failed: {}", e));
                                return;
                            }
                        }
                    }
                }
            }
            _ => minified_content,
        }
    } else {
        minified_content
    };

    if config.enable_gzip && encoding.as_ref().map(|e| e != "gzip").unwrap_or(true) {
        queued_encodings.push("gzip".to_string());
    }
    if config.enable_brotli && encoding.as_ref().map(|e| e != "br").unwrap_or(true) {
        queued_encodings.push("br".to_string());
    }

    for enc in &queued_encodings {
        let compression_task = CompressionTask {
            site_id: site_id.clone(),
            path: path.clone(),
            encoding: enc.clone(),
            queued_at: Instant::now(),
        };
        if let Ok(mut queue) = state.compression_queue.write() {
            queue.push(compression_task);
        }
    }

    let mut ipc = state.ipc.blocking_lock();
    let _ = ipc.send(&crate::process::Message::MinifyResponse {
            request_id,
            site_id,
            path,
            content: response_content,
            content_type,
            encoding,
            queued_encodings,
        });
}

fn send_error_sync(state: &StaticWorkerState, request_id: u64, error: String) {
    let mut ipc = state.ipc.blocking_lock();
    let _ = ipc.send(&crate::process::Message::MinifyError {
        request_id,
        error,
    });
}

fn poison_image_sync(
    _state: &StaticWorkerState,
    _site_id: &str,
    body: Vec<u8>,
    _last_modified: Option<String>,
) -> Vec<u8> {
    if body.is_empty() {
        return body;
    }
    // STUB - returns body unchanged
    // TODO: Implement actual image poisoning algorithm
    // The last_modified date is available for metadata preservation
    body
}

fn handle_compressed_request_sync(
    state: &StaticWorkerState,
    request_id: u64,
    site_id: String,
    path: String,
    encoding: String,
) {
    let cache = {
        let caches = match state.minifier_caches.read() {
            Ok(c) => c,
            Err(_) => {
                send_error_sync(state, request_id, "Cache lock poisoned".to_string());
                return;
            }
        };
        match caches.get(&site_id).cloned() {
            Some(c) => c,
            None => {
                send_error_sync(state, request_id, format!("No cache for site: {}", site_id));
                return;
            }
        }
    };

    let enc = match encoding.as_str() {
        "gzip" => minifier::Encoding::Gzip,
        "br" => minifier::Encoding::Br,
        _ => {
            send_error_sync(state, request_id, format!("Unknown encoding: {}", encoding));
            return;
        }
    };

    let enc_key = minifier::CacheKey {
        site_id: Arc::from(site_id.as_str()),
        path: Arc::from(path.as_str()),
        encoding: enc,
    };

    let content = match cache.get(&enc_key) {
        Some(entry) => entry.content.to_vec(),
        None => {
            send_error_sync(state, request_id, "Compressed version not cached".to_string());
            return;
        }
    };

    let mut ipc = state.ipc.blocking_lock();
    let _ = ipc.send(&crate::process::Message::GetCompressedResponse {
        request_id,
        content,
    });
}

fn process_compression_queue(state: &StaticWorkerState) {
    let tasks: Vec<CompressionTask> = match state.compression_queue.write() {
        Ok(mut queue) => queue.drain(..).collect(),
        Err(_) => return,
    };

    for task in tasks {
        if !state.running.is_running() {
            break;
        }

        let caches = match state.minifier_caches.read() {
            Ok(c) => c,
            Err(_) => continue,
        };
        
        if let Some(cache) = caches.get(&task.site_id) {
            let minified_key = minifier::CacheKey {
                site_id: Arc::from(task.site_id.as_str()),
                path: Arc::from(task.path.as_str()),
                encoding: minifier::Encoding::None,
            };

            let minified_content = match cache.get(&minified_key) {
                Some(e) => e.content.to_vec(),
                None => continue,
            };

            let enc = match task.encoding.as_str() {
                "gzip" => minifier::Encoding::Gzip,
                "br" => minifier::Encoding::Br,
                _ => continue,
            };

            match cache.generate_compressed(&task.site_id, &task.path, &minified_content, &enc) {
                Ok(content) => {
                    let site_id_clone = task.site_id.clone();
                    let path_clone = task.path.clone();
                    let content_clone = content.clone();
                    let enc_clone = enc.clone();
                    let write_result = task::block_in_place(|| {
                        cache.write_compressed_to_disk(&site_id_clone, &path_clone, &content_clone, &enc_clone)
                    });
                    if let Err(e) = write_result {
                        tracing::warn!("Failed to write {} file: {}", task.encoding, e);
                    } else {
                        tracing::debug!("Generated {} for {}/{}", task.encoding, task.site_id, task.path);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to generate {}: {}", task.encoding, e);
                }
            }
        }
    }
}

async fn send_error(state: &StaticWorkerState, request_id: u64, error: String) {
    let mut ipc = state.ipc.lock().await;
    let _ = ipc.send(&crate::process::Message::MinifyError {
        request_id,
        error,
    }).await;
}

async fn send_compressed_error(state: &StaticWorkerState, request_id: u64, error: String) {
    let mut ipc = state.ipc.lock().await;
    let _ = ipc.send(&crate::process::Message::MinifyError {
        request_id,
        error,
    }).await;
}
