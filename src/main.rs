use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::{broadcast, RwLock};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use rustwaf::config::ConfigManager;
use rustwaf::config::main::{LoggingConfig, MainConfig};
use rustwaf::waf::{ProbeTracker, SuspiciousWordTracker, UpstreamErrorTracker, ThreatLevelManager};
use rustwaf::process::{ProcessManager, ProcessManagerConfig, ProcessEvent, IpcStream, Message, PidFileManager, CommandClient, MasterCommand};
use rustwaf::worker::{WorkerArgs, run_worker, setup_worker_panic_handler, StaticWorkerArgs, run_static_worker};
use rustwaf::log_controller;

#[derive(Parser, Debug)]
#[command(name = "rustwaf")]
#[command(about = "Multi-Process Web Application Firewall")]
#[command(version)]
struct Args {
    #[arg(long, help = "Run as worker process")]
    worker: bool,

    #[arg(long, value_name = "ID", help = "Worker ID (worker mode only)")]
    worker_id: Option<usize>,

    #[arg(long, value_name = "PORT", help = "Worker port (worker mode only)")]
    port: Option<u16>,

    #[arg(long, value_name = "PATH", help = "Config directory path")]
    config_path: Option<PathBuf>,

    #[arg(long, value_name = "PATH", help = "Master socket path (worker mode only)")]
    master_socket: Option<PathBuf>,

    #[arg(long, help = "Run as static file worker process")]
    static_worker: bool,

    #[arg(long, value_name = "ID", help = "Static worker ID")]
    static_worker_id: Option<usize>,

    #[arg(short, long, help = "Run in foreground (don't daemonize)")]
    foreground: bool,

    #[arg(long, help = "Validate config files and exit")]
    configtest: bool,

    #[arg(long, help = "Show status of running instance")]
    status: bool,

    #[arg(long, help = "Stop running instance")]
    stop: bool,

    #[arg(long, help = "Restart instance (stop + start)")]
    restart: bool,

    #[arg(long, help = "Reload configuration and propagate to workers")]
    rehash: bool,

    #[arg(long, help = "Generate a new admin token and save it to config/main.toml")]
    generatenewtoken: bool,

    #[arg(long, help = "Generate and print an admin token (does not save to config)")]
    generatetoken: bool,

    #[arg(long, value_name = "MODE", help = "Test mode: challenge-off, ratelimit-off, attack-off, bot-off, flood-off, all-off")]
    test: Option<Vec<String>>,

    #[arg(short, long, value_name = "LEVEL", help = "Log level: trace, debug, info, warn, error (overrides config)")]
    log_level: Option<String>,
}

#[derive(Clone)]
struct MasterState {
    config: Arc<RwLock<ConfigManager>>,
    shutdown_tx: broadcast::Sender<()>,
    probe_tracker: Option<Arc<ProbeTracker>>,
    suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    threat_level_manager: Option<Arc<ThreatLevelManager>>,
}

impl MasterState {
    fn new(
        config: Arc<RwLock<ConfigManager>>, 
        probe_tracker: Option<Arc<ProbeTracker>>,
        suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
        upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
        threat_level_manager: Option<Arc<ThreatLevelManager>>,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        
        Self {
            config,
            shutdown_tx,
            probe_tracker,
            suspicious_word_tracker,
            upstream_error_tracker,
            threat_level_manager,
        }
    }
    
    fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
    
    async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

fn setup_master_panic_handler() {
    std::panic::set_hook(Box::new(|panic_info| {
        let location = panic_info.location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        
        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };

        tracing::error!("MASTER PANIC at {}: {}", location, message);
        eprintln!("\n=== MASTER PROCESS PANIC ===\nLocation: {}\nMessage: {}\n", location, message);
        
        let _ = std::fs::write("/tmp/rustwaf-panic.log", format!("{}: {}", location, message));
    }));
}

fn setup_signal_handlers(master_state: MasterState, process_manager: Arc<ProcessManager>) {
    let state = master_state.clone();
    let pm = process_manager.clone();
    
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
                state.shutdown().await;
                pm.graceful_shutdown().await;
            }
            Err(e) => {
                tracing::error!("Error in signal handler: {}", e);
            }
        }
    });

    /// Unix-specific signal handler for graceful shutdown.
    ///
    /// Signal handling notes:
    /// - This handles SIGTERM (not SIGINT/Ctrl+C which is handled separately above)
    /// - On Unix, SIGTERM is the standard signal for graceful shutdown request
    /// - On Windows, we rely solely on Ctrl+C (handled by ctrl_c() above)
    /// - The SIGTERM handler triggers the same graceful shutdown flow as Ctrl+C
    #[cfg(unix)]
    {
        let state = master_state.clone();
        let pm = process_manager.clone();
        
        tokio::spawn(async move {
            let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Failed to install SIGTERM handler: {}", e);
                    return;
                }
            };
            
            sigterm.recv().await;
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
            state.shutdown().await;
            pm.graceful_shutdown().await;
        });
    }
}

fn init_logging(config: &LoggingConfig, log_level_override: Option<String>) {
    let level = log_level_override.unwrap_or_else(|| config.level.clone());
    log_controller::init_logging_with_dynamic_level(&level);
}

fn init_logging_simple() {
    log_controller::init_logging_with_dynamic_level("info");
}

fn print_test_mode_warning(test_flags: &[String]) {
    let mut disabled = Vec::new();
    
    for flag in test_flags {
        match flag.as_str() {
            "challenge-off" | "challenge_off" => disabled.push("challenge"),
            "ratelimit-off" | "ratelimit_off" => disabled.push("ratelimit"),
            "attack-off" | "attack_off" => disabled.push("attack"),
            "bot-off" | "bot_off" => disabled.push("bot"),
            "flood-off" | "flood_off" => disabled.push("flood"),
            "all-off" | "all_off" => {
                disabled.clear();
                disabled.push("ALL");
                break;
            }
            _ => {}
        }
    }
    
    if disabled.is_empty() {
        disabled.push("ALL");
    }
    
    let is_all_disabled = disabled.iter().any(|s| s.to_lowercase() == "all");
    let disabled_str = if is_all_disabled {
        "ALL".to_string()
    } else {
        disabled.join(", ")
    };
    
    eprintln!("");
    eprintln!("╔═══════════════════════════════════════════════════════════════════════════╗");
    eprintln!("║                     WARNING: TEST MODE ENABLED                           ║");
    eprintln!("║                                                                       ║");
    eprintln!("║  Protections DISABLED: {}                                          ║", disabled_str);
    eprintln!("║  This mode is intended for throughput/capacity testing only.         ║");
    eprintln!("║  DO NOT use in production.                                          ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════════════════╝");
    eprintln!("");
}

fn handle_status() -> Result<(), Box<dyn std::error::Error>> {
    let pid_manager = PidFileManager::new();
    
    if let Some(content) = pid_manager.read_pid() {
        if pid_manager.is_running() {
            let client = CommandClient::new(Some(pid_manager.socket_file_path()));
            
            match client.get_status() {
                Ok(status) => {
                    println!("RustWAF Status");
                    println!("==============");
                    println!("Master PID: {}", status.master_pid);
                    println!("Version: {}", status.version);
                    println!("Uptime: {} seconds", status.uptime_secs);
                    println!("");
                    println!("Workers:");
                    println!("  {:<4} {:<8} {:<6} {:<10} {:<12} {:<10}", "ID", "PID", "Port", "Status", "Requests", "Blocked");
                    println!("  {}", "-".repeat(60));
                    for worker in &status.workers {
                        println!("  {:<4} {:<8} {:<6} {:<10} {:<12} {:<10}", 
                            worker.id, worker.pid, worker.port, worker.status, worker.requests, worker.blocked);
                    }
                    println!("");
                    println!("Stats (last hour):");
                    println!("  Total Requests:    {}", status.stats.total_requests);
                    println!("  Blocked:           {} ({:.1}%)", 
                        status.stats.blocked_last_hour,
                        if status.stats.total_requests > 0 { 
                            (status.stats.blocked_last_hour as f64 / status.stats.total_requests as f64) * 100.0 
                        } else { 0.0 });
                    println!("  Challenged:        {}", status.stats.challenged_last_hour);
                    println!("  Proxied:           {}", status.stats.proxied_last_hour);
                    println!("");
                    println!("Threat Summary:");
                    println!("  Active Blocks:     {}", status.stats.active_blocks);
                    println!("  Critical IPs:      {}", status.threat_summary.critical_ips);
                    println!("  Elevated IPs:     {}", status.threat_summary.elevated_ips);
                    
                    return Ok(());
                }
                Err(e) => {
                    println!("RustWAF appears to be running but status is unavailable: {}", e);
                    println!("PID: {}", content.pid);
                    return Ok(());
                }
            }
        }
    }
    
    println!("RustWAF is not running");
    Ok(())
}

fn handle_stop() -> Result<(), Box<dyn std::error::Error>> {
    let pid_manager = PidFileManager::new();
    
    if let Some(content) = pid_manager.read_pid() {
        if pid_manager.is_running() {
            let client = CommandClient::new(Some(pid_manager.socket_file_path()));
            
            match client.send_command(MasterCommand::Stop { graceful: true }) {
                Ok(msg) => {
                    println!("Stop signal sent: {}", msg);
                    println!("Waiting for shutdown...");
                    
                    let mut count = 0;
                    while pid_manager.is_running() && count < 30 {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        count += 1;
                    }
                    
                    if pid_manager.is_running() {
                        println!("Warning: Process did not shut down cleanly");
                    } else {
                        println!("RustWAF stopped");
                        pid_manager.remove_pid()?;
                        pid_manager.remove_socket()?;
                    }
                }
                Err(e) => {
                    println!("Failed to send stop command: {}", e);
                }
            }
            return Ok(());
        }
    }
    
    println!("RustWAF is not running");
    Ok(())
}

fn handle_rehash() -> Result<(), Box<dyn std::error::Error>> {
    let pid_manager = PidFileManager::new();
    
    if let Some(content) = pid_manager.read_pid() {
        if pid_manager.is_running() {
            let client = CommandClient::new(Some(pid_manager.socket_file_path()));
            
            match client.send_command(MasterCommand::ReloadConfig) {
                Ok(msg) => {
                    println!("Reload signal sent: {}", msg);
                }
                Err(e) => {
                    println!("Failed to send reload command: {}", e);
                }
            }
            return Ok(());
        }
    }
    
    println!("RustWAF is not running");
    Ok(())
}

fn handle_configtest(config_path: &Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = config_path.clone().unwrap_or_else(|| PathBuf::from("config"));
    let main_config_path = config_dir.join("main.toml");
    
    println!("Testing configuration files...");
    
    if !main_config_path.exists() {
        eprintln!("Error: main.toml not found at {:?}", main_config_path);
        std::process::exit(1);
    }
    
    match MainConfig::from_file(&main_config_path) {
        Ok(config) => {
            println!("✓ main.toml is valid");
            
            let sites_dir = config_dir.join("sites");
            if sites_dir.exists() {
                for entry in std::fs::read_dir(&sites_dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().map(|e| e == "toml").unwrap_or(false) {
                        match rustwaf::config::site::SiteConfig::from_file(&path) {
                            Ok(_) => {
                                println!("✓ {} is valid", path.file_name().unwrap().to_string_lossy());
                            }
                            Err(e) => {
                                eprintln!("✗ {}: {}", path.file_name().unwrap().to_string_lossy(), e);
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }
            
            println!("\nAll configuration files are valid");
            Ok(())
        }
        Err(e) => {
            eprintln!("✗ main.toml: {}", e);
            std::process::exit(1);
        }
    }
}

fn generate_token_hex() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn handle_generatetoken() {
    let token = generate_token_hex();
    println!("{}", token);
}

fn handle_generatenewtoken(config_path: &Option<PathBuf>) {
    let token = generate_token_hex();
    println!("{}", token);

    let config_dir = config_path.clone().unwrap_or_else(|| PathBuf::from("config"));
    let main_config_path = config_dir.join("main.toml");

    if let Err(e) = std::fs::create_dir_all(&config_dir) {
        eprintln!("Error: Failed to create config directory: {}", e);
        return;
    }

    let content = if main_config_path.exists() {
        match std::fs::read_to_string(&main_config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: Failed to read config file: {}", e);
                return;
            }
        }
    } else {
        let default_config = r#"# RustWAF Main Configuration
# This file was generated by --generatenewtoken

[server]
host = "0.0.0.0"
port = 8080
trusted_proxies = ["127.0.0.1", "::1"]

[tokio]
worker_threads = "auto"

[http]
header_read_timeout_secs = 10
keep_alive_timeout_secs = 60
max_headers = 128
max_request_line_size = 8192
max_header_size_ingress = 4096
max_header_size_egress = 16384
max_request_size = 1048576
pipeline_limit = 32

[admin]
enabled = true
port = 8081
token = "TOKEN_PLACEHOLDER"

[logging]
level = "info"
access_log = true
access_log_format = "json"
retention_days = 5
max_entries_per_file = 50000

[metrics]
enabled = true
port = 9090

[defaults]
[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60
per_5min = 200
per_10min = 350
per_hour = 500
per_day = 1000
burst = 20

[defaults.ratelimit.global]
per_second = 500
per_minute = 5000
per_5min = 20000
max_connections = 1000

[defaults.blocked]
paths = ["/.env", "/.git", "/wp-login.php"]
use_regex = true
block_methods = ["GET", "POST", "PUT", "DELETE"]

[defaults.worker_pool]
mode = "shared"
workers = 4
worker_port_base = 9000
auto_scale = true
"#;
        default_config.to_string()
    };

    let updated_content = if content.contains("[admin]") {
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut in_admin_section = false;
        let mut token_updated = false;

        for (i, line) in lines.iter_mut().enumerate() {
            let trimmed = line.trim();
            if trimmed == "[admin]" {
                in_admin_section = true;
            } else if trimmed.starts_with('[') && trimmed != "[admin]" {
                in_admin_section = false;
            }
            
            if in_admin_section && trimmed.starts_with("token") && trimmed.contains('=') {
                *line = format!("token = \"{}\"", token);
                token_updated = true;
                break;
            }
        }

        if !token_updated {
            if let Some(pos) = lines.iter().position(|l| l.trim() == "[admin]") {
                lines.insert(pos + 3, format!("token = \"{}\"", token));
            }
        }

        lines.join("\n")
    } else {
        let admin_section = format!("\n[admin]\nenabled = true\nport = 8081\ntoken = \"{}\"\n", token);
        content + &admin_section
    };

    if let Err(e) = std::fs::write(&main_config_path, &updated_content) {
        eprintln!("Error: Failed to write config file: {}", e);
        return;
    }

    println!("Config file updated: {:?}", main_config_path);
    println!("Admin token has been set in [admin] section");
}

fn main() {
    let args = Args::parse();

    // Handle CLI commands that don't require starting the server
    if args.configtest {
        if let Err(e) = handle_configtest(&args.config_path) {
            eprintln!("Config test failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.generatetoken {
        handle_generatetoken();
        std::process::exit(0);
    }

    if args.generatenewtoken {
        handle_generatenewtoken(&args.config_path);
        std::process::exit(0);
    }

    if args.status {
        if let Err(e) = handle_status() {
            eprintln!("Status check failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.stop {
        if let Err(e) = handle_stop() {
            eprintln!("Stop failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.rehash {
        if let Err(e) = handle_rehash() {
            eprintln!("Reload failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.restart {
        let _ = handle_stop();
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Check for test mode flags and print warning
    if let Some(ref test_flags) = args.test {
        print_test_mode_warning(test_flags);
    }

    // Check if already running
    let pid_manager = PidFileManager::new();
    if pid_manager.is_running() {
        eprintln!("RustWAF is already running (PID: {:?})", pid_manager.get_pid());
        std::process::exit(1);
    }

    // Check for worker mode
    if args.worker {
        setup_worker_panic_handler();
        init_logging_simple();

        let worker_args = WorkerArgs {
            worker_id: args.worker_id.unwrap_or(0),
            port: args.port.unwrap_or(9000),
            config_path: args.config_path.unwrap_or_else(|| PathBuf::from("config")),
            master_socket: args.master_socket.unwrap_or_else(|| PathBuf::from("/tmp/rustwaf-master.sock")),
            test_mode: args.test,
            log_level: args.log_level,
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");

        if let Err(e) = rt.block_on(run_worker(worker_args)) {
            tracing::error!("Worker error: {}", e);
            std::process::exit(1);
        }
    } else if args.static_worker {
        setup_worker_panic_handler();
        init_logging_simple();

        let static_worker_args = StaticWorkerArgs {
            worker_id: args.static_worker_id.unwrap_or(0),
            config_path: args.config_path.unwrap_or_else(|| PathBuf::from("config")),
            master_socket: args.master_socket.unwrap_or_else(|| PathBuf::from("/tmp/rustwaf-master.sock")),
            static_worker_socket: PathBuf::from("/tmp/rustwaf-static-worker.sock"),
            log_level: args.log_level,
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");

        if let Err(e) = rt.block_on(run_static_worker(static_worker_args)) {
            tracing::error!("Static worker error: {}", e);
            std::process::exit(1);
        }
    } else {
        setup_master_panic_handler();

        let config_dir = args.config_path.unwrap_or_else(|| PathBuf::from("config"));
        let main_config_path = config_dir.join("main.toml");

        let mut config_manager = ConfigManager::new(config_dir.clone());

        if let Err(e) = config_manager.load_main(&main_config_path) {
            eprintln!("Failed to load main.toml: {}, using defaults", e);
        }

        let main_config = config_manager.main.clone();

        // Write PID file before starting
        let pid_manager = PidFileManager::new();
        let current_pid = std::process::id();
        let version = env!("CARGO_PKG_VERSION");
        
        if let Err(e) = pid_manager.write_pid(current_pid, version) {
            eprintln!("Warning: Failed to write PID file: {}", e);
        }

        // Daemonize unless foreground flag is set or test mode is enabled
        let should_daemonize = !args.foreground && args.test.is_none();
        
        if should_daemonize {
            #[cfg(unix)]
            {
                let current_dir = std::env::current_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("/"));
                
                match daemonize::Daemonize::new()
                    .working_directory(current_dir)
                    .umask(0o077)
                    .pid_file(pid_manager.pid_file_path())
                    .start()
                {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Failed to daemonize: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                eprintln!("Warning: Daemonization is not supported on this platform, running in foreground");
            }
        }

        let worker_threads = main_config.tokio.worker_threads;
        tracing::info!("Starting RustWAF Master Process with {} worker threads", worker_threads);

        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("Failed to build Tokio runtime: {}", e);
                std::process::exit(1);
            }
        };

        let result = std::panic::catch_unwind(|| {
            rt.block_on(run_master(config_manager, main_config, args.log_level.clone()))
        });

        match result {
            Ok(Ok(())) => {
                tracing::info!("RustWAF master process exited cleanly");
            }
            Ok(Err(e)) => {
                tracing::error!("RustWAF master process error: {}", e);
                eprintln!("Error: {}", e);
                
                eprintln!("Master process exiting due to error");
                std::process::exit(1);
            }
            Err(panic_info) => {
                tracing::error!("RustWAF master process panicked: {:?}", panic_info);
                eprintln!("Master process panic: {:?}", panic_info);
                eprintln!("Master process exiting due to panic");
                std::process::exit(1);
            }
        }
    }
}

async fn run_master(
    mut config_manager: ConfigManager,
    main_config: MainConfig,
    log_level_override: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let log_level_for_process = log_level_override.clone();
    init_logging(&main_config.logging, log_level_override);

    tracing::info!("========================================");
    tracing::info!("Starting RustWAF - Multi-Process WAF");
    tracing::info!("========================================");
    tracing::info!("Main HTTP entry: http://{}:{}", main_config.server.host, main_config.server.port);

    let site_results = config_manager.discover_sites();
    let loaded_count = site_results.iter().filter(|r| r.1.is_ok()).count();
    let failed_count = site_results.iter().filter(|r| r.1.is_err()).count();
    
    tracing::info!("Loaded {} site(s), {} failed", loaded_count, failed_count);

    for (site_id, result) in &site_results {
        if let Err(e) = result {
            tracing::warn!("Site '{}' error: {}", site_id, e);
        }
    }

    let config_path_for_process = config_manager.sites_dir.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| config_manager.sites_dir.clone());
    
    let shared_config = Arc::new(RwLock::new(config_manager));
    
    let unified_server = rustwaf::server::UnifiedServer::new(shared_config.clone()).await?;
    let probe_tracker = unified_server.get_probe_tracker();
    let suspicious_word_tracker = unified_server.get_suspicious_word_tracker();
    let upstream_error_tracker = unified_server.get_upstream_error_tracker();
    let threat_level_manager = unified_server.get_threat_level_manager();
    
    let master_state = MasterState::new(
        shared_config.clone(), 
        probe_tracker,
        suspicious_word_tracker,
        upstream_error_tracker,
        threat_level_manager,
    );

    #[cfg(unix)]
    let master_socket_path = PathBuf::from("/tmp/rustwaf-master.sock");
    
    #[cfg(windows)]
    let master_socket_path = PathBuf::from("rustwaf-master");

    #[cfg(unix)]
    if master_socket_path.exists() {
        std::fs::remove_file(&master_socket_path)?;
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let pipe_name: Vec<u16> = std::ffi::OsStr::new("\\\\.\\pipe\\rustwaf-master")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        // Try to clean up any existing pipe
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(
                windows_sys::Win32::System::Pipes::CreateNamedPipeW(
                    pipe_name.as_ptr(),
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
            );
        }
    }

    let process_config = ProcessManagerConfig {
        min_workers: main_config.defaults.worker_pool.workers,
        max_workers: 16,
        max_restart_attempts: 5,
        restart_cooldown_secs: 60,
        heartbeat_timeout_secs: 30,
        graceful_shutdown_timeout_secs: 30,
        worker_port_base: main_config.defaults.worker_pool.worker_port_base,
        config_path: config_path_for_process,
        master_socket_path: master_socket_path.clone(),
        log_level: log_level_for_process,
    };

    let (process_manager, mut event_rx) = ProcessManager::new(process_config);
    let process_manager = Arc::new(process_manager);

    #[cfg(unix)]
    {
        let ipc_listener = tokio::net::UnixListener::bind(&master_socket_path)?;
        tracing::info!("Master IPC socket listening at {:?}", master_socket_path);

        let pm_clone = process_manager.clone();
        tokio::spawn(async move {
            loop {
                match ipc_listener.accept().await {
                    Ok((stream, _addr)) => {
                        #[cfg(unix)]
                        {
                            let stream = stream.into_std().expect("Failed to convert stream");
                            let ipc = IpcStream::new(stream);
                            let pm = pm_clone.clone();
                            
                            tokio::spawn(async move {
                                handle_worker_connection(ipc, pm).await;
                            });
                        }
                    }
                    Err(e) => {
                        tracing::debug!("IPC accept error: {}", e);
                    }
                }
            }
        });
    }

    #[cfg(windows)]
    {
        tracing::info!("Master IPC listening on Windows named pipe: \\\\.\\pipe\\rustwaf-master");
        
        // On Windows, we need a different approach for IPC
        // The workers will connect via named pipes
        // For now, we'll spawn a background task that handles Windows pipe connections
        let pm_clone = process_manager.clone();
        let master_path = master_socket_path.clone();
        
        tokio::spawn(async move {
            windows_ipc_accept_loop(pm_clone, master_path).await;
        });

        // Also start command pipe listener for CLI commands
        let config_clone = config_manager.clone();
        tokio::spawn(async move {
            windows_command_pipe_listener(config_clone).await;
        });
    }

    for _ in 0..main_config.defaults.worker_pool.workers {
        process_manager.spawn_worker()?;
    }

    if main_config.static_config.as_ref().and_then(|c| c.enabled).unwrap_or(true) {
        if let Err(e) = process_manager.spawn_static_worker() {
            tracing::warn!("Failed to spawn static worker: {}", e);
        }
    }

    setup_signal_handlers(master_state.clone(), process_manager.clone());

    let pm_health = process_manager.clone();
    tokio::spawn(async move {
        rustwaf::process::start_health_monitor(pm_health, 5).await;
    });

    tracing::info!("Starting admin server...");
    let admin_state = master_state.clone();
    tokio::spawn(async move {
        rustwaf::admin::start_admin_server(
            admin_state.config, 
            admin_state.probe_tracker,
            admin_state.suspicious_word_tracker,
            admin_state.upstream_error_tracker,
            admin_state.threat_level_manager,
        ).await;
    });

    tracing::info!("Starting unified server...");
    let server_state = master_state.clone();
    tokio::spawn(async move {
        if let Err(e) = run_server(server_state, unified_server).await {
            tracing::error!("Server error: {}", e);
        }
    });

    let mut shutdown_rx = master_state.subscribe_shutdown();

    loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
                match event {
                    ProcessEvent::WorkerStarted(id, pid, port) => {
                        tracing::info!("Worker {} started (PID: {}, port: {})", id, pid, port);
                    }
                    ProcessEvent::WorkerReady(id) => {
                        tracing::info!("Worker {} ready", id);
                    }
                    ProcessEvent::WorkerStopped(id) => {
                        tracing::warn!("Worker {} stopped", id);
                    }
                    ProcessEvent::WorkerFailed(id, error) => {
                        tracing::error!("Worker {} failed: {}", id, error);
                    }
                    ProcessEvent::WorkerRestarted(id, attempt) => {
                        tracing::info!("Worker {} restarted (attempt {})", id, attempt);
                    }
                    ProcessEvent::ShutdownInitiated => {
                        tracing::info!("Shutdown initiated by process manager");
                    }
                    ProcessEvent::ShutdownComplete => {
                        tracing::info!("Process manager shutdown complete");
                        break;
                    }
                }
            }
            
            _ = shutdown_rx.recv() => {
                tracing::info!("Shutdown signal received");
                break;
            }
        }
    }

    tracing::info!("Initiating graceful shutdown...");
    process_manager.graceful_shutdown().await;

    if master_socket_path.exists() {
        std::fs::remove_file(&master_socket_path)?;
    }

    tracing::info!("RustWAF shutdown complete");
    Ok(())
}

#[cfg(windows)]
async fn windows_ipc_accept_loop(process_manager: Arc<ProcessManager>, pipe_name: PathBuf) {
    use std::os::windows::ffi::OsStrExt;
    
    let pipe_name_str = format!("\\\\.\\pipe\\rustwaf-master");
    let pipe_name_wide: Vec<u16> = std::ffi::OsStr::new(&pipe_name_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    loop {
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
            tracing::error!("Failed to create named pipe: {:?}", std::io::Error::last_os_error());
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        }

        // Convert raw handle to File
        let stream = unsafe { std::fs::File::from_raw_fd(pipe_handle as i32) };
        
        let pm = process_manager.clone();
        tokio::spawn(async move {
            let ipc = IpcStream::new(stream);
            handle_worker_connection(ipc, pm).await;
        });
    }
}

#[cfg(windows)]
async fn windows_command_pipe_listener(config_manager: Arc<RwLock<ConfigManager>>) {
    use std::os::windows::ffi::OsStrExt;
    
    let pipe_name_str = "\\\\.\\pipe\\rustwaf-commands";
    let pipe_name_wide: Vec<u16> = std::ffi::OsStr::new(pipe_name_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    loop {
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
            tracing::error!("Failed to create command pipe: {:?}", std::io::Error::last_os_error());
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        }

        // Convert raw handle to File and handle command
        let stream = unsafe { std::fs::File::from_raw_fd(pipe_handle as i32) };
        tokio::spawn(async move {
            handle_command_connection(stream, config_manager.clone()).await;
        });
    }
}

#[cfg(windows)]
async fn handle_command_connection(stream: std::fs::File, config_manager: Arc<RwLock<ConfigManager>>) {
    use std::io::{Read, Write};
    
    let mut stream = stream;
    
    // Read command
    let mut length_buf = [0u8; 4];
    match stream.read_exact(&mut length_buf) {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to read command length: {}", e);
            return;
        }
    }
    
    let len = u32::from_be_bytes(length_buf) as usize;
    if len > 1024 * 1024 {
        let _ = stream.write_all(&0u32.to_be_bytes());
        return;
    }
    
    let mut json_buf = vec![0u8; len];
    if let Err(e) = stream.read_exact(&mut json_buf) {
        tracing::warn!("Failed to read command: {}", e);
        return;
    }
    
    let command: crate::process::MasterCommand = match serde_json::from_slice(&json_buf) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to parse command: {}", e);
            let _ = stream.write_all(&0u32.to_be_bytes());
            return;
        }
    };
    
    // Handle command and send response
    let response = match command {
        crate::process::MasterCommand::Stop { graceful } => {
            tracing::info!("CLI: Stop command received (graceful: {})", graceful);
            // Trigger shutdown
            let _ = stream.write_all(&4u32.to_be_bytes());
            let _ = stream.write_all(b"true");
            return;
        }
        crate::process::MasterCommand::ReloadConfig => {
            tracing::info!("CLI: ReloadConfig command received");
            // Reload config
            let _ = stream.write_all(&4u32.to_be_bytes());
            let _ = stream.write_all(b"true");
            return;
        }
        crate::process::MasterCommand::Status => {
            // Return status
            let status = crate::process::MasterStatus {
                master_pid: std::process::id(),
                started_at: 0,
                uptime_secs: 0,
                version: env!("CARGO_PKG_VERSION").to_string(),
                workers: vec![],
                stats: crate::process::StatusStats::default(),
                threat_summary: crate::process::ThreatSummary::default(),
            };
            let json = serde_json::to_string(&crate::process::CommandResponse::Status(status)).unwrap_or_default();
            let len = json.len() as u32;
            let _ = stream.write_all(&len.to_be_bytes());
            let _ = stream.write_all(json.as_bytes());
            return;
        }
        crate::process::MasterCommand::HealthCheck => {
            let _ = stream.write_all(&4u32.to_be_bytes());
            let _ = stream.write_all(b"true");
            return;
        }
    };
}

async fn handle_worker_connection(mut ipc: IpcStream, process_manager: Arc<ProcessManager>) {
    loop {
        match ipc.recv(5000) {
            Ok(Some(message)) => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match message {
                        Message::WorkerStarted { id, pid, port, timestamp: _ } => {
                            tracing::debug!("Worker {} connected (PID: {}, port: {})", id, pid, port);
                        }
                        Message::WorkerReady { id } => {
                            process_manager.handle_worker_ready(id);
                        }
                        Message::WorkerHeartbeat { id, timestamp: _, metrics } => {
                            process_manager.handle_heartbeat(id, metrics);
                        }
                        Message::WorkerError { id, error, severity, error_code } => {
                            process_manager.handle_worker_error(id, error, severity, error_code);
                        }
                        Message::WorkerShutdownComplete { id } => {
                            process_manager.mark_worker_stopped(id);
                            return Err(()); 
                        }
                        Message::StaticWorkerStarted { worker_id, pid } => {
                            tracing::debug!("Static worker {} connected (PID: {})", worker_id, pid);
                        }
                        Message::StaticWorkerReady { worker_id } => {
                            process_manager.handle_static_worker_ready(worker_id);
                        }
                        Message::StaticWorkerHeartbeat { worker_id, timestamp: _ } => {
                            process_manager.handle_static_worker_heartbeat(worker_id);
                        }
                        Message::StaticWorkerShutdownComplete { worker_id } => {
                            tracing::info!("Static worker {} shutdown complete", worker_id);
                            return Err(());
                        }
                        Message::MinifyResponse { request_id, site_id, path, content, content_type: _, encoding, queued_encodings } => {
                            tracing::debug!(
                                "Minify response for request {}: site={}, path={}, size={}, queued={:?}",
                                request_id, site_id, path, content.len(), queued_encodings
                            );
                        }
                        Message::MinifyError { request_id, error } => {
                            tracing::warn!("Minify error for request {}: {}", request_id, error);
                        }
                        Message::GetCompressedResponse { request_id, content } => {
                            tracing::debug!("Compressed response for request {}: size={}", request_id, content.len());
                        }
                        Message::HealthCheckAck { timestamp: _ } => {}
                        _ => {}
                    }
                    Ok(())
                }));
                
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(())) => break,
                    Err(panic_info) => {
                        tracing::error!("IPC message handler panicked: {:?}", panic_info);
                        break;
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("Worker connection error: {}", e);
                break;
            }
        }
    }
}

async fn run_server(
    state: MasterState,
    unified_server: rustwaf::server::UnifiedServer,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut shutdown_rx = state.subscribe_shutdown();
    
    let server_task = tokio::spawn(async move {
        if let Err(e) = unified_server.run().await {
            tracing::error!("Unified server error: {}", e);
        }
    });
    
    tokio::select! {
        result = server_task => {
            if let Err(e) = result {
                tracing::error!("Server task error: {}", e);
            }
        }
        _ = shutdown_rx.recv() => {
            tracing::info!("Server received shutdown signal");
        }
    }
    
    Ok(())
}
