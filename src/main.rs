use std::path::PathBuf;

use clap::Parser;

#[cfg(feature = "mesh")]
use synvoid::master::handle_export_threat_feed;
use synvoid::master::{
    handle_configtest, handle_generatenewtoken, handle_generatetoken, handle_rehash, handle_status,
    handle_stop,
};
use synvoid::worker::{
    run_static_worker, run_unified_server_worker, setup_unified_server_panic_handler,
    setup_worker_panic_handler,
};

use synvoid::startup::bootstrap::{init_logging_simple, print_test_mode_warning};
use synvoid::startup::daemon::acquire_pid_file;
use synvoid::startup::worker::{build_static_worker_args, build_unified_server_worker_args};
use synvoid::supervisor::run_supervisor_mode;
#[cfg(feature = "mesh")]
use synvoid::startup::master::{run_master_mode, run_overseer_mode};

#[derive(Parser, Debug)]
#[command(name = "synvoid")]
#[command(about = "Multi-Process Web Application Firewall")]
#[command(version)]
struct Args {
    #[arg(long, help = "Run as mesh agent process (control plane)")]
    mesh_agent: bool,

    #[arg(long, help = "Run as master process (legacy mode - managed by Overseer)")]
    master: bool,

    #[arg(long, help = "Run as WASM plugin execution jail")]
    wasm_jail: bool,

    #[arg(long, help = "Run as YARA rule evaluation jail")]
    yara_jail: bool,

    #[arg(long, help = "Run as worker process")]
    worker: bool,

    #[arg(long, value_name = "ID", help = "Worker ID (worker mode only)")]
    worker_id: Option<usize>,

    #[arg(long, value_name = "PORT", help = "Worker port (worker mode only)")]
    port: Option<u16>,

    #[arg(long, value_name = "PATH", help = "Config directory path")]
    config_path: Option<PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Master socket path (worker mode only)"
    )]
    master_socket: Option<PathBuf>,

    #[arg(long, help = "Run as static file worker process")]
    static_worker: bool,

    #[arg(long, value_name = "ID", help = "Static worker ID")]
    static_worker_id: Option<usize>,

    #[arg(
        long,
        help = "Run as unified server worker process (handles HTTP/HTTPS/HTTP3)"
    )]
    unified_server_worker: bool,

    #[arg(long, value_name = "ID", help = "Unified server worker ID")]
    unified_worker_id: Option<usize>,

    #[arg(
        long,
        value_name = "COUNT",
        help = "Number of tokio worker threads (for worker processes)"
    )]
    worker_threads: Option<usize>,

    #[arg(long, value_name = "CORE", help = "CPU core to pin this worker to")]
    cpu_affinity: Option<usize>,

    #[arg(
        long,
        value_name = "COUNT",
        help = "Total number of workers in the pool"
    )]
    total_workers: Option<usize>,

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

    #[arg(
        long,
        help = "Generate a new admin token and save it to config/main.toml"
    )]
    generatenewtoken: bool,

    #[arg(
        long,
        help = "Generate and print an admin token (does not save to config)"
    )]
    generatetoken: bool,

    #[arg(
        long,
        value_name = "TOKEN",
        help = "Hash an admin token for use in config (reads token from stdin if not provided)"
    )]
    hash_token: Option<Option<String>>,

    #[arg(
        long,
        value_name = "COST",
        help = "Bcrypt cost for token hashing (default: 12, min: 4, max: 31)"
    )]
    hash_cost: Option<u32>,

    #[arg(
        long,
        value_name = "MODE",
        help = "Test mode: challenge-off, ratelimit-off, attack-off, bot-off, flood-off, all-off"
    )]
    test: Option<Vec<String>>,

    #[arg(
        long,
        value_name = "PATTERN",
        help = "Check if a regex pattern is safe (ReDoS check)"
    )]
    checkregex: Option<String>,

    #[arg(
        long,
        help = "Required when using --test all-off to confirm intentional testing"
    )]
    force: bool,

    #[arg(
        short,
        long,
        value_name = "LEVEL",
        help = "Log level: trace, debug, info, warn, error (overrides config)"
    )]
    log_level: Option<String>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "Address of the Supervisor control API (gRPC)"
    )]
    control_addr: Option<String>,

    #[arg(long, help = "Export OpenAPI spec as JSON and exit")]
    export_openapi: bool,

    #[arg(long, help = "Export API specification (OpenAPI 3.0) as JSON and exit")]
    export_api_spec: bool,

    #[arg(long, help = "Export threat feed as JSON")]
    export_threat_feed: bool,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to Ed25519 private key for signing threat feed"
    )]
    sign_with: Option<PathBuf>,

    #[arg(long, value_name = "SITE_ID", help = "Filter threat feed by site ID")]
    site_id: Option<String>,

    #[arg(long, help = "Generate a new genesis key for first global node setup")]
    genesis: bool,

    #[arg(
        long,
        help = "Show current node information (node ID, public key, genesis status)"
    )]
    show_node_info: bool,
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

    if args.export_openapi {
        use synvoid::config::MainConfig;
        let schema = schemars::schema_for!(MainConfig);
        println!(
            "{}",
            serde_json::to_string_pretty(&schema).unwrap_or_default()
        );
        std::process::exit(0);
    }

    if args.export_api_spec {
        use synvoid::admin::openapi::synvoidOpenApi;
        let spec = synvoidOpenApi::openapi_json();
        println!(
            "{}",
            serde_json::to_string_pretty(&spec.0).unwrap_or_default()
        );
        std::process::exit(0);
    }

    if args.genesis {
        #[cfg(feature = "mesh")]
        {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            use synvoid::mesh::config::GenesisKeyConfig;

            let genesis = GenesisKeyConfig::generate();
            let genesis_b64 = URL_SAFE_NO_PAD.encode(genesis.private_key.unwrap());

            println!("Genesis key generated successfully.");
            println!();
            println!("IMPORTANT: This genesis key is the root of trust for your mesh network.");
            println!(
                "          Store it securely - it will be needed to add additional global nodes."
            );
            println!();
            println!("Genesis key (base64): {}", genesis_b64);
            println!();
            println!("To use this genesis key, add the following to your config/main.toml:");
            println!();
            println!("  [mesh.node_identity]");
            println!("  genesis_key_base64 = \"{}\"", genesis_b64);
            println!();

            std::process::exit(0);
        }
        #[cfg(not(feature = "mesh"))]
        {
            eprintln!("Genesis key generation requires the mesh feature to be enabled.");
            std::process::exit(1);
        }
    }

    if args.show_node_info {
        #[cfg(feature = "mesh")]
        {
            use synvoid::config::MainConfig;

            let config_path = args
                .config_path
                .unwrap_or_else(|| std::path::PathBuf::from("config"));
            let main_config_path = config_path.join("main.toml");

            if !main_config_path.exists() {
                println!(
                    "No config found at {}. Run with --genesis first to generate genesis key.",
                    main_config_path.display()
                );
                std::process::exit(1);
            }

            match MainConfig::from_file(&main_config_path) {
                Ok(config) => {
                    println!("Node Information:");
                    println!("================");
                    println!();

                    if let Some(ref mesh) = config.tunnel.mesh {
                        println!("Mesh Role: {:?}", mesh.role);
                        println!("Node ID: {}", mesh.node_id());
                        println!("Router ID: {}", mesh.router_id());

                        if let Some(ref genesis) = mesh.genesis_key {
                            println!(
                                "Genesis Key: configured (public: {:?})",
                                genesis
                                    .get_public_key()
                                    .map(|pk| format!("{}...", &pk[..16.min(pk.len())]))
                            );
                        } else {
                            println!("Genesis Key: NOT configured");
                        }

                        if mesh.node_identity.genesis_key_base64.is_some() {
                            println!("Genesis Key Base64: configured in node_identity");
                        }

                        if mesh.has_signing_key() {
                            if let Some(ref pk) = mesh.signing_public_key() {
                                println!(
                                    "Signing Public Key: {}...",
                                    hex::encode(&pk[..16.min(pk.len())])
                                );
                            }
                        } else {
                            println!(
                                "Signing Key: NOT configured (edge/origin node without genesis)"
                            );
                        }
                    } else {
                        println!("Mesh: NOT enabled");
                    }
                }
                Err(e) => {
                    eprintln!("Error loading config: {}", e);
                    std::process::exit(1);
                }
            }

            std::process::exit(0);
        }
        #[cfg(not(feature = "mesh"))]
        {
            eprintln!("Node information requires the mesh feature to be enabled.");
            std::process::exit(1);
        }
    }

    if args.generatetoken {
        handle_generatetoken();
        std::process::exit(0);
    }

    if args.hash_token.is_some() {
        use synvoid::admin::hash_admin_token_with_cost;
        let token = match args.hash_token.flatten() {
            Some(t) => t,
            None => {
                eprintln!("Error: Token argument required");
                eprintln!("Usage: synvoid --hash-token <TOKEN>");
                std::process::exit(1);
            }
        };

        let cost = args.hash_cost.unwrap_or(12).clamp(4, 31);

        match hash_admin_token_with_cost(&token, cost) {
            Ok(hash) => {
                println!("{}", hash);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Error hashing token: {}", e);
                std::process::exit(1);
            }
        }
    }

    if let Some(pattern) = args.checkregex {
        use synvoid::utils::check_regex_complexity;
        let result = check_regex_complexity(&pattern);
        if result.safe {
            println!("✓ Pattern is safe: {}", pattern);
        } else {
            println!("✗ Pattern is UNSAFE: {}", pattern);
            println!(
                "  Reason: {}",
                result.reason.as_deref().unwrap_or("unknown")
            );
        }
        std::process::exit(if result.safe { 0 } else { 1 });
    }

    if args.generatenewtoken {
        handle_generatenewtoken(&args.config_path);
        std::process::exit(0);
    }

    if args.status {
        if let Err(e) = handle_status(args.control_addr) {
            eprintln!("Status check failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.stop {
        if let Err(e) = handle_stop(args.control_addr) {
            eprintln!("Stop failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.rehash {
        if let Err(e) = handle_rehash(args.control_addr) {
            eprintln!("Reload failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    #[cfg(feature = "mesh")]
    if args.export_threat_feed {
        if let Err(e) = handle_export_threat_feed(&args.sign_with, args.site_id.as_deref()) {
            eprintln!("Export threat feed failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    #[cfg(not(feature = "mesh"))]
    if args.export_threat_feed {
        eprintln!("Export threat feed requires the mesh feature to be enabled.");
        std::process::exit(1);
    }

    if args.restart {
        if let Err(e) = handle_stop(args.control_addr) {
            eprintln!(
                "Warning: Restart may fail - could not stop existing instance: {}",
                e
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Check for test mode flags and print warning
    if let Some(ref test_flags) = args.test {
        if !args.force {
            eprintln!("ERROR: --test requires --force flag");
            eprintln!(
                "This mode disables security protections and should only be used for testing."
            );
            eprintln!("If you're sure you want to proceed, add --force");
            std::process::exit(1);
        }
        print_test_mode_warning(test_flags);
    }

    // Acquire PID file (atomic check-and-write to avoid TOCTOU race)
    let pid_manager = acquire_pid_file();

    // Validate mutual exclusivity of worker modes
    let worker_mode_count = [
        args.worker,
        args.static_worker,
        args.unified_server_worker,
        args.mesh_agent,
        args.wasm_jail,
        args.yara_jail,
    ]
    .into_iter()
    .filter(|&b| b)
    .count();

    if worker_mode_count > 1 {
        eprintln!("Error: Only one mode (--worker, --static-worker, --unified-server-worker, --mesh-agent, --wasm-jail, --yara-jail) can be specified");
        std::process::exit(1);
    }

    // Check for worker mode
    if args.static_worker {
        setup_worker_panic_handler();
        init_logging_simple();

        let static_worker_args = build_static_worker_args(
            args.static_worker_id,
            args.config_path,
            args.master_socket,
            args.log_level,
            None,
        );

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");

        if let Err(e) = rt.block_on(run_static_worker(static_worker_args)) {
            tracing::error!("Static worker error: {}", e);
            std::process::exit(1);
        }
    } else if args.unified_server_worker {
        setup_unified_server_panic_handler();
        init_logging_simple();

        let worker_threads = args.worker_threads.unwrap_or(2);

        let unified_worker_args = build_unified_server_worker_args(
            args.unified_worker_id,
            args.config_path,
            args.master_socket,
            args.log_level,
            worker_threads,
            args.cpu_affinity,
            args.total_workers.unwrap_or(1),
        );

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");

        if let Err(e) = rt.block_on(run_unified_server_worker(unified_worker_args)) {
            tracing::error!("Unified server worker error: {}", e);
            std::process::exit(1);
        }
    } else if args.mesh_agent {
        init_logging_simple();
        let config_path = args.config_path.unwrap_or_else(|| PathBuf::from("config"));
        synvoid::supervisor::run_mesh_agent_mode(Some(config_path), args.foreground);
    } else if args.master {
        init_logging_simple();
        run_master_mode(args.config_path, args.log_level);
    } else if args.wasm_jail {
        init_logging_simple();
        synvoid::sandbox::run_wasm_jail_mode();
    } else if args.yara_jail {
        init_logging_simple();
        synvoid::sandbox::run_yara_jail_mode();
    } else {
        // Default: Run as Supervisor (manager of Workers)
        // This replaces the legacy Overseer -> Master hierarchy.
        run_supervisor_mode(
            args.config_path,
            args.foreground,
            args.test.as_deref(),
            &pid_manager,
        );
    }
}
