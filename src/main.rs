use std::path::PathBuf;

use clap::Parser;

use maluwaf::master::{
    handle_configtest, handle_generatenewtoken, handle_generatetoken, handle_rehash, handle_status,
    handle_stop,
};
use maluwaf::worker::{
    run_static_worker, run_unified_server_worker, run_worker, setup_unified_server_panic_handler,
    setup_worker_panic_handler,
};

use maluwaf::startup::bootstrap::{init_logging_simple, print_test_mode_warning};
use maluwaf::startup::daemon::acquire_pid_file;
use maluwaf::startup::master::{run_master_mode, run_overseer_mode};
use maluwaf::startup::worker::{
    build_static_worker_args, build_unified_server_worker_args, build_worker_args,
};

#[derive(Parser, Debug)]
#[command(name = "maluwaf")]
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

    // Internal: Used by Overseer to spawn Master process. Not for direct user invocation.
    // The default behavior (no flags) runs the Overseer which spawns Master.
    #[arg(long, hide = true)]
    master: bool,

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

    #[arg(long, help = "Export OpenAPI spec as JSON and exit")]
    export_openapi: bool,
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
        use maluwaf::admin::openapi::ApiDoc;
        let spec: utoipa::openapi::OpenApi = ApiDoc.into();
        println!(
            "{}",
            serde_json::to_string_pretty(&spec).unwrap_or_default()
        );
        std::process::exit(0);
    }

    if args.generatetoken {
        handle_generatetoken();
        std::process::exit(0);
    }

    if let Some(pattern) = args.checkregex {
        use maluwaf::utils::check_regex_complexity;
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
        if let Err(e) = handle_stop() {
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
        args.master,
    ]
    .into_iter()
    .filter(|&b| b)
    .count();

    if worker_mode_count > 1 {
        eprintln!("Error: Only one worker mode (--worker, --static-worker, --unified-server-worker, --master) can be specified");
        std::process::exit(1);
    }

    // Check for worker mode
    if args.worker {
        setup_worker_panic_handler();
        init_logging_simple();

        let worker_args = build_worker_args(
            args.worker_id,
            args.port,
            args.config_path,
            args.master_socket,
            args.test,
            args.log_level,
        );

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

        let static_worker_args = build_static_worker_args(
            args.static_worker_id,
            args.config_path,
            args.master_socket,
            args.log_level,
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
    // ============================================================================================
    // IMPORTANT: UnifiedServerWorker MUST run as a separate process from the master.
    //
    // Architectural requirements for running as separate process:
    // - Improved robustness: Isolates master from crashes/vulnerabilities in the worker
    // - Rolling updates: Allows graceful draining and restart without affecting master
    // - Process isolation: Prevents worker issues from bringing down the entire system
    //
    // DO NOT run UnifiedServer in-process within the master - this violates the
    // overseer -> master -> worker separation model required for production deployments.
    // ============================================================================================
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
    // ============================================================================================
    // INTERNAL: Master mode is invoked by the Overseer process.
    // This is NOT for direct user invocation - use the default mode instead.
    // ============================================================================================
    } else if args.master {
        run_master_mode(args.config_path, args.log_level);
    } else {
        // Default: Run as Overseer (parent of Master and Workers)
        // This is the only supported mode for production deployments.
        //
        // Process hierarchy:
        //   Overseer (this process) -> Master -> Workers
        run_overseer_mode(
            args.config_path,
            args.foreground,
            args.test.as_deref(),
            &pid_manager,
        );
    }
}
