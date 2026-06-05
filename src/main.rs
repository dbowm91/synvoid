use std::path::PathBuf;

use clap::Parser;
use synvoid_cli::Args;

#[cfg(feature = "mesh")]
use synvoid::supervisor::commands::handle_export_threat_feed;
use synvoid::supervisor::commands::{
    handle_configtest, handle_generatenewtoken, handle_generatetoken, handle_rehash, handle_status,
    handle_stop,
};
use synvoid::worker::{
    run_cpu_worker, run_unified_server_worker, setup_unified_server_panic_handler,
    setup_worker_panic_handler,
};

use synvoid::startup::bootstrap::{init_logging_simple, print_test_mode_warning};
use synvoid::startup::daemon::acquire_pid_file;
use synvoid::startup::worker::{build_cpu_worker_args, build_unified_server_worker_args};
use synvoid::supervisor::run_supervisor_mode;

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
        if let Err(e) = handle_status(args.control_addr, args.control_api_tls) {
            eprintln!("Status check failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.stop {
        if let Err(e) = handle_stop(args.control_addr, args.control_api_tls) {
            eprintln!("Stop failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.rehash {
        if let Err(e) = handle_rehash(args.control_addr, args.control_api_tls) {
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
        if let Err(e) = handle_stop(args.control_addr, args.control_api_tls) {
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
        args.cpu_worker,
        args.unified_server_worker,
        args.mesh_agent,
        args.wasm_jail,
        args.yara_jail,
    ]
    .into_iter()
    .filter(|&b| b)
    .count();

    if worker_mode_count > 1 {
        eprintln!("Error: Only one mode (--worker, --cpu-worker/--static-worker, --unified-server-worker, --mesh-agent, --wasm-jail, --yara-jail) can be specified");
        std::process::exit(1);
    }

    // Check for worker mode
    if args.cpu_worker {
        setup_worker_panic_handler();
        init_logging_simple();

        let cpu_worker_args = build_cpu_worker_args(
            args.cpu_worker_id,
            args.config_path,
            args.supervisor_socket,
            args.log_level,
            None,
        );

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");

        if let Err(e) = rt.block_on(run_cpu_worker(cpu_worker_args)) {
            tracing::error!("CPU worker error: {}", e);
            std::process::exit(1);
        }
    } else if args.unified_server_worker {
        setup_unified_server_panic_handler();
        init_logging_simple();

        let worker_threads = args.worker_threads.unwrap_or(2);

        let unified_worker_args = build_unified_server_worker_args(
            args.unified_worker_id,
            args.config_path,
            args.supervisor_socket,
            args.log_level,
            worker_threads,
            args.cpu_affinity,
            args.total_workers.unwrap_or(1),
            args.reuse_port,
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
    } else if args.wasm_jail {
        init_logging_simple();
        synvoid::sandbox::run_wasm_jail_mode();
    } else if args.yara_jail {
        init_logging_simple();
        synvoid::sandbox::run_yara_jail_mode();
    } else {
        // Default: Run as Supervisor (manager of Workers).
        run_supervisor_mode(
            args.config_path,
            args.foreground,
            args.test.as_deref(),
            &pid_manager,
        );
    }
}
