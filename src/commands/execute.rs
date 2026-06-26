use std::path::PathBuf;

use crate::startup::bootstrap::{init_logging_simple, print_test_mode_warning};
use crate::startup::daemon::acquire_pid_file;
use crate::startup::worker::{build_cpu_worker_args, build_unified_server_worker_args};
use crate::supervisor::commands::handle_configtest;
use crate::supervisor::commands::{handle_generatenewtoken, handle_generatetoken};
use crate::supervisor::run_supervisor_mode;
use crate::worker::{
    run_cpu_worker, run_unified_server_worker, setup_unified_server_panic_handler,
    setup_worker_panic_handler,
};

use super::plan::{
    CommandPlan, CommandPreAction, OneShotCommand, RuntimeCommand, SynvoidCommandPlan,
};
use super::supervisor_control::{execute_restart_pre_stop, execute_supervisor_control_command};

/// Execute a command plan. This is the main entry point after command planning.
///
/// Returns a process exit code.
pub fn execute_command(mut plan: CommandPlan) -> i32 {
    // Handle restart pre-action before executing the main plan.
    // Uses the same typed supervisor-control adapter as normal stop.
    if let Some(CommandPreAction::RestartSupervisor {
        control_addr,
        use_tls,
    }) = plan.pre_action.take()
    {
        if let Err(e) = execute_restart_pre_stop(control_addr, use_tls) {
            eprintln!("Restart pre-stop failed: {}", e);
            return e.exit_code();
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Take ownership of the inner plan to avoid partial move issues
    let inner = std::mem::replace(
        &mut plan.plan,
        SynvoidCommandPlan::Runtime(RuntimeCommand::Supervisor),
    );

    match inner {
        SynvoidCommandPlan::OneShot(cmd) => execute_one_shot(cmd),
        SynvoidCommandPlan::SupervisorControl(cmd) => execute_supervisor_control(cmd),
        SynvoidCommandPlan::Runtime(cmd) => execute_runtime(cmd, &plan),
    }
}

/// Execute a one-shot command that completes without launching the server runtime.
fn execute_one_shot(command: OneShotCommand) -> i32 {
    match command {
        OneShotCommand::ConfigTest => {
            if let Err(e) = handle_configtest(&None) {
                eprintln!("Config test failed: {}", e);
                return 1;
            }
            0
        }
        OneShotCommand::ExportOpenApi => {
            use crate::config::MainConfig;
            let schema = schemars::schema_for!(MainConfig);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
            0
        }
        OneShotCommand::ExportApiSpec => {
            use crate::admin::openapi::synvoidOpenApi;
            let spec = synvoidOpenApi::openapi_json();
            println!(
                "{}",
                serde_json::to_string_pretty(&spec.0).unwrap_or_default()
            );
            0
        }
        OneShotCommand::Genesis => execute_genesis(),
        OneShotCommand::ShowNodeInfo => execute_show_node_info(),
        OneShotCommand::GenerateToken => {
            handle_generatetoken();
            0
        }
        OneShotCommand::GenerateNewToken { config_path } => {
            handle_generatenewtoken(&config_path);
            0
        }
        OneShotCommand::HashToken { token, cost } => execute_hash_token(&token, cost),
        OneShotCommand::CheckRegex { pattern } => execute_check_regex(&pattern),
    }
}

/// Execute a supervisor-control command sent via IPC to a running instance.
///
/// Delegates to the typed adapter which maps commands to outcomes/errors.
/// Exit codes are derived from the typed result, not ad-hoc branching.
fn execute_supervisor_control(command: super::plan::SupervisorControlCommand) -> i32 {
    match execute_supervisor_control_command(command) {
        Ok(outcome) => {
            let display = outcome.display();
            if !display.is_empty() {
                println!("{}", display);
            }
            outcome.exit_code()
        }
        Err(e) => {
            eprintln!("{}", e);
            e.exit_code()
        }
    }
}

/// Execute a runtime launch command that starts a long-running process.
fn execute_runtime(command: RuntimeCommand, plan: &CommandPlan) -> i32 {
    // Print test mode warning if test flags are set
    if let Some(ref test_flags) = plan.test_flags {
        print_test_mode_warning(test_flags);
    }

    let config_path = plan.config_path.clone();

    match command {
        RuntimeCommand::CpuWorker => {
            setup_worker_panic_handler();
            init_logging_simple();

            let cpu_worker_args =
                build_cpu_worker_args(plan.cpu_worker_id, config_path, None, None, None);

            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");

            if let Err(e) = rt.block_on(run_cpu_worker(cpu_worker_args)) {
                tracing::error!("CPU worker error: {}", e);
                return 1;
            }
            0
        }
        RuntimeCommand::UnifiedServerWorker => {
            setup_unified_server_panic_handler();
            init_logging_simple();

            let worker_threads = plan.worker_threads.unwrap_or(2);

            let unified_worker_args = build_unified_server_worker_args(
                plan.unified_worker_id,
                config_path,
                None,
                None,
                worker_threads,
                plan.cpu_affinity,
                plan.total_workers.unwrap_or(1),
                plan.reuse_port,
            );

            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(worker_threads)
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");

            if let Err(e) = rt.block_on(run_unified_server_worker(unified_worker_args)) {
                tracing::error!("Unified server worker error: {}", e);
                return 1;
            }
            0
        }
        RuntimeCommand::MeshAgent => {
            init_logging_simple();
            let config_path = config_path.unwrap_or_else(|| PathBuf::from("config"));
            crate::supervisor::run_mesh_agent_mode(Some(config_path), plan.foreground);
            0
        }
        RuntimeCommand::WasmJail => {
            init_logging_simple();
            crate::sandbox::run_wasm_jail_mode();
            0
        }
        RuntimeCommand::YaraJail => {
            init_logging_simple();
            crate::sandbox::run_yara_jail_mode();
            0
        }
        RuntimeCommand::Supervisor => {
            let pid_manager = acquire_pid_file();
            run_supervisor_mode(
                config_path,
                plan.foreground,
                plan.test_flags.as_deref(),
                &pid_manager,
            );
            0
        }
    }
}

// --- Private one-shot command helpers ---

fn execute_genesis() -> i32 {
    #[cfg(feature = "mesh")]
    {
        use crate::mesh::config::GenesisKeyConfig;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let genesis = GenesisKeyConfig::generate();
        let genesis_b64 = URL_SAFE_NO_PAD.encode(genesis.private_key.unwrap());

        println!("Genesis key generated successfully.");
        println!();
        println!("IMPORTANT: This genesis key is the root of trust for your mesh network.");
        println!("          Store it securely - it will be needed to add additional global nodes.");
        println!();
        println!("Genesis key (base64): {}", genesis_b64);
        println!();
        println!("To use this genesis key, add the following to your config/main.toml:");
        println!();
        println!("  [mesh.node_identity]");
        println!("  genesis_key_base64 = \"{}\"", genesis_b64);
        println!();

        0
    }
    #[cfg(not(feature = "mesh"))]
    {
        eprintln!("Genesis key generation requires the mesh feature to be enabled.");
        1
    }
}

fn execute_show_node_info() -> i32 {
    #[cfg(feature = "mesh")]
    {
        use crate::config::MainConfig;

        let config_path = std::path::PathBuf::from("config");
        let main_config_path = config_path.join("main.toml");

        if !main_config_path.exists() {
            println!(
                "No config found at {}. Run with --genesis first to generate genesis key.",
                main_config_path.display()
            );
            return 1;
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
                        println!("Signing Key: NOT configured (edge/origin node without genesis)");
                    }
                } else {
                    println!("Mesh: NOT enabled");
                }
            }
            Err(e) => {
                eprintln!("Error loading config: {}", e);
                return 1;
            }
        }

        0
    }
    #[cfg(not(feature = "mesh"))]
    {
        eprintln!("Node information requires the mesh feature to be enabled.");
        1
    }
}

fn execute_hash_token(token: &str, cost: u32) -> i32 {
    use crate::admin::hash_admin_token_with_cost;

    match hash_admin_token_with_cost(token, cost) {
        Ok(hash) => {
            println!("{}", hash);
            0
        }
        Err(e) => {
            eprintln!("Error hashing token: {}", e);
            1
        }
    }
}

fn execute_check_regex(pattern: &str) -> i32 {
    use crate::utils::check_regex_complexity;

    let result = check_regex_complexity(pattern);
    if result.safe {
        println!("✓ Pattern is safe: {}", pattern);
    } else {
        println!("✗ Pattern is UNSAFE: {}", pattern);
        println!(
            "  Reason: {}",
            result.reason.as_deref().unwrap_or("unknown")
        );
    }
    if result.safe {
        0
    } else {
        1
    }
}
