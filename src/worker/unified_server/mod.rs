// Submodule: UnifiedServerWorker bootstrap and lifecycle.
//
// Architecture:
//   - [`state`]    : Worker args, state struct, panic handler, IPC setup,
//                    CPU affinity, config setup, bandwidth, port checks,
//                    drain wait.
//   - [`init_runtime`]: re-exports for the runtime helpers from `state`.
//   - [`init_config`] : re-exports for the config helpers from `state`.
//   - [`init_apps`]   : Granian supervisors, serverless manager, ACME wiring.
//   - [`init_waf`]    : WAF background tasks, UploadValidator, port honeypot.
//   - [`init_mesh`]   : Mesh + Threat Intel + YARA rules initialization.
//   - [`lifecycle`]   : Heartbeat task, IPC message loop, server run task.

pub mod init_apps;
pub mod init_config;
pub mod init_mesh;
pub mod init_runtime;
pub mod init_waf;
pub mod lifecycle;
pub mod state;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use tokio::sync::Mutex as TokioMutex;
use tokio::sync::RwLock;

use super::context::RequestServices;
use super::drain_state::WorkerDrainState;
use super::metrics::WorkerMetrics;
use crate::plugin::get_global_plugin_manager;
use crate::process::WorkerId;
use crate::server::UnifiedServer;
use crate::{DrainFlag, RunningFlag};

pub use state::{
    UnifiedServerWorkerArgs, UnifiedServerWorkerState, setup_unified_server_panic_handler,
};

pub async fn run_unified_server_worker(
    args: UnifiedServerWorkerArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ---- Phase 0: identity ----
    let worker_id_raw = args.worker_id;
    crate::process::set_current_worker_id(worker_id_raw);
    let worker_id = WorkerId(worker_id_raw);

    // ---- Phase 1: runtime ----
    state::apply_cpu_affinity(args.cpu_affinity, worker_id);

    if let Some(ref level) = args.log_level {
        crate::log_controller::init_logging_with_dynamic_level(level);
    }

    state::start_shared_connection_heartbeat(worker_id_raw);
    crate::metrics::health::SystemHealthMonitor::start();

    tracing::info!(
        "Unified Server Worker {} starting, config: {:?}, supervisor socket: {:?}",
        worker_id,
        args.config_path,
        args.supervisor_socket
    );

    let ipc = state::setup_worker_ipc(&args.supervisor_socket, &worker_id).await?;
    let shared_config = state::setup_config(&args.config_path).await;

    // ---- Phase 2: pre-bind port check ----
    state::validate_ports_or_skip_for_shared_port(&args, &shared_config).await?;

    // ---- Phase 3: TLS passthrough validation (preserve inline) ----
    {
        let config = shared_config.read().await;
        let passthrough_sites: Vec<_> = config
            .sites
            .iter()
            .filter(|(_, site)| site.proxy.tls_passthrough == Some(true))
            .map(|(id, _)| id.clone())
            .collect();
        let passthrough_with_waf: Vec<_> = config
            .sites
            .iter()
            .filter(|(_, site)| {
                site.proxy.tls_passthrough == Some(true)
                    && site.proxy.tls_passthrough_enforce_waf == Some(true)
            })
            .map(|(id, _)| id.clone())
            .collect();
        if !passthrough_sites.is_empty() {
            if !passthrough_with_waf.is_empty() {
                tracing::info!(
                    "TLS passthrough with WAF enforcement enabled for sites: {:?}. WAF will inspect L7 traffic.",
                    passthrough_with_waf
                );
            }
            let bypass_sites: Vec<_> = passthrough_sites
                .iter()
                .filter(|s| !passthrough_with_waf.contains(s))
                .cloned()
                .collect();
            if !bypass_sites.is_empty() {
                tracing::error!(
                    "TLS passthrough is enabled for sites: {:?}. WAF inspection is BYPASSED for these sites - L7 attacks will not be blocked. Set tls_passthrough_enforce_waf = true to enable WAF inspection for passthrough traffic.",
                    bypass_sites
                );
                crate::metrics::record_tls_passthrough_waf_bypassed();
            }
            let rate_limited_sites: Vec<_> = bypass_sites
                .iter()
                .filter(|s| {
                    let site_config = config.sites.get(*s);
                    let rl = site_config.map(|s| &s.ratelimit);
                    rl.is_none()
                })
                .cloned()
                .collect();
            if !rate_limited_sites.is_empty() {
                tracing::error!(
                    "TLS passthrough sites {:?} do not have rate limiting configured. Rate limiting is required for passthrough sites to prevent abuse.",
                    rate_limited_sites
                );
            }
        }
    }

    // ---- Phase 4: bandwidth config ----
    let (
        bandwidth_data_dir,
        bandwidth_retention_days,
        bandwidth_mesh_excluded,
        bandwidth_reset_config,
    ) = state::extract_bandwidth_config(&shared_config).await;
    crate::metrics::bandwidth::init_global_bandwidth_tracker(
        bandwidth_retention_days,
        bandwidth_mesh_excluded,
    );
    crate::metrics::bandwidth::configure_global_bandwidth_tracker(
        bandwidth_data_dir.as_deref(),
        bandwidth_reset_config,
    );

    // ---- Phase 5: serverless + unified server ----
    let drain_state = Arc::new(WorkerDrainState::new());
    let metrics =
        WorkerMetrics::shared_with_bandwidth(bandwidth_retention_days, bandwidth_mesh_excluded);
    let ipc_for_server = ipc.clone();
    let worker_id_for_server = worker_id;

    let app_servers = Arc::new(RwLock::new(HashMap::new()));
    let serverless_manager = init_apps::init_serverless_manager(&shared_config).await;

    let unified_server = UnifiedServer::new(
        shared_config.clone(),
        None,
        app_servers.clone(),
        args.total_workers,
    )
    .await?
    .with_drain_state(drain_state.clone())
    .with_metrics(metrics.clone())
    .with_ipc(ipc_for_server, worker_id_for_server)
    .with_serverless_manager(serverless_manager.unwrap_or_else(|| {
        let runtime = get_global_plugin_manager().get_wasm_manager();
        Arc::new(crate::serverless::manager::ServerlessManager::new().with_runtime(runtime))
    }));
    let unified_server: Arc<UnifiedServer> = Arc::new(unified_server);

    // ---- Phase 6: ACME + Granian ----
    init_apps::setup_acme(&unified_server, worker_id);
    init_apps::spawn_granian_supervisors(worker_id, shared_config.clone(), app_servers.clone());
    init_apps::wait_after_granian_spawn().await;

    // ---- Phase 7: WAF ----
    init_waf::start_waf_background_tasks(&unified_server);
    init_waf::init_upload_validator(&shared_config).await;
    let port_honeypot_runner = init_waf::build_port_honeypot(&shared_config).await;
    init_waf::spawn_port_honeypot(port_honeypot_runner.clone());

    // ---- Phase 8: mesh + threat intel ----
    let mesh_init =
        init_mesh::init_mesh_and_threat_intel(&shared_config, &args.config_path, &unified_server)
            .await;

    // ---- Phase 9: cross-wire serverless + port-honeypot to mesh ----
    #[cfg(feature = "mesh")]
    {
        init_mesh::wire_serverless_to_mesh(&unified_server, mesh_init.transport_manager.as_ref());
        init_mesh::wire_port_honeypot_to_mesh(
            &port_honeypot_runner,
            &mesh_init.threat_intel,
            mesh_init.transport_manager.is_some(),
        );
    }
    #[cfg(not(feature = "mesh"))]
    {
        let _ = (mesh_init, port_honeypot_runner);
    }

    // ---- Phase 10: request blocklist from supervisor ----
    lifecycle::request_initial_blocklist(&ipc, worker_id, &unified_server).await;

    // ---- Phase 11: build state + Ready ----
    let metrics = WorkerMetrics::shared();
    let running = RunningFlag::new();
    let draining = DrainFlag::new();
    let drain_id = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stopped_accepting = DrainFlag::new();
    let stop_accepting_sender = unified_server.get_stop_accepting_sender();
    let stop_accepting_tx = Arc::new(TokioMutex::new(Some(stop_accepting_sender)));

    let request_services = {
        #[cfg(feature = "mesh")]
        {
            let threat_intel = mesh_init.threat_intel.clone();
            let yara_rules = if let Some(yr) = crate::waf::get_yara_rules() {
                Some(yr)
            } else {
                None
            };
            RequestServices::new(threat_intel, None, yara_rules, None, None)
        }
        #[cfg(not(feature = "mesh"))]
        {
            RequestServices::new(None, None, None)
        }
    };
    let request_services = Arc::new(request_services);
    unified_server
        .get_waf()
        .set_request_services(request_services.clone());

    let state = UnifiedServerWorkerState {
        worker_id,
        metrics: metrics.clone(),
        start_time: std::time::Instant::now(),
        ipc: ipc.clone(),
        running: running.clone(),
        master_dead: RunningFlag::new(),
        app_servers: app_servers.clone(),
        draining: draining.clone(),
        drain_id: drain_id.clone(),
        stopped_accepting: stopped_accepting.clone(),
        drain_state: drain_state.clone(),
        stop_accepting_tx: stop_accepting_tx.clone(),
        unified_server: unified_server.clone(),
        task_handles: Arc::new(TokioMutex::new(Vec::new())),
        request_services: request_services.clone(),
    };

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard
            .send(&crate::process::Message::UnifiedServerWorkerReady { id: worker_id })
            .await?;
    }
    tracing::info!("Unified Server Worker {} ready", worker_id);

    // ---- Phase 12: spawn lifecycle tasks ----
    let worker_exit_code: Arc<AtomicI32> = Arc::new(AtomicI32::new(0));

    let heartbeat_handle = lifecycle::spawn_heartbeat_task(state.clone());
    state.task_handles.lock().await.push(heartbeat_handle);

    let bandwidth_persist_handle = lifecycle::spawn_bandwidth_persist_task();
    state
        .task_handles
        .lock()
        .await
        .push(bandwidth_persist_handle);

    let ipc_handle = lifecycle::spawn_ipc_loop(
        state.clone(),
        shared_config.clone(),
        worker_exit_code.clone(),
    );
    state.task_handles.lock().await.push(ipc_handle);

    // ---- Phase 13: run unified server ----
    let server_state = state.clone();
    let server_handle = lifecycle::spawn_server_run_task(unified_server.clone(), server_state);

    let master_dead_flag = state.master_dead.clone();
    let _ = server_handle.await;

    running.stop();

    if !master_dead_flag.is_running() {
        tracing::error!(
            "Unified Server Worker {} exiting because supervisor died",
            worker_id
        );
        worker_exit_code.store(1, Ordering::Relaxed);
    }

    let exit_code = worker_exit_code.load(Ordering::Relaxed);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    tracing::info!("Unified Server Worker {} shutting down", worker_id);
    Ok(())
}
