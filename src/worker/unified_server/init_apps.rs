// Submodule: Granian (app server) supervisors, serverless manager, and
// ACME-01 challenge wiring.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::plugin::get_global_plugin_manager;
use crate::server::UnifiedServer;
use synvoid_app_server::{GranianConfig, GranianSupervisor};
use synvoid_config::ConfigManager;
use synvoid_ipc::WorkerId;

/// Initialize the global serverless manager from config (if enabled).
/// Returns `None` if the serverless subsystem is disabled or fails to start.
pub async fn init_serverless_manager(
    config: &Arc<RwLock<ConfigManager>>,
) -> Option<Arc<crate::serverless::manager::ServerlessManager>> {
    let serverless_config = {
        let config = config.read().await;
        config.main.serverless.clone()
    };

    if !serverless_config.enabled {
        return None;
    }

    let runtime = get_global_plugin_manager().get_wasm_manager();
    let manager =
        Arc::new(crate::serverless::manager::ServerlessManager::new().with_runtime(runtime));
    if let Err(e) = manager.initialize(serverless_config) {
        tracing::warn!("Failed to initialize serverless manager: {}", e);
        None
    } else {
        tracing::info!("Serverless manager initialized");
        Some(manager)
    }
}

/// Create a default serverless manager using the global plugin manager's WASM
/// runtime. This is the fallback used when the serverless subsystem is disabled
/// or fails to initialize — the manager is still needed because upstream code
/// expects it to exist, but it won't have any loaded functions.
pub fn build_default_serverless_manager() -> Arc<crate::serverless::manager::ServerlessManager> {
    let runtime = get_global_plugin_manager().get_wasm_manager();
    Arc::new(crate::serverless::manager::ServerlessManager::new().with_runtime(runtime))
}

/// Spawn the background task that starts Granian supervisors for every site
/// that has an app-server config. Returns immediately; the spawning task
/// itself is the async work.
pub fn spawn_granian_supervisors(
    worker_id: WorkerId,
    config: Arc<RwLock<ConfigManager>>,
    app_servers: Arc<RwLock<HashMap<String, Arc<GranianSupervisor>>>>,
) {
    let app_servers_for_init = app_servers.clone();
    let config_for_app = config.clone();
    tokio::spawn(async move {
        let config = config_for_app.read().await;

        for (site_id, site_config) in config.sites.iter() {
            let app_config = site_config.app_server_config();
            if !app_config.is_valid() {
                continue;
            }

            let app_config_internal: crate::app_server::AppServerConfig =
                serde_json::from_str(&serde_json::to_string(&app_config).unwrap()).unwrap();
            let mut granian_config = GranianConfig::from(&app_config_internal);
            granian_config = granian_config.with_site_info(site_id, worker_id.as_usize());

            tracing::info!(
                "Initializing granian for site {} on unified server worker with socket: {}",
                site_id,
                granian_config.resolve_socket_path().display()
            );

            let supervisor = Arc::new(GranianSupervisor::new(granian_config));

            if let Err(e) = supervisor.start().await {
                tracing::error!("Failed to start granian for site {}: {}", site_id, e);
                continue;
            }

            app_servers_for_init
                .write()
                .await
                .insert(site_id.clone(), supervisor.clone());
            crate::app_server::register_granian_supervisor(site_id, supervisor);
        }
    });
}

/// Wait for the Granian supervisor spawn delay. Original code uses
/// `tokio::time::sleep(Duration::from_millis(500)).await` here.
pub async fn wait_after_granian_spawn() {
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// Setup ACME if enabled (spawns the renewal task) and wire DNS-01 challenges
/// to the DNS server.
pub fn setup_acme(unified_server: &Arc<UnifiedServer>, worker_id: WorkerId) {
    #[cfg(feature = "dns")]
    {
        if let Some(acme_manager) = unified_server.setup_acme() {
            tracing::info!("ACME manager started for worker {}", worker_id);

            // Wire AcmeDnsChallenge to DNS server for DNS-01 support
            if let Some(dns_server) = unified_server.get_dns_server() {
                if let Some(dns_challenges) = acme_manager.get_dns_challenges() {
                    let _server = (*dns_server)
                        .clone()
                        .with_acme_dns_challenges(dns_challenges);
                    tracing::info!("ACME DNS-01 challenges wired to DNS server");
                }
            }
        }
    }
    #[cfg(not(feature = "dns"))]
    {
        let _ = (unified_server, worker_id);
    }
}
