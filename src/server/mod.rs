use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};

use crate::config::ConfigManager;
use crate::config::{Http3Config, TunnelConfig};
use crate::http::HttpServer;
use crate::router::Router;
use crate::tcp::listener::TcpListenerPool;
use crate::udp::listener::UdpListenerPool;

#[cfg(feature = "dns")]
use crate::dns::DnsServer;
use crate::metrics::adapter::WorkerMetricsSink;
use crate::metrics::WorkerMetrics;
use crate::process::ipc::WorkerId;
use crate::router_adapter::RouterRouteResolver;
#[cfg(feature = "dns")]
use crate::tls::acme::AcmeManager;
use crate::tls::cert_resolver::CertResolver;
use crate::tls::config::InternalTlsConfig;
use crate::tunnel::{TunnelManager, TunnelRouter};
use crate::waf::adapter::RootWafProcessor;
use crate::waf::{FloodProtector, WafCore};
use crate::worker::drain_adapter::WorkerDrainStateAdapter;
use crate::worker::drain_state::WorkerDrainState;
#[cfg(feature = "dns")]
use std::sync::Mutex as StdMutex;
use synvoid_http::runtime::HttpRuntimeContext;

pub mod aux_listener_config;

#[cfg(feature = "dns")]
pub mod dns_runtime_config;
pub mod listener_binding;
pub mod listener_tasks;
pub mod plugin_runtime;
pub mod resources;
pub mod runtime_handles;
pub mod service_assembly;
pub mod startup_plan;
pub mod waf_handler;
pub mod worker_sandbox;

#[cfg(feature = "dns")]
pub use dns_runtime_config::{
    dns_runtime_config_from_persisted, DnsRuntimeConversionError, DnsServerRuntimeConfig,
};

pub use listener_binding::{http_listener_snapshots, BoundHttpListener, HttpListenerSnapshot};
pub use plugin_runtime::{PluginRuntimeOwner, PluginRuntimeReport};
pub use resources::{UnifiedServerResourceError, UnifiedServerResources};
pub use runtime_handles::{
    spawn_registered, spawn_registered_unit, NamedRuntimeHandle, RuntimeHandleClass,
    RuntimeTaskExit, ServerTaskResult, UnifiedServerRuntimeHandles,
    UnifiedServerRuntimeShutdownReport,
};
pub use startup_plan::{UnifiedServerStartupPlan, UnifiedServerStartupPlanError};

#[derive(Clone)]
pub(crate) struct ServerSharedState {
    pub(crate) config: Arc<RwLock<ConfigManager>>,
    pub(crate) router: Arc<Router>,
    pub(crate) waf: Arc<WafCore>,
    pub(crate) flood_protector: Option<Arc<FloodProtector>>,
    pub(crate) drain_state: Option<Arc<WorkerDrainState>>,
    #[cfg(feature = "mesh")]
    pub(crate) mesh_transport: Option<Arc<crate::mesh::transport::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub(crate) mesh_backend_pool: Option<Arc<crate::mesh::MeshBackendPool>>,
    pub(crate) metrics: Option<Arc<WorkerMetrics>>,
    pub(crate) ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    pub(crate) worker_id: Option<WorkerId>,
    /// Set-once handle to the worker-local request-log sink (the admin
    /// `AdminState`). Registered by `spawn_admin_service` once the control
    /// plane exists; read per request by the HTTP/HTTPS lanes.
    pub(crate) request_log_sink: synvoid_http::RequestLogSinkHandle,
    pub(crate) serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
    pub(crate) app_servers: Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
    pub(crate) _http_runtime_context: Option<
        HttpRuntimeContext<
            RootWafProcessor,
            RouterRouteResolver,
            WorkerMetricsSink,
            WorkerDrainStateAdapter,
        >,
    >,
}

#[derive(Clone)]
pub struct UnifiedServer {
    pub(crate) config: Arc<RwLock<ConfigManager>>,
    pub(crate) bound_http_listeners: Arc<Vec<BoundHttpListener>>,
    pub(crate) admin_addr: Option<SocketAddr>,
    pub(crate) tcp_pool: Option<TcpListenerPool>,
    pub(crate) udp_pool: Option<UdpListenerPool>,
    pub(crate) waf: Arc<WafCore>,
    pub(crate) flood_protector: Option<Arc<FloodProtector>>,
    pub(crate) shutdown_tx: broadcast::Sender<()>,
    pub(crate) stop_accepting_tx: broadcast::Sender<()>,
    pub(crate) tls_config: InternalTlsConfig,
    pub(crate) http3_config: Http3Config,
    pub(crate) cert_resolver: Option<Arc<CertResolver>>,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    tunnel_manager: Option<Arc<TunnelManager>>,
    pub(crate) tunnel_router: Option<Arc<Mutex<TunnelRouter>>>,
    pub(crate) tunnel_config: Option<TunnelConfig>,
    pub(crate) drain_state: Option<Arc<WorkerDrainState>>,
    #[cfg(feature = "mesh")]
    pub(crate) mesh_transport: Option<Arc<crate::mesh::transport::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub(crate) mesh_backend_pool: Option<Arc<crate::mesh::MeshBackendPool>>,
    pub(crate) metrics: Option<Arc<WorkerMetrics>>,
    pub(crate) ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    pub(crate) worker_id: Option<WorkerId>,
    block_store: Option<Arc<crate::block_store::BlockStore>>,
    pub(crate) serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
    pub(crate) app_servers: Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,

    // DNS Server
    #[cfg(feature = "dns")]
    _dns_config: Option<crate::config::dns::DnsConfig>,
    #[cfg(feature = "dns")]
    pub(crate) dns_server: Option<Arc<DnsServer>>,
    #[cfg(feature = "dns")]
    _dns_addr: Option<SocketAddr>,
    #[cfg(feature = "dns")]
    _dns_addr_v6: Option<SocketAddr>,
    #[cfg(feature = "dns")]
    pub(crate) acme_manager: Arc<StdMutex<Option<Arc<AcmeManager>>>>,
}

impl UnifiedServer {
    pub async fn new(
        config: Arc<RwLock<ConfigManager>>,
        #[cfg(feature = "mesh")] mesh_transport: Option<
            Arc<crate::mesh::transport::MeshTransportManager>,
        >,
        #[cfg(not(feature = "mesh"))] _mesh_transport: Option<std::marker::PhantomData<fn()>>,
        _app_servers: Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
        worker_count: usize,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Build startup plan from config
        let plan = {
            let cfg = config.read().await;
            UnifiedServerStartupPlan::from_config_snapshot_with_sites(
                &cfg.main,
                &cfg.sites,
                worker_count,
            )
            .map_err(|e| format!("Startup plan validation failed: {}", e))?
        };

        // Build resources from plan
        let resources = {
            let cfg = config.read().await;
            UnifiedServerResources::build(&cfg.main, &plan, config.clone())
                .await
                .map_err(|e| format!("Resource construction failed: {}", e))?
        };

        if plan.http_listeners.iter().any(|listener| listener.tls)
            && resources.cert_resolver.is_none()
        {
            return Err("TLS listener configured without a loaded certificate resolver".into());
        }

        // Bind every data-plane listener before the worker can report ready.
        let reuse_port = worker_count > 1 && synvoid_platform::is_reuse_port_supported();
        let bound_http_listeners =
            listener_binding::bind_http_listeners(&plan.http_listeners, reuse_port)
                .map_err(|e| format!("HTTP listener bind failed: {}", e))?;

        let (shutdown_tx, _) = broadcast::channel(1);
        let (stop_accepting_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            bound_http_listeners,
            admin_addr: plan.admin_addr,
            tcp_pool: resources.tcp_pool,
            udp_pool: resources.udp_pool,
            waf: resources.waf,
            flood_protector: resources.flood_protector,
            shutdown_tx,
            stop_accepting_tx,
            tls_config: plan.tls_config,
            http3_config: plan.http3_config,
            cert_resolver: resources.cert_resolver,
            tunnel_manager: resources.tunnel_manager,
            tunnel_router: resources.tunnel_router,
            tunnel_config: plan.tunnel_config,
            drain_state: None,
            #[cfg(feature = "mesh")]
            mesh_transport,
            #[cfg(feature = "mesh")]
            mesh_backend_pool: None,
            metrics: None,
            ipc: None,
            worker_id: None,
            block_store: None,
            serverless_manager: None,
            app_servers: resources.app_servers,
            #[cfg(feature = "dns")]
            _dns_config: None, // DNS config now lives in resources
            #[cfg(feature = "dns")]
            dns_server: resources.dns_server,
            #[cfg(feature = "dns")]
            _dns_addr: None, // DNS addr derived at startup in plan
            #[cfg(feature = "dns")]
            _dns_addr_v6: None,
            #[cfg(feature = "dns")]
            acme_manager: Arc::new(
                resources
                    .acme_manager
                    .map(|m| StdMutex::new(Some(m)))
                    .unwrap_or_else(|| StdMutex::new(None)),
            ),
        })
    }

    pub fn with_drain_state(mut self, drain_state: Arc<WorkerDrainState>) -> Self {
        self.drain_state = Some(drain_state);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<WorkerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn with_ipc(
        mut self,
        ipc: Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>,
        worker_id: WorkerId,
    ) -> Self {
        self.ipc = Some(ipc);
        self.worker_id = Some(worker_id);
        self
    }

    pub fn with_serverless_manager(
        mut self,
        manager: Arc<crate::serverless::manager::ServerlessManager>,
    ) -> Self {
        self.serverless_manager = Some(manager);
        self
    }

    pub fn with_block_store(mut self, block_store: Arc<crate::block_store::BlockStore>) -> Self {
        self.block_store = Some(block_store);
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_backend_pool(mut self, pool: Arc<crate::mesh::MeshBackendPool>) -> Self {
        self.mesh_backend_pool = Some(pool);
        self
    }

    #[cfg(feature = "mesh")]
    pub fn get_mesh_backend_pool(&self) -> Option<Arc<crate::mesh::MeshBackendPool>> {
        self.mesh_backend_pool.clone()
    }

    pub fn get_serverless_manager(
        &self,
    ) -> Option<Arc<crate::serverless::manager::ServerlessManager>> {
        self.serverless_manager.clone()
    }

    #[cfg(feature = "dns")]
    pub fn setup_acme(&self) -> Option<Arc<AcmeManager>> {
        let tls_config = self.tls_config.clone();
        let cert_resolver = self.cert_resolver.as_ref()?;

        if !tls_config.acme.enabled {
            return None;
        }

        let acme_config = tls_config.acme.clone();
        let resolver = cert_resolver.clone();

        let acme_manager = Arc::new(AcmeManager::new(acme_config, resolver));

        let ipc = self.ipc.as_ref()?;
        let worker_id = self.worker_id?;

        let ipc_clone = ipc.clone();
        let renew_callback = move |domains: Vec<String>| {
            tracing::info!(
                "ACME certificates renewed for {:?}, notifying supervisor",
                domains
            );
            let ipc = ipc_clone.clone();
            let domains = domains.clone();
            // reason: ACME cert reload IPC notification — short-lived, bounded callback
            tokio::spawn(async move {
                let msg = crate::process::Message::WorkerCertReload {
                    id: worker_id,
                    domains,
                };
                let mut ipc = ipc.lock().await;
                if let Err(e) = ipc.send(&msg).await {
                    tracing::error!("Failed to send cert reload message: {}", e);
                }
            });
        };
        acme_manager.set_renew_callback(renew_callback);

        // NOTE: ACME init + renewal task is spawned in run() via handles,
        // not here. This method only creates the manager and wires the callback.

        tracing::info!("ACME manager created");
        *self
            .acme_manager
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(acme_manager.clone());
        Some(acme_manager)
    }

    pub fn stop_accepting(&self) {
        let _ = self.stop_accepting_tx.send(());
        if let Some(ref ds) = self.drain_state {
            ds.stop_accepting();
        }
        tracing::info!("UnifiedServer signaled to stop accepting new connections");
    }

    pub fn get_drain_state(&self) -> Option<Arc<WorkerDrainState>> {
        self.drain_state.clone()
    }

    pub fn get_stop_accepting_sender(&self) -> tokio::sync::broadcast::Sender<()> {
        self.stop_accepting_tx.clone()
    }

    pub fn get_probe_tracker(&self) -> Option<Arc<crate::waf::ProbeTracker>> {
        self.waf.probe_tracker.clone()
    }

    pub fn get_suspicious_word_tracker(&self) -> Option<Arc<crate::waf::SuspiciousWordTracker>> {
        self.waf.suspicious_word_tracker.clone()
    }

    pub fn get_upstream_error_tracker(&self) -> Option<Arc<crate::waf::UpstreamErrorTracker>> {
        self.waf.upstream_error_tracker.clone()
    }

    pub fn get_block_store(&self) -> Option<Arc<crate::block_store::BlockStore>> {
        self.block_store.clone()
    }

    pub fn get_cert_resolver(&self) -> Option<Arc<CertResolver>> {
        self.cert_resolver.clone()
    }

    #[cfg(feature = "dns")]
    pub fn get_dns_server(&self) -> Option<Arc<crate::dns::DnsServer>> {
        self.dns_server.clone()
    }

    pub fn get_waf(&self) -> Arc<crate::waf::WafCore> {
        self.waf.clone()
    }

    pub fn get_threat_level_manager(&self) -> Option<Arc<crate::waf::ThreatLevelManager>> {
        self.waf.threat_level.clone()
    }

    /// Rebuild the global attack detector from the effective configuration and
    /// current rule-feed patterns. Per-site detector variants are invalidated
    /// and rebuilt lazily; streaming scanner settings are preserved.
    pub fn reload_attack_detector(&self) -> Result<(), String> {
        self.waf.reload_attack_detector()
    }

    pub fn get_tunnel_router(&self) -> Option<Arc<Mutex<TunnelRouter>>> {
        self.tunnel_router.clone()
    }

    pub fn get_app_servers(
        &self,
    ) -> Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>> {
        self.app_servers.clone()
    }

    /// Phase 04 orchestration: subsystem assembly order is visible here.
    ///
    /// Stages: tunnel → threat autoscale → plugin → router → HTTP context →
    /// shared state → protocol listeners → aux pools → DNS → ACME → shutdown.
    /// Each stage lives in `service_assembly` / `listener_tasks`; this method
    /// only wires narrow bundles in order.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut handles = UnifiedServerRuntimeHandles::new();

        let config = self.config.clone();
        let waf = self.waf.clone();

        // ── QUIC tunnel ──────────────────────────────────────────────
        service_assembly::start_quic_tunnel(&self.tunnel_router, &self.tunnel_config).await?;

        // ── Threat-level auto-scale (registered) ────────────────────
        service_assembly::spawn_threat_autoscale(&mut handles, &waf, &self.shutdown_tx);

        // ── Plugin runtime (kept alive until after shutdown) ────────
        let plugin_owner = {
            let cfg = config.read().await;
            service_assembly::assemble_plugin_runtime(&cfg.main)
        };

        let plugin_manager = plugin_owner.manager().clone();

        // ── Router ──────────────────────────────────────────────────
        let router = {
            let cfg = config.read().await;
            let main_config = cfg.main.clone();
            let sites = cfg.sites.clone();
            Arc::new(service_assembly::assemble_router(
                &main_config,
                sites,
                plugin_manager,
            ))
        };

        // ── HTTP runtime context ────────────────────────────────────
        let http_runtime_context = service_assembly::assemble_http_runtime_context(
            &waf,
            &router,
            &self.metrics,
            &self.drain_state,
        );

        let shared_state = Arc::new(ServerSharedState {
            config: config.clone(),
            router: router.clone(),
            waf: waf.clone(),
            flood_protector: self.flood_protector.clone(),
            drain_state: self.drain_state.clone(),
            #[cfg(feature = "mesh")]
            mesh_transport: self.mesh_transport.clone(),
            #[cfg(feature = "mesh")]
            mesh_backend_pool: self.mesh_backend_pool.clone(),
            metrics: self.metrics.clone(),
            ipc: self.ipc.clone(),
            worker_id: self.worker_id,
            request_log_sink: synvoid_http::empty_sink_handle(),
            serverless_manager: self.serverless_manager.clone(),
            app_servers: self.app_servers.clone(),
            _http_runtime_context: http_runtime_context,
        });

        // Bridge the stop-accepting signal into the server shutdown path.
        // This turns the previously dropped-receiver channel into a real
        // subscriber: listeners close before connection drain begins.
        {
            let mut stop_rx = self.stop_accepting_tx.subscribe();
            let shutdown_tx = self.shutdown_tx.clone();
            crate::server::runtime_handles::spawn_registered_unit(
                &mut handles,
                "stop_accepting_bridge",
                crate::server::runtime_handles::RuntimeHandleClass::Maintenance,
                async move {
                    if stop_rx.recv().await.is_ok() {
                        let _ = shutdown_tx.send(());
                    }
                },
            );
        }

        // ── Protocol listener tasks (registered, in startup order) ──
        listener_tasks::spawn_http_listeners(
            &mut handles,
            &shared_state,
            self,
            self.bound_http_listeners.as_ref(),
        )
        .await;
        listener_tasks::spawn_aux_pools(&mut handles, self);
        listener_tasks::spawn_admin_service(&mut handles, &shared_state, self).await;

        // ── DNS server (registered) ─────────────────────────────────
        #[cfg(feature = "dns")]
        {
            listener_tasks::spawn_dns_service(&mut handles, self);
        }

        // ── ACME init/renewal (registered) ──────────────────────────
        #[cfg(feature = "dns")]
        {
            listener_tasks::spawn_acme_service(&mut handles, self);
        }

        // ── ACME cert reload IPC notification (short-lived callback) ──
        // This spawn is owned by the ACME renew_callback and is short-lived.
        // It is exempt from handle registration per BoundedShortLived policy.

        Self::wait_for_shutdown_and_drain(handles, &self.shutdown_tx, plugin_owner).await
    }

    /// Wait for the shutdown trigger, broadcast, drain all registered tasks,
    /// then drop the plugin owner after drain (hot-reload watcher lifetime).
    async fn wait_for_shutdown_and_drain(
        mut handles: UnifiedServerRuntimeHandles,
        shutdown_tx: &broadcast::Sender<()>,
        plugin_owner: PluginRuntimeOwner,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // ── Wait for shutdown signal or critical task exit ───────────
        let mut shutdown_rx = shutdown_tx.subscribe();
        let (critical_tx, mut critical_rx) = tokio::sync::oneshot::channel::<String>();

        let shutdown_trigger = async {
            tokio::select! {
                _ = shutdown_rx.recv() => "signal".to_string(),
                msg = &mut critical_rx => {
                    match msg {
                        Ok(name) => name,
                        Err(_) => "channel_closed".to_string(),
                    }
                }
            }
        };

        // Note: We monitor for shutdown signal here. The actual task join
        // and drain happens in shutdown_and_join after the broadcast.
        // If we wanted to detect critical task exits, we'd need the tasks
        // to send on critical_tx. For now, we just wait for ctrl_c/signal.
        let _ = critical_tx; // suppress unused warning — kept for future use
        let shutdown_cause = shutdown_trigger.await;
        tracing::info!(cause = %shutdown_cause, "Shutdown trigger received, broadcasting shutdown");

        // ── Broadcast shutdown and drain all tasks ───────────────────
        let _ = shutdown_tx.send(());

        let report = handles
            .shutdown_and_join(std::time::Duration::from_secs(30))
            .await;

        tracing::info!(
            completed = report.completed,
            failed = report.failed,
            join_errors = report.join_errors,
            aborted = report.aborted,
            timed_out = report.timed_out,
            critical_failures = report.critical_failures,
            "UnifiedServer runtime shutdown report"
        );

        // plugin_owner is dropped here — after all tasks have drained.
        // This ensures hot-reload watcher stays alive for the full runtime lifetime.
        drop(plugin_owner);

        tracing::info!("Unified server shutdown complete");

        Ok(())
    }

    pub(crate) async fn run_http_server_inner(
        state: Arc<ServerSharedState>,
        std_listener: std::net::TcpListener,
        plan: crate::config::HttpListenerPlan,
        http_config: crate::config::HttpConfig,
        main_config: crate::config::MainConfig,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mesh_config = {
            let cfg = state.config.read().await;
            #[cfg(feature = "mesh")]
            let mesh_config = cfg.main.tunnel.mesh.clone();
            #[cfg(not(feature = "mesh"))]
            let mesh_config: Option<()> = None;
            mesh_config
        };
        let _ = &mesh_config;

        let mut server = HttpServer::new(
            plan.addr,
            (*state.router).clone(),
            state.waf.clone(),
            http_config,
            shutdown_rx,
            main_config,
        )
        .with_tcp_listener(std_listener)
        .with_listener_plan(plan);

        if let Some(fp) = state.flood_protector.clone() {
            server = server.with_flood_protector(fp);
        }

        if let Some(ds) = state.drain_state.clone() {
            server = server.with_drain_state(ds);
        }

        #[cfg(feature = "mesh")]
        if let Some(mesh_cfg_external) = mesh_config {
            let mesh_cfg_json = serde_json::to_string(&mesh_cfg_external)?;
            let mesh_cfg_internal: crate::mesh::config::MeshConfig =
                serde_json::from_str(&mesh_cfg_json)?;
            server = server.with_mesh_config(Some(Arc::new(mesh_cfg_internal)));
        }

        #[cfg(feature = "mesh")]
        if let Some(mt) = state.mesh_transport.clone() {
            server = server.with_mesh_transport(Some(mt));
        }

        #[cfg(feature = "mesh")]
        if let Some(pool) = state.mesh_backend_pool.clone() {
            server = server.with_mesh_backend_pool(Some(pool));
        }

        if let Some(m) = state.metrics.clone() {
            server = server.with_metrics(m);
        }

        if let (Some(ipc), Some(worker_id)) = (state.ipc.clone(), state.worker_id) {
            server = server.with_ipc(ipc, worker_id);
        }

        server = server.with_request_log_sink(state.request_log_sink.clone());

        if let Some(sm) = state.serverless_manager.clone() {
            server = server.with_serverless_manager(sm);
        }

        server = server.with_app_servers(Some(state.app_servers.clone()));

        // NOTE (eggbench qualification): the HTTP listener serves on all
        // profiles. A `#[cfg(not(feature = "mesh"))] let _ = server;`
        // stub here silently disabled the data plane on minimal builds;
        // the accept loop carries no mesh dependency.
        server.serve().await
    }

    pub(crate) async fn run_https_server_inner(
        state: Arc<ServerSharedState>,
        std_listener: std::net::TcpListener,
        plan: crate::config::HttpListenerPlan,
        cert_resolver: Arc<CertResolver>,
        tls_config: InternalTlsConfig,
        http_config: crate::config::HttpConfig,
        main_config: crate::config::MainConfig,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::tls::HttpsServer;

        let alt_svc = if plan.http3 {
            let cfg = state.config.read().await;
            Some(format!(
                "h3=\":{}\"; ma={}",
                plan.addr.port(),
                cfg.main.http3.alt_svc_max_age
            ))
        } else {
            None
        };
        let mut server = HttpsServer::new(
            plan.addr,
            tls_config,
            cert_resolver,
            (*state.router).clone(),
            state.waf.clone(),
            http_config,
            main_config,
            shutdown_rx,
        )
        .with_tcp_listener(std_listener)
        .with_listener_plan(plan);

        if let Some(alt_svc) = alt_svc {
            server = server.with_alt_svc(alt_svc);
        }

        if let Some(fp) = state.flood_protector.clone() {
            server = server.with_flood_protector(fp);
        }
        if let Some(metrics) = state.metrics.clone() {
            server = server.with_metrics(metrics);
        }
        if let Some(ds) = state.drain_state.clone() {
            server = server.with_drain_state(ds);
        }
        #[cfg(feature = "mesh")]
        if let Some(mt) = state.mesh_transport.clone() {
            let config_guard = state.config.read().await;
            if let Some(mesh_cfg_external) = config_guard.main.mesh.clone() {
                let mesh_cfg_json = serde_json::to_string(&mesh_cfg_external)?;
                let mesh_cfg_internal: crate::mesh::config::MeshConfig =
                    serde_json::from_str(&mesh_cfg_json)?;
                server = server.with_mesh_config(Arc::new(mesh_cfg_internal));
            }
            drop(config_guard);
            server = server.with_mesh_transport(mt);
        }
        if let (Some(ipc), Some(worker_id)) = (state.ipc.clone(), state.worker_id) {
            server = server.with_ipc(ipc, worker_id);
        }
        server = server.with_request_log_sink(state.request_log_sink.clone());
        if let Some(sm) = state.serverless_manager.clone() {
            server = server.with_serverless_manager(sm);
        }
        server = server.with_app_servers(state.app_servers.clone());

        server.serve().await
    }

    pub(crate) async fn run_http3_server_inner(
        state: Arc<ServerSharedState>,
        std_socket: std::net::UdpSocket,
        plan: crate::config::HttpListenerPlan,
        cert_resolver: Arc<CertResolver>,
        http3_config: Http3Config,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::http3::Http3Server;

        let main_config = state.config.read().await.main.clone();

        let mut server = Http3Server::new(
            plan.addr,
            http3_config,
            (*state.router).clone(),
            state.waf.clone(),
            main_config,
            shutdown_rx,
        )
        .with_udp_socket(std_socket)
        .with_listener_plan(plan);
        if let Some(drain_state) = state.drain_state.clone() {
            let opened_state = drain_state.clone();
            let closed_state = drain_state;
            server = server.with_connection_callbacks(
                Arc::new(move || opened_state.increment_active()),
                Arc::new(move || closed_state.decrement_active()),
            );
        }

        if let Some(fp) = state.flood_protector.clone() {
            server = server.with_flood_protector(fp);
        }

        if let Some(metrics) = state.metrics.clone() {
            server = server.with_metrics(metrics);
        }

        let tls_config = cert_resolver.build_server_config(&[b"h3"])?;
        server.serve(tls_config).await
    }

    pub async fn shutdown(&self) {
        tracing::info!("Shutting down unified server");

        let _ = self.shutdown_tx.send(());

        tracing::info!("Unified server shutdown complete");
    }

    pub async fn reload_config(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut cfg = self.config.write().await;
        let before = synvoid_config::normalize_http_listeners(&cfg.main, &cfg.sites).ok();
        cfg.reload_all();
        let after = synvoid_config::normalize_http_listeners(&cfg.main, &cfg.sites).ok();
        if before != after {
            tracing::warn!(
                "Listener configuration changed; sockets are startup state and require a restart"
            );
            return Err("listener configuration changed; restart the worker to apply it".into());
        }

        tracing::info!("Configuration reloaded");
        Ok(())
    }
}

#[allow(dead_code)]
fn parse_challenge_priority(priority: &str) -> synvoid_challenge::ChallengePriority {
    match priority.to_lowercase().as_str() {
        "pow_then_css" => synvoid_challenge::ChallengePriority::PowThenCss,
        "css_then_pow" => synvoid_challenge::ChallengePriority::CssThenPow,
        "pow_only" => synvoid_challenge::ChallengePriority::PowOnly,
        "css_only" => synvoid_challenge::ChallengePriority::CssOnly,
        _ => synvoid_challenge::ChallengePriority::PowThenCss,
    }
}
