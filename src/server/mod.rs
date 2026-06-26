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

pub mod plugin_runtime;
pub mod resources;
pub mod runtime_handles;
pub mod startup_plan;
pub mod waf_handler;

pub use plugin_runtime::{PluginRuntimeOwner, PluginRuntimeReport};
pub use resources::{UnifiedServerResourceError, UnifiedServerResources};
pub use runtime_handles::{
    NamedRuntimeHandle, RuntimeHandleClass, UnifiedServerRuntimeHandles,
    UnifiedServerRuntimeShutdownReport,
};
pub use startup_plan::{UnifiedServerStartupPlan, UnifiedServerStartupPlanError};

#[derive(Clone)]
struct ServerSharedState {
    config: Arc<RwLock<ConfigManager>>,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    flood_protector: Option<Arc<FloodProtector>>,
    drain_state: Option<Arc<WorkerDrainState>>,
    #[cfg(feature = "mesh")]
    mesh_transport: Option<Arc<crate::mesh::transport::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    mesh_backend_pool: Option<Arc<crate::mesh::MeshBackendPool>>,
    metrics: Option<Arc<WorkerMetrics>>,
    ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    worker_id: Option<WorkerId>,
    serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
    app_servers: Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
    _http_runtime_context: Option<
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
    config: Arc<RwLock<ConfigManager>>,
    http_addr: SocketAddr,
    http_addr_v6: Option<SocketAddr>,
    https_addr: Option<SocketAddr>,
    https_addr_v6: Option<SocketAddr>,
    http3_addr: Option<SocketAddr>,
    http3_addr_v6: Option<SocketAddr>,
    tcp_pool: Option<TcpListenerPool>,
    udp_pool: Option<UdpListenerPool>,
    waf: Arc<WafCore>,
    flood_protector: Option<Arc<FloodProtector>>,
    shutdown_tx: broadcast::Sender<()>,
    stop_accepting_tx: broadcast::Sender<()>,
    tls_config: InternalTlsConfig,
    http3_config: Http3Config,
    cert_resolver: Option<Arc<CertResolver>>,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    tunnel_manager: Option<Arc<TunnelManager>>,
    tunnel_router: Option<Arc<Mutex<TunnelRouter>>>,
    tunnel_config: Option<TunnelConfig>,
    drain_state: Option<Arc<WorkerDrainState>>,
    #[cfg(feature = "mesh")]
    mesh_transport: Option<Arc<crate::mesh::transport::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    mesh_backend_pool: Option<Arc<crate::mesh::MeshBackendPool>>,
    metrics: Option<Arc<WorkerMetrics>>,
    ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    worker_id: Option<WorkerId>,
    block_store: Option<Arc<crate::block_store::BlockStore>>,
    serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
    app_servers: Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,

    // DNS Server
    #[cfg(feature = "dns")]
    _dns_config: Option<crate::config::dns::DnsConfig>,
    #[cfg(feature = "dns")]
    dns_server: Option<Arc<DnsServer>>,
    #[cfg(feature = "dns")]
    _dns_addr: Option<SocketAddr>,
    #[cfg(feature = "dns")]
    _dns_addr_v6: Option<SocketAddr>,
    #[cfg(feature = "dns")]
    acme_manager: Arc<StdMutex<Option<Arc<AcmeManager>>>>,
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
            UnifiedServerStartupPlan::from_config_snapshot(&cfg.main, worker_count)
                .map_err(|e| format!("Startup plan validation failed: {}", e))?
        };

        // Build resources from plan
        let resources = {
            let cfg = config.read().await;
            UnifiedServerResources::build(&cfg.main, &plan, config.clone())
                .map_err(|e| format!("Resource construction failed: {}", e))?
        };

        let (shutdown_tx, _) = broadcast::channel(1);
        let (stop_accepting_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            http_addr: plan.http_addr,
            http_addr_v6: plan.http_addr_v6,
            https_addr: plan.https_addr,
            https_addr_v6: plan.https_addr_v6,
            http3_addr: plan.http3_addr,
            http3_addr_v6: plan.http3_addr_v6,
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
            // reason: ACME cert reload IPC notification — owned by ACME lifecycle
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

        let acme_clone = acme_manager.clone();
        // reason: ACME init + renewal task — owned by AcmeManager lifecycle
        tokio::spawn(async move {
            if let Err(e) = acme_clone.init().await {
                tracing::error!("Failed to initialize ACME manager: {}", e);
                return;
            }
            acme_clone.spawn_renewal_task();
        });

        tracing::info!("ACME manager initialized");
        *self.acme_manager.lock().unwrap() = Some(acme_manager.clone());
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

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let http_addr = self.http_addr;
        let https_addr = self.https_addr;
        let http3_addr = self.http3_addr;
        let config = self.config.clone();
        let waf = self.waf.clone();
        let tls_config = self.tls_config.clone();
        let http3_config = self.http3_config.clone();
        let cert_resolver = self.cert_resolver.clone();

        if let Some(ref tunnel_router) = self.tunnel_router {
            if let Some(ref tunnel_config) = self.tunnel_config {
                if tunnel_config.quic.enabled {
                    tracing::info!("Starting QUIC tunnel router for server-WAF mode");
                    let mut router = tunnel_router.lock().await;
                    router.start().await?;

                    tracing::info!(
                        "QUIC tunnel server listening on {}:{}",
                        tunnel_config.quic.bind_address,
                        tunnel_config.quic.port
                    );
                }
            }
        }

        let threat_level = waf.threat_level.clone();

        if let Some(ref tl) = threat_level {
            let config = tl.get_legacy_config();
            if config.auto_scale {
                let tl_clone = tl.clone();
                // reason: Threat-level auto-scale background task — Maintenance
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        tl_clone.check_and_scale();
                    }
                });
            }
        }

        let router = {
            let cfg = config.read().await;
            let main_config = cfg.main.clone();
            let sites = cfg.sites.clone();

            // Initialize plugin system with owned lifecycle
            let mut plugin_owner = crate::server::plugin_runtime::PluginRuntimeOwner::new(
                Arc::new(crate::plugin::PluginManager::new()),
            );
            plugin_owner.load_configured_plugins(&main_config.plugins.wasm.plugins);

            // Auto-load plugins from configured directory with owned hot-reload
            if let Some(ref plugin_cfg) = main_config.plugins.wasm.plugins.first() {
                let plugin_dir = std::path::Path::new(&plugin_cfg.path)
                    .parent()
                    .unwrap_or(std::path::Path::new("/opt/synvoid/plugins"))
                    .to_path_buf();
                if plugin_dir.is_dir() {
                    if let Err(e) = plugin_owner.enable_hot_reload_if_configured(&plugin_dir) {
                        tracing::debug!("Hot-reload not enabled: {}", e);
                    }
                }
            }

            let plugin_manager = plugin_owner.manager().clone();
            // plugin_owner is stored in the router or kept alive for the server lifetime
            // We keep it alive by not dropping it until after router creation
            let _plugin_owner = plugin_owner;

            Router::new(&main_config, sites).with_plugin_manager(plugin_manager)
        };
        let router = Arc::new(router);

        let http_runtime_context = {
            let root_waf = RootWafProcessor::new(waf.clone());
            let route_resolver = RouterRouteResolver::new(router.clone());
            match (&self.metrics, &self.drain_state) {
                (Some(metrics), Some(drain)) => {
                    let metrics_sink = WorkerMetricsSink::new(metrics.clone());
                    let drain_adapter = WorkerDrainStateAdapter::new(drain.clone());
                    Some(HttpRuntimeContext::new(
                        Arc::new(root_waf),
                        Arc::new(route_resolver),
                        Arc::new(metrics_sink),
                        Arc::new(drain_adapter),
                    ))
                }
                _ => None,
            }
        };

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
            serverless_manager: self.serverless_manager.clone(),
            app_servers: self.app_servers.clone(),
            _http_runtime_context: http_runtime_context,
        });

        // reason: HTTP/1 server — registered in handles as CriticalServer
        let http_jh = {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let state = shared_state.clone();
            tokio::spawn(
                async move { Self::run_http_server_inner(state, http_addr, shutdown_rx).await },
            )
        };

        let http_v6_jh = if let Some(addr_v6) = self.http_addr_v6 {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let state = shared_state.clone();
            // reason: HTTP/1 IPv6 server — registered in handles as ProtocolListener
            Some(tokio::spawn(async move {
                tracing::info!("Starting HTTP server on IPv6 {}", addr_v6);
                Self::run_http_server_inner(state, addr_v6, shutdown_rx).await
            }))
        } else {
            None
        };

        let https_jh = if let (Some(addr), Some(resolver)) = (https_addr, cert_resolver.clone()) {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let state = shared_state.clone();
            let main_config = {
                let cfg = self.config.read().await;
                cfg.main.clone()
            };
            let http_config = main_config.http.clone();
            let tls_cfg = tls_config.clone();
            // reason: HTTPS server — CriticalServer
            Some(tokio::spawn(async move {
                Self::run_https_server_inner(
                    state,
                    addr,
                    resolver,
                    tls_cfg,
                    http_config,
                    main_config,
                    shutdown_rx,
                )
                .await
            }))
        } else {
            None
        };

        let https_v6_jh =
            if let (Some(addr_v6), Some(resolver)) = (self.https_addr_v6, cert_resolver.clone()) {
                let shutdown_rx = self.shutdown_tx.subscribe();
                let state = shared_state.clone();
                let main_config = {
                    let cfg = self.config.read().await;
                    cfg.main.clone()
                };
                let http_config = main_config.http.clone();
                let tls_cfg = tls_config.clone();
                // reason: HTTPS IPv6 server — ProtocolListener
                Some(tokio::spawn(async move {
                    tracing::info!("Starting HTTPS server on IPv6 {}", addr_v6);
                    Self::run_https_server_inner(
                        state,
                        addr_v6,
                        resolver,
                        tls_cfg,
                        http_config,
                        main_config,
                        shutdown_rx,
                    )
                    .await
                }))
            } else {
                None
            };

        let http3_jh = if let (Some(addr), Some(resolver)) = (http3_addr, cert_resolver.clone()) {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let state = shared_state.clone();
            let h3_cfg = http3_config.clone();
            // reason: HTTP/3 server — ProtocolListener
            Some(tokio::spawn(async move {
                Self::run_http3_server_inner(state, addr, resolver, h3_cfg, shutdown_rx).await
            }))
        } else {
            None
        };

        let http3_v6_jh = if let (Some(addr_v6), Some(resolver)) =
            (self.http3_addr_v6, cert_resolver.clone())
        {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let state = shared_state.clone();
            let h3_cfg = http3_config.clone();
            // reason: HTTP/3 IPv6 server — ProtocolListener
            Some(tokio::spawn(async move {
                tracing::info!("Starting HTTP/3 server on IPv6 {}", addr_v6);
                Self::run_http3_server_inner(state, addr_v6, resolver, h3_cfg, shutdown_rx).await
            }))
        } else {
            None
        };

        let tcp_jh = match &self.tcp_pool {
            Some(pool) => {
                let pool = pool.clone();
                // reason: TCP listener pool — ProtocolListener
                Some(tokio::spawn(async move {
                    pool.start().await;
                }))
            }
            None => None,
        };

        let udp_jh = match &self.udp_pool {
            Some(pool) => {
                let pool = pool.clone();
                // reason: UDP listener pool — ProtocolListener
                Some(tokio::spawn(async move {
                    pool.start().await;
                }))
            }
            None => None,
        };

        // DNS Server
        #[cfg(feature = "dns")]
        let dns_jh: Option<tokio::task::JoinHandle<()>> = {
            match &self.dns_server {
                Some(dns_server) => {
                    #[cfg(feature = "mesh")]
                    let is_global = self
                        .mesh_transport
                        .as_ref()
                        .map(|mt| mt.is_global_node())
                        .unwrap_or(false);
                    #[cfg(not(feature = "mesh"))]
                    let is_global = false;
                    #[cfg(feature = "mesh")]
                    let dns_mesh_mode_only = {
                        let topology = self.mesh_transport.as_ref().map(|mt| mt.get_topology());
                        if let Some(ref t) = topology {
                            let cfg = t.config();
                            cfg.dht
                                .as_ref()
                                .map(|d| d.dns_mesh_mode_only)
                                .unwrap_or(true)
                        } else {
                            true
                        }
                    };
                    #[cfg(not(feature = "mesh"))]
                    let dns_mesh_mode_only = true;
                    let can_start = !dns_mesh_mode_only || is_global;

                    if can_start {
                        let dns_server = dns_server.clone();
                        // reason: DNS server — ProtocolListener
                        Some(tokio::spawn(async move {
                            let mut server = (*dns_server).clone();
                            if let Err(e) = server.start().await {
                                tracing::error!("DNS server error: {}", e);
                            }
                        }))
                    } else {
                        tracing::info!(
                            "Skipping DNS server: dns_mesh_mode_only=true and node is not global"
                        );
                        None
                    }
                }
                None => None,
            }
        };

        #[cfg(not(feature = "dns"))]
        let dns_jh: Option<tokio::task::JoinHandle<()>> = None;

        tokio::select! {
            result = http_jh => {
                if let Err(e) = result {
                    tracing::error!("HTTP server error: {}", e);
                }
            }
            _ = async {
                if let Some(jh) = http_v6_jh {
                    jh.await.ok();
                }
            } => {}
            _ = async {
                if let Some(jh) = https_jh {
                    jh.await.ok();
                }
            } => {}
            _ = async {
                if let Some(jh) = https_v6_jh {
                    jh.await.ok();
                }
            } => {}
            _ = async {
                if let Some(jh) = http3_jh {
                    jh.await.ok();
                }
            } => {}
            _ = async {
                if let Some(jh) = http3_v6_jh {
                    jh.await.ok();
                }
            } => {}
            _ = async {
                if let Some(jh) = tcp_jh {
                    jh.await.ok();
                }
            } => {}
            _ = async {
                if let Some(jh) = udp_jh {
                    jh.await.ok();
                }
            } => {}
            _ = async {
                if let Some(jh) = dns_jh {
                    jh.await.ok();
                }
            } => {}
            _ = async { tokio::signal::ctrl_c().await } => {
                tracing::info!("Shutdown signal received");
            }
        }

        self.shutdown().await;

        tracing::info!("Unified server shutdown complete");

        Ok(())
    }

    async fn run_http_server_inner(
        state: Arc<ServerSharedState>,
        http_addr: SocketAddr,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (http_config, alt_svc, main_config, mesh_config) = {
            let cfg = state.config.read().await;
            let http_config = cfg.main.http.clone();
            let http3_config = &cfg.main.http3;
            let main_config = cfg.main.clone();
            #[cfg(feature = "mesh")]
            let mesh_config = cfg.main.tunnel.mesh.clone();
            #[cfg(not(feature = "mesh"))]
            let mesh_config: Option<()> = None;

            let alt_svc = if http3_config.enabled {
                Some(format!(
                    "h3=\":{}\"; ma={}",
                    http3_config.port, http3_config.alt_svc_max_age
                ))
            } else {
                None
            };
            (http_config, alt_svc, main_config, mesh_config)
        };
        let _ = &mesh_config;

        let mut server = HttpServer::new(
            http_addr,
            (*state.router).clone(),
            state.waf.clone(),
            http_config,
            shutdown_rx,
            main_config,
        );

        if let Some(alt_svc) = alt_svc {
            server = server.with_alt_svc(alt_svc);
        }

        if let Some(fp) = state.flood_protector.clone() {
            server = server.with_flood_protector(fp);
        }

        if let Some(ds) = state.drain_state.clone() {
            server = server.with_drain_state(ds);
        }

        #[cfg(feature = "mesh")]
        if let Some(mesh_cfg_external) = mesh_config {
            let mesh_cfg_internal: crate::mesh::config::MeshConfig =
                serde_json::from_str(&serde_json::to_string(&mesh_cfg_external).unwrap()).unwrap();
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

        if let Some(sm) = state.serverless_manager.clone() {
            server = server.with_serverless_manager(sm);
        }

        server = server.with_app_servers(Some(state.app_servers.clone()));

        #[cfg(feature = "mesh")]
        {
            server.serve().await
        }
        #[cfg(not(feature = "mesh"))]
        {
            let _ = server;
            Ok(())
        }
    }

    async fn run_https_server_inner(
        state: Arc<ServerSharedState>,
        https_addr: SocketAddr,
        cert_resolver: Arc<CertResolver>,
        tls_config: InternalTlsConfig,
        http_config: crate::config::HttpConfig,
        main_config: crate::config::MainConfig,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::tls::HttpsServer;

        let mut server = HttpsServer::new(
            https_addr,
            tls_config,
            cert_resolver,
            (*state.router).clone(),
            state.waf.clone(),
            http_config,
            main_config,
            shutdown_rx,
        );

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
                let mesh_cfg_internal: crate::mesh::config::MeshConfig =
                    serde_json::from_str(&serde_json::to_string(&mesh_cfg_external).unwrap())
                        .unwrap();
                server = server.with_mesh_config(Arc::new(mesh_cfg_internal));
            }
            drop(config_guard);
            server = server.with_mesh_transport(mt);
        }
        if let (Some(ipc), Some(worker_id)) = (state.ipc.clone(), state.worker_id) {
            server = server.with_ipc(ipc, worker_id);
        }
        if let Some(sm) = state.serverless_manager.clone() {
            server = server.with_serverless_manager(sm);
        }
        server = server.with_app_servers(state.app_servers.clone());

        server.serve().await
    }

    async fn run_http3_server_inner(
        state: Arc<ServerSharedState>,
        http3_addr: SocketAddr,
        cert_resolver: Arc<CertResolver>,
        http3_config: Http3Config,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::http3::Http3Server;

        let main_config = state.config.read().await.main.clone();

        let mut server = Http3Server::new(
            http3_addr,
            http3_config,
            (*state.router).clone(),
            state.waf.clone(),
            main_config,
            shutdown_rx,
        );

        if let Some(fp) = state.flood_protector.clone() {
            server = server.with_flood_protector(fp);
        }

        if let Some(metrics) = state.metrics.clone() {
            server = server.with_metrics(metrics);
        }

        let tls_config = cert_resolver.build_server_config()?;
        server.serve(tls_config).await
    }

    pub async fn shutdown(&self) {
        tracing::info!("Shutting down unified server");

        let _ = self.shutdown_tx.send(());

        tracing::info!("Unified server shutdown complete");
    }

    pub async fn reload_config(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut cfg = self.config.write().await;
        cfg.reload_all();

        tracing::info!("Configuration reloaded");
        Ok(())
    }
}

#[allow(dead_code)]
fn parse_challenge_priority(priority: &str) -> crate::challenge::ChallengePriority {
    match priority.to_lowercase().as_str() {
        "pow_then_css" => crate::challenge::ChallengePriority::PowThenCss,
        "css_then_pow" => crate::challenge::ChallengePriority::CssThenPow,
        "pow_only" => crate::challenge::ChallengePriority::PowOnly,
        "css_only" => crate::challenge::ChallengePriority::CssOnly,
        _ => crate::challenge::ChallengePriority::PowThenCss,
    }
}
