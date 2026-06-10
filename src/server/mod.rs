use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};

use crate::config::ConfigManager;
use crate::config::{Http3Config, TunnelConfig};
use crate::http::HttpServer;
use crate::router::Router;
use crate::tcp::listener::TcpListenerPool;
use crate::udp::listener::{UdpListenerPool, UdpListenerPoolConfig};

#[cfg(feature = "dns")]
use crate::dns::DnsServer;
#[cfg(feature = "dns")]
use std::sync::Mutex as StdMutex;
#[cfg(feature = "dns")]
use crate::tls::acme::AcmeManager;
use crate::metrics::adapter::WorkerMetricsSink;
use crate::metrics::WorkerMetrics;
use crate::process::ipc::WorkerId;
use crate::router_adapter::RouterRouteResolver;
use crate::tls::cert_resolver::CertResolver;
use crate::tls::config::InternalTlsConfig;
use crate::tunnel::{TunnelManager, TunnelRouter};
use crate::utils::parse_host_port;
use crate::waf::adapter::RootWafProcessor;
use crate::waf::{AttackDetectionConfig, FloodProtector, RateLimitConfigStore, WafCore};
use crate::worker::drain_adapter::WorkerDrainStateAdapter;
use crate::worker::drain_state::WorkerDrainState;
use synvoid_http::runtime::HttpRuntimeContext;

pub mod waf_handler;

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
        let (
            http_addr,
            http_addr_v6,
            https_addr,
            https_addr_v6,
            http3_addr,
            http3_addr_v6,
            tcp_pool,
            flood_protector,
            udp_pool,
            waf,
            tls_config,
            http3_config,
            cert_resolver,
            tunnel_manager,
            tunnel_config,
            tunnel_router,
        ) = {
            let cfg = config.read().await;
            let main_config = &cfg.main;

            let http_addr: SocketAddr =
                parse_host_port(&main_config.server.host, main_config.server.port)
                    .map_err(|e| format!("Invalid HTTP host: {}", e))?;

            let http_addr_v6 = main_config
                .server
                .host_v6
                .as_ref()
                .map(|h| {
                    parse_host_port(h, main_config.server.port)
                        .map_err(|e| format!("Invalid HTTP host_v6: {}", e))
                })
                .transpose()?;

            let tls_config = InternalTlsConfig::from(main_config.tls.clone());
            let (https_addr, https_addr_v6) = if tls_config.enabled {
                let https = parse_host_port(&main_config.server.host, tls_config.port)
                    .map_err(|e| format!("Invalid HTTPS host: {}", e))?;
                let https_v6 = main_config
                    .server
                    .host_v6
                    .as_ref()
                    .map(|h| {
                        parse_host_port(h, tls_config.port)
                            .map_err(|e| format!("Invalid HTTPS host_v6: {}", e))
                    })
                    .transpose()?;
                (Some(https), https_v6)
            } else {
                (None, None)
            };

            let http3_config = main_config.http3.clone();
            let (http3_addr, http3_addr_v6) = if http3_config.enabled {
                let h3 = parse_host_port(&main_config.server.host, http3_config.port)
                    .map_err(|e| format!("Invalid HTTP/3 host: {}", e))?;
                let h3_v6 = http3_config
                    .host_v6
                    .as_ref()
                    .map(|h| {
                        parse_host_port(h, http3_config.port)
                            .map_err(|e| format!("Invalid HTTP/3 host_v6: {}", e))
                    })
                    .transpose()?;
                (Some(h3), h3_v6)
            } else {
                (None, None)
            };

            let waf = Arc::new(Self::create_waf(main_config, worker_count));

            let (tcp_pool, flood_protector) = if main_config.tcp.enabled {
                let (pool, fp) = Self::create_tcp_pool(main_config, waf.clone())?;
                (Some(pool), Some(fp))
            } else {
                (None, None)
            };

            let udp_pool = if main_config.udp.enabled {
                let pool = Self::create_udp_pool(main_config, waf.clone())?;
                let sites = cfg.sites.clone();
                for (site_id, site_config) in &sites {
                    if !site_config.udp.enabled.unwrap_or(false) {
                        continue;
                    }
                    for (port_name, port_config) in &site_config.udp.ports {
                        if let (Some(port), Some(upstream)) =
                            (port_config.port, &port_config.upstream)
                        {
                            let listener_config = crate::udp::listener::UdpListenerConfig {
                                port,
                                bind_address: main_config.server.host.clone(),
                                bind_address_v6: main_config.server.host_v6.clone(),
                                expected_protocol: port_config
                                    .expected_protocol
                                    .clone()
                                    .unwrap_or_else(|| port_name.clone()),
                                upstream_address: upstream.clone(),
                                upstream_address_v6: None,
                                filter_enabled: site_config
                                    .udp
                                    .filter
                                    .as_ref()
                                    .map(|f| f.enabled.unwrap_or(true))
                                    .unwrap_or(true),
                                strict_mode: true,
                                max_packet_size: 4096,
                                rate_limit_per_ip: main_config.udp.rate_per_ip,
                                socket_options: Default::default(),
                            };
                            match pool.add_listener(listener_config).await {
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to add UDP listener for site {} port {}: {}",
                                        site_id,
                                        port,
                                        e
                                    );
                                }
                                _ => {
                                    tracing::info!(
                                        "Added UDP listener for site {} on port {} ({})",
                                        site_id,
                                        port,
                                        port_name
                                    );
                                }
                            }
                        }
                    }
                }
                Some(pool)
            } else {
                None
            };

            let cert_resolver = if tls_config.enabled {
                let resolver = Arc::new(CertResolver::new(tls_config.clone()));
                match resolver.load_certificates() {
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load TLS certificates: {}. TLS will not be available.",
                            e
                        );
                        None
                    }
                    _ => Some(resolver),
                }
            } else {
                None
            };

            let tunnel_config = if main_config.tunnel.enabled {
                Some(main_config.tunnel.clone())
            } else {
                None
            };

            let tunnel_manager = if main_config.tunnel.enabled {
                Some(Arc::new(TunnelManager::new(tunnel_config.clone().unwrap())))
            } else {
                None
            };

            let tunnel_router = if main_config.tunnel.quic.enabled {
                match TunnelRouter::new(tunnel_config.clone().unwrap()) {
                    Ok(router) => Some(Arc::new(Mutex::new(router))),
                    Err(e) => {
                        tracing::warn!("Failed to create tunnel router: {}", e);
                        None
                    }
                }
            } else {
                None
            };

            (
                http_addr,
                http_addr_v6,
                https_addr,
                https_addr_v6,
                http3_addr,
                http3_addr_v6,
                tcp_pool,
                flood_protector,
                udp_pool,
                waf,
                tls_config,
                http3_config,
                cert_resolver,
                tunnel_manager,
                tunnel_config,
                tunnel_router,
            )
        };

        // DNS Server Configuration
        #[cfg(feature = "dns")]
        let (dns_config, dns_server, dns_addr, dns_addr_v6) = {
            let cfg = config.read().await;
            let dns_cfg = cfg.main.dns.clone();

            if !dns_cfg.enabled {
                (None, None, None, None)
            } else {
                let bind_addr: SocketAddr = format!("{}:{}", dns_cfg.bind_address, dns_cfg.port)
                    .parse()
                    .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 53)));

                let dns_addr_v6 = if dns_cfg.bind_address != "0.0.0.0" {
                    format!("[::]:{}", dns_cfg.port).parse().ok()
                } else {
                    None
                };

                // Create DNS server with config and shared TLS certificates
                let mut dns_server = DnsServer::new(dns_cfg.clone(), cert_resolver.clone());

                // Wire up ZoneTransfer configuration if transfers are allowed
                if !dns_cfg.settings.allow_transfer.is_empty()
                    || dns_cfg.settings.allow_wildcard_transfer
                {
                    use crate::dns::tsig::TsigVerifier;

                    let tsig_verifier = if !dns_cfg.dnssec.tsig_keys.is_empty() {
                        match TsigVerifier::new(dns_cfg.dnssec.tsig_keys.clone()) {
                            Ok(v) => Some(Arc::new(v)),
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to initialize TSIG for zone transfers: {}",
                                    e
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };

                    dns_server = dns_server.with_zone_transfer_config(
                        dns_cfg.settings.allow_transfer.clone(),
                        dns_cfg.settings.allow_wildcard_transfer,
                        dns_cfg.settings.wildcard_transfer_requires_tsig,
                        dns_cfg.settings.ixfr_enabled,
                        dns_cfg.settings.ixfr_fallback_to_axfr,
                        tsig_verifier,
                        dns_cfg.settings.require_tsig,
                    );

                    tracing::info!(
                        "Zone transfer configured: IXFR={}, AXFR fallback={}",
                        dns_cfg.settings.ixfr_enabled,
                        dns_cfg.settings.ixfr_fallback_to_axfr
                    );
                }

                let dns_server = Arc::new(dns_server);

                tracing::info!(
                    "DNS server configured on {} (IPv4{})",
                    bind_addr,
                    if dns_addr_v6.is_some() { " + IPv6" } else { "" }
                );

                (
                    Some(dns_cfg),
                    Some(dns_server),
                    Some(bind_addr),
                    dns_addr_v6,
                )
            }
        };

        #[cfg(not(feature = "dns"))]
        let _dns_config: Option<std::convert::Infallible> = None;
        #[cfg(not(feature = "dns"))]
        let _dns_server: Option<std::convert::Infallible> = None;
        #[cfg(not(feature = "dns"))]
        let _dns_addr: Option<SocketAddr> = None;
        #[cfg(not(feature = "dns"))]
        let _dns_addr_v6: Option<SocketAddr> = None;

        let (shutdown_tx, _) = broadcast::channel(1);
        let (stop_accepting_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            http_addr,
            http_addr_v6,
            https_addr,
            https_addr_v6,
            http3_addr,
            http3_addr_v6,
            tcp_pool,
            udp_pool,
            waf,
            flood_protector,
            shutdown_tx,
            stop_accepting_tx,
            tls_config,
            http3_config,
            cert_resolver,
            tunnel_manager,
            tunnel_router,
            tunnel_config,
            drain_state: None,
            #[cfg(feature = "mesh")]
            mesh_transport,
            #[cfg(feature = "mesh")]
            mesh_backend_pool: None,
            metrics: None,
            ipc: None,
            worker_id: None,
            serverless_manager: None,
            app_servers: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "dns")]
            _dns_config: dns_config,
            #[cfg(feature = "dns")]
            dns_server,
            #[cfg(feature = "dns")]
            _dns_addr: dns_addr,
            #[cfg(feature = "dns")]
            _dns_addr_v6: dns_addr_v6,
            #[cfg(feature = "dns")]
            acme_manager: Arc::new(StdMutex::new(None)),
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
        self.waf.block_store.clone()
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

    fn create_waf(main_config: &crate::config::MainConfig, worker_count: usize) -> WafCore {
        let data_dir = main_config
            .persistence
            .data_dir
            .as_ref()
            .map(std::path::PathBuf::from);

        // Scale rate limits by worker count to maintain global semantics
        // (Approximation: total_limit / worker_count)
        let worker_count = worker_count.max(1);
        let mut ip_limit = main_config.defaults.ratelimit.ip.clone();
        let mut global_limit = main_config.defaults.ratelimit.global.clone();

        if worker_count > 1 {
            ip_limit.per_second = (ip_limit.per_second as f64 / worker_count as f64).ceil() as u32;
            ip_limit.per_minute = (ip_limit.per_minute as f64 / worker_count as f64).ceil() as u32;
            global_limit.per_second =
                (global_limit.per_second as f64 / worker_count as f64).ceil() as u32;
            global_limit.per_minute =
                (global_limit.per_minute as f64 / worker_count as f64).ceil() as u32;

            tracing::info!(
                "Scaling worker rate limits by 1/{} (IP: {} RPS, Global: {} RPS)",
                worker_count,
                ip_limit.per_second,
                global_limit.per_second
            );
        }

        WafCore::new(crate::waf::WafCoreConfig {
            rate_config: RateLimitConfigStore {
                ip: ip_limit,
                global: global_limit,
                cleanup_interval_secs: main_config.rate_limit_memory.cleanup_interval_secs,
            },
            memory_config: main_config.rate_limit_memory.clone(),
            bot_config: main_config.defaults.bot.clone(),
            endpoint_config: main_config.defaults.blocked.clone(),
            waf_config: crate::waf::WafConfig {
                enable_css_honeypot: main_config.defaults.css_challenge.enabled,
                enable_pow_challenge: main_config.defaults.pow_challenge.enabled,
                enable_auth_challenge: main_config.defaults.auth.enabled,
                auth_login_path: main_config.defaults.auth.login_path.clone(),
                block_ai_crawlers: main_config.defaults.bot.block_ai_crawlers,
                drop_blocked_requests: false,
                test_mode: crate::waf::TestModeConfig::default(),
                honeypot_ban_duration_secs: 86400,
                css_exempt_paths: main_config.defaults.css_challenge.exempt_paths.clone(),
            },
            whitelist: Vec::new(),
            block_store: None,
            attack_detection_config: Some(AttackDetectionConfig::default()),
            auth_manager: None,
            threat_level_config: Some(main_config.threat_level.clone()),
            ip_feed_config: Some(main_config.ip_feeds.clone()),
            probe_config: Some(main_config.defaults.honeypot_probe.clone()),
            suspicious_words_config: Some(main_config.defaults.suspicious_words.clone()),
            upstream_errors_config: Some(main_config.defaults.upstream_errors.clone()),
            traffic_shaping_config: Some(main_config.traffic_shaping.clone()),
            bandwidth_config: main_config.traffic_shaping.bandwidth.clone(),
            asn_scraping_config: Some(main_config.defaults.asn_scraping.clone()),
            geoip: None,
            data_dir,
            test_mode: crate::waf::TestModeConfig::default(),
            tarpit_defaults: Some(main_config.tarpit.clone()),
        })
    }

    fn create_tcp_pool(
        main_config: &crate::config::MainConfig,
        waf: Arc<WafCore>,
    ) -> Result<(TcpListenerPool, Arc<FloodProtector>), Box<dyn std::error::Error + Send + Sync>>
    {
        use crate::tcp::listener::TcpListenerPoolConfig;
        use crate::tcp::listener::TcpSocketOptions;
        use crate::waf::flood::{FloodConfig, FloodProtector};

        let socket_options = TcpSocketOptions {
            nodelay: main_config.tcp.socket.nodelay,
            send_buffer_size: main_config.tcp.socket.send_buffer_size,
            recv_buffer_size: main_config.tcp.socket.recv_buffer_size,
            reuse_port: true,
            reuse_port_ebpf: false,
            quickack: true,
            keepalive_secs: Some(60),
            keepalive_interval_secs: Some(10),
            keepalive_retries: Some(3),
        };

        let pool_config = TcpListenerPoolConfig {
            worker_pool_size: main_config.tcp.worker_pool_size,
            connection_timeout_secs: 5,
            max_connections: 10000,
            socket_options,
            buffer_size: 64 * 1024,
            enable_concurrency_limit: true,
        };

        let flood_config = FloodConfig {
            syn_rate_per_ip: main_config.tcp.syn_rate_per_ip,
            syn_rate_global: main_config.tcp.syn_rate_global,
            connection_rate_per_ip: main_config.tcp.connection_rate_per_ip,
            connection_rate_global: main_config.tcp.connection_rate_global,
            half_open_max: main_config.tcp.half_open_max,
            half_open_per_ip_max: main_config.tcp.half_open_per_ip_max,
            ..Default::default()
        };
        let flood_protector = Arc::new(FloodProtector::new(flood_config));

        let pool = TcpListenerPool::new(pool_config, Default::default())
            .with_rate_limiter(Arc::new(waf.rate_limiter.clone()))
            .with_flood_protector(flood_protector.clone());

        Ok((pool, flood_protector))
    }

    fn create_udp_pool(
        main_config: &crate::config::MainConfig,
        _waf: Arc<WafCore>,
    ) -> Result<UdpListenerPool, Box<dyn std::error::Error + Send + Sync>> {
        use crate::udp::listener::UdpSocketOptions;
        use crate::waf::flood::{FloodConfig, FloodProtector};

        let socket_options = UdpSocketOptions {
            reuse_port: true,
            recv_buffer_size: main_config.udp.socket.recv_buffer_size,
            send_buffer_size: main_config.udp.socket.send_buffer_size,
        };

        let pool_config = UdpListenerPoolConfig {
            worker_pool_size: main_config.udp.worker_pool_size,
            buffer_size: 8192,
            max_packets_per_second: 10000,
            socket_options,
            workers_per_listener: 1,
        };

        let flood_config = FloodConfig {
            udp_rate_per_ip: main_config.udp.rate_per_ip,
            udp_rate_global: main_config.udp.rate_global,
            ..Default::default()
        };
        let flood_protector = Arc::new(FloodProtector::new(flood_config));

        let pool = UdpListenerPool::new(pool_config, Default::default())
            .with_flood_protector(flood_protector);

        Ok(pool)
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _shutdown_rx = self.shutdown_tx.subscribe();
        let http_addr = self.http_addr;
        let https_addr = self.https_addr;
        let http3_addr = self.http3_addr;
        let config = self.config.clone();
        let waf = self.waf.clone();
        let tls_config = self.tls_config.clone();
        let http3_config = self.http3_config.clone();
        let cert_resolver = self.cert_resolver.clone();

        let _tls_config_for_v6 = tls_config.clone();
        let _http3_config_for_v6 = http3_config.clone();

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

            // Initialize plugin system
            let plugin_manager = Arc::new(crate::plugin::PluginManager::new());
            if !main_config.plugins.wasm.plugins.is_empty() {
                for plugin_cfg in &main_config.plugins.wasm.plugins {
                    let limits = crate::plugin::WasmResourceLimits {
                        max_memory_mb: plugin_cfg
                            .max_memory_mb
                            .unwrap_or(main_config.plugins.wasm.max_memory_mb),
                        max_cpu_fuel: plugin_cfg
                            .max_cpu_fuel
                            .unwrap_or(main_config.plugins.wasm.max_cpu_fuel),
                        timeout_seconds: plugin_cfg
                            .timeout_seconds
                            .unwrap_or(main_config.plugins.wasm.timeout_seconds),
                        allowed_dht_prefixes: plugin_cfg.allowed_dht_prefixes.clone(),
                        ..Default::default()
                    };
                    let path = std::path::Path::new(&plugin_cfg.path);
                    match plugin_manager
                        .wasm_manager()
                        .load_plugin_with_limits(path, limits)
                    {
                        Ok(_) => {
                            tracing::info!("Loaded WASM plugin: {}", plugin_cfg.name);
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to load WASM plugin {}: {}",
                                plugin_cfg.name,
                                e
                            );
                        }
                    }
                }
            }

            // Auto-load plugins from configured directory
            if let Some(ref plugin_dir) = main_config.plugins.wasm.plugins.first().map(|p| {
                std::path::Path::new(&p.path)
                    .parent()
                    .unwrap_or(std::path::Path::new("/opt/synvoid/plugins"))
                    .to_path_buf()
            }) {
                if plugin_dir.is_dir() {
                    let mut lifecycle =
                        crate::plugin::PluginManagerLifecycle::new(plugin_manager.clone());
                    match lifecycle.load_plugins_from_dir(plugin_dir) {
                        Ok(count) if count > 0 => {
                            tracing::info!(
                                "Auto-loaded {} WASM plugins from {}",
                                count,
                                plugin_dir.display()
                            );
                        }
                        _ => {}
                    }
                    // Enable hot-reload for plugin directory.
                    // The lifecycle (and its file watcher) is intentionally leaked
                    // so the watcher thread stays alive for the server's lifetime.
                    if let Err(e) = lifecycle.enable_hot_reload(plugin_dir) {
                        tracing::debug!("Hot-reload not enabled: {}", e);
                    }
                    std::mem::forget(lifecycle);
                }
            }

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
                Some(tokio::spawn(async move {
                    pool.start().await;
                }))
            }
            None => None,
        };

        let udp_jh = match &self.udp_pool {
            Some(pool) => {
                let pool = pool.clone();
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
