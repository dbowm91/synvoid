use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::config::ConfigManager;
use crate::config::main::{TlsConfig, Http3Config};
use crate::http::HttpServer;
use crate::router::Router;
use crate::tcp::listener::{TcpListenerPool, TcpListenerPoolConfig};
use crate::waf::{WafCore, RateLimitConfigStore, AttackDetectionConfig};
use crate::tls::cert_resolver::CertResolver;
use crate::tls::config::InternalTlsConfig;
use crate::tunnel::TunnelManager;
use crate::utils::parse_host_port;

pub struct UnifiedServer {
    config: Arc<RwLock<ConfigManager>>,
    http_addr: SocketAddr,
    http_addr_v6: Option<SocketAddr>,
    https_addr: Option<SocketAddr>,
    https_addr_v6: Option<SocketAddr>,
    http3_addr: Option<SocketAddr>,
    http3_addr_v6: Option<SocketAddr>,
    tcp_pool: Option<TcpListenerPool>,
    waf: Arc<WafCore>,
    shutdown_tx: broadcast::Sender<()>,
    tls_config: InternalTlsConfig,
    http3_config: Http3Config,
    cert_resolver: Option<Arc<CertResolver>>,
    tunnel_manager: Option<Arc<TunnelManager>>,
}

impl UnifiedServer {
    pub async fn new(config: Arc<RwLock<ConfigManager>>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (http_addr, http_addr_v6, https_addr, https_addr_v6, http3_addr, http3_addr_v6, tcp_pool, waf, tls_config, http3_config, cert_resolver, tunnel_manager) = {
            let cfg = config.read().await;
            let main_config = &cfg.main;
            
            let http_addr: SocketAddr = parse_host_port(&main_config.server.host, main_config.server.port)
                .map_err(|e| format!("Invalid HTTP host: {}", e))?;

            let http_addr_v6 = main_config.server.host_v6.as_ref().map(|h| {
                parse_host_port(h, main_config.server.port)
                    .map_err(|e| format!("Invalid HTTP host_v6: {}", e))
            }).transpose()?;

            let tls_config = InternalTlsConfig::from(main_config.tls.clone());
            let (https_addr, https_addr_v6) = if tls_config.enabled {
                let https = parse_host_port(&main_config.server.host, tls_config.port)
                    .map_err(|e| format!("Invalid HTTPS host: {}", e))?;
                let https_v6 = main_config.server.host_v6.as_ref().map(|h| {
                    parse_host_port(h, tls_config.port)
                        .map_err(|e| format!("Invalid HTTPS host_v6: {}", e))
                }).transpose()?;
                (Some(https), https_v6)
            } else {
                (None, None)
            };

            let http3_config = main_config.http3.clone();
            let (http3_addr, http3_addr_v6) = if http3_config.enabled {
                let h3 = parse_host_port(&main_config.server.host, http3_config.port)
                    .map_err(|e| format!("Invalid HTTP/3 host: {}", e))?;
                let h3_v6 = http3_config.host_v6.as_ref().map(|h| {
                    parse_host_port(h, http3_config.port)
                        .map_err(|e| format!("Invalid HTTP/3 host_v6: {}", e))
                }).transpose()?;
                (Some(h3), h3_v6)
            } else {
                (None, None)
            };

            let waf = Arc::new(Self::create_waf(main_config));

            let tcp_pool = if main_config.tcp.enabled {
                Some(Self::create_tcp_pool(main_config, waf.clone())?)
            } else {
                None
            };

            let cert_resolver = if tls_config.enabled {
                let resolver = Arc::new(CertResolver::new(tls_config.clone()));
                if let Err(e) = resolver.load_certificates() {
                    tracing::warn!("Failed to load TLS certificates: {}. TLS will not be available.", e);
                    None
                } else {
                    Some(resolver)
                }
            } else {
                None
            };
            
            let tunnel_manager = if main_config.tunnel.enabled {
                Some(Arc::new(TunnelManager::new(main_config.tunnel.clone())))
            } else {
                None
            };
            
            (http_addr, http_addr_v6, https_addr, https_addr_v6, http3_addr, http3_addr_v6, tcp_pool, waf, tls_config, http3_config, cert_resolver, tunnel_manager)
        };

        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            http_addr,
            http_addr_v6,
            https_addr,
            https_addr_v6,
            http3_addr,
            http3_addr_v6,
            tcp_pool,
            waf,
            shutdown_tx,
            tls_config,
            http3_config,
            cert_resolver,
            tunnel_manager,
        })
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

    pub fn get_threat_level_manager(&self) -> Option<Arc<crate::waf::ThreatLevelManager>> {
        self.waf.threat_level.clone()
    }

    fn create_waf(main_config: &crate::config::MainConfig) -> WafCore {
        let data_dir = main_config.persistence.data_dir.as_ref().map(|d| std::path::PathBuf::from(d));
        
        WafCore::new(
            RateLimitConfigStore {
                ip: main_config.defaults.ratelimit.ip.clone(),
                global: main_config.defaults.ratelimit.global.clone(),
                cleanup_interval_secs: main_config.rate_limit_memory.cleanup_interval_secs,
            },
            main_config.rate_limit_memory.clone(),
            crate::waf::BotProtectionConfig {
                block_ai_crawlers: main_config.defaults.bot.block_ai_crawlers,
                enable_css_honeypot: main_config.defaults.bot.enable_css_honeypot,
                enable_pow_challenge: main_config.defaults.pow_challenge.enabled,
                known_bots_allow: main_config.defaults.bot.known_bots_allow.clone(),
                ai_crawlers_block: main_config.defaults.bot.ai_crawlers_block.clone(),
                challenge_cookie_name: main_config.defaults.bot.challenge_cookie_name.clone(),
                challenge_window_secs: main_config.defaults.bot.challenge_window_secs,
                pow_difficulty: main_config.defaults.pow_challenge.difficulty,
                pow_timeout_secs: main_config.defaults.pow_challenge.timeout_secs,
                pow_window_secs: main_config.defaults.pow_challenge.window_secs,
                css_enabled: main_config.defaults.css_challenge.enabled,
                css_invalid_min: main_config.defaults.css_challenge.invalid_count_min,
                css_invalid_max: main_config.defaults.css_challenge.invalid_count_max,
                css_valid_count: main_config.defaults.css_challenge.valid_count,
                css_asset_path: main_config.defaults.css_challenge.asset_path.clone(),
                css_valid_ratios: main_config.defaults.css_challenge.valid_aspect_ratios.clone(),
                css_window_secs: main_config.defaults.css_challenge.challenge_window_secs,
                css_verification_window_secs: main_config.defaults.css_challenge.verification_window_secs,
                honeypot_endpoints_file: main_config.defaults.honeypot.endpoints_file.clone(),
                honeypot_enabled: true,
                honeypot_paths_per_ip: main_config.defaults.honeypot.paths_per_ip,
                honeypot_ttl_secs: main_config.defaults.honeypot.ttl_secs,
                honeypot_ban_duration: main_config.defaults.honeypot.block.ban_duration.clone(),
                error_pages_enabled: main_config.defaults.error_pages.enabled,
                error_pages_directory: main_config.defaults.error_pages.directory.clone(),
                error_pages_custom_directory: None,
                theme: crate::theme::ThemeConfig::from(main_config.defaults.theme.clone()),
            },
            crate::waf::EndpointBlockerConfig {
                paths: main_config.defaults.blocked.paths.clone(),
                use_regex: main_config.defaults.blocked.use_regex,
                block_methods: main_config.defaults.blocked.block_methods.clone(),
                block_response_code: main_config.defaults.blocked.block_response_code,
                block_page_html: None,
            },
            crate::waf::WafConfig {
                enable_css_honeypot: main_config.defaults.css_challenge.enabled,
                enable_pow_challenge: main_config.defaults.pow_challenge.enabled,
                enable_auth_challenge: main_config.defaults.auth.enabled,
                auth_login_path: main_config.defaults.auth.login_path.clone(),
                block_ai_crawlers: main_config.defaults.bot.block_ai_crawlers,
                drop_blocked_requests: false,
                test_mode: crate::waf::TestModeConfig::default(),
            },
            Vec::new(),
            None,
            Some(AttackDetectionConfig::default()),
            None,
            Some(main_config.threat_level.clone()),
            Some(main_config.ip_feeds.clone()),
            Some(main_config.defaults.honeypot_probe.clone()),
            Some(main_config.defaults.suspicious_words.clone()),
            Some(main_config.defaults.upstream_errors.clone()),
            Some(main_config.traffic_shaping.clone()),
            data_dir,
            crate::waf::TestModeConfig::default(),
        )
    }

    fn create_tcp_pool(main_config: &crate::config::MainConfig, waf: Arc<WafCore>) -> Result<TcpListenerPool, Box<dyn std::error::Error + Send + Sync>> {
        let pool_config = TcpListenerPoolConfig {
            worker_pool_size: main_config.tcp.worker_pool_size,
            connection_timeout_secs: 5,
            max_connections: 1000,
        };

        let pool = TcpListenerPool::new(pool_config, Default::default())
            .with_rate_limiter(Arc::new(waf.rate_limiter.clone()));

        Ok(pool)
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let shutdown_rx = self.shutdown_tx.subscribe();
        let http_addr = self.http_addr;
        let https_addr = self.https_addr;
        let http3_addr = self.http3_addr;
        let config = self.config.clone();
        let waf = self.waf.clone();
        let tls_config = self.tls_config.clone();
        let http3_config = self.http3_config.clone();
        let cert_resolver = self.cert_resolver.clone();
        
        let tls_config_for_v6 = tls_config.clone();
        let http3_config_for_v6 = http3_config.clone();
        
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
            Router::new(&main_config, sites)
        };
        let router = Arc::new(router);
        
        let http_jh = {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let router = router.clone();
            let waf = waf.clone();
            let config = config.clone();
            tokio::spawn(async move {
                Self::run_http_server_inner(config, http_addr, router, waf, shutdown_rx).await
            })
        };

        let http_v6_jh = if let Some(addr_v6) = self.http_addr_v6 {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let router = router.clone();
            let waf = waf.clone();
            let config = config.clone();
            Some(tokio::spawn(async move {
                tracing::info!("Starting HTTP server on IPv6 {}", addr_v6);
                Self::run_http_server_inner(config, addr_v6, router, waf, shutdown_rx).await
            }))
        } else {
            None
        };

        let https_jh = if let (Some(addr), Some(resolver)) = (https_addr, cert_resolver.clone()) {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let router = router.clone();
            let waf = waf.clone();
            Some(tokio::spawn(async move {
                Self::run_https_server_inner(addr, router, waf, resolver, tls_config.clone(), shutdown_rx).await
            }))
        } else {
            None
        };

        let https_v6_jh = if let (Some(addr_v6), Some(resolver)) = (self.https_addr_v6, cert_resolver.clone()) {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let router = router.clone();
            let waf = waf.clone();
            Some(tokio::spawn(async move {
                tracing::info!("Starting HTTPS server on IPv6 {}", addr_v6);
                Self::run_https_server_inner(addr_v6, router, waf, resolver, tls_config_for_v6.clone(), shutdown_rx).await
            }))
        } else {
            None
        };

        let http3_jh = if let (Some(addr), Some(resolver)) = (http3_addr, cert_resolver.clone()) {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let router = router.clone();
            let waf = waf.clone();
            let config = config.clone();
            Some(tokio::spawn(async move {
                let main_config = {
                    let cfg = config.read().await;
                    cfg.main.clone()
                };
                Self::run_http3_server_inner(addr, router, waf, resolver, http3_config.clone(), shutdown_rx, main_config).await
            }))
        } else {
            None
        };

        let http3_v6_jh = if let (Some(addr_v6), Some(resolver)) = (self.http3_addr_v6, cert_resolver.clone()) {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let router = router.clone();
            let waf = waf.clone();
            let config = config.clone();
            Some(tokio::spawn(async move {
                tracing::info!("Starting HTTP/3 server on IPv6 {}", addr_v6);
                let main_config = {
                    let cfg = config.read().await;
                    cfg.main.clone()
                };
                Self::run_http3_server_inner(addr_v6, router, waf, resolver, http3_config_for_v6.clone(), shutdown_rx, main_config).await
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

        let peer_jh = if let Some(ref manager) = self.tunnel_manager {
            if let Some(peer_config) = manager.peer_config() {
                let config = (*peer_config).clone();
                Some(tokio::spawn(async move {
                    use crate::tunnel::WafPeerServer;
                    let mut server = WafPeerServer::new(config);
                    if let Err(e) = server.start().await {
                        tracing::error!("WAF peer server error: {}", e);
                    }
                }))
            } else {
                None
            }
        } else {
            None
        };

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
                if let Some(jh) = peer_jh {
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
        config: Arc<RwLock<ConfigManager>>,
        http_addr: SocketAddr,
        router: Arc<Router>,
        waf: Arc<WafCore>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (http_config, alt_svc, main_config) = {
            let cfg = config.read().await;
            let http_config = cfg.main.http.clone();
            let http3_config = &cfg.main.http3;
            let main_config = cfg.main.clone();

            let alt_svc = if http3_config.enabled {
                Some(format!("h3=\":{}\"; ma={}", http3_config.port, http3_config.alt_svc_max_age))
            } else {
                None
            };
            (http_config, alt_svc, main_config)
        };

        let mut server = HttpServer::new(http_addr, (*router).clone(), waf, http_config, shutdown_rx, main_config);
        
        if let Some(alt_svc) = alt_svc {
            server = server.with_alt_svc(alt_svc);
        }
        
        server.serve().await
    }

    async fn run_https_server_inner(
        https_addr: SocketAddr,
        router: Arc<Router>,
        waf: Arc<WafCore>,
        cert_resolver: Arc<CertResolver>,
        tls_config: InternalTlsConfig,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::tls::HttpsServer;
        
        let server = HttpsServer::new(https_addr, tls_config, cert_resolver, shutdown_rx);
        server.serve().await
    }

    async fn run_http3_server_inner(
        http3_addr: SocketAddr,
        router: Arc<Router>,
        waf: Arc<WafCore>,
        cert_resolver: Arc<CertResolver>,
        http3_config: Http3Config,
        shutdown_rx: broadcast::Receiver<()>,
        main_config: crate::config::MainConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::http3::Http3Server;
        
        let server = Http3Server::new(http3_addr, http3_config, (*router).clone(), waf, shutdown_rx);
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
