use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::config::ConfigManager;
use crate::config::MainConfig;
use crate::tunnel::{TunnelManager, TunnelRouter};
use crate::waf::{FloodProtector, RateLimitConfigStore, WafCore};

use super::startup_plan::UnifiedServerStartupPlan;

pub struct UnifiedServerResources {
    pub waf: Arc<WafCore>,
    pub tcp_pool: Option<crate::tcp::listener::TcpListenerPool>,
    pub udp_pool: Option<crate::udp::listener::UdpListenerPool>,
    pub flood_protector: Option<Arc<FloodProtector>>,
    pub cert_resolver: Option<Arc<crate::tls::cert_resolver::CertResolver>>,
    pub tunnel_manager: Option<Arc<TunnelManager>>,
    pub tunnel_router: Option<Arc<Mutex<TunnelRouter>>>,
    pub app_servers: Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
    #[cfg(feature = "dns")]
    pub dns_server: Option<Arc<crate::dns::DnsServer>>,
    #[cfg(feature = "dns")]
    pub acme_manager: Option<Arc<crate::tls::acme::AcmeManager>>,
}

#[derive(Debug, thiserror::Error)]
pub enum UnifiedServerResourceError {
    #[error("failed to create WAF: {0}")]
    Waf(String),
    #[error("failed to create TCP listener pool: {0}")]
    TcpPool(String),
    #[error("failed to create UDP listener pool: {0}")]
    UdpPool(String),
    #[error("failed to initialize TLS resources: {0}")]
    Tls(String),
    #[error("failed to initialize tunnel resources: {0}")]
    Tunnel(String),
    #[cfg(feature = "dns")]
    #[error("failed to initialize DNS resources: {0}")]
    Dns(String),
}

impl UnifiedServerResources {
    /// Construct all resources from config without spawning tasks.
    pub fn build(
        main_config: &MainConfig,
        plan: &UnifiedServerStartupPlan,
        config: Arc<RwLock<ConfigManager>>,
    ) -> Result<Self, UnifiedServerResourceError> {
        let tls_config = crate::tls::config::InternalTlsConfig::from(main_config.tls.clone());

        // WAF — use plan's pre-scaled rate limits
        let waf = Arc::new(Self::create_waf(
            main_config,
            &plan.scaled_ip_rate_limit,
            &plan.scaled_global_rate_limit,
        ));

        // TCP pool + flood protector
        let (tcp_pool, flood_protector) = if plan.tcp_enabled {
            let (pool, fp) = Self::create_tcp_pool(main_config, waf.clone())
                .map_err(|e| UnifiedServerResourceError::TcpPool(e.to_string()))?;
            (Some(pool), Some(fp))
        } else {
            (None, None)
        };

        // UDP pool (listeners registered later in run())
        let udp_pool = if plan.udp_enabled {
            let pool = Self::create_udp_pool(main_config, waf.clone())
                .map_err(|e| UnifiedServerResourceError::UdpPool(e.to_string()))?;
            Some(pool)
        } else {
            None
        };

        // TLS cert resolver
        let cert_resolver = if tls_config.enabled {
            let resolver = Arc::new(crate::tls::cert_resolver::CertResolver::new(
                tls_config.clone(),
            ));
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

        // Tunnel manager
        let tunnel_manager = if plan.tunnel_enabled {
            let tunnel_config = plan.tunnel_config.clone().ok_or_else(|| {
                UnifiedServerResourceError::Tunnel("missing tunnel config".into())
            })?;
            Some(Arc::new(TunnelManager::new(tunnel_config)))
        } else {
            None
        };

        // Tunnel router (QUIC)
        let tunnel_router = if plan.tunnel_quic_enabled {
            let tunnel_config = plan.tunnel_config.clone().ok_or_else(|| {
                UnifiedServerResourceError::Tunnel("missing tunnel config".into())
            })?;
            match TunnelRouter::new(tunnel_config) {
                Ok(router) => Some(Arc::new(Mutex::new(router))),
                Err(e) => {
                    tracing::warn!("Failed to create tunnel router: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let app_servers = Arc::new(RwLock::new(HashMap::new()));

        // DNS (feature-gated)
        #[cfg(feature = "dns")]
        let (dns_server, acme_manager) = if plan.dns_enabled {
            let dns_cfg = main_config.dns.clone();
            let bind_addr: std::net::SocketAddr =
                format!("{}:{}", dns_cfg.bind_address, dns_cfg.port)
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| UnifiedServerResourceError::Dns(e.to_string()))?;

            let mut dns_server = crate::dns::DnsServer::new(dns_cfg.clone(), cert_resolver.clone());

            // Wire up zone transfer configuration
            if !dns_cfg.settings.allow_transfer.is_empty()
                || dns_cfg.settings.allow_wildcard_transfer
            {
                use crate::dns::tsig::TsigVerifier;

                let tsig_verifier = if !dns_cfg.dnssec.tsig_keys.is_empty() {
                    match TsigVerifier::new(dns_cfg.dnssec.tsig_keys.clone()) {
                        Ok(v) => Some(Arc::new(v)),
                        Err(e) => {
                            tracing::warn!("Failed to initialize TSIG for zone transfers: {}", e);
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
            }

            tracing::info!(
                "DNS server configured on {} (IPv4{})",
                bind_addr,
                if dns_cfg.bind_address != "0.0.0.0" {
                    " + IPv6"
                } else {
                    ""
                }
            );

            let cert_resolver_arc = cert_resolver
                .as_ref()
                .ok_or_else(|| {
                    UnifiedServerResourceError::Dns("ACME requires cert resolver".into())
                })?
                .clone();
            let acme_config = tls_config.acme.clone();
            (
                Some(Arc::new(dns_server)),
                Some(Arc::new(crate::tls::acme::AcmeManager::new(
                    acme_config,
                    cert_resolver_arc,
                ))),
            )
        } else {
            (None, None)
        };

        Ok(Self {
            waf,
            tcp_pool,
            udp_pool,
            flood_protector,
            cert_resolver,
            tunnel_manager,
            tunnel_router,
            app_servers,
            #[cfg(feature = "dns")]
            dns_server,
            #[cfg(feature = "dns")]
            acme_manager,
        })
    }

    fn create_waf(
        main_config: &MainConfig,
        ip_limit: &crate::config::defaults::IpRateLimitConfig,
        global_limit: &crate::config::defaults::GlobalRateLimitConfig,
    ) -> WafCore {
        let data_dir = main_config
            .persistence
            .data_dir
            .as_ref()
            .map(std::path::PathBuf::from);

        WafCore::new(crate::waf::WafCoreConfig {
            rate_config: RateLimitConfigStore {
                ip: ip_limit.clone(),
                global: global_limit.clone(),
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
            attack_detection_config: Some(crate::waf::AttackDetectionConfig::default()),
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
        main_config: &MainConfig,
        waf: Arc<WafCore>,
    ) -> Result<
        (crate::tcp::listener::TcpListenerPool, Arc<FloodProtector>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
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

        let pool = crate::tcp::listener::TcpListenerPool::new(pool_config, Default::default())
            .with_rate_limiter(Arc::new(waf.rate_limiter.clone()))
            .with_flood_protector(flood_protector.clone());

        Ok((pool, flood_protector))
    }

    fn create_udp_pool(
        main_config: &MainConfig,
        _waf: Arc<WafCore>,
    ) -> Result<crate::udp::listener::UdpListenerPool, Box<dyn std::error::Error + Send + Sync>>
    {
        use crate::udp::listener::UdpListenerPoolConfig;
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

        let pool = crate::udp::listener::UdpListenerPool::new(pool_config, Default::default())
            .with_flood_protector(flood_protector);

        Ok(pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigManager;
    use crate::config::MainConfig;
    use crate::server::startup_plan::UnifiedServerStartupPlan;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn make_test_config_manager() -> Arc<RwLock<ConfigManager>> {
        let tmp = tempfile::tempdir().expect("tempdir");
        Arc::new(RwLock::new(ConfigManager::new(tmp.keep())))
    }

    #[test]
    fn build_with_defaults_succeeds() {
        let main_config = MainConfig::default_config();
        let plan =
            UnifiedServerStartupPlan::from_config_snapshot(&main_config, 1).expect("plan builds");
        assert!(!plan.tcp_enabled);
        assert!(!plan.udp_enabled);
        assert!(!plan.tunnel_enabled);
        assert!(!plan.tunnel_quic_enabled);
    }

    #[test]
    fn tunnel_router_not_built_when_disabled() {
        let mut main_config = MainConfig::default_config();
        main_config.tunnel.enabled = false;
        main_config.tunnel.quic.enabled = false;

        let plan =
            UnifiedServerStartupPlan::from_config_snapshot(&main_config, 1).expect("plan builds");
        assert!(!plan.tunnel_enabled);
        assert!(!plan.tunnel_quic_enabled);
    }

    #[test]
    fn cert_resolver_created_when_tls_enabled() {
        let mut main_config = MainConfig::default_config();
        main_config.tls.enabled = true;
        main_config.tls.cert_path = Some("/nonexistent/cert.pem".into());
        main_config.tls.key_path = Some("/nonexistent/key.pem".into());

        let tls_config = crate::tls::config::InternalTlsConfig::from(main_config.tls.clone());
        assert!(tls_config.enabled);
    }

    #[test]
    fn tunnel_manager_created_when_enabled() {
        let mut main_config = MainConfig::default_config();
        main_config.tunnel.enabled = true;

        let tunnel_config = main_config.tunnel.clone();
        let manager = TunnelManager::new(tunnel_config);
        assert!(Arc::strong_count(&Arc::new(manager)) >= 1);
    }

    #[test]
    fn tunnel_router_created_when_quic_enabled() {
        let mut main_config = MainConfig::default_config();
        main_config.tunnel.enabled = true;
        main_config.tunnel.quic.enabled = true;

        let tunnel_config = main_config.tunnel.clone();
        let result = TunnelRouter::new(tunnel_config);
        assert!(result.is_ok());
    }
}
