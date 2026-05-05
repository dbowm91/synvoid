#![allow(
    clippy::collapsible_if,
    clippy::redundant_closure,
    clippy::manual_range_contains
)]

#[allow(unused_imports)]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[cfg(feature = "icmp-filter")]
use crate::icmp_filter::IcmpFilterConfig;

use super::admin::{AdminConfig, AdminCorsConfig, AdminRateLimitConfig, MetricsConfig};
use super::defaults::DefaultsConfig;
#[cfg(feature = "dns")]
use super::dns::DnsConfig;
use super::honeypot_port::HoneypotPortConfig;
use super::http::{Http3Config, HttpConfig, TokioConfig};
use super::limits::{BlocklistLimitsConfig, ProxyLimitsConfig, RateLimitMemoryConfig};
use super::logging::LoggingConfig;
use super::network::{TarpitDefaults, TcpDefaults, UdpDefaults};
use super::plugins::PluginConfig;
use super::process::{OverseerConfig, ProcessManagerConfig, SupervisorConfig};
use super::protection::{
    IpFeedConfig, MimesConfig, RuleFeedConfig, ThreatLevelConfig, YaraRuleFeedConfig,
};
use super::security::{MainSecurityConfig, MainStaticConfig};
use super::server::{FallbackConfig, ServerConfig};
use super::serverless::ServerlessConfig;
use super::tls::TlsConfig;
use super::traffic::TrafficShapingConfig;
use super::tunnel::TunnelConfig;
use super::upgrade::UpgradeConfig;
use super::validation::ConfigValidationError;

pub use super::defaults::{
    GlobalRateLimitConfig as MainGlobalRateLimitConfig,
    HoneypotProbingDefaults as MainHoneypotProbingDefaults,
    IpRateLimitConfig as MainIpRateLimitConfig, SuspiciousWordsConfig as MainSuspiciousWordsConfig,
    UpstreamErrorsConfig as MainUpstreamErrorsConfig, WorkerPoolDefaults as MainWorkerPoolDefaults,
};
pub use super::http::{
    Http3Config as MainHttp3Config, HttpConfig as MainHttpConfig, TokioConfig as MainTokioConfig,
};
pub use super::process::{
    OverseerConfig as MainOverseerConfig, ProcessManagerConfig as MainProcessManagerConfig,
    SupervisorConfig as MainSupervisorConfig,
};
pub use super::protection::{
    IpFeedConfig as MainIpFeedConfig, RuleFeedConfig as MainRuleFeedConfig,
    ThreatLevelConfig as MainThreatLevelConfig, ThreatLevelEscalation,
    YaraRuleFeedConfig as MainYaraRuleFeedConfig,
};
pub use super::server::{FallbackConfig as MainFallbackConfig, ServerConfig as MainServerConfig};
pub use super::serverless::ServerlessConfig as MainServerlessConfig;
pub use super::tls::{
    AcmeConfig as MainAcmeConfig, ClientAuthConfig as MainClientAuthConfig,
    TlsConfig as MainTlsConfig,
};
pub use super::traffic::{
    ConnectionLimitsConfig as MainConnectionLimitsConfig,
    TrafficShapingConfig as MainTrafficShapingConfig,
    TrafficShapingDefaults as MainTrafficShapingDefaults,
};
pub use super::tunnel::{
    PortMappingConfig as MainPortMappingConfig, TunnelConfig as MainTunnelConfig,
    TunnelQuicClientConfig as MainTunnelQuicClientConfig, TunnelQuicConfig as MainTunnelQuicConfig,
    TunnelQuicPeerConfig as MainTunnelQuicPeerConfig, TunnelVpnConfig as MainTunnelVpnConfig,
    VpnAccessLevel as MainVpnAccessLevel, WireGuardPeerConfig as MainWireGuardPeerConfig,
};

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct MainConfig {
    pub server: ServerConfig,
    pub fallback: FallbackConfig,
    pub admin: AdminConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub tokio: TokioConfig,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub http3: Http3Config,
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub threat_level: ThreatLevelConfig,
    #[serde(default)]
    pub ip_feeds: IpFeedConfig,
    #[serde(default)]
    pub rule_feed: RuleFeedConfig,
    #[serde(default)]
    pub yara_feed: YaraRuleFeedConfig,
    #[serde(default)]
    pub rate_limit_memory: RateLimitMemoryConfig,
    #[serde(default)]
    pub proxy_limits: ProxyLimitsConfig,
    #[serde(default)]
    pub blocklist_limits: BlocklistLimitsConfig,
    #[serde(default)]
    pub tcp: TcpDefaults,
    #[serde(default)]
    pub udp: UdpDefaults,
    #[serde(default)]
    pub tarpit: TarpitDefaults,
    #[serde(default)]
    pub persistence: super::defaults::PersistenceConfig,
    #[serde(default)]
    pub traffic_shaping: TrafficShapingConfig,
    #[serde(default)]
    pub security: MainSecurityConfig,
    #[serde(default)]
    pub static_config: Option<MainStaticConfig>,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    #[serde(default)]
    pub plugins: PluginConfig,
    #[serde(default)]
    pub serverless: ServerlessConfig,
    #[serde(default)]
    pub upgrade: Option<UpgradeConfig>,
    #[cfg(feature = "icmp-filter")]
    #[serde(default)]
    pub icmp_filter: IcmpFilterConfig,
    #[serde(default)]
    pub mimes: MimesConfig,
    #[cfg(feature = "dns")]
    #[serde(default)]
    pub dns: DnsConfig,
    #[cfg(feature = "mesh")]
    #[serde(default)]
    pub mesh: Option<super::MeshConfig>,
    #[serde(default)]
    pub overseer: OverseerConfig,
    #[serde(default)]
    pub process_manager: ProcessManagerConfig,
    #[serde(default)]
    pub supervisor: SupervisorConfig,
    #[serde(default)]
    pub honeypot_port: HoneypotPortConfig,
}

impl MainConfig {
    pub fn from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = std::fs::read_to_string(path)?;
        let mut config: MainConfig = toml::from_str(&content)?;

        if config.admin.token.is_empty() || config.admin.token == "changeme" {
            config.admin.token = config.admin.resolve_token();
        }

        if config.security.ipc_enforce_signing {
            if config.security.ipc_session_key_env.is_none() {
                tracing::warn!(
                    "IPC signing enforcement enabled but no session key configured. \
                    Set security.ipc_session_key_env or security.ipc_session_key in config. \
                    Generating ephemeral key (workers will not be able to reconnect after restart)."
                );
            }
        }

        #[cfg(feature = "mesh")]
        // Load global node keys and node identity if mesh is configured
        if let Some(ref mut mesh_config) = config.tunnel.mesh {
            if let Err(e) = mesh_config.load_global_node_keys() {
                tracing::warn!("Failed to load global node keys: {}", e);
            }
            if let Err(e) = mesh_config.load_node_identity() {
                tracing::warn!("Failed to load node identity: {}", e);
            }
        }

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        self.server.validate()?;
        self.http.validate()?;
        self.tls.validate()?;
        self.threat_level.validate()?;
        self.fallback.validate()?;
        self.logging.validate()?;
        self.admin.validate()?;
        self.defaults.validate()?;
        self.tunnel.validate()?;

        #[cfg(feature = "dns")]
        if self.dns.enabled && !cfg!(feature = "dns") {
            return Err(ConfigValidationError {
                field: "dns.enabled".to_string(),
                message: "DNS server configured but binary built without `dns` feature. Rebuild with `--features dns`.".to_string(),
            });
        }

        #[cfg(feature = "mesh")]
        if self.mesh.is_some() && !cfg!(feature = "mesh") {
            return Err(ConfigValidationError {
                field: "mesh".to_string(),
                message: "Mesh configured but binary built without `mesh` feature. Rebuild with `--features mesh`.".to_string(),
            });
        }

        Ok(())
    }

    pub fn default_config() -> Self {
        MainConfig {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                host_v6: None,
                trusted_proxies: vec!["127.0.0.1".to_string(), "::1".to_string()],
            },
            fallback: FallbackConfig {
                mode: "return_404".to_string(),
                upstream: None,
            },
            admin: AdminConfig {
                enabled: true,
                port: 8081,
                bind_address: "127.0.0.1".to_string(),
                token: String::new(),
                token_env_var: Some("SYNVOID_ADMIN_TOKEN".to_string()),
                bcrypt_cost: 12,
                cors: AdminCorsConfig::default(),
                rate_limit: AdminRateLimitConfig::default(),
                trusted_proxies: Vec::new(),
            },
            logging: LoggingConfig::default(),
            metrics: MetricsConfig {
                enabled: true,
                port: 9090,
            },
            tokio: TokioConfig::default(),
            http: HttpConfig::default(),
            tls: TlsConfig::default(),
            http3: Http3Config::default(),
            threat_level: ThreatLevelConfig::default(),
            ip_feeds: IpFeedConfig::default(),
            rule_feed: RuleFeedConfig::default(),
            yara_feed: YaraRuleFeedConfig::default(),
            defaults: DefaultsConfig::default(),
            rate_limit_memory: RateLimitMemoryConfig::default(),
            proxy_limits: ProxyLimitsConfig::default(),
            blocklist_limits: BlocklistLimitsConfig::default(),
            tcp: TcpDefaults::default(),
            udp: UdpDefaults::default(),
            tarpit: TarpitDefaults::default(),
            persistence: super::defaults::PersistenceConfig::default(),
            traffic_shaping: TrafficShapingConfig::default(),
            security: MainSecurityConfig::default(),
            static_config: None,
            tunnel: TunnelConfig::default(),
            plugins: PluginConfig::default(),
            serverless: ServerlessConfig::default(),
            upgrade: None,
            #[cfg(feature = "icmp-filter")]
            icmp_filter: IcmpFilterConfig::default(),
            mimes: MimesConfig::default(),
            #[cfg(feature = "dns")]
            dns: DnsConfig::default(),
            #[cfg(feature = "mesh")]
            mesh: None,
            overseer: super::OverseerConfig::default(),
            process_manager: super::ProcessManagerConfig::default(),
            supervisor: super::SupervisorConfig::default(),
            honeypot_port: HoneypotPortConfig::default(),
        }
    }
}

impl Default for MainConfig {
    fn default() -> Self {
        Self::default_config()
    }
}
