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
use super::process::{ProcessManagerConfig, SupervisorConfig};
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
    ProcessManagerConfig as MainProcessManagerConfig,
    SupervisorConfig as MainSupervisorCompatConfig, SupervisorConfig as MainSupervisorConfig,
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
    #[serde(default)]
    #[cfg(feature = "dns")]
    pub dns: DnsConfig,
    #[cfg(feature = "mesh")]
    pub mesh: Option<super::MeshConfig>,
    #[serde(default)]
    pub supervisor_compat: SupervisorConfig,
    #[serde(default)]
    pub process_manager: ProcessManagerConfig,
    #[serde(default)]
    pub supervisor: SupervisorConfig,
    #[serde(default)]
    pub honeypot_port: HoneypotPortConfig,
}

impl MainConfig {
    /// Parse and validate a main config from a TOML string.
    ///
    /// In-memory seam shared by [`MainConfig::from_file`] and the
    /// `config_parse_validation` fuzz target: no filesystem reads, no socket
    /// creation, no child processes. Validation follows the exact production
    /// path, including admin-token validation (which may consult the
    /// `SYNVOID_ADMIN_TOKEN` environment variable or generate an ephemeral
    /// token, exactly as file loads do). Operator side-effects that require
    /// the filesystem (mesh key/identity loading) live in `from_file` only.
    pub fn from_toml_str(input: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config: MainConfig = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = std::fs::read_to_string(path)?;
        let mut config = Self::from_toml_str(&content)?;

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

        // Load global node keys and node identity if mesh is configured
        #[cfg(feature = "mesh")]
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
        {
            if self.dns.enabled && !cfg!(feature = "dns") {
                return Err(ConfigValidationError {
                    field: "dns.enabled".to_string(),
                    message: "DNS server configured but binary built without `dns` feature. Rebuild with `--features dns`.".to_string(),
                });
            }
            if self.dns.enabled {
                self.dns.validate()?;
            }
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
                secure_cookie: true,
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
            supervisor_compat: super::SupervisorConfig::default(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed strong token (40 hex chars, no weak patterns) so seam tests are
    /// deterministic regardless of the surrounding environment.
    const TEST_TOKEN: &str = "7f3a9c1e5b8d2f4a6c0e9b3d7f1a5c8e0d4b6";

    fn valid_toml() -> String {
        let mut cfg = MainConfig::default_config();
        cfg.admin.token = TEST_TOKEN.to_string();
        cfg.admin.token_env_var = None;
        toml::to_string(&cfg).expect("default config must serialize")
    }

    #[test]
    fn from_toml_str_rejects_garbage_without_panicking() {
        assert!(MainConfig::from_toml_str("").is_err());
        assert!(MainConfig::from_toml_str("\x00\x01\x02{{{").is_err());
        assert!(MainConfig::from_toml_str("[unclosed").is_err());
    }

    #[test]
    fn from_toml_str_rejects_invalid_values_with_typed_error() {
        // Structurally valid TOML, but the server host is not a valid IP.
        let mut cfg = MainConfig::default_config();
        cfg.admin.token = TEST_TOKEN.to_string();
        cfg.admin.token_env_var = None;
        let mut text = toml::to_string(&cfg).expect("default config must serialize");
        text = text.replacen("0.0.0.0", "not a host !!!", 1);
        let err = MainConfig::from_toml_str(&text).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn from_toml_str_accepts_valid_config() {
        let parsed = MainConfig::from_toml_str(&valid_toml()).expect("valid TOML must parse");
        assert_eq!(parsed.server.port, 8080);
    }

    #[test]
    fn from_file_delegates_to_toml_str_seam() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("main.toml");
        let text = valid_toml();
        std::fs::write(&path, &text).unwrap();
        let via_file = MainConfig::from_file(&path).expect("from_file must succeed");
        let via_str = MainConfig::from_toml_str(&text).expect("from_toml_str must succeed");
        assert_eq!(via_file.server.port, via_str.server.port);
    }
}
