#![allow(
    clippy::redundant_closure,
    clippy::manual_range_contains,
    clippy::collapsible_if
)]

use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::validation::ConfigValidationError;

mod app_server;
mod attack_detection;
mod backend;
mod defensive;
mod error_pages;
mod file_manager;
mod listen;
mod misc;
mod network;
mod protocol_features;
mod proxy;
mod ratelimit;
mod security;
mod static_files;
mod traffic_shaping;
mod upload;

pub use app_server::SiteAppServerConfig;
pub use attack_detection::{
    SiteAttackDetectionConfig, SitePathTraversalConfig, SiteRfiConfig, SiteSqliConfig,
    SiteSsrfConfig, SiteXssConfig,
};
pub use backend::{
    BackendConfig, CgiConfig, CgiLocationConfig, FastCgiConfig, FastCgiLocationConfig,
    HeaderOverride, LocationConfig, LocationProxyConfig, PhpConfig, PhpLocationConfig,
};
pub use defensive::{
    SiteBotConfig, SiteCssBlockConfig, SiteCssChallengeConfig, SiteProbeConfig, SiteTarpitConfig,
};
pub use error_pages::{SiteErrorPagesConfig, SiteThemeConfig};
pub use file_manager::SiteFileManagerConfig;
pub use listen::{SiteInfo, SiteListenConfig, UpstreamConfig};
pub use misc::{SiteImagePoisonConfig, SiteLoggingConfig, SiteWorkerPoolConfig};
pub use network::{
    SitePortConfig, SiteProtocolFilterConfig, SiteTcpConfig, SiteTunnelConfig, SiteUdpConfig,
    SiteUdpPortConfig,
};
pub use protocol_features::{SiteGrpcConfig, SiteWebSocketConfig};
pub use proxy::{
    BufferingConfig, ProxyCacheConfig, ProxyHeadersConfig, ProxyUpstreamConfig, RetryConfig,
    SiteProxyConfig, UpstreamTlsConfig, WasmOnError,
};
pub use ratelimit::{
    EndpointRateLimitConfig, GlobalRateLimitOverride, IpRateLimitOverride, SiteRateLimitConfig,
};
pub use security::{
    SiteAuthConfig, SiteBasicAuthConfig, SiteBlockedConfig, SiteCookieConfig, SiteCorsConfig,
    SiteGeoipConfig, SiteSecurityConfig, SiteSecurityHeadersConfig, SiteUpstreamConfig,
    SiteUpstreamTlsConfig, SiteWhitelistConfig,
};
pub use static_files::{SiteStaticConfig, SiteStaticThemeConfig, StaticLocation};
pub use traffic_shaping::{SiteTrafficConnectionConfig, SiteTrafficShapingConfig};
pub use upload::{SiteAllowedTypesConfig, SitePathUploadConfig, SiteUploadConfig};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteConfig {
    pub site: SiteInfo,
    #[serde(default)]
    pub ratelimit: SiteRateLimitConfig,
    #[serde(default)]
    pub blocked: SiteBlockedConfig,
    #[serde(default)]
    pub bot: SiteBotConfig,
    #[serde(default)]
    pub honeypot_probe: SiteProbeConfig,
    #[serde(default)]
    pub error_pages: SiteErrorPagesConfig,
    #[serde(default)]
    pub css_challenge: SiteCssChallengeConfig,
    #[serde(default)]
    pub whitelist: SiteWhitelistConfig,
    #[serde(default)]
    pub worker_pool: SiteWorkerPoolConfig,
    #[serde(default)]
    pub logging: SiteLoggingConfig,
    #[serde(default)]
    pub proxy: SiteProxyConfig,
    #[serde(default)]
    pub tcp: SiteTcpConfig,
    #[serde(default)]
    pub udp: SiteUdpConfig,
    #[serde(default)]
    pub tarpit: SiteTarpitConfig,
    #[serde(default)]
    pub attack_detection: SiteAttackDetectionConfig,
    #[serde(default)]
    pub upload: SiteUploadConfig,
    #[serde(default)]
    pub auth: SiteAuthConfig,
    #[serde(default)]
    pub r#static: SiteStaticConfig,
    #[serde(default)]
    pub security: SiteSecurityConfig,
    #[serde(default)]
    pub security_headers: SiteSecurityHeadersConfig,
    #[serde(default)]
    pub traffic_shaping: SiteTrafficShapingConfig,
    #[serde(default)]
    pub grpc: SiteGrpcConfig,
    #[serde(default)]
    pub websocket: SiteWebSocketConfig,
    #[serde(default)]
    pub tunnel: SiteTunnelConfig,

    #[serde(default)]
    pub app_server: SiteAppServerConfig,
    #[serde(default)]
    pub serverless: Option<super::serverless::ServerlessConfig>,
    #[serde(default)]
    pub image_poison: SiteImagePoisonConfig,
    #[serde(default)]
    pub file_manager: SiteFileManagerConfig,
}

impl SiteConfig {
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "Failed to read site config from {}",
                path.as_ref().display()
            )
        })?;
        let config: SiteConfig =
            toml::from_str(&content).context("Failed to parse site config TOML")?;

        if config.site.domains.is_empty() {
            anyhow::bail!("Site config must have at least one domain");
        }

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        self.site.validate()?;
        self.ratelimit.validate()?;
        self.attack_detection.validate()?;
        self.upload.validate()?;
        self.security_headers.validate()?;
        self.app_server.validate()?;
        self.grpc.validate()?;
        self.websocket.validate()?;
        self.file_manager.validate()?;
        Ok(())
    }

    pub fn site_id(&self) -> String {
        self.site.domains.first().cloned().unwrap_or_default()
    }

    pub fn app_server_config(&self) -> crate::app_server::AppServerConfig {
        let site_config = &self.app_server;

        crate::app_server::AppServerConfig {
            enabled: site_config.enabled.unwrap_or(false),
            app_path: site_config.app_path.clone().unwrap_or_default(),
            interface: site_config
                .interface
                .as_ref()
                .map(|s| crate::app_server::GranianInterface::from(s.as_str()))
                .unwrap_or(crate::app_server::GranianInterface::Asgi),
            workers: site_config.workers.unwrap_or(1),
            blocking_threads: site_config.blocking_threads.unwrap_or(4),
            socket_path: site_config
                .socket_path
                .as_ref()
                .map(std::path::PathBuf::from),
            port: site_config.port,
            host: site_config.host.clone(),
            python_path: site_config
                .python_path
                .as_ref()
                .map(std::path::PathBuf::from),
            working_directory: site_config
                .working_directory
                .as_ref()
                .map(std::path::PathBuf::from),
            env: site_config.env.clone().unwrap_or_default(),
            restart_on_failure: site_config.restart_on_failure.unwrap_or(true),
            max_restarts: site_config.max_restarts.unwrap_or(5),
            health_check_path: site_config
                .health_check_path
                .clone()
                .unwrap_or_else(|| "/".to_string()),
            health_check_interval_secs: site_config.health_check_interval_secs.unwrap_or(10),
            health_check_timeout_secs: site_config.health_check_timeout_secs.unwrap_or(5),
            auto_install_granian: site_config.auto_install_granian.unwrap_or(true),
            auto_detect_venv: site_config.auto_detect_venv.unwrap_or(true),
            auto_detect_app: site_config.auto_detect_app.unwrap_or(true),
            auto_install_requirements: site_config.auto_install_requirements.unwrap_or(true),
            log_level: site_config
                .log_level
                .as_ref()
                .map(|s| crate::app_server::GranianLogLevel::from(s.as_str()))
                .unwrap_or(crate::app_server::GranianLogLevel::Info),
            log_format: site_config
                .log_format
                .as_ref()
                .map(|s| crate::app_server::GranianLogFormat::from(s.as_str()))
                .unwrap_or(crate::app_server::GranianLogFormat::Text),
            log_verbose: site_config.log_verbose.unwrap_or(false),
        }
    }
}
