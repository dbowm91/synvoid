#![allow(unused_mut)]

pub mod admin;
pub mod defaults;
#[cfg(feature = "dns")]
pub mod dns;
pub mod geoip;
pub mod http;
pub mod limits;
pub mod logging;
pub mod main;
pub mod mesh;
pub mod network;
pub mod plugins;
pub mod protection;
pub mod security;
pub mod server;
pub mod site;
pub mod tls;
pub mod traffic;
pub mod tunnel;
pub mod upgrade;
pub mod upload;
pub mod validation;

pub use admin::{AdminConfig, AdminCorsConfig, MetricsConfig};
pub use defaults::{
    AuthDefaults, BlockedDefaults, BotDefaults, CssBlockDefaults, CssChallengeDefaults,
    DefaultsConfig, EndpointRateLimitConfig, ErrorPagesDefaults, GlobalRateLimitConfig,
    HoneypotBlockDefaults, HoneypotDefaults, HoneypotProbingDefaults, IpRateLimitConfig,
    PersistenceConfig, PowBlockDefaults, PowChallengeDefaults, RateLimitDefaults,
    SuspiciousWordsConfig, UpstreamErrorsConfig, WorkerPoolDefaults,
};
#[cfg(feature = "dns")]
pub use dns::{
    DnsConfig, DnsMeshConfig, DnsMode, DnsRateLimitConfig, DnsRateLimitMode, DnsRecordEntry,
    DnsRecordType, DnsSecAlgorithm, DnsSecConfig, DnsSettingsConfig, DnsZoneEntry, DnsZonesConfig,
    QnameLogLevel, QnamePrivacyConfig, QnamePrivacyMode,
};

pub use defaults::{
    GlobalRateLimitConfig as MainGlobalRateLimitConfig, IpRateLimitConfig as MainIpRateLimitConfig,
};
pub use http::{Http3Config, HttpConfig, TokioConfig};
pub use limits::{
    BlocklistLimitsConfig as DenyListLimitsConfig, ProxyLimitsConfig, RateLimitMemoryConfig,
};
pub use logging::{
    ElasticsearchConfig, LogExporterConfig, LoggingConfig, LokiConfig, RequestBodyLoggingConfig,
};
pub use main::MainConfig;
pub use network::{
    TarpitDefaults, TcpDefaults, TcpProtocolConfig, TcpSocketConfig, UdpDefaults,
    UdpProtocolConfig, UdpSocketConfig,
};
pub use plugins::{PluginConfig, WasmPluginGlobalConfig, WasmPluginInstanceConfig};
pub use protection::{
    IpFeedConfig, MimesConfig, RuleFeedConfig, ThreatLevelBanDurations, ThreatLevelConfig,
    ThreatLevelEscalation, ThreatLevelGlobalLimits, YaraRuleFeedConfig,
};
pub use security::{MainSecurityConfig, MainStaticConfig};
pub use server::{FallbackConfig, ServerConfig};
pub use tls::{AcmeConfig, ClientAuthConfig, TlsConfig};
pub use traffic::{
    ConnectionLimitsConfig, GlobalTrafficShapingConfig, SiteConnectionDefaults,
    SiteTrafficShapingDefaults, TrafficShapingConfig, TrafficShapingDefaults,
};
pub use tunnel::{
    PortMappingConfig, QuicVpnAccessConfig, QuicVpnClientConfig, TunnelConfig,
    TunnelQuicClientConfig, TunnelQuicConfig, TunnelQuicPeerConfig, TunnelQuicServerConfig,
    TunnelVpnConfig, VpnAccessLevel, WireGuardPeerConfig,
};
pub use upgrade::UpgradeConfig;
pub use upload::{UploadAllowedTypesDefaults, UploadDefaults};
pub use validation::{parse_size_string, ConfigValidationError};

pub use mesh::{
    MeshConfig, MeshLocalUpstream, MeshNodeRole, MeshPeerConfig, MeshRoutingConfig, MeshSeedNode,
    MeshServicePolicy, MeshTlsConfig, MeshUpstreamConfig, MeshUpstreamPeer,
};
pub use site::{
    SiteBasicAuthConfig, SiteConfig, SiteCookieConfig, SiteCorsConfig, SiteGeoipConfig, SiteInfo,
    SiteProxyConfig, SiteSecurityConfig, SiteSecurityHeadersConfig, SiteTarpitConfig,
    SiteUpstreamConfig, SiteUpstreamTlsConfig, UpstreamConfig,
};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub type ConfigHandle = Arc<MainConfig>;

pub struct ConfigManager {
    pub main: MainConfig,
    pub sites: HashMap<String, SiteConfig>,
    pub sites_dir: PathBuf,
}

impl ConfigManager {
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            main: MainConfig::default_config(),
            sites: HashMap::new(),
            sites_dir: config_dir.join("sites"),
        }
    }

    pub fn load_main<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        self.main = MainConfig::from_file(path)?;
        Ok(())
    }

    pub fn load_site<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let config = SiteConfig::from_file(&path)?;
        let site_id = config.site_id();
        self.sites.insert(site_id.clone(), config);
        Ok(site_id)
    }

    pub fn discover_sites(&mut self) -> Vec<(String, Result<SiteConfig, String>)> {
        let mut results = Vec::new();

        if !self.sites_dir.exists() {
            if let Err(e) = std::fs::create_dir_all(&self.sites_dir) {
                tracing::warn!("Could not create sites directory: {}", e);
            }
            return results;
        }

        let entries = match std::fs::read_dir(&self.sites_dir) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!("Could not read sites directory: {}", e);
                return results;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "toml").unwrap_or(false) {
                let filename = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                match SiteConfig::from_file(&path) {
                    Ok(config) => {
                        let site_id = config.site_id();
                        let config_for_results = config.clone();
                        self.sites.insert(site_id.clone(), config);
                        results.push((site_id, Ok(config_for_results)));
                        tracing::info!("Loaded site config: {}", filename);
                    }
                    Err(e) => {
                        let error_msg = format!("Failed to load {}: {}", filename, e);
                        tracing::warn!("{}", error_msg);
                        results.push((filename, Err(error_msg)));
                    }
                }
            }
        }

        results
    }

    pub fn get_site(&self, domain: &str) -> Option<&SiteConfig> {
        self.sites.get(domain)
    }

    pub fn reload_site(&mut self, domain: &str) -> Result<(), String> {
        if let Some(config) = self.sites.get(domain) {
            let domains = config.site.domains.clone();
            let filename = domains.first().map(|s| s.as_str()).unwrap_or("unknown");

            let path = self.sites_dir.join(format!("{}.toml", filename));
            if path.exists() {
                match SiteConfig::from_file(&path) {
                    Ok(new_config) => {
                        self.sites.insert(domain.to_string(), new_config);
                        tracing::info!("Reloaded site: {}", domain);
                        Ok(())
                    }
                    Err(e) => Err(format!("Failed to reload site {}: {}", domain, e)),
                }
            } else {
                Err(format!("Site config file not found for {}", domain))
            }
        } else {
            Err(format!("Site {} not found", domain))
        }
    }

    pub fn reload_all(&mut self) -> Vec<(String, Result<(), String>)> {
        let mut results = Vec::new();
        let domains: Vec<String> = self.sites.keys().cloned().collect();

        for domain in domains {
            let result = self.reload_site(&domain).map_err(|e| e);
            results.push((domain, result));
        }

        results
    }
}
