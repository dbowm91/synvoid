//! Configuration types and defaults for SynVoid.
//!
//! Provides strongly-typed configuration structs for all subsystems
//! including site configs, DNS, mesh, admin, and TLS settings.

pub mod admin;
pub mod app_server;
pub mod bandwidth;
pub mod defaults;
pub mod dns;
pub mod geoip;
pub mod honeypot_port;
pub mod http;
pub mod icmp_filter;
pub mod limits;
pub mod logging;
pub mod main_config;
pub mod mesh;
pub mod network;
pub mod plugins;
pub mod process;
pub mod protection;
pub mod security;
pub mod server;
pub mod serverless;
pub mod site;
pub mod theme;
pub mod tls;
pub mod traffic;
pub mod tunnel;
pub mod upgrade;
pub mod upload;
pub mod validation;

pub use admin::{AdminConfig, AdminCorsConfig, MetricsConfig};
pub use app_server::{AppServerConfig, GranianInterface, GranianLogFormat, GranianLogLevel};
pub use bandwidth::{MonthlyResetConfig, MonthlyResetMode};
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
pub use theme::{
    ThemeBranding, ThemeColors, ThemeConfig, ThemeDefaults, ThemeEffects, ThemeMode, ThemePreset,
    ThemeRestriction, ThemeSpacing,
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
pub use main_config::MainConfig;
pub use network::{
    TarpitDefaults, TcpDefaults, TcpProtocolConfig, TcpSocketConfig, UdpDefaults,
    UdpProtocolConfig, UdpSocketConfig,
};
pub use plugins::{PluginConfig, WasmPluginGlobalConfig, WasmPluginInstanceConfig};
pub use process::{
    OverseerConfig, ProcessManagerConfig, SupervisorConfig, SupervisorConfigBuilder,
};
pub use protection::{
    IpFeedConfig, MimesConfig, RuleFeedConfig, ThreatIntelligenceConfig, ThreatLevelBanDurations,
    ThreatLevelConfig, ThreatLevelEscalation, ThreatLevelGlobalLimits, YaraRuleFeedConfig,
    YaraRulesMeshConfig,
};
pub use security::{MainSecurityConfig, MainStaticConfig};
pub use server::{FallbackConfig, ServerConfig};
pub use serverless::{FunctionDefinition, ServerlessConfig};
pub use tls::{AcmeChallengeType, AcmeConfig, ClientAuthConfig, TlsConfig};
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
    pub config_dir: PathBuf,
    site_filenames: HashMap<String, PathBuf>,
}

impl ConfigManager {
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            main: MainConfig::default_config(),
            sites: HashMap::new(),
            sites_dir: config_dir.join("sites"),
            config_dir,
            site_filenames: HashMap::new(),
        }
    }

    pub fn load_main<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.main = MainConfig::from_file(path)?;
        Ok(())
    }

    pub fn load_site<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let config = SiteConfig::from_file(&path)?;
        let site_id = config.site_id();
        self.sites.insert(site_id.clone(), config);
        self.site_filenames
            .insert(site_id.clone(), path.as_ref().to_path_buf());
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
                        self.site_filenames.insert(site_id.clone(), path.clone());
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
        self.sites
            .values()
            .find(|site| site.site.domains.iter().any(|d| d == domain))
    }

    pub fn reload_site(&mut self, domain: &str) -> Result<(), String> {
        if let Some(site) = self.sites.get(domain) {
            let site_id = site.site_id();
            let path =
                self.site_filenames.get(&site_id).cloned().ok_or_else(|| {
                    format!("No filename found for site {}, cannot reload", domain)
                })?;

            if path.exists() {
                match SiteConfig::from_file(&path) {
                    Ok(new_config) => {
                        self.sites.insert(site_id.clone(), new_config);
                        tracing::info!("Reloaded site: {}", site_id);
                        Ok(())
                    }
                    Err(e) => Err(format!("Failed to reload site {}: {}", site_id, e)),
                }
            } else {
                Err(format!("Site config file not found at {}", path.display()))
            }
        } else {
            Err(format!("Site {} not found", domain))
        }
    }

    pub fn reload_all(&mut self) -> Vec<(String, Result<(), String>)> {
        let mut results = Vec::new();
        let domains: Vec<String> = self.sites.keys().cloned().collect();

        for domain in domains {
            let result = self.reload_site(&domain);
            results.push((domain, result));
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SITE_TOML: &str = r#"
[site]
domains = ["example.com"]

[site.upstream]
default = "http://localhost:3000"

[[site.listen]]
port = 8080
"#;

    const VALID_SITE_TOML_2: &str = r#"
[site]
domains = ["other.com"]

[site.upstream]
default = "http://localhost:3001"

[[site.listen]]
port = 8081
"#;

    const INVALID_SITE_TOML: &str = r#"
[site]
domains = []

[site.upstream]
default = "http://localhost:3000"
"#;

    #[test]
    fn test_config_manager_new() {
        let dir = tempfile::TempDir::new().unwrap();
        let manager = ConfigManager::new(dir.path().to_path_buf());
        assert!(manager.sites.is_empty());
        assert_eq!(manager.config_dir, dir.path());
    }

    #[test]
    fn test_discover_sites_empty_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut manager = ConfigManager::new(dir.path().to_path_buf());
        let results = manager.discover_sites();
        assert!(results.is_empty());
        // Sites dir should have been created
        assert!(dir.path().join("sites").exists());
    }

    #[test]
    fn test_discover_sites_with_configs() {
        let dir = tempfile::TempDir::new().unwrap();
        let sites_dir = dir.path().join("sites");
        std::fs::create_dir_all(&sites_dir).unwrap();

        std::fs::write(sites_dir.join("example.com.toml"), VALID_SITE_TOML).unwrap();
        std::fs::write(sites_dir.join("other.com.toml"), VALID_SITE_TOML_2).unwrap();

        let mut manager = ConfigManager::new(dir.path().to_path_buf());
        let results = manager.discover_sites();

        assert_eq!(results.len(), 2);
        for (_, result) in &results {
            assert!(result.is_ok());
        }
        assert_eq!(manager.sites.len(), 2);
    }

    #[test]
    fn test_discover_sites_skips_non_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let sites_dir = dir.path().join("sites");
        std::fs::create_dir_all(&sites_dir).unwrap();

        std::fs::write(sites_dir.join("example.com.toml"), VALID_SITE_TOML).unwrap();
        std::fs::write(sites_dir.join("readme.txt"), "not a config").unwrap();
        std::fs::write(sites_dir.join(".DS_Store"), "").unwrap();

        let mut manager = ConfigManager::new(dir.path().to_path_buf());
        let results = manager.discover_sites();

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_discover_sites_invalid_config() {
        let dir = tempfile::TempDir::new().unwrap();
        let sites_dir = dir.path().join("sites");
        std::fs::create_dir_all(&sites_dir).unwrap();

        std::fs::write(sites_dir.join("bad.toml"), INVALID_SITE_TOML).unwrap();

        let mut manager = ConfigManager::new(dir.path().to_path_buf());
        let results = manager.discover_sites();

        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_err());
        assert!(manager.sites.is_empty());
    }

    #[test]
    fn test_load_site() {
        let dir = tempfile::TempDir::new().unwrap();
        let sites_dir = dir.path().join("sites");
        std::fs::create_dir_all(&sites_dir).unwrap();

        let site_path = sites_dir.join("example.com.toml");
        std::fs::write(&site_path, VALID_SITE_TOML).unwrap();

        let mut manager = ConfigManager::new(dir.path().to_path_buf());
        let site_id = manager.load_site(&site_path).unwrap();
        assert_eq!(site_id, "example.com");
        assert!(manager.get_site("example.com").is_some());
    }

    #[test]
    fn test_get_site_nonexistent() {
        let dir = tempfile::TempDir::new().unwrap();
        let manager = ConfigManager::new(dir.path().to_path_buf());
        assert!(manager.get_site("nonexistent.com").is_none());
    }

    #[test]
    fn test_reload_site() {
        let dir = tempfile::TempDir::new().unwrap();
        let sites_dir = dir.path().join("sites");
        std::fs::create_dir_all(&sites_dir).unwrap();

        std::fs::write(sites_dir.join("example.com.toml"), VALID_SITE_TOML).unwrap();

        let mut manager = ConfigManager::new(dir.path().to_path_buf());
        manager.discover_sites();

        let result = manager.reload_site("example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_reload_site_not_found() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut manager = ConfigManager::new(dir.path().to_path_buf());
        let result = manager.reload_site("nonexistent.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_reload_all() {
        let dir = tempfile::TempDir::new().unwrap();
        let sites_dir = dir.path().join("sites");
        std::fs::create_dir_all(&sites_dir).unwrap();

        std::fs::write(sites_dir.join("example.com.toml"), VALID_SITE_TOML).unwrap();
        std::fs::write(sites_dir.join("other.com.toml"), VALID_SITE_TOML_2).unwrap();

        let mut manager = ConfigManager::new(dir.path().to_path_buf());
        manager.discover_sites();

        let results = manager.reload_all();
        assert_eq!(results.len(), 2);
        for (_, result) in &results {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_site_config_from_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(&path, VALID_SITE_TOML).unwrap();

        let config = SiteConfig::from_file(&path).unwrap();
        assert_eq!(config.site.domains, vec!["example.com"]);
        assert_eq!(config.site.listen[0].port, Some(8080));
    }

    #[test]
    fn test_site_config_site_id() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(&path, VALID_SITE_TOML).unwrap();

        let config = SiteConfig::from_file(&path).unwrap();
        assert_eq!(config.site_id(), "example.com");
    }

    #[test]
    fn test_site_config_validation_empty_domains() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, INVALID_SITE_TOML).unwrap();

        let result = SiteConfig::from_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_site_config_from_file_not_found() {
        let result = SiteConfig::from_file("/nonexistent/path.toml");
        assert!(result.is_err());
    }
}
