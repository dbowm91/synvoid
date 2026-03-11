pub mod geoip;
pub mod main;
pub mod site;

pub use main::{
    BlocklistLimitsConfig as DenyListLimitsConfig, ConnectionLimitsConfig, DefaultsConfig,
    EndpointRateLimitConfig as MainEndpointRateLimitConfig, GlobalRateLimitConfig,
    GlobalTrafficShapingConfig, IpRateLimitConfig, MainConfig, ProxyLimitsConfig,
    RateLimitDefaults, RateLimitMemoryConfig, SiteTrafficShapingDefaults, SuspiciousWordsConfig,
    TarpitDefaults, TrafficShapingConfig, TrafficShapingDefaults, UpstreamErrorsConfig,
};
pub use site::{
    SiteBasicAuthConfig, SiteConfig, SiteCookieConfig, SiteCorsConfig, SiteGeoipConfig, SiteInfo,
    SiteProxyConfig, SiteSecurityConfig, SiteSecurityHeadersConfig, SiteTarpitConfig,
    SiteUpstreamConfig, SiteUpstreamTlsConfig, UpstreamConfig,
};

use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
                        self.sites.insert(site_id.clone(), config.clone());
                        results.push((site_id, Ok(config)));
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
