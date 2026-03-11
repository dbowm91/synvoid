pub mod lookup;
pub mod types;
pub mod updater;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::geoip::GeoIpConfig;
use crate::config::site::SiteGeoipConfig;
use parking_lot::RwLock;
use tokio::time::{interval, Duration};

use lookup::GeoIpLookup;
use types::{AsnInfo, CountryInfo, GeoIpResult, GeoIpStatus};
use updater::GeoIpUpdater;

pub struct GeoIpManager {
    config: Arc<GeoIpConfig>,
    lookup: Arc<RwLock<GeoIpLookup>>,
    updater: Arc<GeoIpUpdater>,
    blocked_countries: Arc<RwLock<HashSet<String>>>,
    allowed_countries: Arc<RwLock<HashSet<String>>>,
    last_update: Arc<RwLock<Option<u64>>>,
    is_enabled: bool,
}

impl std::fmt::Debug for GeoIpManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIpManager")
            .field("is_enabled", &self.is_enabled)
            .field("blocked_countries", &self.blocked_countries)
            .field("allowed_countries", &self.allowed_countries)
            .finish()
    }
}

impl GeoIpManager {
    pub fn new(config: GeoIpConfig, site_configs: &[SiteGeoipConfig]) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let lookup = match &config.database_path {
            Some(path) => match GeoIpLookup::new(path) {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!("Failed to load GeoIP database: {}", e);
                    return None;
                }
            },
            None => GeoIpLookup::new("").unwrap_or_else(|_| GeoIpLookup::new("").unwrap()),
        };

        let mut blocked: HashSet<String> = config
            .block_countries
            .iter()
            .map(|s| s.to_uppercase())
            .collect();
        let mut allowed: HashSet<String> = config
            .allow_countries
            .iter()
            .map(|s| s.to_uppercase())
            .collect();

        for site_config in site_configs {
            if site_config.enabled {
                if !site_config.allowed_countries.is_empty() {
                    for c in &site_config.allowed_countries {
                        allowed.insert(c.to_uppercase());
                    }
                }
                if !site_config.blocked_countries.is_empty() {
                    for c in &site_config.blocked_countries {
                        blocked.insert(c.to_uppercase());
                    }
                }
            }
        }

        let updater = GeoIpUpdater::new(
            config.update_url.clone().unwrap_or_default(),
            config.database_path.clone().unwrap_or_default(),
            config.update_interval_hours as u64 * 3600,
        );

        Some(Self {
            config: Arc::new(config),
            lookup: Arc::new(RwLock::new(lookup)),
            updater: Arc::new(updater),
            blocked_countries: Arc::new(RwLock::new(blocked)),
            allowed_countries: Arc::new(RwLock::new(allowed)),
            last_update: Arc::new(RwLock::new(None)),
            is_enabled: true,
        })
    }

    pub fn check_ip(&self, ip: IpAddr) -> GeoIpResult {
        if !self.is_enabled {
            return GeoIpResult::Neutral;
        }

        let country_code = {
            let lookup = self.lookup.read();
            lookup.lookup_country(ip)
        };

        let allowed = self.allowed_countries.read();
        if !allowed.is_empty() {
            if let Some(ref code) = country_code {
                if allowed.contains(code) {
                    return GeoIpResult::Allowed;
                } else {
                    return GeoIpResult::Blocked;
                }
            }
            return GeoIpResult::Neutral;
        }

        let blocked = self.blocked_countries.read();
        if let Some(ref code) = country_code {
            if blocked.contains(code) {
                return GeoIpResult::Blocked;
            }
        }

        GeoIpResult::Neutral
    }

    pub async fn start_auto_update(&self) {
        if !self.config.update_enabled || self.config.update_url.is_none() {
            return;
        }

        let updater = self.updater.clone();
        let last_update = self.last_update.clone();
        let interval_secs = self.config.update_interval_hours as u64 * 3600;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                match updater.update().await {
                    Ok(_) => {
                        *last_update.write() = Some(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        );
                        tracing::info!("GeoIP database updated successfully");
                    }
                    Err(e) => {
                        tracing::warn!("Failed to update GeoIP database: {}", e);
                    }
                }
            }
        });
    }

    pub fn status(&self) -> GeoIpStatus {
        GeoIpStatus {
            enabled: self.is_enabled,
            database_loaded: self.lookup.read().is_loaded(),
            database_path: self.config.database_path.clone(),
            blocked_countries_count: self.blocked_countries.read().len(),
            allowed_countries_count: self.allowed_countries.read().len(),
            last_update: *self.last_update.read(),
        }
    }

    pub fn get_country_info(&self, ip: IpAddr) -> Option<CountryInfo> {
        let lookup = self.lookup.read();
        
        let code = lookup.lookup_country(ip)?;
        let info = lookup.lookup_country_info(ip)?;
        
        Some(CountryInfo {
            code,
            name: info.name,
            subdivision: lookup.lookup_subdivision(ip),
            city: lookup.lookup_city(ip),
        })
    }

    pub fn get_asn_info(&self, ip: IpAddr) -> Option<AsnInfo> {
        let lookup = self.lookup.read();
        lookup.lookup_asn(ip).map(|(asn, org)| AsnInfo {
            asn,
            organization: org,
        })
    }

    pub fn get_continent_code(&self, ip: IpAddr) -> Option<String> {
        let lookup = self.lookup.read();
        
        let reader = lookup.reader.as_ref()?;
        let result = reader.lookup(ip).ok()?;
        
        let code: Option<String> = result.decode_path(&[
            maxminddb::PathElement::Key("continent"),
            maxminddb::PathElement::Key("code"),
        ])
        .ok()
        .flatten();
        
        code
    }
}
