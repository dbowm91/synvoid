pub mod lookup;
pub mod types;
pub mod updater;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::admin::alerting::AlertManager;
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
    alert_manager: Option<Arc<AlertManager>>,
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
    pub fn new(
        config: GeoIpConfig,
        site_configs: &[SiteGeoipConfig],
        alert_manager: Option<Arc<AlertManager>>,
    ) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let lookup = match &config.database_path {
            Some(path) => match GeoIpLookup::new(path) {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!("Failed to load GeoIP database: {}", e);
                    GeoIpLookup::new("").unwrap_or_else(|_| GeoIpLookup::new("").unwrap())
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

        let updater = GeoIpUpdater::new(&config);

        Some(Self {
            config: Arc::new(config),
            lookup: Arc::new(RwLock::new(lookup)),
            updater: Arc::new(updater),
            blocked_countries: Arc::new(RwLock::new(blocked)),
            allowed_countries: Arc::new(RwLock::new(allowed)),
            last_update: Arc::new(RwLock::new(None)),
            alert_manager,
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
        if !self.config.update_enabled {
            return;
        }

        let updater = self.updater.clone();
        let lookup = self.lookup.clone();
        let last_update = self.last_update.clone();
        let stale_threshold_days = self.config.stale_threshold_days;
        let interval_secs = self.config.update_interval_hours as u64 * 3600;
        let alert_manager = self.alert_manager.clone();
        let editions: Vec<String> = self.updater.editions().iter().map(|e| e.edition_id.clone()).collect();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_secs));

            loop {
                interval.tick().await;

                match updater.update().await {
                    Ok(updated) if !updated.is_empty() => {
                        for edition_id in &updated {
                            if let Ok(data) = updater.load_database(edition_id).await {
                                let mut geoip_lookup = lookup.write();
                                if let Err(e) = geoip_lookup.reload_from_slice(data) {
                                    tracing::error!("Failed to reload {}: {}", edition_id, e);
                                }
                            }
                        }

                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        *last_update.write() = Some(now);
                        tracing::info!("GeoIP databases updated: {:?}", updated);
                    }
                    Ok(_) => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        *last_update.write() = Some(now);
                    }
                    Err(e) => {
                        tracing::warn!("GeoIP update failed: {}", e);

                        let days_since_update = {
                            if let Some(last) = *last_update.read() {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                (now - last) / (24 * 60 * 60)
                            } else {
                                u64::MAX
                            }
                        };

                        if days_since_update >= stale_threshold_days as u64 {
                            tracing::warn!(
                                "GeoIP database is {} days old (threshold: {} days)",
                                days_since_update, stale_threshold_days
                            );

                            if let Some(ref am) = alert_manager {
                                for edition_id in &editions {
                                    let am_clone = am.clone();
                                    let edition_clone = edition_id.clone();
                                    let days = days_since_update;
                                    tokio::spawn(async move {
                                        if let Err(e) = am_clone
                                            .send_geoip_stale_notification(&edition_clone, days)
                                            .await
                                        {
                                            tracing::debug!("Failed to send GeoIP stale notification: {}", e);
                                        }
                                    });
                                }
                            }
                        }
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

    pub fn updater(&self) -> &GeoIpUpdater {
        &self.updater
    }

    pub fn is_stale(&self) -> bool {
        let threshold = self.config.stale_threshold_days as u64 * 24 * 60 * 60;
        if let Some(last) = *self.last_update.read() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            return (now - last) > threshold;
        }
        true
    }

    pub fn days_since_update(&self) -> Option<u64> {
        self.last_update.read().map(|last| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            (now - last) / (24 * 60 * 60)
        })
    }
}
