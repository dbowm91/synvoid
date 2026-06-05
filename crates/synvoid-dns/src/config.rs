use std::net::SocketAddr;
use std::sync::Arc;

use synvoid_config::dns::DnsConfig;
use synvoid_geoip::GeoIpManager;

pub struct DnsSettings {
    pub config: Arc<DnsConfig>,
    pub geoip: Option<Arc<GeoIpManager>>,
    pub bind_address: SocketAddr,
}

impl DnsSettings {
    pub fn new(config: DnsConfig, geoip: Option<Arc<GeoIpManager>>) -> Result<Self, String> {
        let bind_address: SocketAddr = format!("{}:{}", config.bind_address, config.port)
            .parse()
            .map_err(|e| format!("Invalid DNS bind address: {}", e))?;

        Ok(Self {
            config: Arc::new(config),
            geoip,
            bind_address,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn is_mesh_mode(&self) -> bool {
        self.config.mode == synvoid_config::dns::DnsMode::Mesh
    }

    pub fn default_ttl(&self) -> u32 {
        self.config.settings.default_ttl
    }

    pub fn min_geo_ttl(&self) -> u32 {
        self.config.settings.min_geo_ttl
    }
}
