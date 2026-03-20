use std::time::Instant;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use super::node_id::NodeId;
use crate::geoip::lookup::GeoIpLookup;

mod serde_secs {
    use serde::{Deserializer, Serializer};
    use std::time::Instant;

    pub fn serialize<S>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let secs = instant.elapsed().as_secs();
        serializer.serialize_u64(secs)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = serde::Deserialize::deserialize(deserializer)?;
        Ok(Instant::now() - std::time::Duration::from_secs(secs))
    }

    pub fn serialize_opt<S>(instant: &Option<Instant>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match instant {
            Some(i) => {
                let secs = i.elapsed().as_secs();
                serializer.serialize_some(&secs)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize_opt<'de, D>(deserializer: D) -> Result<Option<Instant>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs: Option<u64> = serde::Deserialize::deserialize(deserializer)?;
        Ok(secs.map(|s| Instant::now() - std::time::Duration::from_secs(s)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub region: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

impl GeoInfo {
    pub fn new() -> Self {
        Self {
            country: None,
            region: None,
            latitude: None,
            longitude: None,
        }
    }

    pub fn with_coords(lat: f64, lon: f64) -> Self {
        Self {
            country: None,
            region: None,
            latitude: Some(lat),
            longitude: Some(lon),
        }
    }

    pub fn with_country(mut self, country: String) -> Self {
        self.country = Some(country);
        self
    }

    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    pub fn has_location(&self) -> bool {
        self.latitude.is_some() && self.longitude.is_some()
    }
}

impl Default for GeoInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl From<crate::geoip::lookup::GeoLocationInfo> for GeoInfo {
    fn from(info: crate::geoip::lookup::GeoLocationInfo) -> Self {
        Self {
            country: info.country,
            region: info.region,
            latitude: Some(info.latitude),
            longitude: Some(info.longitude),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerContact {
    pub node_id: NodeId,
    pub node_id_string: String,
    pub address: String,
    pub port: u16,
    pub geo: Option<GeoInfo>,
    pub latency_ms: Option<u32>,
    #[serde(with = "serde_secs")]
    pub last_seen: Instant,
    #[serde(skip)]
    pub last_pinged: Option<Instant>,
    #[serde(skip)]
    pub is_global: bool,
    #[serde(skip)]
    pub is_trusted: bool,
    #[serde(skip)]
    pub pow_nonce: Option<u64>,
    #[serde(skip)]
    pub public_key: Option<Vec<u8>>,
}

impl PeerContact {
    pub fn new(node_id: NodeId, node_id_string: String, address: String, port: u16) -> Self {
        Self {
            node_id,
            node_id_string,
            address,
            port,
            geo: None,
            latency_ms: None,
            last_seen: Instant::now(),
            last_pinged: None,
            is_global: false,
            is_trusted: false,
            pow_nonce: None,
            public_key: None,
        }
    }

    pub fn with_geo(mut self, geo: GeoInfo) -> Self {
        self.geo = Some(geo);
        self
    }

    pub fn with_latency(mut self, latency_ms: u32) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    pub fn with_global(mut self, is_global: bool) -> Self {
        self.is_global = is_global;
        self
    }

    pub fn with_trusted(mut self, is_trusted: bool) -> Self {
        self.is_trusted = is_trusted;
        self
    }

    pub fn with_pow(mut self, nonce: u64, public_key: Vec<u8>) -> Self {
        self.pow_nonce = Some(nonce);
        self.public_key = Some(public_key);
        self
    }

    pub fn verify_pow(&self) -> bool {
        if self.is_global || self.is_trusted {
            return true;
        }

        match (self.pow_nonce, &self.public_key) {
            (Some(nonce), Some(pk)) => self.node_id.verify_pow(pk, nonce),
            _ => false,
        }
    }

    pub fn requires_pow(&self) -> bool {
        !self.is_global && !self.is_trusted
    }

    pub fn mark_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn mark_pinged(&mut self) {
        self.last_pinged = Some(Instant::now());
    }

    pub fn is_stale(&self, duration: std::time::Duration) -> bool {
        self.last_seen.elapsed() > duration
    }

    pub fn geo_score(&self, target: &GeoInfo) -> f64 {
        match (&self.geo, &target.latitude, &target.longitude) {
            (Some(peer_geo), Some(target_lat), Some(target_lon)) => {
                if let (Some(peer_lat), Some(peer_lon)) = (peer_geo.latitude, peer_geo.longitude) {
                    let distance =
                        Self::great_circle_distance(peer_lat, peer_lon, *target_lat, *target_lon);
                    1.0 / (1.0 + distance / 1000.0)
                } else {
                    0.0
                }
            }
            _ => 0.0,
        }
    }

    pub fn health_score(&self) -> f64 {
        match self.latency_ms {
            Some(latency) => {
                if latency == 0 {
                    100.0
                } else {
                    10000.0 / (latency as f64)
                }
            }
            None => 0.0,
        }
    }

    pub fn combined_score(&self, target_geo: Option<&GeoInfo>) -> f64 {
        if let Some(geo) = target_geo {
            let geo_score = self.geo_score(geo);
            if geo_score > 0.0 {
                return geo_score * 0.7 + self.health_score() * 0.3;
            }
        }
        self.health_score()
    }

    fn great_circle_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1_rad = lat1.to_radians();
        let lat2_rad = lat2.to_radians();
        let dlat = (lat2 - lat1).to_radians();
        let dlon = (lon2 - lon1).to_radians();

        let a = (dlat / 2.0).sin().powi(2)
            + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().asin();

        EARTH_RADIUS_KM * c
    }

    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }

    pub fn geolocate(&mut self, geo_lookup: Option<&GeoIpLookup>) {
        if self.geo.is_some() {
            return;
        }

        let Some(lookup) = geo_lookup else {
            return;
        };

        let ip = &self.address;
        let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() else {
            return;
        };

        let location_info = lookup.lookup_location_info(ip_addr);

        if let Some(info) = location_info {
            self.geo = Some(GeoInfo::from(info));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_score_with_coords() {
        let peer = PeerContact::new(
            NodeId::random(),
            "test-node".to_string(),
            "192.168.1.1".to_string(),
            443,
        )
        .with_geo(GeoInfo::with_coords(40.7128, -74.0060));

        let target = GeoInfo::with_coords(40.7128, -74.0060);

        let score = peer.geo_score(&target);
        assert!(score > 0.9);
    }

    #[test]
    fn test_geo_score_far_away() {
        let peer = PeerContact::new(
            NodeId::random(),
            "test-node".to_string(),
            "192.168.1.1".to_string(),
            443,
        )
        .with_geo(GeoInfo::with_coords(40.7128, -74.0060));

        let target = GeoInfo::with_coords(51.5074, -0.1278);

        let score = peer.geo_score(&target);
        assert!(score < 0.5);
    }

    #[test]
    fn test_geo_score_no_geo() {
        let peer = PeerContact::new(
            NodeId::random(),
            "test-node".to_string(),
            "192.168.1.1".to_string(),
            443,
        );

        let target = GeoInfo::with_coords(40.7128, -74.0060);

        let score = peer.geo_score(&target);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_health_score() {
        let peer = PeerContact::new(
            NodeId::random(),
            "test-node".to_string(),
            "192.168.1.1".to_string(),
            443,
        )
        .with_latency(100);

        let score = peer.health_score();
        assert!((score - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_health_score_no_latency() {
        let peer = PeerContact::new(
            NodeId::random(),
            "test-node".to_string(),
            "192.168.1.1".to_string(),
            443,
        );

        let score = peer.health_score();
        assert_eq!(score, 0.0);
    }
}
