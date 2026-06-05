use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::contact::GeoInfo;
use super::node_id::NodeId;

#[derive(
    Clone, Debug, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize, JsonSchema,
)]
pub struct GeoRoutingConfig {
    pub enabled: bool,
    pub latency_weight: f64,
    pub geo_distance_weight: f64,
    pub xor_weight: f64,
    pub regional_hub_count: usize,
    pub prefer_regional: bool,
}

impl GeoRoutingConfig {
    pub fn validate(&self) -> Self {
        let total = self.latency_weight + self.geo_distance_weight + self.xor_weight;
        if total <= 0.0 {
            tracing::warn!("All geo weights are 0, using defaults");
            return GeoRoutingConfig::default();
        }
        if (total - 1.0).abs() > 0.001 {
            let scale = 1.0 / total;
            tracing::warn!(
                "Geo routing weights don't sum to 1.0 ({}), normalizing",
                total
            );
            Self {
                enabled: self.enabled,
                latency_weight: self.latency_weight * scale,
                geo_distance_weight: self.geo_distance_weight * scale,
                xor_weight: self.xor_weight * scale,
                regional_hub_count: self.regional_hub_count,
                prefer_regional: self.prefer_regional,
            }
        } else {
            self.clone()
        }
    }
}

impl Default for GeoRoutingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            latency_weight: 0.3,
            geo_distance_weight: 0.5,
            xor_weight: 0.2,
            regional_hub_count: 3,
            prefer_regional: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GeoDistance {
    config: GeoRoutingConfig,
}

impl GeoDistance {
    pub fn new(config: GeoRoutingConfig) -> Self {
        Self {
            config: config.validate(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(GeoRoutingConfig::default())
    }

    pub fn combined_distance(
        &self,
        source_geo: Option<&GeoInfo>,
        target_geo: Option<&GeoInfo>,
        xor_dist: &NodeId,
        latency_ms: Option<u32>,
    ) -> f64 {
        if !self.config.enabled {
            return self.xor_distance_score(xor_dist);
        }

        let geo_dist = self.geo_distance_score(source_geo, target_geo);
        let xor_dist_score = self.xor_distance_score(xor_dist);
        let latency_score = self.latency_score(latency_ms);

        (self.config.geo_distance_weight * geo_dist)
            + (self.config.xor_weight * xor_dist_score)
            + (self.config.latency_weight * latency_score)
    }

    pub fn geo_distance_score(
        &self,
        source_geo: Option<&GeoInfo>,
        target_geo: Option<&GeoInfo>,
    ) -> f64 {
        match (source_geo, target_geo) {
            (Some(src), Some(tgt)) => {
                if let (Some(src_lat), Some(src_lon)) = (src.latitude, src.longitude) {
                    if let (Some(tgt_lat), Some(tgt_lon)) = (tgt.latitude, tgt.longitude) {
                        let distance_km = great_circle_distance(src_lat, src_lon, tgt_lat, tgt_lon);
                        return 1.0 / (1.0 + distance_km / 1000.0);
                    }
                }
                if let (Some(src_country), Some(tgt_country)) = (&src.country, &tgt.country) {
                    if src_country == tgt_country {
                        return 0.8;
                    }
                }
                0.3
            }
            _ => 0.5,
        }
    }

    pub fn xor_distance_score(&self, xor_dist: &NodeId) -> f64 {
        let bytes = xor_dist.as_bytes();
        let total_bits = bytes.len() * 8;
        let mut leading_zero_bits = 0usize;
        for &byte in bytes {
            if byte == 0 {
                leading_zero_bits += 8;
            } else {
                leading_zero_bits += byte.leading_zeros() as usize;
                break;
            }
        }
        leading_zero_bits as f64 / total_bits as f64
    }

    pub fn latency_score(&self, latency_ms: Option<u32>) -> f64 {
        match latency_ms {
            Some(0) => 1.0,
            Some(ms) => 1000.0 / (ms as f64 + 100.0),
            None => 0.3,
        }
    }

    pub fn is_configured(&self) -> bool {
        self.config.enabled
    }
}

fn great_circle_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();

    let a =
        (dlat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);

    let c = 2.0 * a.sqrt().asin();

    EARTH_RADIUS_KM * c
}

pub fn region_key(geo: &GeoInfo) -> String {
    geo.country.clone().unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_distance_score() {
        let geo_dist = GeoDistance::with_defaults();

        let zero_id = NodeId::from_bytes(&[0u8; 32]).unwrap();
        // Zero XOR distance = identical ID = highest score
        assert!((geo_dist.xor_distance_score(&zero_id) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_xor_distance_score_far() {
        let geo_dist = GeoDistance::with_defaults();

        // High XOR distance = far node = low score
        // Use all 0xff to represent maximum XOR distance (furthest possible)
        let far_bytes = [0xff; 32];
        let far_id = NodeId::from_bytes(&far_bytes).unwrap();
        let score = geo_dist.xor_distance_score(&far_id);
        // Maximum XOR distance should give very low score
        assert!(score < 0.1);
    }

    #[test]
    fn test_geo_distance_same_country() {
        let geo_dist = GeoDistance::with_defaults();

        // Test with same country but no coordinates - uses country fallback
        let src = GeoInfo {
            country: Some("US".to_string()),
            region: Some("CA".to_string()),
            latitude: None,
            longitude: None,
        };

        let tgt = GeoInfo {
            country: Some("US".to_string()),
            region: Some("NY".to_string()),
            latitude: None,
            longitude: None,
        };

        // Without coords, should use country match fallback (0.8)
        let score = geo_dist.geo_distance_score(Some(&src), Some(&tgt));
        assert!(score >= 0.7);
    }

    #[test]
    fn test_geo_distance_with_coords() {
        let geo_dist = GeoDistance::with_defaults();

        // Same location - should give high score
        let src = GeoInfo {
            country: Some("US".to_string()),
            region: Some("CA".to_string()),
            latitude: Some(40.7128),
            longitude: Some(-74.0060),
        };

        let tgt = GeoInfo {
            country: Some("US".to_string()),
            region: Some("NY".to_string()),
            latitude: Some(40.7128),
            longitude: Some(-74.0060),
        };

        // Same exact coordinates
        let score = geo_dist.geo_distance_score(Some(&src), Some(&tgt));
        assert!((score - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_combined_distance() {
        let geo_dist = GeoDistance::with_defaults();

        let src = GeoInfo {
            country: Some("US".to_string()),
            region: None,
            latitude: Some(40.7128),
            longitude: Some(-74.0060),
        };

        let tgt = GeoInfo {
            country: Some("US".to_string()),
            region: None,
            latitude: Some(40.7128),
            longitude: Some(-74.0060),
        };

        let xor_dist = NodeId::from_bytes(&[0u8; 32]).unwrap();
        let score = geo_dist.combined_distance(Some(&src), Some(&tgt), &xor_dist, Some(10));

        assert!(score > 0.8);
    }
}
