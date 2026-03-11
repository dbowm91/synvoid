use crate::config::{GlobalTrafficShapingConfig, TrafficShapingConfig};
use crate::waf::ThreatLevelManager;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::async_bucket::AsyncTokenBucket;

#[derive(Clone)]
pub struct GlobalTrafficShaper {
    config: GlobalTrafficShapingConfig,
    ingress_bucket: Arc<AsyncTokenBucket>,
    egress_bucket: Arc<AsyncTokenBucket>,
    threat_level: Arc<RwLock<Option<Arc<ThreatLevelManager>>>>,
}

impl GlobalTrafficShaper {
    pub fn new(config: GlobalTrafficShapingConfig) -> Self {
        let ingress_rate = config.ingress_max_mb_s * 1024 * 1024;
        let egress_rate = config.egress_max_mb_s * 1024 * 1024;
        let burst_capacity = config.burst_allowance_mb * 1024 * 1024;

        Self {
            config: config.clone(),
            ingress_bucket: AsyncTokenBucket::new(
                burst_capacity,
                ingress_rate,
                config.burst_refill_ms,
            ),
            egress_bucket: AsyncTokenBucket::new(
                burst_capacity,
                egress_rate,
                config.burst_refill_ms,
            ),
            threat_level: Arc::new(RwLock::new(None)),
        }
    }

    pub fn set_threat_level(&self, threat_level: Option<Arc<ThreatLevelManager>>) {
        let multiplier = threat_level
            .as_ref()
            .map(|tl| tl.get_throttling_multiplier())
            .unwrap_or(1.0);

        let ingress_rate =
            (self.config.ingress_max_mb_s as f64 * multiplier * 1024.0 * 1024.0) as u64;
        let egress_rate =
            (self.config.egress_max_mb_s as f64 * multiplier * 1024.0 * 1024.0) as u64;

        self.ingress_bucket.set_rate(ingress_rate);
        self.egress_bucket.set_rate(egress_rate);

        tracing::debug!(
            "Traffic shaper throttling multiplier: {:.2} (ingress: {} MB/s, egress: {} MB/s)",
            multiplier,
            ingress_rate / (1024 * 1024),
            egress_rate / (1024 * 1024)
        );
    }

    pub fn ingress_bucket(&self) -> Arc<AsyncTokenBucket> {
        self.ingress_bucket.clone()
    }

    pub fn egress_bucket(&self) -> Arc<AsyncTokenBucket> {
        self.egress_bucket.clone()
    }

    pub fn config(&self) -> &GlobalTrafficShapingConfig {
        &self.config
    }
}

pub struct SiteTrafficShaper {
    site_id: String,
    ingress_bucket: Arc<AsyncTokenBucket>,
    egress_bucket: Arc<AsyncTokenBucket>,
    ingress_max_mb_s: u64,
    egress_max_mb_s: u64,
    burst_allowance_mb: u64,
    enabled: bool,
}

impl SiteTrafficShaper {
    pub fn new(
        site_id: String,
        global: &GlobalTrafficShaper,
        site_ingress: Option<u64>,
        site_egress: Option<u64>,
        site_burst: Option<u64>,
    ) -> Self {
        let ingress_max = site_ingress.unwrap_or(global.config().ingress_max_mb_s);
        let egress_max = site_egress.unwrap_or(global.config().egress_max_mb_s);
        let burst = site_burst.unwrap_or(global.config().burst_allowance_mb);

        let ingress_rate = ingress_max * 1024 * 1024;
        let egress_rate = egress_max * 1024 * 1024;
        let burst_capacity = burst * 1024 * 1024;

        Self {
            site_id,
            ingress_bucket: AsyncTokenBucket::new(
                burst_capacity,
                ingress_rate,
                global.config().burst_refill_ms,
            ),
            egress_bucket: AsyncTokenBucket::new(
                burst_capacity,
                egress_rate,
                global.config().burst_refill_ms,
            ),
            ingress_max_mb_s: ingress_max,
            egress_max_mb_s: egress_max,
            burst_allowance_mb: burst,
            enabled: true,
        }
    }

    pub fn ingress_bucket(&self) -> Option<Arc<AsyncTokenBucket>> {
        if self.enabled {
            Some(self.ingress_bucket.clone())
        } else {
            None
        }
    }

    pub fn egress_bucket(&self) -> Option<Arc<AsyncTokenBucket>> {
        if self.enabled {
            Some(self.egress_bucket.clone())
        } else {
            None
        }
    }

    pub fn update_limits(
        &self,
        ingress_max_mb_s: Option<u64>,
        egress_max_mb_s: Option<u64>,
        _burst_allowance_mb: Option<u64>,
        _global: &GlobalTrafficShaper,
    ) {
        if let Some(ingress) = ingress_max_mb_s {
            let rate = ingress * 1024 * 1024;
            self.ingress_bucket.set_rate(rate);
        }

        if let Some(egress) = egress_max_mb_s {
            let rate = egress * 1024 * 1024;
            self.egress_bucket.set_rate(rate);
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn limits(&self) -> SiteTrafficLimits {
        SiteTrafficLimits {
            site_id: self.site_id.clone(),
            ingress_max_mb_s: self.ingress_max_mb_s,
            egress_max_mb_s: self.egress_max_mb_s,
            burst_allowance_mb: self.burst_allowance_mb,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SiteTrafficLimits {
    pub site_id: String,
    pub ingress_max_mb_s: u64,
    pub egress_max_mb_s: u64,
    pub burst_allowance_mb: u64,
}
