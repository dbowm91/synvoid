use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::metrics::bandwidth::{MonthlyResetConfig, MonthlyResetMode};

const fn default_bandwidth_retention_days() -> u32 {
    365
}

const fn default_mesh_excluded() -> bool {
    false
}

const fn default_monthly_cap_ingress() -> u64 {
    0
}

const fn default_monthly_cap_egress() -> u64 {
    0
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default, JsonSchema)]
pub enum BandwidthLimitAction {
    #[serde(rename = "block")]
    #[default]
    Block,
    #[serde(rename = "throttle")]
    Throttle,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct BandwidthConfig {
    #[serde(default = "default_bandwidth_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_mesh_excluded")]
    pub mesh_excluded_from_total: bool,
    #[serde(default = "default_monthly_cap_ingress")]
    pub monthly_cap_ingress_gb: u64,
    #[serde(default = "default_monthly_cap_egress")]
    pub monthly_cap_egress_gb: u64,
    #[serde(default)]
    pub action_on_limit: BandwidthLimitAction,
    #[serde(default)]
    pub monthly_reset: MonthlyResetConfig,
    #[serde(default)]
    pub data_dir: Option<String>,
}

impl Default for BandwidthConfig {
    fn default() -> Self {
        Self {
            retention_days: 365,
            mesh_excluded_from_total: false,
            monthly_cap_ingress_gb: 0,
            monthly_cap_egress_gb: 0,
            action_on_limit: BandwidthLimitAction::default(),
            monthly_reset: MonthlyResetConfig {
                mode: MonthlyResetMode::Rolling30Days,
                fixed_day: None,
            },
            data_dir: None,
        }
    }
}

impl BandwidthConfig {
    pub fn calculate_rate_limit(&self) -> (u64, u64) {
        let seconds_per_month = 30 * 24 * 60 * 60;
        let ingress_rate = if self.monthly_cap_ingress_gb > 0 {
            (self.monthly_cap_ingress_gb * 1024 * 1024 * 1024) / seconds_per_month
        } else {
            0
        };
        let egress_rate = if self.monthly_cap_egress_gb > 0 {
            (self.monthly_cap_egress_gb * 1024 * 1024 * 1024) / seconds_per_month
        } else {
            0
        };
        (ingress_rate, egress_rate)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct TrafficShapingConfig {
    #[serde(default = "default_ts_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub global: GlobalTrafficShapingConfig,
    #[serde(default)]
    pub connection_limits: ConnectionLimitsConfig,
    #[serde(default)]
    pub bandwidth: BandwidthConfig,
}

impl Default for TrafficShapingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global: GlobalTrafficShapingConfig::default(),
            connection_limits: ConnectionLimitsConfig::default(),
            bandwidth: BandwidthConfig::default(),
        }
    }
}

fn default_ts_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct GlobalTrafficShapingConfig {
    #[serde(default = "default_ingress_max")]
    pub ingress_max_mb_s: u64,
    #[serde(default = "default_egress_max")]
    pub egress_max_mb_s: u64,
    #[serde(default = "default_burst_allowance")]
    pub burst_allowance_mb: u64,
    #[serde(default = "default_burst_refill_ms")]
    pub burst_refill_ms: u64,
    #[serde(default = "default_attack_multiplier")]
    pub attack_mode_multiplier: f64,
}

impl Default for GlobalTrafficShapingConfig {
    fn default() -> Self {
        Self {
            ingress_max_mb_s: 128,
            egress_max_mb_s: 128,
            burst_allowance_mb: 10,
            burst_refill_ms: 100,
            attack_mode_multiplier: 0.5,
        }
    }
}

fn default_ingress_max() -> u64 {
    128
}
fn default_egress_max() -> u64 {
    128
}
fn default_burst_allowance() -> u64 {
    10
}
fn default_burst_refill_ms() -> u64 {
    100
}
fn default_attack_multiplier() -> f64 {
    0.5
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ConnectionLimitsConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "default_connection_queue_size")]
    pub connection_queue_size: u32,
    #[serde(default = "default_connection_queue_timeout_ms")]
    pub connection_queue_timeout_ms: u64,
    #[serde(default = "default_connection_burst")]
    pub connection_burst: u32,
}

impl Default for ConnectionLimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_connections_per_ip: 10,
            connection_queue_size: 100,
            connection_queue_timeout_ms: 60000,
            connection_burst: 5,
        }
    }
}

fn default_max_connections() -> u32 {
    1000
}
fn default_max_connections_per_ip() -> u32 {
    10
}
fn default_connection_queue_size() -> u32 {
    100
}
fn default_connection_queue_timeout_ms() -> u64 {
    60000
}
fn default_connection_burst() -> u32 {
    5
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct TrafficShapingDefaults {
    #[serde(default = "default_ts_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub site: SiteTrafficShapingDefaults,
}

impl Default for TrafficShapingDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            site: SiteTrafficShapingDefaults::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct SiteTrafficShapingDefaults {
    #[serde(default = "default_site_ingress_max")]
    pub ingress_max_mb_s: u64,
    #[serde(default = "default_site_egress_max")]
    pub egress_max_mb_s: u64,
    #[serde(default = "default_site_burst_allowance")]
    pub burst_allowance_mb: u64,
    #[serde(default)]
    pub connection: SiteConnectionDefaults,
}

impl Default for SiteTrafficShapingDefaults {
    fn default() -> Self {
        Self {
            ingress_max_mb_s: 12,
            egress_max_mb_s: 12,
            burst_allowance_mb: 5,
            connection: SiteConnectionDefaults::default(),
        }
    }
}

fn default_site_ingress_max() -> u64 {
    12
}
fn default_site_egress_max() -> u64 {
    12
}
fn default_site_burst_allowance() -> u64 {
    5
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteConnectionDefaults {
    #[serde(default = "default_site_max_connections")]
    pub max_connections: Option<u32>,
    #[serde(default = "default_site_max_connections_per_ip")]
    pub max_connections_per_ip: Option<u32>,
    #[serde(default = "default_site_connection_queue_size")]
    pub connection_queue_size: Option<u32>,
    #[serde(default = "default_site_connection_burst")]
    pub connection_burst: Option<u32>,
}

fn default_site_max_connections() -> Option<u32> {
    None
}
fn default_site_max_connections_per_ip() -> Option<u32> {
    None
}
fn default_site_connection_queue_size() -> Option<u32> {
    None
}
fn default_site_connection_burst() -> Option<u32> {
    None
}
