use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::DnsConfigError;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DnsSettingsConfig {
    #[serde(default = "default_dns_ttl")]
    pub default_ttl: u32,

    #[serde(default = "default_min_geo_ttl")]
    pub min_geo_ttl: u32,

    #[serde(default)]
    pub allow_transfer: Vec<String>,

    #[serde(default = "default_cache_enabled")]
    pub cache_enabled: bool,

    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    #[serde(default = "default_cache_max_ttl")]
    pub cache_max_ttl: u64,

    #[serde(default = "default_cache_min_ttl")]
    pub cache_min_ttl: u64,

    #[serde(default = "default_negative_cache_ttl")]
    pub negative_cache_ttl: u32,

    #[serde(default)]
    pub allow_wildcard_transfer: bool,

    #[serde(default)]
    pub wildcard_transfer_requires_tsig: bool,

    #[serde(default = "default_require_tsig")]
    pub require_tsig: bool,

    #[serde(default)]
    pub serve_stale: ServeStaleConfig,

    #[serde(default = "default_ixfr_history_size")]
    pub ixfr_history_size: usize,

    #[serde(default = "default_ixfr_enabled")]
    pub ixfr_enabled: bool,

    #[serde(default = "default_ixfr_fallback_to_axfr")]
    pub ixfr_fallback_to_axfr: bool,

    #[serde(default)]
    pub ecs_filtering: EcsFilteringConfig,

    #[serde(default)]
    pub padding: DnsPaddingConfig,

    #[serde(default)]
    pub query_coalescing: QueryCoalescingConfig,

    #[serde(default)]
    pub dynamic_update: DynamicUpdateConfig,

    #[serde(default)]
    pub notify: NotifyConfig,

    #[serde(default)]
    pub qname_privacy: QnamePrivacyConfig,
}

fn default_dns_ttl() -> u32 {
    300
}

fn default_negative_cache_ttl() -> u32 {
    300
}

fn default_min_geo_ttl() -> u32 {
    60
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_size() -> usize {
    100000
}

fn default_cache_max_ttl() -> u64 {
    3600
}

fn default_cache_min_ttl() -> u64 {
    60
}

fn default_allow_wildcard_transfer() -> bool {
    false
}

fn default_wildcard_transfer_requires_tsig() -> bool {
    true
}

fn default_require_tsig() -> bool {
    true
}

fn default_ixfr_history_size() -> usize {
    200
}

fn default_ixfr_enabled() -> bool {
    true
}

fn default_ixfr_fallback_to_axfr() -> bool {
    true
}

impl Default for DnsSettingsConfig {
    fn default() -> Self {
        Self {
            default_ttl: default_dns_ttl(),
            min_geo_ttl: default_min_geo_ttl(),
            negative_cache_ttl: default_negative_cache_ttl(),
            allow_transfer: Vec::new(),
            cache_enabled: default_cache_enabled(),
            cache_size: default_cache_size(),
            cache_max_ttl: default_cache_max_ttl(),
            cache_min_ttl: default_cache_min_ttl(),
            allow_wildcard_transfer: default_allow_wildcard_transfer(),
            wildcard_transfer_requires_tsig: default_wildcard_transfer_requires_tsig(),
            require_tsig: default_require_tsig(),
            serve_stale: ServeStaleConfig::default(),
            ixfr_history_size: default_ixfr_history_size(),
            ixfr_enabled: default_ixfr_enabled(),
            ixfr_fallback_to_axfr: default_ixfr_fallback_to_axfr(),
            ecs_filtering: EcsFilteringConfig::default(),
            padding: DnsPaddingConfig::default(),
            query_coalescing: QueryCoalescingConfig::default(),
            dynamic_update: DynamicUpdateConfig::default(),
            notify: NotifyConfig::default(),
            qname_privacy: QnamePrivacyConfig::default(),
        }
    }
}

impl DnsSettingsConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.default_ttl > 86400 {
            return Err(DnsConfigError::InvalidSettings(
                "default_ttl cannot exceed 86400 seconds (24 hours)".to_string(),
            ));
        }

        if self.cache_max_ttl > 604800 {
            return Err(DnsConfigError::InvalidSettings(
                "cache_max_ttl cannot exceed 604800 seconds (7 days)".to_string(),
            ));
        }

        if self.cache_min_ttl > self.cache_max_ttl {
            return Err(DnsConfigError::InvalidSettings(
                "cache_min_ttl cannot be greater than cache_max_ttl".to_string(),
            ));
        }

        if self.cache_size == 0 {
            return Err(DnsConfigError::InvalidSettings(
                "cache_size must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DnsPaddingConfig {
    #[serde(default = "default_padding_enabled")]
    pub enabled: bool,

    #[serde(default = "default_padding_block_size")]
    pub block_size: usize,

    #[serde(default = "default_padding_mode")]
    pub mode: DnsPaddingMode,
}

fn default_padding_enabled() -> bool {
    false
}

fn default_padding_block_size() -> usize {
    128
}

fn default_padding_mode() -> DnsPaddingMode {
    DnsPaddingMode::Normal
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum DnsPaddingMode {
    #[default]
    Normal,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
#[serde(default)]
pub struct QnamePrivacyConfig {
    #[serde(default = "default_qname_privacy_enabled")]
    pub enabled: bool,

    #[serde(default = "default_qname_privacy_mode")]
    pub mode: QnamePrivacyMode,

    #[serde(default = "default_qname_log_level")]
    pub log_level: QnameLogLevel,
}

fn default_qname_privacy_enabled() -> bool {
    false
}

fn default_qname_privacy_mode() -> QnamePrivacyMode {
    QnamePrivacyMode::ZoneOnly
}

fn default_qname_log_level() -> QnameLogLevel {
    QnameLogLevel::Zone
}

impl QnamePrivacyConfig {
    pub fn sanitize_qname(&self, qname: &str, zone_origin: &str) -> String {
        if !self.enabled {
            return qname.to_string();
        }

        match self.mode {
            QnamePrivacyMode::Full => qname.to_string(),
            QnamePrivacyMode::ZoneOnly => {
                let zone = zone_origin.trim_end_matches('.');
                if qname.to_lowercase().ends_with(&format!(".{}", zone)) {
                    let suffix = format!(".{}", zone);
                    qname
                        .strip_suffix(&suffix)
                        .map(|s| {
                            if s.is_empty() {
                                "*".to_string()
                            } else {
                                s.to_string() + &suffix
                            }
                        })
                        .unwrap_or_else(|| qname.to_string())
                } else {
                    "[external]".to_string()
                }
            }
            QnamePrivacyMode::Truncate => {
                let parts: Vec<&str> = qname.split('.').collect();
                if parts.len() <= 2 {
                    qname.to_string()
                } else {
                    let keep = parts.len().min(2);
                    let suffix = parts[parts.len() - keep..].join(".");
                    format!("[redacted].{}", suffix)
                }
            }
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum QnamePrivacyMode {
    #[default]
    ZoneOnly,
    Truncate,
    Full,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum QnameLogLevel {
    #[default]
    Zone,
    Debug,
    Hidden,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
#[serde(default)]
pub struct QueryCoalescingConfig {
    #[serde(default = "default_coalescing_enabled")]
    pub enabled: bool,

    #[serde(default = "default_coalescing_max_wait")]
    pub max_wait_ms: u64,

    #[serde(default = "default_coalescing_max_entries")]
    pub max_entries: usize,

    #[serde(default = "default_coalescing_entry_ttl")]
    pub entry_ttl_secs: u64,

    #[serde(default = "default_coalescing_cleanup_interval")]
    pub cleanup_interval_secs: u64,
}

fn default_coalescing_enabled() -> bool {
    false
}

fn default_coalescing_max_wait() -> u64 {
    500
}

fn default_coalescing_max_entries() -> usize {
    10000
}

fn default_coalescing_entry_ttl() -> u64 {
    30
}

fn default_coalescing_cleanup_interval() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DynamicUpdateConfig {
    #[serde(default = "default_dynamic_update_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub allow_any: bool,

    #[serde(default)]
    pub require_tsig: bool,

    #[serde(default = "default_max_update_size")]
    pub max_update_size: usize,
}

fn default_dynamic_update_enabled() -> bool {
    false
}

fn default_max_update_size() -> usize {
    4096
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
#[serde(default)]
pub struct NotifyConfig {
    #[serde(default = "default_notify_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub also_notify: Vec<String>,
}

fn default_notify_enabled() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(default)]
pub struct EcsFilteringConfig {
    #[serde(default = "default_ecs_enabled")]
    pub enabled: bool,

    #[serde(default = "default_ecs_prefix_v4")]
    pub prefix_v4: u8,

    #[serde(default = "default_ecs_prefix_v6")]
    pub prefix_v6: u8,

    #[serde(default)]
    pub allow_private_prefix: bool,
}

fn default_ecs_enabled() -> bool {
    false
}

fn default_ecs_prefix_v4() -> u8 {
    24
}

fn default_ecs_prefix_v6() -> u8 {
    48
}

impl Default for EcsFilteringConfig {
    fn default() -> Self {
        Self {
            enabled: default_ecs_enabled(),
            prefix_v4: default_ecs_prefix_v4(),
            prefix_v6: default_ecs_prefix_v6(),
            allow_private_prefix: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
#[serde(default)]
pub struct ServeStaleConfig {
    #[serde(default = "default_serve_stale_enabled")]
    pub enabled: bool,

    #[serde(default = "default_serve_stale_max_stale")]
    pub max_stale_secs: u64,

    #[serde(default = "default_serve_stale_max_count")]
    pub max_stale_count: usize,
}

fn default_serve_stale_enabled() -> bool {
    false
}

fn default_serve_stale_max_stale() -> u64 {
    86400
}

fn default_serve_stale_max_count() -> usize {
    100
}
