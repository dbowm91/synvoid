use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::validation::ConfigValidationError;

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ThreatLevelConfig {
    #[serde(default = "default_threat_level_initial")]
    pub initial: u8,
    #[serde(default = "default_threat_level_auto_scale")]
    pub auto_scale: bool,
    #[serde(default = "default_scale_up_attacks")]
    pub scale_up_attacks_per_min: u32,
    #[serde(default = "default_scale_up_window")]
    pub scale_up_window_secs: u32,
    #[serde(default = "default_scale_down_attacks")]
    pub scale_down_attacks_per_min: u32,
    #[serde(default = "default_scale_down_window")]
    pub scale_down_window_secs: u32,
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u32,
    #[serde(default = "default_persist_interval_normal")]
    pub persist_interval_normal_secs: u32,
    #[serde(default = "default_persist_interval_attack")]
    pub persist_interval_attack_secs: u32,
    #[serde(default = "default_auto_deescalate_timeout")]
    pub auto_deescalate_timeout_mins: u32,
    #[serde(default)]
    pub global_limits: ThreatLevelGlobalLimits,
    #[serde(default)]
    pub ban_durations: ThreatLevelBanDurations,
    #[serde(default)]
    pub escalation: ThreatLevelEscalation,
}

impl Default for ThreatLevelConfig {
    fn default() -> Self {
        Self {
            initial: default_threat_level_initial(),
            auto_scale: default_threat_level_auto_scale(),
            scale_up_attacks_per_min: default_scale_up_attacks(),
            scale_up_window_secs: default_scale_up_window(),
            scale_down_attacks_per_min: default_scale_down_attacks(),
            scale_down_window_secs: default_scale_down_window(),
            cooldown_secs: default_cooldown_secs(),
            persist_interval_normal_secs: default_persist_interval_normal(),
            persist_interval_attack_secs: default_persist_interval_attack(),
            auto_deescalate_timeout_mins: default_auto_deescalate_timeout(),
            global_limits: ThreatLevelGlobalLimits::default(),
            ban_durations: ThreatLevelBanDurations::default(),
            escalation: ThreatLevelEscalation::default(),
        }
    }
}

impl ThreatLevelConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.initial < 1 || self.initial > 5 {
            return Err(ConfigValidationError {
                field: "threat_level.initial".to_string(),
                message: "Initial threat level must be between 1 and 5".to_string(),
            });
        }
        if self.scale_up_window_secs == 0 {
            return Err(ConfigValidationError {
                field: "threat_level.scale_up_window_secs".to_string(),
                message: "Scale up window must be greater than 0".to_string(),
            });
        }
        if self.scale_down_window_secs == 0 {
            return Err(ConfigValidationError {
                field: "threat_level.scale_down_window_secs".to_string(),
                message: "Scale down window must be greater than 0".to_string(),
            });
        }
        Ok(())
    }
}

fn default_threat_level_initial() -> u8 {
    1
}
fn default_threat_level_auto_scale() -> bool {
    true
}
fn default_scale_up_attacks() -> u32 {
    50
}
fn default_scale_up_window() -> u32 {
    60
}
fn default_scale_down_attacks() -> u32 {
    10
}
fn default_scale_down_window() -> u32 {
    300
}
fn default_cooldown_secs() -> u32 {
    60
}
fn default_persist_interval_normal() -> u32 {
    60
}
fn default_persist_interval_attack() -> u32 {
    15
}
fn default_auto_deescalate_timeout() -> u32 {
    15
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ThreatLevelGlobalLimits {
    #[serde(default = "default_level_1_multiplier")]
    pub level_1: f32,
    #[serde(default = "default_level_2_multiplier")]
    pub level_2: f32,
    #[serde(default = "default_level_3_multiplier")]
    pub level_3: f32,
    #[serde(default = "default_level_4_multiplier")]
    pub level_4: f32,
    #[serde(default = "default_level_5_multiplier")]
    pub level_5: f32,
}

impl Default for ThreatLevelGlobalLimits {
    fn default() -> Self {
        Self {
            level_1: 1.0,
            level_2: 0.75,
            level_3: 0.5,
            level_4: 0.25,
            level_5: 0.1,
        }
    }
}

fn default_level_1_multiplier() -> f32 {
    1.0
}
fn default_level_2_multiplier() -> f32 {
    0.75
}
fn default_level_3_multiplier() -> f32 {
    0.5
}
fn default_level_4_multiplier() -> f32 {
    0.25
}
fn default_level_5_multiplier() -> f32 {
    0.1
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ThreatLevelBanDurations {
    #[serde(default = "default_level_1_base")]
    pub level_1_base: String,
    #[serde(default = "default_level_2_base")]
    pub level_2_base: String,
    #[serde(default = "default_level_3_base")]
    pub level_3_base: String,
    #[serde(default = "default_level_4_base")]
    pub level_4_base: String,
    #[serde(default = "default_level_5_base")]
    pub level_5_base: String,
}

impl Default for ThreatLevelBanDurations {
    fn default() -> Self {
        Self {
            level_1_base: "1h".to_string(),
            level_2_base: "4h".to_string(),
            level_3_base: "24h".to_string(),
            level_4_base: "7d".to_string(),
            level_5_base: "permanent".to_string(),
        }
    }
}

fn default_level_1_base() -> String {
    "1h".to_string()
}
fn default_level_2_base() -> String {
    "4h".to_string()
}
fn default_level_3_base() -> String {
    "24h".to_string()
}
fn default_level_4_base() -> String {
    "7d".to_string()
}
fn default_level_5_base() -> String {
    "permanent".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ThreatLevelEscalation {
    #[serde(default = "default_escalation_enabled")]
    pub enabled: bool,
    #[serde(default = "default_violations_before_block")]
    pub violations_before_block: u32,
    #[serde(default = "default_violation_window")]
    pub violation_window_secs: u32,
    #[serde(default)]
    pub excluded_ips: Vec<String>,
}

impl Default for ThreatLevelEscalation {
    fn default() -> Self {
        Self {
            enabled: true,
            violations_before_block: 3,
            violation_window_secs: 300,
            excluded_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}

fn default_escalation_enabled() -> bool {
    true
}
fn default_violations_before_block() -> u32 {
    3
}
fn default_violation_window() -> u32 {
    300
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct IpFeedConfig {
    #[serde(default = "default_ip_feed_enabled")]
    pub enabled: bool,
    #[serde(default = "default_feed_update_interval")]
    pub update_interval_hours: u32,
    #[serde(default = "default_feed_url")]
    pub url: String,
    #[serde(default)]
    pub max_permanent_blocks: usize,
}

impl Default for IpFeedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            update_interval_hours: 2,
            url: "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt"
                .to_string(),
            max_permanent_blocks: 1_000_000,
        }
    }
}

fn default_ip_feed_enabled() -> bool {
    true
}
fn default_feed_update_interval() -> u32 {
    2
}
fn default_feed_url() -> String {
    "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct MimesConfig {
    #[serde(default = "default_mimes_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub file: Option<String>,
}

impl Default for MimesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file: Some("config/mimes/mime.types".to_string()),
        }
    }
}

fn default_mimes_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct RuleFeedConfig {
    #[serde(default = "default_rule_feed_enabled")]
    pub enabled: bool,
    #[serde(default = "default_rule_feed_url")]
    pub url: String,
    #[serde(default = "default_rule_feed_update_interval")]
    pub update_interval_hours: u32,
    #[serde(default = "default_rule_feed_auto_apply")]
    pub auto_apply: bool,
    #[serde(default = "default_rule_feed_allow_downgrade")]
    pub allow_downgrade: bool,
}

impl Default for RuleFeedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: "https://rules.example.com/api/v1/rules".to_string(),
            update_interval_hours: 24,
            auto_apply: true,
            allow_downgrade: false,
        }
    }
}

fn default_rule_feed_enabled() -> bool {
    false
}
fn default_rule_feed_url() -> String {
    "https://rules.example.com/api/v1/rules".to_string()
}
fn default_rule_feed_update_interval() -> u32 {
    24
}
fn default_rule_feed_auto_apply() -> bool {
    true
}
fn default_rule_feed_allow_downgrade() -> bool {
    false
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct YaraRuleFeedConfig {
    #[serde(default = "default_yara_feed_enabled")]
    pub enabled: bool,
    #[serde(default = "default_yara_feed_url")]
    pub url: String,
    #[serde(default = "default_yara_feed_update_interval")]
    pub update_interval_hours: u32,
    #[serde(default = "default_yara_feed_elevated_interval")]
    pub elevated_interval_hours: u32,
    #[serde(default = "default_yara_feed_auto_apply")]
    pub auto_apply: bool,
    #[serde(default = "default_yara_feed_allow_downgrade")]
    pub allow_downgrade: bool,
    #[serde(default)]
    pub signer_public_key: String,
    #[serde(default = "default_yara_feed_max_rules_size")]
    pub max_rules_size_kb: u32,
}

impl Default for YaraRuleFeedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: "https://rules.example.com/api/v1/yara".to_string(),
            update_interval_hours: 24,
            elevated_interval_hours: 1,
            auto_apply: true,
            allow_downgrade: false,
            signer_public_key: String::new(),
            max_rules_size_kb: 1024,
        }
    }
}

fn default_yara_feed_enabled() -> bool {
    false
}
fn default_yara_feed_url() -> String {
    "https://rules.example.com/api/v1/yara".to_string()
}
fn default_yara_feed_update_interval() -> u32 {
    24
}
fn default_yara_feed_elevated_interval() -> u32 {
    1
}
fn default_yara_feed_auto_apply() -> bool {
    true
}
fn default_yara_feed_allow_downgrade() -> bool {
    false
}
fn default_yara_feed_max_rules_size() -> u32 {
    1024
}
