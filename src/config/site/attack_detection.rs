use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteSqliConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteXssConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SitePathTraversalConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteRfiConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteSsrfConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
    #[serde(default)]
    pub block_private_ips: Option<bool>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

fn default_attack_detection_enabled() -> Option<bool> {
    Some(true)
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteAttackDetectionConfig {
    #[serde(default = "default_attack_detection_enabled")]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub paranoia_level: Option<u8>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub sqli: SiteSqliConfig,
    #[serde(default)]
    pub xss: SiteXssConfig,
    #[serde(default)]
    pub path_traversal: SitePathTraversalConfig,
    #[serde(default)]
    pub rfi: SiteRfiConfig,
    #[serde(default)]
    pub ssrf: SiteSsrfConfig,
}

impl SiteAttackDetectionConfig {
    pub fn validate(&self) -> Result<(), crate::config::validation::ConfigValidationError> {
        if let Some(ref action) = self.action {
            match action.as_str() {
                "stall" | "block" | "log" => {}
                _ => {
                    return Err(crate::config::validation::ConfigValidationError {
                        field: "attack_detection.action".to_string(),
                        message: "Action must be 'stall', 'block', or 'log'".to_string(),
                    });
                }
            }
        }
        if let Some(level) = self.paranoia_level {
            if level < 1 || level > 3 {
                return Err(crate::config::validation::ConfigValidationError {
                    field: "attack_detection.paranoia_level".to_string(),
                    message: "Paranoia level must be between 1 and 3".to_string(),
                });
            }
        }
        Ok(())
    }
}
