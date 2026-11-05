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

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteAttackPathRule {
    pub path_prefix: String,
    #[serde(default)]
    pub action: Option<String>,
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
    #[serde(default)]
    pub per_path: Vec<SiteAttackPathRule>,
}

impl SiteAttackDetectionConfig {
    pub fn validate(&self) -> Result<(), crate::validation::ConfigValidationError> {
        if let Some(ref action) = self.action {
            match action.as_str() {
                "stall" | "block" | "log" => {}
                _ => {
                    return Err(crate::validation::ConfigValidationError {
                        field: "attack_detection.action".to_string(),
                        message: "Action must be 'stall', 'block', or 'log'".to_string(),
                    });
                }
            }
        }
        if let Some(level) = self.paranoia_level {
            if level < 1 || level > 3 {
                return Err(crate::validation::ConfigValidationError {
                    field: "attack_detection.paranoia_level".to_string(),
                    message: "Paranoia level must be between 1 and 3".to_string(),
                });
            }
        }
        for (index, rule) in self.per_path.iter().enumerate() {
            if !rule.path_prefix.starts_with('/') {
                return Err(crate::validation::ConfigValidationError {
                    field: format!("attack_detection.per_path[{index}].path_prefix"),
                    message: "Path prefix must start with '/'".to_string(),
                });
            }
            match rule.action.as_deref() {
                Some("block") | Some("log") => {}
                _ => {
                    return Err(crate::validation::ConfigValidationError {
                        field: format!("attack_detection.per_path[{index}].action"),
                        message: "Action must be 'block' or 'log'".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(prefix: &str, action: Option<&str>) -> SiteAttackPathRule {
        SiteAttackPathRule {
            path_prefix: prefix.to_string(),
            action: action.map(str::to_string),
        }
    }

    #[test]
    fn per_path_defaults_to_empty_and_valid() {
        let config = SiteAttackDetectionConfig::default();
        assert!(config.per_path.is_empty());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn per_path_accepts_log_rule() {
        let mut config = SiteAttackDetectionConfig::default();
        config.per_path = vec![rule("/admin/", Some("log"))];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn per_path_rejects_relative_prefix() {
        let mut config = SiteAttackDetectionConfig::default();
        config.per_path = vec![rule("admin/", Some("log"))];
        assert!(config.validate().is_err());
    }

    #[test]
    fn per_path_rejects_unknown_action() {
        let mut config = SiteAttackDetectionConfig::default();
        config.per_path = vec![rule("/admin/", Some("stall"))];
        assert!(config.validate().is_err());
    }

    #[test]
    fn per_path_rejects_missing_action() {
        let mut config = SiteAttackDetectionConfig::default();
        config.per_path = vec![rule("/admin/", None)];
        assert!(config.validate().is_err());
    }
}
