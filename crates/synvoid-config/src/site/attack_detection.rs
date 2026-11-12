use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteSqliConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteXssConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
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
    #[serde(default)]
    pub allowlist_only_mode: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteHeaderScanConfig {
    #[serde(default)]
    pub scan: Vec<String>,
    #[serde(default)]
    pub skip: Vec<String>,
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
    pub headers: SiteHeaderScanConfig,
    #[serde(default)]
    pub per_path: Vec<SiteAttackPathRule>,
}

impl SiteHeaderScanConfig {
    pub fn validate(&self) -> Result<(), crate::validation::ConfigValidationError> {
        for (field, names) in [
            ("attack_detection.headers.scan", &self.scan),
            ("attack_detection.headers.skip", &self.skip),
        ] {
            for name in names {
                if name.is_empty()
                    || name.contains(':')
                    || name.contains('\r')
                    || name.contains('\n')
                {
                    return Err(crate::validation::ConfigValidationError {
                        field: field.to_string(),
                        message: format!("Invalid header name {:?}", name),
                    });
                }
            }
        }
        Ok(())
    }
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
        self.headers.validate()?;
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
        let config = SiteAttackDetectionConfig {
            per_path: vec![rule("/admin/", Some("log"))],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn per_path_rejects_relative_prefix() {
        let config = SiteAttackDetectionConfig {
            per_path: vec![rule("admin/", Some("log"))],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn per_path_rejects_unknown_action() {
        let config = SiteAttackDetectionConfig {
            per_path: vec![rule("/admin/", Some("stall"))],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn per_path_rejects_missing_action() {
        let config = SiteAttackDetectionConfig {
            per_path: vec![rule("/admin/", None)],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_invalid_action_and_paranoia() {
        let config = SiteAttackDetectionConfig {
            action: Some("tarpit".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = SiteAttackDetectionConfig {
            paranoia_level: Some(4),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn accepts_detector_custom_patterns_and_ssrf_overrides() {
        let mut config = SiteAttackDetectionConfig::default();
        config.sqli.custom_patterns = vec!["tenant".to_string()];
        config.xss.custom_patterns = vec!["<tenant".to_string()];
        config.path_traversal.custom_patterns = vec!["../secret".to_string()];
        config.rfi.custom_patterns = vec!["evil".to_string()];
        config.ssrf.custom_patterns = vec!["metadata".to_string()];
        config.ssrf.block_private_ips = Some(false);
        config.ssrf.allowed_domains = vec!["api.example.com".to_string()];
        config.ssrf.allowlist_only_mode = Some(true);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn header_scan_lists_validate_header_names() {
        let mut config = SiteAttackDetectionConfig::default();
        config.headers.scan = vec!["x-app-user".to_string()];
        config.headers.skip = vec!["x-internal-trace".to_string()];
        assert!(config.validate().is_ok());

        let mut config = SiteAttackDetectionConfig::default();
        config.headers.scan = vec!["bad:header".to_string()];
        assert!(config.validate().is_err());

        let mut config = SiteAttackDetectionConfig::default();
        config.headers.skip = vec!["bad\nheader".to_string()];
        assert!(config.validate().is_err());
    }
}
