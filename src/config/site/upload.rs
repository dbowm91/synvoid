use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::validation::{parse_size_string, ConfigValidationError};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteUploadConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub max_size: Option<String>,
    #[serde(default)]
    pub memory_threshold: Option<String>,
    #[serde(default)]
    pub scan_with_yara: Option<bool>,
    #[serde(default)]
    pub sandbox_enabled: Option<bool>,
    #[serde(default)]
    pub allowed_types: SiteAllowedTypesConfig,
    #[serde(default)]
    pub paths: Vec<SitePathUploadConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteAllowedTypesConfig {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub mime_types: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SitePathUploadConfig {
    pub pattern: String,
    #[serde(default)]
    pub max_size: Option<String>,
    #[serde(default)]
    pub scan_with_yara: Option<bool>,
    #[serde(default)]
    pub allowed_types: SiteAllowedTypesConfig,
}

impl SiteUploadConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(ref max_size) = self.max_size {
            if let Err(e) = parse_size_string(max_size) {
                return Err(ConfigValidationError {
                    field: "upload.max_size".to_string(),
                    message: format!("Invalid size format: {}", e),
                });
            }
        }
        for path_config in &self.paths {
            if path_config.pattern.is_empty() {
                return Err(ConfigValidationError {
                    field: "upload.paths".to_string(),
                    message: "Path pattern cannot be empty".to_string(),
                });
            }
        }
        Ok(())
    }
}
