use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::validation::{parse_size_string, ConfigValidationError};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteFileManagerConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub root_path: Option<String>,
    #[serde(default)]
    pub max_file_size: Option<String>,
    #[serde(default)]
    pub blocked_extensions: Vec<String>,
    #[serde(default)]
    pub allowed_extensions: Vec<String>,
    #[serde(default)]
    pub allowed_mime_types: Vec<String>,
    #[serde(default)]
    pub scan_on_upload: Option<bool>,
    #[serde(default)]
    pub allow_hidden_files: Option<bool>,
    #[serde(default)]
    pub allow_symlinks: Option<bool>,
    #[serde(default)]
    pub require_auth: Option<bool>,
}

impl SiteFileManagerConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(ref max_size) = self.max_file_size {
            if let Err(e) = parse_size_string(max_size) {
                return Err(ConfigValidationError {
                    field: "file_manager.max_file_size".to_string(),
                    message: format!("Invalid size format: {}", e),
                });
            }
        }
        Ok(())
    }
}
