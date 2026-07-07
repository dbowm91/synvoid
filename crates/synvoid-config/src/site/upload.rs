use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::validation::{parse_size_string, ConfigValidationError};

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
    pub yara_failure_policy: Option<String>,
    #[serde(default)]
    pub sandbox_enabled: Option<bool>,
    #[serde(default)]
    pub allowed_types: SiteAllowedTypesConfig,
    #[serde(default)]
    pub paths: Vec<SitePathUploadConfig>,
    /// Large file scan mode: `full`, `windowed`, or `header_only`.
    #[serde(default)]
    pub yara_large_file_scan_mode: Option<String>,
    /// Window size in bytes for windowed scanning.
    #[serde(default)]
    pub yara_window_size_bytes: Option<u64>,
    /// Maximum number of windows for windowed scanning.
    #[serde(default)]
    pub yara_max_window_count: Option<u32>,
    /// Maximum offset for magic marker probing in windowed mode.
    #[serde(default)]
    pub yara_magic_scan_limit_bytes: Option<u64>,
    /// Maximum concurrent YARA scan tasks.
    #[serde(default)]
    pub yara_max_concurrent_scans: Option<u32>,
    /// Maximum queued YARA scan requests before rejecting.
    #[serde(default)]
    pub yara_max_queued_scans: Option<u32>,
    /// Timeout in ms to wait for a scan permit before rejecting.
    #[serde(default)]
    pub yara_queue_timeout_ms: Option<u64>,
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
    pub yara_failure_policy: Option<String>,
    #[serde(default)]
    pub allowed_types: SiteAllowedTypesConfig,
    #[serde(default)]
    pub yara_large_file_scan_mode: Option<String>,
    #[serde(default)]
    pub yara_window_size_bytes: Option<u64>,
    #[serde(default)]
    pub yara_max_window_count: Option<u32>,
    #[serde(default)]
    pub yara_magic_scan_limit_bytes: Option<u64>,
    /// Maximum concurrent YARA scan tasks.
    #[serde(default)]
    pub yara_max_concurrent_scans: Option<u32>,
    /// Maximum queued YARA scan requests before rejecting.
    #[serde(default)]
    pub yara_max_queued_scans: Option<u32>,
    /// Timeout in ms to wait for a scan permit before rejecting.
    #[serde(default)]
    pub yara_queue_timeout_ms: Option<u64>,
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
