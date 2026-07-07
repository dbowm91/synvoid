use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::validation::{parse_size_string, ConfigValidationError};

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct UploadDefaults {
    #[serde(default = "default_upload_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_size")]
    pub max_size: String,
    #[serde(default = "default_memory_threshold")]
    pub memory_threshold: String,
    #[serde(default = "default_scan_with_yara")]
    pub scan_with_yara: bool,
    #[serde(default = "default_yara_failure_policy")]
    pub yara_failure_policy: String,
    #[serde(default = "default_sandbox_enabled")]
    pub sandbox_enabled: bool,
    #[serde(default = "default_sandbox_dir")]
    pub sandbox_dir: String,
    #[serde(default = "default_quarantine_dir")]
    pub quarantine_dir: String,
    #[serde(default)]
    pub yara_rules_dir: Option<String>,
    #[serde(default = "default_yara_timeout_ms")]
    pub yara_timeout_ms: u64,
    #[serde(default = "default_archive_max_depth")]
    pub archive_max_depth: u32,
    #[serde(default = "default_archive_max_size")]
    pub archive_max_size: u64,
    #[serde(default)]
    pub allowed_types: UploadAllowedTypesDefaults,
    /// Large file scan mode: `full`, `windowed`, or `header_only`.
    #[serde(default = "default_yara_large_file_scan_mode")]
    pub yara_large_file_scan_mode: String,
    /// Window size in bytes for windowed scanning. Default: 1 MiB.
    #[serde(default = "default_yara_window_size_bytes")]
    pub yara_window_size_bytes: u64,
    /// Maximum number of windows for windowed scanning. Default: 8.
    #[serde(default = "default_yara_max_window_count")]
    pub yara_max_window_count: u32,
    /// Maximum offset for magic marker probing in windowed mode. Default: 16 MiB.
    #[serde(default = "default_yara_magic_scan_limit_bytes")]
    pub yara_magic_scan_limit_bytes: u64,
    /// Maximum concurrent YARA scan tasks. Default: 4.
    #[serde(default = "default_yara_max_concurrent_scans")]
    pub yara_max_concurrent_scans: u32,
    /// Maximum queued YARA scan requests before rejecting. Default: 64.
    #[serde(default = "default_yara_max_queued_scans")]
    pub yara_max_queued_scans: u32,
    /// Timeout in ms to wait for a scan permit before rejecting. Default: 1000.
    #[serde(default = "default_yara_queue_timeout_ms")]
    pub yara_queue_timeout_ms: u64,
}

impl Default for UploadDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: "100MB".to_string(),
            memory_threshold: "10MB".to_string(),
            scan_with_yara: true,
            yara_failure_policy: "quarantine_on_error".to_string(),
            sandbox_enabled: true,
            sandbox_dir: "/var/lib/synvoid/sandbox".to_string(),
            quarantine_dir: "/var/lib/synvoid/quarantine".to_string(),
            yara_rules_dir: None,
            yara_timeout_ms: 30000,
            archive_max_depth: 3,
            archive_max_size: 100 * 1024 * 1024,
            allowed_types: UploadAllowedTypesDefaults::default(),
            yara_large_file_scan_mode: "full".to_string(),
            yara_window_size_bytes: 1048576,
            yara_max_window_count: 8,
            yara_magic_scan_limit_bytes: 16 * 1024 * 1024,
            yara_max_concurrent_scans: 4,
            yara_max_queued_scans: 64,
            yara_queue_timeout_ms: 1000,
        }
    }
}

impl UploadDefaults {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.enabled {
            if let Err(e) = parse_size_string(&self.max_size) {
                return Err(ConfigValidationError {
                    field: "defaults.upload.max_size".to_string(),
                    message: format!("Invalid size format: {}. Use format like '100MB', '1GB'", e),
                });
            }
            if let Err(e) = parse_size_string(&self.memory_threshold) {
                return Err(ConfigValidationError {
                    field: "defaults.upload.memory_threshold".to_string(),
                    message: format!("Invalid size format: {}", e),
                });
            }
            if self.scan_with_yara {
                if let Some(ref dir) = self.yara_rules_dir {
                    if !std::path::Path::new(dir).exists() {
                        return Err(ConfigValidationError {
                            field: "defaults.upload.yara_rules_dir".to_string(),
                            message: format!("YARA rules directory not found: {}", dir),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

fn default_upload_enabled() -> bool {
    true
}
fn default_max_size() -> String {
    "100MB".to_string()
}
fn default_memory_threshold() -> String {
    "10MB".to_string()
}
fn default_scan_with_yara() -> bool {
    true
}
fn default_yara_failure_policy() -> String {
    "quarantine_on_error".to_string()
}
fn default_sandbox_enabled() -> bool {
    true
}
fn default_sandbox_dir() -> String {
    "/var/lib/synvoid/sandbox".to_string()
}
fn default_quarantine_dir() -> String {
    "/var/lib/synvoid/quarantine".to_string()
}
fn default_yara_timeout_ms() -> u64 {
    30000
}

fn default_archive_max_depth() -> u32 {
    3
}

fn default_archive_max_size() -> u64 {
    100 * 1024 * 1024
}

fn default_yara_large_file_scan_mode() -> String {
    "full".to_string()
}

fn default_yara_window_size_bytes() -> u64 {
    1048576
}

fn default_yara_max_window_count() -> u32 {
    8
}

fn default_yara_magic_scan_limit_bytes() -> u64 {
    16 * 1024 * 1024
}
fn default_yara_max_concurrent_scans() -> u32 {
    4
}
fn default_yara_max_queued_scans() -> u32 {
    64
}
fn default_yara_queue_timeout_ms() -> u64 {
    1000
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct UploadAllowedTypesDefaults {
    #[serde(default = "default_allowed_types_mode")]
    pub mode: String,
    #[serde(default = "default_allowed_mime_types")]
    pub mime_types: Vec<String>,
}

impl Default for UploadAllowedTypesDefaults {
    fn default() -> Self {
        Self {
            mode: "allowlist".to_string(),
            mime_types: default_allowed_mime_types(),
        }
    }
}

fn default_allowed_types_mode() -> String {
    "allowlist".to_string()
}

fn default_allowed_mime_types() -> Vec<String> {
    vec![
        "image/jpeg".to_string(),
        "image/png".to_string(),
        "image/gif".to_string(),
        "image/webp".to_string(),
        "image/avif".to_string(),
        "image/bmp".to_string(),
        "image/svg+xml".to_string(),
        "video/mp4".to_string(),
        "video/webm".to_string(),
        "video/mpeg".to_string(),
        "video/quicktime".to_string(),
        "audio/mpeg".to_string(),
        "audio/ogg".to_string(),
        "audio/wav".to_string(),
        "audio/flac".to_string(),
        "audio/aac".to_string(),
        "application/pdf".to_string(),
        "application/msword".to_string(),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_string(),
        "application/vnd.ms-excel".to_string(),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string(),
        "application/vnd.ms-powerpoint".to_string(),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation".to_string(),
        "application/vnd.oasis.opendocument.text".to_string(),
        "application/vnd.oasis.opendocument.spreadsheet".to_string(),
        "application/vnd.oasis.opendocument.presentation".to_string(),
        "application/rtf".to_string(),
        "text/plain".to_string(),
        "text/csv".to_string(),
    ]
}
