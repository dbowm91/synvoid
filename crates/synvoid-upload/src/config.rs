use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Policy for handling YARA scanner failures during upload validation.
///
/// - `FailClosed`: Reject upload on scanner error, timeout, panic, or unavailable scanner.
/// - `QuarantineOnError`: Quarantine the upload if possible, then reject with scan-indeterminate error.
/// - `FailOpen`: Allow upload on scan failure, but mark result as scan-indeterminate.
///   **Must be opt-in; never the production default.**
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UploadScanFailurePolicy {
    FailClosed,
    #[default]
    QuarantineOnError,
    FailOpen,
}

/// Scan mode for large file YARA scanning.
///
/// - `Full`: Read and scan the entire file up to configured upload size limit.
///   Safest option; recommended default for production upload endpoints.
/// - `Windowed`: Scan bounded windows (header, footer, middle, around magic offsets).
///   Resource-efficient tradeoff; not equivalent to full malware coverage.
/// - `HeaderOnly`: Scan only the first 8 KiB header. **Low assurance — opt-in only,
///   not recommended for public executable/archive/document upload surfaces.**
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum YaraLargeFileScanMode {
    #[default]
    Full,
    Windowed,
    HeaderOnly,
}

/// Default window size for windowed scanning (1 MiB).
const DEFAULT_WINDOW_SIZE_BYTES: u64 = 1048576;

/// Default maximum number of windows for windowed scanning.
const DEFAULT_MAX_WINDOW_COUNT: u32 = 8;

/// Default magic scan limit: offsets beyond this are not probed for magic markers.
const DEFAULT_MAGIC_SCAN_LIMIT_BYTES: u64 = 16 * 1024 * 1024;

static DEFAULT_SAFE_MIME_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/bmp",
    "image/svg+xml",
    "video/mp4",
    "video/webm",
    "video/mpeg",
    "video/quicktime",
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    "audio/flac",
    "audio/aac",
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
    "application/rtf",
    "text/plain",
    "text/csv",
];

pub fn default_safe_mime_types() -> Vec<String> {
    DEFAULT_SAFE_MIME_TYPES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
pub struct UploadConfig {
    #[serde(default = "default_upload_enabled")]
    pub enabled: bool,

    #[serde(default = "default_max_size")]
    pub max_size: String,

    #[serde(default = "default_memory_threshold")]
    pub memory_threshold: String,

    #[serde(default = "default_scan_with_yara")]
    pub scan_with_yara: bool,

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

    #[serde(default = "default_verify_signature")]
    pub verify_signature: bool,

    #[serde(default = "default_signature_strict_mode")]
    pub signature_strict_mode: bool,

    #[serde(default = "default_rate_limit_enabled")]
    pub rate_limit_enabled: bool,

    #[serde(default = "default_max_uploads_per_minute")]
    pub max_uploads_per_minute: u32,

    #[serde(default = "default_max_uploads_per_hour")]
    pub max_uploads_per_hour: u32,

    #[serde(default = "default_max_bytes_per_minute")]
    pub max_bytes_per_minute: String,

    #[serde(default = "default_burst_allowance")]
    pub burst_allowance: u32,

    #[serde(default)]
    pub allowed_types: AllowedTypesConfig,

    #[serde(default)]
    pub paths: Vec<PathUploadConfig>,

    #[serde(default = "default_reject_mime_mismatch")]
    pub reject_mime_mismatch: bool,

    #[serde(default)]
    pub yara_failure_policy: UploadScanFailurePolicy,

    /// Large file scan mode: `full`, `windowed`, or `header_only`.
    #[serde(default)]
    pub yara_large_file_scan_mode: YaraLargeFileScanMode,

    /// Window size in bytes for windowed scanning.
    #[serde(default = "default_yara_window_size_bytes")]
    pub yara_window_size_bytes: u64,

    /// Maximum number of windows for windowed scanning.
    #[serde(default = "default_yara_max_window_count")]
    pub yara_max_window_count: u32,

    /// Maximum offset (in bytes) for magic marker probing in windowed mode.
    #[serde(default = "default_yara_magic_scan_limit_bytes")]
    pub yara_magic_scan_limit_bytes: u64,
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            enabled: default_upload_enabled(),
            max_size: default_max_size(),
            memory_threshold: default_memory_threshold(),
            scan_with_yara: default_scan_with_yara(),
            sandbox_enabled: default_sandbox_enabled(),
            sandbox_dir: default_sandbox_dir(),
            quarantine_dir: default_quarantine_dir(),
            yara_rules_dir: None,
            yara_timeout_ms: default_yara_timeout_ms(),
            verify_signature: default_verify_signature(),
            signature_strict_mode: default_signature_strict_mode(),
            rate_limit_enabled: default_rate_limit_enabled(),
            max_uploads_per_minute: default_max_uploads_per_minute(),
            max_uploads_per_hour: default_max_uploads_per_hour(),
            max_bytes_per_minute: default_max_bytes_per_minute(),
            burst_allowance: default_burst_allowance(),
            allowed_types: AllowedTypesConfig::default(),
            paths: Vec::new(),
            reject_mime_mismatch: default_reject_mime_mismatch(),
            yara_failure_policy: UploadScanFailurePolicy::default(),
            yara_large_file_scan_mode: YaraLargeFileScanMode::default(),
            yara_window_size_bytes: default_yara_window_size_bytes(),
            yara_max_window_count: default_yara_max_window_count(),
            yara_magic_scan_limit_bytes: default_yara_magic_scan_limit_bytes(),
        }
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

fn default_verify_signature() -> bool {
    true
}

fn default_signature_strict_mode() -> bool {
    false
}

fn default_rate_limit_enabled() -> bool {
    true
}

fn default_max_uploads_per_minute() -> u32 {
    30
}

fn default_max_uploads_per_hour() -> u32 {
    200
}

fn default_max_bytes_per_minute() -> String {
    "100MB".to_string()
}

fn default_burst_allowance() -> u32 {
    5
}

fn default_reject_mime_mismatch() -> bool {
    false
}

fn default_yara_window_size_bytes() -> u64 {
    DEFAULT_WINDOW_SIZE_BYTES
}

fn default_yara_max_window_count() -> u32 {
    DEFAULT_MAX_WINDOW_COUNT
}

fn default_yara_magic_scan_limit_bytes() -> u64 {
    DEFAULT_MAGIC_SCAN_LIMIT_BYTES
}

impl UploadConfig {
    pub fn max_size_bytes(&self) -> u64 {
        parse_size(&self.max_size).unwrap_or(100 * 1024 * 1024)
    }

    pub fn memory_threshold_bytes(&self) -> u64 {
        parse_size(&self.memory_threshold).unwrap_or(10 * 1024 * 1024)
    }

    pub fn max_bytes_per_minute_bytes(&self) -> u64 {
        parse_size(&self.max_bytes_per_minute).unwrap_or(100 * 1024 * 1024)
    }

    pub fn get_path_config(&self, request_path: &str) -> Option<&PathUploadConfig> {
        static COMPILED_PATTERNS: OnceLock<std::sync::Mutex<Vec<(Regex, usize)>>> = OnceLock::new();

        let patterns = COMPILED_PATTERNS.get_or_init(|| std::sync::Mutex::new(Vec::new()));

        let mut patterns = match patterns.lock() {
            Ok(p) => p,
            Err(poisoned) => poisoned.into_inner(),
        };

        if patterns.len() != self.paths.len() {
            patterns.clear();
            for (idx, path_cfg) in self.paths.iter().enumerate() {
                if let Ok(re) = Regex::new(&path_cfg.pattern) {
                    patterns.push((re, idx));
                }
            }
        }

        for (re, idx) in patterns.iter() {
            if re.is_match(request_path) {
                return self.paths.get(*idx);
            }
        }
        None
    }

    pub fn effective_config_for_path(&self, request_path: &str) -> EffectiveUploadConfig {
        if let Some(path_cfg) = self.get_path_config(request_path) {
            let path_has_explicit_allowed_types = !path_cfg.allowed_types.mime_types.is_empty()
                || path_cfg.allowed_types.mode != AllowedTypesMode::Allowlist;

            EffectiveUploadConfig {
                max_size_bytes: path_cfg
                    .max_size
                    .as_ref()
                    .and_then(|s| parse_size(s))
                    .unwrap_or_else(|| self.max_size_bytes()),
                allowed_mime_types: if path_cfg.allowed_types.mime_types.is_empty() {
                    self.allowed_types.effective_mime_types()
                } else {
                    path_cfg.allowed_types.mime_types.clone()
                },
                allowed_types_mode: if path_has_explicit_allowed_types {
                    path_cfg.allowed_types.mode.clone()
                } else {
                    self.allowed_types.mode.clone()
                },
                scan_with_yara: path_cfg.scan_with_yara.unwrap_or(self.scan_with_yara),
                yara_rules_dir: path_cfg
                    .yara_rules_dir
                    .clone()
                    .or_else(|| self.yara_rules_dir.clone())
                    .map(std::path::PathBuf::from),
                yara_timeout_ms: path_cfg.yara_timeout_ms.unwrap_or(self.yara_timeout_ms),
                memory_threshold_bytes: self.memory_threshold_bytes(),
                verify_signature: path_cfg.verify_signature.unwrap_or(self.verify_signature),
                signature_strict_mode: path_cfg
                    .signature_strict_mode
                    .unwrap_or(self.signature_strict_mode),
                rate_limit_enabled: path_cfg
                    .rate_limit_enabled
                    .unwrap_or(self.rate_limit_enabled),
                max_uploads_per_minute: path_cfg
                    .max_uploads_per_minute
                    .unwrap_or(self.max_uploads_per_minute),
                max_uploads_per_hour: path_cfg
                    .max_uploads_per_hour
                    .unwrap_or(self.max_uploads_per_hour),
                max_bytes_per_minute: path_cfg
                    .max_bytes_per_minute
                    .as_ref()
                    .and_then(|s| parse_size(s))
                    .unwrap_or_else(|| self.max_size_bytes()),
                burst_allowance: path_cfg.burst_allowance.unwrap_or(self.burst_allowance),
                reject_mime_mismatch: path_cfg
                    .reject_mime_mismatch
                    .unwrap_or(self.reject_mime_mismatch),
                yara_failure_policy: path_cfg
                    .yara_failure_policy
                    .clone()
                    .unwrap_or_else(|| self.yara_failure_policy.clone()),
                yara_large_file_scan_mode: path_cfg
                    .yara_large_file_scan_mode
                    .clone()
                    .unwrap_or_else(|| self.yara_large_file_scan_mode.clone()),
                yara_window_size_bytes: path_cfg
                    .yara_window_size_bytes
                    .unwrap_or(self.yara_window_size_bytes),
                yara_max_window_count: path_cfg
                    .yara_max_window_count
                    .unwrap_or(self.yara_max_window_count),
                yara_magic_scan_limit_bytes: path_cfg
                    .yara_magic_scan_limit_bytes
                    .unwrap_or(self.yara_magic_scan_limit_bytes),
            }
        } else {
            EffectiveUploadConfig {
                max_size_bytes: self.max_size_bytes(),
                allowed_mime_types: self.allowed_types.effective_mime_types(),
                allowed_types_mode: self.allowed_types.mode.clone(),
                scan_with_yara: self.scan_with_yara,
                yara_rules_dir: self.yara_rules_dir.clone().map(std::path::PathBuf::from),
                yara_timeout_ms: self.yara_timeout_ms,
                memory_threshold_bytes: self.memory_threshold_bytes(),
                verify_signature: self.verify_signature,
                signature_strict_mode: self.signature_strict_mode,
                rate_limit_enabled: self.rate_limit_enabled,
                max_uploads_per_minute: self.max_uploads_per_minute,
                max_uploads_per_hour: self.max_uploads_per_hour,
                max_bytes_per_minute: parse_size(&self.max_bytes_per_minute)
                    .unwrap_or(100 * 1024 * 1024),
                burst_allowance: self.burst_allowance,
                reject_mime_mismatch: self.reject_mime_mismatch,
                yara_failure_policy: self.yara_failure_policy.clone(),
                yara_large_file_scan_mode: self.yara_large_file_scan_mode.clone(),
                yara_window_size_bytes: self.yara_window_size_bytes,
                yara_max_window_count: self.yara_max_window_count,
                yara_magic_scan_limit_bytes: self.yara_magic_scan_limit_bytes,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct EffectiveUploadConfig {
    pub max_size_bytes: u64,
    pub allowed_mime_types: Vec<String>,
    pub allowed_types_mode: AllowedTypesMode,
    pub scan_with_yara: bool,
    pub yara_rules_dir: Option<std::path::PathBuf>,
    pub yara_timeout_ms: u64,
    pub memory_threshold_bytes: u64,
    pub verify_signature: bool,
    pub signature_strict_mode: bool,
    pub rate_limit_enabled: bool,
    pub max_uploads_per_minute: u32,
    pub max_uploads_per_hour: u32,
    pub max_bytes_per_minute: u64,
    pub burst_allowance: u32,
    pub reject_mime_mismatch: bool,
    pub yara_failure_policy: UploadScanFailurePolicy,
    pub yara_large_file_scan_mode: YaraLargeFileScanMode,
    pub yara_window_size_bytes: u64,
    pub yara_max_window_count: u32,
    pub yara_magic_scan_limit_bytes: u64,
}

impl EffectiveUploadConfig {
    pub fn is_mime_allowed(&self, mime_type: &str) -> bool {
        let registry = synvoid_app_handlers::mime::global_registry().read();
        let normalized = registry.normalize_mime(mime_type);

        match self.allowed_types_mode {
            AllowedTypesMode::Allowlist => {
                if self.allowed_mime_types.is_empty() {
                    return true;
                }
                registry.is_mime_allowed(&normalized, &self.allowed_mime_types)
            }
            AllowedTypesMode::Blocklist => {
                if self.allowed_mime_types.is_empty() {
                    return true;
                }
                !registry.is_mime_allowed(&normalized, &self.allowed_mime_types)
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AllowedTypesConfig {
    #[serde(default)]
    pub mode: AllowedTypesMode,

    #[serde(default = "default_safe_mime_types")]
    pub mime_types: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AllowedTypesMode {
    #[default]
    Allowlist,
    Blocklist,
}

impl AllowedTypesConfig {
    pub fn effective_mime_types(&self) -> Vec<String> {
        self.mime_types.clone()
    }

    pub fn is_allowed(&self, mime_type: &str) -> bool {
        let registry = synvoid_app_handlers::mime::global_registry().read();
        let normalized = registry.normalize_mime(mime_type);

        match self.mode {
            AllowedTypesMode::Allowlist => {
                if self.mime_types.is_empty() {
                    return true;
                }
                registry.is_mime_allowed(&normalized, &self.mime_types)
            }
            AllowedTypesMode::Blocklist => {
                if self.mime_types.is_empty() {
                    return true;
                }
                !registry.is_mime_allowed(&normalized, &self.mime_types)
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathUploadConfig {
    pub pattern: String,

    #[serde(default)]
    pub max_size: Option<String>,

    #[serde(default)]
    pub scan_with_yara: Option<bool>,

    #[serde(default)]
    pub yara_rules_dir: Option<String>,

    #[serde(default)]
    pub yara_timeout_ms: Option<u64>,

    #[serde(default)]
    pub verify_signature: Option<bool>,

    #[serde(default)]
    pub signature_strict_mode: Option<bool>,

    #[serde(default)]
    pub rate_limit_enabled: Option<bool>,

    #[serde(default)]
    pub max_uploads_per_minute: Option<u32>,

    #[serde(default)]
    pub max_uploads_per_hour: Option<u32>,

    #[serde(default)]
    pub max_bytes_per_minute: Option<String>,

    #[serde(default)]
    pub burst_allowance: Option<u32>,

    #[serde(default)]
    pub allowed_types: AllowedTypesConfig,

    #[serde(default)]
    pub reject_mime_mismatch: Option<bool>,

    #[serde(default)]
    pub yara_failure_policy: Option<UploadScanFailurePolicy>,

    #[serde(default)]
    pub yara_large_file_scan_mode: Option<YaraLargeFileScanMode>,

    #[serde(default)]
    pub yara_window_size_bytes: Option<u64>,

    #[serde(default)]
    pub yara_max_window_count: Option<u32>,

    #[serde(default)]
    pub yara_magic_scan_limit_bytes: Option<u64>,
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_uppercase();
    let (multiplier, num_part) = if s.ends_with("GB") {
        (1024 * 1024 * 1024, &s[..s.len() - 2])
    } else if s.ends_with("MB") {
        (1024 * 1024, &s[..s.len() - 2])
    } else if s.ends_with("KB") {
        (1024, &s[..s.len() - 2])
    } else if s.ends_with("B") {
        (1, &s[..s.len() - 1])
    } else {
        (1, s.as_str())
    };

    num_part.trim().parse::<u64>().ok().map(|n| n * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("100MB"), Some(100 * 1024 * 1024));
        assert_eq!(parse_size("50mb"), Some(50 * 1024 * 1024));
        assert_eq!(parse_size("1GB"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("512KB"), Some(512 * 1024));
        assert_eq!(parse_size("1024B"), Some(1024));
        assert_eq!(parse_size("1024"), Some(1024));
    }

    #[test]
    fn test_default_config() {
        let config = UploadConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_size_bytes(), 100 * 1024 * 1024);
        assert_eq!(config.memory_threshold_bytes(), 10 * 1024 * 1024);
        assert!(config.scan_with_yara);
        assert_eq!(
            config.yara_large_file_scan_mode,
            YaraLargeFileScanMode::Full
        );
        assert_eq!(config.yara_window_size_bytes, DEFAULT_WINDOW_SIZE_BYTES);
        assert_eq!(config.yara_max_window_count, DEFAULT_MAX_WINDOW_COUNT);
        assert_eq!(
            config.yara_magic_scan_limit_bytes,
            DEFAULT_MAGIC_SCAN_LIMIT_BYTES
        );
    }

    #[test]
    fn test_scan_mode_deserialize() {
        let mode: YaraLargeFileScanMode = serde_json::from_str(r#""full""#).unwrap();
        assert_eq!(mode, YaraLargeFileScanMode::Full);
        let mode: YaraLargeFileScanMode = serde_json::from_str(r#""windowed""#).unwrap();
        assert_eq!(mode, YaraLargeFileScanMode::Windowed);
        let mode: YaraLargeFileScanMode = serde_json::from_str(r#""header_only""#).unwrap();
        assert_eq!(mode, YaraLargeFileScanMode::HeaderOnly);
    }

    #[test]
    fn test_scan_mode_default_is_full() {
        let mode = YaraLargeFileScanMode::default();
        assert_eq!(mode, YaraLargeFileScanMode::Full);
    }

    #[test]
    fn test_path_override_scan_mode() {
        let config = UploadConfig {
            paths: vec![PathUploadConfig {
                pattern: "/api/upload".to_string(),
                max_size: None,
                scan_with_yara: None,
                yara_rules_dir: None,
                yara_timeout_ms: None,
                verify_signature: None,
                signature_strict_mode: None,
                rate_limit_enabled: None,
                max_uploads_per_minute: None,
                max_uploads_per_hour: None,
                max_bytes_per_minute: None,
                burst_allowance: None,
                allowed_types: AllowedTypesConfig::default(),
                reject_mime_mismatch: None,
                yara_failure_policy: None,
                yara_large_file_scan_mode: Some(YaraLargeFileScanMode::Windowed),
                yara_window_size_bytes: Some(512 * 1024),
                yara_max_window_count: Some(4),
                yara_magic_scan_limit_bytes: Some(8 * 1024 * 1024),
            }],
            ..Default::default()
        };

        let effective = config.effective_config_for_path("/api/upload");
        assert_eq!(
            effective.yara_large_file_scan_mode,
            YaraLargeFileScanMode::Windowed
        );
        assert_eq!(effective.yara_window_size_bytes, 512 * 1024);
        assert_eq!(effective.yara_max_window_count, 4);
        assert_eq!(effective.yara_magic_scan_limit_bytes, 8 * 1024 * 1024);

        let effective_default = config.effective_config_for_path("/other");
        assert_eq!(
            effective_default.yara_large_file_scan_mode,
            YaraLargeFileScanMode::Full
        );
        assert_eq!(
            effective_default.yara_window_size_bytes,
            DEFAULT_WINDOW_SIZE_BYTES
        );
    }

    #[test]
    fn test_effective_config_scan_mode_fields() {
        let config = UploadConfig::default();
        let effective = config.effective_config_for_path("/any");
        assert_eq!(
            effective.yara_large_file_scan_mode,
            YaraLargeFileScanMode::Full
        );
        assert_eq!(effective.yara_window_size_bytes, DEFAULT_WINDOW_SIZE_BYTES);
        assert_eq!(effective.yara_max_window_count, DEFAULT_MAX_WINDOW_COUNT);
        assert_eq!(
            effective.yara_magic_scan_limit_bytes,
            DEFAULT_MAGIC_SCAN_LIMIT_BYTES
        );
    }
}
