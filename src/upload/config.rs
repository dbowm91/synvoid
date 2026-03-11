use regex::Regex;
use serde::Deserialize;
use std::sync::OnceLock;

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

    #[serde(default)]
    pub allowed_types: AllowedTypesConfig,

    #[serde(default)]
    pub paths: Vec<PathUploadConfig>,
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
            allowed_types: AllowedTypesConfig::default(),
            paths: Vec::new(),
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
    "/var/lib/rustwaf/sandbox".to_string()
}

fn default_quarantine_dir() -> String {
    "/var/lib/rustwaf/quarantine".to_string()
}

fn default_yara_timeout_ms() -> u64 {
    30000
}

impl UploadConfig {
    pub fn max_size_bytes(&self) -> u64 {
        parse_size(&self.max_size).unwrap_or(100 * 1024 * 1024)
    }

    pub fn memory_threshold_bytes(&self) -> u64 {
        parse_size(&self.memory_threshold).unwrap_or(10 * 1024 * 1024)
    }

    pub fn get_path_config(&self, request_path: &str) -> Option<&PathUploadConfig> {
        static COMPILED_PATTERNS: OnceLock<std::sync::Mutex<Vec<(Regex, usize)>>> = OnceLock::new();

        let patterns = COMPILED_PATTERNS.get_or_init(|| std::sync::Mutex::new(Vec::new()));

        let mut patterns = patterns.lock().unwrap();

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
                scan_with_yara: path_cfg.scan_with_yara.unwrap_or(self.scan_with_yara),
                memory_threshold_bytes: self.memory_threshold_bytes(),
            }
        } else {
            EffectiveUploadConfig {
                max_size_bytes: self.max_size_bytes(),
                allowed_mime_types: self.allowed_types.effective_mime_types(),
                scan_with_yara: self.scan_with_yara,
                memory_threshold_bytes: self.memory_threshold_bytes(),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct EffectiveUploadConfig {
    pub max_size_bytes: u64,
    pub allowed_mime_types: Vec<String>,
    pub scan_with_yara: bool,
    pub memory_threshold_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AllowedTypesConfig {
    #[serde(default)]
    pub mode: AllowedTypesMode,

    #[serde(default = "default_safe_mime_types")]
    pub mime_types: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
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
        let registry = crate::mime::global_registry().read();
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
    pub allowed_types: AllowedTypesConfig,
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
    }
}
