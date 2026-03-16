use serde::{Deserialize, Serialize};

use super::validation::ConfigValidationError;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_access_log")]
    pub access_log: bool,
    #[serde(default)]
    pub access_log_dir: Option<String>,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_max_entries_per_file")]
    pub max_entries_per_file: u32,
    #[serde(default = "default_access_log_format")]
    pub access_log_format: String,
    #[serde(default)]
    pub exporter: LogExporterConfig,
    #[serde(default)]
    pub request_body_logging: RequestBodyLoggingConfig,
    #[serde(default)]
    pub verbose_request_logging: VerboseRequestLoggingConfig,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            access_log: default_access_log(),
            access_log_dir: None,
            retention_days: default_retention_days(),
            max_entries_per_file: default_max_entries_per_file(),
            access_log_format: default_access_log_format(),
            exporter: LogExporterConfig::default(),
            request_body_logging: RequestBodyLoggingConfig::default(),
            verbose_request_logging: VerboseRequestLoggingConfig::default(),
        }
    }
}

impl LoggingConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match self.level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => {
                return Err(ConfigValidationError {
                    field: "logging.level".to_string(),
                    message: "Log level must be one of: trace, debug, info, warn, error"
                        .to_string(),
                });
            }
        }
        match self.access_log_format.as_str() {
            "json" | "text" => {}
            _ => {
                return Err(ConfigValidationError {
                    field: "logging.access_log_format".to_string(),
                    message: "Format must be 'json' or 'text'".to_string(),
                });
            }
        }
        if let Some(ref dir) = self.access_log_dir {
            if !std::path::Path::new(dir).exists() {
                return Err(ConfigValidationError {
                    field: "logging.access_log_dir".to_string(),
                    message: format!("Access log directory not found: {}", dir),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RequestBodyLoggingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_body_log_size")]
    pub max_size: usize,
    #[serde(default)]
    pub scrub_sensitive: bool,
    #[serde(default = "default_sensitive_fields")]
    pub sensitive_fields: Vec<String>,
}

impl Default for RequestBodyLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_size: default_max_body_log_size(),
            scrub_sensitive: true,
            sensitive_fields: default_sensitive_fields(),
        }
    }
}

fn default_max_body_log_size() -> usize {
    1024
}

fn default_sensitive_fields() -> Vec<String> {
    vec![
        "password".to_string(),
        "passwd".to_string(),
        "secret".to_string(),
        "token".to_string(),
        "api_key".to_string(),
        "apikey".to_string(),
        "authorization".to_string(),
        "access_token".to_string(),
        "refresh_token".to_string(),
        "credit_card".to_string(),
        "cc_number".to_string(),
        "ssn".to_string(),
        "social_security".to_string(),
    ]
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VerboseRequestLoggingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub log_blocked: bool,
    #[serde(default)]
    pub log_challenged: bool,
    #[serde(default)]
    pub log_dropped: bool,
    #[serde(default)]
    pub log_proxied: bool,
    #[serde(default)]
    pub log_internal: bool,
    #[serde(default = "default_max_logs_per_second")]
    pub max_logs_per_second: u32,
}

impl Default for VerboseRequestLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_blocked: false,
            log_challenged: false,
            log_dropped: false,
            log_proxied: false,
            log_internal: false,
            max_logs_per_second: default_max_logs_per_second(),
        }
    }
}

fn default_max_logs_per_second() -> u32 {
    100
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogExporterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub elasticsearch: Option<ElasticsearchConfig>,
    #[serde(default)]
    pub loki: Option<LokiConfig>,
}

impl Default for LogExporterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            elasticsearch: None,
            loki: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ElasticsearchConfig {
    pub url: String,
    #[serde(default = "default_es_index")]
    pub index: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_es_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_es_flush_interval_secs")]
    pub flush_interval_secs: u64,
}

fn default_es_index() -> String {
    "maluwaf-logs".to_string()
}

fn default_es_batch_size() -> usize {
    100
}

fn default_es_flush_interval_secs() -> u64 {
    5
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LokiConfig {
    pub url: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_loki_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_loki_flush_interval_secs")]
    pub flush_interval_secs: u64,
}

fn default_loki_batch_size() -> usize {
    100
}

fn default_loki_flush_interval_secs() -> u64 {
    5
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_access_log() -> bool {
    true
}

fn default_retention_days() -> u32 {
    5
}

fn default_max_entries_per_file() -> u32 {
    50000
}

fn default_access_log_format() -> String {
    "json".to_string()
}
