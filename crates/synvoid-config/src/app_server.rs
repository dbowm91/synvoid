use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AppServerConfig {
    pub enabled: bool,
    pub app_path: String,
    pub interface: GranianInterface,
    pub workers: u32,
    pub blocking_threads: u32,
    pub socket_path: Option<PathBuf>,
    pub port: Option<u16>,
    pub host: Option<String>,
    pub python_path: Option<PathBuf>,
    pub working_directory: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub restart_on_failure: bool,
    pub max_restarts: u32,
    pub health_check_path: String,
    pub health_check_interval_secs: u64,
    pub health_check_timeout_secs: u64,
    pub auto_install_granian: bool,
    pub auto_detect_venv: bool,
    pub auto_detect_app: bool,
    pub auto_install_requirements: bool,
    pub require_hashes: bool,
    pub log_level: GranianLogLevel,
    pub log_format: GranianLogFormat,
    pub log_verbose: bool,
}

impl AppServerConfig {
    pub fn is_valid(&self) -> bool {
        !self.app_path.is_empty()
    }
}

impl Default for AppServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            app_path: String::new(),
            interface: GranianInterface::Asgi,
            workers: 1,
            blocking_threads: 4,
            socket_path: None,
            port: Some(8000),
            host: Some("127.0.0.1".to_string()),
            python_path: None,
            working_directory: None,
            env: HashMap::new(),
            restart_on_failure: true,
            max_restarts: 5,
            health_check_path: "/".to_string(),
            health_check_interval_secs: 10,
            health_check_timeout_secs: 5,
            auto_install_granian: true,
            auto_detect_venv: true,
            auto_detect_app: true,
            auto_install_requirements: true,
            require_hashes: false,
            log_level: GranianLogLevel::Info,
            log_format: GranianLogFormat::Text,
            log_verbose: false,
        }
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GranianInterface {
    #[default]
    Asgi,
    AsgiNl,
    Rsgi,
    Wsgi,
}

impl From<&str> for GranianInterface {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "asgi" => GranianInterface::Asgi,
            "asginl" => GranianInterface::AsgiNl,
            "rsgi" => GranianInterface::Rsgi,
            "wsgi" => GranianInterface::Wsgi,
            _ => GranianInterface::Asgi,
        }
    }
}

impl std::fmt::Display for GranianInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GranianInterface::Asgi => write!(f, "asgi"),
            GranianInterface::AsgiNl => write!(f, "asginl"),
            GranianInterface::Rsgi => write!(f, "rsgi"),
            GranianInterface::Wsgi => write!(f, "wsgi"),
        }
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GranianLogLevel {
    #[default]
    Info,
    Debug,
    Warning,
    Error,
}

impl From<&str> for GranianLogLevel {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "debug" => GranianLogLevel::Debug,
            "warning" | "warn" => GranianLogLevel::Warning,
            "error" => GranianLogLevel::Error,
            _ => GranianLogLevel::Info,
        }
    }
}

impl std::fmt::Display for GranianLogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GranianLogLevel::Info => write!(f, "info"),
            GranianLogLevel::Debug => write!(f, "debug"),
            GranianLogLevel::Warning => write!(f, "warning"),
            GranianLogLevel::Error => write!(f, "error"),
        }
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GranianLogFormat {
    #[default]
    Text,
    Json,
}

impl From<&str> for GranianLogFormat {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => GranianLogFormat::Json,
            _ => GranianLogFormat::Text,
        }
    }
}

impl std::fmt::Display for GranianLogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GranianLogFormat::Text => write!(f, "text"),
            GranianLogFormat::Json => write!(f, "json"),
        }
    }
}
