use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteAppServerConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub app_path: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub workers: Option<u32>,
    #[serde(default)]
    pub blocking_threads: Option<u32>,
    #[serde(default)]
    pub socket_path: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub python_path: Option<String>,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default)]
    pub env: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub restart_on_failure: Option<bool>,
    #[serde(default)]
    pub max_restarts: Option<u32>,
    #[serde(default)]
    pub health_check_path: Option<String>,
    #[serde(default)]
    pub health_check_interval_secs: Option<u64>,
    #[serde(default)]
    pub health_check_timeout_secs: Option<u64>,
    #[serde(default = "default_some_true")]
    pub auto_install_granian: Option<bool>,
    #[serde(default = "default_some_true")]
    pub auto_detect_venv: Option<bool>,
    #[serde(default = "default_some_true")]
    pub auto_detect_app: Option<bool>,
    #[serde(default = "default_some_true")]
    pub auto_install_requirements: Option<bool>,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub log_format: Option<String>,
    #[serde(default)]
    pub log_verbose: Option<bool>,
    #[serde(default)]
    pub require_hashes: Option<bool>,
}

fn default_some_true() -> Option<bool> {
    Some(true)
}

impl SiteAppServerConfig {
    pub fn socket_path_for_site(&self, site_id: &str, worker_id: usize) -> std::path::PathBuf {
        if let Some(ref path) = self.socket_path {
            std::path::PathBuf::from(path)
        } else {
            std::env::temp_dir().join(format!("synvoid-{}-app-{}.sock", site_id, worker_id))
        }
    }
}

impl SiteAppServerConfig {
    pub fn validate(&self) -> Result<(), crate::validation::ConfigValidationError> {
        if self.enabled.unwrap_or(false) {
            if self.app_path.is_none() {
                return Err(crate::validation::ConfigValidationError {
                    field: "app_server.app_path".to_string(),
                    message: "App path is required when app server is enabled".to_string(),
                });
            }
            if let Some(ref interface) = self.interface {
                match interface.to_lowercase().as_str() {
                    "asgi" | "rsgi" | "wsgi" => {}
                    _ => {
                        return Err(crate::validation::ConfigValidationError {
                            field: "app_server.interface".to_string(),
                            message: "Interface must be 'asgi', 'rsgi', or 'wsgi'".to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}
