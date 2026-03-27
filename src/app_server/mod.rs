pub mod granian;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

pub use granian::{GranianConfig, GranianInterface, GranianSupervisor};

#[derive(Clone, Debug, Serialize, Deserialize)]
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
        }
    }
}

impl AppServerConfig {
    pub fn is_valid(&self) -> bool {
        self.enabled && (self.auto_detect_app || !self.app_path.is_empty())
    }

    pub fn socket_path_for_site(&self, site_id: &str, worker_id: usize) -> PathBuf {
        if let Some(ref path) = self.socket_path {
            path.clone()
        } else {
            std::env::temp_dir().join(format!("maluwaf-{}-app-{}.sock", site_id, worker_id))
        }
    }
}
