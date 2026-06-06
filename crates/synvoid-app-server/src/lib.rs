pub mod granian;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

pub use granian::{
    GranianConfig, GranianInterface, GranianLogFormat, GranianLogLevel, GranianSupervisor,
};

static GRANIAN_SUPERVISORS: std::sync::LazyLock<RwLock<HashMap<String, Arc<GranianSupervisor>>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

pub fn register_granian_supervisor(site_id: &str, supervisor: Arc<GranianSupervisor>) {
    GRANIAN_SUPERVISORS
        .write()
        .insert(site_id.to_string(), supervisor);
}

pub fn unregister_granian_supervisor(site_id: &str) {
    GRANIAN_SUPERVISORS.write().remove(site_id);
}

pub fn get_granian_supervisor(site_id: &str) -> Option<Arc<GranianSupervisor>> {
    GRANIAN_SUPERVISORS.read().get(site_id).cloned()
}

pub fn get_all_granian_supervisors() -> Vec<(String, Arc<GranianSupervisor>)> {
    GRANIAN_SUPERVISORS
        .read()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

pub fn get_granian_logs(site_id: &str) -> Option<Vec<String>> {
    GRANIAN_SUPERVISORS
        .read()
        .get(site_id)
        .map(|s| s.clone().get_logs())
}

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
    pub auto_install_requirements: bool,
    pub require_hashes: bool,
    pub log_level: GranianLogLevel,
    pub log_format: GranianLogFormat,
    pub log_verbose: bool,
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

impl AppServerConfig {
    pub fn is_valid(&self) -> bool {
        self.enabled && (self.auto_detect_app || !self.app_path.is_empty())
    }

    pub fn socket_path_for_site(&self, site_id: &str, worker_id: usize) -> PathBuf {
        if let Some(ref path) = self.socket_path {
            path.clone()
        } else {
            std::env::temp_dir().join(format!("synvoid-{}-app-{}.sock", site_id, worker_id))
        }
    }
}
