use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct HeaderOverride {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct FastCgiConfig {
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub script_filename: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub params: Option<HashMap<String, String>>,
    #[serde(default)]
    pub env_vars: Option<HashMap<String, String>>,
    #[serde(default)]
    pub split_path_info: Option<String>,
    #[serde(default)]
    pub try_files: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<u64>,
    #[serde(default)]
    pub send_timeout: Option<u64>,
    #[serde(default)]
    pub read_timeout: Option<u64>,
    #[serde(default)]
    pub max_connections: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct PhpConfig {
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub upload_tmp: Option<String>,
    #[serde(default)]
    pub extensions_dir: Option<String>,
    #[serde(default)]
    pub ini_settings: Option<HashMap<String, String>>,
    #[serde(default)]
    pub env_vars: Option<HashMap<String, String>>,
    #[serde(default)]
    pub connect_timeout: Option<u64>,
    #[serde(default)]
    pub send_timeout: Option<u64>,
    #[serde(default)]
    pub read_timeout: Option<u64>,
    #[serde(default)]
    pub disable_functions: Option<Vec<String>>,
    #[serde(default)]
    pub open_basedir: Option<String>,
    #[serde(default)]
    pub allow_url_fopen: Option<bool>,
    #[serde(default)]
    pub max_execution_time: Option<u64>,
    #[serde(default)]
    pub memory_limit: Option<String>,
    #[serde(default)]
    pub upload_max_filesize: Option<String>,
    #[serde(default)]
    pub post_max_size: Option<String>,
    #[serde(default)]
    pub pm: Option<String>,
    #[serde(default)]
    pub pm_max_children: Option<usize>,
    #[serde(default)]
    pub pm_start_servers: Option<usize>,
    #[serde(default)]
    pub pm_min_spare_servers: Option<usize>,
    #[serde(default)]
    pub pm_max_spare_servers: Option<usize>,
    #[serde(default)]
    pub pm_max_requests: Option<usize>,
    #[serde(default)]
    pub pm_status_path: Option<String>,
    #[serde(default)]
    pub drain_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub drain_on_reload: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct CgiConfig {
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub pass_variables: Option<bool>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub stdout_stderr_merge: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
#[serde(tag = "type")]
pub enum BackendConfig {
    #[serde(rename = "upstream")]
    Upstream { url: Option<String> },

    #[serde(rename = "axum-dynamic")]
    AxumDynamic {
        #[serde(default)]
        plugin: Option<String>,
        #[serde(default)]
        socket: Option<String>,
    },

    #[serde(rename = "app-server")]
    AppServer {
        #[serde(default)]
        socket: Option<String>,
    },

    #[serde(rename = "fastcgi")]
    FastCgi {
        #[serde(default)]
        socket: Option<String>,
    },

    #[serde(rename = "static")]
    Static {
        #[serde(default)]
        enabled: Option<bool>,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct LocationConfig {
    pub path: String,
    #[serde(default)]
    pub backend: Option<BackendConfig>,
    #[serde(default)]
    pub fastcgi: Option<FastCgiLocationConfig>,
    #[serde(default)]
    pub php: Option<PhpLocationConfig>,
    #[serde(default)]
    pub cgi: Option<CgiLocationConfig>,
    #[serde(default)]
    pub proxy: Option<LocationProxyConfig>,
    #[serde(default)]
    pub allowed_methods: Option<Vec<String>>,
    #[serde(default)]
    pub serverless: Option<crate::config::serverless::ServerlessConfig>,
}

impl LocationConfig {
    pub fn is_method_allowed(&self, method: &str) -> bool {
        if let Some(ref allowed) = self.allowed_methods {
            let method_upper = method.to_uppercase();
            allowed.iter().any(|m| m.to_uppercase() == method_upper)
        } else {
            true
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct FastCgiLocationConfig {
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub script_filename: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub split_path_info: Option<String>,
    #[serde(default)]
    pub try_files: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<u64>,
    #[serde(default)]
    pub send_timeout: Option<u64>,
    #[serde(default)]
    pub read_timeout: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct PhpLocationConfig {
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub upload_tmp: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<u64>,
    #[serde(default)]
    pub send_timeout: Option<u64>,
    #[serde(default)]
    pub read_timeout: Option<u64>,
    #[serde(default)]
    pub disable_functions: Option<String>,
    #[serde(default)]
    pub open_basedir: Option<String>,
    #[serde(default)]
    pub allow_url_fopen: Option<bool>,
    #[serde(default)]
    pub max_execution_time: Option<u64>,
    #[serde(default)]
    pub memory_limit: Option<String>,
    #[serde(default)]
    pub upload_max_filesize: Option<String>,
    #[serde(default)]
    pub post_max_size: Option<String>,
    #[serde(default)]
    pub pm: Option<String>,
    #[serde(default)]
    pub pm_max_children: Option<usize>,
    #[serde(default)]
    pub pm_start_servers: Option<usize>,
    #[serde(default)]
    pub pm_min_spare_servers: Option<usize>,
    #[serde(default)]
    pub pm_max_spare_servers: Option<usize>,
    #[serde(default)]
    pub pm_max_requests: Option<usize>,
    #[serde(default)]
    pub pm_status_path: Option<String>,
    #[serde(default)]
    pub drain_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub drain_on_reload: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct CgiLocationConfig {
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct LocationProxyConfig {
    #[serde(default)]
    pub url: Option<String>,
}
