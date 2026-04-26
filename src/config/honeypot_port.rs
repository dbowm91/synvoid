#[allow(unused_imports)]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct HoneypotPortConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_honeypot_ports")]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default = "default_site_scope")]
    pub site_scope: String,
}

fn default_true() -> bool {
    true
}

fn default_honeypot_ports() -> Vec<u16> {
    vec![8080, 8443, 9090]
}

fn default_site_scope() -> String {
    "global".to_string()
}

impl Default for HoneypotPortConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: default_honeypot_ports(),
            protocols: vec!["tcp".to_string(), "udp".to_string()],
            site_scope: default_site_scope(),
        }
    }
}
