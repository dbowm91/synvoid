#[allow(unused_imports)]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HoneypotPortConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_honeypot_ports")]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub protocols: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_honeypot_ports() -> Vec<u16> {
    vec![8080, 8443, 9090]
}

impl Default for HoneypotPortConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: default_honeypot_ports(),
            protocols: vec!["tcp".to_string(), "udp".to_string()],
        }
    }
}
