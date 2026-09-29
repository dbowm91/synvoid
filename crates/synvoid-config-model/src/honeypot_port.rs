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

#[cfg(test)]
mod tests {
    use super::HoneypotPortConfig;

    #[test]
    fn defaults_and_serialized_field_names_remain_compatible() {
        let config = HoneypotPortConfig::default();
        assert!(config.enabled);
        assert_eq!(config.ports, [8080, 8443, 9090]);
        assert_eq!(config.protocols, ["tcp", "udp"]);
        assert_eq!(config.site_scope, "global");

        let json = serde_json::to_value(config).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["ports"][0], 8080);
        assert_eq!(json["protocols"][1], "udp");
        assert_eq!(json["site_scope"], "global");
    }
}
