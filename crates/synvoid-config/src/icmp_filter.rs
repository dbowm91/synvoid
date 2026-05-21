use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
pub enum FilterType {
    #[default]
    Auto,
    Nftables,
    Ebpf,
    Pf,
    WindowsFirewall,
    Wfp,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
pub enum IcmpAction {
    #[default]
    Block,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub enum IcmpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct IcmpTypeRule {
    pub icmp_type: u8,
    #[serde(default)]
    pub icmp_code: Option<u8>,
    pub action: IcmpAction,
    #[serde(default)]
    pub description: Option<String>,
}

impl IcmpTypeRule {
    pub fn new(icmp_type: u8, action: IcmpAction) -> Self {
        Self {
            icmp_type,
            icmp_code: None,
            action,
            description: None,
        }
    }

    pub fn with_code(mut self, code: u8) -> Self {
        self.icmp_code = Some(code);
        self
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
pub enum Direction {
    #[default]
    Both,
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(untagged)]
pub enum InterfaceSpec {
    All,
    Specific(Vec<String>),
}

impl Default for InterfaceSpec {
    fn default() -> Self {
        InterfaceSpec::All
    }
}

impl InterfaceSpec {
    pub fn is_all(&self) -> bool {
        matches!(self, InterfaceSpec::All)
    }

    pub fn interfaces(&self) -> Option<&[String]> {
        match self {
            InterfaceSpec::All => None,
            InterfaceSpec::Specific(ifaces) => Some(ifaces),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    pub packets_per_second: u32,
    pub burst: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct IcmpFilterConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub filter_type: FilterType,

    #[serde(default)]
    pub direction: Direction,

    #[serde(default)]
    pub interfaces: InterfaceSpec,

    #[serde(default = "default_table_name")]
    pub table_name: String,

    #[serde(default)]
    pub exempt_ips: Vec<String>,

    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    #[serde(default)]
    pub icmp_type_rules: Vec<IcmpTypeRule>,

    #[serde(default)]
    pub custom_ebpf_bytecode_path: Option<String>,
}

fn default_table_name() -> String {
    "synvoid-icmp".to_string()
}

impl Default for IcmpFilterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            filter_type: FilterType::Auto,
            direction: Direction::Both,
            interfaces: InterfaceSpec::All,
            table_name: default_table_name(),
            exempt_ips: Vec::new(),
            rate_limit: RateLimitConfig::default(),
            icmp_type_rules: Vec::new(),
            custom_ebpf_bytecode_path: None,
        }
    }
}

impl IcmpFilterConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_table_name(mut self, name: String) -> Self {
        self.table_name = name;
        self
    }

    pub fn with_ebpf_bytecode_path(mut self, path: &str) -> Self {
        self.custom_ebpf_bytecode_path = Some(path.to_string());
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        if !is_valid_identifier(&self.table_name) {
            return Err(format!("Invalid table name: {}", self.table_name));
        }

        if let InterfaceSpec::Specific(ifaces) = &self.interfaces {
            for iface in ifaces {
                if !is_valid_identifier(iface) {
                    return Err(format!("Invalid interface name: {}", iface));
                }
            }
        }

        for ip in &self.exempt_ips {
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err(format!("Invalid IP address in exempt_ips: {}", ip));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IcmpFilterConfig::new();
        assert!(!config.enabled);
        assert_eq!(config.table_name, "synvoid-icmp");
        assert!(config.icmp_type_rules.is_empty());
    }

    #[test]
    fn test_builder_pattern() {
        let config = IcmpFilterConfig::new()
            .with_table_name("custom-waf".to_string())
            .with_ebpf_bytecode_path("/tmp/test.o");

        assert_eq!(config.table_name, "custom-waf");
        assert_eq!(config.custom_ebpf_bytecode_path, Some("/tmp/test.o".to_string()));
    }

    #[test]
    fn test_serialization() {
        let config = IcmpFilterConfig::new()
            .with_table_name("waf_rules".to_string());
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: IcmpFilterConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.table_name, "waf_rules");
    }

    #[test]
    fn test_validation() {
        let valid_config = IcmpFilterConfig::new();
        assert!(valid_config.validate().is_ok());

        let invalid_table = IcmpFilterConfig::new().with_table_name("invalid table!".to_string());
        assert!(invalid_table.validate().is_err());

        let mut invalid_ip = IcmpFilterConfig::new();
        invalid_ip.exempt_ips.push("not-an-ip".to_string());
        assert!(invalid_ip.validate().is_err());
    }
}
