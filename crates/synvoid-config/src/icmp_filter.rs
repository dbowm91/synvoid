use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FilterType {
    #[default]
    Auto,
    Nftables,
    Ebpf,
    Pf,
    WindowsFirewall,
    Wfp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IcmpAction {
    #[default]
    Block,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcmpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn is_block(&self) -> bool {
        matches!(self.action, IcmpAction::Block)
    }

    pub fn is_allow(&self) -> bool {
        matches!(self.action, IcmpAction::Allow)
    }

    pub fn validate(&self, is_v6: bool) -> Result<(), String> {
        if is_v6 {
            if self.icmp_type > 255 {
                return Err(format!("Invalid ICMPv6 type {} for rule", self.icmp_type));
            }
        } else {
            if self.icmp_type > 255 {
                return Err(format!("Invalid ICMPv4 type {} for rule", self.icmp_type));
            }
        }
        if let Some(ref desc) = self.description {
            if desc.len() > 256 {
                return Err("Description too long (max 256 chars)".to_string());
            }
        }
        Ok(())
    }
}

pub mod icmp_types {
    pub mod v4 {
        pub const ECHO_REPLY: u8 = 0;
        pub const DESTINATION_UNREACHABLE: u8 = 3;
        pub const SOURCE_QUENCH: u8 = 4;
        pub const REDIRECT: u8 = 5;
        pub const ECHO_REQUEST: u8 = 8;
        pub const ROUTER_ADVERTISEMENT: u8 = 9;
        pub const ROUTER_SOLICITATION: u8 = 10;
        pub const TIME_EXCEEDED: u8 = 11;
        pub const PARAMETER_PROBLEM: u8 = 12;
        pub const TIMESTAMP_REQUEST: u8 = 13;
        pub const TIMESTAMP_REPLY: u8 = 14;
        pub const INFORMATION_REQUEST: u8 = 15;
        pub const INFORMATION_REPLY: u8 = 16;
        pub const ADDRESS_MASK_REQUEST: u8 = 17;
        pub const ADDRESS_MASK_REPLY: u8 = 18;
    }

    pub mod v6 {
        pub const DESTINATION_UNREACHABLE: u8 = 1;
        pub const PACKET_TOO_BIG: u8 = 2;
        pub const TIME_EXCEEDED: u8 = 3;
        pub const PARAMETER_PROBLEM: u8 = 4;
        pub const ECHO_REQUEST: u8 = 128;
        pub const ECHO_REPLY: u8 = 129;
        pub const ROUTER_SOLICITATION: u8 = 133;
        pub const ROUTER_ADVERTISEMENT: u8 = 134;
        pub const NEIGHBOR_SOLICITATION: u8 = 135;
        pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
        pub const REDIRECT: u8 = 137;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[default]
    Both,
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    pub packets_per_second: u32,
    pub burst: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpFilterConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub filter_type: FilterType,

    #[serde(default)]
    pub direction: Direction,

    #[serde(default)]
    pub interfaces: InterfaceSpec,

    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,

    #[serde(default)]
    pub exempt_ips: Vec<IpAddr>,

    #[serde(default = "default_table_name")]
    pub table_name: String,

    #[serde(default)]
    pub icmp_type_rules: Vec<IcmpTypeRule>,

    #[serde(default)]
    pub icmpv6_type_rules: Vec<IcmpTypeRule>,

    #[serde(default)]
    pub ebpf_bytecode_path: Option<String>,
}

fn default_table_name() -> String {
    "synvoid_icmp".to_string()
}

impl Default for IcmpFilterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            filter_type: FilterType::Auto,
            direction: Direction::Both,
            interfaces: InterfaceSpec::All,
            rate_limit: None,
            exempt_ips: Vec::new(),
            table_name: default_table_name(),
            icmp_type_rules: Vec::new(),
            icmpv6_type_rules: Vec::new(),
            ebpf_bytecode_path: None,
        }
    }
}

impl IcmpFilterConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<(), String> {
        if !is_valid_identifier(&self.table_name) {
            return Err(format!(
                "Invalid table name '{}': must be 1-64 chars, alphanumeric/underscore/hyphen only",
                self.table_name
            ));
        }

        if let InterfaceSpec::Specific(ifaces) = &self.interfaces {
            for iface in ifaces {
                if !is_valid_interface_name(iface) {
                    return Err(format!(
                        "Invalid interface name '{}': must be 1-15 chars, alphanumeric/underscore/dot/hyphen only",
                        iface
                    ));
                }
            }
        }

        for rule in &self.icmp_type_rules {
            rule.validate(false)?;
        }

        for rule in &self.icmpv6_type_rules {
            rule.validate(true)?;
        }

        if let Some(ref rate_limit) = self.rate_limit {
            if rate_limit.enabled && rate_limit.packets_per_second == 0 {
                return Err("Rate limit enabled but packets_per_second is 0".to_string());
            }
        }

        Ok(())
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn with_filter_type(mut self, filter_type: FilterType) -> Self {
        self.filter_type = filter_type;
        self
    }

    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    pub fn with_interfaces(mut self, interfaces: InterfaceSpec) -> Self {
        self.interfaces = interfaces;
        self
    }

    pub fn with_rate_limit(mut self, rate_limit: RateLimitConfig) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }

    pub fn with_exempt_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.exempt_ips = ips;
        self
    }

    pub fn with_table_name(mut self, name: impl Into<String>) -> Self {
        self.table_name = name.into();
        self
    }

    pub fn with_icmp_type_rules(mut self, rules: Vec<IcmpTypeRule>) -> Self {
        self.icmp_type_rules = rules;
        self
    }

    pub fn with_icmpv6_type_rules(mut self, rules: Vec<IcmpTypeRule>) -> Self {
        self.icmpv6_type_rules = rules;
        self
    }

    pub fn with_ebpf_bytecode_path(mut self, path: impl Into<String>) -> Self {
        self.ebpf_bytecode_path = Some(path.into());
        self
    }

    pub fn has_type_rules(&self) -> bool {
        !self.icmp_type_rules.is_empty() || !self.icmpv6_type_rules.is_empty()
    }

    pub fn with_default_ddos_rules(mut self) -> Self {
        self.icmp_type_rules = vec![
            IcmpTypeRule::new(icmp_types::v4::ECHO_REQUEST, IcmpAction::Block)
                .with_description("Block ping (ICMP echo request) - prevents ping flood DDOS"),
            IcmpTypeRule::new(icmp_types::v4::TIMESTAMP_REQUEST, IcmpAction::Block)
                .with_description("Block timestamp request - information disclosure"),
            IcmpTypeRule::new(icmp_types::v4::INFORMATION_REQUEST, IcmpAction::Block)
                .with_description("Block information request - information disclosure"),
            IcmpTypeRule::new(icmp_types::v4::ADDRESS_MASK_REQUEST, IcmpAction::Block)
                .with_description("Block address mask request - information disclosure"),
        ];
        self.icmpv6_type_rules =
            vec![
                IcmpTypeRule::new(icmp_types::v6::ECHO_REQUEST, IcmpAction::Block)
                    .with_description("Block ICMPv6 echo request - prevents ping flood DDOS"),
            ];
        self
    }

    pub fn with_default_ddos_rate_limit(mut self) -> Self {
        self.rate_limit = Some(RateLimitConfig {
            enabled: true,
            packets_per_second: 10,
            burst: 20,
        });
        self
    }

    pub fn with_ddos_defaults(mut self) -> Self {
        self = self.with_default_ddos_rules();
        self = self.with_default_ddos_rate_limit();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = IcmpFilterConfig::new();

        assert!(!config.enabled);
        assert_eq!(config.filter_type, FilterType::Auto);
        assert_eq!(config.direction, Direction::Both);
        assert!(config.interfaces.is_all());
        assert!(config.rate_limit.is_none());
        assert!(config.exempt_ips.is_empty());
        assert!(config.icmp_type_rules.is_empty());
        assert!(config.icmpv6_type_rules.is_empty());
        assert_eq!(config.table_name, "synvoid_icmp");
    }

    #[test]
    fn test_config_builder() {
        let config = IcmpFilterConfig::new()
            .with_enabled(true)
            .with_filter_type(FilterType::Nftables)
            .with_direction(Direction::Inbound);

        assert!(config.enabled);
        assert_eq!(config.filter_type, FilterType::Nftables);
        assert_eq!(config.direction, Direction::Inbound);
    }

    #[test]
    fn test_config_serialization() {
        let config = IcmpFilterConfig::new()
            .with_enabled(true)
            .with_filter_type(FilterType::Nftables);

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: IcmpFilterConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.filter_type, deserialized.filter_type);
    }

    #[test]
    fn test_interface_spec() {
        let all = InterfaceSpec::All;
        assert!(all.is_all());
        assert!(all.interfaces().is_none());

        let specific = InterfaceSpec::Specific(vec!["eth0".to_string(), "eth1".to_string()]);
        assert!(!specific.is_all());
        let ifaces = specific.interfaces().unwrap();
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0], "eth0");
        assert_eq!(ifaces[1], "eth1");
    }

    #[test]
    fn test_rate_limit_config() {
        let rate_limit = RateLimitConfig {
            enabled: true,
            packets_per_second: 10,
            burst: 20,
        };

        assert!(rate_limit.enabled);
        assert_eq!(rate_limit.packets_per_second, 10);
        assert_eq!(rate_limit.burst, 20);
    }

    #[test]
    fn test_filter_type_serde() {
        let types = vec![
            FilterType::Auto,
            FilterType::Nftables,
            FilterType::Ebpf,
            FilterType::Pf,
            FilterType::WindowsFirewall,
            FilterType::Wfp,
        ];

        for ft in types {
            let json = serde_json::to_string(&ft).unwrap();
            let deserialized: FilterType = serde_json::from_str(&json).unwrap();
            assert_eq!(ft, deserialized);
        }
    }

    #[test]
    fn test_direction_serde() {
        let directions = vec![Direction::Both, Direction::Inbound, Direction::Outbound];

        for dir in directions {
            let json = serde_json::to_string(&dir).unwrap();
            let deserialized: Direction = serde_json::from_str(&json).unwrap();
            assert_eq!(dir, deserialized);
        }
    }

    #[test]
    fn test_icmp_type_rule() {
        let rule = IcmpTypeRule::new(icmp_types::v4::ECHO_REQUEST, IcmpAction::Block)
            .with_description("Block ping");

        assert_eq!(rule.icmp_type, 8);
        assert!(rule.icmp_code.is_none());
        assert!(rule.is_block());
        assert!(!rule.is_allow());
        assert_eq!(rule.description.as_deref(), Some("Block ping"));
    }

    #[test]
    fn test_icmp_type_rule_with_code() {
        let rule = IcmpTypeRule::new(icmp_types::v4::DESTINATION_UNREACHABLE, IcmpAction::Allow)
            .with_code(3);

        assert_eq!(rule.icmp_type, 3);
        assert_eq!(rule.icmp_code, Some(3));
        assert!(rule.is_allow());
    }

    #[test]
    fn test_icmp_type_rule_serde() {
        let rule = IcmpTypeRule {
            icmp_type: 8,
            icmp_code: Some(0),
            action: IcmpAction::Block,
            description: Some("Echo request".to_string()),
        };

        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: IcmpTypeRule = serde_json::from_str(&json).unwrap();

        assert_eq!(rule.icmp_type, deserialized.icmp_type);
        assert_eq!(rule.icmp_code, deserialized.icmp_code);
        assert_eq!(rule.action, deserialized.action);
    }

    #[test]
    fn test_config_with_type_rules() {
        let config = IcmpFilterConfig::new()
            .with_icmp_type_rules(vec![IcmpTypeRule::new(
                icmp_types::v4::ECHO_REQUEST,
                IcmpAction::Block,
            )])
            .with_icmpv6_type_rules(vec![IcmpTypeRule::new(
                icmp_types::v6::ECHO_REQUEST,
                IcmpAction::Block,
            )]);

        assert!(config.has_type_rules());
        assert_eq!(config.icmp_type_rules.len(), 1);
        assert_eq!(config.icmpv6_type_rules.len(), 1);
    }

    #[test]
    fn test_icmp_action_serde() {
        let actions = vec![IcmpAction::Block, IcmpAction::Allow];

        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let deserialized: IcmpAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, deserialized);
        }
    }

    #[test]
    fn test_is_valid_identifier() {
        assert!(is_valid_identifier("valid_name"));
        assert!(is_valid_identifier("valid-name"));
        assert!(is_valid_identifier("valid123"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("invalid name"));
        assert!(!is_valid_identifier("invalid!name"));
        assert!(!is_valid_identifier(&"a".repeat(65)));
    }

    #[test]
    fn test_is_valid_interface_name() {
        assert!(is_valid_interface_name("eth0"));
        assert!(is_valid_interface_name("wlan0"));
        assert!(is_valid_interface_name("en0"));
        assert!(!is_valid_interface_name(""));
        assert!(!is_valid_interface_name("invalid name"));
        assert!(!is_valid_interface_name(&"a".repeat(16)));
    }

    #[test]
    fn test_config_validation() {
        let valid_config = IcmpFilterConfig::new();
        assert!(valid_config.validate().is_ok());

        let invalid_table = IcmpFilterConfig::new().with_table_name("invalid table!".to_string());
        assert!(invalid_table.validate().is_err());

        let invalid_interface = IcmpFilterConfig::new()
            .with_interfaces(InterfaceSpec::Specific(vec!["invalid name".to_string()]));
        assert!(invalid_interface.validate().is_err());
    }

    #[test]
    fn test_icmp_type_rule_validation() {
        let valid_v4_rule = IcmpTypeRule::new(8, IcmpAction::Block);
        assert!(valid_v4_rule.validate(false).is_ok());

        let valid_v6_rule = IcmpTypeRule::new(128, IcmpAction::Block);
        assert!(valid_v6_rule.validate(true).is_ok());

        let invalid_v6_type = IcmpTypeRule::new(5, IcmpAction::Block);
        assert!(invalid_v6_type.validate(true).is_err());

        let long_desc = IcmpTypeRule::new(8, IcmpAction::Block).with_description("x".repeat(257));
        assert!(long_desc.validate(false).is_err());
    }

    #[test]
    fn test_config_with_ebpf_path() {
        let config = IcmpFilterConfig::new().with_ebpf_bytecode_path("/custom/path/bpf.o");

        assert_eq!(
            config.ebpf_bytecode_path,
            Some("/custom/path/bpf.o".to_string())
        );
    }
}
