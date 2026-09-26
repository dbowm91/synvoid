use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Canonical operational interface-name rule shared with the enforcement
/// crate adapter: 1-15 chars, alphanumeric plus `_`, `.`, `-`.
/// Table names keep the wider 64-char identifier rule; interfaces do not.
pub fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
pub enum FilterType {
    #[default]
    #[serde(alias = "auto")]
    Auto,
    #[serde(alias = "nftables")]
    Nftables,
    #[serde(alias = "ebpf")]
    Ebpf,
    #[serde(alias = "pf")]
    Pf,
    #[serde(alias = "windowsfirewall")]
    #[serde(alias = "windows_firewall")]
    WindowsFirewall,
    #[serde(alias = "wfp")]
    Wfp,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
pub enum IcmpAction {
    #[default]
    #[serde(alias = "block")]
    Block,
    #[serde(alias = "allow")]
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
    #[serde(alias = "both")]
    Both,
    #[serde(alias = "inbound")]
    Inbound,
    #[serde(alias = "outbound")]
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema, Default)]
#[serde(untagged)]
pub enum InterfaceSpec {
    #[default]
    All,
    Specific(Vec<String>),
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
    /// Explicit scope. The first contract supports only `global` (the
    /// semantics current backends truthfully implement). Unknown scopes are
    /// rejected by the typed adapter, never emulated.
    #[serde(default)]
    pub scope: RateLimitScope,
}

/// Rate-limit scope DTO. Single-variant today; the adapter treats any other
/// deserialized spelling as invalid rather than defaulting silently.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitScope {
    #[default]
    #[serde(alias = "Global")]
    Global,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct IcmpFilterConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub filter_type: FilterType,

    #[serde(default)]
    pub direction: Direction,

    // `All` serializes as null under the untagged representation, which TOML
    // cannot represent (`toml::to_string_pretty` errors and every config PUT
    // then persists with 500). Omitting the default preserves the round-trip:
    // a missing key deserializes back to `All` via the field + type defaults.
    #[serde(default, skip_serializing_if = "InterfaceSpec::is_all")]
    pub interfaces: InterfaceSpec,

    #[serde(default = "default_table_name")]
    pub table_name: String,

    #[serde(default)]
    pub exempt_ips: Vec<String>,

    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    #[serde(default)]
    pub icmp_type_rules: Vec<IcmpTypeRule>,

    /// ICMPv6 rule list. Absent in legacy persisted configs (deserializes to
    /// empty); legacy v4 rules are never reinterpreted as v6 — the adapter
    /// maps each list under its documented family.
    #[serde(default)]
    pub icmpv6_type_rules: Vec<IcmpTypeRule>,

    /// Preferred application spelling is `custom_ebpf_bytecode_path`.
    /// The enforcement-crate spelling `ebpf_bytecode_path` is accepted on
    /// read via alias; the typed adapter canonicalizes to one internal value.
    #[serde(default, alias = "ebpf_bytecode_path")]
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
            icmpv6_type_rules: Vec::new(),
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
                if !is_valid_interface_name(iface) {
                    return Err(format!("Invalid interface name: {}", iface));
                }
            }
        }

        for ip in &self.exempt_ips {
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err(format!("Invalid IP address in exempt_ips: {}", ip));
            }
        }

        if self.rate_limit.enabled && self.rate_limit.packets_per_second == 0 {
            return Err("Rate limit enabled but packets_per_second is 0".to_string());
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
        assert_eq!(
            config.custom_ebpf_bytecode_path,
            Some("/tmp/test.o".to_string())
        );
    }

    #[test]
    fn test_serialization() {
        let config = IcmpFilterConfig::new().with_table_name("waf_rules".to_string());

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: IcmpFilterConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.table_name, "waf_rules");
    }

    #[test]
    fn test_toml_round_trip_default_interfaces() {
        // Regression: `InterfaceSpec::All` under the untagged representation
        // serializes as null, which TOML cannot represent. The field is
        // skipped when default so every config PUT can persist (previously
        // all persists returned 500 with `icmp-filter` enabled).
        let config = IcmpFilterConfig::new();
        let toml_str =
            toml::to_string_pretty(&config).expect("default config must serialize to TOML");
        let round_tripped: IcmpFilterConfig =
            toml::from_str(&toml_str).expect("default config must deserialize from TOML");
        assert!(round_tripped.interfaces.is_all());
        assert_eq!(round_tripped.table_name, "synvoid-icmp");
    }

    #[test]
    fn test_toml_round_trip_specific_interfaces() {
        let mut config = IcmpFilterConfig::new();
        config.interfaces = InterfaceSpec::Specific(vec!["eth0".to_string()]);
        let toml_str =
            toml::to_string_pretty(&config).expect("specific config must serialize to TOML");
        assert!(toml_str.contains("eth0"));
        let round_tripped: IcmpFilterConfig =
            toml::from_str(&toml_str).expect("specific config must deserialize from TOML");
        assert_eq!(
            round_tripped.interfaces.interfaces(),
            Some(&["eth0".to_string()][..])
        );
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

    #[test]
    fn test_v6_list_defaults_empty_legacy_compat() {
        // Legacy persisted configs omit the v6 list; it defaults to empty and
        // legacy v4 rules are never reinterpreted as v6.
        let json = r#"{"enabled":false,"icmp_type_rules":[]}"#;
        let cfg: IcmpFilterConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.icmpv6_type_rules.is_empty());
        assert!(cfg.icmp_type_rules.is_empty());
    }

    #[test]
    fn test_lowercase_enum_aliases_accepted() {
        let json = r#"{"enabled":false,"filter_type":"nftables","direction":"inbound"}"#;
        let cfg: IcmpFilterConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.filter_type, FilterType::Nftables);
        assert_eq!(cfg.direction, Direction::Inbound);
    }

    #[test]
    fn test_ebpf_path_alias_accepted() {
        // Enforcement-crate spelling reads into the application field.
        let toml_str = "ebpf_bytecode_path = \"/tmp/bpf.o\"\n";
        let cfg: IcmpFilterConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            cfg.custom_ebpf_bytecode_path,
            Some("/tmp/bpf.o".to_string())
        );
    }

    #[test]
    fn test_interface_validation_operational_rule() {
        assert!(is_valid_interface_name("eth0"));
        assert!(is_valid_interface_name("enp0s3.100"));
        assert!(!is_valid_interface_name("bad name!"));
        assert!(!is_valid_interface_name(&"a".repeat(16)));
        let mut cfg = IcmpFilterConfig::new();
        cfg.interfaces = InterfaceSpec::Specific(vec!["bad name!".to_string()]);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_rate_limit_scope_defaults_global() {
        let cfg = IcmpFilterConfig::new();
        assert_eq!(cfg.rate_limit.scope, RateLimitScope::Global);
        let json = serde_json::to_string(&cfg.rate_limit).unwrap();
        assert!(json.contains("global"));
    }
}
