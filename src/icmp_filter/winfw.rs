/*
 * Windows Firewall (netsh/API) ICMP Backend
 *
 * Capabilities:
 *   - Block/allow ICMP by direction (inbound/outbound/both)
 *   - Per-IP exemption (IPv4 and IPv6)
 *   - ICMP type/code matching
 *   - Interface filtering
 *   - No built-in rate limiting (Windows Firewall API has no rate-limit primitives)
 *
 * Required privilege: Administrator (checked via platform::is_admin)
 *
 * INJECTION WARNING: The windows_firewall crate abstracts the netsh/PowerShell calls.
 * If this backend is modified to shell out to netsh or PowerShell directly, all arguments
 * (rule names, IPs, interface names) MUST be validated against injection. The config
 * validation in IcmpFilterConfig::validate() restricts table names to alphanumeric plus
 * underscore/hyphen, and interface names to alphanumeric plus underscore/dot/hyphen, which
 * mitigates shell injection when these values are interpolated into command arguments.
 *
 * When is_enforcing() == false: the filter was created without admin rights;
 * no Windows Firewall rules are actually created.
 */

use crate::icmp_filter::{
    config::{Direction, IcmpFilterConfig, IcmpTypeRule, InterfaceSpec},
    error::{IcmpFilterError, Result},
    platform::is_admin,
    traits::{FilterBackend, FilterStatus, IcmpFilter},
};
use std::net::IpAddr;

const RULE_PREFIX: &str = "Maluwaf_ICMP";

#[derive(Debug)]
pub struct WinFwFilter {
    config: IcmpFilterConfig,
    enabled: bool,
    has_admin: bool,
    rule_names: Vec<String>,
}

impl WinFwFilter {
    pub fn new(config: IcmpFilterConfig) -> Result<Self> {
        config.validate().map_err(IcmpFilterError::Config)?;
        let has_admin = is_admin();

        if !has_admin {
            tracing::warn!(
                "ICMP filtering requires administrator privileges. \
                 Filter will be created in disabled state."
            );
        }

        Ok(Self {
            config,
            enabled: false,
            has_admin,
            rule_names: Vec::new(),
        })
    }

    fn create_block_rules(&mut self) -> Result<()> {
        if !self.has_admin {
            tracing::warn!("Cannot create firewall rules without administrator privileges");
            return Err(IcmpFilterError::PermissionDenied);
        }

        #[cfg(feature = "icmp-winfw")]
        {
            use windows_firewall::{
                ActionFirewallWindows, DirectionFirewallWindows, ProfileFirewallWindows,
                ProtocolFirewallWindows, WindowsFirewallRule,
            };

            let profiles = ProfileFirewallWindows::all();

            let block_in = matches!(self.config.direction, Direction::Inbound | Direction::Both);
            let block_out = matches!(self.config.direction, Direction::Outbound | Direction::Both);

            self.rule_names.clear();

            let interfaces: Option<Vec<String>> = match &self.config.interfaces {
                InterfaceSpec::All => None,
                InterfaceSpec::Specific(ifaces) => Some(ifaces.clone()),
            };

            if !self.config.exempt_ips.is_empty() {
                for ip in &self.config.exempt_ips {
                    if block_in {
                        let rule_name = format!("{}_Exempt_{}_In", RULE_PREFIX, ip);
                        self.create_exempt_rule(
                            ip,
                            DirectionFirewallWindows::In,
                            interfaces.as_deref(),
                            profiles,
                            &rule_name,
                        )?;
                        self.rule_names.push(rule_name);
                    }
                    if block_out {
                        let rule_name = format!("{}_Exempt_{}_Out", RULE_PREFIX, ip);
                        self.create_exempt_rule(
                            ip,
                            DirectionFirewallWindows::Out,
                            interfaces.as_deref(),
                            profiles,
                            &rule_name,
                        )?;
                        self.rule_names.push(rule_name);
                    }
                }
            }

            if self.config.has_type_rules() {
                self.create_type_rules(
                    block_in,
                    block_out,
                    interfaces.as_deref(),
                    profiles,
                    &self.config.icmp_type_rules,
                    &self.config.icmpv6_type_rules,
                )?;
            }

            let add_icmp_block = |name: String,
                                  direction: DirectionFirewallWindows,
                                  protocol: ProtocolFirewallWindows,
                                  ifaces: Option<&[String]>,
                                  profiles: ProfileFirewallWindows|
             -> Result<()> {
                let mut builder = WindowsFirewallRule::builder()
                    .name(&name)
                    .action(ActionFirewallWindows::Block)
                    .direction(direction)
                    .enabled(true)
                    .protocol(protocol)
                    .description("Maluwaf ICMP blocking rule")
                    .profiles(profiles);

                if let Some(iface_list) = ifaces {
                    builder = builder.interfaces(iface_list.iter().cloned().collect());
                }

                let rule = builder.build();

                rule.add().map_err(|e| {
                    IcmpFilterError::WindowsFirewall(format!(
                        "Failed to add rule '{}': {}",
                        name, e
                    ))
                })?;

                Ok(())
            };

            if block_in {
                let rule_name = format!("{}_Block_In", RULE_PREFIX);
                add_icmp_block(
                    rule_name.clone(),
                    DirectionFirewallWindows::In,
                    ProtocolFirewallWindows::Icmpv4,
                    interfaces.as_deref(),
                    profiles,
                )?;
                self.rule_names.push(rule_name);

                let rule_name = format!("{}_Blockv6_In", RULE_PREFIX);
                add_icmp_block(
                    rule_name.clone(),
                    DirectionFirewallWindows::In,
                    ProtocolFirewallWindows::Icmpv6,
                    interfaces.as_deref(),
                    profiles,
                )?;
                self.rule_names.push(rule_name);
            }

            if block_out {
                let rule_name = format!("{}_Block_Out", RULE_PREFIX);
                add_icmp_block(
                    rule_name.clone(),
                    DirectionFirewallWindows::Out,
                    ProtocolFirewallWindows::Icmpv4,
                    interfaces.as_deref(),
                    profiles,
                )?;
                self.rule_names.push(rule_name);

                let rule_name = format!("{}_Blockv6_Out", RULE_PREFIX);
                add_icmp_block(
                    rule_name.clone(),
                    DirectionFirewallWindows::Out,
                    ProtocolFirewallWindows::Icmpv6,
                    interfaces.as_deref(),
                    profiles,
                )?;
                self.rule_names.push(rule_name);
            }

            tracing::info!(
                "Windows Firewall ICMP blocking rules created ({} rules, {} exempt IPs)",
                self.rule_names.len(),
                self.config.exempt_ips.len()
            );
        }

        #[cfg(not(feature = "icmp-winfw"))]
        {
            return Err(IcmpFilterError::FeatureNotEnabled(
                "icmp-winfw feature not enabled".to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(feature = "icmp-winfw")]
    fn create_exempt_rule(
        &self,
        ip: &IpAddr,
        direction: DirectionFirewallWindows,
        interfaces: Option<&[String]>,
        profiles: ProfileFirewallWindows,
        rule_name: &str,
    ) -> Result<()> {
        use windows_firewall::{
            ActionFirewallWindows, ProtocolFirewallWindows, WindowsFirewallRule,
        };

        let protocol = match ip {
            IpAddr::V4(_) => ProtocolFirewallWindows::Icmpv4,
            IpAddr::V6(_) => ProtocolFirewallWindows::Icmpv6,
        };

        let mut builder = WindowsFirewallRule::builder()
            .name(rule_name)
            .action(ActionFirewallWindows::Allow)
            .direction(direction)
            .enabled(true)
            .protocol(protocol)
            .remote_addresses([*ip].into_iter().collect())
            .description("Maluwaf ICMP exempt rule")
            .profiles(profiles);

        if let Some(iface_list) = interfaces {
            builder = builder.interfaces(iface_list.iter().cloned().collect());
        }

        let rule = builder.build();

        rule.add().map_err(|e| {
            IcmpFilterError::WindowsFirewall(format!(
                "Failed to add exempt rule '{}': {}",
                rule_name, e
            ))
        })?;

        Ok(())
    }

    #[cfg(feature = "icmp-winfw")]
    fn create_type_rules(
        &mut self,
        block_in: bool,
        block_out: bool,
        interfaces: Option<&[String]>,
        profiles: ProfileFirewallWindows,
        icmp_rules: &[IcmpTypeRule],
        icmpv6_rules: &[IcmpTypeRule],
    ) -> Result<()> {
        use windows_firewall::{
            ActionFirewallWindows, DirectionFirewallWindows, ProtocolFirewallWindows,
            WindowsFirewallRule,
        };

        for rule in icmp_rules {
            let action = if rule.is_block() {
                ActionFirewallWindows::Block
            } else {
                ActionFirewallWindows::Allow
            };

            let icmp_type_str = if let Some(code) = rule.icmp_code {
                format!("{}:{}", rule.icmp_type, code)
            } else {
                rule.icmp_type.to_string()
            };

            if block_in {
                let rule_name = format!("{}_Type{}_In", RULE_PREFIX, rule.icmp_type);
                let mut builder = WindowsFirewallRule::builder()
                    .name(&rule_name)
                    .action(action)
                    .direction(DirectionFirewallWindows::In)
                    .enabled(true)
                    .protocol(ProtocolFirewallWindows::Icmpv4)
                    .icmp_types_and_codes(icmp_type_str.clone())
                    .description(
                        rule.description
                            .as_deref()
                            .unwrap_or("Maluwaf ICMP type filter"),
                    )
                    .profiles(profiles);

                if let Some(iface_list) = interfaces {
                    builder = builder.interfaces(iface_list.iter().cloned().collect());
                }

                builder.build().add().map_err(|e| {
                    IcmpFilterError::WindowsFirewall(format!("Failed to add ICMP type rule: {}", e))
                })?;
                self.rule_names.push(rule_name);
            }

            if block_out {
                let rule_name = format!("{}_Type{}_Out", RULE_PREFIX, rule.icmp_type);
                let mut builder = WindowsFirewallRule::builder()
                    .name(&rule_name)
                    .action(action)
                    .direction(DirectionFirewallWindows::Out)
                    .enabled(true)
                    .protocol(ProtocolFirewallWindows::Icmpv4)
                    .icmp_types_and_codes(icmp_type_str.clone())
                    .description(
                        rule.description
                            .as_deref()
                            .unwrap_or("Maluwaf ICMP type filter"),
                    )
                    .profiles(profiles);

                if let Some(iface_list) = interfaces {
                    builder = builder.interfaces(iface_list.iter().cloned().collect());
                }

                builder.build().add().map_err(|e| {
                    IcmpFilterError::WindowsFirewall(format!("Failed to add ICMP type rule: {}", e))
                })?;
                self.rule_names.push(rule_name);
            }
        }

        for rule in icmpv6_rules {
            let action = if rule.is_block() {
                ActionFirewallWindows::Block
            } else {
                ActionFirewallWindows::Allow
            };

            let icmp_type_str = if let Some(code) = rule.icmp_code {
                format!("{}:{}", rule.icmp_type, code)
            } else {
                rule.icmp_type.to_string()
            };

            if block_in {
                let rule_name = format!("{}_Typev6_{}_In", RULE_PREFIX, rule.icmp_type);
                let mut builder = WindowsFirewallRule::builder()
                    .name(&rule_name)
                    .action(action)
                    .direction(DirectionFirewallWindows::In)
                    .enabled(true)
                    .protocol(ProtocolFirewallWindows::Icmpv6)
                    .icmp_types_and_codes(icmp_type_str.clone())
                    .description(
                        rule.description
                            .as_deref()
                            .unwrap_or("Maluwaf ICMPv6 type filter"),
                    )
                    .profiles(profiles);

                if let Some(iface_list) = interfaces {
                    builder = builder.interfaces(iface_list.iter().cloned().collect());
                }

                builder.build().add().map_err(|e| {
                    IcmpFilterError::WindowsFirewall(format!(
                        "Failed to add ICMPv6 type rule: {}",
                        e
                    ))
                })?;
                self.rule_names.push(rule_name);
            }

            if block_out {
                let rule_name = format!("{}_Typev6_{}_Out", RULE_PREFIX, rule.icmp_type);
                let mut builder = WindowsFirewallRule::builder()
                    .name(&rule_name)
                    .action(action)
                    .direction(DirectionFirewallWindows::Out)
                    .enabled(true)
                    .protocol(ProtocolFirewallWindows::Icmpv6)
                    .icmp_types_and_codes(icmp_type_str.clone())
                    .description(
                        rule.description
                            .as_deref()
                            .unwrap_or("Maluwaf ICMPv6 type filter"),
                    )
                    .profiles(profiles);

                if let Some(iface_list) = interfaces {
                    builder = builder.interfaces(iface_list.iter().cloned().collect());
                }

                builder.build().add().map_err(|e| {
                    IcmpFilterError::WindowsFirewall(format!(
                        "Failed to add ICMPv6 type rule: {}",
                        e
                    ))
                })?;
                self.rule_names.push(rule_name);
            }
        }

        Ok(())
    }

    fn remove_block_rules(&self) -> Result<()> {
        if !self.has_admin {
            tracing::warn!(
                "Windows Firewall backend inactive: skipping rule removal (no admin privileges). \
                 {} rule names remain tracked but are not enforced.",
                self.rule_names.len()
            );
            return Ok(());
        }

        #[cfg(feature = "icmp-winfw")]
        {
            use windows_firewall::remove_rule;

            let mut errors = Vec::new();
            for rule_name in &self.rule_names {
                if let Err(e) = remove_rule(rule_name) {
                    errors.push((rule_name.clone(), e));
                }
            }

            if !errors.is_empty() {
                tracing::warn!(
                    "Failed to remove some Windows Firewall rules: {:?}",
                    errors
                        .iter()
                        .map(|(name, e)| format!("{}: {}", name, e))
                        .collect::<Vec<_>>()
                );
            }

            tracing::info!("Windows Firewall ICMP blocking rules removed");
        }

        Ok(())
    }

    pub fn is_available() -> bool {
        #[cfg(feature = "icmp-winfw")]
        {
            true
        }
        #[cfg(not(feature = "icmp-winfw"))]
        {
            false
        }
    }
}

impl IcmpFilter for WinFwFilter {
    fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(IcmpFilterError::AlreadyEnabled);
        }

        if !self.has_admin {
            return Err(IcmpFilterError::PermissionDenied);
        }

        self.create_block_rules()?;
        self.enabled = true;
        tracing::info!("ICMP filter enabled via Windows Firewall");
        Ok(())
    }

    fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(IcmpFilterError::AlreadyDisabled);
        }

        self.remove_block_rules()?;
        self.enabled = false;
        tracing::info!("ICMP filter disabled via Windows Firewall");
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn is_enforcing(&self) -> bool {
        self.enabled && self.has_admin
    }

    fn backend(&self) -> FilterBackend {
        FilterBackend::WindowsFirewall
    }

    fn status(&self) -> FilterStatus {
        FilterStatus {
            enabled: self.enabled,
            backend: FilterBackend::WindowsFirewall,
            config: self.config.clone(),
        }
    }

    fn update_config(&mut self, config: IcmpFilterConfig) -> Result<()> {
        config.validate().map_err(IcmpFilterError::Config)?;
        let was_enabled = self.enabled;

        if was_enabled {
            self.remove_block_rules()?;
        }

        self.config = config;

        if was_enabled && self.config.enabled {
            self.create_block_rules()?;
        }

        if !self.has_admin {
            tracing::warn!(
                "Windows Firewall backend is not enforcing: administrator privileges not held. \
                 Config updated but changes will not take effect until process runs as admin."
            );
        }

        Ok(())
    }

    fn config(&self) -> &IcmpFilterConfig {
        &self.config
    }
}

impl Drop for WinFwFilter {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(e) = self.remove_block_rules() {
                tracing::warn!("Failed to remove Windows Firewall rules on drop: {}", e);
            }
        }
    }
}

#[cfg(all(test, feature = "icmp-winfw"))]
mod tests {
    use super::*;

    #[test]
    fn test_winfw_not_enforcing_without_admin() {
        let config = IcmpFilterConfig::default();
        let filter = WinFwFilter::new(config).expect("new should succeed");
        assert!(!filter.is_enforcing());
        assert!(!filter.is_enabled());
    }

    #[test]
    fn test_winfw_enable_fails_without_admin() {
        let config = IcmpFilterConfig::default();
        let mut filter = WinFwFilter::new(config).expect("new should succeed");
        if !filter.has_admin {
            let result = filter.enable();
            assert!(result.is_err());
        }
    }
}
