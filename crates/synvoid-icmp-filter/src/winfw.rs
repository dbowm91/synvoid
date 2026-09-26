//! Windows Firewall (COM) ICMP backend — documented compatibility fallback.
//!
//! Outcome A (Phase 86): WFP (`wfp.rs`) is the primary Windows lane. This
//! COM lane is retained because its rules are visible to the Windows
//! Defender Firewall UI/GPO tooling (distinct operational value), with
//! reduced guarantees stated honestly:
//! - no engine transactions (rules are added/removed one by one);
//! - no rate limiting (the COM API has no rate-limit primitive; the
//!   constructor rejects rate-limited policy);
//! - no live readback (Phase 87 records this lane as `Unknown`-capped).
//!
//! Interface filtering takes adapter friendly names directly (no LUID
//! resolution needed — the lane's remaining convenience).
//!
//! Required privilege: Administrator (checked via `platform::is_admin`).
//!
//! Cross-compilation is compile evidence only; native proof is Phase 88.

use crate::{
    config::{Direction, IcmpFilterConfig, IcmpTypeRule, InterfaceSpec},
    error::{IcmpFilterError, Result},
    platform::is_admin,
    traits::{check_policy_compatibility, FilterBackend, FilterStatus, IcmpFilter},
};

const RULE_PREFIX: &str = "synvoid_ICMP";

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
        // Admit only policy this lane expresses exactly (no rate limit).
        let (policy, _) =
            crate::compat::adapt_config_to_policy(&config).map_err(IcmpFilterError::from)?;
        if let Err(mismatches) = check_policy_compatibility(FilterBackend::WindowsFirewall, &policy)
        {
            let detail = mismatches
                .iter()
                .map(|m| format!("{}: {}", m.requirement, m.detail))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(IcmpFilterError::Unsupported(format!(
                "Windows Firewall cannot express requested policy: {detail}"
            )));
        }
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
                Action, Direction as FwDirection, FirewallRule, Profile, Protocol,
            };

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
                        Self::add_exempt_rule(
                            ip,
                            FwDirection::In,
                            interfaces.as_deref(),
                            &rule_name,
                        )?;
                        self.rule_names.push(rule_name);
                    }
                    if block_out {
                        let rule_name = format!("{}_Exempt_{}_Out", RULE_PREFIX, ip);
                        Self::add_exempt_rule(
                            ip,
                            FwDirection::Out,
                            interfaces.as_deref(),
                            &rule_name,
                        )?;
                        self.rule_names.push(rule_name);
                    }
                }
            }

            if self.config.has_type_rules() {
                // Clone under the immutable borrow so the `&mut self` call
                // below does not alias config (never compiled before Phase 86,
                // when the missing crate deps hid this borrow error).
                let v4_rules = self.config.icmp_type_rules.clone();
                let v6_rules = self.config.icmpv6_type_rules.clone();
                self.create_type_rules(
                    block_in,
                    block_out,
                    interfaces.as_deref(),
                    &v4_rules,
                    &v6_rules,
                )?;
            }

            let add_icmp_block = |name: String,
                                  direction: FwDirection,
                                  protocol: Protocol,
                                  ifaces: Option<&[String]>|
             -> Result<()> {
                // Optional COM properties are set post-build via getset
                // setters: TypedBuilder changes type-state per optional
                // setter, so conditional chaining cannot reassign one
                // variable.
                let mut rule = FirewallRule::builder()
                    .name(name.clone())
                    .action(Action::Block)
                    .direction(direction)
                    .enabled(true)
                    .protocol(protocol)
                    .description("Synvoid ICMP blocking rule")
                    .profiles(Profile::All)
                    .build();

                if let Some(iface_list) = ifaces {
                    rule.set_interfaces(Some(iface_list.iter().cloned().collect()));
                }

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
                    FwDirection::In,
                    Protocol::Icmpv4,
                    interfaces.as_deref(),
                )?;
                self.rule_names.push(rule_name);

                let rule_name = format!("{}_Blockv6_In", RULE_PREFIX);
                add_icmp_block(
                    rule_name.clone(),
                    FwDirection::In,
                    Protocol::Icmpv6,
                    interfaces.as_deref(),
                )?;
                self.rule_names.push(rule_name);
            }

            if block_out {
                let rule_name = format!("{}_Block_Out", RULE_PREFIX);
                add_icmp_block(
                    rule_name.clone(),
                    FwDirection::Out,
                    Protocol::Icmpv4,
                    interfaces.as_deref(),
                )?;
                self.rule_names.push(rule_name);

                let rule_name = format!("{}_Blockv6_Out", RULE_PREFIX);
                add_icmp_block(
                    rule_name.clone(),
                    FwDirection::Out,
                    Protocol::Icmpv6,
                    interfaces.as_deref(),
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
    fn add_exempt_rule(
        ip: &std::net::IpAddr,
        direction: windows_firewall::Direction,
        interfaces: Option<&[String]>,
        rule_name: &str,
    ) -> Result<()> {
        use windows_firewall::{Action, Address, FirewallRule, Profile, Protocol};

        let protocol = match ip {
            std::net::IpAddr::V4(_) => Protocol::Icmpv4,
            std::net::IpAddr::V6(_) => Protocol::Icmpv6,
        };

        let mut rule = FirewallRule::builder()
            .name(rule_name)
            .action(Action::Allow)
            .direction(direction)
            .enabled(true)
            .protocol(protocol)
            .description("Synvoid ICMP exempt rule")
            .profiles(Profile::All)
            .build();
        rule.set_remote_addresses(Some(vec![Address::Ip(*ip)].into_iter().collect()));

        if let Some(iface_list) = interfaces {
            rule.set_interfaces(Some(iface_list.iter().cloned().collect()));
        }

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
        icmp_rules: &[IcmpTypeRule],
        icmpv6_rules: &[IcmpTypeRule],
    ) -> Result<()> {
        use windows_firewall::{Action, Direction as FwDirection, FirewallRule, Profile, Protocol};

        let mut add_typed = |rule: &IcmpTypeRule,
                             protocol: Protocol,
                             direction: FwDirection,
                             rule_name: String,
                             ifaces: Option<&[String]>|
         -> Result<()> {
            let action = if rule.is_block() {
                Action::Block
            } else {
                Action::Allow
            };

            let icmp_type_str = if let Some(code) = rule.icmp_code {
                format!("{}:{}", rule.icmp_type, code)
            } else {
                rule.icmp_type.to_string()
            };

            let mut rule = FirewallRule::builder()
                .name(rule_name.clone())
                .action(action)
                .direction(direction)
                .enabled(true)
                .protocol(protocol)
                .description(
                    rule.description
                        .as_deref()
                        .unwrap_or("Synvoid ICMP type filter"),
                )
                .profiles(Profile::All)
                .build();
            rule.set_icmp_types_and_codes(Some(icmp_type_str));

            if let Some(iface_list) = ifaces {
                rule.set_interfaces(Some(iface_list.iter().cloned().collect()));
            }

            rule.add().map_err(|e| {
                IcmpFilterError::WindowsFirewall(format!(
                    "Failed to add ICMP type rule '{}': {}",
                    rule_name, e
                ))
            })?;
            self.rule_names.push(rule_name);
            Ok(())
        };

        for rule in icmp_rules {
            if block_in {
                add_typed(
                    rule,
                    Protocol::Icmpv4,
                    FwDirection::In,
                    format!("{}_Type{}_In", RULE_PREFIX, rule.icmp_type),
                    interfaces,
                )?;
            }
            if block_out {
                add_typed(
                    rule,
                    Protocol::Icmpv4,
                    FwDirection::Out,
                    format!("{}_Type{}_Out", RULE_PREFIX, rule.icmp_type),
                    interfaces,
                )?;
            }
        }

        for rule in icmpv6_rules {
            if block_in {
                add_typed(
                    rule,
                    Protocol::Icmpv6,
                    FwDirection::In,
                    format!("{}_Typev6_{}_In", RULE_PREFIX, rule.icmp_type),
                    interfaces,
                )?;
            }
            if block_out {
                add_typed(
                    rule,
                    Protocol::Icmpv6,
                    FwDirection::Out,
                    format!("{}_Typev6_{}_Out", RULE_PREFIX, rule.icmp_type),
                    interfaces,
                )?;
            }
        }

        Ok(())
    }

    fn remove_block_rules(&mut self) -> Result<()> {
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
            for rule_name in self.rule_names.drain(..) {
                if let Err(e) = remove_rule(&rule_name) {
                    errors.push((rule_name, e));
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
