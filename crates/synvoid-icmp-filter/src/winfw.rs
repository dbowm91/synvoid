//! Windows Firewall (COM) ICMP backend — documented compatibility fallback.
//!
//! Outcome A (Phase 86): WFP is the primary lane. This COM lane is retained
//! for Defender/GPO-visible rules with honestly reduced guarantees:
//! - no engine transactions: replacement is staged (upsert new generation,
//!   verify, remove stale) with best-effort rollback; unprovable rollback
//!   surfaces `Unknown`, never a false `Applied`;
//! - no rate limiting (constructor rejects it);
//! - readback is per-rule existence (`rule_exists`), not semantic proof.
//!
//! Ownership is table-scoped (`winfw_rule_prefix(table)`); one table has one
//! owner. COM rules persist across process exit, so disable sweeps tracked
//! names plus the legacy unscoped prefix best-effort.
//!
//! Cross-compilation is compile evidence only; native proof is Phase 88.

use crate::{
    compat::adapt_config_to_policy,
    config::{Direction, IcmpFilterConfig, IcmpTypeRule, InterfaceSpec},
    enforce::{
        policy_fingerprint, winfw_rule_prefix, EnforcementPlan, VerificationOutcome,
        WINFW_LEGACY_PREFIX,
    },
    error::{IcmpFilterError, Result},
    platform::is_admin,
    traits::{check_policy_compatibility, FilterBackend, FilterStatus, IcmpFilter},
};

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
        let (policy, _) = adapt_config_to_policy(&config).map_err(IcmpFilterError::from)?;
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

    fn planned_fingerprint_for(config: &IcmpFilterConfig) -> Result<u64> {
        let (policy, _) = adapt_config_to_policy(config).map_err(IcmpFilterError::from)?;
        Ok(policy_fingerprint(&policy))
    }

    /// Install one generation, returning owned rule names. Upserts are
    /// idempotent (`add_rule_or_update`); names adopt only on success.
    fn install_rules(config: &IcmpFilterConfig, has_admin: bool) -> Result<Vec<String>> {
        if !has_admin {
            tracing::warn!("Cannot create firewall rules without administrator privileges");
            return Err(IcmpFilterError::PermissionDenied);
        }

        #[cfg(feature = "icmp-winfw")]
        {
            use windows_firewall::{
                Action, Direction as FwDirection, FirewallRule, Profile, Protocol,
            };

            let prefix = winfw_rule_prefix(&config.table_name);
            let block_in = matches!(config.direction, Direction::Inbound | Direction::Both);
            let block_out = matches!(config.direction, Direction::Outbound | Direction::Both);

            let mut names = Vec::new();
            let interfaces: Option<Vec<String>> = match &config.interfaces {
                InterfaceSpec::All => None,
                InterfaceSpec::Specific(ifaces) => Some(ifaces.clone()),
            };

            for ip in &config.exempt_ips {
                if block_in {
                    let rule_name = format!("{prefix}_Exempt_{ip}_In");
                    Self::upsert_exempt_rule(
                        ip,
                        FwDirection::In,
                        interfaces.as_deref(),
                        &rule_name,
                    )?;
                    names.push(rule_name);
                }
                if block_out {
                    let rule_name = format!("{prefix}_Exempt_{ip}_Out");
                    Self::upsert_exempt_rule(
                        ip,
                        FwDirection::Out,
                        interfaces.as_deref(),
                        &rule_name,
                    )?;
                    names.push(rule_name);
                }
            }

            names.extend(Self::upsert_type_rules(
                block_in,
                block_out,
                interfaces.as_deref(),
                &prefix,
                &config.icmp_type_rules,
                &config.icmpv6_type_rules,
            )?);

            let upsert_block = |name: String,
                                direction: FwDirection,
                                protocol: Protocol,
                                ifaces: Option<&[String]>|
             -> Result<()> {
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

                upsert(&rule).map_err(|e| {
                    IcmpFilterError::WindowsFirewall(format!("Failed to upsert rule '{name}': {e}"))
                })?;

                Ok(())
            };

            if block_in {
                for (suffix, protocol) in [
                    ("Block_In", Protocol::Icmpv4),
                    ("Blockv6_In", Protocol::Icmpv6),
                ] {
                    let rule_name = format!("{prefix}_{suffix}");
                    upsert_block(
                        rule_name.clone(),
                        FwDirection::In,
                        protocol,
                        interfaces.as_deref(),
                    )?;
                    names.push(rule_name);
                }
            }

            if block_out {
                for (suffix, protocol) in [
                    ("Block_Out", Protocol::Icmpv4),
                    ("Blockv6_Out", Protocol::Icmpv6),
                ] {
                    let rule_name = format!("{prefix}_{suffix}");
                    upsert_block(
                        rule_name.clone(),
                        FwDirection::Out,
                        protocol,
                        interfaces.as_deref(),
                    )?;
                    names.push(rule_name);
                }
            }

            tracing::info!(
                "Windows Firewall ICMP generation installed ({} rules, {} exempt IPs)",
                names.len(),
                config.exempt_ips.len()
            );
            return Ok(names);
        }

        #[cfg(not(feature = "icmp-winfw"))]
        {
            let _ = (config, has_admin);
            return Err(IcmpFilterError::FeatureNotEnabled(
                "icmp-winfw feature not enabled".to_string(),
            ));
        }
    }

    #[cfg(feature = "icmp-winfw")]
    fn upsert_exempt_rule(
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

        upsert(&rule).map_err(|e| {
            IcmpFilterError::WindowsFirewall(format!(
                "Failed to upsert exempt rule '{rule_name}': {e}"
            ))
        })?;

        Ok(())
    }

    #[cfg(feature = "icmp-winfw")]
    fn upsert_type_rules(
        block_in: bool,
        block_out: bool,
        interfaces: Option<&[String]>,
        prefix: &str,
        icmp_rules: &[IcmpTypeRule],
        icmpv6_rules: &[IcmpTypeRule],
    ) -> Result<Vec<String>> {
        use windows_firewall::{Action, Direction as FwDirection, FirewallRule, Profile, Protocol};

        let mut names = Vec::new();
        let mut upsert_typed = |rule: &IcmpTypeRule,
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

            let mut built = FirewallRule::builder()
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
            built.set_icmp_types_and_codes(Some(icmp_type_str));

            if let Some(iface_list) = ifaces {
                built.set_interfaces(Some(iface_list.iter().cloned().collect()));
            }

            upsert(&built).map_err(|e| {
                IcmpFilterError::WindowsFirewall(format!(
                    "Failed to upsert ICMP type rule '{rule_name}': {e}"
                ))
            })?;
            names.push(rule_name);
            Ok(())
        };

        for rule in icmp_rules {
            if block_in {
                upsert_typed(
                    rule,
                    Protocol::Icmpv4,
                    FwDirection::In,
                    format!("{prefix}_Type{}_In", rule.icmp_type),
                    interfaces,
                )?;
            }
            if block_out {
                upsert_typed(
                    rule,
                    Protocol::Icmpv4,
                    FwDirection::Out,
                    format!("{prefix}_Type{}_Out", rule.icmp_type),
                    interfaces,
                )?;
            }
        }

        for rule in icmpv6_rules {
            if block_in {
                upsert_typed(
                    rule,
                    Protocol::Icmpv6,
                    FwDirection::In,
                    format!("{prefix}_Typev6_{}_In", rule.icmp_type),
                    interfaces,
                )?;
            }
            if block_out {
                upsert_typed(
                    rule,
                    Protocol::Icmpv6,
                    FwDirection::Out,
                    format!("{prefix}_Typev6_{}_Out", rule.icmp_type),
                    interfaces,
                )?;
            }
        }

        Ok(names)
    }

    /// Remove exactly the named rules; returns the failures instead of
    /// dropping them so callers report partial cleanup visibly.
    #[cfg(feature = "icmp-winfw")]
    fn remove_names(names: &[String]) -> Vec<(String, String)> {
        use windows_firewall::remove_rule;
        let mut errors = Vec::new();
        for rule_name in names {
            if let Err(e) = remove_rule(rule_name) {
                errors.push((rule_name.clone(), e.to_string()));
            }
        }
        errors
    }

    fn remove_generation(&mut self) -> Result<()> {
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
            let scoped = winfw_rule_prefix(&self.config.table_name);
            let mut errors = Self::remove_names(&self.rule_names);
            self.rule_names.clear();
            // Best-effort sweep of stale rules: legacy unscoped names from
            // pre-Phase-87 installs. Only names under the legacy prefix that
            // are NOT under our scoped prefix are touched (single owner per
            // table); sweep failures are reported, never fatal to tracked
            // cleanup.
            match windows_firewall::list_rules() {
                Ok(rules) => {
                    let stale: Vec<String> = rules
                        .iter()
                        .map(|r| r.name().clone())
                        .filter(|n| n.starts_with(WINFW_LEGACY_PREFIX) && !n.starts_with(&scoped))
                        .collect();
                    errors.extend(Self::remove_names(&stale));
                }
                Err(e) => {
                    tracing::debug!("winfw stale sweep: list_rules failed: {e}");
                }
            }

            if !errors.is_empty() {
                return Err(IcmpFilterError::WindowsFirewall(format!(
                    "Failed to remove some Windows Firewall rules: {:?}",
                    errors
                        .iter()
                        .map(|(name, e)| format!("{name}: {e}"))
                        .collect::<Vec<_>>()
                )));
            }

            tracing::info!("Windows Firewall ICMP generation removed");
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

/// Idempotent upsert (add-or-update by name).
#[cfg(feature = "icmp-winfw")]
fn upsert(rule: &windows_firewall::FirewallRule) -> Result<()> {
    windows_firewall::add_rule_or_update(rule)
        .map(|_| ())
        .map_err(|e| IcmpFilterError::WindowsFirewall(e.to_string()))
}

impl IcmpFilter for WinFwFilter {
    fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(IcmpFilterError::AlreadyEnabled);
        }

        if !self.has_admin {
            return Err(IcmpFilterError::PermissionDenied);
        }

        let _fingerprint = Self::planned_fingerprint_for(&self.config)?;
        let names = Self::install_rules(&self.config, self.has_admin)?;
        self.rule_names = names;
        self.enabled = true;
        tracing::info!("ICMP filter enabled via Windows Firewall");
        Ok(())
    }

    fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(IcmpFilterError::AlreadyDisabled);
        }

        self.remove_generation()?;
        self.enabled = false;
        tracing::info!("ICMP filter disabled via Windows Firewall");
        Ok(())
    }

    fn ensure_disabled(&mut self) -> Result<()> {
        self.remove_generation()?;
        self.enabled = false;
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
        // Compile the replacement before any mutation.
        let _fingerprint = Self::planned_fingerprint_for(&config)?;
        let old = std::mem::replace(&mut self.config, config);
        let was_enabled = self.enabled;
        let want_enabled = self.config.enabled;

        if was_enabled && want_enabled {
            // Bounded staged replacement: upsert the new generation, verify
            // it, then retire stale names. No transaction exists here, so a
            // mid-install failure triggers best-effort rollback of the old
            // generation and an Unknown verdict, never a false Applied.
            let old_names = std::mem::take(&mut self.rule_names);
            match Self::install_rules(&self.config, self.has_admin) {
                Ok(new_names) => {
                    if let Err(e) = self.verify_names(&new_names) {
                        let _ = Self::install_rules(&old, self.has_admin);
                        self.rule_names = old_names;
                        self.config = old;
                        return Err(e);
                    }
                    let stale: Vec<String> = old_names
                        .iter()
                        .filter(|n| !new_names.contains(n))
                        .cloned()
                        .collect();
                    #[cfg(feature = "icmp-winfw")]
                    {
                        let errors = Self::remove_names(&stale);
                        if !errors.is_empty() {
                            // New generation is live but cleanup lagged:
                            // keep tracking the union so a later disable
                            // still converges, and report visibly.
                            self.rule_names =
                                new_names.iter().chain(stale.iter()).cloned().collect();
                            return Err(IcmpFilterError::WindowsFirewall(format!(
                                "Replacement live; stale cleanup failed: {errors:?}"
                            )));
                        }
                    }
                    #[cfg(not(feature = "icmp-winfw"))]
                    {
                        let _ = stale;
                    }
                    self.rule_names = new_names;
                }
                Err(e) => {
                    let _ = Self::install_rules(&old, self.has_admin);
                    self.rule_names = old_names;
                    self.config = old;
                    return Err(e);
                }
            }
        } else if was_enabled {
            if let Err(e) = self.remove_generation() {
                self.config = old;
                return Err(e);
            }
            self.enabled = false;
        }

        if !self.has_admin {
            tracing::warn!(
                "Windows Firewall backend is not enforcing: administrator privileges not held. \
                 Config updated but changes will not take effect until process runs as admin."
            );
        }

        Ok(())
    }

    fn verify_ownership(&self, plan: &EnforcementPlan) -> VerificationOutcome {
        if !self.enabled {
            return VerificationOutcome::Absent;
        }
        match self.verify_names(&self.rule_names) {
            Ok(()) => {
                let _ = plan.fingerprint;
                VerificationOutcome::Verified
            }
            Err(e) => match e {
                IcmpFilterError::WindowsFirewall(detail) if detail.starts_with("absent:") => {
                    VerificationOutcome::Drifted { detail }
                }
                _ => VerificationOutcome::Unknown {
                    detail: e.to_string(),
                },
            },
        }
    }

    fn config(&self) -> &IcmpFilterConfig {
        &self.config
    }
}

impl WinFwFilter {
    /// Existence readback over tracked names. `Ok` = every name exists;
    /// `WindowsFirewall("absent: ...")` = drift; any other error = Unknown.
    fn verify_names(&self, names: &[String]) -> Result<()> {
        #[cfg(feature = "icmp-winfw")]
        {
            for name in names {
                match windows_firewall::rule_exists(name) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(IcmpFilterError::WindowsFirewall(format!(
                            "absent: tracked rule '{name}' missing live"
                        )));
                    }
                    Err(e) => {
                        return Err(IcmpFilterError::WindowsFirewall(format!(
                            "readback unavailable for '{name}': {e}"
                        )));
                    }
                }
            }
            return Ok(());
        }
        #[cfg(not(feature = "icmp-winfw"))]
        {
            let _ = names;
            return Err(IcmpFilterError::FeatureNotEnabled(
                "icmp-winfw feature not enabled".to_string(),
            ));
        }
    }
}

impl Drop for WinFwFilter {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(e) = self.remove_generation() {
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
