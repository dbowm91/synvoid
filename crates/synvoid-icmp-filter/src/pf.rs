use crate::{
    compat::adapt_config_to_policy,
    config::{Direction, IcmpFilterConfig, IcmpTypeRule, InterfaceSpec},
    enforce::{pf_anchor_for, policy_fingerprint, EnforcementPlan, VerificationOutcome},
    error::{IcmpFilterError, Result},
    traits::{FilterBackend, FilterStatus, IcmpFilter},
};
use std::process::Command;

/// Legacy unscoped anchor (pre-Phase-87). Disable sweeps it best-effort so
/// one upgrade cycle cannot orphan enforcement; new installs use the
/// table-scoped anchor from `enforce::pf_anchor_for`.
const LEGACY_ANCHOR_NAME: &str = "synvoid.icmp";

#[derive(Debug)]
pub struct PfFilter {
    config: IcmpFilterConfig,
    enabled: bool,
}

impl PfFilter {
    pub fn new(config: IcmpFilterConfig) -> Result<Self> {
        config.validate().map_err(IcmpFilterError::Config)?;
        Self::check_pf_available()?;
        Ok(Self {
            config,
            enabled: false,
        })
    }

    fn check_pf_available() -> Result<()> {
        let output = Command::new("pfctl")
            .args(["-s", "info"])
            .output()
            .map_err(|e| IcmpFilterError::Pf(format!("pfctl command not found: {}", e)))?;

        if !output.status.success() {
            return Err(IcmpFilterError::Pf(
                "pfctl command failed to execute".to_string(),
            ));
        }

        Ok(())
    }

    fn anchor(&self) -> String {
        pf_anchor_for(&self.config.table_name)
    }

    /// Cardinality the anchor load installs (exempt passes + per-rule lines
    /// + two base blocks). Mirrors `enforce::expected_rule_count_for` for
    /// the PF lane; readback compares against it.
    fn planned_rule_count(&self) -> usize {
        self.config.exempt_ips.len()
            + self.config.icmp_type_rules.len()
            + self.config.icmpv6_type_rules.len()
            + 2
    }

    /// Compile a config (pure; zero mutation).
    fn planned_fingerprint_for(config: &IcmpFilterConfig) -> Result<u64> {
        let (policy, _) = adapt_config_to_policy(config).map_err(IcmpFilterError::from)?;
        Ok(policy_fingerprint(&policy))
    }

    fn build_rules(&self) -> String {
        let mut rules = String::new();

        let direction = match self.config.direction {
            Direction::Both => "in out",
            Direction::Inbound => "in",
            Direction::Outbound => "out",
        };

        let interface_clause = match &self.config.interfaces {
            InterfaceSpec::All => String::new(),
            InterfaceSpec::Specific(ifaces) => {
                let iface_list: Vec<String> = ifaces.iter().map(|i| format!("on {}", i)).collect();
                format!(" {} ", iface_list.join(" "))
            }
        };

        let rate_clause = if let Some(ref rate_limit) = self.config.rate_limit {
            if rate_limit.enabled {
                format!(
                    " max-src-conn-rate {}/{} overload <icmp_flood> flush global",
                    rate_limit.burst, rate_limit.packets_per_second
                )
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        for ip in &self.config.exempt_ips {
            let (inet, proto) = match ip {
                std::net::IpAddr::V4(_) => ("inet", "icmp"),
                std::net::IpAddr::V6(_) => ("inet6", "icmp6"),
            };
            rules.push_str(&format!(
                "pass {} {} {} proto {} from {} to any\n",
                direction, interface_clause, inet, proto, ip
            ));
        }

        for type_rule in &self.config.icmp_type_rules {
            rules.push_str(&self.build_icmp_type_rule(
                type_rule,
                direction,
                &interface_clause,
                false,
            ));
        }

        for type_rule in &self.config.icmpv6_type_rules {
            rules.push_str(&self.build_icmp_type_rule(
                type_rule,
                direction,
                &interface_clause,
                true,
            ));
        }

        rules.push_str(&format!(
            "block {} {} inet proto icmp all{}\n",
            direction, interface_clause, rate_clause
        ));

        rules.push_str(&format!(
            "block {} {} inet6 proto icmp6 all{}",
            direction, interface_clause, rate_clause
        ));

        rules
    }

    fn build_icmp_type_rule(
        &self,
        rule: &IcmpTypeRule,
        direction: &str,
        interface_clause: &str,
        is_v6: bool,
    ) -> String {
        let action = if rule.is_block() { "block" } else { "pass" };
        let (inet, proto, type_keyword) = if is_v6 {
            ("inet6", "icmp6", "icmp6-type")
        } else {
            ("inet", "icmp", "icmp-type")
        };

        let type_match = if let Some(code) = rule.icmp_code {
            format!("{} {} code {}", type_keyword, rule.icmp_type, code)
        } else {
            format!("{} {}", type_keyword, rule.icmp_type)
        };

        format!(
            "{} {} {} {} proto {} {} all\n",
            action, direction, interface_clause, inet, proto, type_match
        )
    }

    fn enable_pf(&self) -> Result<()> {
        let output = Command::new("pfctl")
            .arg("-e")
            .output()
            .map_err(|e| IcmpFilterError::Pf(format!("Failed to enable PF: {}", e)))?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() && !stderr.contains("already enabled") {
            tracing::debug!("PF enable stderr: {}", stderr);
        }

        Ok(())
    }

    fn add_anchor(&self) -> Result<()> {
        // Single anchor load atomically replaces the owned anchor content:
        // no remove-then-add gap. Stale state from a crashed process is
        // overwritten by the load itself.
        Self::load_anchor(&self.anchor(), &self.build_rules())
    }

    fn load_anchor(anchor: &str, rules: &str) -> Result<()> {
        let output = Command::new("pfctl")
            .args(["-a", anchor, "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();

        let mut child = output
            .map_err(|e| IcmpFilterError::Pf(format!("Failed to spawn pfctl for anchor: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(rules.as_bytes()).map_err(|e| {
                IcmpFilterError::Pf(format!("Failed to write rules to pfctl: {}", e))
            })?;
        }

        let status = child
            .wait()
            .map_err(|e| IcmpFilterError::Pf(format!("Failed to wait for pfctl: {}", e)))?;

        if !status.success() {
            return Err(IcmpFilterError::Pf(format!(
                "pfctl anchor command failed with status: {}",
                status
            )));
        }

        tracing::info!("PF anchor rules loaded successfully");

        Ok(())
    }

    fn remove_anchor(&self) -> Result<()> {
        // Remove the scoped anchor; then best-effort sweep the legacy
        // unscoped anchor so upgrades cannot orphan enforcement. A missing
        // anchor is idempotent success; other failures are visible errors.
        Self::flush_anchor(&self.anchor())?;
        Self::flush_anchor(LEGACY_ANCHOR_NAME)?;
        Ok(())
    }

    fn flush_anchor(anchor: &str) -> Result<()> {
        let output = Command::new("pfctl")
            .args(["-a", anchor, "-F", "all"])
            .output()
            .map_err(|e| IcmpFilterError::Pf(format!("Failed to remove anchor: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("nonexistent") {
                tracing::warn!("pfctl anchor removal stderr: {}", stderr);
            }
        }

        Ok(())
    }

    pub fn is_available() -> bool {
        Command::new("pfctl").args(["-s", "info"]).output().is_ok()
    }
}

impl IcmpFilter for PfFilter {
    fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(IcmpFilterError::AlreadyEnabled);
        }

        // Compile first: nothing is installed for an inexpressible policy.
        let _fingerprint = Self::planned_fingerprint_for(&self.config)?;
        self.enable_pf()?;
        self.add_anchor()?;
        self.enabled = true;
        tracing::info!("ICMP filter enabled via macOS PF");
        Ok(())
    }

    fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(IcmpFilterError::AlreadyDisabled);
        }

        self.remove_anchor()?;
        self.enabled = false;
        tracing::info!("ICMP filter disabled via macOS PF");
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn is_enforcing(&self) -> bool {
        self.enabled
    }

    fn backend(&self) -> FilterBackend {
        FilterBackend::Pf
    }

    fn status(&self) -> FilterStatus {
        FilterStatus {
            enabled: self.enabled,
            backend: FilterBackend::Pf,
            config: self.config.clone(),
        }
    }

    fn update_config(&mut self, config: IcmpFilterConfig) -> Result<()> {
        config.validate().map_err(IcmpFilterError::Config)?;
        // Compile the replacement before mutating anchor state.
        let _fingerprint = Self::planned_fingerprint_for(&config)?;
        let old = std::mem::replace(&mut self.config, config);
        let was_enabled = self.enabled;
        let want_enabled = self.config.enabled;

        if was_enabled && want_enabled {
            // Single load replaces the anchor atomically; the previous
            // generation survives install failure.
            if let Err(e) = self.add_anchor() {
                self.config = old;
                return Err(e);
            }
        } else if was_enabled {
            if let Err(e) = self.remove_anchor() {
                self.config = old;
                return Err(e);
            }
            self.enabled = false;
        }

        Ok(())
    }

    fn verify_ownership(&self, plan: &EnforcementPlan) -> VerificationOutcome {
        if !self.enabled {
            return VerificationOutcome::Absent;
        }
        // Presence-plus-cardinality: the anchor must load and hold exactly
        // the planned rule count. This does not prove semantic equivalence
        // (documented reduced guarantee); anything else is Drifted, and an
        // unreadable pfctl is Unknown rather than a false Applied.
        let output = match Command::new("pfctl")
            .args(["-a", &self.anchor(), "-s", "rules"])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                return VerificationOutcome::Unknown {
                    detail: format!("pfctl readback unavailable: {e}"),
                };
            }
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("nonexistent") || output.stdout.is_empty() {
                return VerificationOutcome::Absent;
            }
            return VerificationOutcome::Unknown {
                detail: format!("pfctl anchor read failed: {stderr}"),
            };
        }
        let count = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        let expected = plan
            .expected_rule_count
            .unwrap_or_else(|| self.planned_rule_count());
        if count == expected {
            VerificationOutcome::Verified
        } else {
            VerificationOutcome::Drifted {
                detail: format!("anchor holds {count} rules, planned {expected}"),
            }
        }
    }

    fn config(&self) -> &IcmpFilterConfig {
        &self.config
    }
}

impl Drop for PfFilter {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(e) = self.remove_anchor() {
                tracing::warn!("Failed to remove PF anchor on drop: {}", e);
            }
        }
    }
}
