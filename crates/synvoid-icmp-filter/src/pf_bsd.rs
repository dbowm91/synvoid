use crate::{
    compat::adapt_config_to_policy,
    config::{Direction, IcmpFilterConfig, IcmpTypeRule, InterfaceSpec},
    enforce::{pf_anchor_for, policy_fingerprint, EnforcementPlan, VerificationOutcome},
    error::{IcmpFilterError, Result},
    traits::{FilterBackend, FilterStatus, IcmpFilter},
};
use std::process::Command;

/// Legacy unscoped OpenBSD anchor (pre-Phase-87). Disable sweeps it
/// best-effort; new installs use the table-scoped anchor.
const LEGACY_ANCHOR_NAME: &str = "synvoid.icmp";

/// BSD PF backend: FreeBSD and OpenBSD only, qualified separately.
///
/// NetBSD is explicitly unsupported for ICMP enforcement: its native packet
/// filter is NPF (https://man.netbsd.org/npf.7), not PF. NetBSD compiles to
/// `UnsupportedPlatform`; NPF is a separately scoped future backend, not a
/// Phase 86 deliverable.
#[derive(Debug)]
pub struct PfBsdFilter {
    config: IcmpFilterConfig,
    enabled: bool,
    is_freebsd: bool,
    is_openbsd: bool,
}

impl PfBsdFilter {
    pub fn new(config: IcmpFilterConfig) -> Result<Self> {
        config.validate().map_err(IcmpFilterError::Config)?;
        Self::check_pf_available()?;

        let (is_freebsd, is_openbsd) = Self::detect_bsd_variant();

        Ok(Self {
            config,
            enabled: false,
            is_freebsd,
            is_openbsd,
        })
    }

    fn detect_bsd_variant() -> (bool, bool) {
        #[cfg(target_os = "freebsd")]
        {
            (true, false)
        }

        #[cfg(target_os = "openbsd")]
        {
            (false, true)
        }

        #[cfg(not(any(target_os = "freebsd", target_os = "openbsd")))]
        {
            (false, false)
        }
    }

    fn anchor(&self) -> String {
        pf_anchor_for(&self.config.table_name)
    }

    fn planned_rule_count(&self) -> usize {
        self.config.exempt_ips.len()
            + self.config.icmp_type_rules.len()
            + self.config.icmpv6_type_rules.len()
            + 2
    }

    fn planned_fingerprint_for(config: &IcmpFilterConfig) -> Result<u64> {
        let (policy, _) = adapt_config_to_policy(config).map_err(IcmpFilterError::from)?;
        Ok(policy_fingerprint(&policy))
    }

    fn check_pf_available() -> Result<()> {
        let output = Command::new("pfctl")
            .args(["-s", "info"])
            .output()
            .map_err(|e| IcmpFilterError::Pf(format!("pfctl command not found: {}", e)))?;

        if !output.status.success() {
            return Err(IcmpFilterError::Pf(
                "pfctl command failed to execute. Ensure PF is loaded.".to_string(),
            ));
        }

        Ok(())
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
                if self.is_openbsd {
                    format!(
                        " max-src-conn-rate {}/{} overload <icmp_flood> flush global",
                        rate_limit.burst, rate_limit.packets_per_second
                    )
                } else {
                    format!(
                        " max-src-conn-rate {}/{} overload <icmp_flood> flush",
                        rate_limit.burst, rate_limit.packets_per_second
                    )
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        rules.push_str(&format!("# SynVoid ICMP Filter Rules\n"));

        rules.push_str("table <icmp_flood> persist\n\n");

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
            "block {} {} inet6 proto icmp6 all{}\n",
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
            (
                "inet6",
                "icmp6",
                if self.is_openbsd {
                    "icmp6-type"
                } else {
                    "icmp-type"
                },
            )
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
        // Single anchor load replaces owned content atomically.
        let anchor_path = self.anchor();
        let output = Command::new("pfctl")
            .args(["-a", &anchor_path, "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();

        let mut child = output
            .map_err(|e| IcmpFilterError::Pf(format!("Failed to spawn pfctl for anchor: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let rules = self.build_rules();
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

        tracing::info!("BSD PF anchor rules loaded successfully");
        Ok(())
    }

    fn flush_anchor(anchor: &str) -> Result<()> {
        let output = Command::new("pfctl")
            .args(["-a", anchor, "-F", "all"])
            .output()
            .map_err(|e| IcmpFilterError::Pf(format!("Failed to remove anchor: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("nonexistent") && !stderr.contains("No such file") {
                tracing::warn!("pfctl anchor removal stderr: {}", stderr);
            }
        }
        Ok(())
    }

    fn remove_anchor(&self) -> Result<()> {
        Self::flush_anchor(&self.anchor())?;
        if !self.is_freebsd {
            // Best-effort sweep of the legacy unscoped OpenBSD anchor.
            Self::flush_anchor(LEGACY_ANCHOR_NAME)?;
        }

        let table_output = Command::new("pfctl")
            .args(["-t", "icmp_flood", "-T", "flush"])
            .output();

        if let Ok(output) = table_output {
            if !output.status.success() {
                tracing::debug!("icmp_flood table flush: table may not exist");
            }
        }

        Ok(())
    }

    pub fn is_available() -> bool {
        Command::new("pfctl").args(["-s", "info"]).output().is_ok()
    }
}

impl IcmpFilter for PfBsdFilter {
    fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(IcmpFilterError::AlreadyEnabled);
        }

        let _fingerprint = Self::planned_fingerprint_for(&self.config)?;
        self.enable_pf()?;
        self.add_anchor()?;
        self.enabled = true;

        let variant = if self.is_freebsd {
            "FreeBSD"
        } else if self.is_openbsd {
            "OpenBSD"
        } else {
            "BSD"
        };

        tracing::info!("ICMP filter enabled via {} PF", variant);
        Ok(())
    }

    fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(IcmpFilterError::AlreadyDisabled);
        }

        self.remove_anchor()?;
        self.enabled = false;
        tracing::info!("ICMP filter disabled via BSD PF");
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
        let _fingerprint = Self::planned_fingerprint_for(&config)?;
        let old = std::mem::replace(&mut self.config, config);
        let was_enabled = self.enabled;
        let want_enabled = self.config.enabled;

        if was_enabled && want_enabled {
            // Single load replaces the anchor atomically.
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
            if stderr.contains("nonexistent") || stderr.contains("No such file") {
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

impl Drop for PfBsdFilter {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(e) = self.remove_anchor() {
                tracing::warn!("Failed to remove BSD PF anchor on drop: {}", e);
            }
        }
    }
}
