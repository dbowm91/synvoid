use crate::icmp_filter::{
    config::{Direction, IcmpFilterConfig, IcmpTypeRule, InterfaceSpec},
    error::{IcmpFilterError, Result},
    traits::{FilterBackend, FilterStatus, IcmpFilter},
};
use std::process::Command;

const ANCHOR_NAME: &str = "synvoid.icmp";

#[derive(Debug)]
pub struct PfBsdFilter {
    config: IcmpFilterConfig,
    enabled: bool,
    is_freebsd: bool,
    is_openbsd: bool,
    is_netbsd: bool,
}

impl PfBsdFilter {
    pub fn new(config: IcmpFilterConfig) -> Result<Self> {
        config.validate().map_err(IcmpFilterError::Config)?;
        Self::check_pf_available()?;

        let (is_freebsd, is_openbsd, is_netbsd) = Self::detect_bsd_variant();

        Ok(Self {
            config,
            enabled: false,
            is_freebsd,
            is_openbsd,
            is_netbsd,
        })
    }

    fn detect_bsd_variant() -> (bool, bool, bool) {
        #[cfg(target_os = "freebsd")]
        {
            (true, false, false)
        }

        #[cfg(target_os = "openbsd")]
        {
            (false, true, false)
        }

        #[cfg(target_os = "netbsd")]
        {
            (false, false, true)
        }

        #[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
        {
            (false, false, false)
        }
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
        let anchor_path = if self.is_freebsd || self.is_netbsd {
            format!("{}.icmp", self.config.table_name)
        } else {
            ANCHOR_NAME.to_string()
        };

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

    fn remove_anchor(&self) -> Result<()> {
        let anchor_path = if self.is_freebsd || self.is_netbsd {
            format!("{}.icmp", self.config.table_name)
        } else {
            ANCHOR_NAME.to_string()
        };

        let output = Command::new("pfctl")
            .args(["-a", &anchor_path, "-F", "all"])
            .output()
            .map_err(|e| IcmpFilterError::Pf(format!("Failed to remove anchor: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("nonexistent") && !stderr.contains("No such file") {
                tracing::warn!("pfctl anchor removal stderr: {}", stderr);
            }
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

        self.enable_pf()?;
        self.add_anchor()?;
        self.enabled = true;

        let variant = if self.is_freebsd {
            "FreeBSD"
        } else if self.is_openbsd {
            "OpenBSD"
        } else if self.is_netbsd {
            "NetBSD"
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
        let was_enabled = self.enabled;

        if was_enabled {
            self.remove_anchor()?;
        }

        self.config = config;

        if was_enabled && self.config.enabled {
            self.enable_pf()?;
            self.add_anchor()?;
        }

        Ok(())
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
