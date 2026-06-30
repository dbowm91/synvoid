use crate::{
    config::{Direction, IcmpFilterConfig, IcmpTypeRule},
    error::{IcmpFilterError, Result},
    traits::{FilterBackend, FilterStatus, IcmpFilter},
};
use std::process::Command;

#[derive(Debug)]
pub struct NftablesFilter {
    config: IcmpFilterConfig,
    enabled: bool,
}

impl NftablesFilter {
    pub fn new(config: IcmpFilterConfig) -> Result<Self> {
        config.validate().map_err(IcmpFilterError::Config)?;
        Self::check_nft_available()?;
        Ok(Self {
            config,
            enabled: false,
        })
    }

    fn check_nft_available() -> Result<()> {
        let output = Command::new("nft")
            .arg("--version")
            .output()
            .map_err(|e| IcmpFilterError::Nftables(format!("nft command not found: {}", e)))?;

        if !output.status.success() {
            return Err(IcmpFilterError::Nftables(
                "nft command failed to execute".to_string(),
            ));
        }

        Ok(())
    }

    fn build_ruleset(&self) -> String {
        let table_name = &self.config.table_name;
        let mut rules = Vec::new();

        let input_chain =
            self.config.direction == Direction::Both || self.config.direction == Direction::Inbound;
        let output_chain = self.config.direction == Direction::Both
            || self.config.direction == Direction::Outbound;

        let (in_interface_filter, out_interface_filter) = match &self.config.interfaces {
            crate::config::InterfaceSpec::All => (String::new(), String::new()),
            crate::config::InterfaceSpec::Specific(ifaces) => {
                if ifaces.len() == 1 {
                    (format!("iif {} ", ifaces[0]), format!("oif {} ", ifaces[0]))
                } else {
                    let iface_list = ifaces.join(", ");
                    (
                        format!("iif {{ {} }} ", iface_list),
                        format!("oif {{ {} }} ", iface_list),
                    )
                }
            }
        };

        rules.push(format!("table inet {}", table_name));
        rules.push("{".to_string());

        if input_chain {
            rules.push("\tchain input_icmp {".to_string());
            rules.push("\t\ttype filter hook input priority -150; policy accept;".to_string());

            for ip in &self.config.exempt_ips {
                let exempt_rule = match ip {
                    std::net::IpAddr::V4(addr) => {
                        format!("\t\t{}ip saddr {} accept", in_interface_filter, addr)
                    }
                    std::net::IpAddr::V6(addr) => {
                        format!("\t\t{}ip6 saddr {} accept", in_interface_filter, addr)
                    }
                };
                rules.push(exempt_rule);
            }

            for type_rule in &self.config.icmp_type_rules {
                rules.push(self.build_icmp_type_rule(type_rule, true, &in_interface_filter, false));
            }

            for type_rule in &self.config.icmpv6_type_rules {
                rules.push(self.build_icmp_type_rule(type_rule, true, &in_interface_filter, true));
            }

            let base_icmp_rule = self.build_base_icmp_rule(&in_interface_filter, false);
            rules.push(base_icmp_rule);

            let base_icmpv6_rule = self.build_base_icmp_rule(&in_interface_filter, true);
            rules.push(base_icmpv6_rule);

            rules.push("\t}".to_string());
        }

        if output_chain {
            rules.push("\tchain output_icmp {".to_string());
            rules.push("\t\ttype filter hook output priority -150; policy accept;".to_string());

            for ip in &self.config.exempt_ips {
                let exempt_rule = match ip {
                    std::net::IpAddr::V4(addr) => {
                        format!("\t\t{}ip daddr {} accept", out_interface_filter, addr)
                    }
                    std::net::IpAddr::V6(addr) => {
                        format!("\t\t{}ip6 daddr {} accept", out_interface_filter, addr)
                    }
                };
                rules.push(exempt_rule);
            }

            for type_rule in &self.config.icmp_type_rules {
                rules.push(self.build_icmp_type_rule(
                    type_rule,
                    false,
                    &out_interface_filter,
                    false,
                ));
            }

            for type_rule in &self.config.icmpv6_type_rules {
                rules.push(self.build_icmp_type_rule(
                    type_rule,
                    false,
                    &out_interface_filter,
                    true,
                ));
            }

            let base_icmp_rule = self.build_base_icmp_rule(&out_interface_filter, false);
            rules.push(base_icmp_rule);

            let base_icmpv6_rule = self.build_base_icmp_rule(&out_interface_filter, true);
            rules.push(base_icmpv6_rule);

            rules.push("\t}".to_string());
        }

        rules.push("}".to_string());

        rules.join("\n")
    }

    fn build_icmp_type_rule(
        &self,
        rule: &IcmpTypeRule,
        _is_input: bool,
        interface_filter: &str,
        is_v6: bool,
    ) -> String {
        let action = if rule.is_block() { "drop" } else { "accept" };
        let proto = if is_v6 { "icmpv6" } else { "icmp" };
        let ip_proto = if is_v6 { "ip6 nexthdr" } else { "ip protocol" };

        let type_match = if let Some(code) = rule.icmp_code {
            format!(
                "{} type {} {} code {} {}",
                proto, rule.icmp_type, proto, code, action
            )
        } else {
            format!("{} type {} {}", proto, rule.icmp_type, action)
        };

        format!("\t\t{}{} {}", interface_filter, ip_proto, type_match)
    }

    fn build_base_icmp_rule(&self, interface_filter: &str, is_v6: bool) -> String {
        let (proto, ip_proto) = if is_v6 {
            ("icmpv6", "ip6 nexthdr")
        } else {
            ("icmp", "ip protocol")
        };

        if let Some(ref rate_limit) = self.config.rate_limit {
            if rate_limit.enabled {
                format!(
                    "\t\t{}{} {} limit rate over {}/second burst {} packets drop",
                    interface_filter,
                    ip_proto,
                    proto,
                    rate_limit.packets_per_second,
                    rate_limit.burst
                )
            } else {
                format!("\t\t{}{} {} drop", interface_filter, ip_proto, proto)
            }
        } else {
            format!("\t\t{}{} {} drop", interface_filter, ip_proto, proto)
        }
    }

    fn apply_ruleset(&self) -> Result<()> {
        let ruleset = self.build_ruleset();

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| IcmpFilterError::Nftables(format!("Failed to spawn nft: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(ruleset.as_bytes()).map_err(|e| {
                IcmpFilterError::Nftables(format!("Failed to write ruleset: {}", e))
            })?;
        }

        let status = child
            .wait()
            .map_err(|e| IcmpFilterError::Nftables(format!("Failed to wait for nft: {}", e)))?;

        if !status.success() {
            return Err(IcmpFilterError::Nftables(format!(
                "nft command failed with status: {}",
                status
            )));
        }

        Ok(())
    }

    fn remove_ruleset(&self) -> Result<()> {
        let table_name = &self.config.table_name;

        let output = Command::new("nft")
            .args(["delete", "table", "inet", table_name])
            .output()
            .map_err(|e| IcmpFilterError::Nftables(format!("Failed to delete table: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_lower = stderr.to_lowercase();
            if stderr_lower.contains("no such")
                && (stderr_lower.contains("table")
                    || stderr_lower.contains("file")
                    || stderr_lower.contains("directory"))
            {
                return Ok(());
            }
            return Err(IcmpFilterError::Nftables(format!(
                "Failed to delete table: {}",
                stderr
            )));
        }

        Ok(())
    }

    pub fn is_available() -> bool {
        Command::new("nft").arg("--version").output().is_ok()
    }
}

impl IcmpFilter for NftablesFilter {
    fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(IcmpFilterError::AlreadyEnabled);
        }

        self.apply_ruleset()?;
        self.enabled = true;
        tracing::info!("ICMP filter enabled via nftables");
        Ok(())
    }

    fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(IcmpFilterError::AlreadyDisabled);
        }

        self.remove_ruleset()?;
        self.enabled = false;
        tracing::info!("ICMP filter disabled via nftables");
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn is_enforcing(&self) -> bool {
        self.enabled
    }

    fn backend(&self) -> FilterBackend {
        FilterBackend::Nftables
    }

    fn status(&self) -> FilterStatus {
        FilterStatus {
            enabled: self.enabled,
            backend: FilterBackend::Nftables,
            config: self.config.clone(),
        }
    }

    fn update_config(&mut self, config: IcmpFilterConfig) -> Result<()> {
        config.validate().map_err(IcmpFilterError::Config)?;
        let was_enabled = self.enabled;

        if was_enabled {
            self.remove_ruleset()?;
        }

        self.config = config;

        if was_enabled && self.config.enabled {
            self.apply_ruleset()?;
        }

        Ok(())
    }

    fn config(&self) -> &IcmpFilterConfig {
        &self.config
    }
}

impl Drop for NftablesFilter {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(e) = self.remove_ruleset() {
                tracing::warn!("Failed to remove nftables ruleset on drop: {}", e);
            }
        }
    }
}
