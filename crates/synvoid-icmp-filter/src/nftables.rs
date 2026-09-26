use crate::{
    compat::adapt_config_to_policy,
    config::{Direction, IcmpFilterConfig, IcmpTypeRule},
    enforce::{fingerprint_hex, policy_fingerprint, EnforcementPlan, VerificationOutcome},
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

    /// Compile a config to its fingerprint (pure; zero mutation).
    fn planned_fingerprint_for(config: &IcmpFilterConfig) -> Result<u64> {
        let (policy, _) = adapt_config_to_policy(config).map_err(IcmpFilterError::from)?;
        Ok(policy_fingerprint(&policy))
    }

    /// Compile the current config to its fingerprint (pure; zero mutation).
    fn planned_fingerprint(&self) -> Result<u64> {
        Self::planned_fingerprint_for(&self.config)
    }

    fn marker_chain(fingerprint: u64) -> String {
        format!("gen_{}", fingerprint_hex(fingerprint))
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

    fn build_ruleset(&self, fingerprint: u64) -> String {
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

        // Generation marker: an unhooked, inert chain binding this table to
        // the installed policy fingerprint. Readback checks it; unrelated
        // operator tables never carry this name.
        rules.push(format!(
            "add chain inet {} {}",
            table_name,
            Self::marker_chain(fingerprint)
        ));

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

    /// Atomic replacement: one `nft -f` batch flushes and recreates the
    /// owned table. On failure the previous table survives (nft batch
    /// atomicity) and the error propagates; the caller must not advance
    /// applied state. A missing table (first install, stale cleanup) falls
    /// back to a create-only batch.
    fn apply_ruleset(&self, fingerprint: u64) -> Result<()> {
        let table_name = &self.config.table_name;
        let ruleset = self.build_ruleset(fingerprint);
        let flush_batch = format!("flush table inet {table_name}\n{ruleset}");
        match Self::load_batch(&flush_batch) {
            Ok(()) => Ok(()),
            Err(e) if is_missing_table_error(&e) => Self::load_batch(&ruleset).map_err(|e2| {
                IcmpFilterError::Nftables(format!(
                    "atomic replace failed (flush: {e}; create: {e2})"
                ))
            }),
            Err(e) => Err(e),
        }
    }

    fn load_batch(batch: &str) -> Result<()> {
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| IcmpFilterError::Nftables(format!("Failed to spawn nft: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(batch.as_bytes()).map_err(|e| {
                IcmpFilterError::Nftables(format!("Failed to write ruleset: {}", e))
            })?;
        }

        let status = child
            .wait()
            .map_err(|e| IcmpFilterError::Nftables(format!("Failed to wait for nft: {}", e)))?;

        if !status.success() {
            return Err(IcmpFilterError::Nftables(format!(
                "nft batch failed with status: {}",
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
            if is_missing_table_stderr(&stderr) {
                // Idempotent removal: already absent is success.
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

    /// Read back owned state: the table must exist with the hook chains for
    /// the configured direction plus the generation marker chain. Only the
    /// owned table is inspected; unrelated operator state is tolerated.
    fn readback(&self, fingerprint: u64) -> VerificationOutcome {
        let table_name = &self.config.table_name;
        let output = match Command::new("nft")
            .args(["--json", "list", "table", "inet", table_name])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                return VerificationOutcome::Unknown {
                    detail: format!("nft readback unavailable: {e}"),
                };
            }
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if is_missing_table_stderr(&stderr) {
                return VerificationOutcome::Absent;
            }
            return VerificationOutcome::Unknown {
                detail: format!("nft list failed: {stderr}"),
            };
        }
        let value: serde_json::Value = match serde_json::from_slice(&output.stdout) {
            Ok(v) => v,
            Err(e) => {
                return VerificationOutcome::Unknown {
                    detail: format!("nft JSON unparseable: {e}"),
                };
            }
        };
        let mut chains = Vec::new();
        if let Some(items) = value.get("nftables").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(chain) = item.get("chain") {
                    if let Some(name) = chain.get("name").and_then(|n| n.as_str()) {
                        chains.push(name.to_string());
                    }
                }
            }
        }
        let mut expected = Vec::new();
        if self.config.direction == Direction::Both || self.config.direction == Direction::Inbound {
            expected.push("input_icmp".to_string());
        }
        if self.config.direction == Direction::Both || self.config.direction == Direction::Outbound
        {
            expected.push("output_icmp".to_string());
        }
        expected.push(Self::marker_chain(fingerprint));
        let missing: Vec<_> = expected
            .iter()
            .filter(|e| !chains.contains(e))
            .cloned()
            .collect();
        if missing.is_empty() {
            VerificationOutcome::Verified
        } else {
            VerificationOutcome::Drifted {
                detail: format!("owned table missing chains: {}", missing.join(",")),
            }
        }
    }
}

fn is_missing_table_stderr(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("no such")
        && (lower.contains("table") || lower.contains("file") || lower.contains("directory"))
}

fn is_missing_table_error(e: &IcmpFilterError) -> bool {
    match e {
        IcmpFilterError::Nftables(msg) => {
            // `nft -f` reports batch failures by exit status without
            // machine-readable detail; treat any flush-batch failure as
            // possibly-missing-table and let the create-only retry decide.
            // A genuinely broken ruleset fails both attempts and surfaces.
            let _ = msg;
            true
        }
        _ => false,
    }
}

impl IcmpFilter for NftablesFilter {
    fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(IcmpFilterError::AlreadyEnabled);
        }

        // Compile first (pure): an inexpressible replacement installs nothing.
        let fingerprint = self.planned_fingerprint()?;
        self.apply_ruleset(fingerprint)?;
        self.enabled = true;
        tracing::info!("ICMP filter enabled via nftables");
        Ok(())
    }

    fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(IcmpFilterError::AlreadyDisabled);
        }

        self.ensure_disabled()?;
        tracing::info!("ICMP filter disabled via nftables");
        Ok(())
    }

    fn ensure_disabled(&mut self) -> Result<()> {
        // Idempotent: removing an already-absent table is success, and
        // partial-cleanup failure is visible (error), never silent.
        self.remove_ruleset()?;
        self.enabled = false;
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
        // Compile the replacement completely before touching kernel state.
        let fingerprint = Self::planned_fingerprint_for(&config)?;
        // Swap first so install helpers read the new config; restore the
        // previous generation untouched on any install failure.
        let old = std::mem::replace(&mut self.config, config);
        let was_enabled = self.enabled;
        let want_enabled = self.config.enabled;

        if was_enabled && want_enabled {
            // Single atomic batch replaces the owned table; the previous
            // generation survives install failure (batch atomicity).
            if let Err(e) = self.apply_ruleset(fingerprint) {
                self.config = old;
                return Err(e);
            }
        } else if was_enabled {
            // Replacement disables enforcement: remove the owned table.
            if let Err(e) = self.remove_ruleset() {
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
        self.readback(plan.fingerprint)
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
