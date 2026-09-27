use crate::{
    compat::adapt_config_to_policy,
    config::{Direction, IcmpFilterConfig},
    enforce::{policy_fingerprint, EnforcementPlan, VerificationOutcome},
    error::{IcmpFilterError, Result},
    nft_batch,
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
        nft_batch::marker_chain(fingerprint)
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
        // Single source of truth lives in `nft_batch` so deterministic
        // batch-grammar tests run on every platform without `nft`.
        // Install, replacement, drift repair, and rollback-retry all load
        // this exact batch; disable uses scoped `delete table` only.
        nft_batch::render_batch(&self.config, fingerprint)
    }

    /// Atomic replacement: one `nft -f -` transaction renders the owned
    /// table (`add table` idempotent, then `flush table`, then `add chain`
    /// / `add rule`). On failure the previous owned table survives (nft
    /// batch atomicity) and the error propagates; the caller must not
    /// advance applied state. No unrelated tables, chains, or host firewall
    /// state are flushed or removed.
    fn apply_ruleset(&self, fingerprint: u64) -> Result<()> {
        let batch = self.build_ruleset(fingerprint);
        Self::load_batch(&batch)
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
        // Owned-scope delete only; the argv is the tested single source of
        // truth in `nft_batch::delete_table_argv`.
        let argv = nft_batch::delete_table_argv(&self.config.table_name);
        let output = Command::new("nft")
            .args(&argv[1..])
            .output()
            .map_err(|e| IcmpFilterError::Nftables(format!("Failed to delete table: {e}")))?;

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
