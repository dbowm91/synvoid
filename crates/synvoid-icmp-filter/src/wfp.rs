//! Windows Filtering Platform (WFP) ICMP backend — primary Windows lane.
//!
//! Outcome A (Phase 86): WFP is the supported Windows enforcement lane
//! (typed protocol/ICMP conditions + engine transactions). The Windows
//! Firewall COM lane (`winfw`) remains only as a documented compatibility
//! fallback.
//!
//! Capabilities:
//! - Block/allow ICMP by direction (inbound/outbound/both)
//! - Per-IP exemption as `/32` and `/128` permit filters at higher weight
//!   (exemptions precede blocks by explicit weight ordering)
//! - ICMPv4 and ICMPv6 type/code matching via typed WFP conditions
//! - Interface filtering via LUID conditions: numeric indices resolve with
//!   `ConvertInterfaceIndexToLuid`, adapter names with
//!   `ConvertInterfaceAliasToLuid`; unresolvable names are a hard error
//! - No rate limiting: WFP exposes no rate-limit primitive, and the
//!   constructor rejects rate-limited policy instead of claiming it
//!
//! Required privilege: Administrator (checked via `platform::is_admin`).
//!
//! Cross-compilation (`--target x86_64-pc-windows-*`) is compile evidence
//! only. Native apply/remove proof belongs to Phase 88.

use crate::{
    config::{Direction, IcmpFilterConfig, IcmpTypeRule},
    error::{IcmpFilterError, Result},
    platform::is_admin,
    traits::{check_policy_compatibility, FilterBackend, FilterStatus, IcmpFilter},
};
use std::net::IpAddr;

// Explicit WFP arbitration weights: higher weight is evaluated first, so
// exemptions precede type rules, which precede the base protocol block.
const WEIGHT_EXEMPT: u64 = u64::MAX - 10;
const WEIGHT_TYPE_RULE: u64 = u64::MAX / 2;
const WEIGHT_BASE_BLOCK: u64 = 1;

#[derive(Debug)]
pub struct WfpFilter {
    config: IcmpFilterConfig,
    enabled: bool,
    has_admin: bool,
    filter_ids: Vec<u64>,
}

impl WfpFilter {
    pub fn new(config: IcmpFilterConfig) -> Result<Self> {
        config.validate().map_err(IcmpFilterError::Config)?;
        // Admit only policy this lane expresses exactly: WFP has no rate
        // limiting, so a rate-limited request fails here, never installs a
        // weaker rule set.
        let (policy, _) =
            crate::compat::adapt_config_to_policy(&config).map_err(IcmpFilterError::from)?;
        if let Err(mismatches) = check_policy_compatibility(FilterBackend::Wfp, &policy) {
            let detail = mismatches
                .iter()
                .map(|m| format!("{}: {}", m.requirement, m.detail))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(IcmpFilterError::Unsupported(format!(
                "WFP cannot express requested policy: {detail}"
            )));
        }
        let has_admin = is_admin();

        if !has_admin {
            tracing::warn!(
                "WFP ICMP filtering requires administrator privileges. \
                 Filter will be created in disabled state."
            );
        }

        Ok(Self {
            config,
            enabled: false,
            has_admin,
            filter_ids: Vec::new(),
        })
    }

    /// Build one LUID interface condition per configured interface.
    /// Numeric strings resolve as indices; anything else resolves as an
    /// adapter alias. Failures are hard errors.
    fn configured_interface_names(&self) -> Vec<String> {
        match &self.config.interfaces {
            crate::config::InterfaceSpec::All => Vec::new(),
            crate::config::InterfaceSpec::Specific(ifaces) => ifaces.clone(),
        }
    }

    fn add_icmp_filters(&mut self) -> Result<()> {
        if !self.has_admin {
            tracing::warn!("Cannot create WFP filters without administrator privileges");
            return Err(IcmpFilterError::PermissionDenied);
        }

        #[cfg(feature = "icmp-wfp")]
        {
            use wfp::{
                ActionType, FilterBuilder, FilterEngineBuilder, FilterWeight,
                InterfaceConditionBuilder, IpAddressConditionBuilder, Layer,
                ProtocolConditionBuilder, Transaction,
            };

            let mut engine = FilterEngineBuilder::default()
                .dynamic()
                .open()
                .map_err(|e| IcmpFilterError::Wfp(format!("Failed to open WFP engine: {}", e)))?;

            let transaction = Transaction::new(&mut engine).map_err(|e| {
                IcmpFilterError::Wfp(format!("Failed to create transaction: {}", e))
            })?;

            let block_in = matches!(self.config.direction, Direction::Inbound | Direction::Both);
            let block_out = matches!(self.config.direction, Direction::Outbound | Direction::Both);

            self.filter_ids.clear();

            // Resolve every configured interface to a LUID condition now so
            // an unresolvable name aborts before any filter is installed.
            let mut iface_conditions = Vec::new();
            for name in self.configured_interface_names() {
                let luid = crate::platform::resolve_interface_luid(&name).map_err(|e| {
                    IcmpFilterError::Wfp(format!(
                        "Cannot resolve interface '{name}' to a LUID: {e}"
                    ))
                })?;
                iface_conditions.push(InterfaceConditionBuilder::local().luid(luid).build());
            }

            // Helper: attach collected interface conditions to a builder.
            let with_ifaces = |mut builder: wfp::FilterBuilder<
                wfp::FilterBuilderHasName,
                wfp::FilterBuilderHasAction,
            >,
                               ifaces: &[wfp::Condition]|
             -> wfp::FilterBuilder<
                wfp::FilterBuilderHasName,
                wfp::FilterBuilderHasAction,
            > {
                for cond in ifaces {
                    builder = builder.condition(cond.clone());
                }
                builder
            };

            for ip in &self.config.exempt_ips {
                let layers: &[(Layer, Layer)] = if block_in && block_out {
                    &[
                        (Layer::InboundTransportV4, Layer::InboundTransportV6),
                        (Layer::OutboundTransportV4, Layer::OutboundTransportV6),
                    ]
                } else if block_in {
                    &[(Layer::InboundTransportV4, Layer::InboundTransportV6)]
                } else if block_out {
                    &[(Layer::OutboundTransportV4, Layer::OutboundTransportV6)]
                } else {
                    &[]
                };
                for (v4_layer, v6_layer) in layers {
                    let (layer, condition) = match ip {
                        IpAddr::V4(addr) => (
                            *v4_layer,
                            IpAddressConditionBuilder::remote()
                                .subnet_v4(*addr, 32)
                                .build(),
                        ),
                        IpAddr::V6(addr) => (
                            *v6_layer,
                            IpAddressConditionBuilder::remote()
                                .subnet_v6(*addr, 128)
                                .build(),
                        ),
                    };
                    let builder = with_ifaces(
                        FilterBuilder::default()
                            .name(&format!("synvoid_ICMP_Exempt_{ip}"))
                            .description("Synvoid ICMP exempt filter")
                            .action(ActionType::Permit)
                            .layer(layer)
                            .weight(FilterWeight::Exact(WEIGHT_EXEMPT))
                            .condition(condition),
                        &iface_conditions,
                    );
                    let id = builder.add(&transaction).map_err(|e| {
                        IcmpFilterError::Wfp(format!("Failed to add exempt filter: {}", e))
                    })?;
                    self.filter_ids.push(id);
                }
            }

            self.add_type_rule_filters(block_in, block_out, &iface_conditions, &transaction)?;

            let add_icmp_block = |name: &str, layer: Layer, v6: bool| -> Result<u64> {
                let proto_condition = if v6 {
                    ProtocolConditionBuilder::icmpv6().build()
                } else {
                    ProtocolConditionBuilder::icmp().build()
                };
                let builder = with_ifaces(
                    FilterBuilder::default()
                        .name(name)
                        .description("Synvoid ICMP block filter")
                        .action(ActionType::Block)
                        .layer(layer)
                        .weight(FilterWeight::Exact(WEIGHT_BASE_BLOCK))
                        .condition(proto_condition),
                    &iface_conditions,
                );
                builder.add(&transaction).map_err(|e| {
                    IcmpFilterError::Wfp(format!("Failed to add filter '{}': {}", name, e))
                })
            };

            if block_in {
                self.filter_ids.push(add_icmp_block(
                    "synvoid_ICMP_Block_In_V4",
                    Layer::InboundTransportV4,
                    false,
                )?);
                self.filter_ids.push(add_icmp_block(
                    "synvoid_ICMP_Block_In_V6",
                    Layer::InboundTransportV6,
                    true,
                )?);
            }

            if block_out {
                self.filter_ids.push(add_icmp_block(
                    "synvoid_ICMP_Block_Out_V4",
                    Layer::OutboundTransportV4,
                    false,
                )?);
                self.filter_ids.push(add_icmp_block(
                    "synvoid_ICMP_Block_Out_V6",
                    Layer::OutboundTransportV6,
                    true,
                )?);
            }

            transaction.commit().map_err(|e| {
                IcmpFilterError::Wfp(format!("Failed to commit transaction: {}", e))
            })?;

            tracing::info!(
                "WFP ICMP blocking filters created ({} filters, {} exempt IPs)",
                self.filter_ids.len(),
                self.config.exempt_ips.len()
            );
        }

        #[cfg(not(feature = "icmp-wfp"))]
        {
            return Err(IcmpFilterError::FeatureNotEnabled(
                "icmp-wfp feature not enabled".to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(feature = "icmp-wfp")]
    fn add_type_rule_filters(
        &mut self,
        block_in: bool,
        block_out: bool,
        iface_conditions: &[wfp::Condition],
        transaction: &wfp::Transaction<'_>,
    ) -> Result<()> {
        use wfp::{ActionType, FilterBuilder, FilterWeight, IcmpConditionBuilder, Layer};

        let mut add_rule = |rule: &IcmpTypeRule,
                            layer: Layer,
                            suffix: &str,
                            ifaces: &[wfp::Condition]|
         -> Result<()> {
            let action = if rule.is_block() {
                ActionType::Block
            } else {
                ActionType::Permit
            };
            let name = format!("synvoid_ICMP_Type_{}_{suffix}", rule.icmp_type);
            let mut builder = FilterBuilder::default()
                .name(&name)
                .description(rule.description.as_deref().unwrap_or("ICMP type filter"))
                .action(action)
                .layer(layer)
                .weight(FilterWeight::Exact(WEIGHT_TYPE_RULE))
                .condition(IcmpConditionBuilder::r#type().equal(rule.icmp_type).build());
            if let Some(code) = rule.icmp_code {
                builder = builder.condition(IcmpConditionBuilder::code().equal(code).build());
            }
            for cond in ifaces {
                builder = builder.condition(cond.clone());
            }
            let id = builder.add(transaction).map_err(|e| {
                IcmpFilterError::Wfp(format!("Failed to add ICMP type filter: {}", e))
            })?;
            self.filter_ids.push(id);
            Ok(())
        };

        for rule in &self.config.icmp_type_rules {
            if block_in {
                add_rule(rule, Layer::InboundTransportV4, "In", iface_conditions)?;
            }
            if block_out {
                add_rule(rule, Layer::OutboundTransportV4, "Out", iface_conditions)?;
            }
        }

        for rule in &self.config.icmpv6_type_rules {
            if block_in {
                add_rule(rule, Layer::InboundTransportV6, "In", iface_conditions)?;
            }
            if block_out {
                add_rule(rule, Layer::OutboundTransportV6, "Out", iface_conditions)?;
            }
        }

        Ok(())
    }

    fn remove_icmp_filters(&mut self) -> Result<()> {
        if !self.has_admin {
            tracing::warn!(
                "WFP backend inactive: skipping filter removal (no admin privileges). \
                 {} filter IDs remain tracked but are not enforced.",
                self.filter_ids.len()
            );
            return Ok(());
        }

        #[cfg(feature = "icmp-wfp")]
        {
            use wfp::{delete_filter, FilterEngineBuilder, Transaction};

            let mut engine = FilterEngineBuilder::default()
                .dynamic()
                .open()
                .map_err(|e| IcmpFilterError::Wfp(format!("Failed to open WFP engine: {}", e)))?;

            let transaction = Transaction::new(&mut engine).map_err(|e| {
                IcmpFilterError::Wfp(format!("Failed to create transaction: {}", e))
            })?;

            let mut errors = Vec::new();
            for filter_id in self.filter_ids.drain(..) {
                if let Err(e) = delete_filter(&transaction, filter_id) {
                    errors.push((filter_id, e));
                }
            }

            if let Err(e) = transaction.commit() {
                return Err(IcmpFilterError::Wfp(format!(
                    "Failed to commit filter removal: {}",
                    e
                )));
            }

            if !errors.is_empty() {
                tracing::warn!(
                    "Some WFP filters failed to remove: {:?}",
                    errors
                        .iter()
                        .map(|(id, e)| format!("{}: {}", id, e))
                        .collect::<Vec<_>>()
                );
            }

            tracing::info!("WFP ICMP blocking filters removed");
        }

        Ok(())
    }

    pub fn is_available() -> bool {
        #[cfg(feature = "icmp-wfp")]
        {
            true
        }
        #[cfg(not(feature = "icmp-wfp"))]
        {
            false
        }
    }
}

impl IcmpFilter for WfpFilter {
    fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(IcmpFilterError::AlreadyEnabled);
        }

        if !self.has_admin {
            return Err(IcmpFilterError::PermissionDenied);
        }

        self.add_icmp_filters()?;
        self.enabled = true;
        tracing::info!("ICMP filter enabled via WFP");
        Ok(())
    }

    fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(IcmpFilterError::AlreadyDisabled);
        }

        self.remove_icmp_filters()?;
        self.enabled = false;
        tracing::info!("ICMP filter disabled via WFP");
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn is_enforcing(&self) -> bool {
        self.enabled && self.has_admin
    }

    fn backend(&self) -> FilterBackend {
        FilterBackend::Wfp
    }

    fn status(&self) -> FilterStatus {
        FilterStatus {
            enabled: self.enabled,
            backend: FilterBackend::Wfp,
            config: self.config.clone(),
        }
    }

    fn update_config(&mut self, config: IcmpFilterConfig) -> Result<()> {
        config.validate().map_err(IcmpFilterError::Config)?;
        let was_enabled = self.enabled;

        if was_enabled {
            self.remove_icmp_filters()?;
        }

        self.config = config;

        if was_enabled && self.config.enabled {
            self.add_icmp_filters()?;
        }

        if !self.has_admin {
            tracing::warn!(
                "WFP backend is not enforcing: administrator privileges not held. \
                 Config updated but changes will not take effect until process runs as admin."
            );
        }

        Ok(())
    }

    fn config(&self) -> &IcmpFilterConfig {
        &self.config
    }
}

impl Drop for WfpFilter {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(e) = self.remove_icmp_filters() {
                tracing::warn!("Failed to remove WFP filters on drop: {}", e);
            }
        }
    }
}

#[cfg(all(test, feature = "icmp-wfp"))]
mod tests {
    use super::*;

    #[test]
    fn test_wfp_not_enforcing_without_admin() {
        let config = IcmpFilterConfig::default();
        let filter = WfpFilter::new(config).expect("new should succeed");
        assert!(!filter.is_enforcing());
        assert!(!filter.is_enabled());
    }

    #[test]
    fn test_wfp_enable_fails_without_admin() {
        let config = IcmpFilterConfig::default();
        let mut filter = WfpFilter::new(config).expect("new should succeed");
        if !filter.has_admin {
            let result = filter.enable();
            assert!(result.is_err());
        }
    }
}
