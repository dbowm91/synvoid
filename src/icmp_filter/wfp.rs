/*
 * Windows Filtering Platform (WFP) ICMP Backend
 *
 * Capabilities:
 *   - Block/allow ICMP by direction (inbound/outbound/both)
 *   - Per-IP exemption (IPv4 and IPv6)
 *   - ICMP type/code matching via WFP conditions
 *   - Interface filtering by numeric index
 *   - No built-in rate limiting (WFP has no native rate-limit primitives)
 *
 * Required privilege: Administrator (checked via platform::is_admin)
 *
 * When is_enforcing() == false: the filter was created without admin rights or
 * the icmp-wfp feature is not enabled; no kernel-level enforcement occurs.
 */

use crate::icmp_filter::{
    config::{Direction, IcmpFilterConfig, IcmpTypeRule},
    error::{IcmpFilterError, Result},
    platform::is_admin,
    traits::{FilterBackend, FilterStatus, IcmpFilter},
};
use std::net::IpAddr;

const SUBLAYER_NAME: &str = "synvoid_ICMP_Sublayer";

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

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
        let has_admin = is_admin();

        if !has_admin {
            tracing::warn!(
                "WFP ICMP filtering requires administrator privileges. \
                 Filter will be created in disabled state."
            );
        }

        if config.has_type_rules() {
            tracing::info!(
                "ICMP type/code rules configured. Note: WFP crate limitations may apply."
            );
        }

        Ok(Self {
            config,
            enabled: false,
            has_admin,
            filter_ids: Vec::new(),
        })
    }

    fn add_icmp_filters(&mut self) -> Result<()> {
        if !self.has_admin {
            tracing::warn!("Cannot create WFP filters without administrator privileges");
            return Err(IcmpFilterError::PermissionDenied);
        }

        #[cfg(feature = "icmp-wfp")]
        {
            use wfp::{
                ActionType, Condition, ConditionField, FilterBuilder, FilterEngineBuilder, Layer,
                MatchType, ProtocolConditionBuilder, Transaction,
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

            // Handle interface-specific filtering
            let interface_indices = if !self.config.interfaces.is_all() {
                let mut indices = Vec::new();
                for iface in self.config.interfaces.names() {
                    // Try to parse as index first
                    if let Ok(idx) = iface.parse::<u32>() {
                        indices.push(idx);
                    } else {
                        // In a real implementation, we would resolve name to index here
                        // For now we log a warning if it's not a numeric index
                        tracing::warn!(
                            "WFP interface filtering currently requires numeric indices: {}",
                            iface
                        );
                    }
                }
                Some(indices)
            } else {
                None
            };

            if !self.config.exempt_ips.is_empty() {
                for ip in &self.config.exempt_ips {
                    if block_in {
                        self.add_exempt_filter(
                            ip,
                            Layer::InboundTransportV4,
                            Layer::InboundTransportV6,
                            &transaction,
                        )?;
                    }
                    if block_out {
                        self.add_exempt_filter(
                            ip,
                            Layer::OutboundTransportV4,
                            Layer::OutboundTransportV6,
                            &transaction,
                        )?;
                    }
                }
            }

            if self.config.has_type_rules() {
                self.add_type_rule_filters(
                    block_in,
                    block_out,
                    &self.config.icmp_type_rules,
                    &self.config.icmpv6_type_rules,
                    &transaction,
                )?;
            }

            let mut add_icmp_block =
                |name: &str, layer: Layer, protocol: u8, tx: &Transaction| -> Result<u64> {
                    let mut builder = FilterBuilder::default()
                        .name(name)
                        .description("Synvoid ICMP block filter")
                        .action(ActionType::Block)
                        .layer(layer);

                    builder = builder.condition(
                        ProtocolConditionBuilder::new()
                            .field(ConditionField::Protocol)
                            .equal(protocol)
                            .build(),
                    );

                    if let Some(ref indices) = interface_indices {
                        for &idx in indices {
                            // WFP condition for interface index
                            let iface_cond =
                                Condition::new(ConditionField::InterfaceIndex, MatchType::Equal)
                                    .value(idx);
                            builder = builder.condition(iface_cond);
                        }
                    }

                    let filter_id = builder.add(tx).map_err(|e| {
                        IcmpFilterError::Wfp(format!("Failed to add filter '{}': {}", name, e))
                    })?;
                    Ok(filter_id)
                };

            if block_in {
                let id = add_icmp_block(
                    "synvoid_ICMP_Block_In_V4",
                    Layer::InboundTransportV4,
                    IPPROTO_ICMP,
                    &transaction,
                )?;
                self.filter_ids.push(id);

                let id = add_icmp_block(
                    "synvoid_ICMP_Block_In_V6",
                    Layer::InboundTransportV6,
                    IPPROTO_ICMPV6,
                    &transaction,
                )?;
                self.filter_ids.push(id);
            }

            if block_out {
                let id = add_icmp_block(
                    "synvoid_ICMP_Block_Out_V4",
                    Layer::OutboundTransportV4,
                    IPPROTO_ICMP,
                    &transaction,
                )?;
                self.filter_ids.push(id);

                let id = add_icmp_block(
                    "synvoid_ICMP_Block_Out_V6",
                    Layer::OutboundTransportV6,
                    IPPROTO_ICMPV6,
                    &transaction,
                )?;
                self.filter_ids.push(id);
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
    fn add_exempt_filter(
        &mut self,
        ip: &IpAddr,
        v4_layer: wfp::Layer,
        v6_layer: wfp::Layer,
        transaction: &wfp::Transaction,
    ) -> Result<()> {
        use wfp::{ActionType, Condition, ConditionField, FilterBuilder, MatchType};

        match ip {
            IpAddr::V4(addr) => {
                let bytes = u32::from(*addr).to_be_bytes();
                let condition = Condition::new(ConditionField::RemoteAddress, MatchType::Equal)
                    .value_bytes(&bytes);

                let filter_id = FilterBuilder::default()
                    .name(&format!("synvoid_ICMP_Exempt_{}", addr))
                    .description("Synvoid ICMP exempt filter")
                    .action(ActionType::Permit)
                    .layer(v4_layer)
                    .condition(condition)
                    .add(transaction)
                    .map_err(|e| {
                        IcmpFilterError::Wfp(format!("Failed to add exempt filter: {}", e))
                    })?;
                self.filter_ids.push(filter_id);
            }
            IpAddr::V6(addr) => {
                let condition = Condition::new(ConditionField::RemoteAddress, MatchType::Equal)
                    .value_bytes(&addr.octets());

                let filter_id = FilterBuilder::default()
                    .name(&format!("synvoid_ICMPv6_Exempt_{}", ip))
                    .description("Synvoid ICMPv6 exempt filter")
                    .action(ActionType::Permit)
                    .layer(v6_layer)
                    .condition(condition)
                    .add(transaction)
                    .map_err(|e| {
                        IcmpFilterError::Wfp(format!("Failed to add exempt filter: {}", e))
                    })?;
                self.filter_ids.push(filter_id);
            }
        }

        Ok(())
    }

    #[cfg(feature = "icmp-wfp")]
    fn add_type_rule_filters(
        &mut self,
        block_in: bool,
        block_out: bool,
        icmp_rules: &[IcmpTypeRule],
        icmpv6_rules: &[IcmpTypeRule],
        transaction: &wfp::Transaction,
    ) -> Result<()> {
        use wfp::{ActionType, Condition, ConditionField, FilterBuilder, MatchType};

        for rule in icmp_rules {
            let action = if rule.is_block() {
                ActionType::Block
            } else {
                ActionType::Permit
            };

            let protocol_condition =
                Condition::new(ConditionField::Protocol, MatchType::Equal).value(IPPROTO_ICMP);

            let type_condition =
                Condition::new(ConditionField::IcmpType, MatchType::Equal).value(rule.icmp_type);

            let code_condition = if let Some(code) = rule.icmp_code {
                Some(Condition::new(ConditionField::IcmpCode, MatchType::Equal).value(code))
            } else {
                None
            };

            if block_in {
                let name = format!("synvoid_ICMP_Type_{}_In", rule.icmp_type);
                let mut builder = FilterBuilder::default()
                    .name(&name)
                    .description(rule.description.as_deref().unwrap_or("ICMP type filter"))
                    .action(action)
                    .layer(wfp::Layer::InboundTransportV4)
                    .condition(protocol_condition.clone())
                    .condition(type_condition.clone());

                if let Some(ref code_cond) = code_condition {
                    builder = builder.condition(code_cond.clone());
                }

                let filter_id = builder.add(transaction).map_err(|e| {
                    IcmpFilterError::Wfp(format!("Failed to add ICMP type filter: {}", e))
                })?;
                self.filter_ids.push(filter_id);
            }

            if block_out {
                let name = format!("synvoid_ICMP_Type_{}_Out", rule.icmp_type);
                let mut builder = FilterBuilder::default()
                    .name(&name)
                    .description(rule.description.as_deref().unwrap_or("ICMP type filter"))
                    .action(action)
                    .layer(wfp::Layer::OutboundTransportV4)
                    .condition(protocol_condition.clone())
                    .condition(type_condition.clone());

                if let Some(ref code_cond) = code_condition {
                    builder = builder.condition(code_cond.clone());
                }

                let filter_id = builder.add(transaction).map_err(|e| {
                    IcmpFilterError::Wfp(format!("Failed to add ICMP type filter: {}", e))
                })?;
                self.filter_ids.push(filter_id);
            }
        }

        for rule in icmpv6_rules {
            let action = if rule.is_block() {
                ActionType::Block
            } else {
                ActionType::Permit
            };

            let protocol_condition =
                Condition::new(ConditionField::Protocol, MatchType::Equal).value(IPPROTO_ICMPV6);

            let type_condition =
                Condition::new(ConditionField::IcmpType, MatchType::Equal).value(rule.icmp_type);

            let code_condition = if let Some(code) = rule.icmp_code {
                Some(Condition::new(ConditionField::IcmpCode, MatchType::Equal).value(code))
            } else {
                None
            };

            if block_in {
                let name = format!("synvoid_ICMPv6_Type_{}_In", rule.icmp_type);
                let mut builder = FilterBuilder::default()
                    .name(&name)
                    .description(rule.description.as_deref().unwrap_or("ICMPv6 type filter"))
                    .action(action)
                    .layer(wfp::Layer::InboundTransportV6)
                    .condition(protocol_condition.clone())
                    .condition(type_condition.clone());

                if let Some(ref code_cond) = code_condition {
                    builder = builder.condition(code_cond.clone());
                }

                let filter_id = builder.add(transaction).map_err(|e| {
                    IcmpFilterError::Wfp(format!("Failed to add ICMPv6 type filter: {}", e))
                })?;
                self.filter_ids.push(filter_id);
            }

            if block_out {
                let name = format!("synvoid_ICMPv6_Type_{}_Out", rule.icmp_type);
                let mut builder = FilterBuilder::default()
                    .name(&name)
                    .description(rule.description.as_deref().unwrap_or("ICMPv6 type filter"))
                    .action(action)
                    .layer(wfp::Layer::OutboundTransportV6)
                    .condition(protocol_condition.clone())
                    .condition(type_condition.clone());

                if let Some(ref code_cond) = code_condition {
                    builder = builder.condition(code_cond.clone());
                }

                let filter_id = builder.add(transaction).map_err(|e| {
                    IcmpFilterError::Wfp(format!("Failed to add ICMPv6 type filter: {}", e))
                })?;
                self.filter_ids.push(filter_id);
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
