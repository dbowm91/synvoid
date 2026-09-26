//! Windows Filtering Platform (WFP) ICMP backend — primary Windows lane.
//!
//! Outcome A (Phase 86): WFP is the supported Windows enforcement lane.
//! Phase 87 adds failure-safe replacement and live verification:
//! - provider + sublayer GUIDs derived deterministically from the table
//!   name scope every object this backend owns;
//! - replacement installs inside ONE engine transaction (delete superseded
//!   IDs + ensure provider/sublayer + add new filters, single commit), so a
//!   commit failure rolls back instead of destroying working enforcement;
//! - readback enumerates live filters and checks tracked IDs against our
//!   provider GUID (`Verified` / `Drifted` / `Unknown`, never assumed).
//!
//! Filters are dynamic-session owned: process exit removes them, so crash
//! recovery needs no stale sweep (documented restart semantics).
//!
//! No rate limiting (constructor rejects it). Cross-compilation is compile
//! evidence only; native proof is Phase 88.

use crate::{
    config::{Direction, IcmpFilterConfig, IcmpTypeRule},
    enforce::{policy_fingerprint, wfp_provider_name, EnforcementPlan, VerificationOutcome},
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

    fn planned_fingerprint(&self) -> Result<u64> {
        let (policy, _) =
            crate::compat::adapt_config_to_policy(&self.config).map_err(IcmpFilterError::from)?;
        Ok(policy_fingerprint(&policy))
    }

    /// One engine transaction replaces the generation: delete superseded
    /// IDs, ensure our provider/sublayer, add the new filter set, commit.
    /// Commit failure rolls back (nothing retires early); the new ID list
    /// is returned for the caller to adopt only on success.
    fn apply_generation(
        config: &IcmpFilterConfig,
        old_ids: &[u64],
        has_admin: bool,
    ) -> Result<Vec<u64>> {
        if !has_admin {
            tracing::warn!("Cannot create WFP filters without administrator privileges");
            return Err(IcmpFilterError::PermissionDenied);
        }

        #[cfg(feature = "icmp-wfp")]
        {
            use wfp::{
                ActionType, FilterBuilder, FilterEngineBuilder, FilterWeight,
                InterfaceConditionBuilder, Layer, ProtocolConditionBuilder, ProviderBuilder,
                SubLayerBuilder, Transaction,
            };

            // Prepare stage (before any mutation): resolve every interface
            // to a LUID so an unresolvable name aborts with zero mutation.
            let mut iface_luids = Vec::new();
            let names: Vec<String> = match &config.interfaces {
                crate::config::InterfaceSpec::All => Vec::new(),
                crate::config::InterfaceSpec::Specific(ifaces) => ifaces.clone(),
            };
            for name in &names {
                let luid = crate::platform::resolve_interface_luid(name).map_err(|e| {
                    IcmpFilterError::Wfp(format!(
                        "Cannot resolve interface '{name}' to a LUID: {e}"
                    ))
                })?;
                iface_luids.push(InterfaceConditionBuilder::local().luid(luid).build());
            }

            let mut engine = FilterEngineBuilder::default()
                .dynamic()
                .open()
                .map_err(|e| IcmpFilterError::Wfp(format!("Failed to open WFP engine: {}", e)))?;

            let transaction = Transaction::new(&mut engine).map_err(|e| {
                IcmpFilterError::Wfp(format!("Failed to create transaction: {}", e))
            })?;

            // Backend-scoped ownership: stable provider + sublayer per table.
            let provider_guid = provider_guid_for(&config.table_name);
            let sublayer_guid = sublayer_guid_for(&config.table_name);
            let provider_name = wfp_provider_name(&config.table_name);
            ignore_already_exists(
                ProviderBuilder::default()
                    .name(&provider_name)
                    .description("Synvoid ICMP provider")
                    .guid(provider_guid)
                    .add(&transaction),
            )
            .map_err(|e| IcmpFilterError::Wfp(format!("Failed to ensure provider: {}", e)))?;
            ignore_already_exists(
                SubLayerBuilder::default()
                    .name(&format!("{provider_name} sublayer"))
                    .description("Synvoid ICMP sublayer")
                    .provider(provider_guid)
                    .guid(sublayer_guid)
                    .weight(0x100)
                    .add(&transaction),
            )
            .map_err(|e| IcmpFilterError::Wfp(format!("Failed to ensure sublayer: {}", e)))?;

            let block_in = matches!(config.direction, Direction::Inbound | Direction::Both);
            let block_out = matches!(config.direction, Direction::Outbound | Direction::Both);

            let mut new_ids = Vec::new();

            // Retire superseded filters inside the same transaction: they
            // vanish only if the commit succeeds.
            for filter_id in old_ids {
                use wfp::delete_filter;
                delete_filter(&transaction, *filter_id)
                    .map_err(|e| IcmpFilterError::Wfp(format!("Failed to stage removal: {}", e)))?;
            }

            let with_common = |builder: wfp::FilterBuilder<
                wfp::FilterBuilderHasName,
                wfp::FilterBuilderHasAction,
            >,
                               ifaces: &[wfp::Condition]|
             -> wfp::FilterBuilder<
                wfp::FilterBuilderHasName,
                wfp::FilterBuilderHasAction,
            > {
                let mut builder = builder.sublayer(sublayer_guid).provider(provider_guid);
                for cond in ifaces {
                    builder = builder.condition(cond.clone());
                }
                builder
            };

            for ip in &config.exempt_ips {
                if block_in {
                    new_ids.push(add_filter(
                        &transaction,
                        &with_common(
                            FilterBuilder::default()
                                .name(&format!("synvoid_ICMP_Exempt_{ip}_In"))
                                .description("Synvoid ICMP exempt filter")
                                .action(ActionType::Permit)
                                .layer(match ip {
                                    IpAddr::V4(_) => Layer::InboundTransportV4,
                                    IpAddr::V6(_) => Layer::InboundTransportV6,
                                })
                                .weight(FilterWeight::Exact(WEIGHT_EXEMPT))
                                .condition(exempt_condition(ip)),
                            &iface_luids,
                        ),
                    )?);
                }
                if block_out {
                    new_ids.push(add_filter(
                        &transaction,
                        &with_common(
                            FilterBuilder::default()
                                .name(&format!("synvoid_ICMP_Exempt_{ip}_Out"))
                                .description("Synvoid ICMP exempt filter")
                                .action(ActionType::Permit)
                                .layer(match ip {
                                    IpAddr::V4(_) => Layer::OutboundTransportV4,
                                    IpAddr::V6(_) => Layer::OutboundTransportV6,
                                })
                                .weight(FilterWeight::Exact(WEIGHT_EXEMPT))
                                .condition(exempt_condition(ip)),
                            &iface_luids,
                        ),
                    )?);
                }
            }

            new_ids.extend(add_type_rules(
                &transaction,
                config,
                block_in,
                block_out,
                &iface_luids,
                provider_guid,
                sublayer_guid,
            )?);

            let add_block = |name: &str, layer: Layer, v6: bool| -> Result<u64> {
                let proto = if v6 {
                    ProtocolConditionBuilder::icmpv6().build()
                } else {
                    ProtocolConditionBuilder::icmp().build()
                };
                add_filter(
                    &transaction,
                    &with_common(
                        FilterBuilder::default()
                            .name(name)
                            .description("Synvoid ICMP block filter")
                            .action(ActionType::Block)
                            .layer(layer)
                            .weight(FilterWeight::Exact(WEIGHT_BASE_BLOCK))
                            .condition(proto),
                        &iface_luids,
                    ),
                )
            };

            if block_in {
                new_ids.push(add_block(
                    "synvoid_ICMP_Block_In_V4",
                    Layer::InboundTransportV4,
                    false,
                )?);
                new_ids.push(add_block(
                    "synvoid_ICMP_Block_In_V6",
                    Layer::InboundTransportV6,
                    true,
                )?);
            }
            if block_out {
                new_ids.push(add_block(
                    "synvoid_ICMP_Block_Out_V4",
                    Layer::OutboundTransportV4,
                    false,
                )?);
                new_ids.push(add_block(
                    "synvoid_ICMP_Block_Out_V6",
                    Layer::OutboundTransportV6,
                    true,
                )?);
            }

            transaction.commit().map_err(|e| {
                IcmpFilterError::Wfp(format!("Failed to commit transaction: {}", e))
            })?;

            tracing::info!(
                "WFP ICMP generation installed ({} filters, {} exempt IPs)",
                new_ids.len(),
                config.exempt_ips.len()
            );
            return Ok(new_ids);
        }

        #[cfg(not(feature = "icmp-wfp"))]
        {
            let _ = (config, old_ids, has_admin);
            return Err(IcmpFilterError::FeatureNotEnabled(
                "icmp-wfp feature not enabled".to_string(),
            ));
        }
    }

    fn remove_generation(&mut self) -> Result<()> {
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

            if self.filter_ids.is_empty() {
                return Ok(());
            }
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
                // Partial cleanup failure is visible (returned), never silent.
                return Err(IcmpFilterError::Wfp(format!(
                    "Some WFP filters failed to remove: {:?}",
                    errors
                        .iter()
                        .map(|(id, e)| format!("{}: {}", id, e))
                        .collect::<Vec<_>>()
                )));
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

/// Deterministic GUID derivation (FNV-1a 128-fold of the identity string).
/// Stable per table across processes without storing secrets.
#[cfg(feature = "icmp-wfp")]
fn guid_for_tag(tag: &str) -> wfp::GUID {
    fn fnv64(seed: u64, bytes: &[u8]) -> u64 {
        let mut h = seed;
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }
    let b = tag.as_bytes();
    let lo = fnv64(0xcbf29ce484222325, b);
    let hi = fnv64(0x84222325cbf29ce4, b);
    let bytes = lo.to_le_bytes();
    let bytes2 = hi.to_le_bytes();
    wfp::GUID {
        data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        data2: u16::from_le_bytes([bytes[4], bytes[5]]),
        data3: u16::from_le_bytes([bytes[6], bytes[7]]),
        data4: bytes2,
    }
}

/// `windows_sys` GUID has no `PartialEq`; compare field-wise.
#[cfg(feature = "icmp-wfp")]
fn guid_eq(a: &wfp::GUID, b: &wfp::GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

#[cfg(feature = "icmp-wfp")]
fn provider_guid_for(table: &str) -> wfp::GUID {
    guid_for_tag(&format!("synvoid-icmp-provider:{table}"))
}

#[cfg(feature = "icmp-wfp")]
fn sublayer_guid_for(table: &str) -> wfp::GUID {
    guid_for_tag(&format!("synvoid-icmp-sublayer:{table}"))
}

/// Provider/sublayer ensure tolerates pre-existing identity (same table =
/// same GUID = same owner); any other I/O error propagates.
#[cfg(feature = "icmp-wfp")]
fn ignore_already_exists(r: std::io::Result<()>) -> std::io::Result<()> {
    match r {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(183) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(feature = "icmp-wfp")]
fn exempt_condition(ip: &IpAddr) -> wfp::Condition {
    use wfp::IpAddressConditionBuilder;
    match ip {
        IpAddr::V4(addr) => IpAddressConditionBuilder::remote()
            .subnet_v4(*addr, 32)
            .build(),
        IpAddr::V6(addr) => IpAddressConditionBuilder::remote()
            .subnet_v6(*addr, 128)
            .build(),
    }
}

#[cfg(feature = "icmp-wfp")]
fn add_filter(
    transaction: &wfp::Transaction<'_>,
    builder: &wfp::FilterBuilder<wfp::FilterBuilderHasName, wfp::FilterBuilderHasAction>,
) -> Result<u64> {
    builder
        .add(transaction)
        .map_err(|e| IcmpFilterError::Wfp(format!("Failed to add WFP filter: {}", e)))
}

#[cfg(feature = "icmp-wfp")]
#[allow(clippy::too_many_arguments)]
fn add_type_rules(
    transaction: &wfp::Transaction<'_>,
    config: &IcmpFilterConfig,
    block_in: bool,
    block_out: bool,
    ifaces: &[wfp::Condition],
    provider_guid: wfp::GUID,
    sublayer_guid: wfp::GUID,
) -> Result<Vec<u64>> {
    use wfp::{ActionType, FilterBuilder, FilterWeight, IcmpConditionBuilder, Layer};

    let mut ids = Vec::new();
    let mut add_rule = |rule: &IcmpTypeRule, layer: Layer, suffix: &str| -> Result<()> {
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
            .sublayer(sublayer_guid)
            .provider(provider_guid)
            .weight(FilterWeight::Exact(WEIGHT_TYPE_RULE))
            .condition(IcmpConditionBuilder::r#type().equal(rule.icmp_type).build());
        if let Some(code) = rule.icmp_code {
            builder = builder.condition(IcmpConditionBuilder::code().equal(code).build());
        }
        for cond in ifaces {
            builder = builder.condition(cond.clone());
        }
        let id = builder
            .add(transaction)
            .map_err(|e| IcmpFilterError::Wfp(format!("Failed to add ICMP type filter: {}", e)))?;
        ids.push(id);
        Ok(())
    };

    for rule in &config.icmp_type_rules {
        if block_in {
            add_rule(rule, Layer::InboundTransportV4, "In")?;
        }
        if block_out {
            add_rule(rule, Layer::OutboundTransportV4, "Out")?;
        }
    }
    for rule in &config.icmpv6_type_rules {
        if block_in {
            add_rule(rule, Layer::InboundTransportV6, "In")?;
        }
        if block_out {
            add_rule(rule, Layer::OutboundTransportV6, "Out")?;
        }
    }
    Ok(ids)
}

impl IcmpFilter for WfpFilter {
    fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(IcmpFilterError::AlreadyEnabled);
        }

        if !self.has_admin {
            return Err(IcmpFilterError::PermissionDenied);
        }

        let _fingerprint = self.planned_fingerprint()?;
        let ids = Self::apply_generation(&self.config, &[], self.has_admin)?;
        self.filter_ids = ids;
        self.enabled = true;
        tracing::info!("ICMP filter enabled via WFP");
        Ok(())
    }

    fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(IcmpFilterError::AlreadyDisabled);
        }

        self.remove_generation()?;
        self.enabled = false;
        tracing::info!("ICMP filter disabled via WFP");
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
        // Compile the replacement before any mutation.
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
        let old = std::mem::replace(&mut self.config, config);
        let was_enabled = self.enabled;
        let want_enabled = self.config.enabled;

        if was_enabled && want_enabled {
            // One transaction retires the old generation and installs the
            // new one; commit failure keeps the old filters live. IDs swap
            // only on success; on failure tracking is restored so disable()
            // can still clean up (caller must not claim Applied).
            let old_ids = std::mem::take(&mut self.filter_ids);
            match Self::apply_generation(&self.config, &old_ids, self.has_admin) {
                Ok(new_ids) => {
                    self.filter_ids = new_ids;
                }
                Err(e) => {
                    self.filter_ids = old_ids;
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
                "WFP backend is not enforcing: administrator privileges not held. \
                 Config updated but changes will not take effect until process runs as admin."
            );
        }

        Ok(())
    }

    fn verify_ownership(&self, plan: &EnforcementPlan) -> VerificationOutcome {
        if !self.enabled {
            return VerificationOutcome::Absent;
        }
        #[cfg(feature = "icmp-wfp")]
        {
            use wfp::{FilterEngineBuilder, FilterEnumerator, Transaction};
            let mut engine = match FilterEngineBuilder::default().dynamic().open() {
                Ok(e) => e,
                Err(e) => {
                    return VerificationOutcome::Unknown {
                        detail: format!("WFP engine unavailable for readback: {e}"),
                    };
                }
            };
            let transaction = match Transaction::new(&mut engine) {
                Ok(t) => t,
                Err(e) => {
                    return VerificationOutcome::Unknown {
                        detail: format!("WFP transaction unavailable for readback: {e}"),
                    };
                }
            };
            let expected_provider = provider_guid_for(&self.config.table_name);
            // Scope the borrow: the enumerator borrows the transaction, so
            // collection finishes before `abort()` moves it.
            let live_ids: std::result::Result<std::collections::HashSet<u64>, String> =
                (|| -> std::result::Result<std::collections::HashSet<u64>, String> {
                    let mut enumerator = FilterEnumerator::new(&transaction)
                        .map_err(|e| format!("WFP enumeration unavailable: {e}"))?;
                    let mut live_ids = std::collections::HashSet::new();
                    while let Some(item) = enumerator.next() {
                        match item {
                            Ok(entry) => {
                                if entry
                                    .provider()
                                    .is_some_and(|g| guid_eq(&g, &expected_provider))
                                {
                                    live_ids.insert(entry.id());
                                }
                            }
                            Err(e) => {
                                return Err(format!("WFP enumeration failed: {e}"));
                            }
                        }
                    }
                    Ok(live_ids)
                })();
            let _ = transaction.abort();
            let live_ids = match live_ids {
                Ok(ids) => ids,
                Err(detail) => {
                    return VerificationOutcome::Unknown { detail };
                }
            };
            let missing: Vec<u64> = self
                .filter_ids
                .iter()
                .filter(|id| !live_ids.contains(id))
                .copied()
                .collect();
            if missing.is_empty() && live_ids.len() >= self.filter_ids.len() {
                // Fingerprint binds the generation; IDs bind the objects.
                let _ = plan.fingerprint;
                VerificationOutcome::Verified
            } else {
                VerificationOutcome::Drifted {
                    detail: format!("{} tracked WFP filters absent live", missing.len()),
                }
            }
        }
        #[cfg(not(feature = "icmp-wfp"))]
        {
            let _ = plan;
            VerificationOutcome::Unknown {
                detail: "icmp-wfp feature not enabled".to_string(),
            }
        }
    }

    fn config(&self) -> &IcmpFilterConfig {
        &self.config
    }
}

impl Drop for WfpFilter {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(e) = self.remove_generation() {
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
