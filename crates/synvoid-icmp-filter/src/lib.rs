pub mod compat;
pub mod config;
pub mod enforce;
pub mod error;
pub mod metrics;
pub mod platform;
pub mod policy;
pub mod traits;
pub mod validation;

#[cfg(target_os = "linux")]
pub mod nftables;

#[cfg(all(target_os = "linux", feature = "icmp-ebpf"))]
pub mod ebpf;

#[cfg(all(target_os = "macos", feature = "icmp-pf"))]
pub mod pf;

#[cfg(all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"))]
pub mod pf_bsd;

#[cfg(all(target_os = "windows", feature = "icmp-winfw"))]
pub mod winfw;

#[cfg(all(target_os = "windows", feature = "icmp-wfp"))]
pub mod wfp;

pub use compat::{adapt_config_to_policy, validate_interface_name, AdaptError};
pub use config::{Direction, FilterType, IcmpFilterConfig, InterfaceSpec, RateLimitConfig};
pub use enforce::{
    compile_policy, fingerprint_hex, ownership_tag_for, pf_anchor_for, policy_fingerprint,
    wfp_provider_name, winfw_rule_prefix, ApplyReceipt, DriverState, EnforcementPlan,
    EnforcementReport, EnforcementState, InstallStage, PolicyCompileResult, VerificationOutcome,
    WINFW_LEGACY_PREFIX,
};
pub use error::{IcmpFilterError, Result};
pub use platform::{
    has_privilege_for, required_privilege_for_operation, FilterOperation, PrivilegeLevel,
};
pub use policy::{
    BackendOptions, IcmpFamily, IcmpPolicy, IcmpRule, IcmpSelector, IcmpV4Type, IcmpV6Type,
    IcmpVerdict, InterfaceSelector, PolicyDirection, PolicyRequirements, RateLimitPolicy,
    RateLimitScope, RequestedBackend, CANONICAL_TABLE_NAME, LEGACY_TABLE_NAME_UNDERSCORE,
};
pub use traits::{BackendCapabilities, FilterBackend, FilterStatus, IcmpFilter};
pub use validation::{
    blocks_packet_too_big, validate_policy, FindingSeverity, PolicyFinding, ValidationOverride,
    ValidationRole,
};

#[cfg(target_os = "linux")]
use nftables::NftablesFilter;

#[cfg(all(target_os = "linux", feature = "icmp-ebpf"))]
use ebpf::EbpfFilter;

#[cfg(all(target_os = "macos", feature = "icmp-pf"))]
use pf::PfFilter;

#[cfg(all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"))]
use pf_bsd::PfBsdFilter;

#[cfg(all(target_os = "windows", feature = "icmp-winfw"))]
use winfw::WinFwFilter;

#[cfg(all(target_os = "windows", feature = "icmp-wfp"))]
use wfp::WfpFilter;

/// Why a backend was selected. Returned to callers on every selection so
/// `Auto` fallback is observable and explicit requests are auditable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionReport {
    pub backend: FilterBackend,
    pub requested: FilterType,
    pub reason: String,
}

/// Strict backend selection (Phase 86, Workstream E).
///
/// - `Auto`: may probe and select a fallback in documented priority order
///   (Linux: eBPF when compiled and usable, else the nftables baseline;
///   Windows: WFP primary, else the winfw compatibility lane).
/// - Explicit (`Nftables`, `Ebpf`, `Pf`, `Wfp`, `WindowsFirewall`): fails
///   with `BackendUnavailable` (carrying the probe detail) when that exact
///   backend is unavailable. Never warns-and-switches.
pub fn select_backend_for_host(requested: FilterType) -> Result<SelectionReport> {
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "icmp-ebpf")]
        use crate::platform::probe_ebpf_load;
        use crate::platform::probe_nftables;
        match requested {
            FilterType::Ebpf => {
                #[cfg(feature = "icmp-ebpf")]
                {
                    let probe = probe_ebpf_load();
                    if probe.usable {
                        return Ok(SelectionReport {
                            backend: FilterBackend::Ebpf,
                            requested,
                            reason: "explicit eBPF request satisfied".to_string(),
                        });
                    }
                    return Err(IcmpFilterError::BackendUnavailable(format!(
                        "explicit eBPF request cannot be satisfied: {}",
                        probe.reason
                    )));
                }
                #[cfg(not(feature = "icmp-ebpf"))]
                {
                    return Err(IcmpFilterError::FeatureNotEnabled(
                        "icmp-ebpf feature not enabled".to_string(),
                    ));
                }
            }
            FilterType::Nftables => {
                let probe = probe_nftables();
                if probe.usable {
                    return Ok(SelectionReport {
                        backend: FilterBackend::Nftables,
                        requested,
                        reason: "explicit nftables request satisfied".to_string(),
                    });
                }
                return Err(IcmpFilterError::BackendUnavailable(format!(
                    "explicit nftables request cannot be satisfied: {}",
                    probe.reason
                )));
            }
            FilterType::Auto => {
                #[cfg(feature = "icmp-ebpf")]
                {
                    if probe_ebpf_load().usable {
                        return Ok(SelectionReport {
                            backend: FilterBackend::Ebpf,
                            requested,
                            reason: "auto: eBPF usable, preferred over nftables baseline"
                                .to_string(),
                        });
                    }
                }
                let probe = probe_nftables();
                if probe.usable {
                    return Ok(SelectionReport {
                        backend: FilterBackend::Nftables,
                        requested,
                        reason: "auto: nftables baseline selected".to_string(),
                    });
                }
                return Err(IcmpFilterError::BackendUnavailable(format!(
                    "auto selection found no usable Linux backend: {}",
                    probe.reason
                )));
            }
            other => {
                return Err(IcmpFilterError::Config(format!(
                    "{other:?} is not available on Linux"
                )));
            }
        }
    }
    #[cfg(all(
        target_os = "windows",
        any(feature = "icmp-winfw", feature = "icmp-wfp")
    ))]
    {
        match requested {
            FilterType::Wfp => {
                #[cfg(feature = "icmp-wfp")]
                {
                    if WfpFilter::is_available() {
                        return Ok(SelectionReport {
                            backend: FilterBackend::Wfp,
                            requested,
                            reason: "explicit WFP request satisfied".to_string(),
                        });
                    }
                    return Err(IcmpFilterError::BackendUnavailable(
                        "explicit WFP request cannot be satisfied: WFP engine unavailable"
                            .to_string(),
                    ));
                }
                #[cfg(not(feature = "icmp-wfp"))]
                {
                    return Err(IcmpFilterError::FeatureNotEnabled(
                        "icmp-wfp feature not enabled".to_string(),
                    ));
                }
            }
            FilterType::WindowsFirewall => {
                #[cfg(feature = "icmp-winfw")]
                {
                    if WinFwFilter::is_available() {
                        return Ok(SelectionReport {
                            backend: FilterBackend::WindowsFirewall,
                            requested,
                            reason: "explicit Windows Firewall request satisfied".to_string(),
                        });
                    }
                    return Err(IcmpFilterError::BackendUnavailable(
                        "explicit Windows Firewall request cannot be satisfied".to_string(),
                    ));
                }
                #[cfg(not(feature = "icmp-winfw"))]
                {
                    return Err(IcmpFilterError::FeatureNotEnabled(
                        "icmp-winfw feature not enabled".to_string(),
                    ));
                }
            }
            FilterType::Auto => {
                // Documented priority: WFP primary, winfw compatibility.
                #[cfg(feature = "icmp-wfp")]
                {
                    if WfpFilter::is_available() {
                        return Ok(SelectionReport {
                            backend: FilterBackend::Wfp,
                            requested,
                            reason: "auto: WFP primary selected".to_string(),
                        });
                    }
                }
                #[cfg(feature = "icmp-winfw")]
                {
                    if WinFwFilter::is_available() {
                        return Ok(SelectionReport {
                            backend: FilterBackend::WindowsFirewall,
                            requested,
                            reason: "auto: WFP unavailable, winfw compatibility lane".to_string(),
                        });
                    }
                }
                return Err(IcmpFilterError::BackendUnavailable(
                    "auto selection found no usable Windows backend".to_string(),
                ));
            }
            other => {
                return Err(IcmpFilterError::Config(format!(
                    "{other:?} is not available on Windows"
                )));
            }
        }
    }
    #[cfg(all(target_os = "macos", feature = "icmp-pf"))]
    {
        match requested {
            FilterType::Pf | FilterType::Auto => {
                if pf::PfFilter::is_available() {
                    return Ok(SelectionReport {
                        backend: FilterBackend::Pf,
                        requested,
                        reason: "macOS PF selected (single PF lane)".to_string(),
                    });
                }
                return Err(IcmpFilterError::BackendUnavailable(
                    "explicit PF request cannot be satisfied: pfctl unavailable".to_string(),
                ));
            }
            other => {
                return Err(IcmpFilterError::Config(format!(
                    "{other:?} is not available on macOS"
                )));
            }
        }
    }
    #[cfg(all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"))]
    {
        match requested {
            FilterType::Pf | FilterType::Auto => {
                if pf_bsd::PfBsdFilter::is_available() {
                    return Ok(SelectionReport {
                        backend: FilterBackend::Pf,
                        requested,
                        reason: "BSD PF selected (single PF lane)".to_string(),
                    });
                }
                return Err(IcmpFilterError::BackendUnavailable(
                    "explicit PF request cannot be satisfied: pfctl unavailable".to_string(),
                ));
            }
            other => {
                return Err(IcmpFilterError::Config(format!(
                    "{other:?} is not available on this BSD"
                )));
            }
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        all(
            target_os = "windows",
            any(feature = "icmp-winfw", feature = "icmp-wfp")
        ),
        all(target_os = "macos", feature = "icmp-pf"),
        all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf")
    )))]
    {
        // NetBSD and all other targets compile to an explicit unsupported
        // result (NPF is the NetBSD future trigger, not PF).
        let _ = requested;
        Err(IcmpFilterError::UnsupportedPlatform)
    }
}

#[derive(Debug)]
pub struct IcmpFilterManager {
    #[cfg(any(
        target_os = "linux",
        all(target_os = "macos", feature = "icmp-pf"),
        all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
        all(
            target_os = "windows",
            any(feature = "icmp-winfw", feature = "icmp-wfp")
        )
    ))]
    filter: Box<dyn IcmpFilter>,
    /// Replacement driver state: desired vs applied vs verified.
    /// `status()` stays a compat desired-state view; `report()` is truth.
    #[cfg(any(
        target_os = "linux",
        all(target_os = "macos", feature = "icmp-pf"),
        all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
        all(
            target_os = "windows",
            any(feature = "icmp-winfw", feature = "icmp-wfp")
        )
    ))]
    driver: DriverState,
    #[cfg(not(any(
        target_os = "linux",
        all(target_os = "macos", feature = "icmp-pf"),
        all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
        all(
            target_os = "windows",
            any(feature = "icmp-winfw", feature = "icmp-wfp")
        )
    )))]
    _phantom: (),
}

impl IcmpFilterManager {
    #[cfg(any(
        target_os = "linux",
        all(target_os = "macos", feature = "icmp-pf"),
        all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
        all(
            target_os = "windows",
            any(feature = "icmp-winfw", feature = "icmp-wfp")
        )
    ))]
    pub fn new(config: IcmpFilterConfig) -> Result<Self> {
        let filter = Self::create_filter(config)?;
        Ok(Self {
            filter,
            driver: DriverState::default(),
        })
    }

    #[cfg(not(any(
        target_os = "linux",
        all(target_os = "macos", feature = "icmp-pf"),
        all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
        all(
            target_os = "windows",
            any(feature = "icmp-winfw", feature = "icmp-wfp")
        )
    )))]
    pub fn new(_config: IcmpFilterConfig) -> Result<Self> {
        Err(IcmpFilterError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    fn create_filter(config: IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>> {
        let report = select_backend_for_host(config.filter_type)?;
        tracing::info!("ICMP backend selected: {}", report.reason);
        match report.backend {
            FilterBackend::Ebpf => {
                #[cfg(feature = "icmp-ebpf")]
                {
                    Ok(Box::new(EbpfFilter::new(config)?))
                }
                #[cfg(not(feature = "icmp-ebpf"))]
                {
                    Err(IcmpFilterError::FeatureNotEnabled(
                        "icmp-ebpf feature not enabled".to_string(),
                    ))
                }
            }
            FilterBackend::Nftables => Ok(Box::new(NftablesFilter::new(config)?)),
            other => Err(IcmpFilterError::Config(format!(
                "{other:?} is not available on Linux"
            ))),
        }
    }

    #[cfg(all(target_os = "macos", feature = "icmp-pf"))]
    fn create_filter(config: IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>> {
        let report = select_backend_for_host(config.filter_type)?;
        tracing::info!("ICMP backend selected: {}", report.reason);
        match report.backend {
            FilterBackend::Pf => Ok(Box::new(PfFilter::new(config)?)),
            other => Err(IcmpFilterError::Config(format!(
                "{other:?} is not available on macOS"
            ))),
        }
    }

    #[cfg(all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"))]
    fn create_filter(config: IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>> {
        let report = select_backend_for_host(config.filter_type)?;
        tracing::info!("ICMP backend selected: {}", report.reason);
        match report.backend {
            FilterBackend::Pf => Ok(Box::new(PfBsdFilter::new(config)?)),
            other => Err(IcmpFilterError::Config(format!(
                "{other:?} is not available on this BSD"
            ))),
        }
    }

    #[cfg(all(
        target_os = "windows",
        any(feature = "icmp-winfw", feature = "icmp-wfp")
    ))]
    fn create_filter(config: IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>> {
        // Explicit requests are strict: no silent WFP->winfw fallback.
        let report = select_backend_for_host(config.filter_type)?;
        tracing::info!("ICMP backend selected: {}", report.reason);
        match report.backend {
            FilterBackend::Wfp => {
                #[cfg(feature = "icmp-wfp")]
                {
                    Ok(Box::new(WfpFilter::new(config)?))
                }
                #[cfg(not(feature = "icmp-wfp"))]
                {
                    Err(IcmpFilterError::FeatureNotEnabled(
                        "icmp-wfp feature not enabled".to_string(),
                    ))
                }
            }
            FilterBackend::WindowsFirewall => {
                #[cfg(feature = "icmp-winfw")]
                {
                    Ok(Box::new(WinFwFilter::new(config)?))
                }
                #[cfg(not(feature = "icmp-winfw"))]
                {
                    Err(IcmpFilterError::FeatureNotEnabled(
                        "icmp-winfw feature not enabled".to_string(),
                    ))
                }
            }
            other => Err(IcmpFilterError::Config(format!(
                "{other:?} is not available on Windows"
            ))),
        }
    }

    /// Enable current policy through the verified lifecycle (Phase 90
    /// Finding A). Kernel state never changes without `DriverState`
    /// advancing: enable succeeds only when installation plus live
    /// verification succeeds. No receipt is created on failure.
    pub fn enable(&mut self) -> Result<ApplyReceipt> {
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        ))]
        {
            drive_enable(&mut *self.filter, &mut self.driver)
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        )))]
        {
            Err(IcmpFilterError::UnsupportedPlatform)
        }
    }

    /// Disable enforcement through the verified lifecycle (Phase 90
    /// Finding A). Succeeds only when owned enforcement is verified absent.
    /// Returns an explicit Unknown/Drifted error disposition when absence
    /// cannot be proven. The previous apply receipt is retained as
    /// historical information; the report makes clear live desired state is
    /// disabled/Absent.
    pub fn disable(&mut self) -> Result<()> {
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        ))]
        {
            drive_disable(&mut *self.filter, &mut self.driver)
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        )))]
        {
            Err(IcmpFilterError::UnsupportedPlatform)
        }
    }

    pub fn is_enabled(&self) -> bool {
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        ))]
        {
            self.filter.is_enabled()
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        )))]
        {
            false
        }
    }

    pub fn is_enforcing(&self) -> bool {
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        ))]
        {
            self.filter.is_enforcing()
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        )))]
        {
            tracing::warn!("ICMP filter manager: no backend active on this platform");
            false
        }
    }

    pub fn status(&self) -> Option<FilterStatus> {
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        ))]
        {
            Some(self.filter.status())
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        )))]
        {
            None
        }
    }

    pub fn update_config(&mut self, config: IcmpFilterConfig) -> Result<()> {
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        ))]
        {
            // Workstream C/F: compile-before-mutate with verified receipts
            // through the shared driver (same flow the fake tests prove).
            drive_update(&mut *self.filter, config, &mut self.driver).map(|_| ())
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        )))]
        {
            let _ = config;
            Err(IcmpFilterError::UnsupportedPlatform)
        }
    }

    /// Desired vs applied vs verified report. `last_receipt` advances only
    /// on verified installs; `live` is never inferred from `enabled`.
    /// Authoritative for operator enforcement state (Phase 90).
    pub fn report(&self) -> Option<EnforcementReport> {
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        ))]
        {
            Some(EnforcementReport {
                backend: self.filter.backend(),
                desired_enabled: self.driver.desired_enabled,
                desired_fingerprint: self.driver.desired_fingerprint,
                desired_generation: self.driver.generation,
                last_receipt: self.driver.last_receipt.clone(),
                live: self.driver.live.unwrap_or(EnforcementState::Unknown),
                last_verify_error: self.driver.last_verify_error.clone(),
            })
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        )))]
        {
            None
        }
    }

    /// Re-probe live state without changing desired/applied generations.
    /// Surfaces drift that happened outside this process.
    pub fn verify_live(&mut self) -> VerificationOutcome {
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        ))]
        {
            // Rebuild the compile plan from live config so backends with
            // cardinality readback (PF) verify exact counts.
            let plan = rebuild_verify_plan(self.filter.backend(), self.filter.config());
            let outcome = self.filter.verify_ownership(&plan);
            match &outcome {
                VerificationOutcome::Verified => {
                    self.driver.live = Some(EnforcementState::Applied);
                    self.driver.last_verify_error = None;
                }
                VerificationOutcome::Absent => {
                    self.driver.live = Some(EnforcementState::Absent);
                    self.driver.last_verify_error = Some("owned objects absent".to_string());
                }
                VerificationOutcome::Drifted { detail } => {
                    self.driver.live = Some(EnforcementState::Drifted);
                    self.driver.last_verify_error = Some(detail.clone());
                    crate::metrics::icmp_drift_detected(backend_label(self.filter.backend()));
                }
                VerificationOutcome::Unknown { detail } => {
                    self.driver.live = Some(EnforcementState::Unknown);
                    self.driver.last_verify_error = Some(detail.clone());
                }
            }
            crate::metrics::icmp_verification_observed(
                backend_label(self.filter.backend()),
                match outcome {
                    VerificationOutcome::Verified => "applied",
                    VerificationOutcome::Absent => "absent",
                    VerificationOutcome::Drifted { .. } => "drifted",
                    VerificationOutcome::Unknown { .. } => "unknown",
                },
            );
            return outcome;
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        )))]
        {
            VerificationOutcome::Unknown {
                detail: "no backend compiled for this host".to_string(),
            }
        }
    }

    pub fn config(&self) -> Option<&IcmpFilterConfig> {
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        ))]
        {
            Some(self.filter.config())
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
            all(
                target_os = "windows",
                any(feature = "icmp-winfw", feature = "icmp-wfp")
            )
        )))]
        {
            None
        }
    }
}

/// Rebuild a verify-capable plan from live config. Returns a plan whose
/// fingerprint is `0` with an `uncompilable` tag when adaptation fails, so
/// readback degrades to `Unknown`/`Absent` instead of panicking.
/// Available on all platforms so the verified disable path (Phase 90) can
/// prove absence without kernel access in tests.
fn rebuild_verify_plan(backend: FilterBackend, config: &IcmpFilterConfig) -> EnforcementPlan {
    match adapt_config_to_policy(config) {
        Ok((policy, backend_options)) => match compile_policy(backend, &policy, &backend_options) {
            PolicyCompileResult::Exact(plan) => plan,
            PolicyCompileResult::Unsupported { .. } => EnforcementPlan {
                backend,
                fingerprint: 0,
                ownership_tag: "uncompilable".to_string(),
                operations_summary: String::new(),
                expected_rule_count: None,
                warnings: Vec::new(),
            },
        },
        Err(_) => EnforcementPlan {
            backend,
            fingerprint: 0,
            ownership_tag: "uncompilable".to_string(),
            operations_summary: String::new(),
            expected_rule_count: None,
            warnings: Vec::new(),
        },
    }
}

/// Phase 87 replacement driver: compile-before-mutate with verified
/// receipts. Operates on any `IcmpFilter` (real backends and test fakes
/// share this exact flow):
/// 1. adapt + compile the replacement (pure; zero mutation on failure);
/// 2. install through the backend's atomic/staged replacement;
/// 3. verify live owned state;
/// 4. advance the receipt/generation only on `Verified`.
///
/// Returns the new receipt on success. Any other outcome leaves applied
/// state un-advanced and records `live` + `last_verify_error` on `driver`.
/// Verification failure (`Drifted`/`Unknown`/unexpected `Absent`) is an
/// error, never hidden behind success.
pub fn drive_update(
    filter: &mut dyn IcmpFilter,
    config: IcmpFilterConfig,
    driver: &mut DriverState,
) -> Result<ApplyReceipt> {
    let (policy, backend_options) =
        adapt_config_to_policy(&config).map_err(IcmpFilterError::from)?;
    let backend = filter.backend();
    let plan = match compile_policy(backend, &policy, &backend_options) {
        PolicyCompileResult::Exact(plan) => plan,
        PolicyCompileResult::Unsupported { reasons, .. } => {
            crate::metrics::icmp_apply_finished(backend_label(backend), "compile_rejected");
            return Err(IcmpFilterError::Unsupported(format!(
                "replacement policy inexpressible on {backend:?}: {}",
                reasons.join("; ")
            )));
        }
    };
    driver.desired_fingerprint = Some(plan.fingerprint);
    driver.desired_enabled = Some(config.enabled);
    if let Err(e) = filter.update_config(config) {
        crate::metrics::icmp_apply_finished(backend_label(backend), "install_failed");
        driver.last_verify_error =
            Some(format!("install failed, previous generation retained: {e}"));
        return Err(e);
    }
    match filter.verify_ownership(&plan) {
        VerificationOutcome::Verified => {
            driver.generation += 1;
            let receipt = ApplyReceipt {
                backend,
                fingerprint: plan.fingerprint,
                generation: driver.generation,
                applied_at_secs: now_secs(),
                ownership_tag: plan.ownership_tag.clone(),
            };
            driver.last_receipt = Some(receipt.clone());
            driver.live = Some(EnforcementState::Applied);
            driver.last_verify_error = None;
            crate::metrics::icmp_apply_finished(backend_label(backend), "applied");
            crate::metrics::icmp_verification_observed(backend_label(backend), "applied");
            Ok(receipt)
        }
        VerificationOutcome::Absent => {
            driver.live = Some(EnforcementState::Absent);
            driver.last_verify_error = Some("owned objects absent after install".to_string());
            crate::metrics::icmp_apply_finished(backend_label(backend), "drifted");
            Err(IcmpFilterError::BackendUnavailable(
                "install succeeded but owned objects are absent live (drifted)".to_string(),
            ))
        }
        VerificationOutcome::Drifted { detail } => {
            driver.live = Some(EnforcementState::Drifted);
            driver.last_verify_error = Some(detail.clone());
            crate::metrics::icmp_apply_finished(backend_label(backend), "drifted");
            crate::metrics::icmp_drift_detected(backend_label(backend));
            Err(IcmpFilterError::BackendUnavailable(format!(
                "install succeeded but live state drifted: {detail}"
            )))
        }
        VerificationOutcome::Unknown { detail } => {
            driver.live = Some(EnforcementState::Unknown);
            driver.last_verify_error = Some(detail.clone());
            crate::metrics::icmp_apply_finished(backend_label(backend), "unknown");
            Err(IcmpFilterError::BackendUnavailable(format!(
                "install succeeded but live state is unverifiable: {detail}"
            )))
        }
    }
}

/// Phase 90 Finding A: verified enable lifecycle.
///
/// Shares the manager-owned `DriverState` with replacement/disable: the
/// desired enabled state, generation/fingerprint, receipt, selected backend,
/// live state, and last verification error advance together. Enable succeeds
/// only when installation plus live verification succeeds; a failed enable
/// creates no apply receipt.
pub fn drive_enable(filter: &mut dyn IcmpFilter, driver: &mut DriverState) -> Result<ApplyReceipt> {
    driver.desired_enabled = Some(true);
    let backend = filter.backend();
    // Compile the current policy first (pure): an inexpressible policy
    // installs nothing and advances no receipt.
    let (policy, backend_options) =
        adapt_config_to_policy(filter.config()).map_err(IcmpFilterError::from)?;
    let plan = match compile_policy(backend, &policy, &backend_options) {
        PolicyCompileResult::Exact(plan) => plan,
        PolicyCompileResult::Unsupported { reasons, .. } => {
            crate::metrics::icmp_apply_finished(backend_label(backend), "compile_rejected");
            driver.last_verify_error = Some(format!(
                "enable policy inexpressible on {backend:?}: {}",
                reasons.join("; ")
            ));
            return Err(IcmpFilterError::Unsupported(format!(
                "enable policy inexpressible on {backend:?}: {}",
                reasons.join("; ")
            )));
        }
    };
    driver.desired_fingerprint = Some(plan.fingerprint);
    match filter.enable() {
        Ok(()) => {}
        Err(IcmpFilterError::AlreadyEnabled) => {
            // Idempotent path: already enabled — fall through to live
            // verification of the current install rather than failing.
        }
        Err(e) => {
            crate::metrics::icmp_apply_finished(backend_label(backend), "install_failed");
            driver.last_verify_error = Some(format!("enable failed, no state change claimed: {e}"));
            return Err(e);
        }
    }
    match filter.verify_ownership(&plan) {
        VerificationOutcome::Verified => {
            driver.generation += 1;
            let receipt = ApplyReceipt {
                backend,
                fingerprint: plan.fingerprint,
                generation: driver.generation,
                applied_at_secs: now_secs(),
                ownership_tag: plan.ownership_tag.clone(),
            };
            driver.last_receipt = Some(receipt.clone());
            driver.live = Some(EnforcementState::Applied);
            driver.last_verify_error = None;
            crate::metrics::icmp_apply_finished(backend_label(backend), "applied");
            crate::metrics::icmp_verification_observed(backend_label(backend), "applied");
            Ok(receipt)
        }
        VerificationOutcome::Absent => {
            driver.live = Some(EnforcementState::Absent);
            driver.last_verify_error =
                Some("enable succeeded but owned objects are absent live".to_string());
            crate::metrics::icmp_apply_finished(backend_label(backend), "drifted");
            Err(IcmpFilterError::BackendUnavailable(
                "enable succeeded but owned objects are absent live".to_string(),
            ))
        }
        VerificationOutcome::Drifted { detail } => {
            driver.live = Some(EnforcementState::Drifted);
            driver.last_verify_error = Some(detail.clone());
            crate::metrics::icmp_apply_finished(backend_label(backend), "drifted");
            crate::metrics::icmp_drift_detected(backend_label(backend));
            Err(IcmpFilterError::BackendUnavailable(format!(
                "enable succeeded but live state drifted: {detail}"
            )))
        }
        VerificationOutcome::Unknown { detail } => {
            driver.live = Some(EnforcementState::Unknown);
            driver.last_verify_error = Some(detail.clone());
            crate::metrics::icmp_apply_finished(backend_label(backend), "unknown");
            Err(IcmpFilterError::BackendUnavailable(format!(
                "enable succeeded but live state is unverifiable: {detail}"
            )))
        }
    }
}

/// Phase 90 Finding A: verified disable lifecycle.
///
/// Succeeds only when owned enforcement is verified absent. Returns an
/// explicit Unknown/Drifted error disposition when absence cannot be proven.
/// The previous apply receipt is retained as historical information; the
/// report's desired/live state makes clear enforcement is disabled/Absent.
/// A failed disable never claims Absent.
pub fn drive_disable(filter: &mut dyn IcmpFilter, driver: &mut DriverState) -> Result<()> {
    driver.desired_enabled = Some(false);
    let backend = filter.backend();
    // Already-disabled fast path: prove absence rather than assuming it.
    if !filter.is_enabled() {
        let plan = rebuild_verify_plan(backend, filter.config());
        match filter.verify_ownership(&plan) {
            VerificationOutcome::Absent => {
                driver.live = Some(EnforcementState::Absent);
                driver.last_verify_error = None;
                return Ok(());
            }
            VerificationOutcome::Verified => {
                driver.live = Some(EnforcementState::Drifted);
                driver.last_verify_error = Some(
                    "filter reports disabled but owned objects are live (drifted)".to_string(),
                );
                crate::metrics::icmp_drift_detected(backend_label(backend));
                return Err(IcmpFilterError::BackendUnavailable(
                    "filter reports disabled but owned objects are live".to_string(),
                ));
            }
            VerificationOutcome::Drifted { detail } => {
                driver.live = Some(EnforcementState::Drifted);
                driver.last_verify_error = Some(detail.clone());
                return Err(IcmpFilterError::BackendUnavailable(format!(
                    "disable state drifted: {detail}"
                )));
            }
            VerificationOutcome::Unknown { detail } => {
                driver.live = Some(EnforcementState::Unknown);
                driver.last_verify_error = Some(detail.clone());
                return Err(IcmpFilterError::BackendUnavailable(format!(
                    "disable state unverifiable: {detail}"
                )));
            }
        }
    }
    match filter.disable() {
        Ok(()) => {}
        Err(IcmpFilterError::AlreadyDisabled) => {
            // Lost a race with a concurrent disable: verify absence below.
        }
        Err(e) => {
            driver.last_verify_error = Some(format!("disable failed: {e}"));
            return Err(e);
        }
    }
    let plan = rebuild_verify_plan(backend, filter.config());
    match filter.verify_ownership(&plan) {
        VerificationOutcome::Absent => {
            driver.live = Some(EnforcementState::Absent);
            driver.last_verify_error = None;
            crate::metrics::icmp_apply_finished(backend_label(backend), "disabled");
            Ok(())
        }
        VerificationOutcome::Verified => {
            driver.live = Some(EnforcementState::Drifted);
            driver.last_verify_error =
                Some("disable removed the enabled flag but owned objects remain live".to_string());
            crate::metrics::icmp_drift_detected(backend_label(backend));
            Err(IcmpFilterError::BackendUnavailable(
                "disable removed the enabled flag but owned objects remain live".to_string(),
            ))
        }
        VerificationOutcome::Drifted { detail } => {
            driver.live = Some(EnforcementState::Drifted);
            driver.last_verify_error = Some(detail.clone());
            Err(IcmpFilterError::BackendUnavailable(format!(
                "disable left drifted state: {detail}"
            )))
        }
        VerificationOutcome::Unknown { detail } => {
            driver.live = Some(EnforcementState::Unknown);
            driver.last_verify_error = Some(detail.clone());
            Err(IcmpFilterError::BackendUnavailable(format!(
                "disable state unverifiable (absence unproven): {detail}"
            )))
        }
    }
}

/// Phase 90 Finding D: backend inventory entry projecting the Phase 86
/// probe/selection model. Distinguishes compiled, mechanism-present,
/// privileged/usable, and selected: an empty list is never the only way to
/// express "compiled but insufficient privilege".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendInventoryEntry {
    pub backend: FilterBackend,
    /// Compiled into this build.
    pub compiled: bool,
    /// Usable on this host (`compiled && mechanism_present && privilege`).
    pub usable: bool,
    /// Human reason when unusable; "usable" when usable.
    pub reason: String,
}

/// Project the Phase 86 probe model into an inventory describing relevant
/// backends even when unusable. `current_backend` (selected) comes from the
/// manager report, never from this list.
pub fn probe_backend_inventory() -> Vec<BackendInventoryEntry> {
    let mut out = Vec::new();
    #[cfg(target_os = "linux")]
    {
        let probe = crate::platform::probe_nftables();
        out.push(BackendInventoryEntry {
            backend: FilterBackend::Nftables,
            compiled: true,
            usable: probe.usable,
            reason: probe.reason.clone(),
        });
        #[cfg(feature = "icmp-ebpf")]
        {
            let probe = crate::platform::probe_ebpf_load();
            out.push(BackendInventoryEntry {
                backend: FilterBackend::Ebpf,
                compiled: true,
                usable: probe.usable,
                reason: probe.reason.clone(),
            });
        }
        #[cfg(not(feature = "icmp-ebpf"))]
        {
            out.push(BackendInventoryEntry {
                backend: FilterBackend::Ebpf,
                compiled: false,
                usable: false,
                reason: "eBPF backend requires Linux + icmp-ebpf feature".to_string(),
            });
        }
    }
    #[cfg(all(target_os = "macos", feature = "icmp-pf"))]
    {
        let usable = PfFilter::is_available();
        out.push(BackendInventoryEntry {
            backend: FilterBackend::Pf,
            compiled: true,
            usable,
            reason: if usable {
                "usable".to_string()
            } else {
                "pfctl unavailable or insufficient privilege".to_string()
            },
        });
    }
    #[cfg(all(target_os = "macos", not(feature = "icmp-pf")))]
    {
        out.push(BackendInventoryEntry {
            backend: FilterBackend::Pf,
            compiled: false,
            usable: false,
            reason: "pf backend requires macos + icmp-pf feature".to_string(),
        });
    }
    #[cfg(all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"))]
    {
        let usable = PfBsdFilter::is_available();
        out.push(BackendInventoryEntry {
            backend: FilterBackend::Pf,
            compiled: true,
            usable,
            reason: if usable {
                "usable".to_string()
            } else {
                "pfctl unavailable or insufficient privilege".to_string()
            },
        });
    }
    #[cfg(all(
        target_os = "windows",
        any(feature = "icmp-winfw", feature = "icmp-wfp")
    ))]
    {
        #[cfg(feature = "icmp-wfp")]
        {
            let usable = WfpFilter::is_available();
            out.push(BackendInventoryEntry {
                backend: FilterBackend::Wfp,
                compiled: true,
                usable,
                reason: if usable {
                    "usable".to_string()
                } else {
                    "WFP engine unavailable or insufficient privilege".to_string()
                },
            });
        }
        #[cfg(feature = "icmp-winfw")]
        {
            let usable = WinFwFilter::is_available();
            out.push(BackendInventoryEntry {
                backend: FilterBackend::WindowsFirewall,
                compiled: true,
                usable,
                reason: if usable {
                    "usable".to_string()
                } else {
                    "Windows Firewall COM engine unavailable".to_string()
                },
            });
        }
    }
    out
}

fn backend_label(backend: FilterBackend) -> &'static str {
    match backend {
        FilterBackend::Nftables => "nftables",
        FilterBackend::Ebpf => "ebpf",
        FilterBackend::Pf => "pf",
        FilterBackend::WindowsFirewall => "winfw",
        FilterBackend::Wfp => "wfp",
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn is_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "icmp-ebpf")]
        {
            EbpfFilter::is_available() || NftablesFilter::is_available()
        }
        #[cfg(not(feature = "icmp-ebpf"))]
        {
            NftablesFilter::is_available()
        }
    }
    #[cfg(all(target_os = "macos", feature = "icmp-pf"))]
    {
        PfFilter::is_available()
    }
    #[cfg(all(target_os = "macos", not(feature = "icmp-pf")))]
    {
        false
    }
    #[cfg(all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"))]
    {
        PfBsdFilter::is_available()
    }
    #[cfg(all(
        any(target_os = "freebsd", target_os = "openbsd"),
        not(feature = "icmp-pf")
    ))]
    {
        false
    }
    #[cfg(all(
        target_os = "windows",
        any(feature = "icmp-winfw", feature = "icmp-wfp")
    ))]
    {
        #[cfg(feature = "icmp-winfw")]
        {
            WinFwFilter::is_available()
        }
        #[cfg(all(not(feature = "icmp-winfw"), feature = "icmp-wfp"))]
        {
            WfpFilter::is_available()
        }
    }
    #[cfg(all(
        target_os = "windows",
        not(any(feature = "icmp-winfw", feature = "icmp-wfp"))
    ))]
    {
        false
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "windows"
    )))]
    {
        false
    }
}

pub fn available_backends() -> Vec<FilterBackend> {
    #[cfg(any(
        target_os = "linux",
        all(target_os = "macos", feature = "icmp-pf"),
        all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
        all(
            target_os = "windows",
            any(feature = "icmp-winfw", feature = "icmp-wfp")
        )
    ))]
    let mut backends = Vec::new();
    #[cfg(not(any(
        target_os = "linux",
        all(target_os = "macos", feature = "icmp-pf"),
        all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"),
        all(
            target_os = "windows",
            any(feature = "icmp-winfw", feature = "icmp-wfp")
        )
    )))]
    let backends = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if NftablesFilter::is_available() {
            backends.push(FilterBackend::Nftables);
        }

        #[cfg(feature = "icmp-ebpf")]
        {
            if EbpfFilter::is_available() {
                backends.push(FilterBackend::Ebpf);
            }
        }
    }

    #[cfg(all(target_os = "macos", feature = "icmp-pf"))]
    {
        if PfFilter::is_available() {
            backends.push(FilterBackend::Pf);
        }
    }

    #[cfg(all(any(target_os = "freebsd", target_os = "openbsd"), feature = "icmp-pf"))]
    {
        if PfBsdFilter::is_available() {
            backends.push(FilterBackend::Pf);
        }
    }

    #[cfg(all(target_os = "windows", feature = "icmp-winfw"))]
    {
        if WinFwFilter::is_available() {
            backends.push(FilterBackend::WindowsFirewall);
        }
    }

    #[cfg(all(target_os = "windows", feature = "icmp-wfp"))]
    {
        if WfpFilter::is_available() {
            backends.push(FilterBackend::Wfp);
        }
    }

    backends
}
