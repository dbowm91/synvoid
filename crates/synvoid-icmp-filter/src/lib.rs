pub mod compat;
pub mod config;
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
        Ok(Self { filter })
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

    pub fn enable(&mut self) -> Result<()> {
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
            self.filter.enable()
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
            self.filter.disable()
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
            self.filter.update_config(config)
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
