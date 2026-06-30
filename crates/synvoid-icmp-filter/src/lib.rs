pub mod config;
pub mod error;
pub mod metrics;
pub mod platform;
pub mod traits;

#[cfg(target_os = "linux")]
pub mod nftables;

#[cfg(all(target_os = "linux", feature = "icmp-ebpf"))]
pub mod ebpf;

#[cfg(all(target_os = "macos", feature = "icmp-pf"))]
pub mod pf;

#[cfg(all(
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
    feature = "icmp-pf"
))]
pub mod pf_bsd;

#[cfg(all(target_os = "windows", feature = "icmp-winfw"))]
pub mod winfw;

#[cfg(all(target_os = "windows", feature = "icmp-wfp"))]
pub mod wfp;

pub use config::{Direction, FilterType, IcmpFilterConfig, InterfaceSpec, RateLimitConfig};
pub use error::{IcmpFilterError, Result};
pub use platform::{
    has_privilege_for, required_privilege_for_operation, FilterOperation, PrivilegeLevel,
};
pub use traits::{BackendCapabilities, FilterBackend, FilterStatus, IcmpFilter};

#[cfg(target_os = "linux")]
use nftables::NftablesFilter;

#[cfg(all(target_os = "linux", feature = "icmp-ebpf"))]
use ebpf::EbpfFilter;

#[cfg(all(target_os = "macos", feature = "icmp-pf"))]
use pf::PfFilter;

#[cfg(all(
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
    feature = "icmp-pf"
))]
use pf_bsd::PfBsdFilter;

#[cfg(all(target_os = "windows", feature = "icmp-winfw"))]
use winfw::WinFwFilter;

#[cfg(all(target_os = "windows", feature = "icmp-wfp"))]
use wfp::WfpFilter;

#[derive(Debug)]
pub struct IcmpFilterManager {
    #[cfg(any(
        target_os = "linux",
        all(target_os = "macos", feature = "icmp-pf"),
        all(
            any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
            feature = "icmp-pf"
        ),
        all(
            target_os = "windows",
            any(feature = "icmp-winfw", feature = "icmp-wfp")
        )
    ))]
    filter: Box<dyn IcmpFilter>,
    #[cfg(not(any(
        target_os = "linux",
        all(target_os = "macos", feature = "icmp-pf"),
        all(
            any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
            feature = "icmp-pf"
        ),
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
        all(
            any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
            feature = "icmp-pf"
        ),
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
        all(
            any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
            feature = "icmp-pf"
        ),
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
        match config.filter_type {
            FilterType::Ebpf => {
                #[cfg(feature = "icmp-ebpf")]
                {
                    if EbpfFilter::is_available() {
                        return Ok(Box::new(EbpfFilter::new(config)?));
                    }
                    tracing::warn!("eBPF requested but not available, falling back to nftables");
                }
                #[cfg(not(feature = "icmp-ebpf"))]
                {
                    Err(IcmpFilterError::FeatureNotEnabled(
                        "icmp-ebpf feature not enabled".to_string(),
                    ))
                }
            }
            FilterType::Nftables => Ok(Box::new(NftablesFilter::new(config)?)),
            FilterType::Auto => {
                #[cfg(feature = "icmp-ebpf")]
                {
                    if EbpfFilter::is_available() {
                        return Ok(Box::new(EbpfFilter::new(config)?));
                    }
                }
                Ok(Box::new(NftablesFilter::new(config)?))
            }
            FilterType::Pf => Err(IcmpFilterError::Config(
                "PF is not available on Linux".to_string(),
            )),
            FilterType::WindowsFirewall => Err(IcmpFilterError::Config(
                "Windows Firewall is not available on Linux".to_string(),
            )),
            FilterType::Wfp => Err(IcmpFilterError::Config(
                "WFP is not available on Linux".to_string(),
            )),
        }
    }

    #[cfg(all(target_os = "macos", feature = "icmp-pf"))]
    fn create_filter(config: IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>> {
        match config.filter_type {
            FilterType::Pf | FilterType::Auto => Ok(Box::new(PfFilter::new(config)?)),
            FilterType::Nftables => Err(IcmpFilterError::Config(
                "nftables is not available on macOS".to_string(),
            )),
            FilterType::Ebpf => Err(IcmpFilterError::Config(
                "eBPF is not available on macOS".to_string(),
            )),
            FilterType::WindowsFirewall => Err(IcmpFilterError::Config(
                "Windows Firewall is not available on macOS".to_string(),
            )),
            FilterType::Wfp => Err(IcmpFilterError::Config(
                "WFP is not available on macOS".to_string(),
            )),
        }
    }

    #[cfg(all(
        any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
        feature = "icmp-pf"
    ))]
    fn create_filter(config: IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>> {
        match config.filter_type {
            FilterType::Pf | FilterType::Auto => Ok(Box::new(PfBsdFilter::new(config)?)),
            FilterType::Nftables => Err(IcmpFilterError::Config(
                "nftables is not available on BSD".to_string(),
            )),
            FilterType::Ebpf => Err(IcmpFilterError::Config(
                "eBPF is not available on BSD".to_string(),
            )),
            FilterType::WindowsFirewall => Err(IcmpFilterError::Config(
                "Windows Firewall is not available on BSD".to_string(),
            )),
            FilterType::Wfp => Err(IcmpFilterError::Config(
                "WFP is not available on BSD".to_string(),
            )),
        }
    }

    #[cfg(all(
        target_os = "windows",
        any(feature = "icmp-winfw", feature = "icmp-wfp")
    ))]
    fn create_filter(config: IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>> {
        match config.filter_type {
            FilterType::Wfp => {
                #[cfg(feature = "icmp-wfp")]
                {
                    if WfpFilter::is_available() {
                        return Ok(Box::new(WfpFilter::new(config)?));
                    }
                    tracing::warn!(
                        "WFP requested but not available, falling back to Windows Firewall"
                    );
                }
                #[cfg(not(feature = "icmp-wfp"))]
                {
                    return Err(IcmpFilterError::FeatureNotEnabled(
                        "icmp-wfp feature not enabled".to_string(),
                    ));
                }
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
            FilterType::WindowsFirewall | FilterType::Auto => {
                #[cfg(feature = "icmp-winfw")]
                {
                    Ok(Box::new(WinFwFilter::new(config)?))
                }
                #[cfg(not(feature = "icmp-winfw"))]
                {
                    #[cfg(feature = "icmp-wfp")]
                    {
                        Ok(Box::new(WfpFilter::new(config)?))
                    }
                    #[cfg(not(feature = "icmp-wfp"))]
                    {
                        Err(IcmpFilterError::FeatureNotEnabled(
                            "No Windows ICMP filter feature enabled".to_string(),
                        ))
                    }
                }
            }
            FilterType::Nftables => Err(IcmpFilterError::Config(
                "nftables is not available on Windows".to_string(),
            )),
            FilterType::Ebpf => Err(IcmpFilterError::Config(
                "eBPF is not available on Windows".to_string(),
            )),
            FilterType::Pf => Err(IcmpFilterError::Config(
                "PF is not available on Windows".to_string(),
            )),
        }
    }

    pub fn enable(&mut self) -> Result<()> {
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "icmp-pf"),
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
            all(
                any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
                feature = "icmp-pf"
            ),
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
    #[cfg(all(
        any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
        feature = "icmp-pf"
    ))]
    {
        PfBsdFilter::is_available()
    }
    #[cfg(all(
        any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
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
        target_os = "netbsd",
        target_os = "windows"
    )))]
    {
        false
    }
}

pub fn available_backends() -> Vec<FilterBackend> {
    let mut backends = Vec::new();

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

    #[cfg(all(
        any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"),
        feature = "icmp-pf"
    ))]
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
