use thiserror::Error;

#[derive(Debug, Error)]
pub enum IcmpFilterError {
    #[error("nftables error: {0}")]
    Nftables(String),

    #[error("eBPF error: {0}")]
    Ebpf(String),

    #[error("PF (Packet Filter) error: {0}")]
    Pf(String),

    #[error("Windows Firewall error: {0}")]
    WindowsFirewall(String),

    #[error("WFP (Windows Filtering Platform) error: {0}")]
    Wfp(String),

    #[error("Permission denied: requires administrator privileges")]
    PermissionDenied,

    #[error("Filter already enabled")]
    AlreadyEnabled,

    #[error("Filter already disabled")]
    AlreadyDisabled,

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unsupported platform: ICMP filtering only available on Linux, macOS, and Windows")]
    UnsupportedPlatform,

    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),
}

pub type Result<T> = std::result::Result<T, IcmpFilterError>;
