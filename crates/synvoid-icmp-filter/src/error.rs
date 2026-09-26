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

    #[error("Policy adaptation error: {0}")]
    Adapt(String),

    #[error("Unsupported policy semantics: {0}")]
    Unsupported(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unsupported platform: ICMP filtering available on Linux (nftables/eBPF), macOS/FreeBSD/OpenBSD (PF), and Windows (WFP primary, Windows Firewall fallback). NetBSD packet filtering is NPF, not PF: explicitly unsupported, NPF is a separately scoped future backend")]
    UnsupportedPlatform,

    #[error("Backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),
}

pub type Result<T> = std::result::Result<T, IcmpFilterError>;
