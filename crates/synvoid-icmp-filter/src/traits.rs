use crate::{config::IcmpFilterConfig, error::Result};
use std::fmt::Debug;

/*
 * ICMP Filter Backend Capabilities
 *
 * | Backend             | Platform | Supported Operations            | Required Privilege        | Active Enforcement |
 * |---------------------|----------|----------------------------------|---------------------------|---------------------|
 * | nftables            | Linux    | block/allow/rate-limit/iface     | root or CAP_NET_ADMIN     | Yes (kernel)        |
 * | eBPF (XDP/TC)       | Linux    | block/allow/rate-limit/iface     | root or CAP_BPF+CAP_NET_ADMIN | Yes (kernel)   |
 * | pf (macOS)          | macOS    | block/allow/rate-limit/iface     | root                      | Yes (kernel)        |
 * | pf (FreeBSD/etc)    | BSD      | block/allow/rate-limit/iface     | root                      | Yes (kernel)        |
 * | Windows Firewall    | Windows  | block/allow/type-code/iface      | Administrator             | Yes (WFP stack)     |
 * | WFP                 | Windows  | block/allow/type-code/iface      | Administrator             | Yes (WFP stack)     |
 * | Unsupported stub    | Other    | none                             | N/A                       | No                  |
 *
 * Privilege details:
 *   - Linux nftables: requires CAP_NET_ADMIN (checked via /proc/self/status CapEff bit 12)
 *     or effective UID 0.
 *   - Linux eBPF: requires CAP_BPF + CAP_NET_ADMIN on kernels >= 5.8 when
 *     unprivileged_bpf_disabled != 0; otherwise root.
 *   - macOS/BSD pf: requires root (uid/euid == 0) to execute pfctl.
 *   - Windows Firewall/WFP: requires the Administrators group SID (checked via
 *     CheckTokenMembership with DOMAIN_ALIAS_RID_ADMINS).
 *   - Binding TCP ports < 1024 (privileged ports) requires root on Linux/macOS/BSD
 *     or Administrator on Windows — this is a separate check from firewall privileges.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterBackend {
    #[default]
    Nftables,
    Ebpf,
    Pf,
    WindowsFirewall,
    Wfp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub backend: FilterBackend,
    pub supports_block: bool,
    pub supports_allow: bool,
    pub supports_rate_limit: bool,
    pub supports_type_code_matching: bool,
    pub supports_interface_filtering: bool,
    pub requires_admin: bool,
    pub is_enforcing: bool,
}

impl BackendCapabilities {
    pub fn for_backend(backend: FilterBackend) -> Self {
        match backend {
            FilterBackend::Nftables => Self {
                backend,
                supports_block: true,
                supports_allow: true,
                supports_rate_limit: true,
                supports_type_code_matching: true,
                supports_interface_filtering: true,
                requires_admin: true,
                is_enforcing: true,
            },
            FilterBackend::Ebpf => Self {
                backend,
                supports_block: true,
                supports_allow: true,
                supports_rate_limit: true,
                supports_type_code_matching: true,
                supports_interface_filtering: true,
                requires_admin: true,
                is_enforcing: true,
            },
            FilterBackend::Pf => Self {
                backend,
                supports_block: true,
                supports_allow: true,
                supports_rate_limit: true,
                supports_type_code_matching: true,
                supports_interface_filtering: true,
                requires_admin: true,
                is_enforcing: true,
            },
            FilterBackend::WindowsFirewall => Self {
                backend,
                supports_block: true,
                supports_allow: true,
                supports_rate_limit: false,
                supports_type_code_matching: true,
                supports_interface_filtering: true,
                requires_admin: true,
                is_enforcing: true,
            },
            FilterBackend::Wfp => Self {
                backend,
                supports_block: true,
                supports_allow: true,
                supports_rate_limit: false,
                supports_type_code_matching: true,
                supports_interface_filtering: true,
                requires_admin: true,
                is_enforcing: true,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilterStatus {
    pub enabled: bool,
    pub backend: FilterBackend,
    pub config: IcmpFilterConfig,
}

impl Default for FilterStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: FilterBackend::default(),
            config: IcmpFilterConfig::default(),
        }
    }
}

pub trait IcmpFilter: Debug + Send + Sync {
    fn enable(&mut self) -> Result<()>;
    fn disable(&mut self) -> Result<()>;
    fn is_enabled(&self) -> bool;
    fn is_enforcing(&self) -> bool;
    fn backend(&self) -> FilterBackend;
    fn status(&self) -> FilterStatus;
    fn update_config(&mut self, config: IcmpFilterConfig) -> Result<()>;
    fn config(&self) -> &IcmpFilterConfig;
}

pub trait IcmpFilterFactory: Debug + Send + Sync {
    fn create(&self, config: IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>>;
    fn backend(&self) -> FilterBackend;
    fn is_available(&self) -> bool;
}
