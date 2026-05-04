#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevel {
    None,
    LowPortBinding,
    NetAdmin,
    EbpfAdmin,
    Administrator,
}

pub fn required_privilege_for_operation(op: FilterOperation) -> PrivilegeLevel {
    match op {
        FilterOperation::BindLowPort => PrivilegeLevel::LowPortBinding,
        FilterOperation::Nftables => PrivilegeLevel::NetAdmin,
        FilterOperation::EbpfLoad => PrivilegeLevel::EbpfAdmin,
        FilterOperation::PfControl => PrivilegeLevel::Administrator,
        FilterOperation::WindowsFirewall => PrivilegeLevel::Administrator,
        FilterOperation::WindowsWfp => PrivilegeLevel::Administrator,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterState {
    InactiveNotPrivileged,
    InactiveConfigError,
    Active,
}

impl FilterState {
    pub fn is_active(&self) -> bool {
        matches!(self, FilterState::Active)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOperation {
    BindLowPort,
    Nftables,
    EbpfLoad,
    PfControl,
    WindowsFirewall,
    WindowsWfp,
}

pub fn can_load_ebpf() -> bool {
    #[cfg(target_os = "linux")]
    {
        is_admin()
    }
    #[cfg(not(target_os = "linux"))]
    {
        is_admin()
    }
}

pub fn can_modify_nftables() -> bool {
    #[cfg(target_os = "linux")]
    {
        is_admin()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub fn can_modify_firewall() -> bool {
    is_admin()
}

pub fn filter_state_for_operation(op: FilterOperation) -> FilterState {
    if has_privilege_for(op) {
        FilterState::Active
    } else {
        FilterState::InactiveNotPrivileged
    }
}

pub fn has_privilege_for(op: FilterOperation) -> bool {
    match op {
        FilterOperation::BindLowPort => can_bind_low_ports(),
        FilterOperation::Nftables => can_modify_nftables(),
        FilterOperation::EbpfLoad => can_load_ebpf(),
        FilterOperation::PfControl => is_admin(),
        FilterOperation::WindowsFirewall => can_modify_firewall(),
        FilterOperation::WindowsWfp => can_modify_firewall(),
    }
}

fn can_bind_low_ports() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() == 0 || libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        is_admin()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
pub fn is_admin() -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::BOOL;
    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, FreeSid, DOMAIN_ALIAS_RID_ADMINS,
        SECURITY_BUILTIN_DOMAIN_RID, SECURITY_NT_AUTHORITY, SID_IDENTIFIER_AUTHORITY,
    };

    // SAFETY: This block calls Windows API functions to create a SID for the administrators group.
    // The returned pointer is valid until freed; we free it with FreeSid. All calls return a BOOL which
    // indicates success or failure, and we check the result before using the SID.
    unsafe {
        let mut authority = SID_IDENTIFIER_AUTHORITY {
            Value: SECURITY_NT_AUTHORITY,
        };
        let mut admin_sid: *mut _ = ptr::null_mut();

        let result = AllocateAndInitializeSid(
            &mut authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut admin_sid,
        );

        if result == 0 {
            return false;
        }

        let mut is_admin: BOOL = 0;
        let check_result = CheckTokenMembership(ptr::null_mut(), admin_sid, &mut is_admin);

        FreeSid(admin_sid);

        check_result != 0 && is_admin != 0
    }
}

#[cfg(target_os = "windows")]
pub fn get_network_interfaces() -> Vec<String> {
    tracing::warn!("get_network_interfaces stub: returning empty list (no native resolver active)");
    Vec::new()
}

#[cfg(target_os = "windows")]
pub fn interface_name_to_alias(name: &str) -> Option<String> {
    tracing::debug!("interface_name_to_alias stub: passing through '{}'", name);
    Some(name.to_string())
}

#[cfg(target_os = "linux")]
pub fn is_admin() -> bool {
    // SAFETY: getuid/geteuid are always safe system calls that return the real/effective user ID.
    if unsafe { libc::getuid() == 0 || libc::geteuid() == 0 } {
        return true;
    }

    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled") {
        if content.trim() != "0" {
            return false;
        }
    }

    has_cap_net_admin()
}

#[cfg(target_os = "linux")]
fn has_cap_net_admin() -> bool {
    use std::fs;

    if let Ok(content) = fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("CapEff:") {
                let caps_hex = line.split(':').nth(1).unwrap_or("0").trim();
                if let Ok(caps) = u64::from_str_radix(caps_hex, 16) {
                    const CAP_NET_ADMIN: u64 = 12;
                    return (caps & (1 << CAP_NET_ADMIN)) != 0;
                }
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
pub fn is_admin() -> bool {
    // SAFETY: getuid/geteuid are always safe system calls that return the real/effective user ID.
    unsafe { libc::getuid() == 0 || libc::geteuid() == 0 }
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub fn is_admin() -> bool {
    // SAFETY: getuid/geteuid are always safe system calls that return the real/effective user ID.
    unsafe { libc::getuid() == 0 || libc::geteuid() == 0 }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
pub fn is_admin() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_levels_map_correctly() {
        assert_eq!(
            required_privilege_for_operation(FilterOperation::BindLowPort),
            PrivilegeLevel::LowPortBinding
        );
        assert_eq!(
            required_privilege_for_operation(FilterOperation::Nftables),
            PrivilegeLevel::NetAdmin
        );
        assert_eq!(
            required_privilege_for_operation(FilterOperation::EbpfLoad),
            PrivilegeLevel::EbpfAdmin
        );
        assert_eq!(
            required_privilege_for_operation(FilterOperation::PfControl),
            PrivilegeLevel::Administrator
        );
        assert_eq!(
            required_privilege_for_operation(FilterOperation::WindowsFirewall),
            PrivilegeLevel::Administrator
        );
        assert_eq!(
            required_privilege_for_operation(FilterOperation::WindowsWfp),
            PrivilegeLevel::Administrator
        );
    }

    #[test]
    fn test_filter_state_inactive_when_not_privileged() {
        let state = filter_state_for_operation(FilterOperation::Nftables);
        if !is_admin() {
            assert_eq!(state, FilterState::InactiveNotPrivileged);
        }
    }

    #[test]
    fn test_can_load_ebpf_respects_bpf_disabled() {
        #[cfg(target_os = "linux")]
        {
            let can_load = can_load_ebpf();
            let is_root = unsafe { libc::getuid() == 0 || libc::geteuid() == 0 };
            let can_admin = is_admin();

            if !is_root {
                if let Ok(content) =
                    std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
                {
                    if content.trim() == "2" {
                        assert!(
                            !can_load,
                            "eBPF should be disabled when unprivileged_bpf_disabled=2"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_can_modify_nftables_linux_only() {
        #[cfg(target_os = "linux")]
        {
            let can_modify = can_modify_nftables();
            assert_eq!(can_modify, is_admin());
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!can_modify_nftables());
        }
    }

    #[test]
    fn test_can_modify_firewall_admin_required() {
        let can_modify = can_modify_firewall();
        assert_eq!(can_modify, is_admin());
    }

    #[test]
    fn test_filter_state_active_when_privileged() {
        if is_admin() {
            let state = filter_state_for_operation(FilterOperation::Nftables);
            assert_eq!(state, FilterState::Active);
        }
    }

    #[test]
    fn test_can_bind_low_ports_matches_admin_on_unix() {
        #[cfg(unix)]
        {
            let is_root = unsafe { libc::getuid() == 0 || libc::geteuid() == 0 };
            assert_eq!(can_bind_low_ports(), is_root);
        }
    }
}
