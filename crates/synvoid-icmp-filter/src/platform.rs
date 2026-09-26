//! Operation-specific privilege and mechanism probing (Phase 86).
//!
//! The old generic Linux `is_admin()` read `unprivileged_bpf_disabled`,
//! coupling nftables availability to an unrelated BPF sysctl. Probes here
//! are operation-specific: nftables checks only the authority nftables
//! needs; eBPF distinguishes BPF-load privilege from network-attach
//! privilege and kernel support. `CAP_NET_BIND_SERVICE` / low-port checks
//! are not part of the ICMP public vocabulary: no ICMP backend requires
//! them.

/// Linux capability bit indices (from `linux/capability.h`).
pub const CAP_NET_ADMIN_BIT: u32 = 12;
pub const CAP_BPF_BIT: u32 = 39;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevel {
    None,
    NetAdmin,
    EbpfAdmin,
    Administrator,
}

pub fn required_privilege_for_operation(op: FilterOperation) -> PrivilegeLevel {
    match op {
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
    Nftables,
    EbpfLoad,
    PfControl,
    WindowsFirewall,
    WindowsWfp,
}

/// Whether the current process holds the probed privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeState {
    Sufficient,
    Insufficient,
    /// The probe could not determine privilege (e.g. `/proc` unreadable on
    /// an unexpected platform). Callers must fail closed on `Unknown`.
    Unknown,
}

/// Operation-specific probe result. Static expressiveness lives in
/// `crate::traits::BackendCapabilities`; everything runtime lives here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendProbe {
    /// The backend code is compiled into this build.
    pub compiled: bool,
    /// The host mechanism exists (binary present, kernel support, API
    /// reachable) independent of privilege.
    pub mechanism_present: bool,
    /// Whether the process holds the privilege this operation needs.
    pub privilege: PrivilegeState,
    /// `compiled && mechanism_present && privilege == Sufficient`.
    pub usable: bool,
    /// Human-readable reason naming the failed condition, if any.
    pub reason: String,
}

impl BackendProbe {
    #[cfg(any(test, target_os = "linux"))]
    fn build(compiled: bool, mechanism_present: bool, privilege: PrivilegeState) -> Self {
        let usable = compiled && mechanism_present && privilege == PrivilegeState::Sufficient;
        let reason = if !compiled {
            "backend not compiled into this build".to_string()
        } else if !mechanism_present {
            "host mechanism absent".to_string()
        } else if privilege != PrivilegeState::Sufficient {
            "insufficient privilege".to_string()
        } else {
            "usable".to_string()
        };
        Self {
            compiled,
            mechanism_present,
            privilege,
            usable,
            reason,
        }
    }

    pub fn not_compiled(reason: &'static str) -> Self {
        Self {
            compiled: false,
            mechanism_present: false,
            privilege: PrivilegeState::Unknown,
            usable: false,
            reason: reason.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure, fixture-testable capability parsing
// ---------------------------------------------------------------------------

/// Parse the hex capability mask from a `/proc/self/status`-style
/// `CapEff:` line value (e.g. `"00000000800405fb"`).
pub fn parse_cap_eff_hex(hex: &str) -> Option<u64> {
    u64::from_str_radix(hex.trim(), 16).ok()
}

/// True if capability `bit` is set in the parsed mask.
pub fn cap_is_set(caps: u64, bit: u32) -> bool {
    if bit >= 64 {
        return false;
    }
    (caps & (1 << bit)) != 0
}

/// Extract the effective capability mask from full `/proc/self/status`
/// text. Returns `None` when the `CapEff:` line is absent or malformed.
pub fn parse_cap_eff_status(status_text: &str) -> Option<u64> {
    for line in status_text.lines() {
        if line.starts_with("CapEff:") {
            let hex = line.split(':').nth(1).unwrap_or("").trim();
            return parse_cap_eff_hex(hex);
        }
    }
    None
}

/// Fixture-testable predicate: does this status text grant `bit`?
pub fn has_cap_in_status(status_text: &str, bit: u32) -> bool {
    parse_cap_eff_status(status_text).is_some_and(|caps| cap_is_set(caps, bit))
}

// ---------------------------------------------------------------------------
// Linux helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn process_is_root() -> bool {
    // SAFETY: getuid/geteuid are always-safe syscalls returning ids.
    unsafe { libc::getuid() == 0 || libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
fn read_status_text() -> Option<String> {
    std::fs::read_to_string("/proc/self/status").ok()
}

#[cfg(target_os = "linux")]
fn has_cap_net_admin() -> bool {
    if process_is_root() {
        return true;
    }
    read_status_text().is_some_and(|t| has_cap_in_status(&t, CAP_NET_ADMIN_BIT))
}

#[cfg(all(target_os = "linux", feature = "icmp-ebpf"))]
fn has_cap_bpf() -> bool {
    if process_is_root() {
        return true;
    }
    read_status_text().is_some_and(|t| has_cap_in_status(&t, CAP_BPF_BIT))
}

/// Read `/proc/sys/kernel/unprivileged_bpf_disabled`. `None` when unreadable.
/// This value is diagnostic context for eBPF probes only; it never affects
/// the nftables answer.
#[cfg(target_os = "linux")]
pub fn read_unprivileged_bpf_disabled() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
        .ok()
        .map(|s| s.trim().to_string())
}

/// Probe nftables authority: root or `CAP_NET_ADMIN`. Never consults BPF
/// sysctls.
pub fn probe_nftables() -> BackendProbe {
    #[cfg(target_os = "linux")]
    {
        let mechanism_present = std::process::Command::new("nft")
            .arg("--version")
            .output()
            .is_ok();
        let privilege = if read_status_text().is_none() && !process_is_root() {
            PrivilegeState::Unknown
        } else if has_cap_net_admin() {
            PrivilegeState::Sufficient
        } else {
            PrivilegeState::Insufficient
        };
        let mut probe = BackendProbe::build(true, mechanism_present, privilege);
        if !probe.usable {
            probe.reason = if !mechanism_present {
                "nft binary not found".to_string()
            } else {
                "nftables requires root or CAP_NET_ADMIN".to_string()
            };
        }
        probe
    }
    #[cfg(not(target_os = "linux"))]
    {
        BackendProbe::not_compiled("nftables backend compiles on Linux only")
    }
}

/// Probe eBPF *load* privilege: root or `CAP_BPF` on kernels >= 5.8 where
/// unprivileged loads are disabled; kernel/BTF support is reported as
/// mechanism presence, separately from privilege.
pub fn probe_ebpf_load() -> BackendProbe {
    #[cfg(all(target_os = "linux", feature = "icmp-ebpf"))]
    {
        let mechanism_present = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
        let privilege = if read_status_text().is_none() && !process_is_root() {
            PrivilegeState::Unknown
        } else if has_cap_bpf() {
            PrivilegeState::Sufficient
        } else {
            PrivilegeState::Insufficient
        };
        let mut probe = BackendProbe::build(true, mechanism_present, privilege);
        if !probe.usable {
            probe.reason = if !mechanism_present {
                "kernel BTF (/sys/kernel/btf/vmlinux) absent".to_string()
            } else {
                match read_unprivileged_bpf_disabled().as_deref() {
                    Some("2") => "eBPF load requires root or CAP_BPF (unprivileged_bpf_disabled=2)"
                        .to_string(),
                    _ => "eBPF load requires root or CAP_BPF".to_string(),
                }
            };
        }
        probe
    }
    #[cfg(not(all(target_os = "linux", feature = "icmp-ebpf")))]
    {
        BackendProbe::not_compiled("eBPF backend requires Linux + icmp-ebpf feature")
    }
}

/// Probe eBPF network-*attach* privilege: root or `CAP_NET_ADMIN`.
/// Attaching XDP/TC programs is a network-admin operation, distinct from
/// loading BPF bytecode.
pub fn probe_ebpf_attach() -> BackendProbe {
    #[cfg(all(target_os = "linux", feature = "icmp-ebpf"))]
    {
        let privilege = if read_status_text().is_none() && !process_is_root() {
            PrivilegeState::Unknown
        } else if has_cap_net_admin() {
            PrivilegeState::Sufficient
        } else {
            PrivilegeState::Insufficient
        };
        let mut probe = BackendProbe::build(true, true, privilege);
        if !probe.usable {
            probe.reason = "eBPF attach requires root or CAP_NET_ADMIN".to_string();
        }
        probe
    }
    #[cfg(not(all(target_os = "linux", feature = "icmp-ebpf")))]
    {
        BackendProbe::not_compiled("eBPF backend requires Linux + icmp-ebpf feature")
    }
}

pub fn can_load_ebpf() -> bool {
    probe_ebpf_load().usable
}

pub fn can_modify_nftables() -> bool {
    probe_nftables().usable
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
        FilterOperation::Nftables => can_modify_nftables(),
        FilterOperation::EbpfLoad => can_load_ebpf(),
        FilterOperation::PfControl => is_admin(),
        FilterOperation::WindowsFirewall => can_modify_firewall(),
        FilterOperation::WindowsWfp => can_modify_firewall(),
    }
}

// ---------------------------------------------------------------------------
// Windows helpers (real interface resolution; no stubs)
// ---------------------------------------------------------------------------

/// Parse a numeric interface index. Pure and unit-testable on every
/// platform; the WFP backend accepts numeric indices directly.
pub fn parse_interface_index(s: &str) -> Option<u32> {
    s.trim().parse::<u32>().ok()
}

#[cfg(target_os = "windows")]
pub fn is_admin() -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::BOOL;
    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, FreeSid, SECURITY_NT_AUTHORITY,
        SID_IDENTIFIER_AUTHORITY,
    };

    // Well-known RID values (windows-sys 0.59 exposes no constants for them).
    const SECURITY_BUILTIN_DOMAIN_RID: u32 = 32;
    const DOMAIN_ALIAS_RID_ADMINS: u32 = 544;

    // SAFETY: Windows SID APIs with a valid out-pointer, freed via FreeSid.
    // Return values are checked before the SID is used.
    unsafe {
        let mut authority: SID_IDENTIFIER_AUTHORITY = SECURITY_NT_AUTHORITY;
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

        let mut is_member: BOOL = 0;
        let check_result = CheckTokenMembership(ptr::null_mut(), admin_sid, &mut is_member);

        FreeSid(admin_sid);

        check_result != 0 && is_member != 0
    }
}

/// Resolve a configured interface name to a WFP LUID.
///
/// Numeric strings resolve via `ConvertInterfaceIndexToLuid`; adapter names
/// resolve via `ConvertInterfaceAliasToLuid`. Unresolvable names are a hard
/// error — never silently dropped.
#[cfg(target_os = "windows")]
pub fn resolve_interface_luid(name: &str) -> std::io::Result<u64> {
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceIndexToLuid,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    if let Some(index) = parse_interface_index(name) {
        // SAFETY: out-pointer to a stack LUID; return code checked.
        unsafe {
            let mut luid = std::mem::zeroed::<NET_LUID_LH>();
            let status = ConvertInterfaceIndexToLuid(index, &mut luid);
            if status != NO_ERROR {
                return Err(std::io::Error::from_raw_os_error(status as i32));
            }
            // SAFETY: NET_LUID_LH is an 8-byte union; reading Value is valid.
            return Ok(luid.Value);
        }
    }

    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: null-terminated UTF-16 + valid out-pointer; return checked.
    unsafe {
        let mut luid = std::mem::zeroed::<NET_LUID_LH>();
        let status = ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid);
        if status != NO_ERROR {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        // SAFETY: NET_LUID_LH is an 8-byte union; reading Value is valid.
        Ok(luid.Value)
    }
}

/// Enumerate adapter friendly names via `GetAdaptersAddresses`.
#[cfg(target_os = "windows")]
pub fn get_network_interfaces() -> Vec<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetAdaptersAddresses;
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    // SAFETY: two-call buffer-size pattern per API contract; all pointers
    // valid for the call duration; linked-list traversal bounds reads by the
    // returned buffer length.
    unsafe {
        let mut size: u32 = 0;
        // First call yields the required size (ERROR_BUFFER_OVERFLOW expected).
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        );
        if size == 0 || size > 16 * 1024 * 1024 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        let addrs = buf.as_mut_ptr()
            as *mut windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;
        let rc = GetAdaptersAddresses(AF_UNSPEC as u32, 0, std::ptr::null(), addrs, &mut size);
        if rc != 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut cur = addrs;
        while !cur.is_null() {
            let name_ptr = (*cur).FriendlyName;
            if !name_ptr.is_null() {
                let mut len = 0usize;
                while *name_ptr.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(name_ptr, len);
                out.push(String::from_utf16_lossy(slice));
            }
            cur = (*cur).Next;
        }
        out
    }
}

#[cfg(target_os = "linux")]
pub fn is_admin() -> bool {
    // Coarse network-admin check: root or CAP_NET_ADMIN. This intentionally
    // reads no BPF sysctl (Phase 86): BPF state never affects an nftables
    // answer. Backend probes (`probe_nftables`, `probe_ebpf_load`) are
    // authoritative for their operations, not this helper.
    if process_is_root() {
        return true;
    }
    has_cap_net_admin()
}

#[cfg(target_os = "macos")]
pub fn is_admin() -> bool {
    // SAFETY: getuid/geteuid are always safe system calls.
    unsafe { libc::getuid() == 0 || libc::geteuid() == 0 }
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
pub fn is_admin() -> bool {
    // SAFETY: getuid/geteuid are always safe system calls.
    unsafe { libc::getuid() == 0 || libc::geteuid() == 0 }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "openbsd"
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
    fn cap_eff_parsing_fixture() {
        // CAP_NET_ADMIN (bit 12) + CAP_SYS_ADMIN (bit 21) set.
        let caps = parse_cap_eff_hex("0000000000201000").unwrap();
        assert!(cap_is_set(caps, 12));
        assert!(cap_is_set(caps, 21));
        assert!(!cap_is_set(caps, 39));
        // Empty caps grant nothing.
        assert!(!cap_is_set(0, 12));
        // Out-of-range bit never set.
        assert!(!cap_is_set(u64::MAX, 64));
        // Malformed hex rejected.
        assert!(parse_cap_eff_hex("not-hex").is_none());
    }

    #[test]
    fn status_text_parsing_fixture() {
        let text = "Name:\ttest\nCapEff:\t0000000000201000\nFoo:\tbar\n";
        let caps = parse_cap_eff_status(text).unwrap();
        assert!(cap_is_set(caps, 12));
        assert!(has_cap_in_status(text, 12));
        assert!(!has_cap_in_status("Name:\tx\n", 12));
        assert!(!has_cap_in_status("", 12));
    }

    #[test]
    fn nftables_probe_independent_of_bpf_sysctl() {
        // The nftables probe path never reads the BPF sysctl: assert the
        // probe result equals the pure capability predicate, whatever the
        // sysctl file contains.
        #[cfg(target_os = "linux")]
        {
            let probe = probe_nftables();
            let expected = is_admin();
            // usable requires the nft binary too; privilege must match.
            assert_eq!(
                probe.privilege == PrivilegeState::Sufficient,
                expected,
                "nftables privilege must equal root-or-CAP_NET_ADMIN, got {:?}",
                probe
            );
        }
    }

    #[test]
    fn parse_interface_index_fixture() {
        assert_eq!(parse_interface_index("7"), Some(7));
        assert_eq!(parse_interface_index(" 42 "), Some(42));
        assert_eq!(parse_interface_index("eth0"), None);
        assert_eq!(parse_interface_index(""), None);
        assert_eq!(parse_interface_index("4294967296"), None);
    }

    #[test]
    fn probe_result_shape() {
        let p = BackendProbe::build(true, true, PrivilegeState::Sufficient);
        assert!(p.usable);
        assert_eq!(p.reason, "usable");
        let q = BackendProbe::build(true, false, PrivilegeState::Sufficient);
        assert!(!q.usable);
        let r = BackendProbe::not_compiled("test");
        assert!(!r.compiled && !r.usable);
    }

    #[test]
    fn test_filter_state_inactive_when_not_privileged() {
        let state = filter_state_for_operation(FilterOperation::Nftables);
        if !is_admin() {
            assert_eq!(state, FilterState::InactiveNotPrivileged);
        }
    }

    #[test]
    fn test_can_modify_nftables_linux_only() {
        #[cfg(target_os = "linux")]
        {
            let can_modify = can_modify_nftables();
            assert_eq!(can_modify, probe_nftables().usable);
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
}
