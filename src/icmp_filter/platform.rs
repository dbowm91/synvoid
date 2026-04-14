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
    Vec::new()
}

#[cfg(target_os = "windows")]
pub fn interface_name_to_alias(name: &str) -> Option<String> {
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
