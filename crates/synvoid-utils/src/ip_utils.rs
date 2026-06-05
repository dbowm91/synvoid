use std::net::IpAddr;

/// Maps an IP address to a slot index within `[0, num_slots)`.
///
/// Returns `None` if `num_slots` is 0. Uses a power-of-two fast path
/// when `num_slots` is a power of two.
#[inline]
pub fn ip_to_slot(ip: IpAddr, num_slots: usize) -> Option<usize> {
    if num_slots == 0 {
        return None;
    }
    if num_slots.is_power_of_two() {
        let mask = num_slots - 1;
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let hash = ((u32::from(octets[0]) << 24)
                    | (u32::from(octets[1]) << 16)
                    | (u32::from(octets[2]) << 8)
                    | u32::from(octets[3]))
                .wrapping_mul(0x9e3779b9);
                Some(((hash >> 16) as usize) & mask)
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                let hash = ((segments[0] as u64) << 48
                    | (segments[1] as u64) << 32
                    | (segments[2] as u64) << 16
                    | segments[3] as u64)
                    .wrapping_mul(0x9e3779b9);
                Some(((hash >> 16) as usize) & mask)
            }
        }
    } else {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let hash = ((u32::from(octets[0]) << 24)
                    | (u32::from(octets[1]) << 16)
                    | (u32::from(octets[2]) << 8)
                    | u32::from(octets[3]))
                .wrapping_mul(0x9e3779b9);
                Some((hash as usize) % num_slots)
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                let hash = ((segments[0] as u64) << 48
                    | (segments[1] as u64) << 32
                    | (segments[2] as u64) << 16
                    | segments[3] as u64)
                    .wrapping_mul(0x9e3779b9);
                Some((hash as usize) % num_slots)
            }
        }
    }
}

/// Returns seconds since UNIX_EPOCH, defaulting to 0 on error (e.g. clock skew).
#[inline]
pub fn safe_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns milliseconds since UNIX_EPOCH, defaulting to 0 on error.
#[inline]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Returns Duration since UNIX_EPOCH, defaulting to zero duration on error.
#[inline]
pub fn safe_unix_duration() -> std::time::Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

/// Returns seconds since UNIX_EPOCH (alias for safe_unix_timestamp).
#[inline]
pub fn current_timestamp() -> u64 {
    safe_unix_timestamp()
}

/// Returns the first non-loopback IPv4 address found on this machine.
pub fn get_first_non_loopback_ip() -> Result<std::net::IpAddr, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("Failed to bind socket: {}", e))?;
    socket
        .connect("8.8.8.8:53")
        .map_err(|e| format!("Failed to connect: {}", e))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("Failed to get local addr: {}", e))?;
    Ok(local_addr.ip())
}

/// Compares two semver-style version strings, returns true if `new` > `current`.
pub fn is_newer_version(new: &str, current: &str) -> bool {
    if new == current {
        return false;
    }
    let new_parts: Vec<u32> = new.split('.').filter_map(|s| s.parse().ok()).collect();
    let current_parts: Vec<u32> = current.split('.').filter_map(|s| s.parse().ok()).collect();
    for i in 0..new_parts.len().max(current_parts.len()) {
        let new_part = new_parts.get(i).unwrap_or(&0);
        let current_part = current_parts.get(i).unwrap_or(&0);
        if new_part > current_part {
            return true;
        }
        if new_part < current_part {
            return false;
        }
    }
    false
}
