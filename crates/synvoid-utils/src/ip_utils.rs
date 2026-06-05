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
