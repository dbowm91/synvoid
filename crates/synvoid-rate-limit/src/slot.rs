//! Pure IP-to-slot hash for sharded admission structures.
//!
//! This is a deliberate, documented duplication of the canonical helper in
//! `synvoid-utils` (`ip_to_slot`). Copying ~50 lines of pure hashing keeps
//! this crate dependency-free (std only) instead of pulling an upward utility
//! coupling into a leaf mechanism crate. `synvoid-utils` remains the
//! general-purpose owner; this copy must stay behaviorally identical for the
//! slot mapping and is covered by the same determinism tests.

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn same_ip_maps_to_same_slot() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ip_to_slot(ip, 65536), ip_to_slot(ip, 65536));
        let ip6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(ip_to_slot(ip6, 65536), ip_to_slot(ip6, 65536));
    }

    #[test]
    fn slots_stay_in_range_for_both_families() {
        for slots in [1usize, 16, 100, 256, 65536] {
            for i in 0..256u32 {
                let v4 = IpAddr::V4(Ipv4Addr::from(i * 16_777_217));
                let slot = ip_to_slot(v4, slots).unwrap();
                assert!(slot < slots, "v4 slot {slot} out of {slots}");
                let v6 = IpAddr::V6(Ipv6Addr::from(i as u128 * 1_000_000_007));
                let slot6 = ip_to_slot(v6, slots).unwrap();
                assert!(slot6 < slots, "v6 slot {slot6} out of {slots}");
            }
        }
    }

    #[test]
    fn zero_slots_returns_none() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(ip_to_slot(v4, 0), None);
        assert_eq!(ip_to_slot(v6, 0), None);
    }

    #[test]
    fn distinct_ips_spread_across_shards() {
        // Shard distribution invariant: 1024 sequential client IPs must cover
        // a healthy majority of 64 shards (no pathological pile-up).
        let mut seen = std::collections::HashSet::new();
        for i in 0..1024u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + i));
            seen.insert(ip_to_slot(ip, 64).unwrap());
        }
        assert!(
            seen.len() >= 48,
            "expected broad shard spread, covered only {} of 64",
            seen.len()
        );
    }
}
