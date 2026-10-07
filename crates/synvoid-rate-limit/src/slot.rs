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
                // Fold all 128 bits. Hashing only segments[0..4] dropped the
                // interface ID, so every address in one /64 shared a single
                // rate-limit bucket and legitimate hosts throttled each other.
                let hi = ((segments[0] as u64) << 48
                    | (segments[1] as u64) << 32
                    | (segments[2] as u64) << 16
                    | segments[3] as u64)
                    .wrapping_mul(0x9e3779b97f4a7c15);
                let lo = ((segments[4] as u64) << 48
                    | (segments[5] as u64) << 32
                    | (segments[6] as u64) << 16
                    | segments[7] as u64)
                    .wrapping_mul(0x9e3779b97f4a7c15);
                let hash = hi ^ lo.rotate_left(32);
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
                // Fold all 128 bits. Hashing only segments[0..4] dropped the
                // interface ID, so every address in one /64 shared a single
                // rate-limit bucket and legitimate hosts throttled each other.
                let hi = ((segments[0] as u64) << 48
                    | (segments[1] as u64) << 32
                    | (segments[2] as u64) << 16
                    | segments[3] as u64)
                    .wrapping_mul(0x9e3779b97f4a7c15);
                let lo = ((segments[4] as u64) << 48
                    | (segments[5] as u64) << 32
                    | (segments[6] as u64) << 16
                    | segments[7] as u64)
                    .wrapping_mul(0x9e3779b97f4a7c15);
                let hash = hi ^ lo.rotate_left(32);
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

#[cfg(test)]
mod ipv6_low_bits_tests {
    use super::ip_to_slot;
    use std::net::{IpAddr, Ipv6Addr};

    /// Regression guard: only the top 64 bits used to be hashed, so every
    /// host in a /64 collapsed onto one slot and shared a rate-limit bucket.
    #[test]
    fn hosts_within_one_prefix_64_get_distinct_slots() {
        let base: u128 = 0x2001_0db8_0000_0000;
        let mut seen = std::collections::HashSet::new();
        for i in 0..256u128 {
            let ip = IpAddr::V6(Ipv6Addr::from(base | i));
            seen.insert(ip_to_slot(ip, 65536).unwrap());
        }
        assert_eq!(
            seen.len(),
            256,
            "256 distinct hosts in one /64 must not collapse to one slot"
        );
    }

    #[test]
    fn slot_is_stable_for_the_same_address() {
        let ip = IpAddr::V6(Ipv6Addr::from(0x2001_0db8_0000_0001u128 | 0xdead_beefu128));
        for slots in [1usize, 16, 100, 256, 65536] {
            assert_eq!(ip_to_slot(ip, slots), ip_to_slot(ip, slots));
            assert!(ip_to_slot(ip, slots).unwrap() < slots);
        }
    }
}
