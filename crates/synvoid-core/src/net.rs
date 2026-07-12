//! Small, dependency-free networking helpers shared by security boundaries.

use std::net::IpAddr;

/// Return the network mask for an IPv4 prefix length without shifting by 32.
///
/// Configuration and feed data commonly permit `/0`; the straightforward
/// `1u32 << (32 - prefix)` expression panics for that valid prefix in debug
/// builds and wraps in release builds.
pub const fn ipv4_prefix_mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        1..=31 => u32::MAX << (32 - prefix as u32),
        _ => u32::MAX,
    }
}

/// Whether an address belongs to a non-public or special-use range.
///
/// This is deliberately conservative for request-origin and SSRF decisions:
/// private, link-local, shared-address, benchmarking, multicast, unspecified,
/// and reserved addresses must not be treated as public client/upstream IPs.
pub fn is_restricted_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            a == 0
                || a == 10
                || (a == 100 && (64..=127).contains(&b))
                || a == 127
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 0 || b == 168))
                || (a == 198 && ((18..=19).contains(&b) || b == 51))
                || (a == 203 && b == 0)
                || (224..=255).contains(&a)
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return is_restricted_ip(&IpAddr::V4(ipv4));
            }

            let first = ip.segments()[0];
            ip.is_unspecified()
                || ip.is_loopback()
                || (first & 0xfe00) == 0xfc00 // fc00::/7, unique local
                || (first & 0xffc0) == 0xfe80 // fe80::/10, link local
                || (first & 0xff00) == 0xff00 // ff00::/8, multicast
                || (first == 0x2001 && ip.segments()[1] == 0x0db8) // 2001:db8::/32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_prefix_mask_handles_boundaries() {
        assert_eq!(ipv4_prefix_mask(0), 0);
        assert_eq!(ipv4_prefix_mask(8), 0xff00_0000);
        assert_eq!(ipv4_prefix_mask(32), u32::MAX);
    }

    #[test]
    fn restricted_ip_ranges_cover_special_use_ranges() {
        for ip in [
            IpAddr::V4(Ipv4Addr::new(225, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("febf::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        ] {
            assert!(is_restricted_ip(&ip), "{ip} should be restricted");
        }

        assert!(!is_restricted_ip(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }
}
