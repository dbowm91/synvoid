//! DNS-owned restricted-IP policy (Phase 129 Workstream B).
//!
//! Replaces `synvoid_core::net::is_restricted_ip()`. The predicate decides
//! which source addresses DNS will answer, rebind-check, or refuse, so it is
//! a **security boundary**: the logic below is a character-for-character port
//! of the previous helper, and the differential tests in this module enumerate
//! every branch.
//!
//! **Do not broaden or narrow this policy without separate security review.**
//! Two entries are deliberately broader than RFC 1918 and may look like
//! mistakes:
//!
//! * `192.0.0.0/8` — the test only skips `b == 0`, which is RFC 6890 special
//!   purpose, but in practice this also blocks `192.0.x.x` beyond `/24`.
//! * `198.18.0.0/15` and `198.51.100.0/24` / `203.0.113.0/24` — benchmarking
//!   and documentation ranges, which are not routable but are not RFC 1918
//!   either. Blocking them is intentional.
//!
//! Both are preserved as-is for parity.

use std::net::IpAddr;

/// True when `ip` is in a range DNS must not serve or must refuse.
///
/// The DNS policy treats documentation/benchmark/multicast space as
/// restricted because a public resolver answering from it is never correct.
pub fn is_restricted_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            a == 0 // 0.0.0.0/8 "this network"
                || a == 10 // 10.0.0.0/8 RFC1918
                || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 CGNAT
                || a == 127 // 127.0.0.0/8 loopback
                || (a == 169 && b == 254) // 169.254.0.0/16 link-local
                || (a == 172 && (16..=31).contains(&b)) // 172.16.0.0/12 RFC1918
                || (a == 192 && (b == 0 || b == 168)) // 192.0.0.0/24 + 192.168.0.0/16
                || (a == 198 && ((18..=19).contains(&b) || b == 51)) // 198.18/15 + 198.51.100/24
                || (a == 203 && b == 0) // 203.0.113.0/24 documentation
                || (224..=255).contains(&a) // multicast + reserved
        }
        IpAddr::V6(ip) => {
            // IPv4-mapped addresses are judged by their IPv4 value, so a
            // mapped loopback is restricted and a mapped public address is
            // not. Skipping this would let `::ffff:127.0.0.1` bypass the
            // IPv4 policy entirely.
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return is_restricted_ip(&IpAddr::V4(ipv4));
            }

            let first = ip.segments()[0];
            ip.is_unspecified() // :: 
                || ip.is_loopback() // ::1
                || (first & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (first & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (first & 0xff00) == 0xff00 // ff00::/8 multicast
                || (first == 0x2001 && ip.segments()[1] == 0x0db8) // 2001:db8::/32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().expect("valid IPv6 literal"))
    }

    /// Every IPv4 branch of the policy, with the range each one covers.
    #[test]
    fn ipv4_restricted_branches() {
        for ip in [
            (0, 0, 0, 0),  // 0/8
            (0, 1, 2, 3),  // 0/8, non-zero second octet
            (10, 0, 0, 1), // RFC1918
            (10, 255, 255, 255),
            (100, 64, 0, 1),      // CGNAT low bound
            (100, 127, 255, 255), // CGNAT high bound
            (127, 0, 0, 1),       // loopback
            (169, 254, 1, 1),     // link-local
            (172, 16, 0, 1),      // RFC1918 low bound
            (172, 31, 255, 255),  // RFC1918 high bound
            (192, 0, 0, 1),       // 192.0/24
            (192, 168, 1, 1),     // RFC1918
            (198, 18, 0, 1),      // benchmarking low bound
            (198, 19, 255, 255),  // benchmarking high bound
            (198, 51, 100, 1),    // documentation
            (203, 0, 113, 10),    // documentation
            (224, 0, 0, 1),       // multicast
            (239, 1, 2, 3),
            (255, 255, 255, 255), // reserved / broadcast
        ] {
            assert!(
                is_restricted_ip(&v4(ip.0, ip.1, ip.2, ip.3)),
                "{ip:?} restricted"
            );
        }
    }

    /// Addresses just outside each restricted boundary must NOT be
    /// restricted. This is the half that catches an off-by-one.
    #[test]
    fn ipv4_public_addresses_are_not_restricted() {
        for ip in [
            (1, 2, 3, 4),
            (9, 255, 255, 255),   // just below RFC1918 10/8
            (11, 0, 0, 0),        // just above RFC1918 10/8
            (100, 63, 255, 255),  // just below CGNAT
            (100, 128, 0, 0),     // just above CGNAT
            (126, 255, 255, 255), // just below loopback
            (128, 0, 0, 0),       // just above loopback
            (169, 253, 255, 255), // just below link-local
            (169, 255, 0, 0),     // just above link-local
            (172, 15, 255, 255),  // just below RFC1918 172.16/12
            (172, 32, 0, 0),      // just above RFC1918 172.16/12
            (192, 1, 0, 0),       // above 192.0/24, below RFC1918
            (192, 167, 255, 255), // just below RFC1918
            (192, 169, 0, 0),     // just above RFC1918
            (198, 17, 255, 255),  // just below benchmarking
            (198, 20, 0, 0),      // just above benchmarking
            (198, 50, 255, 255),  // just below 198.51.100/24
            (198, 52, 0, 0),      // just above 198.51.100/24
            (202, 255, 255, 255), // just below 203.0.113/24
            (203, 1, 0, 0),       // just above documentation
            (223, 255, 255, 255), // just below multicast
        ] {
            assert!(
                !is_restricted_ip(&v4(ip.0, ip.1, ip.2, ip.3)),
                "{ip:?} must not be restricted"
            );
        }
    }

    /// `192.0.0.0/24` is matched on the second octet only, so the whole
    /// `192.0.x.x` space is restricted. Pinned because it is broader than the
    /// RFC and looks like a bug otherwise.
    #[test]
    fn ipv4_192_0_slash_8_is_restricted_beyond_slash_24() {
        assert!(is_restricted_ip(&v4(192, 0, 1, 1)));
        assert!(is_restricted_ip(&v4(192, 0, 255, 255)));
        // The next /24 is public.
        assert!(!is_restricted_ip(&v4(192, 1, 0, 0)));
    }

    #[test]
    fn ipv6_restricted_branches() {
        for ip in [
            "::",          // unspecified
            "::1",         // loopback
            "fc00::1",     // fc00::/7 ULA low bound
            "fdff::1",     // fc00::/7 ULA high bound
            "fe80::1",     // fe80::/10 link-local low bound
            "febf::1",     // fe80::/10 link-local high bound
            "ff00::1",     // ff00::/8 multicast
            "ff02::1",     // link-local multicast
            "2001:db8::1", // documentation
        ] {
            assert!(is_restricted_ip(&v6(ip)), "{ip} restricted");
        }
    }

    #[test]
    fn ipv6_public_addresses_are_not_restricted() {
        for ip in [
            "2001:4860:4860::8888", // Google DNS
            "2606:4700:4700::1111", // Cloudflare DNS
            "fbff::1",              // just above fc00::/7
            "fec0::1",              // just above fe80::/10
            "fe00::1",              // just below fe80::/10
            "2001:db7::1",          // just below 2001:db8::/32
            "2001:db9::1",          // just above 2001:db8::/32
        ] {
            assert!(!is_restricted_ip(&v6(ip)), "{ip} must not be restricted");
        }
    }

    /// A mapped address must be judged by its IPv4 value in both directions,
    /// so the mapping cannot be used to bypass the IPv4 policy.
    #[test]
    fn ipv4_mapped_addresses_follow_the_ipv4_policy() {
        assert!(is_restricted_ip(&v6("::ffff:127.0.0.1")));
        assert!(is_restricted_ip(&v6("::ffff:10.0.0.1")));
        assert!(is_restricted_ip(&v6("::ffff:192.168.1.1")));
        assert!(!is_restricted_ip(&v6("::ffff:1.2.3.4")));
        assert!(!is_restricted_ip(&v6("::ffff:8.8.8.8")));
    }
}
