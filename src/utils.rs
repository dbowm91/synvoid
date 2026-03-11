pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();

    if s.is_empty() {
        return None;
    }

    if s.eq_ignore_ascii_case("never")
        || s.eq_ignore_ascii_case("permanent")
        || s.eq_ignore_ascii_case("0")
        || s.eq_ignore_ascii_case("0s")
    {
        return Some(0);
    }

    if let Ok(num) = s.parse::<u64>() {
        return Some(num);
    }

    if s.len() >= 2 {
        let last_two = &s[s.len() - 2..];
        if last_two.eq_ignore_ascii_case("ms") {
            return s[..s.len() - 2].parse::<u64>().ok().map(|n| n / 1000);
        }

        if s.len() >= 9 && s[s.len() - 7..].eq_ignore_ascii_case("seconds") {
            return s[..s.len() - 7].parse::<u64>().ok();
        }
        if s.len() >= 9 && s[s.len() - 7..].eq_ignore_ascii_case("minutes") {
            return s[..s.len() - 7].parse::<u64>().ok().map(|n| n * 60);
        }
        if s.len() >= 6 && s[s.len() - 5..].eq_ignore_ascii_case("hours") {
            return s[..s.len() - 5].parse::<u64>().ok().map(|n| n * 3600);
        }

        if s.len() >= 5 && s[s.len() - 4..].eq_ignore_ascii_case("secs") {
            return s[..s.len() - 4].parse::<u64>().ok();
        }
        if s.len() >= 5 && s[s.len() - 4..].eq_ignore_ascii_case("mins") {
            return s[..s.len() - 4].parse::<u64>().ok().map(|n| n * 60);
        }
        if s.len() >= 4 && s[s.len() - 3..].eq_ignore_ascii_case("hrs") {
            return s[..s.len() - 3].parse::<u64>().ok().map(|n| n * 3600);
        }
        if s.len() >= 5 && s[s.len() - 4..].eq_ignore_ascii_case("days") {
            return s[..s.len() - 4].parse::<u64>().ok().map(|n| n * 86400);
        }

        if s.len() >= 4 && s[s.len() - 3..].eq_ignore_ascii_case("sec") {
            return s[..s.len() - 3].parse::<u64>().ok();
        }
        if s.len() >= 4 && s[s.len() - 3..].eq_ignore_ascii_case("min") {
            return s[..s.len() - 3].parse::<u64>().ok().map(|n| n * 60);
        }
        if s.len() >= 3 && s[s.len() - 2..].eq_ignore_ascii_case("hr") {
            return s[..s.len() - 2].parse::<u64>().ok().map(|n| n * 3600);
        }
        if s.len() >= 4 && s[s.len() - 3..].eq_ignore_ascii_case("day") {
            return s[..s.len() - 3].parse::<u64>().ok().map(|n| n * 86400);
        }

        let last_one = &s[s.len() - 1..];
        if last_one == "s" || last_one == "S" {
            return s[..s.len() - 1].parse::<u64>().ok();
        }
        if last_one == "m" || last_one == "M" {
            return s[..s.len() - 1].parse::<u64>().ok().map(|n| n * 60);
        }
        if last_one == "h" || last_one == "H" {
            return s[..s.len() - 1].parse::<u64>().ok().map(|n| n * 3600);
        }
        if last_one == "d" || last_one == "D" {
            return s[..s.len() - 1].parse::<u64>().ok().map(|n| n * 86400);
        }
    }

    None
}

pub fn format_duration(seconds: u64) -> String {
    if seconds == 0 {
        return "never".to_string();
    }
    if seconds < 60 {
        return format!("{}s", seconds);
    }
    if seconds < 3600 {
        return format!("{}m", seconds / 60);
    }
    if seconds < 86400 {
        return format!("{}h", seconds / 3600);
    }
    format!("{}d", seconds / 86400)
}

use std::net::{IpAddr, SocketAddr};

pub fn parse_host_port(host: &str, port: u16) -> Result<SocketAddr, String> {
    if host.starts_with('[') {
        if let Some(end_bracket) = host.find(']') {
            let ip_str = &host[1..end_bracket];
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|e| format!("Invalid IPv6 address: {}", e))?;
            return Ok(SocketAddr::new(ip, port));
        }
        return Err("Unclosed bracket in IPv6 address".to_string());
    }

    if host.contains(':') {
        let ip: IpAddr = host
            .parse()
            .map_err(|e| format!("Invalid IP address: {}", e))?;
        return Ok(SocketAddr::new(ip, port));
    }

    let ip: IpAddr = host
        .parse()
        .map_err(|e| format!("Invalid IP address: {}", e))?;
    Ok(SocketAddr::new(ip, port))
}

pub fn is_ipv6_host(host: &str) -> bool {
    host.contains(':')
}

pub fn ip_to_slot(ip: IpAddr, num_slots: usize) -> usize {
    hash_ip(ip) % num_slots
}

pub fn hash_ip(ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let mut hash: usize = 0;
            hash ^= (octets[0] as usize) << 24;
            hash ^= (octets[1] as usize) << 16;
            hash ^= (octets[2] as usize) << 8;
            hash ^= octets[3] as usize;
            hash
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let mut hash: usize = 0;
            for (i, seg) in segments.iter().enumerate() {
                hash ^= (*seg as usize) << ((i % 4) * 4);
            }
            hash
        }
    }
}

#[cfg(test)]
mod ip_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ip_to_slot_consistency() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let slot1 = ip_to_slot(ip, 65536);
        let slot2 = ip_to_slot(ip, 65536);
        assert_eq!(slot1, slot2, "Same IP should produce same slot");
    }

    #[test]
    fn test_ip_to_slot_different_ips() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let slot1 = ip_to_slot(ip1, 65536);
        let slot2 = ip_to_slot(ip2, 65536);
        assert_ne!(
            slot1, slot2,
            "Different IPs should likely produce different slots"
        );
    }

    #[test]
    fn test_ipv6_to_slot() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let slot = ip_to_slot(ip, 65536);
        assert!(slot < 65536);
    }

    #[test]
    fn test_hash_ip_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let hash1 = hash_ip(ip);
        let hash2 = hash_ip(ip);
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, 0);
    }

    #[test]
    fn test_hash_ip_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let hash1 = hash_ip(ip);
        let hash2 = hash_ip(ip);
        assert_eq!(hash1, hash2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30"), Some(30), "30");
        assert_eq!(parse_duration("30s"), Some(30), "30s");
        assert_eq!(parse_duration("30sec"), Some(30), "30sec");
        assert_eq!(parse_duration("30m"), Some(1800), "30m");
        assert_eq!(parse_duration("30min"), Some(1800), "30min");
        assert_eq!(parse_duration("2h"), Some(7200), "2h");
        assert_eq!(parse_duration("2hr"), Some(7200), "2hr");
        assert_eq!(parse_duration("2hours"), Some(7200), "2hours");
        assert_eq!(parse_duration("1d"), Some(86400), "1d");
        assert_eq!(parse_duration("1day"), Some(86400), "1day");
        assert_eq!(parse_duration("2days"), Some(172800), "2days");
        assert_eq!(parse_duration("never"), Some(0), "never");
        assert_eq!(parse_duration("permanent"), Some(0), "permanent");
        assert_eq!(parse_duration("0"), Some(0), "0");
    }

    #[test]
    fn test_parse_host_port_ipv4() {
        assert_eq!(
            parse_host_port("127.0.0.1", 8080).unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
        );
        assert_eq!(
            parse_host_port("0.0.0.0", 80).unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 80)
        );
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        assert_eq!(
            parse_host_port("::1", 8080).unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080)
        );
        assert_eq!(
            parse_host_port("[::1]", 8080).unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080)
        );
        assert_eq!(
            parse_host_port("::", 443).unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 443)
        );
        assert_eq!(
            parse_host_port("[::]", 443).unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 443)
        );
    }

    #[test]
    fn test_parse_host_port_invalid() {
        assert!(parse_host_port("invalid", 8080).is_err());
        assert!(parse_host_port("[invalid", 8080).is_err());
    }

    #[test]
    fn test_is_ipv6_host() {
        assert!(!is_ipv6_host("127.0.0.1"));
        assert!(!is_ipv6_host("192.168.1.1"));
        assert!(is_ipv6_host("::1"));
        assert!(is_ipv6_host("[::1]"));
        assert!(is_ipv6_host("2001:db8::1"));
    }
}
