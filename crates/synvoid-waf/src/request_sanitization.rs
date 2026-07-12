use http::{HeaderMap, HeaderName};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct RequestSanitizer {
    trusted_proxies: Vec<TrustedProxy>,
    sanitize_forwarded: bool,
}

#[derive(Debug, Clone)]
enum TrustedProxy {
    IPv4(Ipv4Addr, u8),
    IPv6(Ipv6Addr, u8),
}

impl TrustedProxy {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (TrustedProxy::IPv4(net, prefix), IpAddr::V4(ip)) => {
                let network = u32::from(*net);
                let ip_bits = u32::from(ip);
                let mask = synvoid_core::net::ipv4_prefix_mask(*prefix);
                (network & mask) == (ip_bits & mask)
            }
            (TrustedProxy::IPv6(net, prefix), IpAddr::V6(ip)) => {
                let network = net.octets();
                let ip_bits = ip.octets();
                let prefix_bytes = prefix / 8;
                let prefix_bits = prefix % 8;

                if network[..prefix_bytes as usize] != ip_bits[..prefix_bytes as usize] {
                    return false;
                }

                if prefix_bits > 0 {
                    let mask = !(0xFF >> prefix_bits);
                    return (network[prefix_bytes as usize] & mask)
                        == (ip_bits[prefix_bytes as usize] & mask);
                }

                true
            }
            _ => false,
        }
    }
}

impl RequestSanitizer {
    pub fn new(trusted_proxies: Vec<String>, sanitize_forwarded: bool) -> Self {
        let proxies = trusted_proxies
            .into_iter()
            .filter_map(|p| Self::parse_proxy(&p))
            .collect();

        Self {
            trusted_proxies: proxies,
            sanitize_forwarded,
        }
    }

    fn parse_proxy(proxy: &str) -> Option<TrustedProxy> {
        if let Some((ip, prefix)) = proxy.split_once('/') {
            let prefix: u8 = prefix.parse().ok()?;
            if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                if prefix <= 32 {
                    return Some(TrustedProxy::IPv4(ipv4, prefix));
                }
            } else if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
                if prefix <= 128 {
                    return Some(TrustedProxy::IPv6(ipv6, prefix));
                }
            }
        } else if let Ok(ipv4) = proxy.parse::<Ipv4Addr>() {
            return Some(TrustedProxy::IPv4(ipv4, 32));
        } else if let Ok(ipv6) = proxy.parse::<Ipv6Addr>() {
            return Some(TrustedProxy::IPv6(ipv6, 128));
        }

        None
    }

    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|p| p.contains(ip))
    }

    pub fn sanitize(&self, headers: &mut HeaderMap, client_ip: IpAddr) -> SanitizedRequest {
        let mut sanitized = SanitizedRequest::default();

        if self.sanitize_forwarded && self.is_trusted_proxy(client_ip) {
            sanitized.original_forwarded_for = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            sanitized.original_forwarded_proto = headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            sanitized.original_forwarded_host = headers
                .get("x-forwarded-host")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            sanitized.forwarded_from_trusted = true;
        } else if self.sanitize_forwarded {
            headers.remove("x-forwarded-for");
            headers.remove("x-forwarded-proto");
            headers.remove("x-forwarded-host");
            headers.remove("x-forwarded-port");
            headers.remove("forwarded");

            sanitized.original_forwarded_for = None;
            sanitized.original_forwarded_proto = None;
            sanitized.original_forwarded_host = None;
            sanitized.forwarded_from_trusted = false;
            sanitized.headers_sanitized = true;
        } else {
            sanitized.client_ip = Some(client_ip);
        }

        sanitized
    }

    pub fn sanitize_request_headers(&self, headers: &mut HeaderMap, client_ip: IpAddr) {
        if self.sanitize_forwarded && !self.is_trusted_proxy(client_ip) {
            headers.remove("x-forwarded-for");
            headers.remove("x-forwarded-proto");
            headers.remove("x-forwarded-host");
            headers.remove("x-forwarded-port");
            headers.remove("forwarded");

            let hop_by_hop = ["proxy-authorization"];

            for header in hop_by_hop {
                if let Ok(name) = HeaderName::from_bytes(header.as_bytes()) {
                    headers.remove(name);
                }
            }
        }
    }

    pub fn get_real_ip(&self, headers: &HeaderMap, client_ip: IpAddr) -> Option<IpAddr> {
        if self.sanitize_forwarded && self.is_trusted_proxy(client_ip) {
            if let Some(forwarded_for) = headers.get("x-forwarded-for") {
                if let Ok(value) = forwarded_for.to_str() {
                    let ips: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
                    if !ips.is_empty() {
                        if let Some(client_ip_from_xff) = self.find_client_ip_in_xff(&ips) {
                            return Some(client_ip_from_xff);
                        }
                    }
                }
            }

            if let Some(forwarded) = headers.get("forwarded") {
                if let Ok(value) = forwarded.to_str() {
                    for part in value.split(';') {
                        if let Some((key, val)) = part.split_once('=') {
                            if key.trim().eq_ignore_ascii_case("for") {
                                let ip_str = val.trim().trim_matches('"');
                                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                    if !self.is_private_ip(&ip) {
                                        return Some(ip);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Some(client_ip)
    }

    fn find_client_ip_in_xff(&self, ips: &[&str]) -> Option<IpAddr> {
        let n = ips.len();
        let mut found_trusted = false;
        for i in (0..n).rev() {
            if let Ok(ip) = ips[i].parse::<IpAddr>() {
                if self.is_trusted_proxy(ip) {
                    found_trusted = true;
                    continue;
                }
                if found_trusted {
                    if self.is_private_ip(&ip) {
                        continue;
                    }
                    return Some(ip);
                }
                if self.is_private_ip(&ip) {
                    return None;
                }
                return Some(ip);
            } else {
                return None;
            }
        }
        None
    }

    fn is_private_ip(&self, ip: &IpAddr) -> bool {
        synvoid_core::net::is_restricted_ip(ip)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SanitizedRequest {
    pub client_ip: Option<IpAddr>,
    pub original_forwarded_for: Option<String>,
    pub original_forwarded_proto: Option<String>,
    pub original_forwarded_host: Option<String>,
    pub forwarded_from_trusted: bool,
    pub headers_sanitized: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_proxy_ipv4_cidr() {
        let sanitizer = RequestSanitizer::new(vec!["10.0.0.0/8".to_string()], true);

        assert!(sanitizer.is_trusted_proxy(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(sanitizer.is_trusted_proxy(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(!sanitizer.is_trusted_proxy(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn test_trusted_proxy_single() {
        let sanitizer = RequestSanitizer::new(vec!["127.0.0.1".to_string()], true);

        assert!(sanitizer.is_trusted_proxy(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!sanitizer.is_trusted_proxy(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))));
    }

    #[test]
    fn test_sanitize_untrusted() {
        let sanitizer = RequestSanitizer::new(vec!["127.0.0.1".to_string()], true);

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());

        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = sanitizer.sanitize(&mut headers, client_ip);

        assert!(result.headers_sanitized);
        assert!(result.original_forwarded_for.is_none());
        assert!(!result.forwarded_from_trusted);
    }

    #[test]
    fn test_sanitize_trusted() {
        let sanitizer = RequestSanitizer::new(vec!["192.168.0.0/16".to_string()], true);

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());

        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = sanitizer.sanitize(&mut headers, client_ip);

        assert!(!result.headers_sanitized);
        assert!(result.forwarded_from_trusted);
        assert_eq!(
            result.original_forwarded_for,
            Some("1.2.3.4, 5.6.7.8".to_string())
        );
    }

    #[test]
    fn test_get_real_ip_direct_untrusted_client() {
        let sanitizer = RequestSanitizer::new(vec!["10.0.0.0/8".to_string()], true);

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());

        let client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let result = sanitizer.get_real_ip(&headers, client_ip);
        assert_eq!(result, Some(client_ip));
    }

    #[test]
    fn test_get_real_ip_trusted_proxy_single() {
        let sanitizer = RequestSanitizer::new(vec!["10.0.0.10".to_string()], true);

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 10.0.0.10".parse().unwrap());

        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let result = sanitizer.get_real_ip(&headers, client_ip);
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn test_get_real_ip_multiple_trusted_proxies() {
        let sanitizer =
            RequestSanitizer::new(vec!["10.0.0.10".to_string(), "10.0.0.11".to_string()], true);

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "1.2.3.4, 10.0.0.10, 10.0.0.11".parse().unwrap(),
        );

        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let result = sanitizer.get_real_ip(&headers, client_ip);
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn test_get_real_ip_private_client_rejected() {
        let sanitizer = RequestSanitizer::new(vec!["10.0.0.10".to_string()], true);

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.1, 10.0.0.10".parse().unwrap());

        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let result = sanitizer.get_real_ip(&headers, client_ip);
        assert_eq!(result, Some(client_ip));
    }

    #[test]
    fn test_get_real_ip_spoofed_middle_public_ip_rejected() {
        let sanitizer = RequestSanitizer::new(vec!["10.0.0.10".to_string()], true);

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "1.2.3.4, 5.6.7.8, 10.0.0.10".parse().unwrap(),
        );

        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let result = sanitizer.get_real_ip(&headers, client_ip);
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))));
    }

    #[test]
    fn test_get_real_ip_forwarded_header() {
        let sanitizer = RequestSanitizer::new(vec!["10.0.0.10".to_string()], true);

        let mut headers = HeaderMap::new();
        headers.insert("forwarded", "for=1.2.3.4".parse().unwrap());

        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let result = sanitizer.get_real_ip(&headers, client_ip);
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn test_get_real_ip_empty_xff() {
        let sanitizer = RequestSanitizer::new(vec!["10.0.0.10".to_string()], true);

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "".parse().unwrap());

        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let result = sanitizer.get_real_ip(&headers, client_ip);
        assert_eq!(result, Some(client_ip));
    }

    #[test]
    fn test_trusted_proxy_zero_prefix_does_not_panic() {
        let sanitizer = RequestSanitizer::new(vec!["0.0.0.0/0".to_string()], true);
        assert!(sanitizer.is_trusted_proxy("203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn test_restricted_ipv6_and_multicast_addresses_are_not_client_ips() {
        let sanitizer = RequestSanitizer::new(vec!["10.0.0.10".to_string()], true);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "fd00::1, 10.0.0.10".parse().unwrap());
        let client_ip = "10.0.0.10".parse().unwrap();
        assert_eq!(sanitizer.get_real_ip(&headers, client_ip), Some(client_ip));

        headers.insert("x-forwarded-for", "225.1.1.1, 10.0.0.10".parse().unwrap());
        assert_eq!(sanitizer.get_real_ip(&headers, client_ip), Some(client_ip));
    }
}
