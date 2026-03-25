use std::net::IpAddr;

pub struct QnameMinimizer {
    enabled: bool,
}

impl QnameMinimizer {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub fn minimize(&self, qname: &str, zones: &[String]) -> String {
        if !self.enabled {
            return qname.to_string();
        }

        let qname_lower = qname.to_lowercase();

        let mut best_match: Option<&String> = None;
        let mut best_match_len = 0;

        for zone in zones {
            let zone_lower = zone.to_lowercase();
            if (qname_lower.ends_with(&zone_lower) || qname_lower == zone_lower)
                && zone_lower.len() > best_match_len {
                    best_match = Some(zone);
                    best_match_len = zone_lower.len();
                }
        }

        if let Some(zone) = best_match {
            let zone_lower = zone.to_lowercase();
            if qname_lower == zone_lower {
                return ".".to_string();
            }

            if let Some(stripped) = qname_lower.strip_suffix(&format!(".{}", zone_lower)) {
                let parts: Vec<&str> = stripped.split('.').collect();
                if parts.len() > 1 {
                    let second_level = parts[parts.len() - 1];
                    return format!("*.{}", second_level);
                }
                return format!("*.{}", zone);
            }
        }

        let parts: Vec<&str> = qname_lower.split('.').collect();
        if parts.len() > 2 {
            let minimized = format!("*.{}", parts[parts.len() - 2]);
            return minimized;
        }

        qname.to_string()
    }
}

pub struct RebindingChecker {
    private_ip_ranges: Vec<(IpAddr, u8)>,
    min_ttl: u32,
    allowed_domains: Vec<String>,
}

impl RebindingChecker {
    pub fn new(min_ttl: u32, allowed_domains: Vec<String>) -> Self {
        Self {
            private_ip_ranges: vec![
                (IpAddr::from([10, 0, 0, 0]), 8),
                (IpAddr::from([172, 16, 0, 0]), 12),
                (IpAddr::from([192, 168, 0, 0]), 16),
                (IpAddr::from([127, 0, 0, 0]), 8),
                (IpAddr::from([169, 254, 0, 0]), 16),
            ],
            min_ttl,
            allowed_domains,
        }
    }

    pub fn is_private_ip(&self, ip: &IpAddr) -> bool {
        for (network, prefix) in &self.private_ip_ranges {
            if let (IpAddr::V4(client), IpAddr::V4(net)) = (ip, network) {
                if self.ipv4_in_prefix(client, net, *prefix) {
                    return true;
                }
            }
        }
        false
    }

    fn ipv4_in_prefix(
        &self,
        ip: &std::net::Ipv4Addr,
        network: &std::net::Ipv4Addr,
        prefix: u8,
    ) -> bool {
        let ip_bits = u32::from_be_bytes(ip.octets());
        let net_bits = u32::from_be_bytes(network.octets());
        let mask = !((1u32 << (32 - prefix)) - 1);
        (ip_bits & mask) == (net_bits & mask)
    }

    pub fn check(&self, qname: &str, ttl: u32) -> Result<(), String> {
        for domain in &self.allowed_domains {
            if qname.ends_with(domain) || qname == domain.trim_start_matches('.') {
                return Ok(());
            }
        }

        if ttl < self.min_ttl {
            return Err(format!(
                "Query {} has TTL {} below minimum {} - potential rebinding",
                qname, ttl, self.min_ttl
            ));
        }

        Ok(())
    }
}
